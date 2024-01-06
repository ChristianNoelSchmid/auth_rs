use std::collections::BTreeMap;

use axum::async_trait;
use base64::{engine::general_purpose, Engine};
use chrono::{Utc, DateTime};
use derive_more::Constructor;
use dotenvy::var;
use hmac::{Hmac, Mac};
use jwt::{SignWithKey, VerifyWithKey};
use rand::RngCore;
use sha2::Sha256;

use crate::auth::config::AuthServiceSettings;

use self::error::*;

pub mod error;

const JWT_SECRET_ENV_VAR: &'static str = "JWT_SECRET";

pub trait TokenService : Send + Sync {
    ///
    /// Creates a new access token for the given user
    /// 
    fn gen_access_token<'a>(&self, email: &'a str, timestamp_utc: DateTime<Utc>) -> Result<String>;
    ///
    /// Verifies the authenticity of the provided access token, returning
    /// the subject if successful
    /// 
    fn verify_access_token<'a>(&self, token_str: &'a str, timestamp_utc: DateTime<Utc>) -> Result<String>;
    ///
    /// Creates a new random token as a formatted String
    /// 
    fn gen_rand_token(&self) -> String;
}

#[derive(Constructor)]
pub struct CoreTokenService<'a> {
    config: &'a AuthServiceSettings
}

#[async_trait]
impl<'s> TokenService for CoreTokenService<'s> {
    fn gen_access_token<'a>(&self, email: &'a str, timestamp_utc: DateTime<Utc>) -> Result<String> {
        // Retrieve the JWT secret from env
        let secret = var(JWT_SECRET_ENV_VAR).expect(&format!("`{JWT_SECRET_ENV_VAR}` expected in env"));
        // Create key from secret
        let key: Hmac<Sha256> = Hmac::new_from_slice(&secret.as_bytes()).expect(&format!("Invalid secret length: `{JWT_SECRET_ENV_VAR}`"));

        // Build out claims body
        let timestamp_str = (timestamp_utc + self.config.get_access_token_lifetime()).to_rfc3339();
        let mut claims = BTreeMap::new();
        claims.insert("subject", email);
        claims.insert("expires_on", &timestamp_str);
        claims.insert("issuer", &self.config.issuer);
        claims.insert("audience", &self.config.audience);

        // Create JWT
        let access_token = claims.sign_with_key(&key)?;
        
        Ok(access_token)
    }
    fn verify_access_token<'a>(&self, token_str: &'a str, timestamp_utc: DateTime<Utc>) -> Result<String> {
        // Retrieve the JWT secret from env
        let secret = var(JWT_SECRET_ENV_VAR).expect(&format!("`{JWT_SECRET_ENV_VAR}` expected in env"));
        // Create key from secret
        let key: Hmac<Sha256> = Hmac::new_from_slice(&secret.as_bytes()).expect(&format!("Invalid secret length: `{JWT_SECRET_ENV_VAR}`"));

        let mut claims: BTreeMap<String, String> = token_str.verify_with_key(&key).map_err(|e|  
            if let jwt::Error::RustCryptoMac(_) = e {
                Error::InvalidToken
            } else {
                Error::InternalServerError(Box::new(e))
            }
        )?;

        // It can be assumed that there is a valid, well-formatted
        // DateTime<Utc> property since the token has been verificed
        let expires_on = claims
            .remove("expires_on").unwrap()
            .parse::<DateTime<Utc>>().unwrap();

        // Return Error if the token is expired
        if expires_on <= timestamp_utc {
            return Err(Error::TokenExpired);
        }

        // Subject field is guaranteed as signature has been verified
        // (any tampering of JWT that could result in subject field not existing would be caught)
        Ok(claims.remove("subject").unwrap())
    }
    fn gen_rand_token(&self) -> String {
        let mut bytes = [0u8;64];
        rand::thread_rng().fill_bytes(&mut bytes);
        general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose;
    use chrono::NaiveDateTime;
    use lazy_static::lazy_static;
    use serde::{Deserialize, Serialize};

    #[derive(Deserialize, Serialize)]
    struct TokenContents {
        subject: String,
        expires_on: String,
        issuer: String,
        audience: String
    }

    lazy_static! {
        static ref AUTH_SERVICE_SETTINGS: AuthServiceSettings = AuthServiceSettings::new(
            String::from("test_audience"), String::from("test_issuer"),
            String::from("0.00:00:05"), String::from("0.00:00:05")
        );
    }

    #[test]
    fn test_token_gen_and_verify() {
        // Static date for MockDateTimeService: 2023-05-10 16:00
        let date = NaiveDateTime::from_timestamp_millis(1683748800000).unwrap().and_utc();

        let svc = CoreTokenService::new(&AUTH_SERVICE_SETTINGS);
        let access_token = svc.gen_access_token("tester@mail.com", date).unwrap();

        // Grab the content of the JWT, deserialize it, and update the role to "Admin"
        // to attempt to hack the role requirements
        let token_body = access_token.split('.').skip(1).next().unwrap();
        let token_body = general_purpose::STANDARD_NO_PAD.decode(token_body).unwrap();

        let contents: TokenContents =
            serde_json::from_str(&String::from_utf8_lossy(&token_body).to_string()).unwrap();

        assert_eq!(contents.issuer, "test_issuer");
        assert_eq!(contents.audience, "test_audience");
        assert_eq!(contents.expires_on, "2023-05-10T20:00:05+00:00");
        assert_eq!(contents.subject, "tester@mail.com");
    }

    #[test]
    fn test_improper_token() {
        // Static date for MockDateTimeService: 2023-05-10 16:00
        let date = NaiveDateTime::from_timestamp_millis(1683748800000).unwrap().and_utc();

        let svc = CoreTokenService::new(&AUTH_SERVICE_SETTINGS);
        let access_token = svc.gen_access_token("tester@mail.com", date).unwrap();

        // Grab the content of the JWT, deserialize it, and update the role to "Admin"
        // to attempt to hack the role requirements
        let str = access_token.split('.').skip(1).next().unwrap();
        let str = general_purpose::STANDARD_NO_PAD.decode(str).unwrap();
        let mut contents: TokenContents =
            serde_json::from_str(&String::from_utf8_lossy(&str).to_string()).unwrap();

        contents.subject = "replacement@mail.com".to_string();

        // Build the new token with the new role, but with the same
        // header and key
        let new_token = format!(
            "{}.{}.{}",
            access_token.split('.').next().unwrap(),
            general_purpose::STANDARD_NO_PAD.encode(serde_json::to_string(&contents).unwrap()),
            access_token.split('.').skip(2).next().unwrap()
        );

        // Assert that an error is thrown when the token is attempted to
        // be verified
        let verified_info = svc.verify_access_token(&new_token, date);
        let Err(Error::InvalidToken) = verified_info else {
            panic!("Expected {}", Error::InvalidToken);
        };
    }
}