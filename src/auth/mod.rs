use std::sync::Arc;

use axum::{async_trait, extract::{FromRequestParts, FromRef}, http::{StatusCode, request::Parts, header}};
use lazy_static::lazy_static;
use regex::Regex;

use crate::{users::routes::RouterState, error::AppError};

use self::services::{token_service::{TokenService, self}, date_time_service::DateTimeService};

pub mod config;
pub mod services {
    pub mod auth_service;
    pub mod token_service;
    pub mod verify_email_service;
    pub mod send_email_service;
    pub mod date_time_service;
}
pub mod routes;

lazy_static! {
    static ref AUTH_HEADER_REGEX: Regex = Regex::new(r#"^(?i)bearer(?-i)\s+(?<token>\S+)$"#).unwrap();
}

/// Extractor for retrieving authorization context of the given user
pub struct AuthContext {
    pub email: String
}

#[async_trait]
impl<S> FromRequestParts<S> for AuthContext
    where 
        S: Send + Sync,
        RouterState: FromRef<S>
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // Get the RouterState from the middlewares state reference
        let state = RouterState::from_ref(state);

        // Get the authorization header from the request
        let auth_header = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok());

        // If the header exists, attempt to extract the email from the access token
        if let Some(header) = auth_header {
            return match extract_email(header, &state.token_service, &state.date_time_service) {
                // On success return AuthContext with the email
                Ok(email) => Ok(Self { email }),
                // If the token is invalid, return error
                Err(token_service::error::Error::InternalServerError(e)) => 
                    Err(AppError::InternalServerError(e)),
                // For all other errors, return the error string
                Err(e) => Err(AppError::ClientError(StatusCode::UNAUTHORIZED, e.to_string()))
            }
        }
        // If the header was not found, return error requesting the header
        return Err(AppError::ClientError(StatusCode::UNAUTHORIZED, "Access token not found. Please provide the access token in the `Authorization` header of the request".to_string()))    
    }
}

/// Parses an authorization header's access token and extracts the client's email from it
/// 
/// # Arguments
/// `auth_header`: the string of the Authorization header
/// `token_service`: the service which will parse the token
/// `date_time_service`: service which provides the current date/time
fn extract_email(auth_header: &str, token_service: &Arc<dyn TokenService>, date_time_service: &Arc<dyn DateTimeService>) -> token_service::error::Result<String> {
    if let Some(captures) = AUTH_HEADER_REGEX.captures(&auth_header) {
        let token = captures.name("token").unwrap();
        return token_service.verify_access_token(token.as_str(), date_time_service.now_utc());
    }
    return Err(token_service::error::Error::InvalidToken);
}