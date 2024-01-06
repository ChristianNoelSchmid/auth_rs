use std::sync::Arc;

use argon2::{Argon2, password_hash::SaltString, PasswordHasher, PasswordHash, PasswordVerifier};
use axum::async_trait;
use derive_more::Constructor;
use rand::rngs::OsRng;

use crate::auth::config::AuthServiceSettings;

use self::{error::*, models::*, data_layer::DataLayer};

use super::{token_service::TokenService, verify_email_service::VerifyEmailService, date_time_service::DateTimeService};

pub mod error;
pub mod models;
pub mod data_layer;

#[async_trait]
pub trait AuthService : Send + Sync {
    ///
    /// Attempts to register a new user with the data in the `RegisterRequest` info
    /// 
    async fn register(&self, model: RegisterRequest) -> Result<()>;
    ///
    /// Attempts to login to the server using the `email` and `password`
    /// 
    async fn login<'a>(&self, email: &'a str, password: &'a str) -> Result<AuthTokens>;
    ///
    /// Attempts to generate new auth tokens given the `refresh_token`
    /// 
    async fn refresh<'a>(&self, refresh_token: &'a str) -> Result<AuthTokens>;
}

///
/// Core implementation for AuthService
/// 
#[derive(Constructor)]
pub struct CoreAuthService<'s> {
    ///
    /// The DataLayer, which handles Auth database connections
    /// 
    data_layer: Arc<dyn DataLayer>,
    ///
    /// The EmailVerifyService for generation and messaging of verification token
    /// 
    email_verify_service: Arc<dyn VerifyEmailService>,
    ///
    /// The TokenService for generation of auth tokens
    /// 
    token_service: Arc<dyn TokenService>,    
    ///
    /// The DateTimeService for generating current DateTimes
    /// 
    date_time_service: Arc<dyn DateTimeService>,
    ///
    /// JWT settings for generation of JWTs
    /// 
    jwt_settings: &'s AuthServiceSettings
}

#[async_trait]
impl<'s> AuthService for CoreAuthService<'s> {
    async fn register(&self, model: RegisterRequest) -> Result<()> {
        // Lowercase email, for comparison
        let email = model.email.to_lowercase();

        // Ensure email isn't already in use
        if let Some(_) = self.data_layer.get_user_by_email(&email).await? {
            return Err(Error::EmailInUse);
        }

        // Hash and salt the password
        let salt = SaltString::generate(&mut OsRng);
        let hash = Argon2::default().hash_password(model.password.as_bytes(), &salt).unwrap().to_string();

        // Add the new user to the database
        let user_id = self.data_layer.create_user(&email, &hash).await?;

        // Create the email verification token for the given user
        // If there's a failure in creating the verification token, delete the user
        // and return an internal server error
        if let Err(e) = self.email_verify_service.create_ver_token(user_id, &email).await {
            self.data_layer.delete_user(user_id).await?;
            return Err(Error::ServiceError(Box::new(e)));
        }

        Ok(())
    }

    async fn login<'a>(&self, email: &'a str, password: &'a str) -> Result<AuthTokens> {
        // Lowercase the email, for comparison
        let email = email.to_lowercase();
        if let Some(user) = self.data_layer.get_user_by_email(&email).await? {
            // Verify the password with the row's password hash
            let hash = PasswordHash::new(&user.password_hash).unwrap();
            if let Err(_) = Argon2::default().verify_password(password.as_bytes(), &hash) {
                return Err(Error::AuthenticationFailed);
            } 

            // Ensure that the email has been verified
            // Generate a new token and return error to the client if not
            if !user.email_verified {
                self.email_verify_service.create_ver_token(user.id, &email).await?;
                return Err(Error::EmailNotVerified);
            }

            // Generate the access and refresh token, and the date the refresh token expires
            let now = self.date_time_service.now_utc();
            let access_token = self.token_service.gen_access_token(&email, now)?;
            let refr_token_str = self.token_service.gen_rand_token();
            let dur = self.jwt_settings.get_refresh_token_lifetime();
            let refr_expires_on = now + dur;

            // Insert the new refresh token for the given user_id, and previous token if one was given
            self.data_layer.add_user_refresh_token(user.id, &refr_token_str, refr_expires_on, None).await?;
            
            return Ok(AuthTokens { access_token, refresh_token: refr_token_str });
        }
        Err(Error::AuthenticationFailed)
    }

    async fn refresh<'a>(&self, token_str: &'a str) -> Result<AuthTokens> {
        // Get the current date/time
        let now = self.date_time_service.now_utc();

        // Check if the refresh token exists in the database, and retrieve
        // the user associated with it
        return match self.data_layer.get_refresh_token_status(&token_str, now).await? {
            RefreshTokenStatus::NotFound => Err(Error::RefreshTokenNotFound),
            RefreshTokenStatus::Stale => Err(Error::RefreshTokenStale),
            RefreshTokenStatus::Reused(token_id) => {
                self.data_layer.revoke_refresh_token(token_id).await?;
                Err(Error::RefreshTokenReuse)
            },
            RefreshTokenStatus::Active { user_id, user_email, token_id } => {
                // Generate a new access and refresh token
                let access_token = self.token_service.gen_access_token(&user_email, now)?;
                let refresh_token = self.token_service.gen_rand_token();
                let refr_expires_on = now + self.jwt_settings.get_refresh_token_lifetime();

                self.data_layer.add_user_refresh_token(user_id, &refresh_token, refr_expires_on, Some(token_id)).await?;

                Ok(AuthTokens { access_token, refresh_token })
            }
        };
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
    use chrono::NaiveDateTime;
    use mockall::predicate::{eq, ne, always};
    use rand::rngs::OsRng;

    use crate::auth::{services::{auth_service::{data_layer::MockDataLayer, CoreAuthService, models::RegisterRequest, AuthService, error::Error}, verify_email_service::MockVerifyEmailService, token_service::CoreTokenService, date_time_service::{CoreDateTimeService, MockDateTimeService}}, config::AuthServiceSettings};

    use super::{data_layer::UserByEmail, models::RefreshTokenStatus};

    lazy_static::lazy_static! {
        static ref AUTH_SERVICE_SETTINGS: AuthServiceSettings = AuthServiceSettings::new(
            String::from("test_audience"), String::from("test_issuer"),
            String::from("0.00:00:05"), String::from("0.00:00:05")
        );
    }

    #[tokio::test]
    async fn test_successful_register() {
        let mut mock_dl = MockDataLayer::new();
        let mut mock_ves = MockVerifyEmailService::new();
        // Get user by email should return Ok(None) when "tester@mail.com" is provided
        // meaning that there is not yet any user with that email
        mock_dl.expect_get_user_by_email().with(eq("tester@mail.com"))
            .once().returning(|_| Ok(None));
        // Create user should never include the raw password (it should be the password hash)
        mock_dl.expect_create_user().with(eq("tester@mail.com"), ne("password"))
            .once().returning(|_,_| Ok(1));
        // Create verification token should return Ok when supplied the new user ID
        mock_ves.expect_create_ver_token().with(eq(1), eq("tester@mail.com"))
            .once().returning(|_,_| Ok(()));

        let svc = CoreAuthService::new(
            Arc::new(mock_dl), Arc::new(mock_ves), 
            Arc::new(CoreTokenService::new(&AUTH_SERVICE_SETTINGS)),
            Arc::new(CoreDateTimeService::new()), &AUTH_SERVICE_SETTINGS
        );

        let res = svc.register(
            RegisterRequest::new(String::from("tester@mail.com"), String::from("password"))
        )
            .await;
        
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_register_with_email_already_in_use() {
        //! Testing registration attempt with email already being used
        //! Should return Error::EmailInUse
        let mut mock_dl = MockDataLayer::new();

        mock_dl.expect_get_user_by_email().with(eq("tester@mail.com"))
            .times(2).returning(|_| Ok(Some(UserByEmail::new(1, true, String::from("hash")))));

        let svc = CoreAuthService::new(
            Arc::new(mock_dl), Arc::new(MockVerifyEmailService::new()), 
            Arc::new(CoreTokenService::new(&AUTH_SERVICE_SETTINGS)),
            Arc::new(CoreDateTimeService::new()), &AUTH_SERVICE_SETTINGS
        );

        let res = svc.register(RegisterRequest::new(String::from("tester@mail.com"), String::from("password"))).await;
        let Err(Error::EmailInUse) = res else { 
            panic!("Returned error is not `Error::EmailInUse`"); 
        };

        let res = svc.register(RegisterRequest::new(String::from("tEsTeR@mAiL.cOm"), String::from("password"))).await;
        let Err(Error::EmailInUse) = res else { 
            panic!("Returned error is not `Error::EmailInUse`"); 
        };
    }

    #[tokio::test]
    async fn test_login_with_incorrect_password() {
        //! Testing registration attempt with incorrect password
        //! Should return Error::AuthenticationFailed
        let mut mock_dl = MockDataLayer::new();
        let salt = SaltString::generate(&mut OsRng);

        // Create a password hash for the password: "password", for the mock method
        let hash = Argon2::default().hash_password("password".as_bytes(), &salt).unwrap().to_string();

        mock_dl.expect_get_user_by_email().with(eq("tester@mail.com"))
            .once().returning(move |_| Ok(Some(UserByEmail::new(1, false, hash.clone()))));

        let svc = CoreAuthService::new(
            Arc::new(mock_dl), Arc::new(MockVerifyEmailService::new()), 
            Arc::new(CoreTokenService::new(&AUTH_SERVICE_SETTINGS)),
            Arc::new(CoreDateTimeService::new()), &AUTH_SERVICE_SETTINGS
        );

        let res = svc.login("tester@mail.com", "incorrect_password").await;
        let Err(Error::AuthenticationFailed) = res else {
            panic!("Returned error is not `{}`", Error::AuthenticationFailed); 
        };
    }

    #[tokio::test]
    async fn test_login_with_email_not_verified() {
        //! Testing registration attempt with email not verified
        //! Should return Error::EmailNotVerified
        let mut mock_dl = MockDataLayer::new();
        let mut mock_ves = MockVerifyEmailService::new();
        let salt = SaltString::generate(&mut OsRng);

        // Create a password hash for the password: "password", for the mock method
        let hash = Argon2::default().hash_password("password".as_bytes(), &salt).unwrap().to_string();

        mock_dl.expect_get_user_by_email().with(eq("tester@mail.com"))
            .times(2).returning(move |_| Ok(Some(UserByEmail::new(1, false, hash.clone()))));
        mock_ves.expect_create_ver_token().with(eq(1), eq("tester@mail.com")).times(2).returning(|_,_| Ok(()));

        let svc = CoreAuthService::new(
            Arc::new(mock_dl), Arc::new(mock_ves), 
            Arc::new(CoreTokenService::new(&AUTH_SERVICE_SETTINGS)),
            Arc::new(CoreDateTimeService::new()), &AUTH_SERVICE_SETTINGS
        );

        let res = svc.login("tester@mail.com", "password").await;
        let Err(Error::EmailNotVerified) = res else {
            panic!("Returned error is not `{}`", Error::EmailNotVerified); 
        };

        let res = svc.login("tEsTeR@mAiL.CoM", "password").await;
        let Err(Error::EmailNotVerified) = res else {
            panic!("Returned error is not `{}`", Error::EmailNotVerified); 
        };
    }

    #[tokio::test]
    async fn test_login_successful() {
        //! Testing login attempt with correct email and password
        //! Should return Ok
        let mut mock_dl = MockDataLayer::new();
        let mock_ves = MockVerifyEmailService::new();
        let mut mock_dts = MockDateTimeService::new();
        let salt = SaltString::generate(&mut OsRng);

        // Create a password hash for the password: "password", for the mock method
        let hash = Argon2::default().hash_password("password".as_bytes(), &salt).unwrap().to_string();

        // Static date for MockDateTimeService: 2023-05-10 16:00
        let date = NaiveDateTime::from_timestamp_millis(1683748800000).unwrap().and_utc();

        mock_dl.expect_get_user_by_email().with(eq("tester@mail.com"))
            .once().returning(move |_| Ok(Some(UserByEmail::new(1, true, hash.clone()))));
        mock_dl.expect_add_user_refresh_token().with(
            eq(1), always(), 
            eq(date + AUTH_SERVICE_SETTINGS.get_refresh_token_lifetime()),
            eq(None)
        )
            .once().returning(|_,_,_,_| Ok(()));

        mock_dts.expect_now_utc().once().returning(move || date.clone());

        let svc = CoreAuthService::new(
            Arc::new(mock_dl), Arc::new(mock_ves), 
            Arc::new(CoreTokenService::new(&AUTH_SERVICE_SETTINGS)),
            Arc::new(mock_dts), &AUTH_SERVICE_SETTINGS
        );

        let res = svc.login("tester@mail.com", "password").await;
        let Ok(_) = res else {
            panic!("Returned value is not `Ok`, instead is `{:?}`", res.unwrap_err());
        };
    }

    #[tokio::test]
    async fn test_refresh_token_not_found() {
        //! Testing Refresh with refresh token not in database.
        //! Should return Error::RefreshTokenNotFound
        let mut mock_dl = MockDataLayer::new();
        let mut mock_dts = MockDateTimeService::new();
        // Static date for MockDateTimeService: 2023-05-10 16:00
        let date = NaiveDateTime::from_timestamp_millis(1683748800000).unwrap().and_utc();

        mock_dl.expect_get_refresh_token_status().with(eq("token_str"), eq(date))
            .once().returning(move |_,_| Ok(RefreshTokenStatus::NotFound));
        mock_dts.expect_now_utc().once().returning(move || date.clone());

        let svc = CoreAuthService::new(
            Arc::new(mock_dl), Arc::new(MockVerifyEmailService::new()), 
            Arc::new(CoreTokenService::new(&AUTH_SERVICE_SETTINGS)),
            Arc::new(mock_dts), &AUTH_SERVICE_SETTINGS
        );

        let res = svc.refresh("token_str").await;
        let Err(Error::RefreshTokenNotFound) = res else {
            panic!("Returned error is not `{}`", Error::RefreshTokenNotFound); 
        };
    }

    #[tokio::test]
    async fn test_refresh_token_stale() {
        //! Testing Refresh with refresh token stale
        //! Should return Error::RefreshTokenStale
        let mut mock_dl = MockDataLayer::new();
        let mut mock_dts = MockDateTimeService::new();
        // Static date for MockDateTimeService: 2023-05-10 16:00
        let date = NaiveDateTime::from_timestamp_millis(1683748800000).unwrap().and_utc();

        mock_dl.expect_get_refresh_token_status().with(eq("token_str"), eq(date))
            .once().returning(move |_,_| Ok(RefreshTokenStatus::Stale));
        mock_dts.expect_now_utc().once().returning(move || date.clone());

        let svc = CoreAuthService::new(
            Arc::new(mock_dl), Arc::new(MockVerifyEmailService::new()), 
            Arc::new(CoreTokenService::new(&AUTH_SERVICE_SETTINGS)),
            Arc::new(mock_dts), &AUTH_SERVICE_SETTINGS
        );

        let res = svc.refresh("token_str").await;
        let Err(Error::RefreshTokenStale) = res else {
            panic!("Returned error is not `{}`", Error::RefreshTokenStale); 
        };
    }

    #[tokio::test]
    async fn test_refresh_token_reused() {
        //! Testing Refresh with reused token
        //! Should return Error::RefreshTokenReuse
        let mut mock_dl = MockDataLayer::new();
        let mut mock_dts = MockDateTimeService::new();
        // Static date for MockDateTimeService: 2023-05-10 16:00
        let date = NaiveDateTime::from_timestamp_millis(1683748800000).unwrap().and_utc();

        mock_dl.expect_get_refresh_token_status().with(eq("token_str"), eq(date))
            .once().returning(move |_,_| Ok(RefreshTokenStatus::Reused(1)));
        mock_dl.expect_revoke_refresh_token().with(eq(1)).once().returning(|_| Ok(()));
        mock_dts.expect_now_utc().once().returning(move || date.clone());

        let svc = CoreAuthService::new(
            Arc::new(mock_dl), Arc::new(MockVerifyEmailService::new()), 
            Arc::new(CoreTokenService::new(&AUTH_SERVICE_SETTINGS)),
            Arc::new(mock_dts), &AUTH_SERVICE_SETTINGS
        );

        let res = svc.refresh("token_str").await;
        let Err(Error::RefreshTokenReuse) = res else {
            panic!("Returned error is not `{}`", Error::RefreshTokenReuse); 
        };
    }

    #[tokio::test]
    async fn test_refresh_success() {
        //! Testing successful Refresh, with good token
        //! Should return Ok(())
        let mut mock_dl = MockDataLayer::new();
        let mut mock_dts = MockDateTimeService::new();
        // Static date for MockDateTimeService: 2023-05-10 16:00
        let date = NaiveDateTime::from_timestamp_millis(1683748800000).unwrap().and_utc();

        mock_dl.expect_get_refresh_token_status().with(eq("token_str"), eq(date))
            .once().returning(move |_,_| Ok(RefreshTokenStatus::Active { 
                user_id: 1, 
                user_email: String::from("tester@mail.com"), 
                token_id: 3 
            }));
        mock_dl.expect_add_user_refresh_token().with(
            eq(1), always(), 
            eq(date + AUTH_SERVICE_SETTINGS.get_refresh_token_lifetime()),
            eq(Some(3))
        )
            .once().returning(|_,_,_,_| Ok(()));
        mock_dts.expect_now_utc().once().returning(move || date.clone());

        let svc = CoreAuthService::new(
            Arc::new(mock_dl), Arc::new(MockVerifyEmailService::new()), 
            Arc::new(CoreTokenService::new(&AUTH_SERVICE_SETTINGS)),
            Arc::new(mock_dts), &AUTH_SERVICE_SETTINGS
        );

        let res = svc.refresh("token_str").await;
        let Ok(_) = res else {
            panic!("Returned value is not `Ok`, instead is `{:?}`", res.unwrap_err()); 
        };
    }
}