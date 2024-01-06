use std::sync::Arc;

use axum::async_trait;
use derive_more::Constructor;

#[cfg(test)]
use mockall::automock;

use self::{data_layer::*, error::*};

use super::{token_service::TokenService, send_email_service::SendEmailService};

pub mod error;
pub mod data_layer;

#[cfg_attr(test, automock)]
#[async_trait]
pub trait VerifyEmailService : Send + Sync {
    /// Creates a new verification token, and outputs the token URL
    /// 
    /// # Arguments
    /// 
    /// * `user_id`: the ID of the user the token is being created for
    /// * `email`: the email address of the user the token is being created for
    /// 
    async fn create_ver_token<'a>(&self, user_id: i64, email: &'a str) -> Result<()>;
    async fn verify_token(&self, token_str: String) -> Result<()>; 
}

#[derive(Constructor)]
pub struct CoreEmailVerifyService {
    token_service: Arc<dyn TokenService>,
    data_layer: Arc<dyn DataLayer>,
    send_email_service: Arc<dyn SendEmailService>
}

#[async_trait]
impl VerifyEmailService for CoreEmailVerifyService {
    async fn create_ver_token<'a>(&self, user_id: i64, email: &'a str) -> Result<()> {
        // Generate random tokens and attempt to insert into the database.
        // Continue until a unique one is added 
        // (probably on the first attempt, but it is technically possible)
        while {
            let token_str = self.token_service.gen_rand_token();
            let res = self.data_layer.add_token(user_id, &token_str).await?;

            if res {
                self.send_email_service.send_verify_email(email, &token_str).await?;
            }

            !res
        } {}

        Ok(())
    }
    async fn verify_token(&self, token_str: String) -> Result<()> {
        return match self.data_layer.verify_token(&token_str).await? {
            Some(_) => Ok(()),
            None => Err(Error::VerificationTokenNotFound)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use mockall::{predicate::{eq, always}, Sequence};

    use crate::auth::{
        config::AuthServiceSettings,
        services::{
            token_service::CoreTokenService,
            verify_email_service::{CoreEmailVerifyService, data_layer::MockDataLayer, VerifyEmailService, error::Error}, send_email_service::MockSendEmailService
        }
    };

    lazy_static::lazy_static! {
        static ref AUTH_SERVICE_SETTINGS: AuthServiceSettings 
            = AuthServiceSettings::new(
                "test_audience".to_string(), 
                "test_issuer".to_string(), 
                "0.00:00:05".to_string(), 
                "0.00:00:05".to_string()
            );
    }

    #[tokio::test]
    async fn test_successful_verify_token() {
        let mut dl_mock = MockDataLayer::new();

        // Expect DataLayer::verify_token to be called once, with argument "token"
        dl_mock.expect_verify_token()
            .with(eq("token".to_string()))
            .times(1).returning(|_token_str| Ok(Some(10)));

        let service = CoreEmailVerifyService::new(
            Arc::new(CoreTokenService::new(&AUTH_SERVICE_SETTINGS)),
            Arc::new(dl_mock), Arc::new(MockSendEmailService::new())
        );

        assert!(service.verify_token("token".to_string()).await.is_ok());
    }

    #[tokio::test]
    async fn test_successful_add_token() {
        let mut dl_mock = MockDataLayer::new();
        let mut ses_mock = MockSendEmailService::new();

        dl_mock.expect_add_token()
            .with(eq(1), always())
            .times(1).returning(|_, _| Ok(true));

        ses_mock.expect_send_verify_email().with(eq("addr@mail.com"), always())
            .once().returning(|_,_| Ok(()));

        let service = CoreEmailVerifyService::new(
            Arc::new(CoreTokenService::new(&AUTH_SERVICE_SETTINGS)), 
            Arc::new(dl_mock), 
            Arc::new(ses_mock)
        );

        assert!(service.create_ver_token(1, "addr@mail.com").await.is_ok());
    }

    #[tokio::test]
    async fn test_add_token_duplicate_token() {
        let mut dl_mock = MockDataLayer::new();
        let mut ses_mock = MockSendEmailService::new();

        let mut seq = Sequence::new();

        // The first add attempt replicates a non-unique token error, which should
        // result in the service repeating the process
        // (this can techincally be run as many times as wanted, since it will always
        // queue the service to try again, but once() is sufficient for testing)
        dl_mock.expect_add_token()
            .with(eq(1), always()).once()
            .returning(|_, _tkn| { /* println!("{:?}", tkn); */ Ok(false) })
            .in_sequence(&mut seq);

        // The second attempt replicates a success, at which point the service
        // completes
        dl_mock.expect_add_token()
            .with(eq(1), always()).once()
            .returning(|_, _tkn| { /* println!("{:?}", tkn); */ Ok(true) })
            .in_sequence(&mut seq);
        
        ses_mock.expect_send_verify_email().with(eq("addr@mail.com"), always())
            .once().returning(|_,_| Ok(()));

        let service = CoreEmailVerifyService::new(
            Arc::new(CoreTokenService::new(&AUTH_SERVICE_SETTINGS)), 
            Arc::new(dl_mock), 
            Arc::new(ses_mock)
        );

        assert!(service.create_ver_token(1, "addr@mail.com").await.is_ok());
    }

    #[tokio::test]
    async fn test_data_layer_db_error_returns_internal_server_error() {
        let mut dl_mock = MockDataLayer::new();

        dl_mock.expect_add_token()
            .with(always(), always()).once()
            .returning(|_, _| Err(Error::DataLayerError(Box::new(sqlx::error::Error::WorkerCrashed))));

        dl_mock.expect_verify_token()
            .with(always()).once()
            .returning(|_| Err(Error::DataLayerError(Box::new(sqlx::error::Error::WorkerCrashed))));

        let service = CoreEmailVerifyService::new(
            Arc::new(CoreTokenService::new(&AUTH_SERVICE_SETTINGS)),
            Arc::new(dl_mock), 
            Arc::new(MockSendEmailService::new())
        );

        assert!(service.create_ver_token(1, "addr@mail.com").await.is_err());
        assert!(service.verify_token("token".to_string()).await.is_err());
    }
}