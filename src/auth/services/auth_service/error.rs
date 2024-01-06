use axum::http::StatusCode;
use thiserror::Error;

use crate::{auth::services::{token_service, verify_email_service}, error::{BoxError, AppError}};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    ServiceError(BoxError),
    #[error(transparent)]
    DataLayerError(BoxError),
    #[error("Email in use")]
    EmailInUse,
    #[error("Email not found")]
    EmailNotFound,
    #[error("Email is not verified - please follow the link sent to your email to verify your email.")]
    EmailNotVerified,
    #[error("Authentication failed - please try again")]
    AuthenticationFailed,
    #[error("Refresh token not found in cookies")]
    RefreshTokenNotSet,
    #[error("The refresh token provided could not be found.")]
    RefreshTokenNotFound,
    #[error("The refresh token provided is stale.")]
    RefreshTokenStale,
    #[error("The refresh token has been reused. Descendent token revoked.")]
    RefreshTokenReuse
}

impl From<Error> for AppError {
    fn from(value: Error) -> Self {
        match value {
            Error::ServiceError(e) | Error::DataLayerError(e) => AppError::InternalServerError(e),
            Error::EmailInUse | Error::EmailNotFound => AppError::ClientError(
                StatusCode::BAD_REQUEST, 
                String::from("Authorization failed. Please try again.")
            ),
            e => AppError::ClientError(StatusCode::BAD_REQUEST, e.to_string())
        }
    }
}

impl From<BoxError> for Error {
    fn from(value: BoxError) -> Self {
        Error::DataLayerError(value)
    }
}

impl From<token_service::error::Error> for Error {
    fn from(value: token_service::error::Error) -> Self {
        Error::ServiceError(Box::new(value))
    }
}

impl From<verify_email_service::error::Error> for Error {
    fn from(value: verify_email_service::error::Error) -> Self {
        Error::ServiceError(Box::new(value))
    }
}