use axum::{response::IntoResponse, http::StatusCode, Json};
use serde_json::json;
use thiserror::Error;

use crate::{error::{BoxError, AppError}, auth::services::send_email_service};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    ServiceError(BoxError),
    #[error(transparent)]
    DataLayerError(BoxError),
    #[error("Verification token not found")]
    VerificationTokenNotFound
}

impl From<Error> for AppError {
    fn from(value: Error) -> Self {
        match value {
            Error::ServiceError(e) | Error::DataLayerError(e) => Self::InternalServerError(e),
            Error::VerificationTokenNotFound => Self::ClientError(StatusCode::BAD_REQUEST, value.to_string())    
        }
    }
}

impl From<sqlx::Error> for Error {
    fn from(value: sqlx::Error) -> Self {
        Error::DataLayerError(Box::new(value))
    }
}

impl From<send_email_service::error::Error> for Error {
    fn from(value: send_email_service::error::Error) -> Self {
        Self::ServiceError(Box::new(value))
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> axum::response::Response {
        let (status_code, msg) = if let Error::DataLayerError(e) = self {
            println!("{:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "An internal server error occured".to_string())
        } else {
            (StatusCode::BAD_REQUEST, self.to_string())
        };

        return (status_code, Json(json!({ "error": msg }))).into_response();
    }
}