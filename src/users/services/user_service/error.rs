use axum::http::StatusCode;
use thiserror::Error;

use crate::error::{BoxError, AppError};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    DataLayerError(BoxError),
    #[error("The user with the given email `{0}` could not be found")]
    UserEmailDoesNotExist(String),
}

impl From<crate::error::BoxError> for Error {
    fn from(value: crate::error::BoxError) -> Self {
        Error::DataLayerError(value)
    }
}

impl From<Error> for AppError {
    fn from(value: Error) -> Self {
        match value { 
            Error::DataLayerError(e) => AppError::InternalServerError(e),
            e => AppError::ClientError(StatusCode::BAD_REQUEST, e.to_string())
        }
    }
}