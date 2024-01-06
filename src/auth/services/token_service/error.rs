use thiserror::Error;

use crate::error::BoxError;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    InternalServerError(BoxError),
    #[error("JWT is expired")]
    TokenExpired,
    #[error("JWT supplied is invalid")]
    InvalidToken
}

impl From<jwt::Error> for Error {
    fn from(value: jwt::Error) -> Self {
        Error::InternalServerError(Box::new(value))
    }
}