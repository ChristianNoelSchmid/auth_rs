use sendgrid::SendgridError;
use thiserror::Error;

use crate::error::BoxError;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    InternalServerError(BoxError)
}

impl From<SendgridError> for Error {
    fn from(value: SendgridError) -> Self {
        Error::InternalServerError(Box::new(value))
    }
}