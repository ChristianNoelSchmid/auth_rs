pub mod data_layer;
pub mod error;
pub mod models;

use axum::async_trait;
use derive_more::Constructor;
use self::error::*;
use self::data_layer::DataLayer;
use self::models::UserModel;

#[async_trait]
pub trait UserService : Send + Sync {
    async fn get_user(&self, email: &str) -> Result<UserModel>;
    async fn delete_user(&self, email: &str) -> Result<()>;
}

#[derive(Constructor)]
pub struct CoreUserService<DL : DataLayer> {
    data_layer: DL
}

#[async_trait]
impl<DL : DataLayer> UserService for CoreUserService<DL> {
    async fn get_user(&self, email: &str) -> Result<UserModel> {
        return match self.data_layer.get_user_by_email(&email).await? {
            Some(dto) => Ok(UserModel::new(email.to_string(), dto.timestamp_millis())),
            None => Err(Error::UserEmailDoesNotExist(email.to_string()))
        };
    }
    async fn delete_user(&self, email: &str) -> Result<()> {
        return match self.data_layer.delete_user_by_email(&email).await? {
            true => Ok(()),
            false => Err(Error::UserEmailDoesNotExist(email.to_string()))
        };
    }
}