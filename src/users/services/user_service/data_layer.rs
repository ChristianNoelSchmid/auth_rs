use axum::async_trait;
use chrono::{Utc, DateTime};
use derive_more::Constructor;
use sqlx::SqlitePool;

use crate::error::BoxResult;

#[async_trait]
pub trait DataLayer : Send + Sync {
    async fn get_user_by_email(&self, email: &str) -> BoxResult<Option<DateTime<Utc>>>;
    async fn delete_user_by_email(&self, email: &str) -> BoxResult<bool>;
}

#[derive(Constructor)]
pub struct DbDataLayer {
    db: SqlitePool
}

#[async_trait]
impl DataLayer for DbDataLayer {
    async fn get_user_by_email(&self, email: &str) -> BoxResult<Option<DateTime<Utc>>> {
        Ok(
            sqlx::query!("SELECT created_on_utc FROM users WHERE email = ?", email)
                .fetch_optional(&self.db).await
                .map_err(|e| Box::new(e))?
                .and_then(|row| Some(row.created_on_utc.and_utc()))
        )
    }

    async fn delete_user_by_email(&self, email: &str) -> BoxResult<bool> {
        Ok(
            sqlx::query!("DELETE FROM users WHERE email = ?", email)
                .execute(&self.db).await
                .map_err(|e| Box::new(e))?
                .rows_affected() == 1
        )
    }
}