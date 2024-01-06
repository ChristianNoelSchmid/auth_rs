use std::sync::Arc;

use axum::async_trait;
use chrono::{DateTime, Utc};
use derive_more::Constructor;

#[cfg(test)]
use mockall::automock;
use sqlx::SqlitePool;

use crate::{error::*, auth::services::date_time_service::DateTimeService};

use super::models::RefreshTokenStatus;

#[cfg_attr(test, automock)]
#[async_trait]
pub trait DataLayer : Send + Sync {
    async fn get_user_by_email<'a>(&'a self, email: &'a str) -> BoxResult<Option<UserByEmail>>;
    async fn create_user<'a>(&self, email: &'a str, password_hash: &'a str) -> BoxResult<i64>;
    async fn delete_user(&self, user_id: i64) -> BoxResult<()>;
    async fn add_user_refresh_token<'a>(
        &self, user_id: i64, token_str: &'a str, 
        expires_on: DateTime<Utc>, prev_token_id: Option<i64>
    )  -> BoxResult<()>;
    async fn get_refresh_token_status<'a>(&self, token_str: &'a str, current_date_time: DateTime<Utc>) -> BoxResult<RefreshTokenStatus>;
    async fn revoke_refresh_token(&self, token_id: i64) -> BoxResult<()>;
}

#[derive(Constructor)]
pub struct DbDataLayer {
    db: SqlitePool,
    date_time_service: Arc<dyn DateTimeService>
}

#[derive(Constructor)]
pub struct UserByEmail {
    pub id: i64,
    pub email_verified: bool,
    pub password_hash: String
}

#[async_trait]
impl DataLayer for DbDataLayer {
    async fn get_user_by_email<'a>(&'a self, email: &'a str) -> BoxResult<Option<UserByEmail>> {
        return match sqlx::query!(
            "SELECT id, email_verified, password_hash FROM users WHERE email = ?", 
            email
        ) 
            .fetch_optional(&self.db).await
        {
            Err(e) => Err(Box::new(e)),
            Ok(Some(row)) => Ok(Some(UserByEmail::new(row.id, row.email_verified == 1, row.password_hash))),
            Ok(None) => Ok(None)
        }
    }

    async fn create_user<'a>(&self, email: &'a str, password_hash: &'a str) -> BoxResult<i64> {
        // Get current date/time
        let now = self.date_time_service.now_utc();
        // Insert the new user into the database
        let row = sqlx::query!(
            "INSERT INTO users (email, password_hash, created_on_utc) VALUES (?, ?, ?)",
            email, password_hash, now
        )
            .execute(&self.db).await.map_err(|e| Box::new(e))?;

        // Return the id of the new user
        Ok(row.last_insert_rowid())
    }

    async fn add_user_refresh_token<'a>(
        &self, user_id: i64, token_str: &'a str, 
        expires_on: DateTime<Utc>, prev_token_id: Option<i64>
    )  -> BoxResult<()> {
        // Start a transaction
        let mut tr = self.db.begin().await?;

        // Insert the new token with the given attributes
        let new_row_id = sqlx::query!(
            "INSERT INTO refresh_tokens (user_id, token_str, expires_on) VALUES (?, ?, ?)",
            user_id, token_str, expires_on
        )
            .execute(&mut *tr).await?
            .last_insert_rowid();

        // If there is a previous token, update it's next_token_id to the new token
        if let Some(prev_token_id) = prev_token_id {
            let now = self.date_time_service.now_utc();
            sqlx::query!(
                "UPDATE refresh_tokens SET next_token_id = ?, revoked_on = ? WHERE id = ?",
                new_row_id, now, prev_token_id
            )
                .execute(&mut *tr).await?;
        }

        tr.commit().await?;

        Ok(())
    }

    async fn get_refresh_token_status<'a>(&self, token_str: &'a str, current_utc: DateTime<Utc>) -> BoxResult<RefreshTokenStatus> {
        if let Some(row) = sqlx::query!(
            "
                SELECT t.id as token_id, t.expires_on, t.revoked_on, t.next_token_id, u.id as user_id, u.email as email 
                FROM refresh_tokens t LEFT JOIN users u ON u.id = t.user_id 
                WHERE t.token_str = ?
            ", 
            token_str
        )
            .fetch_optional(&self.db).await?
        {
            // Ensure the refresh token isn't being reused.
            // Determined by whether this token has a descendent token
            if row.next_token_id.is_some() || row.revoked_on.is_some() {
                return Ok(RefreshTokenStatus::Reused(row.token_id.unwrap()));
            }
            if current_utc > row.expires_on.and_utc() {
                return Ok(RefreshTokenStatus::Stale);
            }

            return Ok(RefreshTokenStatus::Active{
                user_id: row.user_id, 
                user_email: row.email.unwrap(), 
                token_id: row.token_id.unwrap()
            });
        }

        Ok(RefreshTokenStatus::NotFound)
    }

    async fn revoke_refresh_token(&self, token_id: i64) -> BoxResult<()> {
        // Retrieve descendent refresh tokens until the latest one is found
        let mut target_token_id = token_id;
        loop {
            match sqlx::query!(
                "SELECT next_token_id FROM refresh_tokens WHERE id = ?", 
                target_token_id
            )
                .fetch_optional(&self.db).await?
                .and_then(|row| row.next_token_id)
            {
                Some(prev_token_id) => target_token_id = prev_token_id,
                None => break
            };
        }

        // Revoke the descendent refresh token
        let now = self.date_time_service.now_utc();
        sqlx::query!(
            r#"UPDATE refresh_tokens SET revoked_on = ?, revoked_by = "SERVER - DUPLICATE REFRESH" WHERE id = ?"#, 
            now, target_token_id
        )
            .execute(&self.db).await?;

        Ok(())
    }

    async fn delete_user(&self, user_id: i64) -> BoxResult<()> {
        Ok(sqlx::query!("DELETE FROM users WHERE id = ?", user_id)
            .execute(&self.db).await.and(Ok(()))?)
    }
}