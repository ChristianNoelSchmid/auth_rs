use axum::async_trait;
use derive_more::Constructor;
use sqlx::{SqlitePool, error::ErrorKind};

#[cfg(test)]
use mockall::automock;

use super::error::*;

#[cfg_attr(test, automock)]
#[async_trait]
pub trait DataLayer : Send + Sync {
    ///
    /// Adds the given `user_id` and `token_str` to the verification table.
    /// Returns true if successful, or false if the token was already found in the table.
    /// 
    async fn add_token<'a>(&self, user_id: i64, token_str: &'a str) -> Result<bool>;
    async fn verify_token<'a>(&self, token_str: &'a str) -> Result<Option<i64>>;
}

#[derive(Constructor)]
pub struct DbDataLayer {
    db: SqlitePool
}

#[async_trait]
impl DataLayer for DbDataLayer {
    async fn add_token<'a>(&self, user_id: i64, token_str: &'a str) -> Result<bool> {
        // Attempt to add the user_id and token_str to the database
        return match sqlx::query!(
            "INSERT INTO email_verifications (user_id, token_str) VALUES (?, ?)",
            user_id, token_str
        )
            .execute(&self.db).await
        {
            // If there is a unique violation database error, 
            // return Ok(false) to signify that the insertion connected, but was unsuccessful.
            Err(sqlx::Error::Database(e)) if e.kind() == ErrorKind::UniqueViolation => Ok(false),
            Err(e) => Err(e)?,
            Ok(_) => Ok(true)
        }
    }
    async fn verify_token<'a>(&self, token_str: &'a str) -> Result<Option<i64>> {
        // Retreive the row that has the matching token_str
        return match sqlx::query!(
            "SELECT user_id FROM email_verifications WHERE token_str = ?", 
            token_str
        )
            .fetch_one(&self.db).await
        {
            Err(sqlx::Error::RowNotFound) => Ok(None),
            Err(e) => Err(Error::DataLayerError(Box::new(e))),
            Ok(row) => {
                // Start a transaction
                let mut tr = self.db.begin().await?;

                // Set the user's verification status to 1
                sqlx::query!(
                    "UPDATE users SET email_verified = 1 WHERE id = ?",
                    row.user_id
                )
                    .execute(&mut *tr).await?;

                // Delete all email_verification rows from the database pertaining
                // to the given user_id
                sqlx::query!(
                    "DELETE FROM email_verifications WHERE user_id = ?", 
                    row.user_id
                )
                    .execute(&mut *tr).await?;    

                // Commit the transaction
                tr.commit().await?;     

                Ok(Some(row.user_id))
            }
        };
    }
}