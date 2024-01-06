use std::{backtrace::Backtrace, fmt::Display};

use axum::{response::IntoResponse, http::StatusCode, Json};
use chrono::Utc;
use serde_json::json;

pub type BoxResult<T> = std::result::Result<T, BoxError>;
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Represents a highest-level error that occured, which
/// can be sent back to the user as a response
#[derive(Debug)]
pub enum AppError {
    InternalServerError(BoxError),
    ClientError(StatusCode, String)
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        // Set the status code, and body and print the error if it's an internal server error
        let (status, body) = match &self {
            Self::InternalServerError(e) => {
                println!("{:?}: {}", e, Backtrace::capture());
                (
                    StatusCode::INTERNAL_SERVER_ERROR, 
                    Json(json!({ "error": "An internal server error has occured. Please try again."}))
                )
            },
            _ => (
                StatusCode::BAD_REQUEST, 
                Json(json!({ 
                    "timestamp": Utc::now().to_rfc3339(),
                    "error": self.to_string()  
                }))
            )
        };

        (status, body).into_response()
    }
}

impl Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InternalServerError(_) => f.write_str("An internal server error has occured"),
            Self::ClientError(_, msg) => f.write_str(msg)
        }
    }
}