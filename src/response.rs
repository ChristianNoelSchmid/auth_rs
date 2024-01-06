use axum::{http::StatusCode, response::IntoResponse, Json};
use chrono::Utc;
use derive_more::Constructor;
use serde::Serialize;
use serde_json::json;

use crate::error::AppError;

pub type AppResult<T> = std::result::Result<AppResponse<T>, AppError>;

#[derive(Constructor)]
pub struct AppResponse<T : Serialize> {
    status_code: StatusCode,
    value: T
}

impl<T : Serialize> IntoResponse for AppResponse<T> {
    fn into_response(self) -> axum::response::Response {
        match serde_json::to_string(&self.value) {
            Ok(model_str) => (
                self.status_code,
                Json(json!({
                    "timestamp": Utc::now().to_rfc3339(),
                    "model": model_str
                }))
            )
                .into_response(),
            Err(e) => AppError::InternalServerError(Box::new(e)).into_response()
        }
    }
}