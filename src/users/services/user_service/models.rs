use axum::{response::IntoResponse, Json, http::StatusCode};
use derive_more::Constructor;
use serde::Serialize;
use serde_json::json;

#[derive(Constructor, Serialize)]
pub struct UserModel {
    email: String,
    created_on_epoch_ms: i64
}

impl IntoResponse for UserModel {
    fn into_response(self) -> axum::response::Response {
        (StatusCode::OK, Json(json!({
            "email": self.email,
            "created_on_epoch_ms": self.created_on_epoch_ms
        }))).into_response()
    }
}

#[derive(Constructor)]
pub struct DeleteUserModel;

impl IntoResponse for DeleteUserModel {
    fn into_response(self) -> axum::response::Response {
        (StatusCode::OK, Json(json!({ "msg": "User deleted" }))).into_response()
    }
}