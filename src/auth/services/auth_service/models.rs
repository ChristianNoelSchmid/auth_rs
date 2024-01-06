use axum::{response::IntoResponse, http::StatusCode, Json};
use derive_more::Constructor;
use serde::Deserialize;
use serde_json::json;

///
/// All possible statuses for a refresh token in the application
/// 
pub enum RefreshTokenStatus {
    ///
    /// The refresh token is active and valid
    /// 
    Active { user_id: i64, user_email: String, token_id: i64 },
    ///
    /// The refresh token is past its expiration date
    /// 
    Stale,
    ///
    /// The refresh token has already been used
    /// 
    Reused(i64),
    ///
    /// The refresh token was not found in the database
    /// 
    NotFound
}

#[derive(Debug)]
pub struct AuthTokens {
    pub access_token: String,
    pub refresh_token: String
}

#[derive(Constructor, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
}

#[derive(Constructor, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

pub struct RegisterSuccessResponse;
impl IntoResponse for RegisterSuccessResponse {
    fn into_response(self) -> axum::response::Response {
        (StatusCode::CREATED, Json(json!({ "msg": "User created. Please verify your email with the sent link." }))).into_response()
    }
}

pub struct AuthSuccessResponse(pub String);
impl IntoResponse for AuthSuccessResponse {
    fn into_response(self) -> axum::response::Response {
        (StatusCode::OK, Json(json!({ "msg": "Authorization successful", "access_token": self.0 }))).into_response()
    }
}

pub struct EmailVerifiedResponse;
impl IntoResponse for EmailVerifiedResponse {
    fn into_response(self) -> axum::response::Response {
        (StatusCode::OK, Json(json!({ "msg": "Email verified. Thanks!" }))).into_response()
    }
}

#[derive(Constructor)]
pub struct UserModel {
    pub id: i64,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub password_hash: Option<String>
}