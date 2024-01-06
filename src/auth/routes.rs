use std::sync::Arc;

use axum::{Router, routing::{post, get}, extract::{Query, FromRef, State}, Json, http::StatusCode};

use serde::Deserialize;
use tower_cookies::{Cookies, Cookie, cookie::time::OffsetDateTime, CookieManagerLayer};

use crate::response::{AppResponse, AppResult};
use super::super::error::AppError;

use super::services::{auth_service::{AuthService, models::{RegisterRequest, LoginRequest}}, verify_email_service::VerifyEmailService};

#[derive(Clone, FromRef)]
struct RouterState {
    auth_service: Arc<dyn AuthService>,
    verify_email_service: Arc<dyn VerifyEmailService>
}

pub fn routes(auth_service: Arc<dyn AuthService>, verify_email_service: Arc<dyn VerifyEmailService>) -> Router {
    return Router::new()
        .route("/register", post(register)) 
        .route("/verify-email", get(verify_email))
        .route("/login", post(login))
        .route("/refresh", post(refresh))
        .route("/logout", post(logout))
        .layer(CookieManagerLayer::new())
        .with_state(RouterState { auth_service, verify_email_service });
}

async fn register(
    State(auth_service): State<Arc<dyn AuthService>>, 
    Json(model): Json<RegisterRequest>
) -> AppResult<&'static str> {
    auth_service.register(model).await?;
    Ok(AppResponse::new(StatusCode::CREATED, "Registeration successful. Please check your email and verify."))
}

async fn login(
    State(auth_service): State<Arc<dyn AuthService>>,
    cookies: Cookies,
    Json(model): Json<LoginRequest>,
) -> AppResult<String> {
    Ok(
        auth_service.login(&model.email, &model.password).await.and_then(|r| {
            let cookie = Cookie::build(("refresh-token", r.refresh_token))
                .http_only(true)
                .permanent()
                .build();

            cookies.add(cookie);
            Ok(AppResponse::new(StatusCode::OK, r.access_token))
        })?
    )
}

async fn refresh(
    State(auth_service): State<Arc<dyn AuthService>>,
    cookies: Cookies 
) -> AppResult<String> {
    let refresh_token = cookies.get("refresh-token").and_then(|c| Some(c.value().to_string()));
    return match refresh_token {
        Some(refresh_token) => {
            Ok(
                auth_service.refresh(&refresh_token).await.and_then(|r| {
                    // Build the cookie from the refresh token
                    let cookie = Cookie::build(("refresh-token", r.refresh_token))
                        .http_only(true)
                        .permanent()
                        .build();

                    cookies.add(cookie);
                    Ok(AppResponse::new(StatusCode::OK, r.access_token))
                })?
            )
        },
        None => Err(AppError::ClientError(StatusCode::BAD_REQUEST, String::from("Refresh Token not provided")))
    }
}

async fn logout(cookies: Cookies) {
    cookies.add(Cookie::build(("refresh-token", "")).expires(OffsetDateTime::now_utc()).build());
}

#[derive(Deserialize)]
struct VerifyEmailModel {
    verify_token: String
}

async fn verify_email(
    verify_email_model: Query<VerifyEmailModel>,
    State(verify_email_service): State<Arc<dyn VerifyEmailService>>,
) -> AppResult<&'static str> {
    Ok(
        verify_email_service.verify_token(verify_email_model.verify_token.to_string()).await
            .and_then(|()| Ok(AppResponse::new(StatusCode::OK, "Email verified, thanks!")))?
    )
}