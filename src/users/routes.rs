use std::sync::Arc;

use axum::{Router, routing::{get, delete}, extract::{State, FromRef}, http::StatusCode};

use crate::{auth::{services::{token_service::TokenService, date_time_service::DateTimeService}, AuthContext}, response::{AppResult, AppResponse}};

use super::services::user_service::{UserService, models::UserModel};

#[derive(Clone, FromRef)]
pub struct RouterState {
    pub user_service: Arc<dyn UserService>,
    pub token_service: Arc<dyn TokenService>,
    pub date_time_service: Arc<dyn DateTimeService>
}

pub fn routes(user_service: Arc<dyn UserService>, token_service: Arc<dyn TokenService>, date_time_service: Arc<dyn DateTimeService>) -> Router {
    let state = RouterState { user_service, token_service, date_time_service };
    return Router::new()
        .route("/", get(get_user))
        .route("/", delete(delete_user))
        .layer(axum::middleware::from_extractor_with_state::<AuthContext, RouterState>(state.clone()))
        .with_state(state)
}

async fn get_user(ctx: AuthContext, State(user_service): State<Arc<dyn UserService>>) -> AppResult<UserModel> {
    Ok(
        user_service.get_user(&ctx.email).await
            .and_then(|r| Ok(AppResponse::new(StatusCode::OK, r)))?
    )
}

async fn delete_user(ctx: AuthContext, State(user_service): State<Arc<dyn UserService>>) -> AppResult<()> {
    Ok(
        user_service.delete_user(&ctx.email).await
            .and_then(|()| Ok(AppResponse::new(StatusCode::OK, ())))?
    )
}