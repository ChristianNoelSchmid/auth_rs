use std::sync::Arc;

use auth_rs::{auth::{config::Config, services::{token_service::CoreTokenService, auth_service::{CoreAuthService, self}, date_time_service::CoreDateTimeService, verify_email_service::{CoreEmailVerifyService, self}, send_email_service}}, users::services::user_service::{self, CoreUserService}};
use axum::Router;
use dotenvy::{self, var};

use lazy_static::lazy_static;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

lazy_static! {
    static ref CONFIG: Config = Config::from_file("./config.json").expect("`config.json` could not be found in working directory");
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "rust-auth-server=debug".into())
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let db_pool = sqlx::SqlitePool::connect(&var("DATABASE_URL")?).await?;

    let date_time_service = Arc::new(CoreDateTimeService::new());
    let token_service = Arc::new(CoreTokenService::new(&CONFIG.auth_service_settings));

    let send_email_service = Arc::new(send_email_service::CoreSendEmailService::new(&CONFIG.send_email_service_settings));

    let verify_email_data_layer = Arc::new(verify_email_service::data_layer::DbDataLayer::new(db_pool.clone()));
    let verify_email_service = Arc::new(CoreEmailVerifyService::new(token_service.clone(), verify_email_data_layer, send_email_service));

    let auth_data_layer = Arc::new(auth_service::data_layer::DbDataLayer::new(db_pool.clone(), date_time_service.clone()));
    let auth_service = Arc::new(CoreAuthService::new(auth_data_layer, verify_email_service.clone(), token_service.clone(), date_time_service.clone(), &CONFIG.auth_service_settings));

    let user_data_layer = user_service::data_layer::DbDataLayer::new(db_pool);
    let user_service = Arc::new(CoreUserService::new(user_data_layer));

    let app = Router::new()
        .nest("/auth", auth_rs::auth::routes::routes(auth_service, verify_email_service))
        .nest("/user", auth_rs::users::routes::routes(user_service, token_service, date_time_service));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    axum::serve(listener, app).await?;

    Ok(())
}

