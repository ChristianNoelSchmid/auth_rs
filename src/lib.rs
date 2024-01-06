pub mod error;

pub mod auth;
pub mod response;
pub mod users {
    pub mod routes;

    pub mod services {
        pub mod user_service;
    }
}