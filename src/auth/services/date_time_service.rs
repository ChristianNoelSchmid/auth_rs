use chrono::{DateTime, Utc};
use derive_more::Constructor;
use mockall::automock;

#[automock]
pub trait DateTimeService : Send + Sync {
    fn now_utc(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

#[derive(Constructor)]
pub struct CoreDateTimeService;
impl DateTimeService for CoreDateTimeService { }