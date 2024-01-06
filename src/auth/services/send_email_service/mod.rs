use std::env;

use axum::async_trait;
use derive_more::Constructor;

#[cfg(test)]
use mockall::automock;
use sendgrid::v3::{Personalization, Email, Message, Content, Sender};

use crate::auth::config::SendEmailServiceSettings;

use self::error::*;
pub mod error;


#[cfg_attr(test, automock)]
#[async_trait]
pub trait SendEmailService : Send + Sync {
    async fn send_verify_email<'a>(&self, email_addr: &'a str, token_str: &'a str) -> Result<()>;
}

#[derive(Constructor)]
pub struct CoreSendEmailService {
    settings: &'static SendEmailServiceSettings
}

#[async_trait]
impl SendEmailService for CoreSendEmailService {
    async fn send_verify_email<'a>(&self, email_addr: &'a str, token_str: &'a str) -> Result<()> {

    let p = Personalization::new(Email::new(email_addr));

    let m = Message::new(Email::new(&self.settings.from_email_addr))
        .set_subject("Please verify your email")
        .add_content(
            Content::new()
                .set_content_type("text/html")
                .set_value(format!(r"
                <p>Hello! Thanks for registering with christianssoftware.com!</a>
                <p>Please <a href='{}/auth/verify-email?verify_token={}'>click here</a> to verify your email.</p>
            ", 
            &self.settings.base_url, token_str)),
        )
            .add_personalization(p);

        let api_key = env::var("SENDGRID_API_KEY").unwrap();
        let sender = Sender::new(api_key);
        sender.send(&m).await?;
        Ok(())
    }
}