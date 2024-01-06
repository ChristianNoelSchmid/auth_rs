use std::{fs, path::Path};

use anyhow::Error;
use chrono::Duration;
use derive_more::Constructor;
use lazy_static::lazy_static;
use regex::Regex;
use serde::Deserialize;

lazy_static! {
    static ref DURATION_REGEX: Regex = Regex::new(r"^(\d+).(\d{2}):(\d{2}):(\d{2})").unwrap();
}

#[derive(Deserialize)]
pub struct Config {
    pub auth_service_settings: AuthServiceSettings,
    pub send_email_service_settings: SendEmailServiceSettings
}

impl Config {
    pub fn from_file(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        Ok(serde_json::from_str(&fs::read_to_string(path)?)?)
    }
}

#[derive(Constructor, Deserialize)]
pub struct AuthServiceSettings {
    pub audience: String,
    pub issuer: String,
    access_token_lifetime: String,
    refr_token_lifetime: String,
}

impl AuthServiceSettings {
    pub fn get_access_token_lifetime(&self) -> Duration {
        match self.parse_dur(&self.access_token_lifetime) {
            Ok(dur) => dur,
            Err(e) => panic!("{:?}", e)
        }
    }  
    pub fn get_refresh_token_lifetime(&self) -> Duration {
        match self.parse_dur(&self.refr_token_lifetime) {
            Ok(dur) => dur,
            Err(e) => panic!("{:?}", e)
        }
    }

    fn parse_dur(&self, dur_str: &str) -> anyhow::Result<Duration> {
        let captures = DURATION_REGEX.captures(dur_str)
            .and_then(|c| Some(c.extract()));

        if let Some(captures) = captures {
            let (_, [days, hours, minutes, seconds]) = captures;
            let (days, hours, minutes, seconds) = (
                days.parse::<i64>()?, 
                hours.parse::<i64>()?,
                minutes.parse::<i64>()?,
                seconds.parse::<i64>()?
            );

            return Ok(Duration::seconds(seconds + minutes * 60 + hours * 3600 + days * 86400));
        }

        Err(Error::msg("Could not parse expression"))
    }
}

#[derive(Constructor, Deserialize)]
pub struct SendEmailServiceSettings {
    pub base_url: String,
    pub from_email_addr: String
}