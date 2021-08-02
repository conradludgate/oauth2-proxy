use chrono::Utc;
use jsonwebtoken::{decode, DecodingKey, Validation};
use rocket::{
    http::Status,
    request::{FromRequest, Outcome, Request},
    State,
};
use serde::{Deserialize, Serialize};

use crate::config::Config;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    #[serde(rename = "sub")]
    pub username: String,

    #[serde(rename = "exp", with = "chrono::serde::ts_seconds")]
    pub expires: chrono::DateTime<Utc>,
}

#[async_trait]
impl<'r> FromRequest<'r> for Claims {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let config = match request.guard::<&State<Config>>().await {
            Outcome::Success(config) => config,
            Outcome::Failure((status, ())) => return Outcome::Failure((status, "no config found")),
            Outcome::Forward(forward) => return Outcome::Forward(forward),
        };

        let key = match DecodingKey::from_base64_secret(&config.state_key) {
            Ok(key) => key,
            Err(_) => return Outcome::Failure((Status::InternalServerError, "invalid secret")),
        };

        let access_token = match request.cookies().get("access_token") {
            Some(access_token) => access_token,
            None => return Outcome::Forward(()),
        };

        match decode(access_token.value(), &key, &Validation::default()) {
            Ok(token_data) => Outcome::Success(token_data.claims),
            Err(_) => Outcome::Forward(()),
        }
    }
}
