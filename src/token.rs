use std::str::FromStr;

use chrono::Utc;
use rocket::request::FromParam;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub struct ID(Uuid);
impl From<ID> for Uuid {
    fn from(u: ID) -> Self {
        u.0
    }
}
#[async_trait]
impl<'a> FromParam<'a> for ID {
    type Error = <Uuid as FromStr>::Err;

    fn from_param(param: &'a str) -> Result<Self, Self::Error> {
        param.parse().map(ID)
    }
}

#[derive(FromForm)]
pub struct Data {
    pub name: String,
    pub provider_id: String,
    pub scopes: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub token_id: String,
    pub provider_id: String,
    pub scopes: Vec<String>,

    #[serde(rename = "sub")]
    pub username: String,

    #[serde(rename = "exp", with = "chrono::serde::ts_seconds")]
    pub expires: chrono::DateTime<Utc>,
}
