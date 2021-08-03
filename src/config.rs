use std::collections::HashMap;

use serde::Deserialize;

use crate::token::Provider;

#[inline]
fn base_url() -> oauth2::url::Url {
    oauth2::url::Url::parse("http://localhost:27228").unwrap()
}

#[inline]
const fn bcrypt_cost() -> u32 {
    12
}

#[derive(Deserialize)]
pub struct Config {
    pub state_key: String,

    #[serde(default = "bcrypt_cost")]
    pub bcrypt_cost: u32,

    #[serde(default = "base_url")]
    pub base_url: oauth2::url::Url,

    pub providers: HashMap<String, Provider>,
}
