use std::lazy::SyncLazy;

use serde::Deserialize;

use crate::{provider::spotify::SpotifyProvider, token::Provider};

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

    pub spotify: Provider<SpotifyProvider>,
}

pub static CONFIG: SyncLazy<Config> = SyncLazy::new(|| {
    let config_str = std::fs::read_to_string("config.toml").expect("could not read config file");
    toml::from_str(&config_str).expect("could not parse config file")
});
