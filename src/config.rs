use std::{collections::HashMap, fs::File, io::Read, lazy::SyncLazy};

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

pub static CONFIG: SyncLazy<Config> = SyncLazy::new(|| {
    let mut config_file = File::open("config.toml").expect("config.toml file not found");
    let mut config_str = String::new();
    config_file.read_to_string(&mut config_str).expect("could not read config file");
    toml::from_str(&config_str).expect("could not parse config file")
});
