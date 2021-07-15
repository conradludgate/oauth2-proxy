use serde::Deserialize;
use std::error::Error;
use std::fs::File;
use std::io::Read;

fn base_url() -> String {
    "http://localhost:27228".to_owned()
}

#[derive(Deserialize)]
pub struct Config {
    #[serde(default = "base_url")]
    pub base_url: String,
    pub spotify: Client,
}

#[derive(Deserialize)]
pub struct Client {
    pub client_id: String,
    pub client_secret: String,
}

pub fn parse() -> Result<Config, Box<dyn Error>> {
    let mut file = File::open("oauth2.toml")?;
    let mut s = String::new();
    file.read_to_string(&mut s)?;

    Ok(toml::from_str(&s)?)
}
