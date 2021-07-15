use serde::Deserialize;

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
