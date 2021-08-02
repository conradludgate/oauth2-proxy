use std::collections::HashMap;

use oauth2::{basic::BasicClient, AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl};
use serde::Deserialize;

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

#[derive(Deserialize)]
pub struct Provider {
    pub name: String,
    pub client_id: String,
    pub client_secret: String,
    pub auth_url: oauth2::url::Url,
    pub token_url: oauth2::url::Url,
    pub scopes: Vec<String>,
}

impl Provider {
    pub fn oauth2_client(&self, config: &Config) -> BasicClient {
        let mut redirect = config.base_url.clone();
        redirect.set_path("/callback");

        BasicClient::new(
            ClientId::new(self.client_id.clone()),
            Some(ClientSecret::new(self.client_secret.clone())),
            AuthUrl::from_url(self.auth_url.clone()),
            Some(TokenUrl::from_url(self.token_url.clone())),
        )
        .set_redirect_uri(RedirectUrl::from_url(redirect))
    }
}
