use nitroglycerin::{Attributes, Key, Query, Table};
use oauth2::{basic::BasicTokenType, AccessToken, RefreshToken};
use uuid::Uuid;

#[derive(Attributes, Key)]
pub struct User {
    #[nitro(partition_key)]
    pub username: String,
    pub password_hash: String,
}

#[derive(Clone, Attributes, Key, Query)]
pub struct Token {
    #[nitro(partition_key)]
    pub username: String,

    #[nitro(sort_key)]
    pub token_id: Uuid,
    pub name: String,
    pub provider_id: String,
    pub scopes: Vec<String>,

    pub key_hash: String,

    pub access_token: AccessToken,
    pub refresh_token: RefreshToken,
    pub token_type: BasicTokenType,
    #[nitro(with = nitroglycerin::convert::chrono::seconds)]
    pub expires: chrono::DateTime<chrono::Utc>,
}

impl Table for User {
    fn table_name() -> String {
        "Users".to_string()
    }
}

impl Table for Token {
    fn table_name() -> String {
        "Token".to_string()
    }
}
