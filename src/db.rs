use nitroglycerin::{Attributes, Key, Query, Table, TableIndex};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Attributes, Key)]
pub struct User {
    #[nitro(partition_key)]
    pub username: String,
    pub password_hash: String,
}

#[derive(Attributes, Key)]
pub struct Token {
    #[nitro(partition_key)]
    pub token_id: Uuid,
    #[nitro(sort_key)]
    pub username: String,
    pub name: String,
    pub provider_id: String,
    pub scopes: Vec<String>,
    pub oauth: Option<OauthToken>,
}

#[derive(Serialize, Deserialize, Attributes, Debug)]
pub struct OauthToken {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires: Option<chrono::DateTime<chrono::Utc>>,
    pub token_type: String,
    pub key_hash: String,
}

#[derive(Attributes, Query)]
pub struct TokenUserIndex {
    #[nitro(partition_key)]
    pub username: String,

    pub token_id: Uuid,
    pub name: String,
}

impl Table for User {
    fn table_name() -> String {
        "Users".to_string()
    }
}

impl Table for Token {
    fn table_name() -> String {
        "Tokens".to_string()
    }
}

impl TableIndex for TokenUserIndex {
    type Table = Token;
    fn index_name() -> Option<String> {
        Some("TokenUserIndex".to_string())
    }
}
