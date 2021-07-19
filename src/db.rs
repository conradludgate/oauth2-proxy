use nitroglycerin::{Attributes, Get, Query, Table, TableIndex};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Attributes, Get)]
pub struct UserSession {
    #[nitro(partition_key)]
    pub session_id: Uuid,
    pub user_id: String,
}

#[derive(Attributes, Get)]
pub struct Token {
    #[nitro(partition_key)]
    pub token_id: Uuid,
    pub user_id: String,
    pub name: String,
    // pub api_key: String,
    pub provider_id: String,
    pub oauth: OauthToken,
}

#[derive(Serialize, Deserialize, Attributes, Debug)]
pub struct OauthToken {
    pub access_token: String,
    pub refresh_token: String,
    pub expires: chrono::DateTime<chrono::Utc>,
    pub token_type: String,
    pub scopes: Vec<String>,
}

#[derive(Attributes, Query)]
pub struct TokenUserIndex {
    #[nitro(partition_key)]
    pub user_id: String,

    pub token_id: Uuid,
    pub name: String,
}

impl Table for UserSession {
    fn table_name() -> String {
        "UserSessions".to_string()
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
