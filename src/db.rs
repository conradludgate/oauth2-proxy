mod helpers;
pub use helpers::{DynamoError, DynamoPrimaryKey, DynamoSecondaryKey};
use helpers::{DynamoIndex, DynamoTable, Query};

use dynomite::{Attribute, Item};
use uuid::Uuid;

#[derive(Item)]
pub struct UserSession {
    #[dynomite(partition_key)]
    pub session_id: Uuid,
    pub user_id: Uuid,
}

#[derive(Item)]
pub struct Token {
    #[dynomite(partition_key)]
    pub token_id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    // pub api_key: String,

    // pub access_token: String,
    // pub refresh_token: String,
    // pub expires: chrono::DateTime<chrono::Utc>,
    // pub token_type: String,
    pub scopes: Vec<String>,
}

#[derive(Item)]
pub struct TokenUserIndex {
    #[dynomite(partition_key)]
    pub user_id: Uuid,

    pub token_id: Uuid,
    pub name: String,
}

#[derive(Item)]
pub struct Provider {
    #[dynomite(partition_key)]
    pub provider_id: String,
    pub client_id: String,
    pub client_secret: String,

    pub redirect_uri: String,
    pub scopes: Vec<String>,
}

impl DynamoTable for UserSession {
    const TABLE_NAME: &'static str = "UserSessions";
}

impl DynamoPrimaryKey for UserSessionKey {
    type Table = UserSession;
}

impl DynamoTable for Token {
    const TABLE_NAME: &'static str = "Tokens";
}

impl DynamoPrimaryKey for TokenKey {
    type Table = Token;
}

impl DynamoIndex for TokenUserIndex {
    type Table = Token;
    const INDEX_NAME: &'static str = "TokenUserIndex";
}

impl DynamoSecondaryKey for TokenUserIndexKey {
    type Index = TokenUserIndex;
    fn query_condition(self) -> Result<Query, dynomite::AttributeError> {
        let key = "user_id".to_string();
        let value = self.user_id.into_attr();
        Ok(Query::Equal(key, value))
    }
}

impl DynamoTable for Provider {
    const TABLE_NAME: &'static str = "Providers";
}

impl DynamoPrimaryKey for ProviderKey {
    type Table = Provider;
}
