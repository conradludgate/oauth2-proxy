mod helpers;
pub use helpers::{get, query, save, DynamoError};
use helpers::{DynamoIndex, DynamoPrimaryKey, DynamoSecondaryKey, DynamoTable, Query};

use dynomite::{Attribute, Attributes, Item};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Item)]
pub struct UserSession {
    #[dynomite(partition_key)]
    pub session_id: Uuid,
    pub user_id: String,
}

#[derive(Item)]
pub struct Token {
    #[dynomite(partition_key)]
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

#[derive(Item)]
pub struct TokenUserIndex {
    #[dynomite(partition_key)]
    pub user_id: String,

    pub token_id: Uuid,
    pub name: String,
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
