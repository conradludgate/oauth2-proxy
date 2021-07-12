use serde::{Deserialize, Serialize};

mod helpers;
pub use helpers::{DynamoError, DynamoPrimaryKey, DynamoSecondaryKey};
use helpers::{DynamoIndex, DynamoTable, Query};

#[derive(Serialize, Deserialize)]
pub struct UserSession {
    pub session_id: String,
    pub user_id: String,
}

#[derive(Serialize, Deserialize)]
pub struct SessionKey {
    pub session_id: String,
}

#[derive(Serialize, Deserialize)]
pub struct Token {
    pub token_id: String,
    pub user_id: String,
    pub name: String,
    pub api_key: String,

    pub access_token: String,
    pub refresh_token: String,
    pub expires: chrono::DateTime<chrono::Utc>,
    pub token_type: String,
    pub scopes: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct TokenUserIndex {
    pub token_id: String,
    pub user_id: String,
    pub name: String,
}

pub struct TokensByUserID {
    pub user_id: String,
}

impl DynamoTable for UserSession {
    const TABLE_NAME: &'static str = "UserSessions";
}

impl DynamoPrimaryKey for SessionKey {
    type Table = UserSession;
}

impl DynamoTable for Token {
    const TABLE_NAME: &'static str = "Tokens";
}

impl DynamoIndex for TokenUserIndex {
    type Table = Token;
    const INDEX_NAME: &'static str = "TokenUserIndex";
}

impl DynamoSecondaryKey for TokensByUserID {
    type Index = TokenUserIndex;
    fn query_condition(&self) -> Result<Query, DynamoError<rusoto_dynamodb::QueryError>> {
        let key = "user_id".to_string();
        let value = serde_dynamo::to_attribute_value(&self.user_id)?;
        Ok(Query::Equal(key, value))
    }
}
