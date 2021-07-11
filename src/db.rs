use std::collections::HashMap;

use rusoto_dynamodb::{GetItemError, QueryError};
use serde::{Deserialize, Serialize};

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

#[derive(Serialize, Deserialize)]
pub struct TokenUserKey {
    pub user_id: String,
}

pub trait DynamoTable: for<'a> Deserialize<'a> {
    const TABLE_NAME: &'static str;
}

pub enum DynamoError<E> {
    DynamoSerde(serde_dynamodb::Error),
    Rusoto(rusoto_core::RusotoError<E>),
}

use async_trait::async_trait;

#[async_trait]
pub trait DynamoPrimaryKey: Serialize {
    type Table: DynamoTable;

    async fn get(&self) -> Result<Option<Self::Table>, DynamoError<GetItemError>> {
        use rusoto_core::Region;
        use rusoto_dynamodb::{DynamoDb, DynamoDbClient, GetItemInput};
        use DynamoError::*;

        let client = DynamoDbClient::new(Region::default());

        let key = serde_dynamodb::to_hashmap(self).map_err(DynamoSerde)?;

        let output = client
            .get_item(GetItemInput {
                table_name: Self::Table::TABLE_NAME.to_string(),
                key,
                ..Default::default()
            })
            .await
            .map_err(Rusoto)?;

        let item = output
            .item
            .map(serde_dynamodb::from_hashmap)
            .transpose()
            .map_err(DynamoSerde)?;

        Ok(item)
    }
}

pub trait DynamoIndex: for<'a> Deserialize<'a> {
    type Table: DynamoTable;
    const INDEX_NAME: &'static str = "TokenUserIndex";
}

#[async_trait]
pub trait DynamoSecondaryKey: Serialize {
    type Index: DynamoIndex;

    async fn query(&self) -> Result<Vec<Self::Index>, DynamoError<QueryError>> {
        use rusoto_core::Region;
        use rusoto_dynamodb::{DynamoDb, DynamoDbClient, QueryInput};
        use DynamoError::*;

        let client = DynamoDbClient::new(Region::default());

        let key = serde_dynamodb::to_hashmap(self).map_err(DynamoSerde)?;
        let mut expr = "".to_string();
        let mut names = HashMap::new();
        let mut values = HashMap::new();
        for (i, (name, value)) in key.into_iter().enumerate() {
            let n = format!("#{}", i);
            let v = format!(":{}", i);
            if expr.is_empty() {
                expr = format!("{} = {}", n, v);
            } else {
                expr = format!("({}) AND ({} = {})", expr, n, v);
            }
            names.insert(n, name);
            values.insert(v, value);
        }
        println!("{:?}", expr);

        let output = client
            .query(QueryInput {
                table_name: <Self::Index as DynamoIndex>::Table::TABLE_NAME.to_string(),
                index_name: Some(Self::Index::INDEX_NAME.to_string()),
                key_condition_expression: Some(expr),
                expression_attribute_names: Some(names),
                expression_attribute_values: Some(values),
                ..Default::default()
            })
            .await
            .map_err(Rusoto)?;

        let item = output
            .items
            .unwrap_or_else(Vec::new)
            .into_iter()
            .map(serde_dynamodb::from_hashmap)
            .collect::<Result<Vec<_>, _>>()
            .map_err(DynamoSerde)?;

        Ok(item)
    }
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

impl DynamoSecondaryKey for TokenUserKey {
    type Index = TokenUserIndex;
}
