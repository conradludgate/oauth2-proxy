use rusoto_dynamodb::{AttributeValue, GetItemError, QueryError, QueryInput};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub trait DynamoTable: for<'a> Deserialize<'a> {
    const TABLE_NAME: &'static str;
}

#[derive(Debug, Error)]
pub enum DynamoError<E: std::error::Error + 'static> {
    #[error("could not parse dynamo attributes: {0}")]
    DynamoSerde(#[from] serde_dynamo::Error),
    #[error("could not connect to dynamo: {0}")]
    Rusoto(#[from] rusoto_core::RusotoError<E>),
}

use async_trait::async_trait;

#[async_trait]
pub trait DynamoPrimaryKey: Serialize {
    type Table: DynamoTable;

    async fn get(&self) -> Result<Option<Self::Table>, DynamoError<GetItemError>> {
        use rusoto_core::Region;
        use rusoto_dynamodb::{DynamoDb, DynamoDbClient, GetItemInput};

        let client = DynamoDbClient::new(Region::default());

        let key = serde_dynamo::to_item(self)?;

        let output = client
            .get_item(GetItemInput {
                table_name: Self::Table::TABLE_NAME.to_string(),
                key,
                ..Default::default()
            })
            .await?;

        let item = output.item.map(serde_dynamo::from_item).transpose()?;

        Ok(item)
    }
}

pub trait DynamoIndex: for<'a> Deserialize<'a> {
    type Table: DynamoTable;
    const INDEX_NAME: &'static str = "TokenUserIndex";
}

#[async_trait]
pub trait DynamoSecondaryKey {
    type Index: DynamoIndex;

    fn query_condition(&self) -> Result<Query, DynamoError<QueryError>>;

    async fn query(&self) -> Result<Vec<Self::Index>, DynamoError<QueryError>> {
        use rusoto_core::Region;
        use rusoto_dynamodb::{DynamoDb, DynamoDbClient};

        let client = DynamoDbClient::new(Region::default());

        let table_name = <Self::Index as DynamoIndex>::Table::TABLE_NAME.to_string();
        let index_name = Some(Self::Index::INDEX_NAME.to_string());
        let input = self
            .query_condition()?
            .build()
            .build(table_name, index_name);

        let output = client.query(input).await?;

        let item = output
            .items
            .map(serde_dynamo::from_items)
            .transpose()?
            .unwrap_or_else(Vec::new);

        Ok(item)
    }
}

struct Condition {
    pub names: Vec<String>,
    pub values: Vec<AttributeValue>,
    pub expr: String,
}

impl Condition {
    fn build(self, table_name: String, index_name: Option<String>) -> QueryInput {
        QueryInput {
            table_name,
            index_name,
            key_condition_expression: Some(self.expr),
            expression_attribute_names: Some(
                self.names
                    .into_iter()
                    .enumerate()
                    .map(|(i, name)| (format!("#{}", i), name))
                    .collect(),
            ),
            expression_attribute_values: Some(
                self.values
                    .into_iter()
                    .enumerate()
                    .map(|(i, value)| (format!(":{}", i), value))
                    .collect(),
            ),
            ..Default::default()
        }
    }
}

pub enum Query {
    Equal(String, AttributeValue),
    And(Box<Query>, Box<Query>),
}

impl Query {
    fn build(self) -> Condition {
        let mut names = vec![];
        let mut values = vec![];
        let expr = self._build(&mut names, &mut values);
        Condition {
            names,
            values,
            expr,
        }
    }

    fn _build(self, names: &mut Vec<String>, values: &mut Vec<AttributeValue>) -> String {
        match self {
            Query::Equal(name, value) => {
                let i = names.len();
                let j = values.len();

                names.push(name);
                values.push(value);

                format!("#{} = :{}", i, j)
            }
            Query::And(lhs, rhs) => {
                let lhs = lhs._build(names, values);
                let rhs = rhs._build(names, values);

                format!("({}) AND ({})", lhs, rhs)
            }
        }
    }
}
