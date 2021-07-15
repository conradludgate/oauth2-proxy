use std::convert::TryFrom;

use dynomite::{
    dynamodb::{
        DynamoDb, DynamoDbClient, GetItemError, GetItemInput, PutItemError, PutItemInput,
        QueryError, QueryInput,
    },
    AttributeValue, Attributes,
};
use rusoto_core::Region;

use thiserror::Error;

#[async_trait]
pub trait DynamoTable: TryFrom<Attributes, Error = dynomite::AttributeError> {
    const TABLE_NAME: &'static str;

    async fn save(self) -> Result<(), DynamoError<PutItemError>>
    where
        Self: Into<Attributes>,
    {
        let client = DynamoDbClient::new(Region::default());
        let input = PutItemInput {
            table_name: Self::TABLE_NAME.to_owned(),
            item: self.into(),
            ..PutItemInput::default()
        };
        client.put_item(input).await?;
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum DynamoError<E: std::error::Error + 'static> {
    #[error("could not parse dynamo attributes: {0}")]
    ParseError(#[from] dynomite::AttributeError),
    #[error("could not connect to dynamo: {0}")]
    Rusoto(#[from] rusoto_core::RusotoError<E>),
}

use async_trait::async_trait;

#[async_trait]
pub trait DynamoPrimaryKey: Into<dynomite::Attributes> {
    type Table: DynamoTable;

    async fn get(self) -> Result<Option<Self::Table>, DynamoError<GetItemError>> {
        let client = DynamoDbClient::new(Region::default());

        let key = self.into();

        let output = client
            .get_item(GetItemInput {
                table_name: Self::Table::TABLE_NAME.to_string(),
                key,
                ..GetItemInput::default()
            })
            .await?;

        let item = output.item.map(Self::Table::try_from).transpose()?;

        Ok(item)
    }
}

pub trait DynamoIndex: TryFrom<Attributes, Error = dynomite::AttributeError> {
    type Table: DynamoTable;
    const INDEX_NAME: &'static str = "TokenUserIndex";
}

#[async_trait]
pub trait DynamoSecondaryKey: Sized {
    type Index: DynamoIndex;

    fn query_condition(self) -> Result<Query, dynomite::AttributeError>;

    async fn query(self) -> Result<Vec<Self::Index>, DynamoError<QueryError>> {
        use rusoto_core::Region;

        let client = DynamoDbClient::new(Region::default());

        let table_name = <Self::Index as DynamoIndex>::Table::TABLE_NAME.to_string();
        let index_name = Some(Self::Index::INDEX_NAME.to_string());
        let input = self.query_condition()?.build(table_name, index_name);

        let output = client.query(input).await?;

        let item = output
            .items
            .unwrap_or_else(Vec::new)
            .into_iter()
            .map(Self::Index::try_from)
            .collect::<Result<Vec<_>, _>>()?;

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
            ..QueryInput::default()
        }
    }
}

pub enum Query {
    Equal(String, AttributeValue),
    // And(Box<Query>, Box<Query>),
}

impl From<Query> for Condition {
    fn from(q: Query) -> Self {
        let mut names = vec![];
        let mut values = vec![];
        let expr = q.__enrich(&mut names, &mut values);
        Self {
            names,
            values,
            expr,
        }
    }
}

impl Query {
    fn build(self, table_name: String, index_name: Option<String>) -> QueryInput {
        let cond: Condition = self.into();
        cond.build(table_name, index_name)
    }

    fn __enrich(self, names: &mut Vec<String>, values: &mut Vec<AttributeValue>) -> String {
        match self {
            Query::Equal(name, value) => {
                let i = names.len();
                let j = values.len();

                names.push(name);
                values.push(value);

                format!("#{} = :{}", i, j)
            } // Query::And(lhs, rhs) => {
              //     let lhs = lhs.__enrich(names, values);
              //     let rhs = rhs.__enrich(names, values);

              //     format!("({}) AND ({})", lhs, rhs)
              // }
        }
    }
}
