use std::{convert::TryFrom, error::Error};

use dynomite::{
    dynamodb::{
        DynamoDb, DynamoDbClient, GetItemError, GetItemInput, PutItemError, PutItemInput,
        QueryError, QueryInput,
    },
    AttributeValue, Attributes,
};
use rocket::{http::Status, response::Responder, Request};
use rusoto_core::Region;

use thiserror::Error;

pub trait DynamoTable: TryFrom<Attributes, Error = dynomite::AttributeError> {
    const TABLE_NAME: &'static str;
}

#[derive(Debug, Error)]
pub enum DynamoError<E: Error + 'static> {
    #[error("could not parse dynamo attributes: {0}")]
    ParseError(#[from] dynomite::AttributeError),
    #[error("could not connect to dynamo: {0}")]
    Rusoto(#[from] rusoto_core::RusotoError<E>),
}

impl<'r, 'o: 'r, E: Error + 'static> Responder<'r, 'o> for DynamoError<E> {
    fn respond_to(self, _: &'r Request<'_>) -> rocket::response::Result<'o> {
        error!("{}", self);
        Err(Status::InternalServerError)
    }
}

pub trait DynamoPrimaryKey: Into<dynomite::Attributes> {
    type Table: DynamoTable;
}

pub trait DynamoIndex: TryFrom<Attributes, Error = dynomite::AttributeError> {
    type Table: DynamoTable;
    const INDEX_NAME: &'static str = "TokenUserIndex";
}

pub trait DynamoSecondaryKey: Sized {
    type Index: DynamoIndex;

    fn query_condition(self) -> Result<Query, dynomite::AttributeError>;
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

pub struct Client(DynamoDbClient);

impl std::default::Default for Client {
    fn default() -> Self {
        Self(DynamoDbClient::new(Region::default()))
    }
}

impl Client {
    pub async fn save<T>(&self, t: T) -> Result<(), DynamoError<PutItemError>>
    where
        T: DynamoTable + Into<Attributes> + Send,
    {
        let input = PutItemInput {
            table_name: T::TABLE_NAME.to_owned(),
            item: t.into(),
            ..PutItemInput::default()
        };
        self.0.put_item(input).await?;
        Ok(())
    }

    pub async fn get<K>(&self, k: K) -> Result<Option<K::Table>, DynamoError<GetItemError>>
    where
        K: DynamoPrimaryKey + Send,
    {
        let input = GetItemInput {
            table_name: K::Table::TABLE_NAME.to_string(),
            key: k.into(),
            ..GetItemInput::default()
        };
        let output = self.0.get_item(input).await?;
        Ok(output.item.map(K::Table::try_from).transpose()?)
    }

    pub async fn query<K>(&self, k: K) -> Result<Vec<K::Index>, DynamoError<QueryError>>
    where
        K: DynamoSecondaryKey + Send,
    {
        let table_name = <K::Index as DynamoIndex>::Table::TABLE_NAME.to_string();
        let index_name = Some(K::Index::INDEX_NAME.to_string());
        let input = k.query_condition()?.build(table_name, index_name);
        let output = self.0.query(input).await?;

        let item = output
            .items
            .unwrap_or_else(Vec::new)
            .into_iter()
            .map(K::Index::try_from)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(item)
    }
}
