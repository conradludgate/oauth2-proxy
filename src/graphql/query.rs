use async_graphql::{Context, Object, Result, SimpleObject};
use nitroglycerin::{DynamoDb, dynamodb::DynamoDbClient};

use crate::db;

use super::provider::{Provider};

pub struct Query {
    pub db: DynamoDbClient,
}

#[Object]
impl Query {
    async fn version(&self) -> String {
        "0.1.0".to_string()
    }

    async fn tokens(
        &self,
        ctx: &Context<'_>,
    ) -> Result<Vec<Token>> {
        let user = ctx.data_opt::<User>().ok_or_else(|| "Forbidden")?;
        let tokens = self
            .db
            .query::<db::Token>()
            .username(&user.0)
            .execute()
            .await?
            .into_iter()
            .map(Token::from)
            .collect();

        Ok(tokens)
    }

    async fn token(&self, ctx: &Context<'_>, id: uuid::Uuid) -> Result<Token> {
        let user = ctx.data_opt::<User>().ok_or_else(|| "Forbidden")?;
        let token = self
            .db
            .get::<db::Token>()
            .username(&user.0)
            .token_id(id)
            .execute()
            .await?
            .ok_or_else(|| "Not Found")?;

        Ok(token.into())
    }
}

#[derive(SimpleObject)]
struct Token {
    id: uuid::Uuid,
    name: String,
    scopes: Vec<String>,
    provider: Provider,
}

impl From<db::Token> for Token {
    fn from(t: db::Token) -> Self {
        Self {
            id: t.token_id,
            name: t.name,
            scopes: t.scopes,
            provider: Provider::new(&t.provider_id).unwrap(),
        }
    }
}

pub struct User(pub String);
