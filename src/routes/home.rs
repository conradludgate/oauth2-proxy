use askama_rocket::Responder;
use nitroglycerin::{
    dynamodb::{DynamoDbClient, QueryError},
    DynamoDb, DynamoError,
};
use rocket::{http::Status, request::Request, State};
use thiserror::Error;

use crate::{config::Config, db::TokenUserIndex, login, templates, util::bail};

#[get("/")]
pub async fn page(db: &State<DynamoDbClient>, config: &State<Config>, login_claims: login::Claims) -> Result<templates::Home, Error> {
    let login::Claims { username, .. } = login_claims;
    let tokens = db.query::<TokenUserIndex>().username(username).execute().await?;

    Ok(templates::Home {
        tokens: tokens.into_iter().map(|token| templates::HomeToken { id: token.token_id, name: token.name }).collect(),
        providers: config
            .providers
            .iter()
            .map(|(id, provider)| templates::Provider {
                slug: id.clone(),
                name: provider.name.clone(),
            })
            .collect(),
    })
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("error making db request {0}")]
    DynamoQuery(#[from] DynamoError<QueryError>),
}
impl<'r, 'o: 'r> Responder<'r, 'o> for Error {
    fn respond_to(self, _r: &'r Request<'_>) -> rocket::response::Result<'o> {
        bail(self, Status::InternalServerError)
    }
}

#[get("/", rank = 2)]
pub const fn index() -> templates::Index {
    templates::Index
}
