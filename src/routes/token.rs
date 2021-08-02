use askama_rocket::Responder;
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, EncodingKey, Header};
use nitroglycerin::{
    dynamodb::{DeleteItemError, DynamoDbClient, GetItemError, PutItemError},
    DynamoDb, DynamoError,
};
use oauth2::{CsrfToken, Scope};
use rocket::{
    form::Form,
    http::{uri::Reference, Status},
    request::Request,
    response::Redirect,
    State,
};
use thiserror::Error;
use uuid::Uuid;

use crate::{config::Config, db::Token, login, templates, token, util::bail};

#[post("/token", data = "<token_data>")]
pub async fn create(db: &State<DynamoDbClient>, config: &State<Config>, login_claims: login::Claims, token_data: Form<token::Data>) -> Result<Redirect, CreateError> {
    let token::Data { name, provider_id, scopes } = token_data.into_inner();

    let token_id = Uuid::new_v4();
    let claims = token::Claims {
        token_id: token_id.to_string(),
        provider_id,
        scopes,
        username: login_claims.username,
        expires: Utc::now() + Duration::minutes(10),
    };
    let state = encode(&Header::default(), &claims, &EncodingKey::from_base64_secret(&config.state_key)?)?;
    let token::Claims { provider_id, scopes, username, .. } = claims;

    let (url, _) = config
        .providers
        .get(&provider_id)
        .ok_or_else(|| CreateError::MissingProvider(provider_id.clone()))?
        .oauth2_client(config)
        .authorize_url(|| CsrfToken::new(state))
        .add_scopes(scopes.clone().into_iter().map(Scope::new))
        .url();

    db.put(Token {
        token_id,
        username,
        name,
        provider_id,
        scopes,
        oauth: None,
    })
    .execute()
    .await?;

    Ok(Redirect::to(Reference::parse_owned(url.to_string()).unwrap()))
}

#[derive(Debug, Error)]
pub enum CreateError {
    #[error("error making db request {0}")]
    DynamoPut(#[from] DynamoError<PutItemError>),
    #[error("error encoding jwt {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
    #[error("missing provider information for {0}")]
    MissingProvider(String),
}
impl<'r, 'o: 'r> Responder<'r, 'o> for CreateError {
    fn respond_to(self, _r: &'r Request<'_>) -> rocket::response::Result<'o> {
        bail(self, Status::InternalServerError)
    }
}

#[get("/token/<provider_id>", rank = 2)]
pub fn new(config: &State<Config>, provider_id: String) -> Option<templates::NewToken> {
    let provider = config.providers.get(&provider_id)?;
    Some(templates::NewToken {
        provider_id,
        scopes: provider.scopes.clone(),
    })
}

#[get("/token/<token_id>")]
pub async fn view(db: &State<DynamoDbClient>, token_id: token::ID, login_claims: login::Claims) -> Result<Option<templates::ViewToken>, ViewError> {
    fn result(token: Option<Token>) -> Option<templates::ViewToken> {
        let token = token?;

        Some(templates::ViewToken {
            name: token.name,
            id: token.token_id,
            scopes: token.scopes,
            api_key: None,
        })
    }

    let token = db.get::<Token>().token_id(token_id).username(login_claims.username).execute().await?;
    Ok(result(token))
}

#[derive(Debug, Error)]
pub enum ViewError {
    #[error("error making db request {0}")]
    DynamoGet(#[from] DynamoError<GetItemError>),
}
impl<'r, 'o: 'r> Responder<'r, 'o> for ViewError {
    fn respond_to(self, _r: &'r Request<'_>) -> rocket::response::Result<'o> {
        bail(self, Status::InternalServerError)
    }
}

#[post("/token/<token_id>/delete")]
pub async fn delete(db: &State<DynamoDbClient>, token_id: token::ID, login_claims: login::Claims) -> Result<Redirect, DeleteError> {
    db.delete::<Token>().token_id(token_id).username(login_claims.username).execute().await?;
    Ok(Redirect::to(uri!(crate::routes::home::page)))
}

#[derive(Debug, Error)]
pub enum DeleteError {
    #[error("error making db request {0}")]
    DynamoDelete(#[from] DynamoError<DeleteItemError>),
}
impl<'r, 'o: 'r> Responder<'r, 'o> for DeleteError {
    fn respond_to(self, _r: &'r Request<'_>) -> rocket::response::Result<'o> {
        bail(self, Status::InternalServerError)
    }
}
