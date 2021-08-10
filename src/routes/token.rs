use askama_rocket::Responder;
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, EncodingKey, Header};
use metrics::decrement_gauge;
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

use crate::{config::Config, db::Token, login, routes::callback::random_key, templates, token, util::bail};

#[post("/token", data = "<token_data>")]
pub async fn token_create(config: &State<Config>, login_claims: login::Claims, token_data: Form<token::Data>) -> Result<Redirect, CreateError> {
    let token::Data { name, provider_id, scopes } = token_data.into_inner();

    let claims = token::Claims {
        name,
        provider_id,
        scopes: scopes,
        username: login_claims.username,
        expires: Utc::now() + Duration::minutes(10),
    };
    let state = encode(&Header::default(), &claims, &EncodingKey::from_base64_secret(&config.state_key)?)?;
    let token::Claims { provider_id, scopes, .. } = claims;

    let (url, _) = config
        .providers
        .get(&provider_id)
        .ok_or_else(|| CreateError::MissingProvider(provider_id.clone()))?
        .oauth2_client(config.base_url.clone())
        .authorize_url(|| CsrfToken::new(state))
        .add_scopes(scopes.into_iter().map(Scope::new))
        .url();

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
        Err(bail(self, Status::InternalServerError))
    }
}

#[get("/token/<provider_id>", rank = 2)]
pub fn token_new_page(config: &State<Config>, provider_id: String, _login_claims: login::Claims) -> Option<templates::NewToken> {
    let provider = config.providers.get(&provider_id)?;
    Some(templates::NewToken {
        provider_id,
        scopes: provider.scopes.clone(),
    })
}

#[get("/token/<token_id>")]
pub async fn token_view(db: &State<DynamoDbClient>, config: &State<Config>, token_id: token::ID, login_claims: login::Claims) -> Result<Option<templates::ViewToken>, ViewError> {
    fn result(token: Option<Token>, baseurl: String) -> Option<templates::ViewToken> {
        let token = token?;

        Some(templates::ViewToken {
            name: token.name,
            id: token.token_id,
            scopes: token.scopes,
            api_key: None,

            username: token.username,
            baseurl,
        })
    }

    let token = db.get::<Token>().username(login_claims.username).token_id(token_id).execute().await?;
    Ok(result(token, config.base_url.to_string()))
}

#[get("/token/<token_id>", rank = 3)]
pub async fn token_view_unauthenticated(token_id: token::ID) -> Redirect {
    let redirect_to = uri!(token_view(token_id)).to_string();
    let redirect = uri!(super::login::login_page(Some(redirect_to)));
    Redirect::to(redirect)
}

#[derive(Debug, Error)]
pub enum ViewError {
    #[error("error making db request {0}")]
    DynamoGet(#[from] DynamoError<GetItemError>),
}
impl<'r, 'o: 'r> Responder<'r, 'o> for ViewError {
    fn respond_to(self, _r: &'r Request<'_>) -> rocket::response::Result<'o> {
        Err(bail(self, Status::InternalServerError))
    }
}

#[post("/token/<token_id>/delete")]
pub async fn token_delete(db: &State<DynamoDbClient>, token_id: token::ID, login_claims: login::Claims) -> Result<Redirect, DeleteError> {
    let token = db.delete::<Token>().username(login_claims.username).token_id(token_id).return_all_old().execute().await?;

    decrement_gauge!("oauth2_proxy_tokens", 1.0, "provider" => token.provider_id);

    Ok(Redirect::to(uri!(crate::routes::home::home_page)))
}

#[derive(Debug, Error)]
pub enum DeleteError {
    #[error("error making db request {0}")]
    DynamoDelete(#[from] DynamoError<DeleteItemError>),
}
impl<'r, 'o: 'r> Responder<'r, 'o> for DeleteError {
    fn respond_to(self, _r: &'r Request<'_>) -> rocket::response::Result<'o> {
        Err(bail(self, Status::InternalServerError))
    }
}

#[post("/token/<token_id>/revoke")]
pub async fn token_revoke(db: &State<DynamoDbClient>, config: &State<Config>, token_id: token::ID, login_claims: login::Claims) -> Result<Option<templates::ViewToken>, RevokeError> {
    let mut token = match db.get::<Token>().username(login_claims.username).token_id(token_id).execute().await? {
        Some(token) => token,
        None => return Ok(None),
    };

    let api_key = random_key();
    let api_key = base64::encode_config(api_key, base64::URL_SAFE);

    token.key_hash = bcrypt::hash(&api_key, 12)?;
    db.put(token.clone()).execute().await?;

    Ok(Some(templates::ViewToken {
        name: token.name,
        id: token.token_id,
        scopes: token.scopes,
        api_key: Some(api_key),

        username: token.username,
        baseurl: config.base_url.to_string(),
    }))
}

#[derive(Debug, Error)]
pub enum RevokeError {
    #[error("error making db request {0}")]
    DynamoGet(#[from] DynamoError<GetItemError>),
    #[error("error making db request {0}")]
    DynamoPut(#[from] DynamoError<PutItemError>),
    #[error("error creating hash {0}")]
    Bcrypt(#[from] bcrypt::BcryptError),
}
impl<'r, 'o: 'r> Responder<'r, 'o> for RevokeError {
    fn respond_to(self, _r: &'r Request<'_>) -> rocket::response::Result<'o> {
        Err(bail(self, Status::InternalServerError))
    }
}
