use askama_rocket::Responder;
use chrono::{Duration, Utc};
use metrics::increment_counter;
use nitroglycerin::{
    dynamodb::{DynamoDbClient, GetItemError, PutItemError},
    DynamoDb, DynamoError,
};
use oauth2::{basic::BasicTokenType, reqwest::async_http_client, AccessToken};
use rocket::{
    http::Status,
    request::{FromRequest, Outcome, Request},
    serde::json::Json,
    State,
};
use serde::Serialize;
use thiserror::Error;

use crate::{config::Config, db::Token, token, util::bail};

pub struct Basic {
    username: String,
    password: String,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Basic {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let auth = match request.headers().get_one("Authorization") {
            Some(auth) => auth,
            None => return Outcome::Failure((Status::Unauthorized, "missing basic authorization header")),
        };
        let auth = match auth.strip_prefix("Basic ") {
            Some(auth) => auth,
            None => return Outcome::Failure((Status::Unauthorized, "missing basic authorization header")),
        };
        let auth = match base64::decode_config(auth, base64::URL_SAFE) {
            Ok(auth) => auth,
            Err(_) => return Outcome::Failure((Status::Unauthorized, "invalid basic authorization header")),
        };
        let auth = match String::from_utf8(auth) {
            Ok(auth) => auth,
            Err(_) => return Outcome::Failure((Status::Unauthorized, "invalid basic authorization header")),
        };
        let auth = match auth.split_once(":") {
            Some(auth) => auth,
            None => return Outcome::Failure((Status::Unauthorized, "invalid basic authorization header")),
        };
        let (username, password) = auth;
        Outcome::Success(Self {
            username: username.to_owned(),
            password: password.to_owned(),
        })
    }
}

#[post("/api/v1/token/<token_id>")]
pub async fn exchange(db: &State<DynamoDbClient>, config: &State<Config>, token_id: token::ID, auth: Basic) -> Result<Json<ExchangeResponse>, ExchangeError> {
    let Basic { username, password } = auth;
    let mut token = db.get::<Token>().username(username).token_id(token_id).execute().await?.ok_or(ExchangeError::NotFound)?;
    if !bcrypt::verify(password, &token.key_hash)? {
        return Err(ExchangeError::IncorrectPassword);
    }

    if token.expires < Utc::now() {
        let provider = config.providers.get(&token.provider_id).ok_or_else(|| ExchangeError::InvalidProvider(token.provider_id.clone()))?;
        let new_token = provider
            .oauth2_client(config.base_url.clone())
            .exchange_refresh_token(&token.refresh_token)
            .request_async(async_http_client)
            .await?;

        token = Token {
            access_token: new_token.access_token,
            refresh_token: new_token.refresh_token.unwrap_or(token.refresh_token),
            token_type: new_token.token_type,
            expires: Utc::now() + Duration::seconds(new_token.expires_in as i64),
            ..token
        };

        db.put(token.clone()).execute().await?;
    }

    increment_counter!("oauth2_proxy_token_exchanges");

    Ok(Json(ExchangeResponse {
        access_token: token.access_token,
        token_type: token.token_type,
        expires: token.expires,
    }))
}

#[derive(Serialize)]
pub struct ExchangeResponse {
    access_token: AccessToken,
    token_type: BasicTokenType,
    #[serde(with = "chrono::serde::ts_seconds")]
    expires: chrono::DateTime<Utc>,
}

#[derive(Debug, Error)]
pub enum ExchangeError {
    #[error("error exchanging oauth2 token {0}")]
    Oauth2(#[from] oauth2::RequestTokenError<oauth2::reqwest::Error<reqwest::Error>, oauth2::StandardErrorResponse<oauth2::basic::BasicErrorResponseType>>),
    #[error("error making db request {0}")]
    DynamoGet(#[from] DynamoError<GetItemError>),
    #[error("error making db request {0}")]
    DynamoPut(#[from] DynamoError<PutItemError>),
    #[error("error decoding json {0}")]
    Bcrypt(#[from] bcrypt::BcryptError),
    #[error("invalid provider {0}")]
    InvalidProvider(String),
    #[error("invalid password")]
    IncorrectPassword,
    #[error("not found")]
    NotFound,
}

impl<'r, 'o: 'r> Responder<'r, 'o> for ExchangeError {
    fn respond_to(self, _r: &'r Request<'_>) -> rocket::response::Result<'o> {
        match self {
            Self::Bcrypt(bcrypt::BcryptError::InvalidPassword) | Self::IncorrectPassword | Self::NotFound => Err(Status::Unauthorized),
            _ => Err(bail(self, Status::InternalServerError)),
        }
    }
}
