use askama_rocket::Responder;
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, DecodingKey, Validation};
use nitroglycerin::{
    dynamodb::{DynamoDbClient, PutItemError},
    DynamoDb, DynamoError,
};
use oauth2::{reqwest::async_http_client, AuthorizationCode, TokenResponse};
use rocket::{http::Status, request::Request, State};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    config::Config,
    db::{OauthToken, Token},
    templates, token,
    util::bail,
};

#[get("/callback?<code>&<state>")]
pub async fn callback(config: &State<Config>, db: &State<DynamoDbClient>, code: String, state: &str) -> Result<templates::ViewToken, HandlerError> {
    let token_data = decode(state, &DecodingKey::from_base64_secret(&config.state_key)?, &Validation::default())?;
    let token::Claims {
        token_id,
        provider_id,
        scopes,
        username,
        ..
    } = token_data.claims;
    let token_id = token_id.parse::<Uuid>()?;

    let mut token = db
        .get::<Token>()
        .token_id(token_id)
        .username(username)
        .execute()
        .await
        .ok()
        .flatten()
        .ok_or(HandlerError::Status(Status::BadRequest))?;

    let provider = config.providers.get(&provider_id).ok_or(HandlerError::Status(Status::InternalServerError))?;
    let t = provider.oauth2_client(config).exchange_code(AuthorizationCode::new(code)).request_async(async_http_client).await?;

    let api_key = random_key();
    let api_key = base64::encode_config(api_key, base64::URL_SAFE);

    token.oauth = Some(OauthToken {
        access_token: t.access_token().secret().clone(),
        refresh_token: t.refresh_token().map(|rt| rt.secret().clone()),
        expires: t.expires_in().map(|exp| Utc::now() + Duration::seconds(exp.as_secs() as i64)),
        token_type: t.token_type().as_ref().to_owned(),
        key_hash: bcrypt::hash(&api_key, 12)?,
    });

    let template = templates::ViewToken {
        name: token.name.clone(),
        id: token.token_id,
        scopes,
        api_key: Some(api_key),
    };

    db.put(token).execute().await?;

    Ok(template)
}

fn random_key() -> [u8; 48] {
    use rand::Rng;

    let mut rng = rand::thread_rng();
    let mut key = [0; 48];
    rng.try_fill(&mut key[..]).unwrap();
    key
}

#[get("/callback?<error>", rank = 2)]
pub fn error(error: &str) -> Status {
    warn!("callback_error: {}", error);
    Status::Unauthorized
}

#[derive(Debug, Error)]
pub enum HandlerError {
    #[error("error exchanging oauth2 token {0}")]
    Oauth2(#[from] oauth2::RequestTokenError<oauth2::reqwest::Error<reqwest::Error>, oauth2::StandardErrorResponse<oauth2::basic::BasicErrorResponseType>>),
    #[error("error making db request {0}")]
    Dynamo(#[from] DynamoError<PutItemError>),
    #[error("error creating hash {0}")]
    Bcrypt(#[from] bcrypt::BcryptError),
    #[error("error encoding jwt {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
    #[error("error parsing uuid {0}")]
    Uuid(#[from] uuid::Error),
    #[error("{0}")]
    Status(Status),
}

impl<'r, 'o: 'r> Responder<'r, 'o> for HandlerError {
    fn respond_to(self, request: &'r Request<'_>) -> rocket::response::Result<'o> {
        match self {
            Self::Status(status) => status.respond_to(request),
            Self::Jwt(_) | Self::Uuid(_) => bail(self, Status::BadRequest),
            _ => bail(self, Status::InternalServerError),
        }
    }
}
