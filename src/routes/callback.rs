use askama_rocket::Responder;
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, DecodingKey, Validation};
use metrics::increment_gauge;
use nitroglycerin::{
    dynamodb::{DynamoDbClient, PutItemError},
    DynamoDb, DynamoError,
};
use oauth2::{reqwest::async_http_client, AuthorizationCode};
use rocket::{http::Status, request::Request, State};
use thiserror::Error;
use uuid::Uuid;

use crate::{config::Config, db::Token, templates, token, util::bail};

#[get("/callback?<code>&<state>")]
pub async fn callback(config: &State<Config>, db: &State<DynamoDbClient>, code: String, state: &str) -> Result<templates::ViewToken, HandlerError> {
    let token_data = decode(state, &DecodingKey::from_base64_secret(&config.state_key)?, &Validation::default())?;
    let token::Claims {
        name, provider_id, scopes, username, ..
    } = token_data.claims;

    let provider = config.providers.get(&provider_id).ok_or(HandlerError::Status(Status::InternalServerError))?;
    let token = provider
        .oauth2_client(config.base_url.clone())
        .exchange_code(AuthorizationCode::new(code))
        .request_async(async_http_client)
        .await?;

    let api_key = random_key();
    let api_key = base64::encode_config(api_key, base64::URL_SAFE);

    let token = Token {
        token_id: Uuid::new_v4(),
        username,
        name,
        provider_id,
        scopes,

        key_hash: bcrypt::hash(&api_key, 12)?,

        access_token: token.access_token,
        refresh_token: token.refresh_token.ok_or(HandlerError::Status(Status::InternalServerError))?,
        token_type: token.token_type,
        expires: Utc::now() + Duration::seconds(token.expires_in as i64),
    };

    let template = templates::ViewToken {
        name: token.name.clone(),
        id: token.token_id.clone(),
        scopes: token.scopes.clone(),
        api_key: Some(api_key),

        username: token.username.clone(),
        baseurl: config.base_url.to_string(),
    };

    let provider_id = token.provider_id.clone();

    db.put(token).execute().await?;

    increment_gauge!("oauth2_proxy_tokens", 1.0, "provider" => provider_id);

    Ok(template)
}

pub fn random_key() -> [u8; 48] {
    use rand::Rng;

    let mut rng = rand::thread_rng();
    let mut key = [0; 48];
    rng.try_fill(&mut key[..]).unwrap();
    key
}

#[get("/callback?<error>", rank = 2)]
pub fn callback_error(error: &str) -> Status {
    warn!("callback_error: {}", error);
    Status::Unauthorized
}

impl Type for Provider {
    fn type_name() -> Cow<'static, str> {
        "Provider".into()
    }

    fn create_type_info(registry: &mut async_graphql::registry::Registry) -> String {
        registry.create_type::<Self, _>(|registry| {
            async_graphql::registry::MetaType::Enum {
                name: "Provider".into(),
                description: "Enumeration of Oauth2.0 Providers",
                enum_values: {
                    let mut enum_items = async_graphql::indexmap::IndexMap::new();

                    PROVIDER_ITEMS.iter().for_each(|item| {
                        enum_items.insert(item.name, async_graphql::registry::MetaEnumValue {
                            name: item.name,
                            description: format!("Oauth2.0 Provider {}", item.name),
                            deprecation: false,
                            visible: true,
                        });
                    });

                    enum_items
                },
                visible: true,
            }
        })
    }
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
            Self::Jwt(_) | Self::Uuid(_) => Err(bail(self, Status::BadRequest)),
            _ => Err(bail(self, Status::InternalServerError)),
        }
    }
}
