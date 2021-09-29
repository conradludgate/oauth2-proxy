use async_graphql::{Context, Error, Object, Result, SimpleObject};
use chrono::{Duration, Utc};
use jsonwebtoken as jwt;
use nitroglycerin::{dynamodb::DynamoDbClient, DynamoDb};
use oauth2::{reqwest::async_http_client, AuthorizationCode, CsrfToken, Scope};
use uuid::Uuid;

use super::query::User;
use crate::{
    config::CONFIG,
    db, login,
    provider::{spotify::SpotifyScope, ProviderScopes, ScopeCollection, Scopes},
    token,
};

pub struct Mutation {
    pub db: DynamoDbClient,
}

#[Object]
impl Mutation {
    async fn register(&self, username: String, password: String) -> Result<String> {
        let user = self
            .db
            .get::<db::User>()
            .username(&username)?
            .execute()
            .await?;
        match user {
            None => {
                self.db
                    .put(db::User {
                        username: username.clone(),
                        password_hash: bcrypt::hash(password, CONFIG.bcrypt_cost)?,
                    })?
                    .execute()
                    .await?;
            }
            Some(_) => {
                return Err(Error::new("account already exists"));
            }
        };

        let claims = login::Claims {
            username,
            expires: Utc::now() + Duration::hours(1),
        };
        let value = jwt::encode(
            &jwt::Header::default(),
            &claims,
            &jwt::EncodingKey::from_base64_secret(&CONFIG.state_key)?,
        )?;

        Ok(value)
    }

    async fn login(&self, username: String, password: String) -> Result<String> {
        let user = self
            .db
            .get::<db::User>()
            .username(&username)?
            .execute()
            .await?;
        match user {
            None => {
                // hash password anyway - reduces timing attack surface to determine a valid username
                let _ = bcrypt::verify(
                    password,
                    "$2a$12$K4uukigIEtRzdPAajgVYXe6PBFkT4q/VIQPRJrRy4Okocmu2h6AtK",
                )?;
                return Err(Error::new("incorrect username or password"));
            }
            Some(user) => {
                if !bcrypt::verify(password, &user.password_hash)? {
                    return Err(Error::new("incorrect username or password"));
                }
            }
        };

        let claims = login::Claims {
            username,
            expires: Utc::now() + Duration::hours(1),
        };
        let value = jwt::encode(
            &jwt::Header::default(),
            &claims,
            &jwt::EncodingKey::from_base64_secret(&CONFIG.state_key)?,
        )?;

        Ok(value)
    }

    async fn revoke_token_api_key(&self, ctx: &Context<'_>, id: uuid::Uuid) -> Result<String> {
        let user = ctx.data_opt::<User>().ok_or_else(|| "Forbidden")?;
        let mut token = self
            .db
            .get::<db::Token>()
            .username(&user.0)?
            .token_id(&id)?
            .execute()
            .await?
            .ok_or_else(|| "Forbidden")?;

        let api_key = random_key();
        let api_key = base64::encode_config(api_key, base64::URL_SAFE);

        token.key_hash = bcrypt::hash(&api_key, 12)?;
        self.db.put(token)?.execute().await?;

        Ok(api_key)
    }

    async fn delete_token(&self, ctx: &Context<'_>, id: uuid::Uuid) -> Result<bool> {
        let user = ctx.data_opt::<User>().ok_or_else(|| "Forbidden")?;
        self.db
            .delete::<db::Token>()
            .username(&user.0)?
            .token_id(&id)?
            .execute()
            .await?;

        Ok(true)
    }

    async fn create_spotify_token_auth_url(
        &self,
        ctx: &Context<'_>,
        name: String,
        scopes: Vec<SpotifyScope>,
    ) -> Result<String> {
        let user = ctx.data_opt::<User>().ok_or_else(|| "Forbidden")?;

        let claims = token::Claims {
            name,
            scopes: Scopes::Spotify(ScopeCollection { values: scopes }),
            username: user.0.to_owned(),
            expires: Utc::now() + Duration::minutes(10),
        };
        let state = jwt::encode(
            &jwt::Header::default(),
            &claims,
            &jwt::EncodingKey::from_base64_secret(&CONFIG.state_key)?,
        )?;
        let token::Claims {
            scopes: Scopes::Spotify(ScopeCollection { values: scopes }),
            ..
        } = claims;

        let (url, _) = CONFIG
            .spotify
            .oauth2_client(CONFIG.base_url.clone())
            .authorize_url(|| CsrfToken::new(state))
            .add_scopes(
                scopes
                    .iter()
                    .map(ProviderScopes::to_str)
                    .map(String::from)
                    .map(Scope::new),
            )
            .url();

        Ok(url.to_string())
    }

    async fn create_token(&self, code: String, state: String) -> Result<NewToken> {
        let token_data = jwt::decode(
            &state,
            &jwt::DecodingKey::from_base64_secret(&CONFIG.state_key)?,
            &jwt::Validation::default(),
        )?;
        let token::Claims {
            name,
            scopes,
            username,
            ..
        } = token_data.claims;

        let token = match &scopes {
            Scopes::Spotify(_) => {
                CONFIG
                    .spotify
                    .oauth2_client(CONFIG.base_url.clone())
                    .exchange_code(AuthorizationCode::new(code))
                    .request_async(async_http_client)
                    .await?
            }
        };

        let api_key = random_key();
        let api_key = base64::encode_config(api_key, base64::URL_SAFE);

        let id = Uuid::new_v4();
        let token = db::Token {
            token_id: id.clone(),
            username,
            name,
            scopes,

            key_hash: bcrypt::hash(&api_key, 12)?,

            access_token: token.access_token,
            refresh_token: token.refresh_token.ok_or("an error occurred")?,
            token_type: token.token_type,
            expires: Utc::now() + Duration::seconds(token.expires_in as i64),
        };

        self.db.put(token)?.execute().await?;

        Ok(NewToken { id, api_key })
    }
}

#[derive(SimpleObject)]
struct NewToken {
    id: uuid::Uuid,
    api_key: String,
}

pub fn random_key() -> [u8; 48] {
    use rand::Rng;

    let mut rng = rand::thread_rng();
    let mut key = [0; 48];
    rng.try_fill(&mut key[..]).unwrap();
    key
}
