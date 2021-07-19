use std::error::Error;
use std::str::FromStr;

use askama_rocket::Responder;
use nitroglycerin::dynamodb::DynamoDbClient;
use nitroglycerin::DynamoDb;
use rocket::{
    http::Status,
    request::{FromParam, FromRequest, Outcome, Request},
    Route, State,
};
use uuid::Uuid;

use crate::db::{Token, UserSession};
use crate::{db::TokenUserIndex, templates};

pub fn routes() -> Vec<Route> {
    routes![home, view_token, new_token]
}

#[derive(Debug)]
pub struct InternalServerError(Box<dyn Error>);

impl<E: Error + 'static> From<E> for InternalServerError {
    fn from(e: E) -> Self {
        Self(Box::new(e))
    }
}
impl std::fmt::Display for InternalServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl<'r, 'o: 'r> Responder<'r, 'o> for InternalServerError {
    fn respond_to(self, _: &'r Request<'_>) -> rocket::response::Result<'o> {
        error!("{}", self);
        Err(Status::InternalServerError)
    }
}

struct UserID(String);
impl From<UserID> for String {
    fn from(u: UserID) -> Self {
        u.0
    }
}
#[async_trait]
impl<'r> FromRequest<'r> for UserID {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let session_id = match request.cookies().get_private("session") {
            Some(session_id) => session_id,
            None => return Outcome::Failure((Status::Unauthorized, "invalid session cookie")),
        };

        let session_id: Uuid = match session_id.value().to_string().parse() {
            Ok(session_id) => session_id,
            Err(_) => return Outcome::Failure((Status::Unauthorized, "invalid session cookie")),
        };

        let db: &DynamoDbClient = request.rocket().state().unwrap();
        let user_session = db
            .get::<UserSession>()
            .session_id(session_id)
            .execute()
            .await;
        match user_session {
            Ok(Some(user_session)) => Outcome::Success(Self(user_session.user_id)),
            Ok(None) | Err(_) => Outcome::Failure((Status::Unauthorized, "invalid session cookie")),
        }
    }
}

struct TokenID(Uuid);
impl From<TokenID> for Uuid {
    fn from(u: TokenID) -> Self {
        u.0
    }
}
#[async_trait]
impl<'a> FromParam<'a> for TokenID {
    type Error = <Uuid as FromStr>::Err;

    fn from_param(param: &'a str) -> Result<Self, Self::Error> {
        param.parse().map(TokenID)
    }
}

#[get("/")]
async fn home(
    db: &State<DynamoDbClient>,
    user_id: UserID,
) -> Result<templates::Home, InternalServerError> {
    let tokens = db
        .query::<TokenUserIndex>()
        .user_id(user_id)
        .execute()
        .await?;

    Ok(templates::Home {
        tokens: tokens
            .into_iter()
            .map(|token| templates::HomeToken {
                id: token.token_id,
                name: token.name,
            })
            .collect(),
        providers: vec![templates::Provider {
            slug: "spotify".to_owned(),
            name: "Spotify".to_owned(),
        }],
    })
}

#[get("/token/<token_id>")]
async fn view_token(
    db: &State<DynamoDbClient>,
    token_id: TokenID,
    user_id: UserID,
) -> Result<Option<templates::ViewToken>, InternalServerError> {
    let token = db.get::<Token>().token_id(token_id).execute().await?;
    let token = match token {
        Some(token) => token,
        None => return Ok(None),
    };

    if token.user_id == user_id.0 {
        Ok(Some(templates::ViewToken {
            name: token.name,
            id: token.token_id,
            scopes: token.oauth.scopes,
            api_key: None,
        }))
    } else {
        Ok(None)
    }
}

#[get("/token/spotify")]
fn new_token() -> templates::NewToken {
    templates::NewToken {
        scopes: vec![
            "ugc-image-upload".to_owned(),
            "user-read-recently-played".to_owned(),
            "user-top-read".to_owned(),
            "user-read-playback-position".to_owned(),
            "user-read-playback-state".to_owned(),
            "user-modify-playback-state".to_owned(),
            "user-read-currently-playing".to_owned(),
            "app-remote-control".to_owned(),
            "streaming".to_owned(),
            "playlist-modify-public".to_owned(),
            "playlist-modify-private".to_owned(),
            "playlist-read-private".to_owned(),
            "playlist-read-collaborative".to_owned(),
            "user-follow-modify".to_owned(),
            "user-follow-read".to_owned(),
            "user-library-modify".to_owned(),
            "user-library-read".to_owned(),
            "user-read-email".to_owned(),
            "user-read-private".to_owned(),
        ],
    }
}
