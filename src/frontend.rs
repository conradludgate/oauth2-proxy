use std::str::FromStr;

use dynomite::dynamodb::{GetItemError, QueryError};
use rocket::{
    http::Status,
    request::{FromParam, FromRequest, Outcome, Request},
    response::Responder,
    Route,
};
use uuid::Uuid;

use crate::{
    db::{self, DynamoError, TokenKey, TokenUserIndex, TokenUserIndexKey, UserSessionKey},
    templates,
};

pub fn routes() -> Vec<Route> {
    routes![home, view_token, new_token]
}

struct UserID(String);
#[async_trait]
impl<'r> FromRequest<'r> for UserID {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let session_id = match request.cookies().get_private("session") {
            Some(session_id) => session_id,
            None => return Outcome::Failure((Status::Unauthorized, "invalid session cookie")),
        };

        let session_id = match session_id.value().to_string().parse() {
            Ok(session_id) => session_id,
            Err(_) => return Outcome::Failure((Status::Unauthorized, "invalid session cookie")),
        };

        let user_session = db::get(UserSessionKey { session_id }).await;
        match user_session {
            Ok(Some(user_session)) => Outcome::Success(Self(user_session.user_id)),
            Ok(None) | Err(_) => Outcome::Failure((Status::Unauthorized, "invalid session cookie")),
        }
    }
}

struct TokenID(Uuid);
#[async_trait]
impl<'a> FromParam<'a> for TokenID {
    type Error = <Uuid as FromStr>::Err;

    fn from_param(param: &'a str) -> Result<Self, Self::Error> {
        param.parse().map(TokenID)
    }
}

impl<'r, 'o: 'r, E: std::error::Error + 'static> Responder<'r, 'o> for DynamoError<E> {
    fn respond_to(self, _: &'r Request<'_>) -> rocket::response::Result<'o> {
        error!("{}", self);
        Err(Status::InternalServerError)
    }
}

#[get("/")]
async fn home(user_id: UserID) -> Result<templates::Home, DynamoError<QueryError>> {
    let tokens: Vec<TokenUserIndex> = db::query(TokenUserIndexKey { user_id: user_id.0 }).await?;

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
    token_id: TokenID,
    user_id: UserID,
) -> Result<Option<templates::ViewToken>, DynamoError<GetItemError>> {
    let token = db::get(TokenKey {
        token_id: token_id.0,
    })
    .await?;
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
