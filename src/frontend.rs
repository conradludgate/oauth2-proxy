use std::str::FromStr;

use dynomite::dynamodb::{GetItemError, QueryError};
use rocket::{
    http::{Cookie, CookieJar, Status},
    request::{FromParam, FromRequest, Outcome, Request},
    response::Responder,
    Route,
};
use uuid::Uuid;

use crate::{
    db::{
        DynamoError, DynamoPrimaryKey, DynamoSecondaryKey, ProviderKey, TokenKey,
        TokenUserIndexKey, UserSessionKey,
    },
    templates,
};

pub fn routes() -> Vec<Route> {
    routes![home, session, view_token, new_token]
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

        let user_session = UserSessionKey { session_id }.get().await;
        match user_session {
            Ok(Some(user_session)) => Outcome::Success(UserID(user_session.user_id)),
            Ok(None) => Outcome::Failure((Status::Unauthorized, "invalid session cookie")),
            Err(_) => Outcome::Failure((Status::Unauthorized, "invalid session cookie")),
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
    let tokens = TokenUserIndexKey { user_id: user_id.0 }.query().await?;

    Ok(templates::Home {
        tokens: tokens
            .into_iter()
            .map(|token| templates::HomeToken {
                id: token.token_id,
                name: token.name,
            })
            .collect(),
    })
}

#[get("/session")]
fn session(cookies: &CookieJar<'_>) {
    cookies.add_private(Cookie::new(
        "session",
        "072fd190-745f-4824-a69b-c71200f2271c",
    ));
}

#[get("/token/<token_id>")]
async fn view_token(
    token_id: TokenID,
    user_id: UserID,
) -> Result<Option<templates::ViewToken>, DynamoError<GetItemError>> {
    let token = TokenKey {
        token_id: token_id.0,
    }
    .get()
    .await?;
    let token = match token {
        Some(token) => token,
        None => return Ok(None),
    };

    if token.user_id != user_id.0 {
        Ok(None)
    } else {
        Ok(Some(templates::ViewToken {
            name: token.name,
            id: token.token_id,
            scopes: token.oauth.scopes,
            api_key: None,
        }))
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
