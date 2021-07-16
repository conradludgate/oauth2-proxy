use crate::{
    config::Config,
    db::{Client, DynamoError, UserSession},
    templates,
};
use dynomite::dynamodb::PutItemError;
use rocket::{
    http::{uri::Absolute, Cookie, CookieJar, SameSite, Status},
    request::Request,
    response::{Redirect, Responder},
    Route, State,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::Duration;
use uuid::Uuid;

pub fn routes() -> Vec<Route> {
    routes![login, callback, callback_error]
}

#[derive(Serialize, Deserialize, Debug)]
struct AuthState {
    state: String,
    scopes: Vec<String>,
    login: bool,
}

#[get("/login/spotify")]
fn login(config: &State<Config>, cookies: &CookieJar<'_>) -> Redirect {
    use rand::Rng;

    let redirect_uri = format!("{}/api/callback/{}", config.base_url, "spotify");

    let mut rng = rand::thread_rng();
    let mut state = [0; 24];
    rng.try_fill(&mut state).unwrap();
    let state = base64::encode(&state);

    let url: Absolute = uri!(
        "https://accounts.spotify.com",
        authorize(
            response_type = "code",
            client_id = &config.spotify.client_id,
            redirect_uri = redirect_uri,
            state = &state
        )
    );

    let auth_state = AuthState {
        state,
        scopes: vec![],
        login: true,
    };
    let auth_state = serde_json::to_string(&auth_state).unwrap();

    let mut cookie = Cookie::new("state", auth_state);
    cookie.set_same_site(SameSite::Lax);
    cookie.set_max_age(Duration::minutes(1));
    cookies.add_private(cookie);

    Redirect::to(url)
}

#[get("/authorize?<response_type>&<client_id>&<redirect_uri>&<state>")]
#[allow(dead_code, unused_variables)]
const fn authorize(response_type: &str, client_id: &str, redirect_uri: &str, state: &str) {}

#[derive(Debug, Error)]
enum CallbackError {
    #[error("error making http request {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("error making db request {0}")]
    Dynamo(#[from] DynamoError<PutItemError>),
    #[error("error decoding json {0}")]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    Status(Status),
}

impl<'r, 'o: 'r> Responder<'r, 'o> for CallbackError {
    fn respond_to(self, r: &'r Request<'_>) -> rocket::response::Result<'o> {
        match self {
            CallbackError::Dynamo(d) => d.respond_to(r),
            CallbackError::Reqwest(e) => {
                error!("{}", e);
                Err(Status::InternalServerError)
            }
            CallbackError::Status(s) => Err(s),
            CallbackError::Json(j) => {
                error!("{}", j);
                Err(Status::InternalServerError)
            }
        }
    }
}

#[get("/callback/spotify?<code>&<state>")]
async fn callback(
    config: &State<Config>,
    db: &State<Client>,
    cookies: &CookieJar<'_>,
    code: &str,
    state: &str,
) -> Result<templates::Redirect, CallbackError> {
    #[derive(Deserialize, Debug)]
    pub struct AccessToken {
        pub access_token: String,
        pub refresh_token: String,
        pub expires_in: usize,
        pub token_type: String,
    }

    #[derive(Debug, Deserialize)]
    struct Me {
        id: String,
    }

    let redirect_uri = format!("{}/api/callback/{}", config.base_url, "spotify");

    let auth_state = cookies
        .get_private("state")
        .ok_or(CallbackError::Status(Status::ImATeapot))?;
    let auth_state: AuthState = serde_json::from_str(auth_state.value())?;

    if auth_state.state != state {
        error!("invalid state");
        return Err(CallbackError::Status(Status::BadRequest));
    }

    let crate::config::Client {
        client_id,
        client_secret,
    } = &config.spotify;

    let client = reqwest::Client::new();

    let token: AccessToken = client
        .post("https://accounts.spotify.com/api/token")
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", &redirect_uri),
        ])
        .basic_auth(client_id, Some(client_secret))
        .send()
        .await?
        .json()
        .await?;

    let me: Me = client
        .get("https://api.spotify.com/v1/me")
        .bearer_auth(token.access_token)
        .send()
        .await?
        .json()
        .await?;

    let session_id = Uuid::new_v4();

    cookies.add_private(Cookie::new("session", session_id.to_string()));

    db.save(UserSession {
        user_id: me.id,
        session_id,
    })
    .await?;

    Ok(templates::Redirect {
        text: "Click here to finish logging in".to_owned(),
        path: "/".to_owned(),
    })
}

#[get("/callback/spotify?<error>", rank = 2)]
fn callback_error(error: &str) -> Status {
    warn!("callback_error: {}", error);
    Status::Unauthorized
}
