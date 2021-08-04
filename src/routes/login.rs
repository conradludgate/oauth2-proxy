use askama_rocket::Responder;
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, EncodingKey, Header};
use nitroglycerin::{
    dynamodb::{DynamoDbClient, GetItemError},
    DynamoDb, DynamoError,
};
use rocket::{
    form::Form,
    http::{Cookie, CookieJar, SameSite, Status},
    request::Request,
    response::Redirect,
    State,
};
use thiserror::Error;

use crate::{config::Config, db::User, login, templates, util::bail};

#[post("/login", data = "<login_data>")]
pub async fn post(db: &State<DynamoDbClient>, config: &State<Config>, cookies: &CookieJar<'_>, login_data: Form<Data>) -> Result<Redirect, Error> {
    let Data { username, password } = login_data.into_inner();
    let user = db.get::<User>().username(&username).execute().await?;
    match user {
        None => return Err(Error::IncorrectPassword),
        Some(user) => {
            if !bcrypt::verify(password, &user.password_hash)? {
                return Err(Error::IncorrectPassword);
            }
        }
    };

    let claims = login::Claims {
        username,
        expires: Utc::now() + Duration::hours(1),
    };
    let value = encode(&Header::default(), &claims, &EncodingKey::from_base64_secret(&config.state_key)?)?;
    cookies.add(Cookie::build("access_token", value).http_only(true).same_site(SameSite::Strict).secure(true).finish());

    Ok(Redirect::to(uri!(crate::routes::home::page)))
}

#[get("/login")]
pub const fn page() -> templates::Login {
    templates::Login
}

#[derive(FromForm)]
pub struct Data {
    username: String,
    password: String,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("error making db request {0}")]
    DynamoGet(#[from] DynamoError<GetItemError>),
    #[error("error decoding json {0}")]
    Bcrypt(#[from] bcrypt::BcryptError),
    #[error("error encoding jwt {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
    #[error("invalid password")]
    IncorrectPassword,
}

impl<'r, 'o: 'r> Responder<'r, 'o> for Error {
    fn respond_to(self, _r: &'r Request<'_>) -> rocket::response::Result<'o> {
        match self {
            Self::Bcrypt(bcrypt::BcryptError::InvalidPassword) | Self::IncorrectPassword => Err(Status::Unauthorized),
            _ => bail(self, Status::InternalServerError),
        }
    }
}
