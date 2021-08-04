use askama_rocket::Responder;
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, EncodingKey, Header};
use nitroglycerin::{
    dynamodb::{DynamoDbClient, GetItemError, PutItemError},
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

#[post("/register", data = "<login_data>")]
pub async fn post(db: &State<DynamoDbClient>, config: &State<Config>, cookies: &CookieJar<'_>, login_data: Form<Data>) -> Result<Redirect, Error> {
    let Data { username, password } = login_data.into_inner();
    let user = db.get::<User>().username(&username).execute().await?;
    match user {
        None => {
            db.put(User {
                username: username.clone(),
                password_hash: bcrypt::hash(password, config.bcrypt_cost)?,
            })
            .execute()
            .await?;
        }
        Some(_) => return Err(Error::UserExists),
    };

    let claims = login::Claims {
        username,
        expires: Utc::now() + Duration::hours(1),
    };
    let value = encode(&Header::default(), &claims, &EncodingKey::from_base64_secret(&config.state_key)?)?;
    cookies.add(Cookie::build("access_token", value).http_only(true).same_site(SameSite::Strict).secure(true).finish());

    Ok(Redirect::to(uri!(crate::routes::home::page)))
}

#[get("/register")]
pub const fn page() -> templates::Register {
    templates::Register
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
    #[error("error making db request {0}")]
    DynamoPut(#[from] DynamoError<PutItemError>),
    #[error("error decoding json {0}")]
    Bcrypt(#[from] bcrypt::BcryptError),
    #[error("error encoding jwt {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
    #[error("user exists")]
    UserExists,
}

impl<'r, 'o: 'r> Responder<'r, 'o> for Error {
    fn respond_to(self, _r: &'r Request<'_>) -> rocket::response::Result<'o> {
        match self {
            Self::Bcrypt(bcrypt::BcryptError::InvalidPassword) | Self::UserExists => Err(Status::BadRequest),
            _ => bail(self, Status::InternalServerError),
        }
    }
}
