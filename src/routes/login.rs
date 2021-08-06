use chrono::{Duration, Utc};
use jsonwebtoken::{encode, EncodingKey, Header};
use nitroglycerin::{
    dynamodb::{DynamoDbClient, GetItemError},
    DynamoDb, DynamoError,
};
use rocket::{
    form::Form,
    http::{uri::Origin, Cookie, CookieJar, SameSite, Status},
    request::Request,
    response::{Redirect, Responder},
    State,
};
use thiserror::Error;

use crate::{config::Config, db::User, login, templates, util::bail};

#[post("/login?<redirect_to>", data = "<login_data>")]
pub async fn post(db: &State<DynamoDbClient>, config: &State<Config>, cookies: &CookieJar<'_>, redirect_to: String, login_data: Form<Data>) -> Result<Redirect, Error> {
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

    let redirect_to = Origin::parse_owned(redirect_to).unwrap_or(uri!(crate::routes::home::page));

    Ok(Redirect::to(redirect_to))
}

#[get("/login?<redirect_to>")]
pub fn page(redirect_to: Option<String>) -> templates::Login {
    let redirect_to = redirect_to.unwrap_or_else(|| "/".to_owned());
    templates::Login { error: None, redirect_to }
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
    fn respond_to(self, request: &'r Request<'_>) -> rocket::response::Result<'o> {
        match self {
            Self::Bcrypt(bcrypt::BcryptError::InvalidPassword) | Self::IncorrectPassword => templates::Login {
                error: Some("username or password incorrect".to_owned()),
                redirect_to: request.query_value("redirect_to").ok_or(Status::BadRequest)?.map_err(|err| bail(err, Status::BadRequest))?,
            }
            .respond_to(request),
            _ => Err(bail(self, Status::InternalServerError)),
        }
    }
}
