use chrono::{Duration, Utc};
use jsonwebtoken::{encode, EncodingKey, Header};
use metrics::increment_counter;
use nitroglycerin::{
    dynamodb::{DynamoDbClient, GetItemError, PutItemError},
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

#[post("/register?<redirect_to>", data = "<login_data>")]
pub async fn post(db: &State<DynamoDbClient>, config: &State<Config>, cookies: &CookieJar<'_>, redirect_to: String, login_data: Form<Data>) -> Result<Redirect, Error> {
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

    let redirect_to = Origin::parse_owned(redirect_to).unwrap_or(uri!(crate::routes::home::page));

    increment_counter!("oauth2_proxy_users");

    Ok(Redirect::to(redirect_to))
}

#[get("/register?<redirect_to>")]
pub fn page(redirect_to: Option<String>) -> templates::Register {
    let redirect_to = redirect_to.unwrap_or_else(|| "/".to_owned());
    templates::Register { error: None, redirect_to }
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
    fn respond_to(self, request: &'r Request<'_>) -> rocket::response::Result<'o> {
        match self {
            Self::Bcrypt(bcrypt::BcryptError::InvalidPassword) => templates::Register {
                error: Some("password is invalid".to_owned()),
                redirect_to: request.query_value("redirect_to").ok_or(Status::BadRequest)?.map_err(|err| bail(err, Status::BadRequest))?,
            }
            .respond_to(request),
            Self::UserExists => templates::Register {
                error: Some("username already taken".to_owned()),
                redirect_to: request.query_value("redirect_to").ok_or(Status::BadRequest)?.map_err(|err| bail(err, Status::BadRequest))?,
            }
            .respond_to(request),
            _ => Err(bail(self, Status::InternalServerError)),
        }
    }
}
