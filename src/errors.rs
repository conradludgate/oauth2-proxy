use http::{StatusCode, Uri};
use serde::Serialize;
use std::{convert::Infallible, error::Error, fmt::Debug};

#[derive(Debug)]
pub struct SessionUnauthorized;
impl warp::reject::Reject for SessionUnauthorized {}

#[derive(Debug)]
struct RusotoError<E>(rusoto_core::RusotoError<E>);
impl<E: Debug + Send + Sync + 'static> warp::reject::Reject for RusotoError<E> {}

#[derive(Debug)]
struct DynamoSerde(dynomite::AttributeError);
impl warp::reject::Reject for DynamoSerde {}

#[derive(Debug)]
struct UrlParseError2(http::uri::InvalidUri);
impl warp::reject::Reject for UrlParseError2 {}

#[derive(Debug)]
struct RequestError(reqwest::Error);
impl warp::reject::Reject for RequestError {}

#[derive(Serialize)]
struct ErrorMessage {
    code: u16,
    message: String,
}

pub async fn handle(err: warp::Rejection) -> Result<Box<dyn warp::Reply>, Infallible> {
    let code;
    let message;

    if err.is_not_found() {
        code = StatusCode::NOT_FOUND;
        message = "NOT_FOUND".into();
    } else if let Some(SessionUnauthorized) = err.find() {
        return Ok(Box::new(warp::redirect::see_other(Uri::from_static("/"))));
    } else if let Some(e) = err.find::<warp::filters::body::BodyDeserializeError>() {
        message = match e.source() {
            Some(cause) => {
                format!("BAD_REQUEST: {}", cause)
            }
            None => "BAD_REQUEST".into(),
        };
        code = StatusCode::BAD_REQUEST;
    } else if err.find::<warp::reject::MethodNotAllowed>().is_some() {
        code = StatusCode::METHOD_NOT_ALLOWED;
        message = "METHOD_NOT_ALLOWED".into();
    } else {
        eprintln!("unhandled rejection: {:?}", err);
        code = StatusCode::INTERNAL_SERVER_ERROR;
        message = "UNHANDLED_REJECTION".into();
    }

    let json = warp::reply::json(&ErrorMessage {
        code: code.as_u16(),
        message,
    });

    Ok(Box::new(warp::reply::with_status(json, code)))
}

pub trait Reject {
    fn reject(self) -> warp::Rejection;
}
pub fn reject(err: impl Reject) -> warp::Rejection {
    err.reject()
}

use crate::db::DynamoError;
impl<E: std::error::Error + Debug + Send + Sync + 'static> Reject for DynamoError<E> {
    fn reject(self) -> warp::Rejection {
        match self {
            DynamoError::ParseError(e) => warp::reject::custom(DynamoSerde(e)),
            DynamoError::Rusoto(e) => warp::reject::custom(RusotoError(e)),
        }
    }
}

impl Reject for http::uri::InvalidUri {
    fn reject(self) -> warp::Rejection {
        warp::reject::custom(UrlParseError2(self))
    }
}

impl Reject for reqwest::Error {
    fn reject(self) -> warp::Rejection {
        warp::reject::custom(RequestError(self))
    }
}
