#![feature(prelude_import)]
#![allow(clippy::nonstandard_macro_braces)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![feature(once_cell)]
#[prelude_import]
use std::prelude::rust_2018::*;
#[macro_use]
extern crate std;
use actix_web::{App, HttpServer};
use nitroglycerin::dynamodb::DynamoDbClient;
use rusoto_core::Region;
use tracing_actix_web::TracingLogger;
mod actix_web_graphql {
    #![forbid(unsafe_code)]
    #![allow(clippy::upper_case_acronyms)]
    #![warn(missing_docs)]
    use std::future::Future;
    use std::io::{self, ErrorKind};
    use std::pin::Pin;
    use actix_web::dev::{Payload, PayloadStream};
    use actix_web::error::PayloadError;
    use actix_web::http::{Method, StatusCode};
    use actix_web::{http, Error, FromRequest, HttpRequest, HttpResponse, Responder, Result};
    use futures_util::future::{self, FutureExt};
    use futures_util::{StreamExt, TryStreamExt};
    use async_graphql::http::MultipartOptions;
    use async_graphql::ParseRequestError;
    /// Extractor for GraphQL request.
    ///
    /// `async_graphql::http::MultipartOptions` allows to configure extraction process.
    pub struct Request(pub async_graphql::Request);
    impl Request {
        /// Unwraps the value to `async_graphql::Request`.
        #[must_use]
        pub fn into_inner(self) -> async_graphql::Request {
            self.0
        }
    }
    type BatchToRequestMapper =
        fn(<<BatchRequest as FromRequest>::Future as Future>::Output) -> Result<Request>;
    impl FromRequest for Request {
        type Error = Error;
        type Future = future::Map<<BatchRequest as FromRequest>::Future, BatchToRequestMapper>;
        type Config = MultipartOptions;
        fn from_request(req: &HttpRequest, payload: &mut Payload<PayloadStream>) -> Self::Future {
            BatchRequest::from_request(req, payload).map(|res| {
                Ok(Self(
                    res?.0
                        .into_single()
                        .map_err(actix_web::error::ErrorBadRequest)?,
                ))
            })
        }
    }
    /// Extractor for GraphQL batch request.
    ///
    /// `async_graphql::http::MultipartOptions` allows to configure extraction process.
    pub struct BatchRequest(pub async_graphql::BatchRequest);
    impl FromRequest for BatchRequest {
        type Error = Error;
        type Future = Pin<Box<dyn Future<Output = Result<BatchRequest>>>>;
        type Config = MultipartOptions;
        fn from_request(req: &HttpRequest, payload: &mut Payload<PayloadStream>) -> Self::Future {
            let config = req.app_data::<Self::Config>().cloned().unwrap_or_default();
            if req.method() == Method::GET {
                let res = serde_urlencoded::from_str(req.query_string());
                Box::pin(async move { Ok(Self(async_graphql::BatchRequest::Single(res?))) })
            } else if req.method() == Method::POST {
                let content_type = req
                    .headers()
                    .get(http::header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok())
                    .map(|value| value.to_string());
                let (tx, rx) = async_channel::bounded(16);
                let mut payload = payload.take();
                actix::spawn(async move {
                    while let Some(item) = payload.next().await {
                        if tx.send(item).await.is_err() {
                            return;
                        }
                    }
                });
                Box::pin(async move {
                    Ok(BatchRequest(
                        async_graphql::http::receive_batch_body(
                            content_type,
                            rx.map_err(|e| match e {
                                PayloadError::Incomplete(Some(e)) | PayloadError::Io(e) => e,
                                PayloadError::Incomplete(None) => {
                                    io::Error::from(ErrorKind::UnexpectedEof)
                                }
                                PayloadError::EncodingCorrupted => io::Error::new(
                                    ErrorKind::InvalidData,
                                    "cannot decode content-encoding",
                                ),
                                PayloadError::Overflow => io::Error::new(
                                    ErrorKind::InvalidData,
                                    "a payload reached size limit",
                                ),
                                PayloadError::UnknownLength => {
                                    io::Error::new(ErrorKind::Other, "a payload length is unknown")
                                }
                                PayloadError::Http2Payload(e) if e.is_io() => e.into_io().unwrap(),
                                PayloadError::Http2Payload(e) => {
                                    io::Error::new(ErrorKind::Other, e)
                                }
                                _ => io::Error::new(ErrorKind::Other, "unknown error"),
                            })
                            .into_async_read(),
                            config,
                        )
                        .await
                        .map_err(|err| match err {
                            ParseRequestError::PayloadTooLarge => {
                                actix_web::error::ErrorPayloadTooLarge(err)
                            }
                            _ => actix_web::error::ErrorBadRequest(err),
                        })?,
                    ))
                })
            } else {
                Box::pin(async move {
                    Err(actix_web::error::ErrorMethodNotAllowed(
                        "GraphQL only supports GET and POST requests",
                    ))
                })
            }
        }
    }
    /// Responder for a GraphQL response.
    ///
    /// This contains a batch response, but since regular responses are a type of batch response it
    /// works for both.
    pub struct Response(pub async_graphql::BatchResponse);
    impl From<async_graphql::Response> for Response {
        fn from(resp: async_graphql::Response) -> Self {
            Self(resp.into())
        }
    }
    impl From<async_graphql::BatchResponse> for Response {
        fn from(resp: async_graphql::BatchResponse) -> Self {
            Self(resp)
        }
    }
    impl Responder for Response {
        fn respond_to(self, _req: &HttpRequest) -> HttpResponse {
            let mut res = HttpResponse::build(StatusCode::OK);
            res.content_type("application/json");
            if self.0.is_ok() {
                if let Some(cache_control) = self.0.cache_control().value() {
                    res.append_header(("cache-control", cache_control));
                }
            }
            for h in self.0.http_headers() {
                res.append_header(h);
            }
            HttpResponse::Ok().json(&self.0)
        }
    }
}
mod graphql {
    use actix_web::{
        dev::HttpServiceFactory, get, http::header, post, web, HttpRequest, HttpResponse, Result,
    };
    use async_graphql::{
        extensions::{ApolloTracing, Tracing},
        http::{playground_source, GraphQLPlaygroundConfig},
        EmptySubscription, Schema,
    };
    use jsonwebtoken as jwt;
    use nitroglycerin::dynamodb::DynamoDbClient;
    use query::User;
    use crate::{
        actix_web_graphql::{Request, Response},
        config::CONFIG,
        login::Claims,
    };
    mod mutation {
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
            provider::{ProviderScopes, ScopeCollection, Scopes, spotify::SpotifyScope},
            token,
        };
        pub struct Mutation {
            pub db: DynamoDbClient,
        }
        impl Mutation {
            async fn register(
                &self,
                _: &async_graphql::Context<'_>,
                username: String,
                password: String,
            ) -> Result<String> {
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
            async fn login(
                &self,
                _: &async_graphql::Context<'_>,
                username: String,
                password: String,
            ) -> Result<String> {
                let user = self
                    .db
                    .get::<db::User>()
                    .username(&username)?
                    .execute()
                    .await?;
                match user {
                    None => {
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
            async fn revoke_token_api_key(
                &self,
                ctx: &Context<'_>,
                id: uuid::Uuid,
            ) -> Result<String> {
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
                    scopes: Scopes::Spotify(ScopeCollection(scopes)),
                    username: user.0.to_owned(),
                    expires: Utc::now() + Duration::minutes(10),
                };
                let state = jwt::encode(
                    &jwt::Header::default(),
                    &claims,
                    &jwt::EncodingKey::from_base64_secret(&CONFIG.state_key)?,
                )?;
                let token::Claims {
                    scopes: Scopes::Spotify(ScopeCollection(scopes)),
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
            async fn create_token(
                &self,
                _: &async_graphql::Context<'_>,
                code: String,
                state: String,
            ) -> Result<NewToken> {
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
        #[allow(non_snake_case)]
        type __ShadowMutation = Mutation;
        #[allow(clippy::all, clippy::pedantic)]
        impl async_graphql::Type for __ShadowMutation {
            fn type_name() -> ::std::borrow::Cow<'static, ::std::primitive::str> {
                ::std::borrow::Cow::Borrowed("Mutation")
            }
            fn create_type_info(
                registry: &mut async_graphql::registry::Registry,
            ) -> ::std::string::String {
                let ty = registry . create_type :: < Self , _ > (| registry | async_graphql :: registry :: MetaType :: Object { name : :: std :: borrow :: ToOwned :: to_owned ("Mutation") , description : :: std :: option :: Option :: None , fields : { let mut fields = async_graphql :: indexmap :: IndexMap :: new () ; fields . insert (:: std :: borrow :: ToOwned :: to_owned ("register") , async_graphql :: registry :: MetaField { name : :: std :: borrow :: ToOwned :: to_owned ("register") , description : :: std :: option :: Option :: None , args : { let mut args = async_graphql :: indexmap :: IndexMap :: new () ; args . insert ("username" , async_graphql :: registry :: MetaInputValue { name : "username" , description : :: std :: option :: Option :: None , ty : < String as async_graphql :: Type > :: create_type_info (registry) , default_value : :: std :: option :: Option :: None , validator : :: std :: option :: Option :: None , visible : :: std :: option :: Option :: None , is_secret : false , }) ; args . insert ("password" , async_graphql :: registry :: MetaInputValue { name : "password" , description : :: std :: option :: Option :: None , ty : < String as async_graphql :: Type > :: create_type_info (registry) , default_value : :: std :: option :: Option :: None , validator : :: std :: option :: Option :: None , visible : :: std :: option :: Option :: None , is_secret : false , }) ; args } , ty : < String as async_graphql :: Type > :: create_type_info (registry) , deprecation : async_graphql :: registry :: Deprecation :: NoDeprecated , cache_control : async_graphql :: CacheControl { public : true , max_age : 0usize , } , external : false , provides : :: std :: option :: Option :: None , requires : :: std :: option :: Option :: None , visible : :: std :: option :: Option :: None , compute_complexity : :: std :: option :: Option :: None , }) ; fields . insert (:: std :: borrow :: ToOwned :: to_owned ("login") , async_graphql :: registry :: MetaField { name : :: std :: borrow :: ToOwned :: to_owned ("login") , description : :: std :: option :: Option :: None , args : { let mut args = async_graphql :: indexmap :: IndexMap :: new () ; args . insert ("username" , async_graphql :: registry :: MetaInputValue { name : "username" , description : :: std :: option :: Option :: None , ty : < String as async_graphql :: Type > :: create_type_info (registry) , default_value : :: std :: option :: Option :: None , validator : :: std :: option :: Option :: None , visible : :: std :: option :: Option :: None , is_secret : false , }) ; args . insert ("password" , async_graphql :: registry :: MetaInputValue { name : "password" , description : :: std :: option :: Option :: None , ty : < String as async_graphql :: Type > :: create_type_info (registry) , default_value : :: std :: option :: Option :: None , validator : :: std :: option :: Option :: None , visible : :: std :: option :: Option :: None , is_secret : false , }) ; args } , ty : < String as async_graphql :: Type > :: create_type_info (registry) , deprecation : async_graphql :: registry :: Deprecation :: NoDeprecated , cache_control : async_graphql :: CacheControl { public : true , max_age : 0usize , } , external : false , provides : :: std :: option :: Option :: None , requires : :: std :: option :: Option :: None , visible : :: std :: option :: Option :: None , compute_complexity : :: std :: option :: Option :: None , }) ; fields . insert (:: std :: borrow :: ToOwned :: to_owned ("revokeTokenApiKey") , async_graphql :: registry :: MetaField { name : :: std :: borrow :: ToOwned :: to_owned ("revokeTokenApiKey") , description : :: std :: option :: Option :: None , args : { let mut args = async_graphql :: indexmap :: IndexMap :: new () ; args . insert ("id" , async_graphql :: registry :: MetaInputValue { name : "id" , description : :: std :: option :: Option :: None , ty : < uuid :: Uuid as async_graphql :: Type > :: create_type_info (registry) , default_value : :: std :: option :: Option :: None , validator : :: std :: option :: Option :: None , visible : :: std :: option :: Option :: None , is_secret : false , }) ; args } , ty : < String as async_graphql :: Type > :: create_type_info (registry) , deprecation : async_graphql :: registry :: Deprecation :: NoDeprecated , cache_control : async_graphql :: CacheControl { public : true , max_age : 0usize , } , external : false , provides : :: std :: option :: Option :: None , requires : :: std :: option :: Option :: None , visible : :: std :: option :: Option :: None , compute_complexity : :: std :: option :: Option :: None , }) ; fields . insert (:: std :: borrow :: ToOwned :: to_owned ("deleteToken") , async_graphql :: registry :: MetaField { name : :: std :: borrow :: ToOwned :: to_owned ("deleteToken") , description : :: std :: option :: Option :: None , args : { let mut args = async_graphql :: indexmap :: IndexMap :: new () ; args . insert ("id" , async_graphql :: registry :: MetaInputValue { name : "id" , description : :: std :: option :: Option :: None , ty : < uuid :: Uuid as async_graphql :: Type > :: create_type_info (registry) , default_value : :: std :: option :: Option :: None , validator : :: std :: option :: Option :: None , visible : :: std :: option :: Option :: None , is_secret : false , }) ; args } , ty : < bool as async_graphql :: Type > :: create_type_info (registry) , deprecation : async_graphql :: registry :: Deprecation :: NoDeprecated , cache_control : async_graphql :: CacheControl { public : true , max_age : 0usize , } , external : false , provides : :: std :: option :: Option :: None , requires : :: std :: option :: Option :: None , visible : :: std :: option :: Option :: None , compute_complexity : :: std :: option :: Option :: None , }) ; fields . insert (:: std :: borrow :: ToOwned :: to_owned ("createSpotifyTokenAuthUrl") , async_graphql :: registry :: MetaField { name : :: std :: borrow :: ToOwned :: to_owned ("createSpotifyTokenAuthUrl") , description : :: std :: option :: Option :: None , args : { let mut args = async_graphql :: indexmap :: IndexMap :: new () ; args . insert ("name" , async_graphql :: registry :: MetaInputValue { name : "name" , description : :: std :: option :: Option :: None , ty : < String as async_graphql :: Type > :: create_type_info (registry) , default_value : :: std :: option :: Option :: None , validator : :: std :: option :: Option :: None , visible : :: std :: option :: Option :: None , is_secret : false , }) ; args . insert ("scopes" , async_graphql :: registry :: MetaInputValue { name : "scopes" , description : :: std :: option :: Option :: None , ty : < Vec < SpotifyScope > as async_graphql :: Type > :: create_type_info (registry) , default_value : :: std :: option :: Option :: None , validator : :: std :: option :: Option :: None , visible : :: std :: option :: Option :: None , is_secret : false , }) ; args } , ty : < String as async_graphql :: Type > :: create_type_info (registry) , deprecation : async_graphql :: registry :: Deprecation :: NoDeprecated , cache_control : async_graphql :: CacheControl { public : true , max_age : 0usize , } , external : false , provides : :: std :: option :: Option :: None , requires : :: std :: option :: Option :: None , visible : :: std :: option :: Option :: None , compute_complexity : :: std :: option :: Option :: None , }) ; fields . insert (:: std :: borrow :: ToOwned :: to_owned ("createToken") , async_graphql :: registry :: MetaField { name : :: std :: borrow :: ToOwned :: to_owned ("createToken") , description : :: std :: option :: Option :: None , args : { let mut args = async_graphql :: indexmap :: IndexMap :: new () ; args . insert ("code" , async_graphql :: registry :: MetaInputValue { name : "code" , description : :: std :: option :: Option :: None , ty : < String as async_graphql :: Type > :: create_type_info (registry) , default_value : :: std :: option :: Option :: None , validator : :: std :: option :: Option :: None , visible : :: std :: option :: Option :: None , is_secret : false , }) ; args . insert ("state" , async_graphql :: registry :: MetaInputValue { name : "state" , description : :: std :: option :: Option :: None , ty : < String as async_graphql :: Type > :: create_type_info (registry) , default_value : :: std :: option :: Option :: None , validator : :: std :: option :: Option :: None , visible : :: std :: option :: Option :: None , is_secret : false , }) ; args } , ty : < NewToken as async_graphql :: Type > :: create_type_info (registry) , deprecation : async_graphql :: registry :: Deprecation :: NoDeprecated , cache_control : async_graphql :: CacheControl { public : true , max_age : 0usize , } , external : false , provides : :: std :: option :: Option :: None , requires : :: std :: option :: Option :: None , visible : :: std :: option :: Option :: None , compute_complexity : :: std :: option :: Option :: None , }) ; fields } , cache_control : async_graphql :: CacheControl { public : true , max_age : 0usize , } , extends : false , keys : :: std :: option :: Option :: None , visible : :: std :: option :: Option :: None , }) ;
                ty
            }
        }
        #[allow(clippy::all, clippy::pedantic, clippy::suspicious_else_formatting)]
        #[allow(unused_braces, unused_variables, unused_parens, unused_mut)]
        impl async_graphql::resolver_utils::ContainerType for __ShadowMutation {
            #[allow(
                clippy::let_unit_value,
                clippy::type_complexity,
                clippy::type_repetition_in_bounds,
                clippy::used_underscore_binding
            )]
            fn resolve_field<'life0, 'life1, 'life2, 'async_trait>(
                &'life0 self,
                ctx: &'life1 async_graphql::Context<'life2>,
            ) -> ::core::pin::Pin<
                Box<
                    dyn ::core::future::Future<
                            Output = async_graphql::ServerResult<
                                ::std::option::Option<async_graphql::Value>,
                            >,
                        > + ::core::marker::Send
                        + 'async_trait,
                >,
            >
            where
                'life0: 'async_trait,
                'life1: 'async_trait,
                'life2: 'async_trait,
                Self: 'async_trait,
            {
                Box::pin(async move {
                    if let ::core::option::Option::Some(__ret) = ::core::option::Option::None::<
                        async_graphql::ServerResult<::std::option::Option<async_graphql::Value>>,
                    > {
                        return __ret;
                    }
                    let __self = self;
                    let ctx = ctx;
                    let __ret: async_graphql::ServerResult<
                        ::std::option::Option<async_graphql::Value>,
                    > = {
                        if ctx.item.node.name.node == "register" {
                            let f = async move {
                                #[allow(non_snake_case)]
                                let __username_getter =
                                    || -> async_graphql::ServerResult<String> {
                                        ctx.param_value("username", ::std::option::Option::None)
                                    };
                                #[allow(non_snake_case)]
                                let username: String = __username_getter()?;
                                #[allow(non_snake_case)]
                                let __password_getter =
                                    || -> async_graphql::ServerResult<String> {
                                        ctx.param_value("password", ::std::option::Option::None)
                                    };
                                #[allow(non_snake_case)]
                                let password: String = __password_getter()?;
                                {
                                    let res = __self.register(ctx, username, password).await;
                                    res.map_err(|err| {
                                        ::std::convert::Into::<async_graphql::Error>::into(err)
                                            .into_server_error(ctx.item.pos)
                                    })
                                }
                            };
                            let obj = f.await.map_err(|err| ctx.set_error_path(err))?;
                            let ctx_obj = ctx.with_selection_set(&ctx.item.node.selection_set);
                            return async_graphql::OutputType::resolve(&obj, &ctx_obj, ctx.item)
                                .await
                                .map(::std::option::Option::Some);
                        }
                        if ctx.item.node.name.node == "login" {
                            let f = async move {
                                #[allow(non_snake_case)]
                                let __username_getter =
                                    || -> async_graphql::ServerResult<String> {
                                        ctx.param_value("username", ::std::option::Option::None)
                                    };
                                #[allow(non_snake_case)]
                                let username: String = __username_getter()?;
                                #[allow(non_snake_case)]
                                let __password_getter =
                                    || -> async_graphql::ServerResult<String> {
                                        ctx.param_value("password", ::std::option::Option::None)
                                    };
                                #[allow(non_snake_case)]
                                let password: String = __password_getter()?;
                                {
                                    let res = __self.login(ctx, username, password).await;
                                    res.map_err(|err| {
                                        ::std::convert::Into::<async_graphql::Error>::into(err)
                                            .into_server_error(ctx.item.pos)
                                    })
                                }
                            };
                            let obj = f.await.map_err(|err| ctx.set_error_path(err))?;
                            let ctx_obj = ctx.with_selection_set(&ctx.item.node.selection_set);
                            return async_graphql::OutputType::resolve(&obj, &ctx_obj, ctx.item)
                                .await
                                .map(::std::option::Option::Some);
                        }
                        if ctx.item.node.name.node == "revokeTokenApiKey" {
                            let f = async move {
                                #[allow(non_snake_case)]
                                let __id_getter = || -> async_graphql::ServerResult<uuid::Uuid> {
                                    ctx.param_value("id", ::std::option::Option::None)
                                };
                                #[allow(non_snake_case)]
                                let id: uuid::Uuid = __id_getter()?;
                                {
                                    let res = __self.revoke_token_api_key(ctx, id).await;
                                    res.map_err(|err| {
                                        ::std::convert::Into::<async_graphql::Error>::into(err)
                                            .into_server_error(ctx.item.pos)
                                    })
                                }
                            };
                            let obj = f.await.map_err(|err| ctx.set_error_path(err))?;
                            let ctx_obj = ctx.with_selection_set(&ctx.item.node.selection_set);
                            return async_graphql::OutputType::resolve(&obj, &ctx_obj, ctx.item)
                                .await
                                .map(::std::option::Option::Some);
                        }
                        if ctx.item.node.name.node == "deleteToken" {
                            let f = async move {
                                #[allow(non_snake_case)]
                                let __id_getter = || -> async_graphql::ServerResult<uuid::Uuid> {
                                    ctx.param_value("id", ::std::option::Option::None)
                                };
                                #[allow(non_snake_case)]
                                let id: uuid::Uuid = __id_getter()?;
                                {
                                    let res = __self.delete_token(ctx, id).await;
                                    res.map_err(|err| {
                                        ::std::convert::Into::<async_graphql::Error>::into(err)
                                            .into_server_error(ctx.item.pos)
                                    })
                                }
                            };
                            let obj = f.await.map_err(|err| ctx.set_error_path(err))?;
                            let ctx_obj = ctx.with_selection_set(&ctx.item.node.selection_set);
                            return async_graphql::OutputType::resolve(&obj, &ctx_obj, ctx.item)
                                .await
                                .map(::std::option::Option::Some);
                        }
                        if ctx.item.node.name.node == "createSpotifyTokenAuthUrl" {
                            let f = async move {
                                #[allow(non_snake_case)]
                                let __name_getter = || -> async_graphql::ServerResult<String> {
                                    ctx.param_value("name", ::std::option::Option::None)
                                };
                                #[allow(non_snake_case)]
                                let name: String = __name_getter()?;
                                #[allow(non_snake_case)]
                                let __scopes_getter =
                                    || -> async_graphql::ServerResult<Vec<SpotifyScope>> {
                                        ctx.param_value("scopes", ::std::option::Option::None)
                                    };
                                #[allow(non_snake_case)]
                                let scopes: Vec<SpotifyScope> = __scopes_getter()?;
                                {
                                    let res = __self
                                        .create_spotify_token_auth_url(ctx, name, scopes)
                                        .await;
                                    res.map_err(|err| {
                                        ::std::convert::Into::<async_graphql::Error>::into(err)
                                            .into_server_error(ctx.item.pos)
                                    })
                                }
                            };
                            let obj = f.await.map_err(|err| ctx.set_error_path(err))?;
                            let ctx_obj = ctx.with_selection_set(&ctx.item.node.selection_set);
                            return async_graphql::OutputType::resolve(&obj, &ctx_obj, ctx.item)
                                .await
                                .map(::std::option::Option::Some);
                        }
                        if ctx.item.node.name.node == "createToken" {
                            let f = async move {
                                #[allow(non_snake_case)]
                                let __code_getter = || -> async_graphql::ServerResult<String> {
                                    ctx.param_value("code", ::std::option::Option::None)
                                };
                                #[allow(non_snake_case)]
                                let code: String = __code_getter()?;
                                #[allow(non_snake_case)]
                                let __state_getter = || -> async_graphql::ServerResult<String> {
                                    ctx.param_value("state", ::std::option::Option::None)
                                };
                                #[allow(non_snake_case)]
                                let state: String = __state_getter()?;
                                {
                                    let res = __self.create_token(ctx, code, state).await;
                                    res.map_err(|err| {
                                        ::std::convert::Into::<async_graphql::Error>::into(err)
                                            .into_server_error(ctx.item.pos)
                                    })
                                }
                            };
                            let obj = f.await.map_err(|err| ctx.set_error_path(err))?;
                            let ctx_obj = ctx.with_selection_set(&ctx.item.node.selection_set);
                            return async_graphql::OutputType::resolve(&obj, &ctx_obj, ctx.item)
                                .await
                                .map(::std::option::Option::Some);
                        }
                        ::std::result::Result::Ok(::std::option::Option::None)
                    };
                    #[allow(unreachable_code)]
                    __ret
                })
            }
            #[allow(
                clippy::let_unit_value,
                clippy::type_complexity,
                clippy::type_repetition_in_bounds,
                clippy::used_underscore_binding
            )]
            fn find_entity<'life0, 'life1, 'life2, 'life3, 'async_trait>(
                &'life0 self,
                ctx: &'life1 async_graphql::Context<'life2>,
                params: &'life3 async_graphql::Value,
            ) -> ::core::pin::Pin<
                Box<
                    dyn ::core::future::Future<
                            Output = async_graphql::ServerResult<
                                ::std::option::Option<async_graphql::Value>,
                            >,
                        > + ::core::marker::Send
                        + 'async_trait,
                >,
            >
            where
                'life0: 'async_trait,
                'life1: 'async_trait,
                'life2: 'async_trait,
                'life3: 'async_trait,
                Self: 'async_trait,
            {
                Box::pin(async move {
                    if let ::core::option::Option::Some(__ret) = ::core::option::Option::None::<
                        async_graphql::ServerResult<::std::option::Option<async_graphql::Value>>,
                    > {
                        return __ret;
                    }
                    let __self = self;
                    let ctx = ctx;
                    let params = params;
                    let __ret: async_graphql::ServerResult<
                        ::std::option::Option<async_graphql::Value>,
                    > = {
                        let params = match params {
                            async_graphql::Value::Object(params) => params,
                            _ => return ::std::result::Result::Ok(::std::option::Option::None),
                        };
                        let typename = if let ::std::option::Option::Some(
                            async_graphql::Value::String(typename),
                        ) = params.get("__typename")
                        {
                            typename
                        } else {
                            return ::std::result::Result::Err(async_graphql::ServerError::new(
                                r#""__typename" must be an existing string."#,
                                ::std::option::Option::Some(ctx.item.pos),
                            ));
                        };
                        ::std::result::Result::Ok(::std::option::Option::None)
                    };
                    #[allow(unreachable_code)]
                    __ret
                })
            }
        }
        #[allow(clippy::all, clippy::pedantic)]
        impl async_graphql::OutputType for __ShadowMutation {
            #[allow(
                clippy::let_unit_value,
                clippy::type_complexity,
                clippy::type_repetition_in_bounds,
                clippy::used_underscore_binding
            )]
            fn resolve<'life0, 'life1, 'life2, 'life3, 'async_trait>(
                &'life0 self,
                ctx: &'life1 async_graphql::ContextSelectionSet<'life2>,
                _field: &'life3 async_graphql::Positioned<async_graphql::parser::types::Field>,
            ) -> ::core::pin::Pin<
                Box<
                    dyn ::core::future::Future<
                            Output = async_graphql::ServerResult<async_graphql::Value>,
                        > + ::core::marker::Send
                        + 'async_trait,
                >,
            >
            where
                'life0: 'async_trait,
                'life1: 'async_trait,
                'life2: 'async_trait,
                'life3: 'async_trait,
                Self: 'async_trait,
            {
                Box::pin(async move {
                    if let ::core::option::Option::Some(__ret) = ::core::option::Option::None::<
                        async_graphql::ServerResult<async_graphql::Value>,
                    > {
                        return __ret;
                    }
                    let __self = self;
                    let ctx = ctx;
                    let _field = _field;
                    let __ret: async_graphql::ServerResult<async_graphql::Value> =
                        { async_graphql::resolver_utils::resolve_container(ctx, __self).await };
                    #[allow(unreachable_code)]
                    __ret
                })
            }
        }
        impl async_graphql::ObjectType for __ShadowMutation {}
        struct NewToken {
            id: uuid::Uuid,
            api_key: String,
        }
        #[allow(clippy::all, clippy::pedantic)]
        impl NewToken {
            #[inline]
            #[allow(missing_docs)]
            async fn id(
                &self,
                ctx: &async_graphql::Context<'_>,
            ) -> async_graphql::Result<&uuid::Uuid> {
                ::std::result::Result::Ok(&self.id)
            }
            #[inline]
            #[allow(missing_docs)]
            async fn api_key(
                &self,
                ctx: &async_graphql::Context<'_>,
            ) -> async_graphql::Result<&String> {
                ::std::result::Result::Ok(&self.api_key)
            }
        }
        #[allow(clippy::all, clippy::pedantic)]
        impl async_graphql::Type for NewToken {
            fn type_name() -> ::std::borrow::Cow<'static, ::std::primitive::str> {
                ::std::borrow::Cow::Borrowed("NewToken")
            }
            fn create_type_info(
                registry: &mut async_graphql::registry::Registry,
            ) -> ::std::string::String {
                registry.create_type::<Self, _>(|registry| {
                    async_graphql::registry::MetaType::Object {
                        name: ::std::borrow::ToOwned::to_owned("NewToken"),
                        description: ::std::option::Option::None,
                        fields: {
                            let mut fields = async_graphql::indexmap::IndexMap::new();
                            fields.insert(
                                ::std::borrow::ToOwned::to_owned("id"),
                                async_graphql::registry::MetaField {
                                    name: ::std::borrow::ToOwned::to_owned("id"),
                                    description: ::std::option::Option::None,
                                    args: ::std::default::Default::default(),
                                    ty: <uuid::Uuid as async_graphql::Type>::create_type_info(
                                        registry,
                                    ),
                                    deprecation: async_graphql::registry::Deprecation::NoDeprecated,
                                    cache_control: async_graphql::CacheControl {
                                        public: true,
                                        max_age: 0usize,
                                    },
                                    external: false,
                                    provides: ::std::option::Option::None,
                                    requires: ::std::option::Option::None,
                                    visible: ::std::option::Option::None,
                                    compute_complexity: ::std::option::Option::None,
                                },
                            );
                            fields.insert(
                                ::std::borrow::ToOwned::to_owned("apiKey"),
                                async_graphql::registry::MetaField {
                                    name: ::std::borrow::ToOwned::to_owned("apiKey"),
                                    description: ::std::option::Option::None,
                                    args: ::std::default::Default::default(),
                                    ty: <String as async_graphql::Type>::create_type_info(registry),
                                    deprecation: async_graphql::registry::Deprecation::NoDeprecated,
                                    cache_control: async_graphql::CacheControl {
                                        public: true,
                                        max_age: 0usize,
                                    },
                                    external: false,
                                    provides: ::std::option::Option::None,
                                    requires: ::std::option::Option::None,
                                    visible: ::std::option::Option::None,
                                    compute_complexity: ::std::option::Option::None,
                                },
                            );
                            fields
                        },
                        cache_control: async_graphql::CacheControl {
                            public: true,
                            max_age: 0usize,
                        },
                        extends: false,
                        keys: ::std::option::Option::None,
                        visible: ::std::option::Option::None,
                    }
                })
            }
        }
        #[allow(clippy::all, clippy::pedantic)]
        impl async_graphql::resolver_utils::ContainerType for NewToken {
            #[allow(
                clippy::let_unit_value,
                clippy::type_complexity,
                clippy::type_repetition_in_bounds,
                clippy::used_underscore_binding
            )]
            fn resolve_field<'life0, 'life1, 'life2, 'async_trait>(
                &'life0 self,
                ctx: &'life1 async_graphql::Context<'life2>,
            ) -> ::core::pin::Pin<
                Box<
                    dyn ::core::future::Future<
                            Output = async_graphql::ServerResult<
                                ::std::option::Option<async_graphql::Value>,
                            >,
                        > + ::core::marker::Send
                        + 'async_trait,
                >,
            >
            where
                'life0: 'async_trait,
                'life1: 'async_trait,
                'life2: 'async_trait,
                Self: 'async_trait,
            {
                Box::pin(async move {
                    if let ::core::option::Option::Some(__ret) = ::core::option::Option::None::<
                        async_graphql::ServerResult<::std::option::Option<async_graphql::Value>>,
                    > {
                        return __ret;
                    }
                    let __self = self;
                    let ctx = ctx;
                    let __ret: async_graphql::ServerResult<
                        ::std::option::Option<async_graphql::Value>,
                    > = {
                        if ctx.item.node.name.node == "id" {
                            let f = async move {
                                __self
                                    .id(ctx)
                                    .await
                                    .map_err(|err| err.into_server_error(ctx.item.pos))
                            };
                            let obj = f.await.map_err(|err| ctx.set_error_path(err))?;
                            let ctx_obj = ctx.with_selection_set(&ctx.item.node.selection_set);
                            return async_graphql::OutputType::resolve(&obj, &ctx_obj, ctx.item)
                                .await
                                .map(::std::option::Option::Some);
                        }
                        if ctx.item.node.name.node == "apiKey" {
                            let f = async move {
                                __self
                                    .api_key(ctx)
                                    .await
                                    .map_err(|err| err.into_server_error(ctx.item.pos))
                            };
                            let obj = f.await.map_err(|err| ctx.set_error_path(err))?;
                            let ctx_obj = ctx.with_selection_set(&ctx.item.node.selection_set);
                            return async_graphql::OutputType::resolve(&obj, &ctx_obj, ctx.item)
                                .await
                                .map(::std::option::Option::Some);
                        }
                        ::std::result::Result::Ok(::std::option::Option::None)
                    };
                    #[allow(unreachable_code)]
                    __ret
                })
            }
        }
        #[allow(clippy::all, clippy::pedantic)]
        impl async_graphql::OutputType for NewToken {
            #[allow(
                clippy::let_unit_value,
                clippy::type_complexity,
                clippy::type_repetition_in_bounds,
                clippy::used_underscore_binding
            )]
            fn resolve<'life0, 'life1, 'life2, 'life3, 'async_trait>(
                &'life0 self,
                ctx: &'life1 async_graphql::ContextSelectionSet<'life2>,
                _field: &'life3 async_graphql::Positioned<async_graphql::parser::types::Field>,
            ) -> ::core::pin::Pin<
                Box<
                    dyn ::core::future::Future<
                            Output = async_graphql::ServerResult<async_graphql::Value>,
                        > + ::core::marker::Send
                        + 'async_trait,
                >,
            >
            where
                'life0: 'async_trait,
                'life1: 'async_trait,
                'life2: 'async_trait,
                'life3: 'async_trait,
                Self: 'async_trait,
            {
                Box::pin(async move {
                    if let ::core::option::Option::Some(__ret) = ::core::option::Option::None::<
                        async_graphql::ServerResult<async_graphql::Value>,
                    > {
                        return __ret;
                    }
                    let __self = self;
                    let ctx = ctx;
                    let _field = _field;
                    let __ret: async_graphql::ServerResult<async_graphql::Value> =
                        { async_graphql::resolver_utils::resolve_container(ctx, __self).await };
                    #[allow(unreachable_code)]
                    __ret
                })
            }
        }
        impl async_graphql::ObjectType for NewToken {}
        pub fn random_key() -> [u8; 48] {
            use rand::Rng;
            let mut rng = rand::thread_rng();
            let mut key = [0; 48];
            rng.try_fill(&mut key[..]).unwrap();
            key
        }
    }
    mod query {
        use async_graphql::{Context, Object, Result, SimpleObject};
        use nitroglycerin::{dynamodb::DynamoDbClient, DynamoDb};
        use crate::{
            db,
            provider::{ScopeCollection, Scopes, spotify::SpotifyScope},
        };
        pub struct Query {
            pub db: DynamoDbClient,
        }
        impl Query {
            async fn version(
                &self,
                _: &async_graphql::Context<'_>,
            ) -> async_graphql::Result<String> {
                {
                    ::std::result::Result::Ok(
                        async move {
                            let value: String = { "0.1.0".to_string() };
                            value
                        }
                        .await,
                    )
                }
            }
            async fn tokens(&self, ctx: &Context<'_>) -> Result<Vec<Token>> {
                let user = ctx.data_opt::<User>().ok_or_else(|| "Forbidden")?;
                let tokens = self
                    .db
                    .query::<db::Token>()
                    .username(&user.0)
                    .execute()
                    .await?
                    .into_iter()
                    .map(Token::from)
                    .collect();
                Ok(tokens)
            }
            async fn token(&self, ctx: &Context<'_>, id: uuid::Uuid) -> Result<Token> {
                let user = ctx.data_opt::<User>().ok_or_else(|| "Forbidden")?;
                let token = self
                    .db
                    .get::<db::Token>()
                    .username(&user.0)?
                    .token_id(&id)?
                    .execute()
                    .await?
                    .ok_or_else(|| "Not Found")?;
                Ok(token.into())
            }
            async fn scope(&self, _: &async_graphql::Context<'_>) -> Result<Scopes> {
                Ok(Scopes::Spotify(ScopeCollection(<[_]>::into_vec(box [
                    SpotifyScope::UserLibraryRead,
                    SpotifyScope::UserFollowModify,
                ]))))
            }
        }
        #[allow(non_snake_case)]
        type __ShadowQuery = Query;
        #[allow(clippy::all, clippy::pedantic)]
        impl async_graphql::Type for __ShadowQuery {
            fn type_name() -> ::std::borrow::Cow<'static, ::std::primitive::str> {
                ::std::borrow::Cow::Borrowed("Query")
            }
            fn create_type_info(
                registry: &mut async_graphql::registry::Registry,
            ) -> ::std::string::String {
                let ty = registry . create_type :: < Self , _ > (| registry | async_graphql :: registry :: MetaType :: Object { name : :: std :: borrow :: ToOwned :: to_owned ("Query") , description : :: std :: option :: Option :: None , fields : { let mut fields = async_graphql :: indexmap :: IndexMap :: new () ; fields . insert (:: std :: borrow :: ToOwned :: to_owned ("version") , async_graphql :: registry :: MetaField { name : :: std :: borrow :: ToOwned :: to_owned ("version") , description : :: std :: option :: Option :: None , args : { let mut args = async_graphql :: indexmap :: IndexMap :: new () ; args } , ty : < String as async_graphql :: Type > :: create_type_info (registry) , deprecation : async_graphql :: registry :: Deprecation :: NoDeprecated , cache_control : async_graphql :: CacheControl { public : true , max_age : 0usize , } , external : false , provides : :: std :: option :: Option :: None , requires : :: std :: option :: Option :: None , visible : :: std :: option :: Option :: None , compute_complexity : :: std :: option :: Option :: None , }) ; fields . insert (:: std :: borrow :: ToOwned :: to_owned ("tokens") , async_graphql :: registry :: MetaField { name : :: std :: borrow :: ToOwned :: to_owned ("tokens") , description : :: std :: option :: Option :: None , args : { let mut args = async_graphql :: indexmap :: IndexMap :: new () ; args } , ty : < Vec < Token > as async_graphql :: Type > :: create_type_info (registry) , deprecation : async_graphql :: registry :: Deprecation :: NoDeprecated , cache_control : async_graphql :: CacheControl { public : true , max_age : 0usize , } , external : false , provides : :: std :: option :: Option :: None , requires : :: std :: option :: Option :: None , visible : :: std :: option :: Option :: None , compute_complexity : :: std :: option :: Option :: None , }) ; fields . insert (:: std :: borrow :: ToOwned :: to_owned ("token") , async_graphql :: registry :: MetaField { name : :: std :: borrow :: ToOwned :: to_owned ("token") , description : :: std :: option :: Option :: None , args : { let mut args = async_graphql :: indexmap :: IndexMap :: new () ; args . insert ("id" , async_graphql :: registry :: MetaInputValue { name : "id" , description : :: std :: option :: Option :: None , ty : < uuid :: Uuid as async_graphql :: Type > :: create_type_info (registry) , default_value : :: std :: option :: Option :: None , validator : :: std :: option :: Option :: None , visible : :: std :: option :: Option :: None , is_secret : false , }) ; args } , ty : < Token as async_graphql :: Type > :: create_type_info (registry) , deprecation : async_graphql :: registry :: Deprecation :: NoDeprecated , cache_control : async_graphql :: CacheControl { public : true , max_age : 0usize , } , external : false , provides : :: std :: option :: Option :: None , requires : :: std :: option :: Option :: None , visible : :: std :: option :: Option :: None , compute_complexity : :: std :: option :: Option :: None , }) ; fields . insert (:: std :: borrow :: ToOwned :: to_owned ("scope") , async_graphql :: registry :: MetaField { name : :: std :: borrow :: ToOwned :: to_owned ("scope") , description : :: std :: option :: Option :: None , args : { let mut args = async_graphql :: indexmap :: IndexMap :: new () ; args } , ty : < Scopes as async_graphql :: Type > :: create_type_info (registry) , deprecation : async_graphql :: registry :: Deprecation :: NoDeprecated , cache_control : async_graphql :: CacheControl { public : true , max_age : 0usize , } , external : false , provides : :: std :: option :: Option :: None , requires : :: std :: option :: Option :: None , visible : :: std :: option :: Option :: None , compute_complexity : :: std :: option :: Option :: None , }) ; fields } , cache_control : async_graphql :: CacheControl { public : true , max_age : 0usize , } , extends : false , keys : :: std :: option :: Option :: None , visible : :: std :: option :: Option :: None , }) ;
                ty
            }
        }
        #[allow(clippy::all, clippy::pedantic, clippy::suspicious_else_formatting)]
        #[allow(unused_braces, unused_variables, unused_parens, unused_mut)]
        impl async_graphql::resolver_utils::ContainerType for __ShadowQuery {
            #[allow(
                clippy::let_unit_value,
                clippy::type_complexity,
                clippy::type_repetition_in_bounds,
                clippy::used_underscore_binding
            )]
            fn resolve_field<'life0, 'life1, 'life2, 'async_trait>(
                &'life0 self,
                ctx: &'life1 async_graphql::Context<'life2>,
            ) -> ::core::pin::Pin<
                Box<
                    dyn ::core::future::Future<
                            Output = async_graphql::ServerResult<
                                ::std::option::Option<async_graphql::Value>,
                            >,
                        > + ::core::marker::Send
                        + 'async_trait,
                >,
            >
            where
                'life0: 'async_trait,
                'life1: 'async_trait,
                'life2: 'async_trait,
                Self: 'async_trait,
            {
                Box::pin(async move {
                    if let ::core::option::Option::Some(__ret) = ::core::option::Option::None::<
                        async_graphql::ServerResult<::std::option::Option<async_graphql::Value>>,
                    > {
                        return __ret;
                    }
                    let __self = self;
                    let ctx = ctx;
                    let __ret: async_graphql::ServerResult<
                        ::std::option::Option<async_graphql::Value>,
                    > = {
                        if ctx.item.node.name.node == "version" {
                            let f = async move {
                                {
                                    let res = __self.version(ctx).await;
                                    res.map_err(|err| {
                                        ::std::convert::Into::<async_graphql::Error>::into(err)
                                            .into_server_error(ctx.item.pos)
                                    })
                                }
                            };
                            let obj = f.await.map_err(|err| ctx.set_error_path(err))?;
                            let ctx_obj = ctx.with_selection_set(&ctx.item.node.selection_set);
                            return async_graphql::OutputType::resolve(&obj, &ctx_obj, ctx.item)
                                .await
                                .map(::std::option::Option::Some);
                        }
                        if ctx.item.node.name.node == "tokens" {
                            let f = async move {
                                {
                                    let res = __self.tokens(ctx).await;
                                    res.map_err(|err| {
                                        ::std::convert::Into::<async_graphql::Error>::into(err)
                                            .into_server_error(ctx.item.pos)
                                    })
                                }
                            };
                            let obj = f.await.map_err(|err| ctx.set_error_path(err))?;
                            let ctx_obj = ctx.with_selection_set(&ctx.item.node.selection_set);
                            return async_graphql::OutputType::resolve(&obj, &ctx_obj, ctx.item)
                                .await
                                .map(::std::option::Option::Some);
                        }
                        if ctx.item.node.name.node == "token" {
                            let f = async move {
                                #[allow(non_snake_case)]
                                let __id_getter = || -> async_graphql::ServerResult<uuid::Uuid> {
                                    ctx.param_value("id", ::std::option::Option::None)
                                };
                                #[allow(non_snake_case)]
                                let id: uuid::Uuid = __id_getter()?;
                                {
                                    let res = __self.token(ctx, id).await;
                                    res.map_err(|err| {
                                        ::std::convert::Into::<async_graphql::Error>::into(err)
                                            .into_server_error(ctx.item.pos)
                                    })
                                }
                            };
                            let obj = f.await.map_err(|err| ctx.set_error_path(err))?;
                            let ctx_obj = ctx.with_selection_set(&ctx.item.node.selection_set);
                            return async_graphql::OutputType::resolve(&obj, &ctx_obj, ctx.item)
                                .await
                                .map(::std::option::Option::Some);
                        }
                        if ctx.item.node.name.node == "scope" {
                            let f = async move {
                                {
                                    let res = __self.scope(ctx).await;
                                    res.map_err(|err| {
                                        ::std::convert::Into::<async_graphql::Error>::into(err)
                                            .into_server_error(ctx.item.pos)
                                    })
                                }
                            };
                            let obj = f.await.map_err(|err| ctx.set_error_path(err))?;
                            let ctx_obj = ctx.with_selection_set(&ctx.item.node.selection_set);
                            return async_graphql::OutputType::resolve(&obj, &ctx_obj, ctx.item)
                                .await
                                .map(::std::option::Option::Some);
                        }
                        ::std::result::Result::Ok(::std::option::Option::None)
                    };
                    #[allow(unreachable_code)]
                    __ret
                })
            }
            #[allow(
                clippy::let_unit_value,
                clippy::type_complexity,
                clippy::type_repetition_in_bounds,
                clippy::used_underscore_binding
            )]
            fn find_entity<'life0, 'life1, 'life2, 'life3, 'async_trait>(
                &'life0 self,
                ctx: &'life1 async_graphql::Context<'life2>,
                params: &'life3 async_graphql::Value,
            ) -> ::core::pin::Pin<
                Box<
                    dyn ::core::future::Future<
                            Output = async_graphql::ServerResult<
                                ::std::option::Option<async_graphql::Value>,
                            >,
                        > + ::core::marker::Send
                        + 'async_trait,
                >,
            >
            where
                'life0: 'async_trait,
                'life1: 'async_trait,
                'life2: 'async_trait,
                'life3: 'async_trait,
                Self: 'async_trait,
            {
                Box::pin(async move {
                    if let ::core::option::Option::Some(__ret) = ::core::option::Option::None::<
                        async_graphql::ServerResult<::std::option::Option<async_graphql::Value>>,
                    > {
                        return __ret;
                    }
                    let __self = self;
                    let ctx = ctx;
                    let params = params;
                    let __ret: async_graphql::ServerResult<
                        ::std::option::Option<async_graphql::Value>,
                    > = {
                        let params = match params {
                            async_graphql::Value::Object(params) => params,
                            _ => return ::std::result::Result::Ok(::std::option::Option::None),
                        };
                        let typename = if let ::std::option::Option::Some(
                            async_graphql::Value::String(typename),
                        ) = params.get("__typename")
                        {
                            typename
                        } else {
                            return ::std::result::Result::Err(async_graphql::ServerError::new(
                                r#""__typename" must be an existing string."#,
                                ::std::option::Option::Some(ctx.item.pos),
                            ));
                        };
                        ::std::result::Result::Ok(::std::option::Option::None)
                    };
                    #[allow(unreachable_code)]
                    __ret
                })
            }
        }
        #[allow(clippy::all, clippy::pedantic)]
        impl async_graphql::OutputType for __ShadowQuery {
            #[allow(
                clippy::let_unit_value,
                clippy::type_complexity,
                clippy::type_repetition_in_bounds,
                clippy::used_underscore_binding
            )]
            fn resolve<'life0, 'life1, 'life2, 'life3, 'async_trait>(
                &'life0 self,
                ctx: &'life1 async_graphql::ContextSelectionSet<'life2>,
                _field: &'life3 async_graphql::Positioned<async_graphql::parser::types::Field>,
            ) -> ::core::pin::Pin<
                Box<
                    dyn ::core::future::Future<
                            Output = async_graphql::ServerResult<async_graphql::Value>,
                        > + ::core::marker::Send
                        + 'async_trait,
                >,
            >
            where
                'life0: 'async_trait,
                'life1: 'async_trait,
                'life2: 'async_trait,
                'life3: 'async_trait,
                Self: 'async_trait,
            {
                Box::pin(async move {
                    if let ::core::option::Option::Some(__ret) = ::core::option::Option::None::<
                        async_graphql::ServerResult<async_graphql::Value>,
                    > {
                        return __ret;
                    }
                    let __self = self;
                    let ctx = ctx;
                    let _field = _field;
                    let __ret: async_graphql::ServerResult<async_graphql::Value> =
                        { async_graphql::resolver_utils::resolve_container(ctx, __self).await };
                    #[allow(unreachable_code)]
                    __ret
                })
            }
        }
        impl async_graphql::ObjectType for __ShadowQuery {}
        struct Token {
            id: uuid::Uuid,
            name: String,
            scopes: Scopes,
        }
        #[allow(clippy::all, clippy::pedantic)]
        impl Token {
            #[inline]
            #[allow(missing_docs)]
            async fn id(
                &self,
                ctx: &async_graphql::Context<'_>,
            ) -> async_graphql::Result<&uuid::Uuid> {
                ::std::result::Result::Ok(&self.id)
            }
            #[inline]
            #[allow(missing_docs)]
            async fn name(
                &self,
                ctx: &async_graphql::Context<'_>,
            ) -> async_graphql::Result<&String> {
                ::std::result::Result::Ok(&self.name)
            }
            #[inline]
            #[allow(missing_docs)]
            async fn scopes(
                &self,
                ctx: &async_graphql::Context<'_>,
            ) -> async_graphql::Result<&Scopes> {
                ::std::result::Result::Ok(&self.scopes)
            }
        }
        #[allow(clippy::all, clippy::pedantic)]
        impl async_graphql::Type for Token {
            fn type_name() -> ::std::borrow::Cow<'static, ::std::primitive::str> {
                ::std::borrow::Cow::Borrowed("Token")
            }
            fn create_type_info(
                registry: &mut async_graphql::registry::Registry,
            ) -> ::std::string::String {
                registry.create_type::<Self, _>(|registry| {
                    async_graphql::registry::MetaType::Object {
                        name: ::std::borrow::ToOwned::to_owned("Token"),
                        description: ::std::option::Option::None,
                        fields: {
                            let mut fields = async_graphql::indexmap::IndexMap::new();
                            fields.insert(
                                ::std::borrow::ToOwned::to_owned("id"),
                                async_graphql::registry::MetaField {
                                    name: ::std::borrow::ToOwned::to_owned("id"),
                                    description: ::std::option::Option::None,
                                    args: ::std::default::Default::default(),
                                    ty: <uuid::Uuid as async_graphql::Type>::create_type_info(
                                        registry,
                                    ),
                                    deprecation: async_graphql::registry::Deprecation::NoDeprecated,
                                    cache_control: async_graphql::CacheControl {
                                        public: true,
                                        max_age: 0usize,
                                    },
                                    external: false,
                                    provides: ::std::option::Option::None,
                                    requires: ::std::option::Option::None,
                                    visible: ::std::option::Option::None,
                                    compute_complexity: ::std::option::Option::None,
                                },
                            );
                            fields.insert(
                                ::std::borrow::ToOwned::to_owned("name"),
                                async_graphql::registry::MetaField {
                                    name: ::std::borrow::ToOwned::to_owned("name"),
                                    description: ::std::option::Option::None,
                                    args: ::std::default::Default::default(),
                                    ty: <String as async_graphql::Type>::create_type_info(registry),
                                    deprecation: async_graphql::registry::Deprecation::NoDeprecated,
                                    cache_control: async_graphql::CacheControl {
                                        public: true,
                                        max_age: 0usize,
                                    },
                                    external: false,
                                    provides: ::std::option::Option::None,
                                    requires: ::std::option::Option::None,
                                    visible: ::std::option::Option::None,
                                    compute_complexity: ::std::option::Option::None,
                                },
                            );
                            fields.insert(
                                ::std::borrow::ToOwned::to_owned("scopes"),
                                async_graphql::registry::MetaField {
                                    name: ::std::borrow::ToOwned::to_owned("scopes"),
                                    description: ::std::option::Option::None,
                                    args: ::std::default::Default::default(),
                                    ty: <Scopes as async_graphql::Type>::create_type_info(registry),
                                    deprecation: async_graphql::registry::Deprecation::NoDeprecated,
                                    cache_control: async_graphql::CacheControl {
                                        public: true,
                                        max_age: 0usize,
                                    },
                                    external: false,
                                    provides: ::std::option::Option::None,
                                    requires: ::std::option::Option::None,
                                    visible: ::std::option::Option::None,
                                    compute_complexity: ::std::option::Option::None,
                                },
                            );
                            fields
                        },
                        cache_control: async_graphql::CacheControl {
                            public: true,
                            max_age: 0usize,
                        },
                        extends: false,
                        keys: ::std::option::Option::None,
                        visible: ::std::option::Option::None,
                    }
                })
            }
        }
        #[allow(clippy::all, clippy::pedantic)]
        impl async_graphql::resolver_utils::ContainerType for Token {
            #[allow(
                clippy::let_unit_value,
                clippy::type_complexity,
                clippy::type_repetition_in_bounds,
                clippy::used_underscore_binding
            )]
            fn resolve_field<'life0, 'life1, 'life2, 'async_trait>(
                &'life0 self,
                ctx: &'life1 async_graphql::Context<'life2>,
            ) -> ::core::pin::Pin<
                Box<
                    dyn ::core::future::Future<
                            Output = async_graphql::ServerResult<
                                ::std::option::Option<async_graphql::Value>,
                            >,
                        > + ::core::marker::Send
                        + 'async_trait,
                >,
            >
            where
                'life0: 'async_trait,
                'life1: 'async_trait,
                'life2: 'async_trait,
                Self: 'async_trait,
            {
                Box::pin(async move {
                    if let ::core::option::Option::Some(__ret) = ::core::option::Option::None::<
                        async_graphql::ServerResult<::std::option::Option<async_graphql::Value>>,
                    > {
                        return __ret;
                    }
                    let __self = self;
                    let ctx = ctx;
                    let __ret: async_graphql::ServerResult<
                        ::std::option::Option<async_graphql::Value>,
                    > = {
                        if ctx.item.node.name.node == "id" {
                            let f = async move {
                                __self
                                    .id(ctx)
                                    .await
                                    .map_err(|err| err.into_server_error(ctx.item.pos))
                            };
                            let obj = f.await.map_err(|err| ctx.set_error_path(err))?;
                            let ctx_obj = ctx.with_selection_set(&ctx.item.node.selection_set);
                            return async_graphql::OutputType::resolve(&obj, &ctx_obj, ctx.item)
                                .await
                                .map(::std::option::Option::Some);
                        }
                        if ctx.item.node.name.node == "name" {
                            let f = async move {
                                __self
                                    .name(ctx)
                                    .await
                                    .map_err(|err| err.into_server_error(ctx.item.pos))
                            };
                            let obj = f.await.map_err(|err| ctx.set_error_path(err))?;
                            let ctx_obj = ctx.with_selection_set(&ctx.item.node.selection_set);
                            return async_graphql::OutputType::resolve(&obj, &ctx_obj, ctx.item)
                                .await
                                .map(::std::option::Option::Some);
                        }
                        if ctx.item.node.name.node == "scopes" {
                            let f = async move {
                                __self
                                    .scopes(ctx)
                                    .await
                                    .map_err(|err| err.into_server_error(ctx.item.pos))
                            };
                            let obj = f.await.map_err(|err| ctx.set_error_path(err))?;
                            let ctx_obj = ctx.with_selection_set(&ctx.item.node.selection_set);
                            return async_graphql::OutputType::resolve(&obj, &ctx_obj, ctx.item)
                                .await
                                .map(::std::option::Option::Some);
                        }
                        ::std::result::Result::Ok(::std::option::Option::None)
                    };
                    #[allow(unreachable_code)]
                    __ret
                })
            }
        }
        #[allow(clippy::all, clippy::pedantic)]
        impl async_graphql::OutputType for Token {
            #[allow(
                clippy::let_unit_value,
                clippy::type_complexity,
                clippy::type_repetition_in_bounds,
                clippy::used_underscore_binding
            )]
            fn resolve<'life0, 'life1, 'life2, 'life3, 'async_trait>(
                &'life0 self,
                ctx: &'life1 async_graphql::ContextSelectionSet<'life2>,
                _field: &'life3 async_graphql::Positioned<async_graphql::parser::types::Field>,
            ) -> ::core::pin::Pin<
                Box<
                    dyn ::core::future::Future<
                            Output = async_graphql::ServerResult<async_graphql::Value>,
                        > + ::core::marker::Send
                        + 'async_trait,
                >,
            >
            where
                'life0: 'async_trait,
                'life1: 'async_trait,
                'life2: 'async_trait,
                'life3: 'async_trait,
                Self: 'async_trait,
            {
                Box::pin(async move {
                    if let ::core::option::Option::Some(__ret) = ::core::option::Option::None::<
                        async_graphql::ServerResult<async_graphql::Value>,
                    > {
                        return __ret;
                    }
                    let __self = self;
                    let ctx = ctx;
                    let _field = _field;
                    let __ret: async_graphql::ServerResult<async_graphql::Value> =
                        { async_graphql::resolver_utils::resolve_container(ctx, __self).await };
                    #[allow(unreachable_code)]
                    __ret
                })
            }
        }
        impl async_graphql::ObjectType for Token {}
        impl From<db::Token> for Token {
            fn from(t: db::Token) -> Self {
                Self {
                    id: t.token_id,
                    name: t.name,
                    scopes: t.scopes,
                }
            }
        }
        pub struct User(pub String);
    }
    mod provider {}
    pub type Oauth2ProxySchema = Schema<query::Query, mutation::Mutation, EmptySubscription>;
    pub struct Service(web::Data<Oauth2ProxySchema>);
    #[automatically_derived]
    #[allow(unused_qualifications)]
    impl ::core::clone::Clone for Service {
        #[inline]
        fn clone(&self) -> Service {
            match *self {
                Service(ref __self_0_0) => Service(::core::clone::Clone::clone(&(*__self_0_0))),
            }
        }
    }
    impl Service {
        pub fn new(db: DynamoDbClient) -> Self {
            let schema = Schema::build(
                query::Query { db: db.clone() },
                mutation::Mutation { db },
                EmptySubscription,
            )
            .extension(ApolloTracing)
            .extension(Tracing)
            .finish();
            Self(web::Data::new(schema))
        }
    }
    impl HttpServiceFactory for Service {
        fn register(self, config: &mut actix_web::dev::AppService) {
            web::scope("/graphql")
                .app_data(self.0)
                .service(graphql)
                .service(playground)
                .register(config)
        }
    }
    fn authenticated(key: &str, http_req: HttpRequest) -> Option<User> {
        let auth = http_req
            .headers()
            .get(header::AUTHORIZATION)?
            .to_str()
            .ok()?;
        let token = auth.strip_prefix("Bearer ")?;
        let key = jwt::DecodingKey::from_base64_secret(key).ok()?;
        let token_data = jwt::decode::<Claims>(token, &key, &jwt::Validation::default()).ok()?;
        Some(User(token_data.claims.username))
    }
    #[allow(non_camel_case_types, missing_docs)]
    pub struct graphql;
    impl actix_web::dev::HttpServiceFactory for graphql {
        fn register(self, __config: &mut actix_web::dev::AppService) {
            async fn graphql(
                schema: web::Data<Oauth2ProxySchema>,
                http_req: HttpRequest,
                req: Request,
            ) -> Response {
                let request = req.into_inner();
                let request = match authenticated(&CONFIG.state_key, http_req) {
                    Some(user) => request.data(user),
                    None => request,
                };
                schema.execute(request).await.into()
            }
            let __resource = actix_web::Resource::new("")
                .name("graphql")
                .guard(actix_web::guard::Post())
                .to(graphql);
            actix_web::dev::HttpServiceFactory::register(__resource, __config)
        }
    }
    #[allow(non_camel_case_types, missing_docs)]
    pub struct playground;
    impl actix_web::dev::HttpServiceFactory for playground {
        fn register(self, __config: &mut actix_web::dev::AppService) {
            async fn playground() -> Result<HttpResponse> {
                Ok(HttpResponse::Ok()
                    .content_type("text/html; charset=utf-8")
                    .body(playground_source(
                        GraphQLPlaygroundConfig::new("/graphql").subscription_endpoint("/graphql"),
                    )))
            }
            let __resource = actix_web::Resource::new("")
                .name("playground")
                .guard(actix_web::guard::Get())
                .to(playground);
            actix_web::dev::HttpServiceFactory::register(__resource, __config)
        }
    }
}
fn main() -> std::io::Result<()> {
    <::actix_web::rt::System>::new().block_on(async move {
        {
            tracing_subscriber::fmt::init();
            let db = DynamoDbClient::new(Region::default());
            let graphql = graphql::Service::new(db);
            HttpServer::new(move || {
                App::new()
                    .wrap(TracingLogger::default())
                    .service(graphql.clone())
            })
            .bind(("0.0.0.0", 8080))?
            .run()
            .await
        }
    })
}
mod config {
    use std::lazy::SyncLazy;
    use serde::Deserialize;
    use crate::{provider::spotify::SpotifyProvider, token::Provider};
    #[inline]
    fn base_url() -> oauth2::url::Url {
        oauth2::url::Url::parse("http://localhost:27228").unwrap()
    }
    #[inline]
    const fn bcrypt_cost() -> u32 {
        12
    }
    pub struct Config {
        pub state_key: String,
        #[serde(default = "bcrypt_cost")]
        pub bcrypt_cost: u32,
        #[serde(default = "base_url")]
        pub base_url: oauth2::url::Url,
        pub spotify: Provider<SpotifyProvider>,
    }
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        #[allow(unused_extern_crates, clippy::useless_attribute)]
        extern crate serde as _serde;
        #[automatically_derived]
        impl<'de> _serde::Deserialize<'de> for Config {
            fn deserialize<__D>(__deserializer: __D) -> _serde::__private::Result<Self, __D::Error>
            where
                __D: _serde::Deserializer<'de>,
            {
                #[allow(non_camel_case_types)]
                enum __Field {
                    __field0,
                    __field1,
                    __field2,
                    __field3,
                    __ignore,
                }
                struct __FieldVisitor;
                impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                    type Value = __Field;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(__formatter, "field identifier")
                    }
                    fn visit_u64<__E>(
                        self,
                        __value: u64,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            0u64 => _serde::__private::Ok(__Field::__field0),
                            1u64 => _serde::__private::Ok(__Field::__field1),
                            2u64 => _serde::__private::Ok(__Field::__field2),
                            3u64 => _serde::__private::Ok(__Field::__field3),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_str<__E>(
                        self,
                        __value: &str,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            "state_key" => _serde::__private::Ok(__Field::__field0),
                            "bcrypt_cost" => _serde::__private::Ok(__Field::__field1),
                            "base_url" => _serde::__private::Ok(__Field::__field2),
                            "spotify" => _serde::__private::Ok(__Field::__field3),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_bytes<__E>(
                        self,
                        __value: &[u8],
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            b"state_key" => _serde::__private::Ok(__Field::__field0),
                            b"bcrypt_cost" => _serde::__private::Ok(__Field::__field1),
                            b"base_url" => _serde::__private::Ok(__Field::__field2),
                            b"spotify" => _serde::__private::Ok(__Field::__field3),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                }
                impl<'de> _serde::Deserialize<'de> for __Field {
                    #[inline]
                    fn deserialize<__D>(
                        __deserializer: __D,
                    ) -> _serde::__private::Result<Self, __D::Error>
                    where
                        __D: _serde::Deserializer<'de>,
                    {
                        _serde::Deserializer::deserialize_identifier(__deserializer, __FieldVisitor)
                    }
                }
                struct __Visitor<'de> {
                    marker: _serde::__private::PhantomData<Config>,
                    lifetime: _serde::__private::PhantomData<&'de ()>,
                }
                impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                    type Value = Config;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(__formatter, "struct Config")
                    }
                    #[inline]
                    fn visit_seq<__A>(
                        self,
                        mut __seq: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::SeqAccess<'de>,
                    {
                        let __field0 =
                            match match _serde::de::SeqAccess::next_element::<String>(&mut __seq) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            } {
                                _serde::__private::Some(__value) => __value,
                                _serde::__private::None => {
                                    return _serde::__private::Err(
                                        _serde::de::Error::invalid_length(
                                            0usize,
                                            &"struct Config with 4 elements",
                                        ),
                                    );
                                }
                            };
                        let __field1 =
                            match match _serde::de::SeqAccess::next_element::<u32>(&mut __seq) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            } {
                                _serde::__private::Some(__value) => __value,
                                _serde::__private::None => bcrypt_cost(),
                            };
                        let __field2 = match match _serde::de::SeqAccess::next_element::<
                            oauth2::url::Url,
                        >(&mut __seq)
                        {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => base_url(),
                        };
                        let __field3 = match match _serde::de::SeqAccess::next_element::<
                            Provider<SpotifyProvider>,
                        >(&mut __seq)
                        {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(_serde::de::Error::invalid_length(
                                    3usize,
                                    &"struct Config with 4 elements",
                                ));
                            }
                        };
                        _serde::__private::Ok(Config {
                            state_key: __field0,
                            bcrypt_cost: __field1,
                            base_url: __field2,
                            spotify: __field3,
                        })
                    }
                    #[inline]
                    fn visit_map<__A>(
                        self,
                        mut __map: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::MapAccess<'de>,
                    {
                        let mut __field0: _serde::__private::Option<String> =
                            _serde::__private::None;
                        let mut __field1: _serde::__private::Option<u32> = _serde::__private::None;
                        let mut __field2: _serde::__private::Option<oauth2::url::Url> =
                            _serde::__private::None;
                        let mut __field3: _serde::__private::Option<Provider<SpotifyProvider>> =
                            _serde::__private::None;
                        while let _serde::__private::Some(__key) =
                            match _serde::de::MapAccess::next_key::<__Field>(&mut __map) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            }
                        {
                            match __key {
                                __Field::__field0 => {
                                    if _serde::__private::Option::is_some(&__field0) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field(
                                                "state_key",
                                            ),
                                        );
                                    }
                                    __field0 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<String>(
                                            &mut __map,
                                        ) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                __Field::__field1 => {
                                    if _serde::__private::Option::is_some(&__field1) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field(
                                                "bcrypt_cost",
                                            ),
                                        );
                                    }
                                    __field1 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<u32>(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                __Field::__field2 => {
                                    if _serde::__private::Option::is_some(&__field2) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field(
                                                "base_url",
                                            ),
                                        );
                                    }
                                    __field2 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<oauth2::url::Url>(
                                            &mut __map,
                                        ) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                __Field::__field3 => {
                                    if _serde::__private::Option::is_some(&__field3) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field(
                                                "spotify",
                                            ),
                                        );
                                    }
                                    __field3 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<
                                            Provider<SpotifyProvider>,
                                        >(&mut __map)
                                        {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                _ => {
                                    let _ = match _serde::de::MapAccess::next_value::<
                                        _serde::de::IgnoredAny,
                                    >(&mut __map)
                                    {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    };
                                }
                            }
                        }
                        let __field0 = match __field0 {
                            _serde::__private::Some(__field0) => __field0,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("state_key") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        let __field1 = match __field1 {
                            _serde::__private::Some(__field1) => __field1,
                            _serde::__private::None => bcrypt_cost(),
                        };
                        let __field2 = match __field2 {
                            _serde::__private::Some(__field2) => __field2,
                            _serde::__private::None => base_url(),
                        };
                        let __field3 = match __field3 {
                            _serde::__private::Some(__field3) => __field3,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("spotify") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        _serde::__private::Ok(Config {
                            state_key: __field0,
                            bcrypt_cost: __field1,
                            base_url: __field2,
                            spotify: __field3,
                        })
                    }
                }
                const FIELDS: &'static [&'static str] =
                    &["state_key", "bcrypt_cost", "base_url", "spotify"];
                _serde::Deserializer::deserialize_struct(
                    __deserializer,
                    "Config",
                    FIELDS,
                    __Visitor {
                        marker: _serde::__private::PhantomData::<Config>,
                        lifetime: _serde::__private::PhantomData,
                    },
                )
            }
        }
    };
    pub static CONFIG: SyncLazy<Config> = SyncLazy::new(|| {
        let config_str =
            std::fs::read_to_string("config.toml").expect("could not read config file");
        toml::from_str(&config_str).expect("could not parse config file")
    });
}
mod db {
    use nitroglycerin::{Key, Query, Table};
    use oauth2::{basic::BasicTokenType, AccessToken, RefreshToken};
    use uuid::Uuid;
    use nitroglycerin::serde::{Deserialize, Serialize};
    use crate::provider::Scopes;
    pub struct User {
        #[nitro(partition_key)]
        pub username: String,
        pub password_hash: String,
    }
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        #[allow(unused_extern_crates, clippy::useless_attribute)]
        extern crate serde as _serde;
        #[automatically_derived]
        impl _serde::Serialize for User {
            fn serialize<__S>(
                &self,
                __serializer: __S,
            ) -> _serde::__private::Result<__S::Ok, __S::Error>
            where
                __S: _serde::Serializer,
            {
                let mut __serde_state = match _serde::Serializer::serialize_struct(
                    __serializer,
                    "User",
                    false as usize + 1 + 1,
                ) {
                    _serde::__private::Ok(__val) => __val,
                    _serde::__private::Err(__err) => {
                        return _serde::__private::Err(__err);
                    }
                };
                match _serde::ser::SerializeStruct::serialize_field(
                    &mut __serde_state,
                    "username",
                    &self.username,
                ) {
                    _serde::__private::Ok(__val) => __val,
                    _serde::__private::Err(__err) => {
                        return _serde::__private::Err(__err);
                    }
                };
                match _serde::ser::SerializeStruct::serialize_field(
                    &mut __serde_state,
                    "password_hash",
                    &self.password_hash,
                ) {
                    _serde::__private::Ok(__val) => __val,
                    _serde::__private::Err(__err) => {
                        return _serde::__private::Err(__err);
                    }
                };
                _serde::ser::SerializeStruct::end(__serde_state)
            }
        }
    };
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        #[allow(unused_extern_crates, clippy::useless_attribute)]
        extern crate serde as _serde;
        #[automatically_derived]
        impl<'de> _serde::Deserialize<'de> for User {
            fn deserialize<__D>(__deserializer: __D) -> _serde::__private::Result<Self, __D::Error>
            where
                __D: _serde::Deserializer<'de>,
            {
                #[allow(non_camel_case_types)]
                enum __Field {
                    __field0,
                    __field1,
                    __ignore,
                }
                struct __FieldVisitor;
                impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                    type Value = __Field;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(__formatter, "field identifier")
                    }
                    fn visit_u64<__E>(
                        self,
                        __value: u64,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            0u64 => _serde::__private::Ok(__Field::__field0),
                            1u64 => _serde::__private::Ok(__Field::__field1),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_str<__E>(
                        self,
                        __value: &str,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            "username" => _serde::__private::Ok(__Field::__field0),
                            "password_hash" => _serde::__private::Ok(__Field::__field1),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_bytes<__E>(
                        self,
                        __value: &[u8],
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            b"username" => _serde::__private::Ok(__Field::__field0),
                            b"password_hash" => _serde::__private::Ok(__Field::__field1),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                }
                impl<'de> _serde::Deserialize<'de> for __Field {
                    #[inline]
                    fn deserialize<__D>(
                        __deserializer: __D,
                    ) -> _serde::__private::Result<Self, __D::Error>
                    where
                        __D: _serde::Deserializer<'de>,
                    {
                        _serde::Deserializer::deserialize_identifier(__deserializer, __FieldVisitor)
                    }
                }
                struct __Visitor<'de> {
                    marker: _serde::__private::PhantomData<User>,
                    lifetime: _serde::__private::PhantomData<&'de ()>,
                }
                impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                    type Value = User;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(__formatter, "struct User")
                    }
                    #[inline]
                    fn visit_seq<__A>(
                        self,
                        mut __seq: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::SeqAccess<'de>,
                    {
                        let __field0 =
                            match match _serde::de::SeqAccess::next_element::<String>(&mut __seq) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            } {
                                _serde::__private::Some(__value) => __value,
                                _serde::__private::None => {
                                    return _serde::__private::Err(
                                        _serde::de::Error::invalid_length(
                                            0usize,
                                            &"struct User with 2 elements",
                                        ),
                                    );
                                }
                            };
                        let __field1 =
                            match match _serde::de::SeqAccess::next_element::<String>(&mut __seq) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            } {
                                _serde::__private::Some(__value) => __value,
                                _serde::__private::None => {
                                    return _serde::__private::Err(
                                        _serde::de::Error::invalid_length(
                                            1usize,
                                            &"struct User with 2 elements",
                                        ),
                                    );
                                }
                            };
                        _serde::__private::Ok(User {
                            username: __field0,
                            password_hash: __field1,
                        })
                    }
                    #[inline]
                    fn visit_map<__A>(
                        self,
                        mut __map: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::MapAccess<'de>,
                    {
                        let mut __field0: _serde::__private::Option<String> =
                            _serde::__private::None;
                        let mut __field1: _serde::__private::Option<String> =
                            _serde::__private::None;
                        while let _serde::__private::Some(__key) =
                            match _serde::de::MapAccess::next_key::<__Field>(&mut __map) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            }
                        {
                            match __key {
                                __Field::__field0 => {
                                    if _serde::__private::Option::is_some(&__field0) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field(
                                                "username",
                                            ),
                                        );
                                    }
                                    __field0 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<String>(
                                            &mut __map,
                                        ) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                __Field::__field1 => {
                                    if _serde::__private::Option::is_some(&__field1) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field(
                                                "password_hash",
                                            ),
                                        );
                                    }
                                    __field1 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<String>(
                                            &mut __map,
                                        ) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                _ => {
                                    let _ = match _serde::de::MapAccess::next_value::<
                                        _serde::de::IgnoredAny,
                                    >(&mut __map)
                                    {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    };
                                }
                            }
                        }
                        let __field0 = match __field0 {
                            _serde::__private::Some(__field0) => __field0,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("username") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        let __field1 = match __field1 {
                            _serde::__private::Some(__field1) => __field1,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("password_hash") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        _serde::__private::Ok(User {
                            username: __field0,
                            password_hash: __field1,
                        })
                    }
                }
                const FIELDS: &'static [&'static str] = &["username", "password_hash"];
                _serde::Deserializer::deserialize_struct(
                    __deserializer,
                    "User",
                    FIELDS,
                    __Visitor {
                        marker: _serde::__private::PhantomData::<User>,
                        lifetime: _serde::__private::PhantomData,
                    },
                )
            }
        }
    };
    impl<
            '__nitroglycerin_dynamo_db_dlient,
            __NitroglycerinDynamoDBClient: '__nitroglycerin_dynamo_db_dlient + ?Sized,
            __NitroglycerinKeyRequest,
        >
        ::nitroglycerin::key::Builder<
            '__nitroglycerin_dynamo_db_dlient,
            __NitroglycerinDynamoDBClient,
            __NitroglycerinKeyRequest,
        > for User
    where
        Self: ::nitroglycerin::Table,
        __NitroglycerinKeyRequest: ::std::convert::From<::nitroglycerin::key::Key>,
    {
        type Builder = UserKeyBuilder<
            '__nitroglycerin_dynamo_db_dlient,
            __NitroglycerinDynamoDBClient,
            __NitroglycerinKeyRequest,
        >;
        fn key(
            client: &'__nitroglycerin_dynamo_db_dlient __NitroglycerinDynamoDBClient,
        ) -> Self::Builder {
            Self::Builder {
                client,
                _phantom: ::std::marker::PhantomData,
            }
        }
    }
    ///part one of the key builder chain for User
    pub struct UserKeyBuilder<
        '__nitroglycerin_dynamo_db_dlient,
        __NitroglycerinDynamoDBClient: '__nitroglycerin_dynamo_db_dlient + ?Sized,
        __NitroglycerinKeyRequest,
    > {
        client: &'__nitroglycerin_dynamo_db_dlient __NitroglycerinDynamoDBClient,
        _phantom: ::std::marker::PhantomData<(__NitroglycerinKeyRequest,)>,
    }
    impl<
            '__nitroglycerin_dynamo_db_dlient,
            __NitroglycerinDynamoDBClient: '__nitroglycerin_dynamo_db_dlient + ?Sized,
            __NitroglycerinKeyRequest,
        >
        UserKeyBuilder<
            '__nitroglycerin_dynamo_db_dlient,
            __NitroglycerinDynamoDBClient,
            __NitroglycerinKeyRequest,
        >
    where
        __NitroglycerinKeyRequest: ::std::convert::From<::nitroglycerin::key::Key>,
    {
        ///set the value of the partition key (username)
        pub fn username(
            self,
            username: &String,
        ) -> ::std::result::Result<
            UserKeyBuilderPartition<
                '__nitroglycerin_dynamo_db_dlient,
                __NitroglycerinDynamoDBClient,
                __NitroglycerinKeyRequest,
            >,
            ::nitroglycerin::SerError,
        >
        where
            String: ::nitroglycerin::serde::Serialize,
            User: ::nitroglycerin::Table,
        {
            let partition_key: &String = username;
            let Self { client, _phantom } = self;
            let key = ::nitroglycerin::key::Key::new::<User, _>("username", partition_key)?;
            ::std::result::Result::Ok(UserKeyBuilderPartition::new(client, key))
        }
    }
    ///part two of the key builder chain for User
    pub type UserKeyBuilderPartition<
        '__nitroglycerin_dynamo_db_dlient,
        __NitroglycerinDynamoDBClient,
        __NitroglycerinKeyRequest,
    > = ::nitroglycerin::key::Expr<
        '__nitroglycerin_dynamo_db_dlient,
        __NitroglycerinDynamoDBClient,
        __NitroglycerinKeyRequest,
        User,
    >;
    pub struct Token {
        #[nitro(partition_key)]
        pub username: String,
        #[nitro(sort_key)]
        pub token_id: Uuid,
        pub name: String,
        pub scopes: Scopes,
        pub key_hash: String,
        pub access_token: AccessToken,
        pub refresh_token: RefreshToken,
        pub token_type: BasicTokenType,
        # [nitro (with = nitroglycerin :: convert :: chrono :: seconds)]
        pub expires: chrono::DateTime<chrono::Utc>,
    }
    #[automatically_derived]
    #[allow(unused_qualifications)]
    impl ::core::clone::Clone for Token {
        #[inline]
        fn clone(&self) -> Token {
            match *self {
                Token {
                    username: ref __self_0_0,
                    token_id: ref __self_0_1,
                    name: ref __self_0_2,
                    scopes: ref __self_0_3,
                    key_hash: ref __self_0_4,
                    access_token: ref __self_0_5,
                    refresh_token: ref __self_0_6,
                    token_type: ref __self_0_7,
                    expires: ref __self_0_8,
                } => Token {
                    username: ::core::clone::Clone::clone(&(*__self_0_0)),
                    token_id: ::core::clone::Clone::clone(&(*__self_0_1)),
                    name: ::core::clone::Clone::clone(&(*__self_0_2)),
                    scopes: ::core::clone::Clone::clone(&(*__self_0_3)),
                    key_hash: ::core::clone::Clone::clone(&(*__self_0_4)),
                    access_token: ::core::clone::Clone::clone(&(*__self_0_5)),
                    refresh_token: ::core::clone::Clone::clone(&(*__self_0_6)),
                    token_type: ::core::clone::Clone::clone(&(*__self_0_7)),
                    expires: ::core::clone::Clone::clone(&(*__self_0_8)),
                },
            }
        }
    }
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        #[allow(unused_extern_crates, clippy::useless_attribute)]
        extern crate serde as _serde;
        #[automatically_derived]
        impl _serde::Serialize for Token {
            fn serialize<__S>(
                &self,
                __serializer: __S,
            ) -> _serde::__private::Result<__S::Ok, __S::Error>
            where
                __S: _serde::Serializer,
            {
                let mut __serde_state = match _serde::Serializer::serialize_struct(
                    __serializer,
                    "Token",
                    false as usize + 1 + 1 + 1 + 1 + 1 + 1 + 1 + 1 + 1,
                ) {
                    _serde::__private::Ok(__val) => __val,
                    _serde::__private::Err(__err) => {
                        return _serde::__private::Err(__err);
                    }
                };
                match _serde::ser::SerializeStruct::serialize_field(
                    &mut __serde_state,
                    "username",
                    &self.username,
                ) {
                    _serde::__private::Ok(__val) => __val,
                    _serde::__private::Err(__err) => {
                        return _serde::__private::Err(__err);
                    }
                };
                match _serde::ser::SerializeStruct::serialize_field(
                    &mut __serde_state,
                    "token_id",
                    &self.token_id,
                ) {
                    _serde::__private::Ok(__val) => __val,
                    _serde::__private::Err(__err) => {
                        return _serde::__private::Err(__err);
                    }
                };
                match _serde::ser::SerializeStruct::serialize_field(
                    &mut __serde_state,
                    "name",
                    &self.name,
                ) {
                    _serde::__private::Ok(__val) => __val,
                    _serde::__private::Err(__err) => {
                        return _serde::__private::Err(__err);
                    }
                };
                match _serde::ser::SerializeStruct::serialize_field(
                    &mut __serde_state,
                    "scopes",
                    &self.scopes,
                ) {
                    _serde::__private::Ok(__val) => __val,
                    _serde::__private::Err(__err) => {
                        return _serde::__private::Err(__err);
                    }
                };
                match _serde::ser::SerializeStruct::serialize_field(
                    &mut __serde_state,
                    "key_hash",
                    &self.key_hash,
                ) {
                    _serde::__private::Ok(__val) => __val,
                    _serde::__private::Err(__err) => {
                        return _serde::__private::Err(__err);
                    }
                };
                match _serde::ser::SerializeStruct::serialize_field(
                    &mut __serde_state,
                    "access_token",
                    &self.access_token,
                ) {
                    _serde::__private::Ok(__val) => __val,
                    _serde::__private::Err(__err) => {
                        return _serde::__private::Err(__err);
                    }
                };
                match _serde::ser::SerializeStruct::serialize_field(
                    &mut __serde_state,
                    "refresh_token",
                    &self.refresh_token,
                ) {
                    _serde::__private::Ok(__val) => __val,
                    _serde::__private::Err(__err) => {
                        return _serde::__private::Err(__err);
                    }
                };
                match _serde::ser::SerializeStruct::serialize_field(
                    &mut __serde_state,
                    "token_type",
                    &self.token_type,
                ) {
                    _serde::__private::Ok(__val) => __val,
                    _serde::__private::Err(__err) => {
                        return _serde::__private::Err(__err);
                    }
                };
                match _serde::ser::SerializeStruct::serialize_field(
                    &mut __serde_state,
                    "expires",
                    &self.expires,
                ) {
                    _serde::__private::Ok(__val) => __val,
                    _serde::__private::Err(__err) => {
                        return _serde::__private::Err(__err);
                    }
                };
                _serde::ser::SerializeStruct::end(__serde_state)
            }
        }
    };
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        #[allow(unused_extern_crates, clippy::useless_attribute)]
        extern crate serde as _serde;
        #[automatically_derived]
        impl<'de> _serde::Deserialize<'de> for Token {
            fn deserialize<__D>(__deserializer: __D) -> _serde::__private::Result<Self, __D::Error>
            where
                __D: _serde::Deserializer<'de>,
            {
                #[allow(non_camel_case_types)]
                enum __Field {
                    __field0,
                    __field1,
                    __field2,
                    __field3,
                    __field4,
                    __field5,
                    __field6,
                    __field7,
                    __field8,
                    __ignore,
                }
                struct __FieldVisitor;
                impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                    type Value = __Field;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(__formatter, "field identifier")
                    }
                    fn visit_u64<__E>(
                        self,
                        __value: u64,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            0u64 => _serde::__private::Ok(__Field::__field0),
                            1u64 => _serde::__private::Ok(__Field::__field1),
                            2u64 => _serde::__private::Ok(__Field::__field2),
                            3u64 => _serde::__private::Ok(__Field::__field3),
                            4u64 => _serde::__private::Ok(__Field::__field4),
                            5u64 => _serde::__private::Ok(__Field::__field5),
                            6u64 => _serde::__private::Ok(__Field::__field6),
                            7u64 => _serde::__private::Ok(__Field::__field7),
                            8u64 => _serde::__private::Ok(__Field::__field8),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_str<__E>(
                        self,
                        __value: &str,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            "username" => _serde::__private::Ok(__Field::__field0),
                            "token_id" => _serde::__private::Ok(__Field::__field1),
                            "name" => _serde::__private::Ok(__Field::__field2),
                            "scopes" => _serde::__private::Ok(__Field::__field3),
                            "key_hash" => _serde::__private::Ok(__Field::__field4),
                            "access_token" => _serde::__private::Ok(__Field::__field5),
                            "refresh_token" => _serde::__private::Ok(__Field::__field6),
                            "token_type" => _serde::__private::Ok(__Field::__field7),
                            "expires" => _serde::__private::Ok(__Field::__field8),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_bytes<__E>(
                        self,
                        __value: &[u8],
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            b"username" => _serde::__private::Ok(__Field::__field0),
                            b"token_id" => _serde::__private::Ok(__Field::__field1),
                            b"name" => _serde::__private::Ok(__Field::__field2),
                            b"scopes" => _serde::__private::Ok(__Field::__field3),
                            b"key_hash" => _serde::__private::Ok(__Field::__field4),
                            b"access_token" => _serde::__private::Ok(__Field::__field5),
                            b"refresh_token" => _serde::__private::Ok(__Field::__field6),
                            b"token_type" => _serde::__private::Ok(__Field::__field7),
                            b"expires" => _serde::__private::Ok(__Field::__field8),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                }
                impl<'de> _serde::Deserialize<'de> for __Field {
                    #[inline]
                    fn deserialize<__D>(
                        __deserializer: __D,
                    ) -> _serde::__private::Result<Self, __D::Error>
                    where
                        __D: _serde::Deserializer<'de>,
                    {
                        _serde::Deserializer::deserialize_identifier(__deserializer, __FieldVisitor)
                    }
                }
                struct __Visitor<'de> {
                    marker: _serde::__private::PhantomData<Token>,
                    lifetime: _serde::__private::PhantomData<&'de ()>,
                }
                impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                    type Value = Token;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(__formatter, "struct Token")
                    }
                    #[inline]
                    fn visit_seq<__A>(
                        self,
                        mut __seq: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::SeqAccess<'de>,
                    {
                        let __field0 =
                            match match _serde::de::SeqAccess::next_element::<String>(&mut __seq) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            } {
                                _serde::__private::Some(__value) => __value,
                                _serde::__private::None => {
                                    return _serde::__private::Err(
                                        _serde::de::Error::invalid_length(
                                            0usize,
                                            &"struct Token with 9 elements",
                                        ),
                                    );
                                }
                            };
                        let __field1 =
                            match match _serde::de::SeqAccess::next_element::<Uuid>(&mut __seq) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            } {
                                _serde::__private::Some(__value) => __value,
                                _serde::__private::None => {
                                    return _serde::__private::Err(
                                        _serde::de::Error::invalid_length(
                                            1usize,
                                            &"struct Token with 9 elements",
                                        ),
                                    );
                                }
                            };
                        let __field2 =
                            match match _serde::de::SeqAccess::next_element::<String>(&mut __seq) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            } {
                                _serde::__private::Some(__value) => __value,
                                _serde::__private::None => {
                                    return _serde::__private::Err(
                                        _serde::de::Error::invalid_length(
                                            2usize,
                                            &"struct Token with 9 elements",
                                        ),
                                    );
                                }
                            };
                        let __field3 =
                            match match _serde::de::SeqAccess::next_element::<Scopes>(&mut __seq) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            } {
                                _serde::__private::Some(__value) => __value,
                                _serde::__private::None => {
                                    return _serde::__private::Err(
                                        _serde::de::Error::invalid_length(
                                            3usize,
                                            &"struct Token with 9 elements",
                                        ),
                                    );
                                }
                            };
                        let __field4 =
                            match match _serde::de::SeqAccess::next_element::<String>(&mut __seq) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            } {
                                _serde::__private::Some(__value) => __value,
                                _serde::__private::None => {
                                    return _serde::__private::Err(
                                        _serde::de::Error::invalid_length(
                                            4usize,
                                            &"struct Token with 9 elements",
                                        ),
                                    );
                                }
                            };
                        let __field5 = match match _serde::de::SeqAccess::next_element::<AccessToken>(
                            &mut __seq,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(_serde::de::Error::invalid_length(
                                    5usize,
                                    &"struct Token with 9 elements",
                                ));
                            }
                        };
                        let __field6 = match match _serde::de::SeqAccess::next_element::<RefreshToken>(
                            &mut __seq,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(_serde::de::Error::invalid_length(
                                    6usize,
                                    &"struct Token with 9 elements",
                                ));
                            }
                        };
                        let __field7 = match match _serde::de::SeqAccess::next_element::<
                            BasicTokenType,
                        >(&mut __seq)
                        {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(_serde::de::Error::invalid_length(
                                    7usize,
                                    &"struct Token with 9 elements",
                                ));
                            }
                        };
                        let __field8 = match match _serde::de::SeqAccess::next_element::<
                            chrono::DateTime<chrono::Utc>,
                        >(&mut __seq)
                        {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(_serde::de::Error::invalid_length(
                                    8usize,
                                    &"struct Token with 9 elements",
                                ));
                            }
                        };
                        _serde::__private::Ok(Token {
                            username: __field0,
                            token_id: __field1,
                            name: __field2,
                            scopes: __field3,
                            key_hash: __field4,
                            access_token: __field5,
                            refresh_token: __field6,
                            token_type: __field7,
                            expires: __field8,
                        })
                    }
                    #[inline]
                    fn visit_map<__A>(
                        self,
                        mut __map: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::MapAccess<'de>,
                    {
                        let mut __field0: _serde::__private::Option<String> =
                            _serde::__private::None;
                        let mut __field1: _serde::__private::Option<Uuid> = _serde::__private::None;
                        let mut __field2: _serde::__private::Option<String> =
                            _serde::__private::None;
                        let mut __field3: _serde::__private::Option<Scopes> =
                            _serde::__private::None;
                        let mut __field4: _serde::__private::Option<String> =
                            _serde::__private::None;
                        let mut __field5: _serde::__private::Option<AccessToken> =
                            _serde::__private::None;
                        let mut __field6: _serde::__private::Option<RefreshToken> =
                            _serde::__private::None;
                        let mut __field7: _serde::__private::Option<BasicTokenType> =
                            _serde::__private::None;
                        let mut __field8: _serde::__private::Option<chrono::DateTime<chrono::Utc>> =
                            _serde::__private::None;
                        while let _serde::__private::Some(__key) =
                            match _serde::de::MapAccess::next_key::<__Field>(&mut __map) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            }
                        {
                            match __key {
                                __Field::__field0 => {
                                    if _serde::__private::Option::is_some(&__field0) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field(
                                                "username",
                                            ),
                                        );
                                    }
                                    __field0 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<String>(
                                            &mut __map,
                                        ) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                __Field::__field1 => {
                                    if _serde::__private::Option::is_some(&__field1) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field(
                                                "token_id",
                                            ),
                                        );
                                    }
                                    __field1 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<Uuid>(&mut __map)
                                        {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                __Field::__field2 => {
                                    if _serde::__private::Option::is_some(&__field2) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field(
                                                "name",
                                            ),
                                        );
                                    }
                                    __field2 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<String>(
                                            &mut __map,
                                        ) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                __Field::__field3 => {
                                    if _serde::__private::Option::is_some(&__field3) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field(
                                                "scopes",
                                            ),
                                        );
                                    }
                                    __field3 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<Scopes>(
                                            &mut __map,
                                        ) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                __Field::__field4 => {
                                    if _serde::__private::Option::is_some(&__field4) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field(
                                                "key_hash",
                                            ),
                                        );
                                    }
                                    __field4 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<String>(
                                            &mut __map,
                                        ) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                __Field::__field5 => {
                                    if _serde::__private::Option::is_some(&__field5) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field(
                                                "access_token",
                                            ),
                                        );
                                    }
                                    __field5 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<AccessToken>(
                                            &mut __map,
                                        ) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                __Field::__field6 => {
                                    if _serde::__private::Option::is_some(&__field6) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field(
                                                "refresh_token",
                                            ),
                                        );
                                    }
                                    __field6 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<RefreshToken>(
                                            &mut __map,
                                        ) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                __Field::__field7 => {
                                    if _serde::__private::Option::is_some(&__field7) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field(
                                                "token_type",
                                            ),
                                        );
                                    }
                                    __field7 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<BasicTokenType>(
                                            &mut __map,
                                        ) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                __Field::__field8 => {
                                    if _serde::__private::Option::is_some(&__field8) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field(
                                                "expires",
                                            ),
                                        );
                                    }
                                    __field8 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<
                                            chrono::DateTime<chrono::Utc>,
                                        >(&mut __map)
                                        {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                _ => {
                                    let _ = match _serde::de::MapAccess::next_value::<
                                        _serde::de::IgnoredAny,
                                    >(&mut __map)
                                    {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    };
                                }
                            }
                        }
                        let __field0 = match __field0 {
                            _serde::__private::Some(__field0) => __field0,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("username") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        let __field1 = match __field1 {
                            _serde::__private::Some(__field1) => __field1,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("token_id") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        let __field2 = match __field2 {
                            _serde::__private::Some(__field2) => __field2,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("name") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        let __field3 = match __field3 {
                            _serde::__private::Some(__field3) => __field3,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("scopes") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        let __field4 = match __field4 {
                            _serde::__private::Some(__field4) => __field4,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("key_hash") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        let __field5 = match __field5 {
                            _serde::__private::Some(__field5) => __field5,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("access_token") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        let __field6 = match __field6 {
                            _serde::__private::Some(__field6) => __field6,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("refresh_token") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        let __field7 = match __field7 {
                            _serde::__private::Some(__field7) => __field7,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("token_type") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        let __field8 = match __field8 {
                            _serde::__private::Some(__field8) => __field8,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("expires") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        _serde::__private::Ok(Token {
                            username: __field0,
                            token_id: __field1,
                            name: __field2,
                            scopes: __field3,
                            key_hash: __field4,
                            access_token: __field5,
                            refresh_token: __field6,
                            token_type: __field7,
                            expires: __field8,
                        })
                    }
                }
                const FIELDS: &'static [&'static str] = &[
                    "username",
                    "token_id",
                    "name",
                    "scopes",
                    "key_hash",
                    "access_token",
                    "refresh_token",
                    "token_type",
                    "expires",
                ];
                _serde::Deserializer::deserialize_struct(
                    __deserializer,
                    "Token",
                    FIELDS,
                    __Visitor {
                        marker: _serde::__private::PhantomData::<Token>,
                        lifetime: _serde::__private::PhantomData,
                    },
                )
            }
        }
    };
    impl<
            '__nitroglycerin_dynamo_db_dlient,
            __NitroglycerinDynamoDBClient: '__nitroglycerin_dynamo_db_dlient + ?Sized,
            __NitroglycerinKeyRequest,
        >
        ::nitroglycerin::key::Builder<
            '__nitroglycerin_dynamo_db_dlient,
            __NitroglycerinDynamoDBClient,
            __NitroglycerinKeyRequest,
        > for Token
    where
        Self: ::nitroglycerin::Table,
        __NitroglycerinKeyRequest: ::std::convert::From<::nitroglycerin::key::Key>,
    {
        type Builder = TokenKeyBuilder<
            '__nitroglycerin_dynamo_db_dlient,
            __NitroglycerinDynamoDBClient,
            __NitroglycerinKeyRequest,
        >;
        fn key(
            client: &'__nitroglycerin_dynamo_db_dlient __NitroglycerinDynamoDBClient,
        ) -> Self::Builder {
            Self::Builder {
                client,
                _phantom: ::std::marker::PhantomData,
            }
        }
    }
    ///part one of the key builder chain for Token
    pub struct TokenKeyBuilder<
        '__nitroglycerin_dynamo_db_dlient,
        __NitroglycerinDynamoDBClient: '__nitroglycerin_dynamo_db_dlient + ?Sized,
        __NitroglycerinKeyRequest,
    > {
        client: &'__nitroglycerin_dynamo_db_dlient __NitroglycerinDynamoDBClient,
        _phantom: ::std::marker::PhantomData<(__NitroglycerinKeyRequest,)>,
    }
    impl<
            '__nitroglycerin_dynamo_db_dlient,
            __NitroglycerinDynamoDBClient: '__nitroglycerin_dynamo_db_dlient + ?Sized,
            __NitroglycerinKeyRequest,
        >
        TokenKeyBuilder<
            '__nitroglycerin_dynamo_db_dlient,
            __NitroglycerinDynamoDBClient,
            __NitroglycerinKeyRequest,
        >
    where
        __NitroglycerinKeyRequest: ::std::convert::From<::nitroglycerin::key::Key>,
    {
        ///set the value of the partition key (username)
        pub fn username(
            self,
            username: &String,
        ) -> ::std::result::Result<
            TokenKeyBuilderPartition<
                '__nitroglycerin_dynamo_db_dlient,
                __NitroglycerinDynamoDBClient,
                __NitroglycerinKeyRequest,
            >,
            ::nitroglycerin::SerError,
        >
        where
            String: ::nitroglycerin::serde::Serialize,
            Token: ::nitroglycerin::Table,
        {
            let partition_key: &String = username;
            let Self { client, _phantom } = self;
            let key = ::nitroglycerin::key::Key::new::<Token, _>("username", partition_key)?;
            ::std::result::Result::Ok(TokenKeyBuilderPartition::new(client, key))
        }
    }
    ///part two of the key builder chain for Token
    pub struct TokenKeyBuilderPartition<
        '__nitroglycerin_dynamo_db_dlient,
        __NitroglycerinDynamoDBClient: '__nitroglycerin_dynamo_db_dlient + ?Sized,
        __NitroglycerinKeyRequest,
    > {
        client: &'__nitroglycerin_dynamo_db_dlient __NitroglycerinDynamoDBClient,
        key: ::nitroglycerin::key::Key,
        _phantom: ::std::marker::PhantomData<(__NitroglycerinKeyRequest,)>,
    }
    impl<
            '__nitroglycerin_dynamo_db_dlient,
            __NitroglycerinDynamoDBClient: '__nitroglycerin_dynamo_db_dlient + ?Sized,
            __NitroglycerinKeyRequest,
        >
        TokenKeyBuilderPartition<
            '__nitroglycerin_dynamo_db_dlient,
            __NitroglycerinDynamoDBClient,
            __NitroglycerinKeyRequest,
        >
    where
        __NitroglycerinKeyRequest: ::std::convert::From<::nitroglycerin::key::Key>,
    {
        fn new(
            client: &'__nitroglycerin_dynamo_db_dlient __NitroglycerinDynamoDBClient,
            key: ::nitroglycerin::key::Key,
        ) -> Self {
            Self {
                client,
                key,
                _phantom: ::std::marker::PhantomData,
            }
        }
    }
    impl<
            '__nitroglycerin_dynamo_db_dlient,
            __NitroglycerinDynamoDBClient: '__nitroglycerin_dynamo_db_dlient + ?Sized,
            __NitroglycerinKeyRequest,
        >
        TokenKeyBuilderPartition<
            '__nitroglycerin_dynamo_db_dlient,
            __NitroglycerinDynamoDBClient,
            __NitroglycerinKeyRequest,
        >
    where
        __NitroglycerinKeyRequest: ::std::convert::From<::nitroglycerin::key::Key>,
    {
        ///set the value of the sort key (token_id)
        pub fn token_id(
            self,
            token_id: &Uuid,
        ) -> ::std::result::Result<
            ::nitroglycerin::key::Expr<
                '__nitroglycerin_dynamo_db_dlient,
                __NitroglycerinDynamoDBClient,
                __NitroglycerinKeyRequest,
                Token,
            >,
            ::nitroglycerin::SerError,
        >
        where
            Uuid: ::nitroglycerin::serde::Serialize,
        {
            let sort_key: &Uuid = token_id;
            let Self {
                client,
                mut key,
                _phantom,
            } = self;
            key.insert("token_id", sort_key)?;
            ::std::result::Result::Ok(::nitroglycerin::key::Expr::new(client, key))
        }
    }
    impl<
            '__nitroglycerin_dynamo_db_dlient,
            __NitroglycerinDynamoDBClient: '__nitroglycerin_dynamo_db_dlient + ?Sized,
        >
        ::nitroglycerin::query::Query<
            '__nitroglycerin_dynamo_db_dlient,
            __NitroglycerinDynamoDBClient,
        > for Token
    where
        Self: ::nitroglycerin::TableIndex,
    {
        type Builder =
            TokenQueryBuilder<'__nitroglycerin_dynamo_db_dlient, __NitroglycerinDynamoDBClient>;
        fn query(
            client: &'__nitroglycerin_dynamo_db_dlient __NitroglycerinDynamoDBClient,
        ) -> Self::Builder {
            Self::Builder {
                client,
                _phantom: ::std::marker::PhantomData,
            }
        }
    }
    ///part one of the query builder chain for Token
    pub struct TokenQueryBuilder<
        '__nitroglycerin_dynamo_db_dlient,
        __NitroglycerinDynamoDBClient: '__nitroglycerin_dynamo_db_dlient + ?Sized,
    > {
        client: &'__nitroglycerin_dynamo_db_dlient __NitroglycerinDynamoDBClient,
        _phantom: ::std::marker::PhantomData<()>,
    }
    impl<
            '__nitroglycerin_dynamo_db_dlient,
            __NitroglycerinDynamoDBClient: '__nitroglycerin_dynamo_db_dlient + ?Sized,
        > TokenQueryBuilder<'__nitroglycerin_dynamo_db_dlient, __NitroglycerinDynamoDBClient>
    {
        ///set the value of the sort key (username)
        pub fn username(
            self,
            username: &String,
        ) -> TokenQueryBuilderPartition<
            '__nitroglycerin_dynamo_db_dlient,
            __NitroglycerinDynamoDBClient,
        >
        where
            String: ::nitroglycerin::serde::Serialize,
            Token: ::nitroglycerin::TableIndex,
        {
            let partition_key: &String = username;
            let Self { client, _phantom } = self;
            let input = ::nitroglycerin::query::new_input::<Token, _>("username", partition_key);
            TokenQueryBuilderPartition::new(client, input)
        }
    }
    ///part two of the query builder chain for Token
    pub struct TokenQueryBuilderPartition<
        '__nitroglycerin_dynamo_db_dlient,
        __NitroglycerinDynamoDBClient: '__nitroglycerin_dynamo_db_dlient + ?Sized,
    > {
        client: &'__nitroglycerin_dynamo_db_dlient __NitroglycerinDynamoDBClient,
        input: ::nitroglycerin::dynamodb::QueryInput,
        _phantom: ::std::marker::PhantomData<()>,
    }
    impl<
            '__nitroglycerin_dynamo_db_dlient,
            __NitroglycerinDynamoDBClient: '__nitroglycerin_dynamo_db_dlient + ?Sized,
        >
        TokenQueryBuilderPartition<'__nitroglycerin_dynamo_db_dlient, __NitroglycerinDynamoDBClient>
    {
        fn new(
            client: &'__nitroglycerin_dynamo_db_dlient __NitroglycerinDynamoDBClient,
            input: ::nitroglycerin::dynamodb::QueryInput,
        ) -> Self {
            Self {
                client,
                input,
                _phantom: ::std::marker::PhantomData,
            }
        }
        pub fn consistent_read(
            self,
        ) -> ::nitroglycerin::query::Expr<
            '__nitroglycerin_dynamo_db_dlient,
            __NitroglycerinDynamoDBClient,
            Token,
        > {
            let Self {
                client,
                input,
                _phantom,
            } = self;
            ::nitroglycerin::query::Expr::new(client, input).consistent_read()
        }
        pub async fn execute(
            self,
        ) -> ::std::result::Result<
            ::std::vec::Vec<Token>,
            ::nitroglycerin::DynamoError<::nitroglycerin::dynamodb::QueryError>,
        >
        where
            __NitroglycerinDynamoDBClient: ::nitroglycerin::dynamodb::DynamoDb,
            &'__nitroglycerin_dynamo_db_dlient __NitroglycerinDynamoDBClient: ::std::marker::Send,
            Token: ::nitroglycerin::serde::de::DeserializeOwned + ::std::marker::Send,
        {
            let Self {
                client,
                input,
                _phantom,
            } = self;
            ::nitroglycerin::query::Expr::new(client, input)
                .execute()
                .await
        }
    }
    impl<
            '__nitroglycerin_dynamo_db_dlient,
            __NitroglycerinDynamoDBClient: '__nitroglycerin_dynamo_db_dlient + ?Sized,
        >
        TokenQueryBuilderPartition<'__nitroglycerin_dynamo_db_dlient, __NitroglycerinDynamoDBClient>
    {
        ///set the value of the sort key (token_id)
        pub fn token_id(
            self,
        ) -> ::nitroglycerin::query::BuilderSort<
            '__nitroglycerin_dynamo_db_dlient,
            __NitroglycerinDynamoDBClient,
            Uuid,
            Token,
        > {
            let Self {
                client,
                input,
                _phantom,
            } = self;
            ::nitroglycerin::query::BuilderSort::new(client, input, "token_id")
        }
    }
    impl Table for User {
        fn table_name() -> String {
            "Users".to_string()
        }
    }
    impl Table for Token {
        fn table_name() -> String {
            "Tokens".to_string()
        }
    }
}
mod login {
    use chrono::Utc;
    use serde::{Deserialize, Serialize};
    pub struct Claims {
        #[serde(rename = "sub")]
        pub username: String,
        #[serde(rename = "exp", with = "chrono::serde::ts_seconds")]
        pub expires: chrono::DateTime<Utc>,
    }
    #[automatically_derived]
    #[allow(unused_qualifications)]
    impl ::core::fmt::Debug for Claims {
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            match *self {
                Claims {
                    username: ref __self_0_0,
                    expires: ref __self_0_1,
                } => {
                    let debug_trait_builder =
                        &mut ::core::fmt::Formatter::debug_struct(f, "Claims");
                    let _ = ::core::fmt::DebugStruct::field(
                        debug_trait_builder,
                        "username",
                        &&(*__self_0_0),
                    );
                    let _ = ::core::fmt::DebugStruct::field(
                        debug_trait_builder,
                        "expires",
                        &&(*__self_0_1),
                    );
                    ::core::fmt::DebugStruct::finish(debug_trait_builder)
                }
            }
        }
    }
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        #[allow(unused_extern_crates, clippy::useless_attribute)]
        extern crate serde as _serde;
        #[automatically_derived]
        impl _serde::Serialize for Claims {
            fn serialize<__S>(
                &self,
                __serializer: __S,
            ) -> _serde::__private::Result<__S::Ok, __S::Error>
            where
                __S: _serde::Serializer,
            {
                let mut __serde_state = match _serde::Serializer::serialize_struct(
                    __serializer,
                    "Claims",
                    false as usize + 1 + 1,
                ) {
                    _serde::__private::Ok(__val) => __val,
                    _serde::__private::Err(__err) => {
                        return _serde::__private::Err(__err);
                    }
                };
                match _serde::ser::SerializeStruct::serialize_field(
                    &mut __serde_state,
                    "sub",
                    &self.username,
                ) {
                    _serde::__private::Ok(__val) => __val,
                    _serde::__private::Err(__err) => {
                        return _serde::__private::Err(__err);
                    }
                };
                match _serde::ser::SerializeStruct::serialize_field(&mut __serde_state, "exp", {
                    struct __SerializeWith<'__a> {
                        values: (&'__a chrono::DateTime<Utc>,),
                        phantom: _serde::__private::PhantomData<Claims>,
                    }
                    impl<'__a> _serde::Serialize for __SerializeWith<'__a> {
                        fn serialize<__S>(
                            &self,
                            __s: __S,
                        ) -> _serde::__private::Result<__S::Ok, __S::Error>
                        where
                            __S: _serde::Serializer,
                        {
                            chrono::serde::ts_seconds::serialize(self.values.0, __s)
                        }
                    }
                    &__SerializeWith {
                        values: (&self.expires,),
                        phantom: _serde::__private::PhantomData::<Claims>,
                    }
                }) {
                    _serde::__private::Ok(__val) => __val,
                    _serde::__private::Err(__err) => {
                        return _serde::__private::Err(__err);
                    }
                };
                _serde::ser::SerializeStruct::end(__serde_state)
            }
        }
    };
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        #[allow(unused_extern_crates, clippy::useless_attribute)]
        extern crate serde as _serde;
        #[automatically_derived]
        impl<'de> _serde::Deserialize<'de> for Claims {
            fn deserialize<__D>(__deserializer: __D) -> _serde::__private::Result<Self, __D::Error>
            where
                __D: _serde::Deserializer<'de>,
            {
                #[allow(non_camel_case_types)]
                enum __Field {
                    __field0,
                    __field1,
                    __ignore,
                }
                struct __FieldVisitor;
                impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                    type Value = __Field;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(__formatter, "field identifier")
                    }
                    fn visit_u64<__E>(
                        self,
                        __value: u64,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            0u64 => _serde::__private::Ok(__Field::__field0),
                            1u64 => _serde::__private::Ok(__Field::__field1),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_str<__E>(
                        self,
                        __value: &str,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            "sub" => _serde::__private::Ok(__Field::__field0),
                            "exp" => _serde::__private::Ok(__Field::__field1),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_bytes<__E>(
                        self,
                        __value: &[u8],
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            b"sub" => _serde::__private::Ok(__Field::__field0),
                            b"exp" => _serde::__private::Ok(__Field::__field1),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                }
                impl<'de> _serde::Deserialize<'de> for __Field {
                    #[inline]
                    fn deserialize<__D>(
                        __deserializer: __D,
                    ) -> _serde::__private::Result<Self, __D::Error>
                    where
                        __D: _serde::Deserializer<'de>,
                    {
                        _serde::Deserializer::deserialize_identifier(__deserializer, __FieldVisitor)
                    }
                }
                struct __Visitor<'de> {
                    marker: _serde::__private::PhantomData<Claims>,
                    lifetime: _serde::__private::PhantomData<&'de ()>,
                }
                impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                    type Value = Claims;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(__formatter, "struct Claims")
                    }
                    #[inline]
                    fn visit_seq<__A>(
                        self,
                        mut __seq: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::SeqAccess<'de>,
                    {
                        let __field0 =
                            match match _serde::de::SeqAccess::next_element::<String>(&mut __seq) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            } {
                                _serde::__private::Some(__value) => __value,
                                _serde::__private::None => {
                                    return _serde::__private::Err(
                                        _serde::de::Error::invalid_length(
                                            0usize,
                                            &"struct Claims with 2 elements",
                                        ),
                                    );
                                }
                            };
                        let __field1 = match {
                            struct __DeserializeWith<'de> {
                                value: chrono::DateTime<Utc>,
                                phantom: _serde::__private::PhantomData<Claims>,
                                lifetime: _serde::__private::PhantomData<&'de ()>,
                            }
                            impl<'de> _serde::Deserialize<'de> for __DeserializeWith<'de> {
                                fn deserialize<__D>(
                                    __deserializer: __D,
                                ) -> _serde::__private::Result<Self, __D::Error>
                                where
                                    __D: _serde::Deserializer<'de>,
                                {
                                    _serde::__private::Ok(__DeserializeWith {
                                        value: match chrono::serde::ts_seconds::deserialize(
                                            __deserializer,
                                        ) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                        phantom: _serde::__private::PhantomData,
                                        lifetime: _serde::__private::PhantomData,
                                    })
                                }
                            }
                            _serde::__private::Option::map(
                                match _serde::de::SeqAccess::next_element::<__DeserializeWith<'de>>(
                                    &mut __seq,
                                ) {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                },
                                |__wrap| __wrap.value,
                            )
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(_serde::de::Error::invalid_length(
                                    1usize,
                                    &"struct Claims with 2 elements",
                                ));
                            }
                        };
                        _serde::__private::Ok(Claims {
                            username: __field0,
                            expires: __field1,
                        })
                    }
                    #[inline]
                    fn visit_map<__A>(
                        self,
                        mut __map: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::MapAccess<'de>,
                    {
                        let mut __field0: _serde::__private::Option<String> =
                            _serde::__private::None;
                        let mut __field1: _serde::__private::Option<chrono::DateTime<Utc>> =
                            _serde::__private::None;
                        while let _serde::__private::Some(__key) =
                            match _serde::de::MapAccess::next_key::<__Field>(&mut __map) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            }
                        {
                            match __key {
                                __Field::__field0 => {
                                    if _serde::__private::Option::is_some(&__field0) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field(
                                                "sub",
                                            ),
                                        );
                                    }
                                    __field0 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<String>(
                                            &mut __map,
                                        ) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                __Field::__field1 => {
                                    if _serde::__private::Option::is_some(&__field1) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field(
                                                "exp",
                                            ),
                                        );
                                    }
                                    __field1 = _serde::__private::Some({
                                        struct __DeserializeWith<'de> {
                                            value: chrono::DateTime<Utc>,
                                            phantom: _serde::__private::PhantomData<Claims>,
                                            lifetime: _serde::__private::PhantomData<&'de ()>,
                                        }
                                        impl<'de> _serde::Deserialize<'de> for __DeserializeWith<'de> {
                                            fn deserialize<__D>(
                                                __deserializer: __D,
                                            ) -> _serde::__private::Result<Self, __D::Error>
                                            where
                                                __D: _serde::Deserializer<'de>,
                                            {
                                                _serde::__private::Ok(__DeserializeWith {
                                                    value:
                                                        match chrono::serde::ts_seconds::deserialize(
                                                            __deserializer,
                                                        ) {
                                                            _serde::__private::Ok(__val) => __val,
                                                            _serde::__private::Err(__err) => {
                                                                return _serde::__private::Err(
                                                                    __err,
                                                                );
                                                            }
                                                        },
                                                    phantom: _serde::__private::PhantomData,
                                                    lifetime: _serde::__private::PhantomData,
                                                })
                                            }
                                        }
                                        match _serde::de::MapAccess::next_value::<
                                            __DeserializeWith<'de>,
                                        >(&mut __map)
                                        {
                                            _serde::__private::Ok(__wrapper) => __wrapper.value,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        }
                                    });
                                }
                                _ => {
                                    let _ = match _serde::de::MapAccess::next_value::<
                                        _serde::de::IgnoredAny,
                                    >(&mut __map)
                                    {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    };
                                }
                            }
                        }
                        let __field0 = match __field0 {
                            _serde::__private::Some(__field0) => __field0,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("sub") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        let __field1 = match __field1 {
                            _serde::__private::Some(__field1) => __field1,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    <__A::Error as _serde::de::Error>::missing_field("exp"),
                                )
                            }
                        };
                        _serde::__private::Ok(Claims {
                            username: __field0,
                            expires: __field1,
                        })
                    }
                }
                const FIELDS: &'static [&'static str] = &["sub", "exp"];
                _serde::Deserializer::deserialize_struct(
                    __deserializer,
                    "Claims",
                    FIELDS,
                    __Visitor {
                        marker: _serde::__private::PhantomData::<Claims>,
                        lifetime: _serde::__private::PhantomData,
                    },
                )
            }
        }
    };
}
mod provider {
    use async_graphql::{
        from_value, scalar, to_value, ContainerType, Context, Scalar, InputValueResult, OutputType,
        ScalarType, ServerResult, Union, Value,
    };
    use nitroglycerin::serde::{Deserialize, Serialize};
    use self::spotify::SpotifyScope;
    pub mod spotify {
        use async_graphql::{Enum};
        use nitroglycerin::serde::{Serialize, Deserialize};
        pub struct SpotifyProvider;
        impl super::Provider for SpotifyProvider {
            const AUTH_URL: &'static str = "https://accounts.spotify.com/authorize";
            const TOKEN_URL: &'static str = "https://accounts.spotify.com/api/token";
            type Scopes = SpotifyScope;
        }
        pub enum SpotifyScope {
            UgcImageUpload,
            UserReadRecentlyPlayed,
            UserTopRead,
            UserReadPlaybackPosition,
            UserReadPlaybackState,
            UserModifyPlaybackState,
            UserReadCurrentlyPlaying,
            AppRemoteControl,
            Streaming,
            PlaylistModifyPublic,
            PlaylistModifyPrivate,
            PlaylistReadPrivate,
            PlaylistReadCollaborative,
            UserFollowModify,
            UserFollowRead,
            UserLibraryModify,
            UserLibraryRead,
            UserReadEmail,
            UserReadPrivate,
        }
        #[allow(clippy::all, clippy::pedantic)]
        impl async_graphql::resolver_utils::EnumType for SpotifyScope {
            fn items() -> &'static [async_graphql::resolver_utils::EnumItem<SpotifyScope>] {
                &[
                    async_graphql::resolver_utils::EnumItem {
                        name: "UGC_IMAGE_UPLOAD",
                        value: SpotifyScope::UgcImageUpload,
                    },
                    async_graphql::resolver_utils::EnumItem {
                        name: "USER_READ_RECENTLY_PLAYED",
                        value: SpotifyScope::UserReadRecentlyPlayed,
                    },
                    async_graphql::resolver_utils::EnumItem {
                        name: "USER_TOP_READ",
                        value: SpotifyScope::UserTopRead,
                    },
                    async_graphql::resolver_utils::EnumItem {
                        name: "USER_READ_PLAYBACK_POSITION",
                        value: SpotifyScope::UserReadPlaybackPosition,
                    },
                    async_graphql::resolver_utils::EnumItem {
                        name: "USER_READ_PLAYBACK_STATE",
                        value: SpotifyScope::UserReadPlaybackState,
                    },
                    async_graphql::resolver_utils::EnumItem {
                        name: "USER_MODIFY_PLAYBACK_STATE",
                        value: SpotifyScope::UserModifyPlaybackState,
                    },
                    async_graphql::resolver_utils::EnumItem {
                        name: "USER_READ_CURRENTLY_PLAYING",
                        value: SpotifyScope::UserReadCurrentlyPlaying,
                    },
                    async_graphql::resolver_utils::EnumItem {
                        name: "APP_REMOTE_CONTROL",
                        value: SpotifyScope::AppRemoteControl,
                    },
                    async_graphql::resolver_utils::EnumItem {
                        name: "STREAMING",
                        value: SpotifyScope::Streaming,
                    },
                    async_graphql::resolver_utils::EnumItem {
                        name: "PLAYLIST_MODIFY_PUBLIC",
                        value: SpotifyScope::PlaylistModifyPublic,
                    },
                    async_graphql::resolver_utils::EnumItem {
                        name: "PLAYLIST_MODIFY_PRIVATE",
                        value: SpotifyScope::PlaylistModifyPrivate,
                    },
                    async_graphql::resolver_utils::EnumItem {
                        name: "PLAYLIST_READ_PRIVATE",
                        value: SpotifyScope::PlaylistReadPrivate,
                    },
                    async_graphql::resolver_utils::EnumItem {
                        name: "PLAYLIST_READ_COLLABORATIVE",
                        value: SpotifyScope::PlaylistReadCollaborative,
                    },
                    async_graphql::resolver_utils::EnumItem {
                        name: "USER_FOLLOW_MODIFY",
                        value: SpotifyScope::UserFollowModify,
                    },
                    async_graphql::resolver_utils::EnumItem {
                        name: "USER_FOLLOW_READ",
                        value: SpotifyScope::UserFollowRead,
                    },
                    async_graphql::resolver_utils::EnumItem {
                        name: "USER_LIBRARY_MODIFY",
                        value: SpotifyScope::UserLibraryModify,
                    },
                    async_graphql::resolver_utils::EnumItem {
                        name: "USER_LIBRARY_READ",
                        value: SpotifyScope::UserLibraryRead,
                    },
                    async_graphql::resolver_utils::EnumItem {
                        name: "USER_READ_EMAIL",
                        value: SpotifyScope::UserReadEmail,
                    },
                    async_graphql::resolver_utils::EnumItem {
                        name: "USER_READ_PRIVATE",
                        value: SpotifyScope::UserReadPrivate,
                    },
                ]
            }
        }
        #[allow(clippy::all, clippy::pedantic)]
        impl async_graphql::Type for SpotifyScope {
            fn type_name() -> ::std::borrow::Cow<'static, ::std::primitive::str> {
                ::std::borrow::Cow::Borrowed("SpotifyScope")
            }
            fn create_type_info(
                registry: &mut async_graphql::registry::Registry,
            ) -> ::std::string::String {
                registry.create_type::<Self, _>(|registry| {
                    async_graphql::registry::MetaType::Enum {
                        name: ::std::borrow::ToOwned::to_owned("SpotifyScope"),
                        description: ::std::option::Option::None,
                        enum_values: {
                            let mut enum_items = async_graphql::indexmap::IndexMap::new();
                            enum_items.insert(
                                "UGC_IMAGE_UPLOAD",
                                async_graphql::registry::MetaEnumValue {
                                    name: "UGC_IMAGE_UPLOAD",
                                    description: ::std::option::Option::None,
                                    deprecation: async_graphql::registry::Deprecation::NoDeprecated,
                                    visible: ::std::option::Option::None,
                                },
                            );
                            enum_items.insert(
                                "USER_READ_RECENTLY_PLAYED",
                                async_graphql::registry::MetaEnumValue {
                                    name: "USER_READ_RECENTLY_PLAYED",
                                    description: ::std::option::Option::None,
                                    deprecation: async_graphql::registry::Deprecation::NoDeprecated,
                                    visible: ::std::option::Option::None,
                                },
                            );
                            enum_items.insert(
                                "USER_TOP_READ",
                                async_graphql::registry::MetaEnumValue {
                                    name: "USER_TOP_READ",
                                    description: ::std::option::Option::None,
                                    deprecation: async_graphql::registry::Deprecation::NoDeprecated,
                                    visible: ::std::option::Option::None,
                                },
                            );
                            enum_items.insert(
                                "USER_READ_PLAYBACK_POSITION",
                                async_graphql::registry::MetaEnumValue {
                                    name: "USER_READ_PLAYBACK_POSITION",
                                    description: ::std::option::Option::None,
                                    deprecation: async_graphql::registry::Deprecation::NoDeprecated,
                                    visible: ::std::option::Option::None,
                                },
                            );
                            enum_items.insert(
                                "USER_READ_PLAYBACK_STATE",
                                async_graphql::registry::MetaEnumValue {
                                    name: "USER_READ_PLAYBACK_STATE",
                                    description: ::std::option::Option::None,
                                    deprecation: async_graphql::registry::Deprecation::NoDeprecated,
                                    visible: ::std::option::Option::None,
                                },
                            );
                            enum_items.insert(
                                "USER_MODIFY_PLAYBACK_STATE",
                                async_graphql::registry::MetaEnumValue {
                                    name: "USER_MODIFY_PLAYBACK_STATE",
                                    description: ::std::option::Option::None,
                                    deprecation: async_graphql::registry::Deprecation::NoDeprecated,
                                    visible: ::std::option::Option::None,
                                },
                            );
                            enum_items.insert(
                                "USER_READ_CURRENTLY_PLAYING",
                                async_graphql::registry::MetaEnumValue {
                                    name: "USER_READ_CURRENTLY_PLAYING",
                                    description: ::std::option::Option::None,
                                    deprecation: async_graphql::registry::Deprecation::NoDeprecated,
                                    visible: ::std::option::Option::None,
                                },
                            );
                            enum_items.insert(
                                "APP_REMOTE_CONTROL",
                                async_graphql::registry::MetaEnumValue {
                                    name: "APP_REMOTE_CONTROL",
                                    description: ::std::option::Option::None,
                                    deprecation: async_graphql::registry::Deprecation::NoDeprecated,
                                    visible: ::std::option::Option::None,
                                },
                            );
                            enum_items.insert(
                                "STREAMING",
                                async_graphql::registry::MetaEnumValue {
                                    name: "STREAMING",
                                    description: ::std::option::Option::None,
                                    deprecation: async_graphql::registry::Deprecation::NoDeprecated,
                                    visible: ::std::option::Option::None,
                                },
                            );
                            enum_items.insert(
                                "PLAYLIST_MODIFY_PUBLIC",
                                async_graphql::registry::MetaEnumValue {
                                    name: "PLAYLIST_MODIFY_PUBLIC",
                                    description: ::std::option::Option::None,
                                    deprecation: async_graphql::registry::Deprecation::NoDeprecated,
                                    visible: ::std::option::Option::None,
                                },
                            );
                            enum_items.insert(
                                "PLAYLIST_MODIFY_PRIVATE",
                                async_graphql::registry::MetaEnumValue {
                                    name: "PLAYLIST_MODIFY_PRIVATE",
                                    description: ::std::option::Option::None,
                                    deprecation: async_graphql::registry::Deprecation::NoDeprecated,
                                    visible: ::std::option::Option::None,
                                },
                            );
                            enum_items.insert(
                                "PLAYLIST_READ_PRIVATE",
                                async_graphql::registry::MetaEnumValue {
                                    name: "PLAYLIST_READ_PRIVATE",
                                    description: ::std::option::Option::None,
                                    deprecation: async_graphql::registry::Deprecation::NoDeprecated,
                                    visible: ::std::option::Option::None,
                                },
                            );
                            enum_items.insert(
                                "PLAYLIST_READ_COLLABORATIVE",
                                async_graphql::registry::MetaEnumValue {
                                    name: "PLAYLIST_READ_COLLABORATIVE",
                                    description: ::std::option::Option::None,
                                    deprecation: async_graphql::registry::Deprecation::NoDeprecated,
                                    visible: ::std::option::Option::None,
                                },
                            );
                            enum_items.insert(
                                "USER_FOLLOW_MODIFY",
                                async_graphql::registry::MetaEnumValue {
                                    name: "USER_FOLLOW_MODIFY",
                                    description: ::std::option::Option::None,
                                    deprecation: async_graphql::registry::Deprecation::NoDeprecated,
                                    visible: ::std::option::Option::None,
                                },
                            );
                            enum_items.insert(
                                "USER_FOLLOW_READ",
                                async_graphql::registry::MetaEnumValue {
                                    name: "USER_FOLLOW_READ",
                                    description: ::std::option::Option::None,
                                    deprecation: async_graphql::registry::Deprecation::NoDeprecated,
                                    visible: ::std::option::Option::None,
                                },
                            );
                            enum_items.insert(
                                "USER_LIBRARY_MODIFY",
                                async_graphql::registry::MetaEnumValue {
                                    name: "USER_LIBRARY_MODIFY",
                                    description: ::std::option::Option::None,
                                    deprecation: async_graphql::registry::Deprecation::NoDeprecated,
                                    visible: ::std::option::Option::None,
                                },
                            );
                            enum_items.insert(
                                "USER_LIBRARY_READ",
                                async_graphql::registry::MetaEnumValue {
                                    name: "USER_LIBRARY_READ",
                                    description: ::std::option::Option::None,
                                    deprecation: async_graphql::registry::Deprecation::NoDeprecated,
                                    visible: ::std::option::Option::None,
                                },
                            );
                            enum_items.insert(
                                "USER_READ_EMAIL",
                                async_graphql::registry::MetaEnumValue {
                                    name: "USER_READ_EMAIL",
                                    description: ::std::option::Option::None,
                                    deprecation: async_graphql::registry::Deprecation::NoDeprecated,
                                    visible: ::std::option::Option::None,
                                },
                            );
                            enum_items.insert(
                                "USER_READ_PRIVATE",
                                async_graphql::registry::MetaEnumValue {
                                    name: "USER_READ_PRIVATE",
                                    description: ::std::option::Option::None,
                                    deprecation: async_graphql::registry::Deprecation::NoDeprecated,
                                    visible: ::std::option::Option::None,
                                },
                            );
                            enum_items
                        },
                        visible: ::std::option::Option::None,
                    }
                })
            }
        }
        #[allow(clippy::all, clippy::pedantic)]
        impl async_graphql::InputType for SpotifyScope {
            fn parse(
                value: ::std::option::Option<async_graphql::Value>,
            ) -> async_graphql::InputValueResult<Self> {
                async_graphql::resolver_utils::parse_enum(value.unwrap_or_default())
            }
            fn to_value(&self) -> async_graphql::Value {
                async_graphql::resolver_utils::enum_value(*self)
            }
        }
        impl async_graphql::OutputType for SpotifyScope {
            #[allow(
                clippy::let_unit_value,
                clippy::type_complexity,
                clippy::type_repetition_in_bounds,
                clippy::used_underscore_binding
            )]
            fn resolve<'life0, 'life1, 'life2, 'life3, 'async_trait>(
                &'life0 self,
                __arg1: &'life1 async_graphql::ContextSelectionSet<'life2>,
                _field: &'life3 async_graphql::Positioned<async_graphql::parser::types::Field>,
            ) -> ::core::pin::Pin<
                Box<
                    dyn ::core::future::Future<
                            Output = async_graphql::ServerResult<async_graphql::Value>,
                        > + ::core::marker::Send
                        + 'async_trait,
                >,
            >
            where
                'life0: 'async_trait,
                'life1: 'async_trait,
                'life2: 'async_trait,
                'life3: 'async_trait,
                Self: 'async_trait,
            {
                Box::pin(async move {
                    if let ::core::option::Option::Some(__ret) = ::core::option::Option::None::<
                        async_graphql::ServerResult<async_graphql::Value>,
                    > {
                        return __ret;
                    }
                    let __self = self;
                    let _ = __arg1;
                    let _field = _field;
                    let __ret: async_graphql::ServerResult<async_graphql::Value> = {
                        ::std::result::Result::Ok(async_graphql::resolver_utils::enum_value(
                            *__self,
                        ))
                    };
                    #[allow(unreachable_code)]
                    __ret
                })
            }
        }
        #[automatically_derived]
        #[allow(unused_qualifications)]
        impl ::core::fmt::Debug for SpotifyScope {
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                match (&*self,) {
                    (&SpotifyScope::UgcImageUpload,) => {
                        let debug_trait_builder =
                            &mut ::core::fmt::Formatter::debug_tuple(f, "UgcImageUpload");
                        ::core::fmt::DebugTuple::finish(debug_trait_builder)
                    }
                    (&SpotifyScope::UserReadRecentlyPlayed,) => {
                        let debug_trait_builder =
                            &mut ::core::fmt::Formatter::debug_tuple(f, "UserReadRecentlyPlayed");
                        ::core::fmt::DebugTuple::finish(debug_trait_builder)
                    }
                    (&SpotifyScope::UserTopRead,) => {
                        let debug_trait_builder =
                            &mut ::core::fmt::Formatter::debug_tuple(f, "UserTopRead");
                        ::core::fmt::DebugTuple::finish(debug_trait_builder)
                    }
                    (&SpotifyScope::UserReadPlaybackPosition,) => {
                        let debug_trait_builder =
                            &mut ::core::fmt::Formatter::debug_tuple(f, "UserReadPlaybackPosition");
                        ::core::fmt::DebugTuple::finish(debug_trait_builder)
                    }
                    (&SpotifyScope::UserReadPlaybackState,) => {
                        let debug_trait_builder =
                            &mut ::core::fmt::Formatter::debug_tuple(f, "UserReadPlaybackState");
                        ::core::fmt::DebugTuple::finish(debug_trait_builder)
                    }
                    (&SpotifyScope::UserModifyPlaybackState,) => {
                        let debug_trait_builder =
                            &mut ::core::fmt::Formatter::debug_tuple(f, "UserModifyPlaybackState");
                        ::core::fmt::DebugTuple::finish(debug_trait_builder)
                    }
                    (&SpotifyScope::UserReadCurrentlyPlaying,) => {
                        let debug_trait_builder =
                            &mut ::core::fmt::Formatter::debug_tuple(f, "UserReadCurrentlyPlaying");
                        ::core::fmt::DebugTuple::finish(debug_trait_builder)
                    }
                    (&SpotifyScope::AppRemoteControl,) => {
                        let debug_trait_builder =
                            &mut ::core::fmt::Formatter::debug_tuple(f, "AppRemoteControl");
                        ::core::fmt::DebugTuple::finish(debug_trait_builder)
                    }
                    (&SpotifyScope::Streaming,) => {
                        let debug_trait_builder =
                            &mut ::core::fmt::Formatter::debug_tuple(f, "Streaming");
                        ::core::fmt::DebugTuple::finish(debug_trait_builder)
                    }
                    (&SpotifyScope::PlaylistModifyPublic,) => {
                        let debug_trait_builder =
                            &mut ::core::fmt::Formatter::debug_tuple(f, "PlaylistModifyPublic");
                        ::core::fmt::DebugTuple::finish(debug_trait_builder)
                    }
                    (&SpotifyScope::PlaylistModifyPrivate,) => {
                        let debug_trait_builder =
                            &mut ::core::fmt::Formatter::debug_tuple(f, "PlaylistModifyPrivate");
                        ::core::fmt::DebugTuple::finish(debug_trait_builder)
                    }
                    (&SpotifyScope::PlaylistReadPrivate,) => {
                        let debug_trait_builder =
                            &mut ::core::fmt::Formatter::debug_tuple(f, "PlaylistReadPrivate");
                        ::core::fmt::DebugTuple::finish(debug_trait_builder)
                    }
                    (&SpotifyScope::PlaylistReadCollaborative,) => {
                        let debug_trait_builder = &mut ::core::fmt::Formatter::debug_tuple(
                            f,
                            "PlaylistReadCollaborative",
                        );
                        ::core::fmt::DebugTuple::finish(debug_trait_builder)
                    }
                    (&SpotifyScope::UserFollowModify,) => {
                        let debug_trait_builder =
                            &mut ::core::fmt::Formatter::debug_tuple(f, "UserFollowModify");
                        ::core::fmt::DebugTuple::finish(debug_trait_builder)
                    }
                    (&SpotifyScope::UserFollowRead,) => {
                        let debug_trait_builder =
                            &mut ::core::fmt::Formatter::debug_tuple(f, "UserFollowRead");
                        ::core::fmt::DebugTuple::finish(debug_trait_builder)
                    }
                    (&SpotifyScope::UserLibraryModify,) => {
                        let debug_trait_builder =
                            &mut ::core::fmt::Formatter::debug_tuple(f, "UserLibraryModify");
                        ::core::fmt::DebugTuple::finish(debug_trait_builder)
                    }
                    (&SpotifyScope::UserLibraryRead,) => {
                        let debug_trait_builder =
                            &mut ::core::fmt::Formatter::debug_tuple(f, "UserLibraryRead");
                        ::core::fmt::DebugTuple::finish(debug_trait_builder)
                    }
                    (&SpotifyScope::UserReadEmail,) => {
                        let debug_trait_builder =
                            &mut ::core::fmt::Formatter::debug_tuple(f, "UserReadEmail");
                        ::core::fmt::DebugTuple::finish(debug_trait_builder)
                    }
                    (&SpotifyScope::UserReadPrivate,) => {
                        let debug_trait_builder =
                            &mut ::core::fmt::Formatter::debug_tuple(f, "UserReadPrivate");
                        ::core::fmt::DebugTuple::finish(debug_trait_builder)
                    }
                }
            }
        }
        #[automatically_derived]
        #[allow(unused_qualifications)]
        impl ::core::marker::Copy for SpotifyScope {}
        #[automatically_derived]
        #[allow(unused_qualifications)]
        impl ::core::clone::Clone for SpotifyScope {
            #[inline]
            fn clone(&self) -> SpotifyScope {
                {
                    *self
                }
            }
        }
        impl ::core::marker::StructuralEq for SpotifyScope {}
        #[automatically_derived]
        #[allow(unused_qualifications)]
        impl ::core::cmp::Eq for SpotifyScope {
            #[inline]
            #[doc(hidden)]
            #[no_coverage]
            fn assert_receiver_is_total_eq(&self) -> () {
                {}
            }
        }
        impl ::core::marker::StructuralPartialEq for SpotifyScope {}
        #[automatically_derived]
        #[allow(unused_qualifications)]
        impl ::core::cmp::PartialEq for SpotifyScope {
            #[inline]
            fn eq(&self, other: &SpotifyScope) -> bool {
                {
                    let __self_vi = ::core::intrinsics::discriminant_value(&*self);
                    let __arg_1_vi = ::core::intrinsics::discriminant_value(&*other);
                    if true && __self_vi == __arg_1_vi {
                        match (&*self, &*other) {
                            _ => true,
                        }
                    } else {
                        false
                    }
                }
            }
        }
        #[doc(hidden)]
        #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
        const _: () = {
            #[allow(unused_extern_crates, clippy::useless_attribute)]
            extern crate serde as _serde;
            #[automatically_derived]
            impl _serde::Serialize for SpotifyScope {
                fn serialize<__S>(
                    &self,
                    __serializer: __S,
                ) -> _serde::__private::Result<__S::Ok, __S::Error>
                where
                    __S: _serde::Serializer,
                {
                    match *self {
                        SpotifyScope::UgcImageUpload => _serde::Serializer::serialize_unit_variant(
                            __serializer,
                            "SpotifyScope",
                            0u32,
                            "UgcImageUpload",
                        ),
                        SpotifyScope::UserReadRecentlyPlayed => {
                            _serde::Serializer::serialize_unit_variant(
                                __serializer,
                                "SpotifyScope",
                                1u32,
                                "UserReadRecentlyPlayed",
                            )
                        }
                        SpotifyScope::UserTopRead => _serde::Serializer::serialize_unit_variant(
                            __serializer,
                            "SpotifyScope",
                            2u32,
                            "UserTopRead",
                        ),
                        SpotifyScope::UserReadPlaybackPosition => {
                            _serde::Serializer::serialize_unit_variant(
                                __serializer,
                                "SpotifyScope",
                                3u32,
                                "UserReadPlaybackPosition",
                            )
                        }
                        SpotifyScope::UserReadPlaybackState => {
                            _serde::Serializer::serialize_unit_variant(
                                __serializer,
                                "SpotifyScope",
                                4u32,
                                "UserReadPlaybackState",
                            )
                        }
                        SpotifyScope::UserModifyPlaybackState => {
                            _serde::Serializer::serialize_unit_variant(
                                __serializer,
                                "SpotifyScope",
                                5u32,
                                "UserModifyPlaybackState",
                            )
                        }
                        SpotifyScope::UserReadCurrentlyPlaying => {
                            _serde::Serializer::serialize_unit_variant(
                                __serializer,
                                "SpotifyScope",
                                6u32,
                                "UserReadCurrentlyPlaying",
                            )
                        }
                        SpotifyScope::AppRemoteControl => {
                            _serde::Serializer::serialize_unit_variant(
                                __serializer,
                                "SpotifyScope",
                                7u32,
                                "AppRemoteControl",
                            )
                        }
                        SpotifyScope::Streaming => _serde::Serializer::serialize_unit_variant(
                            __serializer,
                            "SpotifyScope",
                            8u32,
                            "Streaming",
                        ),
                        SpotifyScope::PlaylistModifyPublic => {
                            _serde::Serializer::serialize_unit_variant(
                                __serializer,
                                "SpotifyScope",
                                9u32,
                                "PlaylistModifyPublic",
                            )
                        }
                        SpotifyScope::PlaylistModifyPrivate => {
                            _serde::Serializer::serialize_unit_variant(
                                __serializer,
                                "SpotifyScope",
                                10u32,
                                "PlaylistModifyPrivate",
                            )
                        }
                        SpotifyScope::PlaylistReadPrivate => {
                            _serde::Serializer::serialize_unit_variant(
                                __serializer,
                                "SpotifyScope",
                                11u32,
                                "PlaylistReadPrivate",
                            )
                        }
                        SpotifyScope::PlaylistReadCollaborative => {
                            _serde::Serializer::serialize_unit_variant(
                                __serializer,
                                "SpotifyScope",
                                12u32,
                                "PlaylistReadCollaborative",
                            )
                        }
                        SpotifyScope::UserFollowModify => {
                            _serde::Serializer::serialize_unit_variant(
                                __serializer,
                                "SpotifyScope",
                                13u32,
                                "UserFollowModify",
                            )
                        }
                        SpotifyScope::UserFollowRead => _serde::Serializer::serialize_unit_variant(
                            __serializer,
                            "SpotifyScope",
                            14u32,
                            "UserFollowRead",
                        ),
                        SpotifyScope::UserLibraryModify => {
                            _serde::Serializer::serialize_unit_variant(
                                __serializer,
                                "SpotifyScope",
                                15u32,
                                "UserLibraryModify",
                            )
                        }
                        SpotifyScope::UserLibraryRead => {
                            _serde::Serializer::serialize_unit_variant(
                                __serializer,
                                "SpotifyScope",
                                16u32,
                                "UserLibraryRead",
                            )
                        }
                        SpotifyScope::UserReadEmail => _serde::Serializer::serialize_unit_variant(
                            __serializer,
                            "SpotifyScope",
                            17u32,
                            "UserReadEmail",
                        ),
                        SpotifyScope::UserReadPrivate => {
                            _serde::Serializer::serialize_unit_variant(
                                __serializer,
                                "SpotifyScope",
                                18u32,
                                "UserReadPrivate",
                            )
                        }
                    }
                }
            }
        };
        #[doc(hidden)]
        #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
        const _: () = {
            #[allow(unused_extern_crates, clippy::useless_attribute)]
            extern crate serde as _serde;
            #[automatically_derived]
            impl<'de> _serde::Deserialize<'de> for SpotifyScope {
                fn deserialize<__D>(
                    __deserializer: __D,
                ) -> _serde::__private::Result<Self, __D::Error>
                where
                    __D: _serde::Deserializer<'de>,
                {
                    #[allow(non_camel_case_types)]
                    enum __Field {
                        __field0,
                        __field1,
                        __field2,
                        __field3,
                        __field4,
                        __field5,
                        __field6,
                        __field7,
                        __field8,
                        __field9,
                        __field10,
                        __field11,
                        __field12,
                        __field13,
                        __field14,
                        __field15,
                        __field16,
                        __field17,
                        __field18,
                    }
                    struct __FieldVisitor;
                    impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                        type Value = __Field;
                        fn expecting(
                            &self,
                            __formatter: &mut _serde::__private::Formatter,
                        ) -> _serde::__private::fmt::Result {
                            _serde::__private::Formatter::write_str(
                                __formatter,
                                "variant identifier",
                            )
                        }
                        fn visit_u64<__E>(
                            self,
                            __value: u64,
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            match __value {
                                0u64 => _serde::__private::Ok(__Field::__field0),
                                1u64 => _serde::__private::Ok(__Field::__field1),
                                2u64 => _serde::__private::Ok(__Field::__field2),
                                3u64 => _serde::__private::Ok(__Field::__field3),
                                4u64 => _serde::__private::Ok(__Field::__field4),
                                5u64 => _serde::__private::Ok(__Field::__field5),
                                6u64 => _serde::__private::Ok(__Field::__field6),
                                7u64 => _serde::__private::Ok(__Field::__field7),
                                8u64 => _serde::__private::Ok(__Field::__field8),
                                9u64 => _serde::__private::Ok(__Field::__field9),
                                10u64 => _serde::__private::Ok(__Field::__field10),
                                11u64 => _serde::__private::Ok(__Field::__field11),
                                12u64 => _serde::__private::Ok(__Field::__field12),
                                13u64 => _serde::__private::Ok(__Field::__field13),
                                14u64 => _serde::__private::Ok(__Field::__field14),
                                15u64 => _serde::__private::Ok(__Field::__field15),
                                16u64 => _serde::__private::Ok(__Field::__field16),
                                17u64 => _serde::__private::Ok(__Field::__field17),
                                18u64 => _serde::__private::Ok(__Field::__field18),
                                _ => _serde::__private::Err(_serde::de::Error::invalid_value(
                                    _serde::de::Unexpected::Unsigned(__value),
                                    &"variant index 0 <= i < 19",
                                )),
                            }
                        }
                        fn visit_str<__E>(
                            self,
                            __value: &str,
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            match __value {
                                "UgcImageUpload" => _serde::__private::Ok(__Field::__field0),
                                "UserReadRecentlyPlayed" => {
                                    _serde::__private::Ok(__Field::__field1)
                                }
                                "UserTopRead" => _serde::__private::Ok(__Field::__field2),
                                "UserReadPlaybackPosition" => {
                                    _serde::__private::Ok(__Field::__field3)
                                }
                                "UserReadPlaybackState" => _serde::__private::Ok(__Field::__field4),
                                "UserModifyPlaybackState" => {
                                    _serde::__private::Ok(__Field::__field5)
                                }
                                "UserReadCurrentlyPlaying" => {
                                    _serde::__private::Ok(__Field::__field6)
                                }
                                "AppRemoteControl" => _serde::__private::Ok(__Field::__field7),
                                "Streaming" => _serde::__private::Ok(__Field::__field8),
                                "PlaylistModifyPublic" => _serde::__private::Ok(__Field::__field9),
                                "PlaylistModifyPrivate" => {
                                    _serde::__private::Ok(__Field::__field10)
                                }
                                "PlaylistReadPrivate" => _serde::__private::Ok(__Field::__field11),
                                "PlaylistReadCollaborative" => {
                                    _serde::__private::Ok(__Field::__field12)
                                }
                                "UserFollowModify" => _serde::__private::Ok(__Field::__field13),
                                "UserFollowRead" => _serde::__private::Ok(__Field::__field14),
                                "UserLibraryModify" => _serde::__private::Ok(__Field::__field15),
                                "UserLibraryRead" => _serde::__private::Ok(__Field::__field16),
                                "UserReadEmail" => _serde::__private::Ok(__Field::__field17),
                                "UserReadPrivate" => _serde::__private::Ok(__Field::__field18),
                                _ => _serde::__private::Err(_serde::de::Error::unknown_variant(
                                    __value, VARIANTS,
                                )),
                            }
                        }
                        fn visit_bytes<__E>(
                            self,
                            __value: &[u8],
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            match __value {
                                b"UgcImageUpload" => _serde::__private::Ok(__Field::__field0),
                                b"UserReadRecentlyPlayed" => {
                                    _serde::__private::Ok(__Field::__field1)
                                }
                                b"UserTopRead" => _serde::__private::Ok(__Field::__field2),
                                b"UserReadPlaybackPosition" => {
                                    _serde::__private::Ok(__Field::__field3)
                                }
                                b"UserReadPlaybackState" => {
                                    _serde::__private::Ok(__Field::__field4)
                                }
                                b"UserModifyPlaybackState" => {
                                    _serde::__private::Ok(__Field::__field5)
                                }
                                b"UserReadCurrentlyPlaying" => {
                                    _serde::__private::Ok(__Field::__field6)
                                }
                                b"AppRemoteControl" => _serde::__private::Ok(__Field::__field7),
                                b"Streaming" => _serde::__private::Ok(__Field::__field8),
                                b"PlaylistModifyPublic" => _serde::__private::Ok(__Field::__field9),
                                b"PlaylistModifyPrivate" => {
                                    _serde::__private::Ok(__Field::__field10)
                                }
                                b"PlaylistReadPrivate" => _serde::__private::Ok(__Field::__field11),
                                b"PlaylistReadCollaborative" => {
                                    _serde::__private::Ok(__Field::__field12)
                                }
                                b"UserFollowModify" => _serde::__private::Ok(__Field::__field13),
                                b"UserFollowRead" => _serde::__private::Ok(__Field::__field14),
                                b"UserLibraryModify" => _serde::__private::Ok(__Field::__field15),
                                b"UserLibraryRead" => _serde::__private::Ok(__Field::__field16),
                                b"UserReadEmail" => _serde::__private::Ok(__Field::__field17),
                                b"UserReadPrivate" => _serde::__private::Ok(__Field::__field18),
                                _ => {
                                    let __value = &_serde::__private::from_utf8_lossy(__value);
                                    _serde::__private::Err(_serde::de::Error::unknown_variant(
                                        __value, VARIANTS,
                                    ))
                                }
                            }
                        }
                    }
                    impl<'de> _serde::Deserialize<'de> for __Field {
                        #[inline]
                        fn deserialize<__D>(
                            __deserializer: __D,
                        ) -> _serde::__private::Result<Self, __D::Error>
                        where
                            __D: _serde::Deserializer<'de>,
                        {
                            _serde::Deserializer::deserialize_identifier(
                                __deserializer,
                                __FieldVisitor,
                            )
                        }
                    }
                    struct __Visitor<'de> {
                        marker: _serde::__private::PhantomData<SpotifyScope>,
                        lifetime: _serde::__private::PhantomData<&'de ()>,
                    }
                    impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                        type Value = SpotifyScope;
                        fn expecting(
                            &self,
                            __formatter: &mut _serde::__private::Formatter,
                        ) -> _serde::__private::fmt::Result {
                            _serde::__private::Formatter::write_str(
                                __formatter,
                                "enum SpotifyScope",
                            )
                        }
                        fn visit_enum<__A>(
                            self,
                            __data: __A,
                        ) -> _serde::__private::Result<Self::Value, __A::Error>
                        where
                            __A: _serde::de::EnumAccess<'de>,
                        {
                            match match _serde::de::EnumAccess::variant(__data) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            } {
                                (__Field::__field0, __variant) => {
                                    match _serde::de::VariantAccess::unit_variant(__variant) {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    };
                                    _serde::__private::Ok(SpotifyScope::UgcImageUpload)
                                }
                                (__Field::__field1, __variant) => {
                                    match _serde::de::VariantAccess::unit_variant(__variant) {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    };
                                    _serde::__private::Ok(SpotifyScope::UserReadRecentlyPlayed)
                                }
                                (__Field::__field2, __variant) => {
                                    match _serde::de::VariantAccess::unit_variant(__variant) {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    };
                                    _serde::__private::Ok(SpotifyScope::UserTopRead)
                                }
                                (__Field::__field3, __variant) => {
                                    match _serde::de::VariantAccess::unit_variant(__variant) {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    };
                                    _serde::__private::Ok(SpotifyScope::UserReadPlaybackPosition)
                                }
                                (__Field::__field4, __variant) => {
                                    match _serde::de::VariantAccess::unit_variant(__variant) {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    };
                                    _serde::__private::Ok(SpotifyScope::UserReadPlaybackState)
                                }
                                (__Field::__field5, __variant) => {
                                    match _serde::de::VariantAccess::unit_variant(__variant) {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    };
                                    _serde::__private::Ok(SpotifyScope::UserModifyPlaybackState)
                                }
                                (__Field::__field6, __variant) => {
                                    match _serde::de::VariantAccess::unit_variant(__variant) {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    };
                                    _serde::__private::Ok(SpotifyScope::UserReadCurrentlyPlaying)
                                }
                                (__Field::__field7, __variant) => {
                                    match _serde::de::VariantAccess::unit_variant(__variant) {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    };
                                    _serde::__private::Ok(SpotifyScope::AppRemoteControl)
                                }
                                (__Field::__field8, __variant) => {
                                    match _serde::de::VariantAccess::unit_variant(__variant) {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    };
                                    _serde::__private::Ok(SpotifyScope::Streaming)
                                }
                                (__Field::__field9, __variant) => {
                                    match _serde::de::VariantAccess::unit_variant(__variant) {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    };
                                    _serde::__private::Ok(SpotifyScope::PlaylistModifyPublic)
                                }
                                (__Field::__field10, __variant) => {
                                    match _serde::de::VariantAccess::unit_variant(__variant) {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    };
                                    _serde::__private::Ok(SpotifyScope::PlaylistModifyPrivate)
                                }
                                (__Field::__field11, __variant) => {
                                    match _serde::de::VariantAccess::unit_variant(__variant) {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    };
                                    _serde::__private::Ok(SpotifyScope::PlaylistReadPrivate)
                                }
                                (__Field::__field12, __variant) => {
                                    match _serde::de::VariantAccess::unit_variant(__variant) {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    };
                                    _serde::__private::Ok(SpotifyScope::PlaylistReadCollaborative)
                                }
                                (__Field::__field13, __variant) => {
                                    match _serde::de::VariantAccess::unit_variant(__variant) {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    };
                                    _serde::__private::Ok(SpotifyScope::UserFollowModify)
                                }
                                (__Field::__field14, __variant) => {
                                    match _serde::de::VariantAccess::unit_variant(__variant) {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    };
                                    _serde::__private::Ok(SpotifyScope::UserFollowRead)
                                }
                                (__Field::__field15, __variant) => {
                                    match _serde::de::VariantAccess::unit_variant(__variant) {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    };
                                    _serde::__private::Ok(SpotifyScope::UserLibraryModify)
                                }
                                (__Field::__field16, __variant) => {
                                    match _serde::de::VariantAccess::unit_variant(__variant) {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    };
                                    _serde::__private::Ok(SpotifyScope::UserLibraryRead)
                                }
                                (__Field::__field17, __variant) => {
                                    match _serde::de::VariantAccess::unit_variant(__variant) {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    };
                                    _serde::__private::Ok(SpotifyScope::UserReadEmail)
                                }
                                (__Field::__field18, __variant) => {
                                    match _serde::de::VariantAccess::unit_variant(__variant) {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    };
                                    _serde::__private::Ok(SpotifyScope::UserReadPrivate)
                                }
                            }
                        }
                    }
                    const VARIANTS: &'static [&'static str] = &[
                        "UgcImageUpload",
                        "UserReadRecentlyPlayed",
                        "UserTopRead",
                        "UserReadPlaybackPosition",
                        "UserReadPlaybackState",
                        "UserModifyPlaybackState",
                        "UserReadCurrentlyPlaying",
                        "AppRemoteControl",
                        "Streaming",
                        "PlaylistModifyPublic",
                        "PlaylistModifyPrivate",
                        "PlaylistReadPrivate",
                        "PlaylistReadCollaborative",
                        "UserFollowModify",
                        "UserFollowRead",
                        "UserLibraryModify",
                        "UserLibraryRead",
                        "UserReadEmail",
                        "UserReadPrivate",
                    ];
                    _serde::Deserializer::deserialize_enum(
                        __deserializer,
                        "SpotifyScope",
                        VARIANTS,
                        __Visitor {
                            marker: _serde::__private::PhantomData::<SpotifyScope>,
                            lifetime: _serde::__private::PhantomData,
                        },
                    )
                }
            }
        };
        impl super::ProviderScopes for SpotifyScope {
            fn to_str(&self) -> &'static str {
                match self {
                    Self::UgcImageUpload => "ugc-image-upload",
                    Self::UserReadRecentlyPlayed => "user-read-recently-played",
                    Self::UserTopRead => "user-top-read",
                    Self::UserReadPlaybackPosition => "user-read-playback-position",
                    Self::UserReadPlaybackState => "user-read-playback-state",
                    Self::UserModifyPlaybackState => "user-modify-playback-state",
                    Self::UserReadCurrentlyPlaying => "user-read-currently-playing",
                    Self::AppRemoteControl => "app-remote-control",
                    Self::Streaming => "streaming",
                    Self::PlaylistModifyPublic => "playlist-modify-public",
                    Self::PlaylistModifyPrivate => "playlist-modify-private",
                    Self::PlaylistReadPrivate => "playlist-read-private",
                    Self::PlaylistReadCollaborative => "playlist-read-collaborative",
                    Self::UserFollowModify => "user-follow-modify",
                    Self::UserFollowRead => "user-follow-read",
                    Self::UserLibraryModify => "user-library-modify",
                    Self::UserLibraryRead => "user-library-read",
                    Self::UserReadEmail => "user-read-email",
                    Self::UserReadPrivate => "user-read-private",
                }
            }
        }
    }
    pub trait Provider {
        const AUTH_URL: &'static str;
        const TOKEN_URL: &'static str;
        type Scopes: ProviderScopes;
    }
    pub trait ProviderScopes {
        fn to_str(&self) -> &'static str;
    }
    pub struct ScopeCollection<T>(pub Vec<T>);
    #[automatically_derived]
    #[allow(unused_qualifications)]
    impl<T: ::core::fmt::Debug> ::core::fmt::Debug for ScopeCollection<T> {
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            match *self {
                ScopeCollection(ref __self_0_0) => {
                    let debug_trait_builder =
                        &mut ::core::fmt::Formatter::debug_tuple(f, "ScopeCollection");
                    let _ = ::core::fmt::DebugTuple::field(debug_trait_builder, &&(*__self_0_0));
                    ::core::fmt::DebugTuple::finish(debug_trait_builder)
                }
            }
        }
    }
    #[automatically_derived]
    #[allow(unused_qualifications)]
    impl<T: ::core::clone::Clone> ::core::clone::Clone for ScopeCollection<T> {
        #[inline]
        fn clone(&self) -> ScopeCollection<T> {
            match *self {
                ScopeCollection(ref __self_0_0) => {
                    ScopeCollection(::core::clone::Clone::clone(&(*__self_0_0)))
                }
            }
        }
    }
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        #[allow(unused_extern_crates, clippy::useless_attribute)]
        extern crate serde as _serde;
        #[automatically_derived]
        impl<T> _serde::Serialize for ScopeCollection<T>
        where
            T: _serde::Serialize,
        {
            fn serialize<__S>(
                &self,
                __serializer: __S,
            ) -> _serde::__private::Result<__S::Ok, __S::Error>
            where
                __S: _serde::Serializer,
            {
                _serde::Serializer::serialize_newtype_struct(
                    __serializer,
                    "ScopeCollection",
                    &self.0,
                )
            }
        }
    };
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        #[allow(unused_extern_crates, clippy::useless_attribute)]
        extern crate serde as _serde;
        #[automatically_derived]
        impl<'de, T> _serde::Deserialize<'de> for ScopeCollection<T>
        where
            T: _serde::Deserialize<'de>,
        {
            fn deserialize<__D>(__deserializer: __D) -> _serde::__private::Result<Self, __D::Error>
            where
                __D: _serde::Deserializer<'de>,
            {
                struct __Visitor<'de, T>
                where
                    T: _serde::Deserialize<'de>,
                {
                    marker: _serde::__private::PhantomData<ScopeCollection<T>>,
                    lifetime: _serde::__private::PhantomData<&'de ()>,
                }
                impl<'de, T> _serde::de::Visitor<'de> for __Visitor<'de, T>
                where
                    T: _serde::Deserialize<'de>,
                {
                    type Value = ScopeCollection<T>;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "tuple struct ScopeCollection",
                        )
                    }
                    #[inline]
                    fn visit_newtype_struct<__E>(
                        self,
                        __e: __E,
                    ) -> _serde::__private::Result<Self::Value, __E::Error>
                    where
                        __E: _serde::Deserializer<'de>,
                    {
                        let __field0: Vec<T> =
                            match <Vec<T> as _serde::Deserialize>::deserialize(__e) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            };
                        _serde::__private::Ok(ScopeCollection(__field0))
                    }
                    #[inline]
                    fn visit_seq<__A>(
                        self,
                        mut __seq: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::SeqAccess<'de>,
                    {
                        let __field0 =
                            match match _serde::de::SeqAccess::next_element::<Vec<T>>(&mut __seq) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            } {
                                _serde::__private::Some(__value) => __value,
                                _serde::__private::None => {
                                    return _serde::__private::Err(
                                        _serde::de::Error::invalid_length(
                                            0usize,
                                            &"tuple struct ScopeCollection with 1 element",
                                        ),
                                    );
                                }
                            };
                        _serde::__private::Ok(ScopeCollection(__field0))
                    }
                }
                _serde::Deserializer::deserialize_newtype_struct(
                    __deserializer,
                    "ScopeCollection",
                    __Visitor {
                        marker: _serde::__private::PhantomData::<ScopeCollection<T>>,
                        lifetime: _serde::__private::PhantomData,
                    },
                )
            }
        }
    };
    impl ScalarType for ScopeCollection<SpotifyScope> {
        fn parse(value: Value) -> InputValueResult<Self> {
            ::std::result::Result::Ok(from_value(value)?)
        }
        fn to_value(&self) -> Value {
            to_value(self).unwrap_or_else(|_| Value::Null)
        }
    }
    #[allow(clippy::all, clippy::pedantic)]
    impl async_graphql::Type for ScopeCollection<SpotifyScope> {
        fn type_name() -> ::std::borrow::Cow<'static, ::std::primitive::str> {
            ::std::borrow::Cow::Borrowed("SpotifyScopes")
        }
        fn create_type_info(
            registry: &mut async_graphql::registry::Registry,
        ) -> ::std::string::String {
            registry.create_type::<ScopeCollection<SpotifyScope>, _>(|_| {
                async_graphql::registry::MetaType::Scalar {
                    name: ::std::borrow::ToOwned::to_owned("SpotifyScopes"),
                    description: ::std::option::Option::None,
                    is_valid: |value| {
                        <ScopeCollection<SpotifyScope> as async_graphql::ScalarType>::is_valid(
                            value,
                        )
                    },
                    visible: ::std::option::Option::None,
                }
            })
        }
    }
    #[allow(clippy::all, clippy::pedantic)]
    impl async_graphql::InputType for ScopeCollection<SpotifyScope> {
        fn parse(
            value: ::std::option::Option<async_graphql::Value>,
        ) -> async_graphql::InputValueResult<Self> {
            <ScopeCollection<SpotifyScope> as async_graphql::ScalarType>::parse(
                value.unwrap_or_default(),
            )
        }
        fn to_value(&self) -> async_graphql::Value {
            <ScopeCollection<SpotifyScope> as async_graphql::ScalarType>::to_value(self)
        }
    }
    #[allow(clippy::all, clippy::pedantic)]
    impl async_graphql::OutputType for ScopeCollection<SpotifyScope> {
        #[allow(
            clippy::let_unit_value,
            clippy::type_complexity,
            clippy::type_repetition_in_bounds,
            clippy::used_underscore_binding
        )]
        fn resolve<'life0, 'life1, 'life2, 'life3, 'async_trait>(
            &'life0 self,
            __arg1: &'life1 async_graphql::ContextSelectionSet<'life2>,
            _field: &'life3 async_graphql::Positioned<async_graphql::parser::types::Field>,
        ) -> ::core::pin::Pin<
            Box<
                dyn ::core::future::Future<
                        Output = async_graphql::ServerResult<async_graphql::Value>,
                    > + ::core::marker::Send
                    + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            'life2: 'async_trait,
            'life3: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(async move {
                if let ::core::option::Option::Some(__ret) = ::core::option::Option::None::<
                    async_graphql::ServerResult<async_graphql::Value>,
                > {
                    return __ret;
                }
                let __self = self;
                let _ = __arg1;
                let _field = _field;
                let __ret: async_graphql::ServerResult<async_graphql::Value> =
                    { ::std::result::Result::Ok(async_graphql::ScalarType::to_value(__self)) };
                #[allow(unreachable_code)]
                __ret
            })
        }
    }
    pub enum Scopes {
        Spotify(ScopeCollection<SpotifyScope>),
    }
    const _: fn() = || {
        trait AmbiguousIfMoreThanOne<A> {
            fn some_item() {}
        }
        {
            #[allow(dead_code)]
            struct Token;
            impl<T: ?Sized + async_graphql::ObjectType> AmbiguousIfMoreThanOne<Token> for T {}
        }
        let _ = <ScopeCollection<SpotifyScope> as AmbiguousIfMoreThanOne<_>>::some_item;
    };
    #[allow(clippy::all, clippy::pedantic)]
    impl ::std::convert::From<ScopeCollection<SpotifyScope>> for Scopes {
        fn from(obj: ScopeCollection<SpotifyScope>) -> Self {
            Scopes::Spotify(obj)
        }
    }
    #[allow(clippy::all, clippy::pedantic)]
    impl async_graphql::Type for Scopes {
        fn type_name() -> ::std::borrow::Cow<'static, ::std::primitive::str> {
            ::std::borrow::Cow::Borrowed("Scopes")
        }
        fn introspection_type_name(&self) -> ::std::borrow::Cow<'static, ::std::primitive::str> {
            match self {
                Scopes::Spotify(obj) => {
                    <ScopeCollection<SpotifyScope> as async_graphql::Type>::type_name()
                }
            }
        }
        fn create_type_info(
            registry: &mut async_graphql::registry::Registry,
        ) -> ::std::string::String {
            registry.create_type::<Self, _>(|registry| {
                <ScopeCollection<SpotifyScope> as async_graphql::Type>::create_type_info(registry);
                async_graphql::registry::MetaType::Union {
                    name: ::std::borrow::ToOwned::to_owned("Scopes"),
                    description: ::std::option::Option::None,
                    possible_types: {
                        let mut possible_types = async_graphql::indexmap::IndexSet::new();
                        possible_types.insert(
                            <ScopeCollection<SpotifyScope> as async_graphql::Type>::type_name()
                                .into_owned(),
                        );
                        possible_types
                    },
                    visible: ::std::option::Option::None,
                }
            })
        }
    }
    #[allow(clippy::all, clippy::pedantic)]
    impl async_graphql::resolver_utils::ContainerType for Scopes {
        #[allow(
            clippy::let_unit_value,
            clippy::type_complexity,
            clippy::type_repetition_in_bounds,
            clippy::used_underscore_binding
        )]
        fn resolve_field<'life0, 'life1, 'life2, 'async_trait>(
            &'life0 self,
            ctx: &'life1 async_graphql::Context<'life2>,
        ) -> ::core::pin::Pin<
            Box<
                dyn ::core::future::Future<
                        Output = async_graphql::ServerResult<
                            ::std::option::Option<async_graphql::Value>,
                        >,
                    > + ::core::marker::Send
                    + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            'life2: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(async move {
                if let ::core::option::Option::Some(__ret) = ::core::option::Option::None::<
                    async_graphql::ServerResult<::std::option::Option<async_graphql::Value>>,
                > {
                    return __ret;
                }
                let __self = self;
                let ctx = ctx;
                let __ret: async_graphql::ServerResult<
                    ::std::option::Option<async_graphql::Value>,
                > = { ::std::result::Result::Ok(::std::option::Option::None) };
                #[allow(unreachable_code)]
                __ret
            })
        }
        fn collect_all_fields<'__life>(
            &'__life self,
            ctx: &async_graphql::ContextSelectionSet<'__life>,
            fields: &mut async_graphql::resolver_utils::Fields<'__life>,
        ) -> async_graphql::ServerResult<()> {
            match self {
                Scopes::Spotify(obj) => obj.collect_all_fields(ctx, fields),
            }
        }
    }
    #[allow(clippy::all, clippy::pedantic)]
    impl async_graphql::OutputType for Scopes {
        #[allow(
            clippy::let_unit_value,
            clippy::type_complexity,
            clippy::type_repetition_in_bounds,
            clippy::used_underscore_binding
        )]
        fn resolve<'life0, 'life1, 'life2, 'life3, 'async_trait>(
            &'life0 self,
            ctx: &'life1 async_graphql::ContextSelectionSet<'life2>,
            _field: &'life3 async_graphql::Positioned<async_graphql::parser::types::Field>,
        ) -> ::core::pin::Pin<
            Box<
                dyn ::core::future::Future<
                        Output = async_graphql::ServerResult<async_graphql::Value>,
                    > + ::core::marker::Send
                    + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            'life2: 'async_trait,
            'life3: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(async move {
                if let ::core::option::Option::Some(__ret) = ::core::option::Option::None::<
                    async_graphql::ServerResult<async_graphql::Value>,
                > {
                    return __ret;
                }
                let __self = self;
                let ctx = ctx;
                let _field = _field;
                let __ret: async_graphql::ServerResult<async_graphql::Value> =
                    { async_graphql::resolver_utils::resolve_container(ctx, __self).await };
                #[allow(unreachable_code)]
                __ret
            })
        }
    }
    impl async_graphql::UnionType for Scopes {}
    #[automatically_derived]
    #[allow(unused_qualifications)]
    impl ::core::fmt::Debug for Scopes {
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            match (&*self,) {
                (&Scopes::Spotify(ref __self_0),) => {
                    let debug_trait_builder =
                        &mut ::core::fmt::Formatter::debug_tuple(f, "Spotify");
                    let _ = ::core::fmt::DebugTuple::field(debug_trait_builder, &&(*__self_0));
                    ::core::fmt::DebugTuple::finish(debug_trait_builder)
                }
            }
        }
    }
    #[automatically_derived]
    #[allow(unused_qualifications)]
    impl ::core::clone::Clone for Scopes {
        #[inline]
        fn clone(&self) -> Scopes {
            match (&*self,) {
                (&Scopes::Spotify(ref __self_0),) => {
                    Scopes::Spotify(::core::clone::Clone::clone(&(*__self_0)))
                }
            }
        }
    }
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        #[allow(unused_extern_crates, clippy::useless_attribute)]
        extern crate serde as _serde;
        #[automatically_derived]
        impl _serde::Serialize for Scopes {
            fn serialize<__S>(
                &self,
                __serializer: __S,
            ) -> _serde::__private::Result<__S::Ok, __S::Error>
            where
                __S: _serde::Serializer,
            {
                match *self {
                    Scopes::Spotify(ref __field0) => _serde::Serializer::serialize_newtype_variant(
                        __serializer,
                        "Scopes",
                        0u32,
                        "Spotify",
                        __field0,
                    ),
                }
            }
        }
    };
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        #[allow(unused_extern_crates, clippy::useless_attribute)]
        extern crate serde as _serde;
        #[automatically_derived]
        impl<'de> _serde::Deserialize<'de> for Scopes {
            fn deserialize<__D>(__deserializer: __D) -> _serde::__private::Result<Self, __D::Error>
            where
                __D: _serde::Deserializer<'de>,
            {
                #[allow(non_camel_case_types)]
                enum __Field {
                    __field0,
                }
                struct __FieldVisitor;
                impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                    type Value = __Field;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(__formatter, "variant identifier")
                    }
                    fn visit_u64<__E>(
                        self,
                        __value: u64,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            0u64 => _serde::__private::Ok(__Field::__field0),
                            _ => _serde::__private::Err(_serde::de::Error::invalid_value(
                                _serde::de::Unexpected::Unsigned(__value),
                                &"variant index 0 <= i < 1",
                            )),
                        }
                    }
                    fn visit_str<__E>(
                        self,
                        __value: &str,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            "Spotify" => _serde::__private::Ok(__Field::__field0),
                            _ => _serde::__private::Err(_serde::de::Error::unknown_variant(
                                __value, VARIANTS,
                            )),
                        }
                    }
                    fn visit_bytes<__E>(
                        self,
                        __value: &[u8],
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            b"Spotify" => _serde::__private::Ok(__Field::__field0),
                            _ => {
                                let __value = &_serde::__private::from_utf8_lossy(__value);
                                _serde::__private::Err(_serde::de::Error::unknown_variant(
                                    __value, VARIANTS,
                                ))
                            }
                        }
                    }
                }
                impl<'de> _serde::Deserialize<'de> for __Field {
                    #[inline]
                    fn deserialize<__D>(
                        __deserializer: __D,
                    ) -> _serde::__private::Result<Self, __D::Error>
                    where
                        __D: _serde::Deserializer<'de>,
                    {
                        _serde::Deserializer::deserialize_identifier(__deserializer, __FieldVisitor)
                    }
                }
                struct __Visitor<'de> {
                    marker: _serde::__private::PhantomData<Scopes>,
                    lifetime: _serde::__private::PhantomData<&'de ()>,
                }
                impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                    type Value = Scopes;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(__formatter, "enum Scopes")
                    }
                    fn visit_enum<__A>(
                        self,
                        __data: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::EnumAccess<'de>,
                    {
                        match match _serde::de::EnumAccess::variant(__data) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            (__Field::__field0, __variant) => _serde::__private::Result::map(
                                _serde::de::VariantAccess::newtype_variant::<
                                    ScopeCollection<SpotifyScope>,
                                >(__variant),
                                Scopes::Spotify,
                            ),
                        }
                    }
                }
                const VARIANTS: &'static [&'static str] = &["Spotify"];
                _serde::Deserializer::deserialize_enum(
                    __deserializer,
                    "Scopes",
                    VARIANTS,
                    __Visitor {
                        marker: _serde::__private::PhantomData::<Scopes>,
                        lifetime: _serde::__private::PhantomData,
                    },
                )
            }
        }
    };
}
mod token {
    use std::{marker::PhantomData, time::Duration};
    use chrono::Utc;
    use oauth2::{
        basic::{
            BasicErrorResponse, BasicRevocationErrorResponse, BasicTokenIntrospectionResponse,
            BasicTokenType,
        },
        AccessToken, AuthUrl, ClientId, ClientSecret, RedirectUrl, RefreshToken, Scope,
        StandardRevocableToken, TokenResponse, TokenUrl,
    };
    use serde::{Deserialize, Serialize};
    use crate::provider::{self, Scopes};
    pub struct Claims {
        pub name: String,
        pub scopes: Scopes,
        #[serde(rename = "sub")]
        pub username: String,
        #[serde(rename = "exp", with = "chrono::serde::ts_seconds")]
        pub expires: chrono::DateTime<Utc>,
    }
    #[automatically_derived]
    #[allow(unused_qualifications)]
    impl ::core::fmt::Debug for Claims {
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            match *self {
                Claims {
                    name: ref __self_0_0,
                    scopes: ref __self_0_1,
                    username: ref __self_0_2,
                    expires: ref __self_0_3,
                } => {
                    let debug_trait_builder =
                        &mut ::core::fmt::Formatter::debug_struct(f, "Claims");
                    let _ = ::core::fmt::DebugStruct::field(
                        debug_trait_builder,
                        "name",
                        &&(*__self_0_0),
                    );
                    let _ = ::core::fmt::DebugStruct::field(
                        debug_trait_builder,
                        "scopes",
                        &&(*__self_0_1),
                    );
                    let _ = ::core::fmt::DebugStruct::field(
                        debug_trait_builder,
                        "username",
                        &&(*__self_0_2),
                    );
                    let _ = ::core::fmt::DebugStruct::field(
                        debug_trait_builder,
                        "expires",
                        &&(*__self_0_3),
                    );
                    ::core::fmt::DebugStruct::finish(debug_trait_builder)
                }
            }
        }
    }
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        #[allow(unused_extern_crates, clippy::useless_attribute)]
        extern crate serde as _serde;
        #[automatically_derived]
        impl _serde::Serialize for Claims {
            fn serialize<__S>(
                &self,
                __serializer: __S,
            ) -> _serde::__private::Result<__S::Ok, __S::Error>
            where
                __S: _serde::Serializer,
            {
                let mut __serde_state = match _serde::Serializer::serialize_struct(
                    __serializer,
                    "Claims",
                    false as usize + 1 + 1 + 1 + 1,
                ) {
                    _serde::__private::Ok(__val) => __val,
                    _serde::__private::Err(__err) => {
                        return _serde::__private::Err(__err);
                    }
                };
                match _serde::ser::SerializeStruct::serialize_field(
                    &mut __serde_state,
                    "name",
                    &self.name,
                ) {
                    _serde::__private::Ok(__val) => __val,
                    _serde::__private::Err(__err) => {
                        return _serde::__private::Err(__err);
                    }
                };
                match _serde::ser::SerializeStruct::serialize_field(
                    &mut __serde_state,
                    "scopes",
                    &self.scopes,
                ) {
                    _serde::__private::Ok(__val) => __val,
                    _serde::__private::Err(__err) => {
                        return _serde::__private::Err(__err);
                    }
                };
                match _serde::ser::SerializeStruct::serialize_field(
                    &mut __serde_state,
                    "sub",
                    &self.username,
                ) {
                    _serde::__private::Ok(__val) => __val,
                    _serde::__private::Err(__err) => {
                        return _serde::__private::Err(__err);
                    }
                };
                match _serde::ser::SerializeStruct::serialize_field(&mut __serde_state, "exp", {
                    struct __SerializeWith<'__a> {
                        values: (&'__a chrono::DateTime<Utc>,),
                        phantom: _serde::__private::PhantomData<Claims>,
                    }
                    impl<'__a> _serde::Serialize for __SerializeWith<'__a> {
                        fn serialize<__S>(
                            &self,
                            __s: __S,
                        ) -> _serde::__private::Result<__S::Ok, __S::Error>
                        where
                            __S: _serde::Serializer,
                        {
                            chrono::serde::ts_seconds::serialize(self.values.0, __s)
                        }
                    }
                    &__SerializeWith {
                        values: (&self.expires,),
                        phantom: _serde::__private::PhantomData::<Claims>,
                    }
                }) {
                    _serde::__private::Ok(__val) => __val,
                    _serde::__private::Err(__err) => {
                        return _serde::__private::Err(__err);
                    }
                };
                _serde::ser::SerializeStruct::end(__serde_state)
            }
        }
    };
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        #[allow(unused_extern_crates, clippy::useless_attribute)]
        extern crate serde as _serde;
        #[automatically_derived]
        impl<'de> _serde::Deserialize<'de> for Claims {
            fn deserialize<__D>(__deserializer: __D) -> _serde::__private::Result<Self, __D::Error>
            where
                __D: _serde::Deserializer<'de>,
            {
                #[allow(non_camel_case_types)]
                enum __Field {
                    __field0,
                    __field1,
                    __field2,
                    __field3,
                    __ignore,
                }
                struct __FieldVisitor;
                impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                    type Value = __Field;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(__formatter, "field identifier")
                    }
                    fn visit_u64<__E>(
                        self,
                        __value: u64,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            0u64 => _serde::__private::Ok(__Field::__field0),
                            1u64 => _serde::__private::Ok(__Field::__field1),
                            2u64 => _serde::__private::Ok(__Field::__field2),
                            3u64 => _serde::__private::Ok(__Field::__field3),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_str<__E>(
                        self,
                        __value: &str,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            "name" => _serde::__private::Ok(__Field::__field0),
                            "scopes" => _serde::__private::Ok(__Field::__field1),
                            "sub" => _serde::__private::Ok(__Field::__field2),
                            "exp" => _serde::__private::Ok(__Field::__field3),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_bytes<__E>(
                        self,
                        __value: &[u8],
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            b"name" => _serde::__private::Ok(__Field::__field0),
                            b"scopes" => _serde::__private::Ok(__Field::__field1),
                            b"sub" => _serde::__private::Ok(__Field::__field2),
                            b"exp" => _serde::__private::Ok(__Field::__field3),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                }
                impl<'de> _serde::Deserialize<'de> for __Field {
                    #[inline]
                    fn deserialize<__D>(
                        __deserializer: __D,
                    ) -> _serde::__private::Result<Self, __D::Error>
                    where
                        __D: _serde::Deserializer<'de>,
                    {
                        _serde::Deserializer::deserialize_identifier(__deserializer, __FieldVisitor)
                    }
                }
                struct __Visitor<'de> {
                    marker: _serde::__private::PhantomData<Claims>,
                    lifetime: _serde::__private::PhantomData<&'de ()>,
                }
                impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                    type Value = Claims;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(__formatter, "struct Claims")
                    }
                    #[inline]
                    fn visit_seq<__A>(
                        self,
                        mut __seq: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::SeqAccess<'de>,
                    {
                        let __field0 =
                            match match _serde::de::SeqAccess::next_element::<String>(&mut __seq) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            } {
                                _serde::__private::Some(__value) => __value,
                                _serde::__private::None => {
                                    return _serde::__private::Err(
                                        _serde::de::Error::invalid_length(
                                            0usize,
                                            &"struct Claims with 4 elements",
                                        ),
                                    );
                                }
                            };
                        let __field1 =
                            match match _serde::de::SeqAccess::next_element::<Scopes>(&mut __seq) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            } {
                                _serde::__private::Some(__value) => __value,
                                _serde::__private::None => {
                                    return _serde::__private::Err(
                                        _serde::de::Error::invalid_length(
                                            1usize,
                                            &"struct Claims with 4 elements",
                                        ),
                                    );
                                }
                            };
                        let __field2 =
                            match match _serde::de::SeqAccess::next_element::<String>(&mut __seq) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            } {
                                _serde::__private::Some(__value) => __value,
                                _serde::__private::None => {
                                    return _serde::__private::Err(
                                        _serde::de::Error::invalid_length(
                                            2usize,
                                            &"struct Claims with 4 elements",
                                        ),
                                    );
                                }
                            };
                        let __field3 = match {
                            struct __DeserializeWith<'de> {
                                value: chrono::DateTime<Utc>,
                                phantom: _serde::__private::PhantomData<Claims>,
                                lifetime: _serde::__private::PhantomData<&'de ()>,
                            }
                            impl<'de> _serde::Deserialize<'de> for __DeserializeWith<'de> {
                                fn deserialize<__D>(
                                    __deserializer: __D,
                                ) -> _serde::__private::Result<Self, __D::Error>
                                where
                                    __D: _serde::Deserializer<'de>,
                                {
                                    _serde::__private::Ok(__DeserializeWith {
                                        value: match chrono::serde::ts_seconds::deserialize(
                                            __deserializer,
                                        ) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                        phantom: _serde::__private::PhantomData,
                                        lifetime: _serde::__private::PhantomData,
                                    })
                                }
                            }
                            _serde::__private::Option::map(
                                match _serde::de::SeqAccess::next_element::<__DeserializeWith<'de>>(
                                    &mut __seq,
                                ) {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                },
                                |__wrap| __wrap.value,
                            )
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(_serde::de::Error::invalid_length(
                                    3usize,
                                    &"struct Claims with 4 elements",
                                ));
                            }
                        };
                        _serde::__private::Ok(Claims {
                            name: __field0,
                            scopes: __field1,
                            username: __field2,
                            expires: __field3,
                        })
                    }
                    #[inline]
                    fn visit_map<__A>(
                        self,
                        mut __map: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::MapAccess<'de>,
                    {
                        let mut __field0: _serde::__private::Option<String> =
                            _serde::__private::None;
                        let mut __field1: _serde::__private::Option<Scopes> =
                            _serde::__private::None;
                        let mut __field2: _serde::__private::Option<String> =
                            _serde::__private::None;
                        let mut __field3: _serde::__private::Option<chrono::DateTime<Utc>> =
                            _serde::__private::None;
                        while let _serde::__private::Some(__key) =
                            match _serde::de::MapAccess::next_key::<__Field>(&mut __map) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            }
                        {
                            match __key {
                                __Field::__field0 => {
                                    if _serde::__private::Option::is_some(&__field0) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field(
                                                "name",
                                            ),
                                        );
                                    }
                                    __field0 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<String>(
                                            &mut __map,
                                        ) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                __Field::__field1 => {
                                    if _serde::__private::Option::is_some(&__field1) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field(
                                                "scopes",
                                            ),
                                        );
                                    }
                                    __field1 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<Scopes>(
                                            &mut __map,
                                        ) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                __Field::__field2 => {
                                    if _serde::__private::Option::is_some(&__field2) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field(
                                                "sub",
                                            ),
                                        );
                                    }
                                    __field2 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<String>(
                                            &mut __map,
                                        ) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                __Field::__field3 => {
                                    if _serde::__private::Option::is_some(&__field3) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field(
                                                "exp",
                                            ),
                                        );
                                    }
                                    __field3 = _serde::__private::Some({
                                        struct __DeserializeWith<'de> {
                                            value: chrono::DateTime<Utc>,
                                            phantom: _serde::__private::PhantomData<Claims>,
                                            lifetime: _serde::__private::PhantomData<&'de ()>,
                                        }
                                        impl<'de> _serde::Deserialize<'de> for __DeserializeWith<'de> {
                                            fn deserialize<__D>(
                                                __deserializer: __D,
                                            ) -> _serde::__private::Result<Self, __D::Error>
                                            where
                                                __D: _serde::Deserializer<'de>,
                                            {
                                                _serde::__private::Ok(__DeserializeWith {
                                                    value:
                                                        match chrono::serde::ts_seconds::deserialize(
                                                            __deserializer,
                                                        ) {
                                                            _serde::__private::Ok(__val) => __val,
                                                            _serde::__private::Err(__err) => {
                                                                return _serde::__private::Err(
                                                                    __err,
                                                                );
                                                            }
                                                        },
                                                    phantom: _serde::__private::PhantomData,
                                                    lifetime: _serde::__private::PhantomData,
                                                })
                                            }
                                        }
                                        match _serde::de::MapAccess::next_value::<
                                            __DeserializeWith<'de>,
                                        >(&mut __map)
                                        {
                                            _serde::__private::Ok(__wrapper) => __wrapper.value,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        }
                                    });
                                }
                                _ => {
                                    let _ = match _serde::de::MapAccess::next_value::<
                                        _serde::de::IgnoredAny,
                                    >(&mut __map)
                                    {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    };
                                }
                            }
                        }
                        let __field0 = match __field0 {
                            _serde::__private::Some(__field0) => __field0,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("name") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        let __field1 = match __field1 {
                            _serde::__private::Some(__field1) => __field1,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("scopes") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        let __field2 = match __field2 {
                            _serde::__private::Some(__field2) => __field2,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("sub") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        let __field3 = match __field3 {
                            _serde::__private::Some(__field3) => __field3,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    <__A::Error as _serde::de::Error>::missing_field("exp"),
                                )
                            }
                        };
                        _serde::__private::Ok(Claims {
                            name: __field0,
                            scopes: __field1,
                            username: __field2,
                            expires: __field3,
                        })
                    }
                }
                const FIELDS: &'static [&'static str] = &["name", "scopes", "sub", "exp"];
                _serde::Deserializer::deserialize_struct(
                    __deserializer,
                    "Claims",
                    FIELDS,
                    __Visitor {
                        marker: _serde::__private::PhantomData::<Claims>,
                        lifetime: _serde::__private::PhantomData,
                    },
                )
            }
        }
    };
    pub struct Provider<P> {
        pub client_id: String,
        pub client_secret: String,
        #[serde(skip)]
        _provider: PhantomData<P>,
    }
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        #[allow(unused_extern_crates, clippy::useless_attribute)]
        extern crate serde as _serde;
        #[automatically_derived]
        impl<'de, P> _serde::Deserialize<'de> for Provider<P> {
            fn deserialize<__D>(__deserializer: __D) -> _serde::__private::Result<Self, __D::Error>
            where
                __D: _serde::Deserializer<'de>,
            {
                #[allow(non_camel_case_types)]
                enum __Field {
                    __field0,
                    __field1,
                    __ignore,
                }
                struct __FieldVisitor;
                impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                    type Value = __Field;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(__formatter, "field identifier")
                    }
                    fn visit_u64<__E>(
                        self,
                        __value: u64,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            0u64 => _serde::__private::Ok(__Field::__field0),
                            1u64 => _serde::__private::Ok(__Field::__field1),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_str<__E>(
                        self,
                        __value: &str,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            "client_id" => _serde::__private::Ok(__Field::__field0),
                            "client_secret" => _serde::__private::Ok(__Field::__field1),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_bytes<__E>(
                        self,
                        __value: &[u8],
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            b"client_id" => _serde::__private::Ok(__Field::__field0),
                            b"client_secret" => _serde::__private::Ok(__Field::__field1),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                }
                impl<'de> _serde::Deserialize<'de> for __Field {
                    #[inline]
                    fn deserialize<__D>(
                        __deserializer: __D,
                    ) -> _serde::__private::Result<Self, __D::Error>
                    where
                        __D: _serde::Deserializer<'de>,
                    {
                        _serde::Deserializer::deserialize_identifier(__deserializer, __FieldVisitor)
                    }
                }
                struct __Visitor<'de, P> {
                    marker: _serde::__private::PhantomData<Provider<P>>,
                    lifetime: _serde::__private::PhantomData<&'de ()>,
                }
                impl<'de, P> _serde::de::Visitor<'de> for __Visitor<'de, P> {
                    type Value = Provider<P>;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(__formatter, "struct Provider")
                    }
                    #[inline]
                    fn visit_seq<__A>(
                        self,
                        mut __seq: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::SeqAccess<'de>,
                    {
                        let __field0 =
                            match match _serde::de::SeqAccess::next_element::<String>(&mut __seq) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            } {
                                _serde::__private::Some(__value) => __value,
                                _serde::__private::None => {
                                    return _serde::__private::Err(
                                        _serde::de::Error::invalid_length(
                                            0usize,
                                            &"struct Provider with 2 elements",
                                        ),
                                    );
                                }
                            };
                        let __field1 =
                            match match _serde::de::SeqAccess::next_element::<String>(&mut __seq) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            } {
                                _serde::__private::Some(__value) => __value,
                                _serde::__private::None => {
                                    return _serde::__private::Err(
                                        _serde::de::Error::invalid_length(
                                            1usize,
                                            &"struct Provider with 2 elements",
                                        ),
                                    );
                                }
                            };
                        let __field2 = _serde::__private::Default::default();
                        _serde::__private::Ok(Provider {
                            client_id: __field0,
                            client_secret: __field1,
                            _provider: __field2,
                        })
                    }
                    #[inline]
                    fn visit_map<__A>(
                        self,
                        mut __map: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::MapAccess<'de>,
                    {
                        let mut __field0: _serde::__private::Option<String> =
                            _serde::__private::None;
                        let mut __field1: _serde::__private::Option<String> =
                            _serde::__private::None;
                        while let _serde::__private::Some(__key) =
                            match _serde::de::MapAccess::next_key::<__Field>(&mut __map) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            }
                        {
                            match __key {
                                __Field::__field0 => {
                                    if _serde::__private::Option::is_some(&__field0) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field(
                                                "client_id",
                                            ),
                                        );
                                    }
                                    __field0 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<String>(
                                            &mut __map,
                                        ) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                __Field::__field1 => {
                                    if _serde::__private::Option::is_some(&__field1) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field(
                                                "client_secret",
                                            ),
                                        );
                                    }
                                    __field1 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<String>(
                                            &mut __map,
                                        ) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                _ => {
                                    let _ = match _serde::de::MapAccess::next_value::<
                                        _serde::de::IgnoredAny,
                                    >(&mut __map)
                                    {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    };
                                }
                            }
                        }
                        let __field0 = match __field0 {
                            _serde::__private::Some(__field0) => __field0,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("client_id") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        let __field1 = match __field1 {
                            _serde::__private::Some(__field1) => __field1,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("client_secret") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        _serde::__private::Ok(Provider {
                            client_id: __field0,
                            client_secret: __field1,
                            _provider: _serde::__private::Default::default(),
                        })
                    }
                }
                const FIELDS: &'static [&'static str] = &["client_id", "client_secret"];
                _serde::Deserializer::deserialize_struct(
                    __deserializer,
                    "Provider",
                    FIELDS,
                    __Visitor {
                        marker: _serde::__private::PhantomData::<Provider<P>>,
                        lifetime: _serde::__private::PhantomData,
                    },
                )
            }
        }
    };
    type OauthClient = oauth2::Client<
        BasicErrorResponse,
        SimpleTokenResponse,
        BasicTokenType,
        BasicTokenIntrospectionResponse,
        StandardRevocableToken,
        BasicRevocationErrorResponse,
    >;
    pub struct SimpleTokenResponse {
        pub access_token: AccessToken,
        #[serde(deserialize_with = "oauth2::helpers::deserialize_untagged_enum_case_insensitive")]
        pub token_type: BasicTokenType,
        pub expires_in: u64,
        pub refresh_token: Option<RefreshToken>,
    }
    #[automatically_derived]
    #[allow(unused_qualifications)]
    impl ::core::fmt::Debug for SimpleTokenResponse {
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            match *self {
                SimpleTokenResponse {
                    access_token: ref __self_0_0,
                    token_type: ref __self_0_1,
                    expires_in: ref __self_0_2,
                    refresh_token: ref __self_0_3,
                } => {
                    let debug_trait_builder =
                        &mut ::core::fmt::Formatter::debug_struct(f, "SimpleTokenResponse");
                    let _ = ::core::fmt::DebugStruct::field(
                        debug_trait_builder,
                        "access_token",
                        &&(*__self_0_0),
                    );
                    let _ = ::core::fmt::DebugStruct::field(
                        debug_trait_builder,
                        "token_type",
                        &&(*__self_0_1),
                    );
                    let _ = ::core::fmt::DebugStruct::field(
                        debug_trait_builder,
                        "expires_in",
                        &&(*__self_0_2),
                    );
                    let _ = ::core::fmt::DebugStruct::field(
                        debug_trait_builder,
                        "refresh_token",
                        &&(*__self_0_3),
                    );
                    ::core::fmt::DebugStruct::finish(debug_trait_builder)
                }
            }
        }
    }
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        #[allow(unused_extern_crates, clippy::useless_attribute)]
        extern crate serde as _serde;
        #[automatically_derived]
        impl _serde::Serialize for SimpleTokenResponse {
            fn serialize<__S>(
                &self,
                __serializer: __S,
            ) -> _serde::__private::Result<__S::Ok, __S::Error>
            where
                __S: _serde::Serializer,
            {
                let mut __serde_state = match _serde::Serializer::serialize_struct(
                    __serializer,
                    "SimpleTokenResponse",
                    false as usize + 1 + 1 + 1 + 1,
                ) {
                    _serde::__private::Ok(__val) => __val,
                    _serde::__private::Err(__err) => {
                        return _serde::__private::Err(__err);
                    }
                };
                match _serde::ser::SerializeStruct::serialize_field(
                    &mut __serde_state,
                    "access_token",
                    &self.access_token,
                ) {
                    _serde::__private::Ok(__val) => __val,
                    _serde::__private::Err(__err) => {
                        return _serde::__private::Err(__err);
                    }
                };
                match _serde::ser::SerializeStruct::serialize_field(
                    &mut __serde_state,
                    "token_type",
                    &self.token_type,
                ) {
                    _serde::__private::Ok(__val) => __val,
                    _serde::__private::Err(__err) => {
                        return _serde::__private::Err(__err);
                    }
                };
                match _serde::ser::SerializeStruct::serialize_field(
                    &mut __serde_state,
                    "expires_in",
                    &self.expires_in,
                ) {
                    _serde::__private::Ok(__val) => __val,
                    _serde::__private::Err(__err) => {
                        return _serde::__private::Err(__err);
                    }
                };
                match _serde::ser::SerializeStruct::serialize_field(
                    &mut __serde_state,
                    "refresh_token",
                    &self.refresh_token,
                ) {
                    _serde::__private::Ok(__val) => __val,
                    _serde::__private::Err(__err) => {
                        return _serde::__private::Err(__err);
                    }
                };
                _serde::ser::SerializeStruct::end(__serde_state)
            }
        }
    };
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        #[allow(unused_extern_crates, clippy::useless_attribute)]
        extern crate serde as _serde;
        #[automatically_derived]
        impl<'de> _serde::Deserialize<'de> for SimpleTokenResponse {
            fn deserialize<__D>(__deserializer: __D) -> _serde::__private::Result<Self, __D::Error>
            where
                __D: _serde::Deserializer<'de>,
            {
                #[allow(non_camel_case_types)]
                enum __Field {
                    __field0,
                    __field1,
                    __field2,
                    __field3,
                    __ignore,
                }
                struct __FieldVisitor;
                impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                    type Value = __Field;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(__formatter, "field identifier")
                    }
                    fn visit_u64<__E>(
                        self,
                        __value: u64,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            0u64 => _serde::__private::Ok(__Field::__field0),
                            1u64 => _serde::__private::Ok(__Field::__field1),
                            2u64 => _serde::__private::Ok(__Field::__field2),
                            3u64 => _serde::__private::Ok(__Field::__field3),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_str<__E>(
                        self,
                        __value: &str,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            "access_token" => _serde::__private::Ok(__Field::__field0),
                            "token_type" => _serde::__private::Ok(__Field::__field1),
                            "expires_in" => _serde::__private::Ok(__Field::__field2),
                            "refresh_token" => _serde::__private::Ok(__Field::__field3),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_bytes<__E>(
                        self,
                        __value: &[u8],
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            b"access_token" => _serde::__private::Ok(__Field::__field0),
                            b"token_type" => _serde::__private::Ok(__Field::__field1),
                            b"expires_in" => _serde::__private::Ok(__Field::__field2),
                            b"refresh_token" => _serde::__private::Ok(__Field::__field3),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                }
                impl<'de> _serde::Deserialize<'de> for __Field {
                    #[inline]
                    fn deserialize<__D>(
                        __deserializer: __D,
                    ) -> _serde::__private::Result<Self, __D::Error>
                    where
                        __D: _serde::Deserializer<'de>,
                    {
                        _serde::Deserializer::deserialize_identifier(__deserializer, __FieldVisitor)
                    }
                }
                struct __Visitor<'de> {
                    marker: _serde::__private::PhantomData<SimpleTokenResponse>,
                    lifetime: _serde::__private::PhantomData<&'de ()>,
                }
                impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                    type Value = SimpleTokenResponse;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "struct SimpleTokenResponse",
                        )
                    }
                    #[inline]
                    fn visit_seq<__A>(
                        self,
                        mut __seq: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::SeqAccess<'de>,
                    {
                        let __field0 = match match _serde::de::SeqAccess::next_element::<AccessToken>(
                            &mut __seq,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(_serde::de::Error::invalid_length(
                                    0usize,
                                    &"struct SimpleTokenResponse with 4 elements",
                                ));
                            }
                        };
                        let __field1 = match {
                            struct __DeserializeWith<'de> {
                                value: BasicTokenType,
                                phantom: _serde::__private::PhantomData<SimpleTokenResponse>,
                                lifetime: _serde::__private::PhantomData<&'de ()>,
                            }
                            impl<'de> _serde::Deserialize<'de> for __DeserializeWith<'de> {
                                fn deserialize<__D>(
                                    __deserializer: __D,
                                ) -> _serde::__private::Result<Self, __D::Error>
                                where
                                    __D: _serde::Deserializer<'de>,
                                {
                                    _serde :: __private :: Ok (__DeserializeWith { value : match oauth2 :: helpers :: deserialize_untagged_enum_case_insensitive (__deserializer) { _serde :: __private :: Ok (__val) => __val , _serde :: __private :: Err (__err) => { return _serde :: __private :: Err (__err) ; } } , phantom : _serde :: __private :: PhantomData , lifetime : _serde :: __private :: PhantomData , })
                                }
                            }
                            _serde::__private::Option::map(
                                match _serde::de::SeqAccess::next_element::<__DeserializeWith<'de>>(
                                    &mut __seq,
                                ) {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                },
                                |__wrap| __wrap.value,
                            )
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(_serde::de::Error::invalid_length(
                                    1usize,
                                    &"struct SimpleTokenResponse with 4 elements",
                                ));
                            }
                        };
                        let __field2 =
                            match match _serde::de::SeqAccess::next_element::<u64>(&mut __seq) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            } {
                                _serde::__private::Some(__value) => __value,
                                _serde::__private::None => {
                                    return _serde::__private::Err(
                                        _serde::de::Error::invalid_length(
                                            2usize,
                                            &"struct SimpleTokenResponse with 4 elements",
                                        ),
                                    );
                                }
                            };
                        let __field3 = match match _serde::de::SeqAccess::next_element::<
                            Option<RefreshToken>,
                        >(&mut __seq)
                        {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(_serde::de::Error::invalid_length(
                                    3usize,
                                    &"struct SimpleTokenResponse with 4 elements",
                                ));
                            }
                        };
                        _serde::__private::Ok(SimpleTokenResponse {
                            access_token: __field0,
                            token_type: __field1,
                            expires_in: __field2,
                            refresh_token: __field3,
                        })
                    }
                    #[inline]
                    fn visit_map<__A>(
                        self,
                        mut __map: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::MapAccess<'de>,
                    {
                        let mut __field0: _serde::__private::Option<AccessToken> =
                            _serde::__private::None;
                        let mut __field1: _serde::__private::Option<BasicTokenType> =
                            _serde::__private::None;
                        let mut __field2: _serde::__private::Option<u64> = _serde::__private::None;
                        let mut __field3: _serde::__private::Option<Option<RefreshToken>> =
                            _serde::__private::None;
                        while let _serde::__private::Some(__key) =
                            match _serde::de::MapAccess::next_key::<__Field>(&mut __map) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            }
                        {
                            match __key {
                                __Field::__field0 => {
                                    if _serde::__private::Option::is_some(&__field0) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field(
                                                "access_token",
                                            ),
                                        );
                                    }
                                    __field0 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<AccessToken>(
                                            &mut __map,
                                        ) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                __Field::__field1 => {
                                    if _serde::__private::Option::is_some(&__field1) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field(
                                                "token_type",
                                            ),
                                        );
                                    }
                                    __field1 = _serde::__private::Some({
                                        struct __DeserializeWith<'de> {
                                            value: BasicTokenType,
                                            phantom:
                                                _serde::__private::PhantomData<SimpleTokenResponse>,
                                            lifetime: _serde::__private::PhantomData<&'de ()>,
                                        }
                                        impl<'de> _serde::Deserialize<'de> for __DeserializeWith<'de> {
                                            fn deserialize<__D>(
                                                __deserializer: __D,
                                            ) -> _serde::__private::Result<Self, __D::Error>
                                            where
                                                __D: _serde::Deserializer<'de>,
                                            {
                                                _serde :: __private :: Ok (__DeserializeWith { value : match oauth2 :: helpers :: deserialize_untagged_enum_case_insensitive (__deserializer) { _serde :: __private :: Ok (__val) => __val , _serde :: __private :: Err (__err) => { return _serde :: __private :: Err (__err) ; } } , phantom : _serde :: __private :: PhantomData , lifetime : _serde :: __private :: PhantomData , })
                                            }
                                        }
                                        match _serde::de::MapAccess::next_value::<
                                            __DeserializeWith<'de>,
                                        >(&mut __map)
                                        {
                                            _serde::__private::Ok(__wrapper) => __wrapper.value,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        }
                                    });
                                }
                                __Field::__field2 => {
                                    if _serde::__private::Option::is_some(&__field2) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field(
                                                "expires_in",
                                            ),
                                        );
                                    }
                                    __field2 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<u64>(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                __Field::__field3 => {
                                    if _serde::__private::Option::is_some(&__field3) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field(
                                                "refresh_token",
                                            ),
                                        );
                                    }
                                    __field3 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<
                                            Option<RefreshToken>,
                                        >(&mut __map)
                                        {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                _ => {
                                    let _ = match _serde::de::MapAccess::next_value::<
                                        _serde::de::IgnoredAny,
                                    >(&mut __map)
                                    {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    };
                                }
                            }
                        }
                        let __field0 = match __field0 {
                            _serde::__private::Some(__field0) => __field0,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("access_token") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        let __field1 = match __field1 {
                            _serde::__private::Some(__field1) => __field1,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    <__A::Error as _serde::de::Error>::missing_field("token_type"),
                                )
                            }
                        };
                        let __field2 = match __field2 {
                            _serde::__private::Some(__field2) => __field2,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("expires_in") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        let __field3 = match __field3 {
                            _serde::__private::Some(__field3) => __field3,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("refresh_token") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        _serde::__private::Ok(SimpleTokenResponse {
                            access_token: __field0,
                            token_type: __field1,
                            expires_in: __field2,
                            refresh_token: __field3,
                        })
                    }
                }
                const FIELDS: &'static [&'static str] =
                    &["access_token", "token_type", "expires_in", "refresh_token"];
                _serde::Deserializer::deserialize_struct(
                    __deserializer,
                    "SimpleTokenResponse",
                    FIELDS,
                    __Visitor {
                        marker: _serde::__private::PhantomData::<SimpleTokenResponse>,
                        lifetime: _serde::__private::PhantomData,
                    },
                )
            }
        }
    };
    impl TokenResponse<BasicTokenType> for SimpleTokenResponse {
        fn access_token(&self) -> &AccessToken {
            &self.access_token
        }
        fn token_type(&self) -> &BasicTokenType {
            &self.token_type
        }
        fn expires_in(&self) -> Option<Duration> {
            Some(Duration::from_secs(self.expires_in))
        }
        fn refresh_token(&self) -> Option<&RefreshToken> {
            self.refresh_token.as_ref()
        }
        fn scopes(&self) -> Option<&Vec<Scope>> {
            None
        }
    }
    impl<P: provider::Provider> Provider<P> {
        pub fn oauth2_client(&self, base_url: oauth2::url::Url) -> OauthClient {
            let mut redirect = base_url;
            redirect.set_path("/callback");
            OauthClient::new(
                ClientId::new(self.client_id.clone()),
                Some(ClientSecret::new(self.client_secret.clone())),
                AuthUrl::from_url(
                    oauth2::url::Url::parse(P::AUTH_URL).expect("could not parse auth url"),
                ),
                Some(TokenUrl::from_url(
                    oauth2::url::Url::parse(P::TOKEN_URL).expect("could not parse token url"),
                )),
            )
            .set_redirect_uri(RedirectUrl::from_url(redirect))
        }
    }
}
