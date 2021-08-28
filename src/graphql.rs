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

mod mutation;
mod query;
mod provider;

pub type Oauth2ProxySchema = Schema<query::Query, mutation::Mutation, EmptySubscription>;

#[derive(Clone)]
pub struct Service(web::Data<Oauth2ProxySchema>);
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

#[post("")]
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

#[get("")]
async fn playground() -> Result<HttpResponse> {
    Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(playground_source(
            GraphQLPlaygroundConfig::new("/graphql").subscription_endpoint("/graphql"),
        )))
}
