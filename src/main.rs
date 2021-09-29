#![allow(clippy::nonstandard_macro_braces)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]

use actix_web::{App, HttpServer};
use nitroglycerin::dynamodb::DynamoDbClient;
use rusoto_core::Region;
use tracing_actix_web::TracingLogger;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod config;
mod db;
mod login;
// mod route_metrics;
mod routes;
mod templates;
mod token;
mod util;

// #[launch]
// fn rocket() -> _ {
//     let port = std::env::var("PORT").ok().and_then(|s| s.parse::<u16>().ok()).unwrap_or(27228);

//     let figment = rocket::Config::figment().merge(("port", port));

//     let metrics_builder = metrics_exporter_prometheus::PrometheusBuilder::new();

//     let metrics_builder = if let Ok(addr) = std::env::var("PROMETHEUS_ADDRESS") {
//         metrics_builder.listen_address(addr.parse::<SocketAddr>().expect("'PROMETHEUS_ADDRESS' was not a valid ip:port address"))
//     } else {
//         metrics_builder
//     };

//     metrics_builder.install().expect("Could not install prometheus metrics exporter");

//     register_counter!("oauth2_proxy_users", Unit::Count);
//     register_counter!("oauth2_proxy_token_exchanges", Unit::Count);
//     register_gauge!("oauth2_proxy_tokens", Unit::Count);
//     register_histogram!("oauth2_proxy_route_durations", Unit::Nanoseconds);

//     rocket::custom(figment)
//         .attach(AdHoc::config::<Config>())
//         .attach(route_metrics::RouteMetrics)
//         .manage(DynamoDbClient::new(Region::default()))
//         .mount("/", routes::routes())
// }

#[actix_web::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let tracer = opentelemetry_jaeger::new_pipeline()
        .with_service_name("report_example")
        .install_batch(opentelemetry::runtime::Tokio)?;
    let telemetry = tracing_opentelemetry::layer().with_tracer(tracer);
    tracing_subscriber::registry().with(telemetry).try_init()?;

    let config: Config = Figment::new()
        .merge(Toml::file("config.toml"))
        .merge(Env::prefixed("OAUTH2_PROXY_"))
        .extract()?;

    let db = DynamoDbClient::new(Region::default());

    HttpServer::new(move || {
        App::new()
            .wrap(TracingLogger::default())
            .service(graphql.clone())
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await?;

    Ok(())
}
