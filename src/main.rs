#![feature(once_cell)]

mod config;
mod errors;
mod frontend;
mod templates;
mod db;
mod api;
mod signing;

use tracing_subscriber::fmt::format::FmtSpan;
use warp::Filter;

#[tokio::main]
async fn main() {
    let config = Box::leak(Box::new(config::parse()));

    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(&config.rust_log)
        .with_span_events(FmtSpan::CLOSE)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("no global subscriber has been set");

    tracing_log::LogTracer::init().expect("could not init logger");

    let router = frontend::routes::router()
        .or(api::routes::router())
        .recover(errors::handle)
        .with(warp::trace::request());

    warp::serve(router).run(([127, 0, 0, 1], config.port)).await;
}
