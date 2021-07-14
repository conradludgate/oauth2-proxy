#![feature(once_cell)]

mod api;
mod config;
mod db;
mod frontend;
mod signing;
mod templates;

#[macro_use]
extern crate rocket;

#[launch]
fn rocket() -> _ {
    let config = config::parse().unwrap();

    let port = std::env::var("PORT")
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(27228);

    let figment = rocket::Config::figment().merge(("port", port));
    rocket::custom(figment)
        .manage(config)
        .mount("/", frontend::routes())
        .mount("/api", api::routes())
}

// #[tokio::main]
// async fn main() {
//     let config = Box::leak(Box::new(config::parse()));

//     let subscriber = tracing_subscriber::fmt()
//         .with_env_filter(&config.rust_log)
//         .with_span_events(FmtSpan::CLOSE)
//         .finish();
//     tracing::subscriber::set_global_default(subscriber).expect("no global subscriber has been set");

//     tracing_log::LogTracer::init().expect("could not init logger");

//     let router = frontend::routes::router()
//         .or(api::routes::router())
//         .recover(errors::handle)
//         .with(warp::trace::request());

//     warp::serve(router).run(([127, 0, 0, 1], config.port)).await;
// }
