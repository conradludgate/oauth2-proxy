#![allow(clippy::nonstandard_macro_braces)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]

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
