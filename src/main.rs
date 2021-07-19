#![allow(clippy::nonstandard_macro_braces)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]

use config::Config;
use nitroglycerin::dynamodb::DynamoDbClient;
use rocket::fairing::AdHoc;
use rusoto_core::Region;

mod api;
mod config;
mod db;
mod frontend;
mod templates;

#[macro_use]
extern crate rocket;

#[launch]
fn rocket() -> _ {
    let port = std::env::var("PORT")
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(27228);

    let figment = rocket::Config::figment().merge(("port", port));

    rocket::custom(figment)
        .attach(AdHoc::config::<Config>())
        .manage(DynamoDbClient::new(Region::default()))
        .mount("/", frontend::routes())
        .mount("/api", api::routes())
}
