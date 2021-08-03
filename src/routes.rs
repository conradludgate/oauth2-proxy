use rocket::Route;

mod api;
mod callback;
mod home;
mod login;
mod token;

pub fn routes() -> Vec<Route> {
    routes![
        api::exchange,
        callback::callback,
        callback::error,
        login::post,
        login::page,
        home::page,
        home::index,
        token::view,
        token::new,
        token::create,
        token::delete,
        token::revoke,
    ]
}
