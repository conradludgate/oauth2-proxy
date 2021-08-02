use rocket::Route;

mod callback;
mod home;
mod login;
mod token;

pub fn routes() -> Vec<Route> {
    routes![
        home::page,
        home::index,
        token::view,
        token::new,
        token::create,
        token::delete,
        login::post,
        login::page,
        callback::callback,
        callback::error
    ]
}
