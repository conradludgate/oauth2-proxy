use rocket::Route;

mod api;
mod callback;
mod home;
mod login;
mod register;
mod token;

pub fn routes() -> Vec<Route> {
    routes![
        api::exchange,
        callback::callback,
        callback::callback_error,
        login::login_post,
        login::login_page,
        home::home_page,
        home::index,
        register::register_page,
        register::register_post,
        token::token_view,
        token::token_view_unauthenticated,
        token::token_new_page,
        token::token_create,
        token::token_delete,
        token::token_revoke,
    ]
}
