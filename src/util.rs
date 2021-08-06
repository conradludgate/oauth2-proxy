pub fn bail<'o>(err: impl std::fmt::Display, status: rocket::http::Status) -> rocket::http::Status {
    error!("{}", err);
    status
}
