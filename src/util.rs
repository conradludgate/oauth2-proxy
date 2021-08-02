pub fn bail<'o>(err: impl std::error::Error, status: rocket::http::Status) -> rocket::response::Result<'o> {
    error!("{}", err);
    Err(status)
}
