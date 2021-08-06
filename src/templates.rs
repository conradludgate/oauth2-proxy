use askama::Template;
use uuid::Uuid;

#[derive(Template)]
#[template(path = "home.html")]
pub struct Home {
    pub tokens: Vec<HomeToken>,
    pub providers: Vec<Provider>,
}

pub struct HomeToken {
    pub id: Uuid,
    pub name: String,
}

pub struct Provider {
    pub slug: String,
    pub name: String,
}

#[derive(Template)]
#[template(path = "index.html")]
pub struct Index;

#[derive(Template)]
#[template(path = "new_token.html")]
pub struct NewToken {
    pub provider_id: String,
    pub scopes: Vec<String>,
}

#[derive(Template)]
#[template(path = "token.html")]
pub struct ViewToken {
    pub name: String,
    pub id: Uuid,
    pub scopes: Vec<String>,
    pub api_key: Option<String>,

    pub username: String,
    pub baseurl: String,
}

#[derive(Template)]
#[template(path = "login.html")]
pub struct Login {
    pub error: Option<String>,
    pub redirect_to: String,
}

#[derive(Template)]
#[template(path = "register.html")]
pub struct Register {
    pub error: Option<String>,
    pub redirect_to: String,
}
