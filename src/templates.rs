use askama::Template;

#[derive(Template)]
#[template(path = "home.html")]
pub struct Home {
    pub tokens: Vec<HomeToken>,
}

pub struct HomeToken {
    pub id: String,
    pub name: String,
}

#[derive(Template)]
#[template(path = "index.html")]
pub struct Index;

#[derive(Template)]
#[template(path = "new_token.html")]
pub struct NewToken {
    pub scopes: Vec<String>,
}

#[derive(Template)]
#[template(path = "redirect.html")]
pub struct Redirect {
    path: String,
    text: String,
}

#[derive(Template)]
#[template(path = "token.html")]
pub struct Token {
    name: String,
    id: String,
    scopes: Vec<String>,
    api_key: Option<String>,
}
