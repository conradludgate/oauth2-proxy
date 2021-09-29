use self::spotify::SpotifyScope;
use async_graphql::{OutputType, SimpleObject, Union};
use nitroglycerin::serde::{Serialize, Deserialize};

pub mod spotify;

pub trait Provider {
    const AUTH_URL: &'static str;
    const TOKEN_URL: &'static str;

    type Scopes: ProviderScopes;
}

pub trait ProviderScopes {
    fn to_str(&self) -> &'static str;
}

#[derive(SimpleObject, Debug, Clone, Serialize, Deserialize)]
#[graphql(concrete(name = "SpotifyScopes", params(SpotifyScope)))]
pub struct ScopeCollection<T: OutputType> {
    pub values: Vec<T>,
}

#[derive(Union, Debug, Clone, Serialize, Deserialize)]
pub enum Scopes {
    Spotify(ScopeCollection<SpotifyScope>),
}
