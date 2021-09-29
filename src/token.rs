use std::{marker::PhantomData, time::Duration};

use chrono::Utc;
use oauth2::{
    basic::{BasicErrorResponse, BasicRevocationErrorResponse, BasicTokenIntrospectionResponse, BasicTokenType},
    AccessToken, AuthUrl, ClientId, ClientSecret, RedirectUrl, RefreshToken, Scope, StandardRevocableToken, TokenResponse, TokenUrl,
};
// use rocket::{
//     http::{
//         impl_from_uri_param_identity,
//         uri::fmt::{Formatter, Part, UriDisplay},
//     },
//     request::FromParam,
// };
use serde::{Deserialize, Serialize};

use crate::provider::{self, Scopes};
// use uuid::Uuid;

// pub struct ID(Uuid);
// impl From<ID> for Uuid {
//     fn from(u: ID) -> Self {
//         u.0
//     }
// }
// #[async_trait]
// impl<'a> FromParam<'a> for ID {
//     type Error = <Uuid as FromStr>::Err;

//     fn from_param(param: &'a str) -> Result<Self, Self::Error> {
//         param.parse().map(ID)
//     }
// }

// impl<P: Part> UriDisplay<P> for ID {
//     fn fmt(&self, f: &mut Formatter<'_, P>) -> fmt::Result {
//         f.write_str(&self.0.to_string())
//     }
// }
// impl_from_uri_param_identity!(ID);

// pub struct Data {
//     pub name: String,
//     pub provider_id: String,
//     pub scopes: Vec<String>,
// }

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub name: String,
    pub scopes: Scopes,

    #[serde(rename = "sub")]
    pub username: String,

    #[serde(rename = "exp", with = "chrono::serde::ts_seconds")]
    pub expires: chrono::DateTime<Utc>,
}

#[derive(Deserialize)]
pub struct Provider<P> {
    pub client_id: String,
    pub client_secret: String,
    #[serde(skip)]
    _provider: PhantomData<P>,
}

type OauthClient = oauth2::Client<BasicErrorResponse, SimpleTokenResponse, BasicTokenType, BasicTokenIntrospectionResponse, StandardRevocableToken, BasicRevocationErrorResponse>;

#[derive(Debug, Serialize, Deserialize)]
pub struct SimpleTokenResponse {
    pub access_token: AccessToken,
    #[serde(deserialize_with = "oauth2::helpers::deserialize_untagged_enum_case_insensitive")]
    pub token_type: BasicTokenType,
    pub expires_in: u64,
    pub refresh_token: Option<RefreshToken>,
}

impl TokenResponse<BasicTokenType> for SimpleTokenResponse {
    fn access_token(&self) -> &AccessToken {
        &self.access_token
    }
    fn token_type(&self) -> &BasicTokenType {
        &self.token_type
    }
    fn expires_in(&self) -> Option<Duration> {
        Some(Duration::from_secs(self.expires_in))
    }
    fn refresh_token(&self) -> Option<&RefreshToken> {
        self.refresh_token.as_ref()
    }
    fn scopes(&self) -> Option<&Vec<Scope>> {
        None
    }
}

impl<P: provider::Provider> Provider<P> {
    pub fn oauth2_client(&self, base_url: oauth2::url::Url) -> OauthClient {
        let mut redirect = base_url;
        redirect.set_path("/callback");

        OauthClient::new(
            ClientId::new(self.client_id.clone()),
            Some(ClientSecret::new(self.client_secret.clone())),
            AuthUrl::from_url(oauth2::url::Url::parse(P::AUTH_URL).expect("could not parse auth url")),
            Some(TokenUrl::from_url(oauth2::url::Url::parse(P::TOKEN_URL).expect("could not parse token url"))),
        )
        .set_redirect_uri(RedirectUrl::from_url(redirect))
    }
}
