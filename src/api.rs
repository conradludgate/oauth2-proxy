pub mod routes {
    use super::handlers;
    use warp::Filter;

    pub fn router() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
        login().or(callback())
    }

    pub fn login() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
        warp::get()
            .and(warp::path!("api" / "login" / String))
            .and_then(handlers::login)
            .with(warp::trace::named("login"))
    }

    pub fn callback() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
        warp::get()
            .and(warp::path!("api" / "callback" / String))
            .and(warp::query())
            .and_then(handlers::callback)
            .with(warp::trace::named("callback"))
    }
}

mod handlers {
    use std::collections::HashMap;

    use serde::Deserialize;

    use crate::{
        db::{DynamoPrimaryKey, OauthToken, ProviderKey},
        errors::reject,
    };

    pub async fn login(provider_id: String) -> Result<impl warp::Reply, warp::Rejection> {
        let provider = ProviderKey { provider_id }
            .get()
            .await
            .map_err(reject)?
            .ok_or_else(warp::reject::not_found)?;

        let mut query: HashMap<&str, &str> = HashMap::new();
        query.insert("response_type", "code");
        query.insert("client_id", provider.client_id.as_str());
        query.insert("redirect_uri", provider.redirect_uri.as_str());
        query.insert("state", "foo");
        let query = serde_urlencoded::to_string(query).unwrap();
        let url = format!("{}?{}", provider.auth_url, query);

        Ok(warp::redirect::see_other(
            url.parse::<http::Uri>().map_err(reject)?,
        ))
    }

    #[derive(Deserialize)]
    pub struct CallbackQuery {
        code: String,
        state: String,
    }

    pub async fn callback(
        provider_id: String,
        callback_query: CallbackQuery,
    ) -> Result<impl warp::Reply, warp::Rejection> {
        let provider = ProviderKey { provider_id }
            .get()
            .await
            .map_err(reject)?
            .ok_or_else(warp::reject::not_found)?;

        let client = reqwest::Client::new();

        #[derive(Deserialize, Debug)]
        pub struct Token {
            pub access_token: String,
            pub refresh_token: String,
            pub expires_in: usize,
            pub token_type: String,
        }

        let token: Token = client
            .post(provider.token_url)
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", callback_query.code.as_str()),
                ("redirect_uri", provider.redirect_uri.as_str()),
            ])
            .basic_auth(provider.client_id, Some(provider.client_secret)).send()
            .await
            .map_err(reject)?
            .json()
            .await
            .map_err(reject)?;

        println!("{:?}", token);

        Ok(warp::reply())
    }
}
