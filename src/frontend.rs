pub mod routes {
    use super::{filters::*, handlers};
    use crate::config::Config;
    use warp::Filter;

    pub fn router(
        config: &'static Config,
    ) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
        home(config).or(new_token(config))
    }

    pub fn home(
        config: &'static Config,
    ) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
        warp::get()
            .and(warp::path::end())
            .and(with_config(config))
            .and(with_user())
            .and_then(handlers::home)
            // .map(handlers::home)
            .with(warp::trace::named("home"))
    }

    pub fn new_token(
        config: &'static Config,
    ) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
        warp::get()
            .and(warp::path!("token" / "new"))
            .and(with_config(config))
            .and(with_user())
            .map(handlers::new_token)
            .with(warp::trace::named("new_token"))
    }
}

mod handlers {
    use crate::{
        config::Config,
        db::{DynamoSecondaryKey, TokenUserKey},
        templates::{self, HomeToken},
    };

    pub async fn home(
        config: &Config,
        user_id: String,
    ) -> Result<impl warp::Reply, warp::Rejection> {
        let tokens = TokenUserKey { user_id }
            .query()
            .await
            .map_err(crate::errors::reject)?;
        Ok(templates::Home {
            tokens: tokens
                .into_iter()
                .map(|token| HomeToken {
                    id: token.token_id,
                    name: token.name,
                })
                .collect(),
        })
    }

    pub fn new_token(config: &Config, user_id: String) -> impl warp::Reply {
        templates::NewToken {
            scopes: vec!["super".into(), "awesome".into(), "scopes".into()],
        }
    }
}

mod filters {
    use crate::{
        config::Config,
        db::{DynamoPrimaryKey, SessionKey},
        errors::SessionUnauthorized,
    };
    use warp::Filter;

    pub fn with_user() -> impl Filter<Extract = (String,), Error = warp::Rejection> + Clone {
        warp::cookie("session").and_then(get_user)
    }

    pub fn with_config(
        config: &'static Config,
    ) -> impl Filter<Extract = (&'static Config,), Error = std::convert::Infallible> + Clone {
        warp::any().map(move || config)
    }

    async fn get_user(session_id: String) -> Result<String, warp::Rejection> {
        let user_session = SessionKey { session_id }
            .get()
            .await
            .map_err(crate::errors::reject)?
            .ok_or(warp::reject::custom(SessionUnauthorized))?;

        Ok(user_session.user_id)
    }
}
