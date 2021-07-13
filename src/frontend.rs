pub mod routes {
    use super::{filters::*, handlers};
    use uuid::Uuid;
    use warp::Filter;

    pub fn router() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
        home().or(view_token()).or(new_token())
    }

    pub fn home() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
        warp::get()
            .and(warp::path::end())
            .and(with_user())
            .and_then(handlers::home)
            .with(warp::trace::named("home"))
    }

    pub fn view_token() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone
    {
        warp::get()
            .and(warp::path!("token" / Uuid))
            .and(with_user())
            .and_then(handlers::view_token)
            .with(warp::trace::named("view_token"))
    }

    pub fn new_token() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
        warp::get()
            .and(warp::path!("token" / String))
            .and(with_user())
            .and_then(handlers::new_token)
            .with(warp::trace::named("new_token"))
    }
}

mod handlers {
    use uuid::Uuid;

    use crate::{
        db::{DynamoPrimaryKey, DynamoSecondaryKey, ProviderKey, TokenKey, TokenUserIndexKey},
        templates::{self, HomeToken},
    };

    pub async fn home(user_id: Uuid) -> Result<impl warp::Reply, warp::Rejection> {
        let tokens = TokenUserIndexKey { user_id }
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

    pub async fn view_token(
        token_id: Uuid,
        user_id: Uuid,
    ) -> Result<impl warp::Reply, warp::Rejection> {
        let token = TokenKey { token_id }
            .get()
            .await
            .map_err(crate::errors::reject)?
            .ok_or_else(warp::reject::not_found)?;

        if token.user_id != user_id {
            return Err(warp::reject::not_found());
        }

        Ok(templates::ViewToken {
            name: token.name,
            id: token_id,
            scopes: token.oauth.scopes,
            api_key: None,
        })
    }

    pub async fn new_token(
        provider_id: String,
        _: Uuid,
    ) -> Result<impl warp::Reply, warp::Rejection> {
        let provider = ProviderKey { provider_id }
            .get()
            .await
            .map_err(crate::errors::reject)?
            .ok_or_else(warp::reject::not_found)?;

        Ok(templates::NewToken {
            scopes: provider.scopes,
        })
    }
}

mod filters {
    use crate::{
        config::Config,
        db::{DynamoPrimaryKey, UserSessionKey},
        errors::SessionUnauthorized,
    };
    use uuid::Uuid;
    use warp::Filter;

    pub fn with_user() -> impl Filter<Extract = (Uuid,), Error = warp::Rejection> + Clone {
        warp::cookie("session").and_then(get_user)
    }

    pub fn with_config(
        config: &'static Config,
    ) -> impl Filter<Extract = (&'static Config,), Error = std::convert::Infallible> + Clone {
        warp::any().map(move || config)
    }

    async fn get_user(session_id: Uuid) -> Result<Uuid, warp::Rejection> {
        let user_session = UserSessionKey { session_id }
            .get()
            .await
            .map_err(crate::errors::reject)?
            .ok_or_else(|| warp::reject::custom(SessionUnauthorized))?;

        Ok(user_session.user_id)
    }
}
