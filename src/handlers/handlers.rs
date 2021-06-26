use anyhow::Result;
use handlebars::Handlebars;
use serde_json::json;
use sqlx::{Pool, Postgres};
use warp::http::StatusCode;
use warp::Filter;
use warp_sessions::{MemoryStore, SessionWithStore};

use crate::handlers::util::{
    error_html, get_and_clear_flash, get_current_username, HandlerReturn, Page,
};
use crate::Config;

pub fn with_db(
    db: Pool<Postgres>,
) -> impl Filter<Extract = (Pool<Postgres>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || db.clone())
}

pub fn with_config(
    config: Config,
) -> impl Filter<Extract = (Config,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || config.clone())
}

pub fn with_templates(
    templates: Handlebars,
) -> impl Filter<Extract = (Handlebars,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || templates.clone())
}

pub async fn index_handler(
    db: Pool<Postgres>,
    templates: Handlebars<'_>,
    session_with_store: SessionWithStore<MemoryStore>,
) -> Result<HandlerReturn, warp::Rejection> {
    let (flash, session_with_store) = get_and_clear_flash(session_with_store);

    let current_username = get_current_username(&db, &session_with_store).await;

    let pages = match sqlx::query_as!(
        Page,
        "SELECT slug, title FROM pages \
        ORDER BY updated_at DESC \
        LIMIT 3",
    )
    .fetch_all(&db)
    .await
    {
        Ok(pages) => pages,
        Err(_) => {
            return Ok(error_html(
                "Unable to fetch recently updated pages",
                StatusCode::INTERNAL_SERVER_ERROR,
                &templates,
                session_with_store,
            ));
        }
    };

    let pages = match pages.len() {
        0 => None,
        _ => Some(pages),
    };

    let text = match templates.render(
        "index",
        &json!({ "flash": flash, "pages": pages, "current_username": current_username}),
    ) {
        Ok(text) => text,
        Err(e) => {
            format!("<html>Error rendering index template: {}</html>", e)
        }
    };

    Ok((
        Box::new(warp::reply::with_status(
            warp::reply::html(text),
            StatusCode::OK,
        )),
        session_with_store,
    ))
}
