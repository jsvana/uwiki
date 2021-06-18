mod handlers;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use handlebars::Handlebars;
use log::info;
use sqlx::postgres::PgPoolOptions;
use warp::Filter;
use warp_sessions::{CookieOptions, MemoryStore, SameSiteCookieOption};

#[derive(Clone, Debug)]
pub struct Config {
    bind_address: SocketAddr,
    database_url: String,
    token_ttl: Duration,
    wiki_page_template_path: PathBuf,
    edit_page_template_path: PathBuf,
    error_page_template_path: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "info");
    }
    pretty_env_logger::init();

    let config = Config {
        bind_address: dotenv::var("BIND_ADDRESS")
            .unwrap_or_else(|_| "0.0.0.0:1181".to_string())
            .parse()
            .context("failed to parse BIND_ADDRESS")?,
        database_url: dotenv::var("DATABASE_URL").context("Missing env var $DATABASE_URL")?,
        token_ttl: Duration::from_secs(
            dotenv::var("TOKEN_TTL_SECONDS")
                .unwrap_or_else(|_| "604800".to_string()) // Defaults to one week
                .parse()
                .context("failed to parse TOKEN_TTL_SECONDS")?,
        ),
        wiki_page_template_path: dotenv::var("WIKI_PAGE_TEMPLATE_PATH")
            .context("Missing env var $WIKI_PAGE_TEMPLATE_PATH")?
            .parse()
            .context("failed to parse WIKI_PAGE_TEMPLATE_PATH")?,
        edit_page_template_path: dotenv::var("EDIT_PAGE_TEMPLATE_PATH")
            .context("Missing env var $EDIT_PAGE_TEMPLATE_PATH")?
            .parse()
            .context("failed to parse EDIT_PAGE_TEMPLATE_PATH")?,
        error_page_template_path: dotenv::var("ERROR_PAGE_TEMPLATE_PATH")
            .context("Missing env var $ERROR_PAGE_TEMPLATE_PATH")?
            .parse()
            .context("failed to parse ERROR_PAGE_TEMPLATE_PATH")?,
    };

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&config.database_url)
        .await
        .context("failed to create Postgres connection pool")?;

    // TODO(jsvana): make template config a dir and assume specific files exist
    let wiki_page_template = std::fs::read_to_string(config.wiki_page_template_path.clone())
        .with_context(|| {
            format!(
                "failed to read wiki template {:?}",
                config.wiki_page_template_path
            )
        })?;
    let edit_page_template = std::fs::read_to_string(config.edit_page_template_path.clone())
        .with_context(|| {
            format!(
                "failed to read edit template {:?}",
                config.edit_page_template_path
            )
        })?;
    let error_page_template = std::fs::read_to_string(config.error_page_template_path.clone())
        .with_context(|| {
            format!(
                "failed to read error template {:?}",
                config.error_page_template_path
            )
        })?;

    let mut handlebars = Handlebars::new();
    handlebars
        .register_template_string("wiki_page", wiki_page_template)
        .context("failed to register wiki template")?;
    handlebars
        .register_template_string("edit_page", edit_page_template)
        .context("failed to register edit template")?;
    handlebars
        .register_template_string("error_page", error_page_template)
        .context("failed to register error template")?;

    let session_store = MemoryStore::new();

    let index = warp::get()
        .and(warp::path::end())
        .and(warp_sessions::request::with_session(
            session_store.clone(),
            Some(CookieOptions {
                cookie_name: "sid",
                cookie_value: None,
                max_age: None,
                domain: None,
                path: None,
                secure: false,
                http_only: true,
                same_site: Some(SameSiteCookieOption::Strict),
            }),
        ))
        .and_then(handlers::index_handler)
        .untuple_one()
        .and_then(warp_sessions::reply::with_session);

    let add_user = warp::post()
        .and(warp::path("u"))
        .and(warp::body::content_length_limit(1024 * 16))
        .and(warp::body::json())
        .and(handlers::with_db(pool.clone()))
        .and_then(handlers::add_user_handler);

    let login = warp::get()
        .and(warp::path("login"))
        .and(warp_sessions::request::with_session(
            session_store.clone(),
            None,
        ))
        .and_then(handlers::login_handler)
        .untuple_one()
        .and_then(warp_sessions::reply::with_session);

    let authenticate = warp::post()
        .and(warp::path("a"))
        .and(warp::body::form())
        .and(handlers::with_db(pool.clone()))
        .and(handlers::with_config(config.clone()))
        .and(warp_sessions::request::with_session(
            session_store.clone(),
            None,
        ))
        .and_then(handlers::authenticate_handler)
        .untuple_one()
        .and_then(warp_sessions::reply::with_session);

    let render_wiki = warp::get()
        .and(warp::path("w"))
        .and(warp::path::tail())
        .and(handlers::with_db(pool.clone()))
        .and(handlers::with_templates(handlebars.clone()))
        .and_then(handlers::render_handler);

    let get_page = warp::post()
        .and(warp::path("g"))
        .and(warp::path::tail())
        .and(handlers::with_db(pool.clone()))
        .and(warp_sessions::request::with_session(
            session_store.clone(),
            None,
        ))
        .and_then(handlers::get_page_handler)
        .untuple_one()
        .and_then(warp_sessions::reply::with_session);

    let edit_page = warp::get()
        .and(warp::path("e"))
        .and(warp::path::tail())
        .and(handlers::with_db(pool.clone()))
        .and(handlers::with_templates(handlebars.clone()))
        .and(warp_sessions::request::with_session(
            session_store.clone(),
            None,
        ))
        .and_then(handlers::edit_page_handler)
        .untuple_one()
        .and_then(warp_sessions::reply::with_session);

    let set_page = warp::post()
        .and(warp::path("s"))
        .and(warp::path::tail())
        .and(warp::body::form())
        .and(handlers::with_db(pool))
        .and(handlers::with_templates(handlebars.clone()))
        .and(warp_sessions::request::with_session(session_store, None))
        .and_then(handlers::set_page_handler)
        .untuple_one()
        .and_then(warp_sessions::reply::with_session);

    info!("Starting server at {}", config.bind_address);

    warp::serve(
        index
            .or(login)
            .or(add_user)
            .or(authenticate)
            .or(render_wiki)
            .or(get_page)
            .or(edit_page)
            .or(set_page),
    )
    .run(config.bind_address)
    .await;

    Ok(())
}
