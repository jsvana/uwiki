mod handlers;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use handlebars::Handlebars;
use log::info;
use sqlx::postgres::PgPoolOptions;
use warp::http::{HeaderMap, HeaderValue};
use warp::Filter;
use warp_sessions::MemoryStore;

#[derive(Clone, Debug)]
pub struct Config {
    bind_address: SocketAddr,
    database_url: String,
    token_ttl: Duration,
    asset_template_path: PathBuf,
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
        asset_template_path: dotenv::var("ASSET_TEMPLATE_PATH")
            .context("Missing env var $ASSET_TEMPLATE_PATH")?
            .parse()
            .context("failed to parse ASSET_TEMPLATE_PATH")?,
    };

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&config.database_url)
        .await
        .context("failed to create Postgres connection pool")?;

    let templates = vec![
        "index",
        "login",
        "wiki",
        "edit",
        "error",
        "create",
        "upload_image",
        "user",
        "page_history",
    ];
    let mut handlebars = Handlebars::new();

    for template in templates {
        let path = config
            .asset_template_path
            .join(format!("{}.html.hbs", template));
        let page_template = std::fs::read_to_string(path.clone())
            .with_context(|| format!("failed to read {} template {:?}", template, path))?;
        handlebars
            .register_template_string(template, page_template)
            .with_context(|| format!("failed to register {} template", template))?;
    }

    let session_store = MemoryStore::new();

    let css = warp::path("css").and(warp::fs::dir("assets/css"));
    let images = warp::path("img").and(warp::fs::dir("assets/img"));

    let mut headers = HeaderMap::new();
    headers.insert("cache_control", HeaderValue::from_static("no-cache"));

    let index = warp::get()
        .and(warp::path::end())
        .and(handlers::with_db(pool.clone()))
        .and(handlers::with_templates(handlebars.clone()))
        .and(warp_sessions::request::with_session(
            session_store.clone(),
            None,
        ))
        .and_then(handlers::index_handler)
        .untuple_one()
        .and_then(warp_sessions::reply::with_session)
        .with(warp::reply::with::headers(headers.clone()));

    let add_user = warp::post()
        .and(warp::path("u"))
        .and(warp::body::content_length_limit(1024 * 16))
        .and(warp::body::json())
        .and(handlers::with_db(pool.clone()))
        .and_then(handlers::add_user_handler);

    let login = warp::get()
        .and(warp::path("login"))
        .and(handlers::with_templates(handlebars.clone()))
        .and(warp_sessions::request::with_session(
            session_store.clone(),
            None,
        ))
        .and_then(handlers::login_handler)
        .untuple_one()
        .and_then(warp_sessions::reply::with_session)
        .with(warp::reply::with::headers(headers.clone()));

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
        .and_then(warp_sessions::reply::with_session)
        .with(warp::reply::with::headers(headers.clone()));

    let render_wiki = warp::get()
        .and(warp::path("w"))
        .and(warp::path::tail())
        .and(handlers::with_db(pool.clone()))
        .and(handlers::with_templates(handlebars.clone()))
        .and(warp_sessions::request::with_session(
            session_store.clone(),
            None,
        ))
        .and_then(handlers::render_handler)
        .untuple_one()
        .and_then(warp_sessions::reply::with_session)
        .with(warp::reply::with::headers(headers.clone()));

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
        .and_then(warp_sessions::reply::with_session)
        .with(warp::reply::with::headers(headers.clone()));

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
        .and_then(warp_sessions::reply::with_session)
        .with(warp::reply::with::headers(headers.clone()));

    let set_page = warp::post()
        .and(warp::path("s"))
        .and(warp::path::tail())
        .and(warp::body::form())
        .and(handlers::with_db(pool.clone()))
        .and(handlers::with_templates(handlebars.clone()))
        .and(warp_sessions::request::with_session(
            session_store.clone(),
            None,
        ))
        .and_then(handlers::set_page_handler)
        .untuple_one()
        .and_then(warp_sessions::reply::with_session)
        .with(warp::reply::with::headers(headers.clone()));

    let create_page = warp::get()
        .and(warp::path("pages"))
        .and(warp::path("create"))
        .and(handlers::with_templates(handlebars.clone()))
        .and(handlers::with_db(pool.clone()))
        .and(warp_sessions::request::with_session(
            session_store.clone(),
            None,
        ))
        .and_then(handlers::create_page_handler)
        .untuple_one()
        .and_then(warp_sessions::reply::with_session)
        .with(warp::reply::with::headers(headers.clone()));

    let persist_new_page = warp::post()
        .and(warp::path("c"))
        .and(warp::body::form())
        .and(handlers::with_db(pool.clone()))
        .and(handlers::with_templates(handlebars.clone()))
        .and(warp_sessions::request::with_session(
            session_store.clone(),
            None,
        ))
        .and_then(handlers::persist_new_page_handler)
        .untuple_one()
        .and_then(warp_sessions::reply::with_session)
        .with(warp::reply::with::headers(headers.clone()));

    let upload_image = warp::get()
        .and(warp::path("images"))
        .and(warp::path("create"))
        .and(handlers::with_templates(handlebars.clone()))
        .and(handlers::with_db(pool.clone()))
        .and(warp_sessions::request::with_session(
            session_store.clone(),
            None,
        ))
        .and_then(handlers::upload_image_page_handler)
        .untuple_one()
        .and_then(warp_sessions::reply::with_session)
        .with(warp::reply::with::headers(headers.clone()));

    let persist_new_image = warp::post()
        .and(warp::path("ui"))
        .and(warp::filters::multipart::form())
        .and(handlers::with_db(pool.clone()))
        .and(handlers::with_templates(handlebars.clone()))
        .and(warp_sessions::request::with_session(
            session_store.clone(),
            None,
        ))
        .and_then(handlers::persist_new_image_handler)
        .untuple_one()
        .and_then(warp_sessions::reply::with_session)
        .with(warp::reply::with::headers(headers.clone()));

    let user = warp::get()
        .and(warp::path("me"))
        .and(handlers::with_db(pool.clone()))
        .and(handlers::with_templates(handlebars.clone()))
        .and(warp_sessions::request::with_session(
            session_store.clone(),
            None,
        ))
        .and_then(handlers::user_handler)
        .untuple_one()
        .and_then(warp_sessions::reply::with_session)
        .with(warp::reply::with::headers(headers.clone()));

    let delete_page = warp::post()
        .and(warp::path("pages"))
        .and(warp::path("delete"))
        .and(warp::path::tail())
        .and(handlers::with_db(pool.clone()))
        .and(handlers::with_templates(handlebars.clone()))
        .and(warp_sessions::request::with_session(
            session_store.clone(),
            None,
        ))
        .and_then(handlers::delete_page_handler)
        .untuple_one()
        .and_then(warp_sessions::reply::with_session)
        .with(warp::reply::with::headers(headers.clone()));

    let delete_image = warp::post()
        .and(warp::path("images"))
        .and(warp::path("delete"))
        .and(warp::path::tail())
        .and(handlers::with_db(pool.clone()))
        .and(handlers::with_templates(handlebars.clone()))
        .and(warp_sessions::request::with_session(
            session_store.clone(),
            None,
        ))
        .and_then(handlers::delete_image_handler)
        .untuple_one()
        .and_then(warp_sessions::reply::with_session)
        .with(warp::reply::with::headers(headers.clone()));

    let page_history = warp::get()
        .and(warp::path("pages"))
        .and(warp::path("history"))
        .and(warp::path::tail())
        .and(handlers::with_db(pool.clone()))
        .and(handlers::with_templates(handlebars.clone()))
        .and(warp_sessions::request::with_session(
            session_store.clone(),
            None,
        ))
        .and_then(handlers::page_history_handler)
        .untuple_one()
        .and_then(warp_sessions::reply::with_session)
        .with(warp::reply::with::headers(headers.clone()));

    info!("Starting server at {}", config.bind_address);

    warp::serve(
        css.or(images)
            .or(index)
            .or(login)
            .or(add_user)
            .or(authenticate)
            .or(render_wiki)
            .or(get_page)
            .or(edit_page)
            .or(set_page)
            .or(create_page)
            .or(persist_new_page)
            .or(upload_image)
            .or(persist_new_image)
            .or(user)
            .or(delete_page)
            .or(delete_image)
            .or(page_history),
    )
    .run(config.bind_address)
    .await;

    Ok(())
}
