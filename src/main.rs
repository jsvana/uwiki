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
    image_path: PathBuf,
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
        image_path: dotenv::var("IMAGE_PATH")
            .context("Missing env var $IMAGE_PATH")?
            .parse()
            .context("failed to parse IMAGE_PATH")?,
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
        "new_user",
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
    let images = warp::path("img").and(warp::fs::dir(config.image_path.clone()));

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

    // Users
    let new_user_page = warp::get()
        .and(warp::path("users"))
        .and(warp::path("request"))
        .and(handlers::with_templates(handlebars.clone()))
        .and(warp_sessions::request::with_session(
            session_store.clone(),
            None,
        ))
        .and_then(handlers::users::render_create)
        .untuple_one()
        .and_then(warp_sessions::reply::with_session)
        .with(warp::reply::with::headers(headers.clone()));

    let request_new_user = warp::post()
        .and(warp::path("users"))
        .and(warp::path("request"))
        .and(warp::body::form())
        .and(handlers::with_db(pool.clone()))
        .and(warp_sessions::request::with_session(
            session_store.clone(),
            None,
        ))
        .and_then(handlers::users::create)
        .untuple_one()
        .and_then(warp_sessions::reply::with_session)
        .with(warp::reply::with::headers(headers.clone()));

    let approve_user = warp::post()
        .and(warp::path("users"))
        .and(warp::path::param())
        .and(warp::path("approve"))
        .and(handlers::with_db(pool.clone()))
        .and(handlers::with_templates(handlebars.clone()))
        .and(warp_sessions::request::with_session(
            session_store.clone(),
            None,
        ))
        .and_then(handlers::users::approve)
        .untuple_one()
        .and_then(warp_sessions::reply::with_session)
        .with(warp::reply::with::headers(headers.clone()));

    let reject_user = warp::post()
        .and(warp::path("users"))
        .and(warp::path::param())
        .and(warp::path("reject"))
        .and(handlers::with_db(pool.clone()))
        .and(handlers::with_templates(handlebars.clone()))
        .and(warp_sessions::request::with_session(
            session_store.clone(),
            None,
        ))
        .and_then(handlers::users::reject)
        .untuple_one()
        .and_then(warp_sessions::reply::with_session)
        .with(warp::reply::with::headers(headers.clone()));

    let login = warp::get()
        .and(warp::path("login"))
        .and(handlers::with_templates(handlebars.clone()))
        .and(warp_sessions::request::with_session(
            session_store.clone(),
            None,
        ))
        .and_then(handlers::users::render_login)
        .untuple_one()
        .and_then(warp_sessions::reply::with_session)
        .with(warp::reply::with::headers(headers.clone()));

    let authenticate = warp::post()
        .and(warp::path("login"))
        .and(warp::body::form())
        .and(handlers::with_db(pool.clone()))
        .and(handlers::with_config(config.clone()))
        .and(warp_sessions::request::with_session(
            session_store.clone(),
            None,
        ))
        .and_then(handlers::users::login)
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
        .and_then(handlers::users::render)
        .untuple_one()
        .and_then(warp_sessions::reply::with_session)
        .with(warp::reply::with::headers(headers.clone()));

    // Pages
    let create_page = warp::get()
        .and(warp::path("pages"))
        .and(warp::path("create"))
        .and(handlers::with_templates(handlebars.clone()))
        .and(handlers::with_db(pool.clone()))
        .and(warp_sessions::request::with_session(
            session_store.clone(),
            None,
        ))
        .and_then(handlers::pages::render_create)
        .untuple_one()
        .and_then(warp_sessions::reply::with_session)
        .with(warp::reply::with::headers(headers.clone()));

    let persist_new_page = warp::post()
        .and(warp::path("pages"))
        .and(warp::path("create"))
        .and(warp::body::form())
        .and(handlers::with_db(pool.clone()))
        .and(handlers::with_templates(handlebars.clone()))
        .and(warp_sessions::request::with_session(
            session_store.clone(),
            None,
        ))
        .and_then(handlers::pages::create)
        .untuple_one()
        .and_then(warp_sessions::reply::with_session)
        .with(warp::reply::with::headers(headers.clone()));

    let edit_page = warp::get()
        .and(warp::path("pages"))
        .and(warp::path("update"))
        .and(warp::path::tail())
        .and(handlers::with_db(pool.clone()))
        .and(handlers::with_templates(handlebars.clone()))
        .and(warp_sessions::request::with_session(
            session_store.clone(),
            None,
        ))
        .and_then(handlers::pages::render_update)
        .untuple_one()
        .and_then(warp_sessions::reply::with_session)
        .with(warp::reply::with::headers(headers.clone()));

    let set_page = warp::post()
        .and(warp::path("pages"))
        .and(warp::path("update"))
        .and(warp::path::tail())
        .and(warp::body::form())
        .and(handlers::with_db(pool.clone()))
        .and(handlers::with_templates(handlebars.clone()))
        .and(warp_sessions::request::with_session(
            session_store.clone(),
            None,
        ))
        .and_then(handlers::pages::update)
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
        .and_then(handlers::pages::render)
        .untuple_one()
        .and_then(warp_sessions::reply::with_session)
        .with(warp::reply::with::headers(headers.clone()));

    let get_page = warp::post()
        .and(warp::path("api"))
        .and(warp::path("pages"))
        .and(warp::path::tail())
        .and(handlers::with_db(pool.clone()))
        .and(warp_sessions::request::with_session(
            session_store.clone(),
            None,
        ))
        .and_then(handlers::pages::api_get)
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
        .and_then(handlers::pages::delete)
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
        .and_then(handlers::pages::history)
        .untuple_one()
        .and_then(warp_sessions::reply::with_session)
        .with(warp::reply::with::headers(headers.clone()));

    // Images
    let upload_image = warp::get()
        .and(warp::path("images"))
        .and(warp::path("create"))
        .and(handlers::with_templates(handlebars.clone()))
        .and(handlers::with_db(pool.clone()))
        .and(warp_sessions::request::with_session(
            session_store.clone(),
            None,
        ))
        .and_then(handlers::images::render_create)
        .untuple_one()
        .and_then(warp_sessions::reply::with_session)
        .with(warp::reply::with::headers(headers.clone()));

    let persist_new_image = warp::post()
        .and(warp::path("images"))
        .and(warp::path("create"))
        .and(warp::filters::multipart::form())
        .and(handlers::with_db(pool.clone()))
        .and(handlers::with_templates(handlebars.clone()))
        .and(handlers::with_config(config.clone()))
        .and(warp_sessions::request::with_session(
            session_store.clone(),
            None,
        ))
        .and_then(handlers::images::create)
        .untuple_one()
        .and_then(warp_sessions::reply::with_session)
        .with(warp::reply::with::headers(headers.clone()));

    let delete_image = warp::post()
        .and(warp::path("images"))
        .and(warp::path("delete"))
        .and(warp::path::tail())
        .and(handlers::with_db(pool.clone()))
        .and(handlers::with_templates(handlebars.clone()))
        .and(handlers::with_config(config.clone()))
        .and(warp_sessions::request::with_session(
            session_store.clone(),
            None,
        ))
        .and_then(handlers::images::delete)
        .untuple_one()
        .and_then(warp_sessions::reply::with_session)
        .with(warp::reply::with::headers(headers.clone()));

    info!("Starting server at {}", config.bind_address);

    warp::serve(
        css.or(images)
            .or(index)
            .or(login)
            .or(new_user_page)
            .or(request_new_user)
            .or(approve_user)
            .or(reject_user)
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
