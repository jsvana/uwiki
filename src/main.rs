use std::convert::Infallible;
use std::convert::TryInto;
use std::iter;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use bcrypt::{hash, verify, DEFAULT_COST};
use handlebars::Handlebars;
use log::info;
use maplit::btreemap;
use pandoc::{InputFormat, InputKind, OutputFormat, OutputKind, PandocOutput};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use sqlx::postgres::PgPoolOptions;
use sqlx::{Pool, Postgres};
use warp::http::StatusCode;
use warp::path::Tail;
use warp::Filter;

#[derive(Clone, Debug)]
pub struct Config {
    bind_address: SocketAddr,
    database_url: String,
    token_ttl: Duration,
    wiki_page_template_path: PathBuf,
    error_page_template_path: PathBuf,
}

pub async fn add_user_handler(
    request: uwiki_types::AddUserRequest,
    db: Pool<Postgres>,
) -> Result<impl warp::Reply, Infallible> {
    let hashed_password = match hash(request.password, DEFAULT_COST) {
        Ok(password) => password,
        Err(e) => {
            return Ok(warp::reply::json(&uwiki_types::AddUserResponse {
                success: false,
                message: format!("Error hashing password: {}", e),
            }));
        }
    };

    match sqlx::query!(
        "INSERT INTO users (username, password) VALUES ($1, $2)",
        request.username,
        hashed_password,
    )
    .execute(&db)
    .await
    {
        Ok(_) => Ok(warp::reply::json(&uwiki_types::AddUserResponse {
            success: true,
            message: format!("Added user {}", request.username),
        })),
        Err(e) => Ok(warp::reply::json(&uwiki_types::AddUserResponse {
            success: false,
            message: format!("Error adding user: {}", e),
        })),
    }
}

pub async fn authenticate_handler(
    request: uwiki_types::AuthenticateRequest,
    db: Pool<Postgres>,
    config: Config,
) -> Result<impl warp::Reply, Infallible> {
    let mut tx = match db.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            return Ok(warp::reply::json(
                &uwiki_types::AuthenticateResponse::error(format!("Error authenticating: {}", e)),
            ));
        }
    };

    let user = match sqlx::query!(
        "SELECT id, password FROM users WHERE username = $1",
        request.username,
    )
    .fetch_one(&mut tx)
    .await
    {
        Ok(user) => user,
        Err(_) => {
            return Ok(warp::reply::json(
                &uwiki_types::AuthenticateResponse::error(
                    "Invalid username or password".to_string(),
                ),
            ));
        }
    };

    if let Ok(false) | Err(_) = verify(request.password, &user.password) {
        return Ok(warp::reply::json(
            &uwiki_types::AuthenticateResponse::error("Invalid username or password".to_string()),
        ));
    }

    let token: String = {
        let mut rng = thread_rng();
        iter::repeat(())
            .map(|()| rng.sample(Alphanumeric))
            .map(char::from)
            .take(60)
            .collect()
    };

    let token = format!("lgn:{}", token);

    let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(timestamp) => timestamp,
        Err(_) => {
            return Ok(warp::reply::json(
                &uwiki_types::AuthenticateResponse::error(
                    "Internal error (time went backwards)".to_string(),
                ),
            ));
        }
    };

    let expiration: i32 = match (now + config.token_ttl).as_secs().try_into() {
        Ok(timestamp) => timestamp,
        Err(_) => {
            return Ok(warp::reply::json(
                &uwiki_types::AuthenticateResponse::error(
                    "Internal error (expiration timestamp too large)".to_string(),
                ),
            ));
        }
    };

    if let Err(e) = sqlx::query!(
        "INSERT INTO tokens (user_id, token, expiration) VALUES ($1, $2, $3)",
        user.id,
        token,
        expiration,
    )
    .execute(&mut tx)
    .await
    {
        return Ok(warp::reply::json(
            &uwiki_types::AuthenticateResponse::error(format!("Error generating token: {}", e)),
        ));
    }

    match tx.commit().await {
        Ok(_) => Ok(warp::reply::json(&uwiki_types::AuthenticateResponse {
            success: true,
            message: "Logged in successfully".to_string(),
            token: Some(token),
        })),
        Err(e) => Ok(warp::reply::json(
            &uwiki_types::AuthenticateResponse::error(format!("Error generating token: {}", e)),
        )),
    }
}

async fn set_page_handler(
    request: uwiki_types::SetPageRequest,
    db: Pool<Postgres>,
) -> Result<impl warp::Reply, Infallible> {
    let mut tx = match db.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            return Ok(warp::reply::json(&uwiki_types::SetPageResponse::error(
                format!("Error setting content: {}", e),
            )));
        }
    };

    let user_id = match sqlx::query!(
        "SELECT user_id FROM tokens \
        WHERE token = $1 \
        AND expiration >= CAST(EXTRACT(epoch FROM CURRENT_TIMESTAMP) AS INTEGER)",
        request.token,
    )
    .fetch_one(&mut tx)
    .await
    {
        Ok(row) => row.user_id,
        Err(_) => {
            return Ok(warp::reply::json(&uwiki_types::SetPageResponse::error(
                "Invalid API token".to_string(),
            )));
        }
    };

    let page = match sqlx::query!(
        "SELECT owner_id, current_version FROM pages WHERE slug = $1",
        request.slug,
    )
    .fetch_one(&mut tx)
    .await
    {
        Ok(page) => page,
        Err(e) => {
            return Ok(warp::reply::json(&uwiki_types::SetPageResponse::error(
                format!("Error getting page: {}", e),
            )));
        }
    };

    if page.owner_id != user_id {
        return Ok(warp::reply::json(&uwiki_types::SetPageResponse::error(
            "Refusing to modify page you do not own".to_string(),
        )));
    }

    if page.current_version != request.previous_version {
        return Ok(warp::reply::json(&uwiki_types::SetPageResponse::error(
            "Page has been updated since fetching. Refusing to update".to_string(),
        )));
    }

    let new_version = request.previous_version + 1;

    let rendered_body = {
        let mut doc = pandoc::new();
        doc.set_input_format(InputFormat::MarkdownGithub, Vec::new());
        doc.set_output_format(OutputFormat::Html, Vec::new());
        doc.set_input(InputKind::Pipe(request.body.clone()));
        doc.set_output(OutputKind::Pipe);
        let output = match doc.execute() {
            Ok(output) => output,
            Err(e) => {
                return Ok(warp::reply::json(&uwiki_types::SetPageResponse::error(
                    format!("Error rendering page (failed to run pandoc: {})", e),
                )));
            }
        };

        match output {
            PandocOutput::ToBuffer(buffer) => buffer,
            _ => {
                return Ok(warp::reply::json(&uwiki_types::SetPageResponse::error(
                    "Malformed Pandoc response".to_string(),
                )));
            }
        }
    };

    if let Err(e) = sqlx::query!(
        "UPDATE pages SET title = $1, body = $2, rendered_body = $3, current_version = $4 WHERE slug = $5",
        request.title,
        request.body,
        rendered_body,
        new_version,
        request.slug,
    )
    .execute(&mut tx)
    .await
    {
        return Ok(warp::reply::json(&uwiki_types::SetPageResponse::error(
            format!("Error updating page: {}", e),
        )));
    }

    match tx.commit().await {
        Ok(_) => Ok(warp::reply::json(&uwiki_types::SetPageResponse {
            success: true,
            message: "Updated successfully".to_string(),
            new_version: Some(new_version),
        })),
        Err(e) => Ok(warp::reply::json(&uwiki_types::SetPageResponse::error(
            format!("Error updating page: {}", e),
        ))),
    }
}

async fn get_page_handler(
    request: uwiki_types::GetPageRequest,
    db: Pool<Postgres>,
) -> Result<impl warp::Reply, Infallible> {
    let mut tx = match db.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            return Ok(warp::reply::json(&uwiki_types::GetPageResponse::error(
                format!("Error getting page: {}", e),
            )));
        }
    };

    let user_id = match sqlx::query!(
        "SELECT user_id FROM tokens \
        WHERE token = $1 \
        AND expiration >= CAST(EXTRACT(epoch FROM CURRENT_TIMESTAMP) AS INTEGER)",
        request.token,
    )
    .fetch_one(&mut tx)
    .await
    {
        Ok(row) => row.user_id,
        Err(_) => {
            return Ok(warp::reply::json(&uwiki_types::GetPageResponse::error(
                "Invalid API token (can't claim a page without an API token)".to_string(),
            )));
        }
    };

    if let Err(e) = sqlx::query!(
        "INSERT INTO pages (owner_id, slug) VALUES ($1, $2) ON CONFLICT DO NOTHING",
        user_id,
        request.slug,
    )
    .execute(&mut tx)
    .await
    {
        return Ok(warp::reply::json(&uwiki_types::GetPageResponse::error(
            format!("Error getting page: {}", e),
        )));
    }

    let page = match sqlx::query!(
        "SELECT title, body, current_version FROM pages WHERE slug = $1",
        request.slug,
    )
    .fetch_one(&mut tx)
    .await
    {
        Ok(page) => page,
        Err(e) => {
            return Ok(warp::reply::json(&uwiki_types::GetPageResponse::error(
                format!("Error getting page: {}", e),
            )));
        }
    };

    match tx.commit().await {
        Ok(_) => Ok(warp::reply::json(&uwiki_types::GetPageResponse {
            success: true,
            message: "paged fetched successfully".to_string(),
            title: page.title,
            body: page.body,
            version: Some(page.current_version),
        })),
        Err(e) => Ok(warp::reply::json(&uwiki_types::GetPageResponse::error(
            format!("Error updating page: {}", e),
        ))),
    }
}

fn error_html(message: &str, templates: &Handlebars) -> String {
    match templates.render("error_page", &btreemap! { "error" => "No such page" }) {
        Ok(text) => text,
        Err(e) => {
            format!(
                "<html>Error: {} (hit \"{}\" while generating HTML)</html>",
                message, e
            )
        }
    }
}

async fn render_handler(
    tail: Tail,
    db: Pool<Postgres>,
    templates: Handlebars<'_>,
) -> Result<impl warp::Reply, Infallible> {
    let page = match sqlx::query!(
        "SELECT title, rendered_body FROM pages WHERE slug = $1",
        tail.as_str()
    )
    .fetch_one(&db)
    .await
    {
        Ok(page) => page,
        Err(_) => {
            return Ok(warp::reply::with_status(
                warp::reply::html(error_html("No such page", &templates)),
                StatusCode::NOT_FOUND,
            ));
        }
    };

    let (title, rendered_body) = match (page.title, page.rendered_body) {
        (Some(title), Some(rendered_body)) => (title, rendered_body),
        (Some(_), None) => {
            return Ok(warp::reply::with_status(
                warp::reply::html(error_html(
                    "Page is still being populated (has title, missing body)",
                    &templates,
                )),
                StatusCode::NOT_FOUND,
            ));
        }
        (None, Some(rendered_body)) => (tail.as_str().to_string(), rendered_body),
        (None, None) => {
            return Ok(warp::reply::with_status(
                warp::reply::html(error_html("Page is still being populated.", &templates)),
                StatusCode::NOT_FOUND,
            ));
        }
    };

    let text = match templates.render(
        "wiki_page",
        &btreemap! { "title" => title, "body" => rendered_body },
    ) {
        Ok(text) => text,
        Err(e) => {
            format!("<html>Error: {}</html>", e)
        }
    };

    Ok(warp::reply::with_status(
        warp::reply::html(text),
        StatusCode::OK,
    ))
}

fn with_db(
    db: Pool<Postgres>,
) -> impl Filter<Extract = (Pool<Postgres>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || db.clone())
}

fn with_config(
    config: Config,
) -> impl Filter<Extract = (Config,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || config.clone())
}

fn with_templates(
    templates: Handlebars,
) -> impl Filter<Extract = (Handlebars,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || templates.clone())
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

    let wiki_page_template = std::fs::read_to_string(config.wiki_page_template_path.clone())
        .with_context(|| {
            format!(
                "failed to read wiki template {:?}",
                config.wiki_page_template_path
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
        .register_template_string("error_page", error_page_template)
        .context("failed to register error template")?;

    let add_user = warp::post()
        .and(warp::path("u"))
        .and(warp::body::content_length_limit(1024 * 16))
        .and(warp::body::json())
        .and(with_db(pool.clone()))
        .and_then(add_user_handler);

    let authenticate = warp::post()
        .and(warp::path("a"))
        .and(warp::body::content_length_limit(1024 * 16))
        .and(warp::body::json())
        .and(with_db(pool.clone()))
        .and(with_config(config.clone()))
        .and_then(authenticate_handler);

    let render_wiki = warp::get()
        .and(warp::path("w"))
        .and(warp::path::tail())
        .and(with_db(pool.clone()))
        .and(with_templates(handlebars))
        .and_then(render_handler);

    let get_page = warp::post()
        .and(warp::path("g"))
        .and(warp::body::content_length_limit(1024 * 16))
        .and(warp::body::json())
        .and(with_db(pool.clone()))
        .and_then(get_page_handler);

    let set_page = warp::post()
        .and(warp::path("s"))
        .and(warp::body::content_length_limit(1024 * 16))
        .and(warp::body::json())
        .and(with_db(pool))
        .and_then(set_page_handler);

    info!("Starting server at {}", config.bind_address);

    warp::serve(
        add_user
            .or(authenticate)
            .or(render_wiki)
            .or(get_page)
            .or(set_page),
    )
    .run(config.bind_address)
    .await;

    Ok(())
}
