use std::convert::Infallible;
use std::iter;

use anyhow::{Context, Result};
use log::debug;
use pandoc::{InputFormat, InputKind, OutputFormat, OutputKind, PandocOption, PandocOutput};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use serde_derive::{Deserialize, Serialize};
use sqlx::postgres::PgPoolOptions;
use sqlx::{Pool, Postgres};
use warp::http::StatusCode;
use warp::path::Tail;
use warp::Filter;

#[derive(Serialize)]
struct Token {
    token: String,
}

#[derive(Serialize)]
struct Error {
    message: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Credentials {
    username: String,
    password: String,
}

pub async fn authenticate_handler(
    credentials: Credentials,
    db: Pool<Postgres>,
) -> Result<impl warp::Reply, Infallible> {
    debug!("authenticate: {:?}", credentials);

    let id = match sqlx::query!(
        "SELECT id FROM users WHERE username = $1 AND hashed_password = $2",
        credentials.username,
        credentials.password
    )
    .fetch_one(&db)
    .await
    {
        Ok(user) => user.id,
        Err(_) => {
            return Ok(warp::reply::json(&Error {
                message: "Unknown username or password".to_string(),
            }));
        }
    };

    let token: String = {
        let mut rng = thread_rng();
        iter::repeat(())
            .map(|()| rng.sample(Alphanumeric))
            .map(char::from)
            .take(60)
            .collect()
    };

    let token = format!("lgn:{}", token);

    match sqlx::query!(
        "INSERT INTO tokens (user_id, token) VALUES ($1, $2)",
        id,
        token
    )
    .execute(&db)
    .await
    {
        Ok(_) => Ok(warp::reply::json(&Token { token })),
        Err(e) => Ok(warp::reply::json(&Error {
            message: format!("Error generating token: {}", e),
        })),
    }
}

async fn render_handler(tail: Tail, db: Pool<Postgres>) -> Result<impl warp::Reply, Infallible> {
    let page = match sqlx::query!(
        "SELECT title, body FROM pages WHERE slug = $1",
        tail.as_str()
    )
    .fetch_one(&db)
    .await
    {
        Ok(page) => page,
        Err(_) => {
            return Ok(warp::reply::with_status(
                warp::reply::html("<html>No such page</html>".to_string()),
                StatusCode::NOT_FOUND,
            ));
        }
    };

    let mut doc = pandoc::new();
    doc.set_variable("title", &page.title);
    // TODO(jsvana): config option?
    doc.add_option(PandocOption::Template("assets/template.html".into()));
    doc.set_input_format(InputFormat::Markdown, Vec::new());
    doc.set_output_format(OutputFormat::Html, Vec::new());
    doc.set_input(InputKind::Pipe(page.body));
    doc.set_output(OutputKind::Pipe);
    let output = match doc.execute() {
        Ok(output) => output,
        Err(_) => {
            return Ok(warp::reply::with_status(
                // TODO(jsvana): static page?
                warp::reply::html("<html>Error</html>".to_string()),
                StatusCode::INTERNAL_SERVER_ERROR,
            ));
        }
    };

    let buffer = match output {
        PandocOutput::ToBuffer(buffer) => buffer,
        _ => {
            return Ok(warp::reply::with_status(
                // TODO(jsvana): static page?
                warp::reply::html("<html>Error</html>".to_string()),
                StatusCode::INTERNAL_SERVER_ERROR,
            ));
        }
    };

    Ok(warp::reply::with_status(
        warp::reply::html(buffer),
        StatusCode::OK,
    ))
}

fn with_db(
    db: Pool<Postgres>,
) -> impl Filter<Extract = (Pool<Postgres>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || db.clone())
}

#[tokio::main]
async fn main() -> Result<()> {
    if std::env::var_os("RUST_LOG").is_none() {
        // Set `RUST_LOG=todos=debug` to see debug logs,
        // this only shows access logs.
        std::env::set_var("RUST_LOG", "todos=info");
    }
    pretty_env_logger::init();

    let database_url = dotenv::var("DATABASE_URL").context("Missing env var $DATABASE_URL")?;

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?;

    let authenticate = warp::post()
        .and(warp::path("authenticate"))
        .and(warp::body::content_length_limit(1024 * 16))
        .and(warp::body::json())
        .and(with_db(pool.clone()))
        .and_then(authenticate_handler);

    let render_wiki = warp::get()
        .and(warp::path("w"))
        .and(warp::path::tail())
        .and(with_db(pool))
        .and_then(render_handler);

    warp::serve(authenticate.or(render_wiki))
        .run(([127, 0, 0, 1], 3030))
        .await;

    Ok(())
}
