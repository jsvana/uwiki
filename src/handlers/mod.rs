use std::convert::Infallible;
use std::convert::TryInto;
use std::iter;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use bcrypt::{hash, verify, DEFAULT_COST};
use handlebars::Handlebars;
use maplit::btreemap;
use pandoc::{InputFormat, InputKind, OutputFormat, OutputKind, PandocOutput};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use sqlx::{Pool, Postgres};
use warp::http::StatusCode;
use warp::path::Tail;
use warp::Filter;
use warp_sessions::{MemoryStore, SessionWithStore};

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
    session_with_store: SessionWithStore<MemoryStore>,
) -> Result<(impl warp::Reply, SessionWithStore<MemoryStore>), warp::Rejection> {
    // TODO(jsvana): template? dynamic page list?
    Ok((
        warp::reply::with_status(
            warp::reply::html("<html>Welcome to uwiki!</html>"),
            StatusCode::OK,
        ),
        session_with_store,
    ))
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
    mut session_with_store: SessionWithStore<MemoryStore>,
) -> Result<(impl warp::Reply, SessionWithStore<MemoryStore>), warp::Rejection> {
    let mut tx = match db.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            return Ok((
                warp::reply::json(&uwiki_types::AuthenticateResponse::error(format!(
                    "Error authenticating: {}",
                    e
                ))),
                session_with_store,
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
            return Ok((
                warp::reply::json(&uwiki_types::AuthenticateResponse::error(
                    "Invalid username or password".to_string(),
                )),
                session_with_store,
            ));
        }
    };

    if let Ok(false) | Err(_) = verify(request.password, &user.password) {
        return Ok((
            warp::reply::json(&uwiki_types::AuthenticateResponse::error(
                "Invalid username or password".to_string(),
            )),
            session_with_store,
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

    if let Err(e) = session_with_store.session.insert("sid", token.clone()) {
        return Ok((
            warp::reply::json(&uwiki_types::AuthenticateResponse::error(format!(
                "Internal error (failed to persist token to session, {})",
                e
            ))),
            session_with_store,
        ));
    }

    let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(timestamp) => timestamp,
        Err(_) => {
            return Ok((
                warp::reply::json(&uwiki_types::AuthenticateResponse::error(
                    "Internal error (time went backwards)".to_string(),
                )),
                session_with_store,
            ));
        }
    };

    let expiration: i32 = match (now + config.token_ttl).as_secs().try_into() {
        Ok(timestamp) => timestamp,
        Err(_) => {
            return Ok((
                warp::reply::json(&uwiki_types::AuthenticateResponse::error(
                    "Internal error (expiration timestamp too large)".to_string(),
                )),
                session_with_store,
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
        return Ok((
            warp::reply::json(&uwiki_types::AuthenticateResponse::error(format!(
                "Error generating token: {}",
                e
            ))),
            session_with_store,
        ));
    }

    match tx.commit().await {
        Ok(_) => Ok((
            warp::reply::json(&uwiki_types::AuthenticateResponse {
                success: true,
                message: "Logged in successfully".to_string(),
                token: Some(token),
            }),
            session_with_store,
        )),
        Err(e) => Ok((
            warp::reply::json(&uwiki_types::AuthenticateResponse::error(format!(
                "Error generating token: {}",
                e
            ))),
            session_with_store,
        )),
    }
}

pub async fn set_page_handler(
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

pub async fn get_page_handler(
    request: uwiki_types::GetPageRequest,
    db: Pool<Postgres>,
    session_with_store: SessionWithStore<MemoryStore>,
) -> Result<(impl warp::Reply, SessionWithStore<MemoryStore>), warp::Rejection> {
    let mut tx = match db.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            return Ok((
                warp::reply::json(&uwiki_types::GetPageResponse::error(format!(
                    "Error getting page: {}",
                    e
                ))),
                session_with_store,
            ));
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
            return Ok((
                warp::reply::json(&uwiki_types::GetPageResponse::error(
                    "Invalid API token (can't claim a page without an API token)".to_string(),
                )),
                session_with_store,
            ));
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
        return Ok((
            warp::reply::json(&uwiki_types::GetPageResponse::error(format!(
                "Error getting page: {}",
                e
            ))),
            session_with_store,
        ));
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
            return Ok((
                warp::reply::json(&uwiki_types::GetPageResponse::error(format!(
                    "Error getting page: {}",
                    e
                ))),
                session_with_store,
            ));
        }
    };

    match tx.commit().await {
        Ok(_) => Ok((
            warp::reply::json(&uwiki_types::GetPageResponse {
                success: true,
                message: "paged fetched successfully".to_string(),
                title: page.title,
                body: page.body,
                version: Some(page.current_version),
            }),
            session_with_store,
        )),
        Err(e) => Ok((
            warp::reply::json(&uwiki_types::GetPageResponse::error(format!(
                "Error updating page: {}",
                e
            ))),
            session_with_store,
        )),
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

pub async fn render_handler(
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
