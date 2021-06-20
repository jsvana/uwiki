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
use warp::http::{StatusCode, Uri};
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

fn error_html(
    message: &str,
    status_code: StatusCode,
    templates: &Handlebars,
    session_with_store: SessionWithStore<MemoryStore>,
) -> (Box<dyn warp::Reply>, SessionWithStore<MemoryStore>) {
    let text = match templates.render("error", &btreemap! { "error" => message }) {
        Ok(text) => text,
        Err(e) => {
            format!(
                "<html>Error: {} (hit \"{}\" while generating HTML)</html>",
                message, e
            )
        }
    };

    (
        Box::new(warp::reply::with_status(
            warp::reply::html(text),
            status_code,
        )),
        session_with_store,
    )
}

pub async fn index_handler(
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

pub async fn login_handler(
    templates: Handlebars<'_>,
    session_with_store: SessionWithStore<MemoryStore>,
) -> Result<(impl warp::Reply, SessionWithStore<MemoryStore>), warp::Rejection> {
    let flash = session_with_store.session.get::<String>("flash");

    let text = match templates.render("login", &btreemap! { "flash" => flash }) {
        Ok(text) => text,
        Err(e) => {
            format!("<html>Error: {}</html>", e)
        }
    };

    Ok((
        warp::reply::with_status(warp::reply::html(text), StatusCode::OK),
        session_with_store,
    ))
}

fn error_redirect(
    destination_uri: Uri,
    message: String,
    mut session_with_store: SessionWithStore<MemoryStore>,
) -> (Box<dyn warp::Reply>, SessionWithStore<MemoryStore>) {
    match session_with_store
        .session
        .insert("flash", message.to_string())
    {
        Ok(_) => (
            Box::new(warp::redirect(destination_uri)),
            session_with_store,
        ),
        Err(e) => (
            Box::new(warp::reply::html(format!(
                "<html>Internal error (failed to persist flash to session cookie): {}",
                e
            ))),
            session_with_store,
        ),
    }
}

macro_rules! value_or_error_redirect {
    ( $input:expr, $destination_uri:expr, $message:expr, $session:expr ) => {{
        match $input {
            Ok(v) => v,
            Err(e) => {
                return Ok(error_redirect(
                    $destination_uri,
                    format!("{}: {}", $message, e),
                    $session,
                ));
            }
        }
    }};
}

pub async fn authenticate_handler(
    request: uwiki_types::AuthenticateRequest,
    db: Pool<Postgres>,
    config: Config,
    mut session_with_store: SessionWithStore<MemoryStore>,
) -> Result<(Box<dyn warp::Reply>, SessionWithStore<MemoryStore>), warp::Rejection> {
    // TODO(jsvana): take template and redirect to login page with flash
    let mut tx = value_or_error_redirect!(
        db.begin().await,
        Uri::from_static("/login"),
        "Error authenticating",
        session_with_store
    );

    let user = value_or_error_redirect!(
        sqlx::query!(
            "SELECT id, password FROM users WHERE username = $1",
            request.username,
        )
        .fetch_one(&mut tx)
        .await,
        Uri::from_static("/login"),
        "Invalid username or password",
        session_with_store
    );

    if let Ok(false) | Err(_) = verify(request.password, &user.password) {
        return Ok(error_redirect(
            Uri::from_static("/login"),
            "Invalid username or password".to_string(),
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
        return Ok(error_redirect(
            Uri::from_static("/login"),
            format!("Internal error (failed to persist token to session): {}", e),
            session_with_store,
        ));
    }

    let now = value_or_error_redirect!(
        SystemTime::now().duration_since(UNIX_EPOCH),
        Uri::from_static("/login"),
        "Internal error (time went backwards)",
        session_with_store
    );

    let expiration: i32 = value_or_error_redirect!(
        (now + config.token_ttl).as_secs().try_into(),
        Uri::from_static("/login"),
        "Internal error (expiration timestamp too large)",
        session_with_store
    );

    if let Err(e) = sqlx::query!(
        "INSERT INTO tokens (user_id, token, expiration) VALUES ($1, $2, $3)",
        user.id,
        token,
        expiration,
    )
    .execute(&mut tx)
    .await
    {
        return Ok(error_redirect(
            Uri::from_static("/login"),
            format!("Internal error (error generating token): {}", e),
            session_with_store,
        ));
    }

    match tx.commit().await {
        Ok(_) => Ok((
            Box::new(warp::reply::html(
                "<html>Logged in successfully!</html>".to_string(),
            )),
            session_with_store,
        )),
        Err(e) => Ok(error_redirect(
            Uri::from_static("/login"),
            format!("Internal error (error persisting data): {}", e),
            session_with_store,
        )),
    }
}

pub async fn set_page_handler(
    tail: Tail,
    request: uwiki_types::SetPageRequest,
    db: Pool<Postgres>,
    templates: Handlebars<'_>,
    session_with_store: SessionWithStore<MemoryStore>,
) -> Result<(Box<dyn warp::Reply>, SessionWithStore<MemoryStore>), warp::Rejection> {
    let slug = tail.as_str().to_string();

    let token = match session_with_store.session.get::<String>("sid") {
        Some(token) => token,
        None => {
            return Ok(error_html(
                "Not logged in (can't claim a page without logging in)",
                StatusCode::FORBIDDEN,
                &templates,
                session_with_store,
            ));
        }
    };

    let mut tx = match db.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            return Ok(error_html(
                &format!("Error setting content: {}", e),
                StatusCode::INTERNAL_SERVER_ERROR,
                &templates,
                session_with_store,
            ));
        }
    };

    let user_id = match sqlx::query!(
        "SELECT user_id FROM tokens \
        WHERE token = $1 \
        AND expiration >= CAST(EXTRACT(epoch FROM CURRENT_TIMESTAMP) AS INTEGER)",
        token,
    )
    .fetch_one(&mut tx)
    .await
    {
        Ok(row) => row.user_id,
        Err(_) => {
            return Ok(error_html(
                "Invalid API token",
                StatusCode::INTERNAL_SERVER_ERROR,
                &templates,
                session_with_store,
            ));
        }
    };

    let page = match sqlx::query!(
        "SELECT owner_id, current_version FROM pages WHERE slug = $1",
        slug,
    )
    .fetch_one(&mut tx)
    .await
    {
        Ok(page) => page,
        Err(e) => {
            return Ok(error_html(
                &format!("Error getting page: {}", e),
                StatusCode::INTERNAL_SERVER_ERROR,
                &templates,
                session_with_store,
            ));
        }
    };

    if page.owner_id != user_id {
        return Ok(error_html(
            "Refusing to modify a page you do not own",
            StatusCode::FORBIDDEN,
            &templates,
            session_with_store,
        ));
    }

    if page.current_version != request.previous_version {
        return Ok(error_html(
            "Page has been updated since fetching. Refusing to update",
            StatusCode::INTERNAL_SERVER_ERROR,
            &templates,
            session_with_store,
        ));
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
                return Ok(error_html(
                    &format!("Error rendering page (failed to run Pandoc: {})", e),
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &templates,
                    session_with_store,
                ));
            }
        };

        match output {
            PandocOutput::ToBuffer(buffer) => buffer,
            _ => {
                return Ok(error_html(
                    "Malformed Pandoc response",
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &templates,
                    session_with_store,
                ));
            }
        }
    };

    if let Err(e) = sqlx::query!(
        r#"
        UPDATE pages
        SET
            title = $1,
            body = $2,
            rendered_body = $3,
            current_version = $4,
            updated_at = CURRENT_TIMESTAMP
        WHERE
            slug = $5"#,
        request.title,
        request.body,
        rendered_body,
        new_version,
        slug,
    )
    .execute(&mut tx)
    .await
    {
        return Ok(error_html(
            &format!("Error updating page: {}", e),
            StatusCode::INTERNAL_SERVER_ERROR,
            &templates,
            session_with_store,
        ));
    }

    let destination_uri: warp::http::Uri = match format!("/w/{}", slug).parse() {
        Ok(uri) => uri,
        Err(e) => {
            return Ok(error_html(
                &format!("Error parsing slug: {}", e),
                StatusCode::INTERNAL_SERVER_ERROR,
                &templates,
                session_with_store,
            ));
        }
    };

    match tx.commit().await {
        Ok(_) => Ok((
            Box::new(warp::redirect(destination_uri)),
            session_with_store,
        )),
        Err(e) => Ok(error_html(
            &format!("Error updating page: {}", e),
            StatusCode::INTERNAL_SERVER_ERROR,
            &templates,
            session_with_store,
        )),
    }
}

pub async fn get_page_handler(
    tail: Tail,
    db: Pool<Postgres>,
    session_with_store: SessionWithStore<MemoryStore>,
) -> Result<(impl warp::Reply, SessionWithStore<MemoryStore>), warp::Rejection> {
    let slug = tail.as_str().to_string();

    let token = match session_with_store.session.get::<String>("sid") {
        Some(token) => token,
        None => {
            return Ok((
                warp::reply::json(&uwiki_types::GetPageResponse::error(
                    "Not logged in (can't claim a page without logging in)".to_string(),
                )),
                session_with_store,
            ));
        }
    };

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
        token,
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
        slug,
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
        slug,
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

pub async fn edit_page_handler(
    tail: Tail,
    db: Pool<Postgres>,
    templates: Handlebars<'_>,
    session_with_store: SessionWithStore<MemoryStore>,
) -> Result<(Box<dyn warp::Reply>, SessionWithStore<MemoryStore>), warp::Rejection> {
    let slug = tail.as_str().to_string();

    let mut tx = match db.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            return Ok(error_html(
                &format!("Error communicating with database: {}", e),
                StatusCode::INTERNAL_SERVER_ERROR,
                &templates,
                session_with_store,
            ));
        }
    };

    let token = match session_with_store.session.get::<String>("sid") {
        Some(token) => token,
        None => {
            return Ok(error_html(
                "Not logged in (can't claim a page without logging in)",
                StatusCode::FORBIDDEN,
                &templates,
                session_with_store,
            ));
        }
    };

    let user_id = match sqlx::query!(
        "SELECT user_id FROM tokens \
        WHERE token = $1 \
        AND expiration >= CAST(EXTRACT(epoch FROM CURRENT_TIMESTAMP) AS INTEGER)",
        token,
    )
    .fetch_one(&mut tx)
    .await
    {
        Ok(row) => row.user_id,
        Err(_) => {
            return Ok(error_html(
                "Not logged in (can't claim a page without logging in)",
                StatusCode::FORBIDDEN,
                &templates,
                session_with_store,
            ));
        }
    };

    if let Err(e) = sqlx::query!(
        "INSERT INTO pages (owner_id, slug) VALUES ($1, $2) ON CONFLICT DO NOTHING",
        user_id,
        slug,
    )
    .execute(&mut tx)
    .await
    {
        return Ok(error_html(
            &format!("Error getting page: {}", e),
            StatusCode::NOT_FOUND,
            &templates,
            session_with_store,
        ));
    }

    let page = match sqlx::query!(
        "SELECT title, body, current_version FROM pages WHERE slug = $1",
        slug,
    )
    .fetch_one(&mut tx)
    .await
    {
        Ok(page) => page,
        Err(e) => {
            return Ok(error_html(
                &format!("Error getting page: {}", e),
                StatusCode::NOT_FOUND,
                &templates,
                session_with_store,
            ));
        }
    };

    if let Err(e) = tx.commit().await {
        return Ok(error_html(
            &format!("Error updating page: {}", e),
            StatusCode::INTERNAL_SERVER_ERROR,
            &templates,
            session_with_store,
        ));
    }

    let text = match templates.render(
        "edit",
        &btreemap! {
            "slug" => slug,
            "title" => page.title.unwrap_or_else(|| "".to_string()),
            "body" => page.body.unwrap_or_else(|| "".to_string()),
            "version" => page.current_version.to_string(),
        },
    ) {
        Ok(text) => text,
        Err(e) => {
            format!("<html>Error: {}</html>", e)
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

pub async fn render_handler(
    tail: Tail,
    db: Pool<Postgres>,
    templates: Handlebars<'_>,
    session_with_store: SessionWithStore<MemoryStore>,
) -> Result<(Box<dyn warp::Reply>, SessionWithStore<MemoryStore>), Infallible> {
    let page = match sqlx::query!(
        "SELECT title, rendered_body FROM pages WHERE slug = $1",
        tail.as_str()
    )
    .fetch_one(&db)
    .await
    {
        Ok(page) => page,
        Err(_) => {
            return Ok(error_html(
                "No such page",
                StatusCode::NOT_FOUND,
                &templates,
                session_with_store,
            ));
        }
    };

    let (title, rendered_body) = match (page.title, page.rendered_body) {
        (Some(title), Some(rendered_body)) => (title, rendered_body),
        (Some(_), None) => {
            return Ok(error_html(
                "Page is still being populated (has title, missing body)",
                StatusCode::NOT_FOUND,
                &templates,
                session_with_store,
            ));
        }
        (None, Some(rendered_body)) => (tail.as_str().to_string(), rendered_body),
        (None, None) => {
            return Ok(error_html(
                "Page is still being populated.",
                StatusCode::NOT_FOUND,
                &templates,
                session_with_store,
            ));
        }
    };

    let text = match templates.render(
        "wiki",
        &btreemap! { "title" => title, "body" => rendered_body },
    ) {
        Ok(text) => text,
        Err(e) => {
            format!("<html>Error: {}</html>", e)
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
