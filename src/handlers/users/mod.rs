use std::convert::TryInto;
use std::iter;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use bcrypt::{hash, verify, DEFAULT_COST};
use handlebars::Handlebars;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use serde_json::json;
use sqlx::{Pool, Postgres};
use warp::http::{StatusCode, Uri};
use warp_sessions::{MemoryStore, SessionWithStore};

use crate::handlers::util::{
    attempt_to_set_flash, error_html, error_redirect, get_and_clear_flash, HandlerReturn, Image,
    Page, User, UserState,
};
use crate::{value_or_error_redirect, Config};

pub async fn render_create(
    templates: Handlebars<'_>,
    session_with_store: SessionWithStore<MemoryStore>,
) -> Result<HandlerReturn, warp::Rejection> {
    let text = match templates.render("users/create", &json!({})) {
        Ok(text) => text,
        Err(e) => {
            format!("<html>Error rendering new user template: {}</html>", e)
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

pub async fn create(
    request: uwiki_types::AddUserRequest,
    db: Pool<Postgres>,
    mut session_with_store: SessionWithStore<MemoryStore>,
) -> Result<HandlerReturn, warp::Rejection> {
    let hashed_password = value_or_error_redirect!(
        hash(request.password, DEFAULT_COST),
        Uri::from_static("/"),
        "Error hashing password",
        session_with_store
    );

    session_with_store = attempt_to_set_flash(
        &format!("Requested new user {}", request.username),
        session_with_store,
    );

    match sqlx::query!(
        "INSERT INTO users (username, password) VALUES ($1, $2)",
        request.username,
        hashed_password,
    )
    .execute(&db)
    .await
    {
        Ok(_) => Ok((
            Box::new(warp::redirect::see_other(Uri::from_static("/"))),
            session_with_store,
        )),
        Err(e) => Ok(error_redirect(
            Uri::from_static("/"),
            format!("Internal error (error persisting data): {}", e),
            session_with_store,
        )),
    }
}

async fn set_user_state(
    target_user_id: i32,
    target_state: UserState,
    db: Pool<Postgres>,
    templates: Handlebars<'_>,
    session_with_store: SessionWithStore<MemoryStore>,
) -> Result<HandlerReturn, warp::Rejection> {
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
            return Ok(error_redirect(
                Uri::from_static("/"),
                "Not logged in".to_string(),
                session_with_store,
            ));
        }
    };

    let admin = match sqlx::query!(
        "SELECT users.admin AS admin \
        FROM tokens \
        LEFT JOIN users \
        ON users.id = tokens.user_id \
        WHERE tokens.token = $1 \
        AND expiration >= CAST(EXTRACT(epoch FROM CURRENT_TIMESTAMP) AS INTEGER)",
        token,
    )
    .fetch_one(&mut tx)
    .await
    {
        Ok(row) => (row.admin),
        Err(_) => {
            return Ok(error_redirect(
                Uri::from_static("/"),
                "Not logged in".to_string(),
                session_with_store,
            ));
        }
    };

    if !admin {
        return Ok(error_redirect(
            Uri::from_static("/me"),
            "You do not have admin permissions".to_string(),
            session_with_store,
        ));
    }

    match sqlx::query!(
        "UPDATE users SET state = $1 WHERE id = $2",
        target_state.to_string(),
        target_user_id
    )
    .execute(&db)
    .await
    {
        Ok(_) => Ok((
            Box::new(warp::redirect::see_other(Uri::from_static("/me"))),
            session_with_store,
        )),
        Err(e) => Ok(error_redirect(
            Uri::from_static("/me"),
            format!("Internal error (error persisting data): {}", e),
            session_with_store,
        )),
    }
}

pub async fn approve(
    user_id: i32,
    db: Pool<Postgres>,
    templates: Handlebars<'_>,
    session_with_store: SessionWithStore<MemoryStore>,
) -> Result<HandlerReturn, warp::Rejection> {
    set_user_state(
        user_id,
        UserState::Active,
        db,
        templates,
        session_with_store,
    )
    .await
}

pub async fn reject(
    user_id: i32,
    db: Pool<Postgres>,
    templates: Handlebars<'_>,
    session_with_store: SessionWithStore<MemoryStore>,
) -> Result<HandlerReturn, warp::Rejection> {
    set_user_state(
        user_id,
        UserState::Rejected,
        db,
        templates,
        session_with_store,
    )
    .await
}

pub async fn render_login(
    templates: Handlebars<'_>,
    session_with_store: SessionWithStore<MemoryStore>,
) -> Result<(impl warp::Reply, SessionWithStore<MemoryStore>), warp::Rejection> {
    let (flash, session_with_store) = get_and_clear_flash(session_with_store);

    let text = match templates.render("users/login", &json!({ "flash": flash })) {
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

pub async fn login(
    request: uwiki_types::AuthenticateRequest,
    db: Pool<Postgres>,
    config: Config,
    mut session_with_store: SessionWithStore<MemoryStore>,
) -> Result<HandlerReturn, warp::Rejection> {
    let mut tx = value_or_error_redirect!(
        db.begin().await,
        Uri::from_static("/login"),
        "Error authenticating",
        session_with_store
    );

    let user = value_or_error_redirect!(
        sqlx::query!(
            "SELECT id, password, state FROM users WHERE username = $1",
            request.username,
        )
        .fetch_one(&mut tx)
        .await,
        Uri::from_static("/login"),
        "Invalid username or password",
        session_with_store
    );

    // TODO(jsvana): read UserState from DB instead of string
    if user.state != "active" {
        return Ok(error_redirect(
            Uri::from_static("/"),
            "Account not yet marked active".to_string(),
            session_with_store,
        ));
    }

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

    session_with_store = attempt_to_set_flash("Logged in successfully", session_with_store);

    match tx.commit().await {
        Ok(_) => Ok((
            Box::new(warp::redirect::see_other(Uri::from_static("/me"))),
            session_with_store,
        )),
        Err(e) => Ok(error_redirect(
            Uri::from_static("/login"),
            format!("Internal error (error persisting data): {}", e),
            session_with_store,
        )),
    }
}

pub async fn render(
    db: Pool<Postgres>,
    templates: Handlebars<'_>,
    session_with_store: SessionWithStore<MemoryStore>,
) -> Result<(Box<dyn warp::Reply>, SessionWithStore<MemoryStore>), warp::Rejection> {
    let (flash, session_with_store) = get_and_clear_flash(session_with_store);

    let token = match session_with_store.session.get::<String>("sid") {
        Some(token) => token,
        None => {
            return Ok(error_redirect(
                Uri::from_static("/"),
                "Not logged in".to_string(),
                session_with_store,
            ));
        }
    };

    let mut tx = match db.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            return Ok(error_html(
                &format!("Error generating user page: {}", e),
                StatusCode::INTERNAL_SERVER_ERROR,
                &templates,
                session_with_store,
            ));
        }
    };

    let (user_id, username, admin) = match sqlx::query!(
        "SELECT \
        users.id AS user_id, \
        users.username AS username, \
        users.admin AS admin \
        FROM tokens \
        LEFT JOIN users
        ON users.id = tokens.user_id
        WHERE token = $1 \
        AND expiration >= CAST(EXTRACT(epoch FROM CURRENT_TIMESTAMP) AS INTEGER)",
        token,
    )
    .fetch_one(&mut tx)
    .await
    {
        Ok(row) => (row.user_id, row.username, row.admin),
        Err(_) => {
            return Ok(error_redirect(
                Uri::from_static("/"),
                "Not logged in".to_string(),
                session_with_store,
            ));
        }
    };

    let pages = match sqlx::query_as!(
        Page,
        "SELECT slug, title FROM pages \
        WHERE owner_id = $1",
        user_id
    )
    .fetch_all(&db)
    .await
    {
        Ok(pages) => pages,
        Err(e) => {
            return Ok(error_html(
                &format!("Unable to fetch owned pages: {}", e),
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

    let images = match sqlx::query_as!(
        Image,
        "SELECT CONCAT(slug, '.', extension) AS slug_with_extension, slug, alt_text FROM images \
        WHERE owner_id = $1",
        user_id
    )
    .fetch_all(&db)
    .await
    {
        Ok(images) => images,
        Err(e) => {
            return Ok(error_html(
                &format!("Unable to fetch owned images: {}", e),
                StatusCode::INTERNAL_SERVER_ERROR,
                &templates,
                session_with_store,
            ));
        }
    };

    let images = match images.len() {
        0 => None,
        _ => Some(images),
    };

    let approvals = if admin {
        let approvals = match sqlx::query_as!(
            User,
            "SELECT \
            username, \
            id, \
            TO_CHAR(created_at, 'MM/DD/YYYY HH24:MI:SS') AS created_at \
            FROM users \
            WHERE state = 'pending' \
            ORDER BY created_at DESC",
        )
        .fetch_all(&mut tx)
        .await
        {
            Ok(approvals) => approvals,
            Err(e) => {
                return Ok(error_html(
                    &format!("Unable to fetch account approvals: {}", e),
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &templates,
                    session_with_store,
                ));
            }
        };

        match approvals.len() {
            0 => None,
            _ => Some(approvals),
        }
    } else {
        None
    };

    let text = match templates.render(
        "users/render",
        &json!({ "flash": flash, "pages": pages, "images": images, "approvals": approvals, "current_username": username}),
    ) {
        Ok(text) => text,
        Err(e) => {
            format!("<html>Error rendering user template: {}</html>", e)
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
