use handlebars::Handlebars;
use log::debug;
use serde_derive::Serialize;
use serde_json::json;
use sqlx::{Pool, Postgres};
use warp::http::{StatusCode, Uri};
use warp_sessions::{MemoryStore, SessionWithStore};

pub type HandlerReturn = (Box<dyn warp::Reply>, SessionWithStore<MemoryStore>);

pub fn error_html(
    message: &str,
    status_code: StatusCode,
    templates: &Handlebars,
    session_with_store: SessionWithStore<MemoryStore>,
) -> HandlerReturn {
    let (flash, session_with_store) = get_and_clear_flash(session_with_store);

    let text = match templates.render("error", &json!({ "error": message , "flash": flash })) {
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

#[derive(Serialize, sqlx::FromRow)]
pub struct Page {
    pub slug: String,
    pub title: Option<String>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct Image {
    pub slug: String,
    pub slug_with_extension: Option<String>,
    pub alt_text: Option<String>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct Revision {
    pub editor: String,
    pub version: i32,
    pub updated_at: Option<String>,
}

pub async fn get_current_username(
    db: &Pool<Postgres>,
    session_with_store: &SessionWithStore<MemoryStore>,
) -> Option<String> {
    let token = match session_with_store.session.get::<String>("sid") {
        Some(token) => token,
        None => {
            return None;
        }
    };

    match sqlx::query!(
        "SELECT users.username AS username \
        FROM tokens \
        LEFT JOIN users \
        ON users.id = tokens.user_id \
        WHERE token = $1 \
        AND expiration >= CAST(EXTRACT(epoch FROM CURRENT_TIMESTAMP) AS INTEGER)",
        token,
    )
    .fetch_one(db)
    .await
    {
        Ok(row) => Some(row.username),
        Err(_) => None,
    }
}

pub fn attempt_to_set_flash(
    message: &str,
    mut session_with_store: SessionWithStore<MemoryStore>,
) -> SessionWithStore<MemoryStore> {
    if let Err(e) = session_with_store.session.insert("flash", message) {
        debug!("Failed to set flash: {}", e);
    }

    session_with_store
}

pub fn get_and_clear_flash(
    mut session_with_store: SessionWithStore<MemoryStore>,
) -> (Option<String>, SessionWithStore<MemoryStore>) {
    let value = session_with_store.session.get("flash");
    session_with_store.session.remove("flash");

    (value, session_with_store)
}

pub fn error_redirect(
    destination_uri: Uri,
    message: String,
    mut session_with_store: SessionWithStore<MemoryStore>,
) -> HandlerReturn {
    session_with_store = attempt_to_set_flash(&message, session_with_store);

    (
        Box::new(warp::redirect::see_other(destination_uri)),
        session_with_store,
    )
}

#[macro_export]
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
