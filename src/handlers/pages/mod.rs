use std::convert::Infallible;

use anyhow::Result;
use handlebars::Handlebars;
use pandoc::{InputFormat, InputKind, OutputFormat, OutputKind, PandocOutput};
use serde_json::json;
use sqlx::{Pool, Postgres};
use warp::http::{StatusCode, Uri};
use warp::path::Tail;
use warp_sessions::{MemoryStore, SessionWithStore};

use crate::handlers::util::{
    attempt_to_set_flash, error_html, error_redirect, get_and_clear_flash, get_current_username,
    HandlerReturn, Revision,
};

pub async fn render_create(
    templates: Handlebars<'_>,
    db: Pool<Postgres>,
    session_with_store: SessionWithStore<MemoryStore>,
) -> Result<(Box<dyn warp::Reply>, SessionWithStore<MemoryStore>), warp::Rejection> {
    let (flash, mut session_with_store) = get_and_clear_flash(session_with_store);

    let current_username = get_current_username(&db, &session_with_store).await;

    if let None = current_username {
        session_with_store =
            attempt_to_set_flash("Must be logged in to create a page", session_with_store);

        return Ok((
            Box::new(warp::redirect::see_other(Uri::from_static("/login"))),
            session_with_store,
        ));
    }

    let text = match templates.render("create", &json!({ "flash": flash })) {
        Ok(text) => text,
        Err(e) => {
            format!("<html>Error rendering create template: {}</html>", e)
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
    request: uwiki_types::CreatePageRequest,
    db: Pool<Postgres>,
    templates: Handlebars<'_>,
    session_with_store: SessionWithStore<MemoryStore>,
) -> Result<HandlerReturn, warp::Rejection> {
    let token = match session_with_store.session.get::<String>("sid") {
        Some(token) => token,
        None => {
            return Ok(error_redirect(
                Uri::from_static("/login"),
                "Not logged in".to_string(),
                session_with_store,
            ));
        }
    };

    let mut tx = match db.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            // TODO(jsvana): should these be redirects w/ flashes instead?
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
            return Ok(error_redirect(
                Uri::from_static("/login"),
                "Not logged in".to_string(),
                session_with_store,
            ));
        }
    };

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
        INSERT INTO pages
        (owner_id, slug, title, body, rendered_body, updated_at)
        VALUES
        ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP)"#,
        user_id,
        request.slug,
        request.title,
        request.body,
        rendered_body,
    )
    .execute(&mut tx)
    .await
    {
        return Ok(error_html(
            &format!("Error adding page: {}", e),
            StatusCode::INTERNAL_SERVER_ERROR,
            &templates,
            session_with_store,
        ));
    }

    let destination_uri: warp::http::Uri = match format!("/w/{}", request.slug).parse() {
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
            Box::new(warp::redirect::see_other(destination_uri)),
            session_with_store,
        )),
        Err(e) => Ok(error_html(
            &format!("Error creating page: {}", e),
            StatusCode::INTERNAL_SERVER_ERROR,
            &templates,
            session_with_store,
        )),
    }
}

pub async fn render(
    tail: Tail,
    db: Pool<Postgres>,
    templates: Handlebars<'_>,
    session_with_store: SessionWithStore<MemoryStore>,
) -> Result<HandlerReturn, Infallible> {
    let slug = tail.as_str().to_string();

    let page = match sqlx::query!(
        "SELECT title, rendered_body FROM pages WHERE slug = $1",
        slug
    )
    .fetch_one(&db)
    .await
    {
        Ok(page) => page,
        Err(_) => {
            // TODO(jsvana): add "missing" template with "create" button
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

    let (flash, session_with_store) = get_and_clear_flash(session_with_store);
    let current_username = get_current_username(&db, &session_with_store).await;

    let text = match templates.render(
        "wiki",
        &json!({ "title": title, "body": rendered_body, "slug": slug, "current_username": current_username, "flash": flash }),
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

pub async fn render_update(
    tail: Tail,
    db: Pool<Postgres>,
    templates: Handlebars<'_>,
    session_with_store: SessionWithStore<MemoryStore>,
) -> Result<HandlerReturn, warp::Rejection> {
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

            return Ok(error_redirect(
                destination_uri,
                "Not logged in".to_string(),
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

            return Ok(error_redirect(
                destination_uri,
                "Not logged in".to_string(),
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
        &json!({
            "slug": slug,
            "title": page.title.unwrap_or_else(|| "".to_string()),
            "body": page.body.unwrap_or_else(|| "".to_string()),
            "version": page.current_version.to_string(),
        }),
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

pub async fn update(
    tail: Tail,
    request: uwiki_types::SetPageRequest,
    db: Pool<Postgres>,
    templates: Handlebars<'_>,
    session_with_store: SessionWithStore<MemoryStore>,
) -> Result<HandlerReturn, warp::Rejection> {
    let slug = tail.as_str().to_string();

    let token = match session_with_store.session.get::<String>("sid") {
        Some(token) => token,
        None => {
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

            return Ok(error_redirect(
                destination_uri,
                "Not logged in".to_string(),
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
        "SELECT current_version, body FROM pages WHERE slug = $1",
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
        INSERT INTO page_revisions
        (slug, editor_id, version, body)
        VALUES
        ($1, $2, $3, $4)"#,
        slug,
        user_id,
        page.current_version,
        page.body,
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
            Box::new(warp::redirect::see_other(destination_uri)),
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

pub async fn api_get(
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

pub async fn history(
    tail: Tail,
    db: Pool<Postgres>,
    templates: Handlebars<'_>,
    session_with_store: SessionWithStore<MemoryStore>,
) -> Result<HandlerReturn, warp::Rejection> {
    let slug = tail.as_str().to_string();

    let revisions = match sqlx::query_as!(
        Revision,
        "SELECT \
            users.username AS editor, \
            page_revisions.version AS version, \
            TO_CHAR(page_revisions.updated_at, 'MM/DD/YYYY HH24:MI:SS') AS updated_at \
        FROM page_revisions \
        LEFT JOIN users
        ON users.id = page_revisions.editor_id
        WHERE slug = $1 \
        ORDER BY updated_at DESC",
        slug,
    )
    .fetch_all(&db)
    .await
    {
        Ok(revisions) => revisions,
        Err(_) => {
            return Ok(error_html(
                "Unable to fetch page history",
                StatusCode::INTERNAL_SERVER_ERROR,
                &templates,
                session_with_store,
            ));
        }
    };

    let revisions = match revisions.len() {
        0 => None,
        _ => Some(revisions),
    };

    let text = match templates.render(
        "page_history",
        &json!({ "slug": slug, "revisions": revisions }),
    ) {
        Ok(text) => text,
        Err(e) => {
            format!("<html>Error rendering page history template: {}</html>", e)
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

pub async fn delete(
    tail: Tail,
    db: Pool<Postgres>,
    templates: Handlebars<'_>,
    mut session_with_store: SessionWithStore<MemoryStore>,
) -> Result<HandlerReturn, warp::Rejection> {
    let slug = tail.as_str().to_string();

    let token = match session_with_store.session.get::<String>("sid") {
        Some(token) => token,
        None => {
            return Ok(error_redirect(
                Uri::from_static("/login"),
                "Not logged in".to_string(),
                session_with_store,
            ));
        }
    };

    let mut tx = match db.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            // TODO(jsvana): should these be redirects w/ flashes instead?
            return Ok(error_html(
                &format!("Error deleting page: {}", e),
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
            return Ok(error_redirect(
                Uri::from_static("/login"),
                "Not logged in".to_string(),
                session_with_store,
            ));
        }
    };

    if let Err(e) = sqlx::query!(
        r#"
        DELETE FROM pages
        WHERE slug = $1 AND owner_id = $2"#,
        slug,
        user_id,
    )
    .execute(&mut tx)
    .await
    {
        return Ok(error_html(
            &format!("Error deleting page: {}", e),
            StatusCode::INTERNAL_SERVER_ERROR,
            &templates,
            session_with_store,
        ));
    }

    session_with_store =
        attempt_to_set_flash(&format!("Deleted page {}", slug), session_with_store);

    match tx.commit().await {
        Ok(_) => Ok((
            Box::new(warp::redirect::see_other(Uri::from_static("/"))),
            session_with_store,
        )),
        Err(e) => Ok(error_html(
            &format!("Error deleting page: {}", e),
            StatusCode::INTERNAL_SERVER_ERROR,
            &templates,
            session_with_store,
        )),
    }
}
