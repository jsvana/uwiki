use anyhow::Result;
use bytes::{Buf, BufMut};
use futures::TryStreamExt;
use handlebars::Handlebars;
use serde_json::json;
use sqlx::{Pool, Postgres};
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use warp::http::{StatusCode, Uri};
use warp::multipart::{FormData, Part};
use warp::path::Tail;
use warp_sessions::{MemoryStore, SessionWithStore};

use crate::handlers::util::{
    attempt_to_set_flash, error_html, error_redirect, get_and_clear_flash, get_current_username,
    HandlerReturn,
};
use crate::Config;

pub async fn render_create(
    templates: Handlebars<'_>,
    db: Pool<Postgres>,
    session_with_store: SessionWithStore<MemoryStore>,
) -> Result<(Box<dyn warp::Reply>, SessionWithStore<MemoryStore>), warp::Rejection> {
    let (flash, mut session_with_store) = get_and_clear_flash(session_with_store);

    let current_username = get_current_username(&db, &session_with_store).await;

    if let None = current_username {
        session_with_store =
            attempt_to_set_flash("Must be logged in to upload an image", session_with_store);

        return Ok((
            Box::new(warp::redirect::see_other(Uri::from_static("/login"))),
            session_with_store,
        ));
    }

    let text = match templates.render("upload_image", &json!({ "flash": flash })) {
        Ok(text) => text,
        Err(e) => {
            format!("<html>Error rendering upload_image template: {}</html>", e)
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

async fn read_into_vec(part: &mut Part, max_size: usize) -> Result<Vec<u8>, warp::Rejection> {
    let data = part
        .data()
        .await
        .ok_or_else(|| warp::reject::reject())?
        .map_err(|_| warp::reject::reject())?;

    let mut buf = data.take(max_size);
    let mut dest = vec![];

    dest.put(&mut buf);

    Ok(dest)
}

pub async fn create(
    form_data: FormData,
    db: Pool<Postgres>,
    templates: Handlebars<'_>,
    config: Config,
    session_with_store: SessionWithStore<MemoryStore>,
) -> Result<HandlerReturn, warp::Rejection> {
    let parts: Vec<Part> = form_data
        .try_collect()
        .await
        .map_err(|_| warp::reject::reject())?;

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
                &format!("Error creating new image: {}", e),
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

    let mut slug: Option<String> = None;
    let mut alt_text: Option<String> = None;
    let mut image_data: Option<Vec<u8>> = None;
    let mut extension: Option<String> = None;

    for mut part in parts {
        match part.name() {
            "slug" => {
                let data = read_into_vec(&mut part, 256).await?;

                slug = Some(
                    std::str::from_utf8(&data)
                        .map_err(|_| warp::reject::reject())?
                        .to_string(),
                );
            }
            "alt_text" => {
                let data = read_into_vec(&mut part, 512).await?;

                alt_text = Some(
                    std::str::from_utf8(&data)
                        .map_err(|_| warp::reject::reject())?
                        .to_string(),
                );
            }
            "file" => {
                extension = Some({
                    let content_type = part.content_type();
                    match content_type {
                        Some(file_type) if file_type.starts_with("image/") => {
                            let parts: Vec<&str> = file_type.split("/").collect();
                            parts
                                .get(1)
                                .ok_or_else(|| warp::reject::reject())?
                                .to_string()
                        }
                        _ => {
                            return Err(warp::reject::reject());
                        }
                    }
                });

                image_data = Some(read_into_vec(&mut part, 2_000_000).await?);
            }
            _ => {}
        }
    }

    // TODO(jsvana): add flashes for missing parameters
    let slug = slug.ok_or_else(|| warp::reject::reject())?;
    let alt_text = alt_text.ok_or_else(|| warp::reject::reject())?;
    let image_data = image_data.ok_or_else(|| warp::reject::reject())?;
    let extension = extension.ok_or_else(|| warp::reject::reject())?;

    let filename = config.image_path.join(format!("{}.{}", slug, extension));

    // TODO(jsvana): add flash for existing file
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(filename.clone())
        .await
        .map_err(|_| warp::reject::reject())?;

    file.write_all(&image_data)
        .await
        .map_err(|_| warp::reject::reject())?;

    if let Err(e) = sqlx::query!(
        r#"
        INSERT INTO images
        (owner_id, slug, extension, alt_text)
        VALUES
        ($1, $2, $3, $4)"#,
        user_id,
        slug,
        extension,
        alt_text,
    )
    .execute(&mut tx)
    .await
    {
        return Ok(error_html(
            &format!("Error creating image: {}", e),
            StatusCode::INTERNAL_SERVER_ERROR,
            &templates,
            session_with_store,
        ));
    }

    let session_with_store = attempt_to_set_flash("Image uploaded", session_with_store);

    match tx.commit().await {
        Ok(_) => Ok((
            Box::new(warp::redirect::see_other(Uri::from_static("/"))),
            session_with_store,
        )),
        Err(e) => Ok(error_html(
            &format!("Error creating image: {}", e),
            StatusCode::INTERNAL_SERVER_ERROR,
            &templates,
            session_with_store,
        )),
    }
}

pub async fn delete(
    tail: Tail,
    db: Pool<Postgres>,
    templates: Handlebars<'_>,
    config: Config,
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
                &format!("Error deleting image: {}", e),
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

    let extension = match sqlx::query!(
        r#"
        SELECT extension
        FROM images
        WHERE slug = $1 AND owner_id = $2"#,
        slug,
        user_id,
    )
    .fetch_one(&mut tx)
    .await
    {
        Ok(row) => row.extension,
        Err(e) => {
            return Ok(error_html(
                &format!("Error deleting image: {}", e),
                StatusCode::INTERNAL_SERVER_ERROR,
                &templates,
                session_with_store,
            ));
        }
    };

    if let Err(e) = sqlx::query!(
        r#"
        DELETE FROM images
        WHERE slug = $1 AND owner_id = $2"#,
        slug,
        user_id,
    )
    .execute(&mut tx)
    .await
    {
        return Ok(error_html(
            &format!("Error deleting image: {}", e),
            StatusCode::INTERNAL_SERVER_ERROR,
            &templates,
            session_with_store,
        ));
    }

    if let Err(e) =
        tokio::fs::remove_file(config.image_path.join(format!("{}.{}", slug, extension))).await
    {
        return Ok(error_html(
            &format!("Error removing image file: {}", e),
            StatusCode::INTERNAL_SERVER_ERROR,
            &templates,
            session_with_store,
        ));
    }

    session_with_store =
        attempt_to_set_flash(&format!("Deleted image {}", slug), session_with_store);

    match tx.commit().await {
        Ok(_) => Ok((
            Box::new(warp::redirect::see_other(Uri::from_static("/"))),
            session_with_store,
        )),
        Err(e) => Ok(error_html(
            &format!("Error deleting image: {}", e),
            StatusCode::INTERNAL_SERVER_ERROR,
            &templates,
            session_with_store,
        )),
    }
}
