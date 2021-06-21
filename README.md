# uwiki

A very small wiki that takes in Markdown and spits out HTML.

## Installation

Database setup (assumes `$DATABASE_URL` is set):
```
$ cargo install sqlx-cli
$ sqlx database create
$ sqlx migrate run
$ cargo sqlx prepare -- --bin uwiki
```

## Configuration

Configuration is done through environment variables.

**Required:**
* `DATABASE_URL`: database connection string
* `ASSET_TEMPLATE_PATH`: location of directory containing HTML templated pages
* `IMAGE_PATH`: location of directory where images will be persisted

**Optional**:
* `TOKEN_TTL_SECONDS`: number of seconds a login token is good for (defaults to one week)
* `BIND_ADDRESS`: IP and port to bind the server to (defaults to `0.0.0.0:1181`)

## Required HTML template pages

* `index.html.hbs`: Main page
* `login.html.hbs`: Login page
* `wiki.html.hbs`: Single wiki page
* `error.html.hbs`: Page shown when the server hits an error
* `edit.html.hbs`: Wiki editor page
* `create.html.hbs`: New page creation
* `page_history.html.hbs`: Page history
* `upload_image.html.hbs`: New image creation
* `user.html.hbs`: User homepage

## License
[MIT](LICENSE.md)
