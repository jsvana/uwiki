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

**Optional**:
* `TOKEN_TTL_SECONDS`: number of seconds a login token is good for (defaults to one week)
* `BIND_ADDRESS`: IP and port to bind the server to (defaults to `0.0.0.0:1181`)

## Required HTML template pages

* `login.html`: Login page
* `wiki.html`: Single wiki page
* `error.html`: Page shown when the server hits an error
* `edit.html`: Wiki editor page

## License
[MIT](LICENSE.md)
