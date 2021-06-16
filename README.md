# uwiki

A very small wiki that takes in Markdown and spits out HTML.

## Installation

Database setup (assumes `$DATABASE_URL` is set):
```
$ cargo install sqlx-cli
$ sqlx database create
$ sqlx migrate run
```

## Configuration

Configuration is done through environment variables.

**Required:**
* `DATABASE_URL`: database connection string
* `PAGE_TEMPLATE_PATH`: location of HTML template used to render wiki pages

**Optional**:
* `TOKEN_TTL_SECONDS`: number of seconds a login token is good for (defaults to one week)
* `BIND_ADDRESS`: IP and port to bind the server to (defaults to `0.0.0.0:1181`)

## License
[MIT](LICENSE.md)