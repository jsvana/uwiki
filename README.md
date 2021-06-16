# uwiki

A very small wiki that takes in Markdown and spits out HTML.

## Installation

Database setup (assumes `$DATABASE_URL` is set):
```
$ cargo install sqlx-cli
$ sqlx database create
$ sqlx migrate run
```

## License
[MIT](LICENSE.md)
