FROM rust:1.52 as builder
WORKDIR /usr/src/uwiki

# Copy over only the files which specify dependencies
COPY Cargo.toml Cargo.lock ./

# We need to create a dummy main in order to get this to properly build.
RUN mkdir src && echo 'fn main() {}' > src/main.rs && cargo build --release

# Copy over the files to actually build the application.
COPY . .

ENV SQLX_OFFLINE true

# We need to make sure the update time on main.rs is newer than the temporary
# file or there are weird cargo caching issues we run into.
RUN touch src/main.rs && cargo build --release && cp -v target/release/uwiki /usr/local/bin

# Create a new base and copy in only what we need.
FROM debian:buster-slim
ENV RUST_LOG=info
ENV DATABASE_URL=
ENV WIKI_PAGE_TEMPLATE_PATH=
ENV ERROR_PAGE_TEMPLATE_PATH=
ENV TOKEN_TTL_SECONDS=604800
ENV BIND_ADDRESS=0.0.0.0:1181

WORKDIR /usr/src/uwiki
RUN apt-get update && apt-get install -y pandoc && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/bin/uwiki /usr/local/bin/uwiki
COPY --from=builder /usr/src/uwiki/assets /usr/src/uwiki/assets
CMD ["uwiki"]
