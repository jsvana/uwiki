FROM rust:1.52 as builder

RUN USER=root cargo new --bin uwiki-docker
WORKDIR ./uwiki-docker
COPY ./Cargo.toml ./Cargo.toml
ENV SQLX_OFFLINE true
RUN cargo build --release
RUN rm src/*.rs

ADD . ./

RUN rm ./target/release/deps/uwiki*
ENV SQLX_OFFLINE true
RUN cargo build --release

FROM debian:buster-slim
ARG APP=/usr/src/app
