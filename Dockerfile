FROM lukemathwalker/cargo-chef:0.1.24-alpha.0-rust-latest as planner
WORKDIR /app
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM lukemathwalker/cargo-chef:0.1.24-alpha.0-rust-latest as cacher
WORKDIR /app
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

FROM rust:1.54.0 as builder
WORKDIR /app
COPY . .
COPY --from=cacher /app/target target
COPY --from=cacher $CARGO_HOME $CARGO_HOME
RUN cargo build --release

FROM rust:1.54.0 as runtime
WORKDIR /app
COPY --from=builder /app/target/release/oauth2-proxy /usr/local/bin
ENTRYPOINT ["/usr/local/bin/oauth2-proxy"]
