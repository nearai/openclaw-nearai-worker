FROM rust:1.93-bookworm AS builder

WORKDIR /app

COPY Cargo.toml Cargo.lock* ./

RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release && rm -rf src

ARG CACHEBUST=0
RUN echo "cachebust=$CACHEBUST"

COPY src ./src

RUN touch src/main.rs && cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/openclaw-oauth-service /app/openclaw-oauth-service

RUN mkdir -p /app/data

EXPOSE 47393

ENV RUST_LOG=info

CMD ["/app/openclaw-oauth-service"]
