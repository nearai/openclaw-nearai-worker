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

# eMudhra intermediate CA key compromise (2026-10-20): bookworm has no fixed
# ca-certificates yet, so distrust the two roots the compromised intermediates
# chain to. Remove once Debian ships a fixed ca-certificates.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && sed -i -e 's|^mozilla/emSign_ECC_Root_CA_-_G3.crt$|!&|' \
       -e 's|^mozilla/Comodo_AAA_Services_root.crt$|!&|' /etc/ca-certificates.conf \
    && update-ca-certificates \
    && test ! -e /etc/ssl/certs/emSign_ECC_Root_CA_-_G3.pem \
    && test ! -e /etc/ssl/certs/Comodo_AAA_Services_root.pem \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/ironclaw-oauth-service /app/ironclaw-oauth-service

RUN mkdir -p /app/data

EXPOSE 47393

ENV RUST_LOG=info

CMD ["/app/ironclaw-oauth-service"]
