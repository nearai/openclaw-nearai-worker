# Build stage
FROM rust:1.93-bookworm AS builder

WORKDIR /app

# Copy manifests and build script
COPY Cargo.toml Cargo.lock* build.rs ./

# Create dummy main.rs to cache dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Build dependencies only (cached layer)
RUN cargo build --release && rm -rf src

# Bust cache so COPY src gets fresh code (pass --build-arg CACHEBUST=$(date +%s) for local dev)
ARG CACHEBUST=0
RUN echo "cachebust=$CACHEBUST"

# Git commit for build metadata (git not available in Docker context)
ARG GIT_COMMIT=unknown
ENV GIT_COMMIT=${GIT_COMMIT}

# Copy actual source code
COPY src ./src

# Build the actual application
RUN touch src/main.rs && cargo build --release

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    libssl3 \
    && install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc \
    && chmod a+r /etc/apt/keyrings/docker.asc \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian bookworm stable" > /etc/apt/sources.list.d/docker.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends docker-ce-cli docker-compose-plugin iptables \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Static age binary — copied into worker containers at backup time so the
# tar|age|upload pipeline runs entirely inside the container
ARG AGE_VERSION=v1.2.1
RUN curl -fsSL "https://github.com/FiloSottile/age/releases/download/${AGE_VERSION}/age-${AGE_VERSION}-linux-amd64.tar.gz" \
    | tar xz -C /usr/local/bin --strip-components=1 age/age \
    && chmod 0755 /usr/local/bin/age

# Copy the binary from builder
COPY --from=builder /app/target/release/openclaw-compose-api /app/openclaw-compose-api

# Bundle the worker compose templates
COPY docker-compose.worker.yml /app/docker-compose.worker.yml
COPY docker-compose.ironclaw.yml /app/docker-compose.ironclaw.yml

# Create data and envs directories
RUN mkdir -p /app/data/envs

EXPOSE 8080

ENV RUST_LOG=info

CMD ["/app/openclaw-compose-api"]
