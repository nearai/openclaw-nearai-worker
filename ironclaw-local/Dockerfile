# syntax=docker/dockerfile:1
#
# Local development image for IronClaw.
# Builds from source with BuildKit cache mounts for fast incremental rebuilds.
#
# Uses named build contexts (no assumptions about directory layout):
#   docker buildx build \
#     --build-context ironclaw=/path/to/ironclaw \
#     -f Dockerfile -t ironclaw:local .
#
# Or use ./run.sh build (handles contexts automatically).

# ── Stage 1: Build ────────────────────────────────────────────────────
FROM rust:1.92-slim-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev cmake gcc g++ \
    && rm -rf /var/lib/apt/lists/* \
    && rustup target add wasm32-wasip2 \
    && cargo install wasm-tools

WORKDIR /app

# Copy source from the ironclaw named context
COPY --from=ironclaw Cargo.toml Cargo.lock ./
COPY --from=ironclaw build.rs ./
COPY --from=ironclaw src/ src/
COPY --from=ironclaw tests/ tests/
COPY --from=ironclaw registry/ registry/
COPY --from=ironclaw channels-src/ channels-src/
COPY --from=ironclaw wit/ wit/

# BuildKit cache mounts: cargo registry, git deps, and target dir persist
# across builds. First build ~5min, subsequent rebuilds ~30s.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    cargo build --release --no-default-features --features libsql --bin ironclaw \
    && cp target/release/ironclaw /ironclaw

# ── Stage 2: Runtime ──────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    ca-certificates libssl3 curl jq procps sudo login \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Non-root user (UID 1001, matching ironclaw-worker)
RUN useradd -m -u 1001 -s /bin/bash agent && \
    echo "agent ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/agent

COPY --from=builder /ironclaw /usr/local/bin/ironclaw

# Entrypoint and workspace bootstrap from the default build context (this dir)
COPY entrypoint.sh /app/entrypoint.sh
COPY workspace/ /app/init/workspace/

RUN chmod +x /app/entrypoint.sh && \
    mkdir -p /home/agent/.ironclaw/channels /home/agent/workspace && \
    chown -R agent:agent /home/agent

WORKDIR /home/agent

EXPOSE 18789

ENTRYPOINT ["/app/entrypoint.sh"]
