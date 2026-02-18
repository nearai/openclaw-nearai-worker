# IronClaw worker image for compose-api deployment.
#
# Requires BuildKit named contexts (ironclaw source provided externally):
#   docker buildx build \
#     --build-context ironclaw=./ironclaw \
#     -t ironclaw-nearai-worker:local \
#     openclaw-nearai-worker/ironclaw-worker/

# ── Stage 1: Build IronClaw with libSQL ──────────────────────────────
FROM rust:1.92-slim-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev cmake gcc g++ make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy manifests and build script for dependency caching
COPY --from=ironclaw Cargo.toml Cargo.lock* build.rs ./

# Stub workspace members and examples for dependency caching
# (ironclaw's Cargo.toml declares benchmarks as a workspace member)
COPY --from=ironclaw benchmarks/Cargo.toml benchmarks/Cargo.toml
RUN mkdir -p src examples benchmarks/src && \
    echo "fn main() {}" > src/main.rs && \
    echo "fn main() {}" > examples/test_heartbeat.rs && \
    echo "fn main() {}" > benchmarks/src/main.rs
RUN cargo build --release --no-default-features --features libsql --bin ironclaw 2>/dev/null || true
RUN rm -rf src examples benchmarks/src

# Bust cache for fresh code
ARG CACHEBUST=0
RUN echo "cachebust=$CACHEBUST"

# Copy actual source and WIT files (needed by wasmtime::component::bindgen!)
COPY --from=ironclaw src ./src
COPY --from=ironclaw wit ./wit

# Stub workspace members and examples that aren't needed for the binary build
RUN mkdir -p examples benchmarks/src && \
    echo "fn main() {}" > examples/test_heartbeat.rs && \
    echo "fn main() {}" > benchmarks/src/main.rs

# Build the real binary
RUN touch src/main.rs && \
    cargo build --release --no-default-features --features libsql --bin ironclaw

# ── Stage 2: Runtime ─────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      openssh-server \
      ca-certificates \
      libssl3 \
      curl \
      git \
      build-essential \
      python3 \
      jq \
      procps \
      vim \
      less \
      nano \
      sudo \
      login \
      && apt-get clean \
      && rm -rf /var/lib/apt/lists/*

# Copy IronClaw binary
COPY --from=builder /app/target/release/ironclaw /usr/local/bin/ironclaw

# Create non-root user (UID 1001, matching OpenClaw worker pattern)
RUN useradd -m -u 1001 -s /bin/bash agent && \
    echo "agent ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/agent

# Install Rust toolchain for agent user (available via SSH)
USER agent
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.92.0
USER root

# Configure SSH, directories, and agent environment
RUN mkdir -p /home/agent/.ssh /home/agent/ssh /home/agent/.ironclaw /home/agent/workspace && \
    chmod 700 /home/agent/.ssh && \
    printf '%s\n' '[ -n "$BASH_VERSION" ] && [ -f "$HOME/.bashrc" ] && . "$HOME/.bashrc"' > /home/agent/.profile && \
    echo 'source "$HOME/.cargo/env"' >> /home/agent/.bashrc && \
    chown -R agent:agent /home/agent

# Copy entrypoint and workspace bootstrap files
COPY entrypoint.sh /app/entrypoint.sh
COPY workspace/ /app/workspace/
RUN chmod +x /app/entrypoint.sh

WORKDIR /home/agent

# Expose gateway and SSH ports
EXPOSE 18789 2222

ENTRYPOINT ["/app/entrypoint.sh"]
