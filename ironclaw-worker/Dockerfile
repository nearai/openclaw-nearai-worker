# IronClaw worker image for compose-api deployment.
#
# Downloads a prebuilt binary from GitHub releases:
#   docker build --build-arg IRONCLAW_VERSION=0.8.0 \
#     -t ironclaw-nearai-worker:local ironclaw-worker/

ARG IRONCLAW_VERSION=0.8.0

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

# Download prebuilt IronClaw binary from GitHub release
ARG IRONCLAW_VERSION
RUN curl -fsSL "https://github.com/nearai/ironclaw/releases/download/ironclaw-v${IRONCLAW_VERSION}/ironclaw-x86_64-unknown-linux-gnu.tar.gz" \
    | tar xz -C /usr/local/bin/ ironclaw

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
