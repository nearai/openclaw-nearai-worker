FROM node:24-bookworm@sha256:b2b2184ba9b78c022e1d6a7924ec6fba577adf28f15c9d9c457730cc4ad3807a

# Install system dependencies and tools for OpenClaw agent execution (Node.js already in base image)
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      openssl \
      openssh-server \
      curl \
      ca-certificates \
      gettext-base \
      git \
      wget \
      build-essential \
      python3 \
      python3-pip \
      jq \
      netcat-traditional \
      iputils-ping \
      procps \
      vim \
      unzip \
      zip \
      tar \
      gzip \
      bzip2 \
      xz-utils \
      sed \
      mawk \
      grep \
      dnsutils \
      strace \
      lsof \
      rsync \
      less \
      nano \
      file \
      login \
      sudo && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*

# Create non-root user for OpenClaw agents
# Use UID 1001 to avoid conflict with default UID 1000
RUN useradd -m -u 1001 -s /bin/bash agent && \
    echo "agent ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/agent

# Global shell for the image (matches agent login shell; used by pnpm setup etc.)
ENV SHELL=/bin/bash

# Install Homebrew as the agent user (non-interactive mode)
# Create the Homebrew directory structure and set ownership before installation
USER root
RUN mkdir -p /home/linuxbrew/.linuxbrew && \
    chown -R agent:agent /home/linuxbrew

# Switch to agent user and install Homebrew
# The installer detects Docker environment and runs non-interactively
USER agent
RUN curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh | bash

# Switch back to root for remaining setup
USER root

# Configure SSH server, directories, brew, pnpm home, and npm for agent user
RUN mkdir -p /home/agent/.ssh /home/agent/ssh /home/agent/.openclaw /home/agent/openclaw /home/agent/.npm-global /home/agent/.local/share/pnpm && \
    ssh-keygen -t ed25519 -f /home/agent/ssh/ssh_host_ed25519_key -N "" && \
    chmod 700 /home/agent/.ssh && \
    printf '%s\n' '[ -n "$BASH_VERSION" ] && [ -f "$HOME/.bashrc" ] && . "$HOME/.bashrc"' > /home/agent/.profile && \
    echo 'eval "$(/home/linuxbrew/.linuxbrew/bin/brew shellenv)"' >> /home/agent/.bashrc && \
    echo 'export PATH="/home/agent/.npm-global/bin:${PATH}"' >> /home/agent/.bashrc && \
    ln -s /home/linuxbrew/.linuxbrew/bin/brew /usr/local/bin/brew && \
    chmod +x /usr/local/bin/brew && \
    chown -R agent:agent /home/agent

# Install pnpm, bun, and OpenClaw as agent user so they go to /home/agent/.npm-global/bin
# This ensures they are in the agent user's PATH (npm config is set in the same RUN instruction below)
USER agent
RUN npm config set prefix "/home/agent/.npm-global" && \
    npm install -g pnpm bun openclaw@2026.2.1 && \
    /home/agent/.npm-global/bin/pnpm setup

# Workaround: NEAR AI streaming bug truncates tool call arguments.
# pi-ai hardcodes stream:true with no config override (openclaw#12218).
# This patch replaces the streaming API call with non-streaming, then synthesizes
# the stream events that openclaw expects. Tool call args arrive complete.
COPY --chown=agent:agent patch-streaming.js /tmp/patch-streaming.js
RUN node /tmp/patch-streaming.js && rm /tmp/patch-streaming.js
# Verify patch applied correctly — fail build if markers are missing
RUN grep -q 'nonStreamParams' /home/agent/.npm-global/lib/node_modules/openclaw/node_modules/@mariozechner/pi-ai/dist/providers/openai-completions.js \
    && grep -q 'stream: false' /home/agent/.npm-global/lib/node_modules/openclaw/node_modules/@mariozechner/pi-ai/dist/providers/openai-completions.js \
    && echo "patch-streaming: verification passed" \
    || (echo "patch-streaming: verification FAILED — patched markers not found" >&2 && exit 1)

# Switch back to root for final setup
USER root

# Copy entrypoint script, config template, and workspace bootstrap files
COPY entrypoint.sh /app/entrypoint.sh
COPY openclaw.json.template /app/openclaw.json.template
COPY workspace/ /app/workspace/
RUN chmod +x /app/entrypoint.sh

ENV NODE_ENV=production
ENV PNPM_HOME="/home/agent/.local/share/pnpm"
ENV PATH="/home/agent/.npm-global/bin:/home/agent/.local/share/pnpm:/home/linuxbrew/.linuxbrew/bin:/home/linuxbrew/.linuxbrew/sbin:${PATH}"
# Run entrypoint as root so it can fix volume ownership; main process drops to agent via runuser
WORKDIR /home/agent

# Expose ports
EXPOSE 18789 18790 2222

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["openclaw", "gateway", "run", "--bind", "lan", "--port", "18789"]
