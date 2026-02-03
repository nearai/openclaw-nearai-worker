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
      nano && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*

# Create non-root user for OpenClaw agents
# Use UID 1001 to avoid conflict with default UID 1000
RUN useradd -m -u 1001 agent

# Configure SSH server to run on non-privileged port 2222
RUN mkdir -p /home/agent/.ssh /home/agent/ssh && \
    ssh-keygen -t ed25519 -f /home/agent/ssh/ssh_host_ed25519_key -N "" && \
    chmod 700 /home/agent/.ssh && \
    chown -R agent:agent /home/agent/.ssh /home/agent/ssh

# Install OpenClaw globally from npm
RUN npm install -g openclaw@2026.2.1

# Create directories for config and workspace
RUN mkdir -p /home/agent/.openclaw /home/agent/openclaw && \
    chown -R agent:agent /home/agent

# Copy entrypoint script and template
COPY entrypoint.sh /app/entrypoint.sh
COPY openclaw.json.template /app/openclaw.json.template
RUN chmod +x /app/entrypoint.sh

ENV NODE_ENV=production
# Run entrypoint as root so it can fix volume ownership; main process drops to agent via runuser
WORKDIR /home/agent

# Expose ports
EXPOSE 18789 18790 2222

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["openclaw", "gateway", "run", "--bind", "lan", "--port", "18789"]
