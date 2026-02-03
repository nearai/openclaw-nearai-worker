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

# Configure SSH server
RUN mkdir -p /run/sshd && \
    ssh-keygen -A && \
    sed -i 's/#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && \
    sed -i 's/#PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config && \
    echo "AllowUsers agent" >> /etc/ssh/sshd_config

# Install gosu for running main process as non-root user
RUN apt-get update && \
    apt-get install -y --no-install-recommends gosu && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user for OpenClaw agents
# Use UID 1001 to avoid conflict with default UID 1000
RUN useradd -m -u 1001 agent

# Install OpenClaw globally from npm
RUN npm install -g openclaw@2026.2.1

# Create directories for config, workspace, and SSH
RUN mkdir -p /home/agent/.openclaw /home/agent/openclaw /home/agent/.ssh && \
    chmod 700 /home/agent/.ssh && \
    chown -R agent:agent /home/agent

# Copy entrypoint script and template
COPY entrypoint.sh /app/entrypoint.sh
COPY openclaw.json.template /app/openclaw.json.template
RUN chmod +x /app/entrypoint.sh

ENV NODE_ENV=production
WORKDIR /home/agent

# Expose SSH port
EXPOSE 22

# Entrypoint runs as root to start sshd, then drops to agent for main process
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["openclaw", "gateway", "run", "--bind", "lan", "--port", "18789"]
