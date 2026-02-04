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

# Install Homebrew (Linux) as non-root user
# Note: Homebrew cannot be installed as root - must be installed as a non-root user
# build-essential, curl, git, and procps are already installed above
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*

# Install Homebrew as the agent user (non-interactive mode)
# The installer detects Docker environment and runs non-interactively
USER agent
RUN /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" < /dev/null

# Switch back to root for remaining setup
USER root
RUN echo 'eval "$(/home/linuxbrew/.linuxbrew/bin/brew shellenv)"' >> /etc/profile.d/brew.sh && \
    echo 'eval "$(/home/linuxbrew/.linuxbrew/bin/brew shellenv)"' >> /root/.bashrc && \
    echo 'eval "$(/home/linuxbrew/.linuxbrew/bin/brew shellenv)"' >> /home/agent/.bashrc && \
    ln -s /home/linuxbrew/.linuxbrew/bin/brew /usr/local/bin/brew && \
    chmod +x /usr/local/bin/brew

# Configure SSH server to run on non-privileged port 2222
RUN mkdir -p /home/agent/.ssh /home/agent/ssh && \
    ssh-keygen -t ed25519 -f /home/agent/ssh/ssh_host_ed25519_key -N "" && \
    chmod 700 /home/agent/.ssh && \
    chown -R agent:agent /home/agent/.ssh /home/agent/ssh

# Install pnpm and bun globally via npm
RUN npm install -g pnpm bun

# Install OpenClaw globally from npm
RUN npm install -g openclaw@2026.2.1

# Create directories for config and workspace
RUN mkdir -p /home/agent/.openclaw /home/agent/openclaw && \
    chown -R agent:agent /home/agent

# Configure npm for agent user to use local directory for global packages
# This prevents permission errors when installing global packages as non-root
RUN mkdir -p /home/agent/.npm-global && \
    chown -R agent:agent /home/agent/.npm-global && \
    su - agent -c 'npm config set prefix "/home/agent/.npm-global"' && \
    echo 'export PATH="/home/agent/.npm-global/bin:${PATH}"' >> /home/agent/.bashrc && \
    echo 'export PATH="/home/agent/.npm-global/bin:${PATH}"' >> /etc/profile.d/npm-agent.sh

# Copy entrypoint script and template
COPY entrypoint.sh /app/entrypoint.sh
COPY openclaw.json.template /app/openclaw.json.template
RUN chmod +x /app/entrypoint.sh

ENV NODE_ENV=production
ENV PATH="/home/agent/.npm-global/bin:/home/linuxbrew/.linuxbrew/bin:/home/linuxbrew/.linuxbrew/sbin:${PATH}"
# Run entrypoint as root so it can fix volume ownership; main process drops to agent via runuser
WORKDIR /home/agent

# Expose ports
EXPOSE 18789 18790 2222

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["openclaw", "gateway", "run", "--bind", "lan", "--port", "18789"]
