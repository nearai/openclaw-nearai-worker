FROM ubuntu:24.04

# Install Node.js 22 and system dependencies and useful tools for OpenClaw agent execution
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      curl \
      ca-certificates \
      gnupg && \
    curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && \
    apt-get install -y --no-install-recommends \
      nodejs \
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
# Use UID 1001 to avoid conflict with Ubuntu's default UID 1000
RUN useradd -m -u 1001 agent

# Install OpenClaw globally from npm
RUN npm install -g openclaw@latest

# Create directories for config and workspace
RUN mkdir -p /home/agent/.openclaw /home/agent/openclaw && \
    chown -R agent:agent /home/agent

# Copy entrypoint script and template
COPY entrypoint.sh /app/entrypoint.sh
COPY openclaw.json.template /app/openclaw.json.template
RUN chmod +x /app/entrypoint.sh

ENV NODE_ENV=production
USER agent
WORKDIR /home/agent

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["openclaw", "gateway", "run", "--bind", "lan", "--port", "18789"]
