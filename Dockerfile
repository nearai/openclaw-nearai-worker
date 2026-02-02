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
      awk \
      grep \
      dnsutils \
      strace \
      lsof \
      rsync \
      less \
      nano && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*

# Create node user with home directory (matching node image convention)
RUN groupadd -r node && useradd -r -g node -m -d /home/node node

# Install OpenClaw globally from npm
RUN npm install -g openclaw@latest

# Create directories for config and workspace
RUN mkdir -p /home/node/.openclaw /home/node/openclaw && \
    chown -R node:node /home/node

# Copy entrypoint script and template
COPY entrypoint.sh /app/entrypoint.sh
COPY openclaw.json.template /app/openclaw.json.template
RUN chmod +x /app/entrypoint.sh

ENV NODE_ENV=production
USER node
WORKDIR /home/node

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["openclaw", "gateway", "run", "--bind", "loopback", "--port", "18789"]
