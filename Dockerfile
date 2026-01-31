FROM node:22-bookworm@sha256:cd7bcd2e7a1e6f72052feb023c7f6b722205d3fcab7bbcbd2d1bfdab10b1e935

# Install system dependencies and useful tools
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      gettext-base \
      git \
      curl \
      wget \
      ca-certificates \
      build-essential \
      python3 \
      python3-pip \
      jq \
      netcat-traditional \
      iputils-ping \
      procps \
      vim && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*

# Install Clawdbot globally from npm
RUN npm install -g clawdbot@2026.1.24-3

# Create directories for config and workspace
RUN mkdir -p /home/node/.clawdbot /home/node/clawd && \
    chown -R node:node /home/node

# Copy entrypoint script and template
COPY entrypoint.sh /app/entrypoint.sh
COPY clawdbot.json.template /app/clawdbot.json.template
RUN chmod +x /app/entrypoint.sh

ENV NODE_ENV=production
USER node
WORKDIR /home/node

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["clawdbot", "gateway", "--bind", "loopback", "--port", "18789"]
