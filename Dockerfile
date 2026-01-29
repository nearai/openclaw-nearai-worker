FROM node:22-bookworm@sha256:cd7bcd2e7a1e6f72052feb023c7f6b722205d3fcab7bbcbd2d1bfdab10b1e935

# Install system dependencies
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      gettext-base && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*

# Install Moltbot globally from npm
# MOLTBOT_VERSION can be set as build arg (e.g., --build-arg MOLTBOT_VERSION=1.0.0)
# If not specified, installs latest version
ARG MOLTBOT_VERSION=latest
RUN npm install -g moltbot@${MOLTBOT_VERSION}

# Create directories for config and workspace
RUN mkdir -p /home/node/.moltbot /home/node/clawd && \
    chown -R node:node /home/node

# Copy entrypoint script and template
COPY entrypoint.sh /app/entrypoint.sh
COPY moltbot.json.template /app/moltbot.json.template
RUN chmod +x /app/entrypoint.sh

ENV NODE_ENV=production
USER node
WORKDIR /home/node

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["moltbot", "gateway", "--bind", "0.0.0.0", "--port", "18789"]
