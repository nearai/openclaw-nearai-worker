FROM node:22-bookworm@sha256:cd7bcd2e7a1e6f72052feb023c7f6b722205d3fcab7bbcbd2d1bfdab10b1e935

# Install system dependencies including OpenSSH server
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      gettext-base \
      openssh-server \
      openssh-client && \
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

# Setup SSH configuration
RUN mkdir -p /var/run/sshd /home/node/.ssh && \
    chmod 755 /var/run/sshd && \
    chmod 700 /home/node/.ssh && \
    chown -R node:node /home/node/.ssh

# Configure SSH server for node user access on port 2222 (non-privileged)
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config && \
    sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config && \
    echo "Port 2222" >> /etc/ssh/sshd_config && \
    echo "ListenAddress 0.0.0.0" >> /etc/ssh/sshd_config && \
    echo "AllowUsers node" >> /etc/ssh/sshd_config && \
    echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config && \
    echo "AuthorizedKeysFile .ssh/authorized_keys" >> /etc/ssh/sshd_config && \
    echo "PidFile /tmp/sshd.pid" >> /etc/ssh/sshd_config && \
    echo "UsePrivilegeSeparation no" >> /etc/ssh/sshd_config || true

# Generate SSH host keys if they don't exist
RUN ssh-keygen -A || true

# Copy entrypoint script and template
COPY entrypoint.sh /app/entrypoint.sh
COPY moltbot.json.template /app/moltbot.json.template
RUN chmod +x /app/entrypoint.sh

ENV NODE_ENV=production
USER node
WORKDIR /home/node

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["moltbot", "gateway", "--bind", "0.0.0.0", "--port", "18789"]
