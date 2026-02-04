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
      file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*

# Create non-root user for OpenClaw agents
# Use UID 1001 to avoid conflict with default UID 1000
# Set shell to bash (required for Homebrew installer and SSH sessions)
RUN useradd -m -u 1001 -s /bin/bash agent && \
    grep -q "^agent:.*:/bin/bash$" /etc/passwd || (echo "Error: agent user shell not set to bash" >&2 && exit 1)

# Install Homebrew as the agent user (non-interactive mode)
# The installer detects Docker environment and runs non-interactively
# Set SHELL to bash to ensure Homebrew installer runs correctly
USER agent
SHELL ["/bin/bash", "-c"]
RUN curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh | bash

# Switch back to root for remaining setup
USER root
SHELL ["/bin/sh", "-c"]

# Install pnpm, bun, and OpenClaw globally via npm
RUN npm install -g pnpm bun openclaw@2026.2.1

# Configure SSH server, directories, brew, and npm for agent user
RUN mkdir -p /home/agent/.ssh /home/agent/ssh /home/agent/.openclaw /home/agent/openclaw /home/agent/.npm-global && \
    ssh-keygen -t ed25519 -f /home/agent/ssh/ssh_host_ed25519_key -N "" && \
    chmod 700 /home/agent/.ssh && \
    # Configure brew environment in .bashrc (PATH already in ENV, but shellenv sets additional variables)
    echo 'eval "$(/home/linuxbrew/.linuxbrew/bin/brew shellenv)"' >> /home/agent/.bashrc && \
    # Configure npm to use local directory for global packages (prevents permission errors as non-root)
    su - agent -c 'npm config set prefix "/home/agent/.npm-global"' && \
    # Add npm-global to PATH in .bashrc (PATH already in ENV, but this ensures it's in shell sessions)
    echo 'export PATH="/home/agent/.npm-global/bin:${PATH}"' >> /home/agent/.bashrc && \
    # Ensure SSH login shells source .bashrc (both .profile and .bash_profile for compatibility)
    echo '[ -f ~/.bashrc ] && . ~/.bashrc' >> /home/agent/.profile && \
    echo '[ -f ~/.bashrc ] && . ~/.bashrc' >> /home/agent/.bash_profile && \
    # Create symlink for easy brew access
    ln -s /home/linuxbrew/.linuxbrew/bin/brew /usr/local/bin/brew && \
    chmod +x /usr/local/bin/brew && \
    # Set ownership for all agent user files
    chown -R agent:agent /home/agent

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
