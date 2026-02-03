#!/bin/bash
set -eu -o pipefail

# Security: Prevent accidental exposure of sensitive environment variables
# Never log, echo, or print the values of these variables:
# - NEARAI_API_KEY
# - OPENCLAW_GATEWAY_TOKEN
# - SSH_PUBKEY
#
# Only log variable names in error messages, never their values.
#
# WARNING: Do not enable debug mode (set -x) as it will expose all variable values
# in the shell output. If debugging is needed, use explicit echo statements
# that only print variable names, not values.

# Ensure volume mount points are writable by agent (Docker often creates volumes as root)
mkdir -p /home/agent/.openclaw /home/agent/openclaw
chown -R agent:agent /home/agent/.openclaw /home/agent/openclaw

# ============================================
# SSH Server Configuration (runs as agent user on port 2222)
# ============================================
setup_ssh() {
  echo "Setting up SSH server..."
  
  # Configure authorized_keys from SSH_PUBKEY environment variable
  if [ -n "${SSH_PUBKEY:-}" ]; then
    echo "Configuring SSH authorized_keys..."
    mkdir -p /home/agent/.ssh
    printf '%s\n' "${SSH_PUBKEY}" > /home/agent/.ssh/authorized_keys
    chmod 700 /home/agent/.ssh
    chmod 600 /home/agent/.ssh/authorized_keys
    echo "SSH authorized_keys configured successfully"
    
    # Start SSH daemon on port 2222 (non-privileged); listen on all interfaces for external access
    echo "Starting SSH daemon on port 2222..."
    SSHD_OUTPUT=$(/usr/sbin/sshd -f /dev/null \
      -o Port=2222 \
      -o ListenAddress=0.0.0.0 \
      -o HostKey=/home/agent/ssh/ssh_host_ed25519_key \
      -o AuthorizedKeysFile=/home/agent/.ssh/authorized_keys \
      -o PasswordAuthentication=no \
      -o PermitRootLogin=no \
      -o PidFile=/home/agent/ssh/sshd.pid \
      -o StrictModes=no 2>&1) && SSHD_RC=0 || SSHD_RC=$?
    if [ "$SSHD_RC" -eq 0 ]; then
      echo "SSH daemon started on port 2222"
    else
      echo "Warning: Failed to start SSH daemon (exit code: $SSHD_RC)" >&2
      echo "SSHD output: $SSHD_OUTPUT" >&2
      echo "SSH access will not be available" >&2
    fi
  else
    echo "Warning: SSH_PUBKEY not set - SSH access will not be available" >&2
  fi
  chown -R agent:agent /home/agent/.ssh 2>/dev/null || true
}

setup_ssh

# ============================================
# OpenClaw Configuration
# ============================================

# Validate required environment variables
if [ -z "${NEARAI_API_KEY:-}" ]; then
  NEARAI_API_KEY=nearai-api-key
  export NEARAI_API_KEY
  # echo "Error: NEARAI_API_KEY environment variable is required" >&2
  # exit 1
fi

# Auto-generate gateway auth token if not configured (export so envsubst sees it)
if [ -z "${OPENCLAW_GATEWAY_TOKEN:-}" ]; then
  OPENCLAW_GATEWAY_TOKEN=$(openssl rand -hex 32)
  export OPENCLAW_GATEWAY_TOKEN
fi

# Create config directory if it doesn't exist
# Note: Directory is already created and owned by agent in Dockerfile, but ensure it exists
mkdir -p /home/agent/.openclaw
chmod 700 /home/agent/.openclaw 2>/dev/null || true

# Generate config from template if it doesn't exist or if forced
# Set OPENCLAW_FORCE_CONFIG_REGEN=1 to force regeneration even if config exists
FORCE_REGEN="${OPENCLAW_FORCE_CONFIG_REGEN:-0}"
if [ ! -f /home/agent/.openclaw/openclaw.json ] || [ "${FORCE_REGEN}" = "1" ]; then
  if [ "${FORCE_REGEN}" = "1" ]; then
    echo "Force regenerating config from template (OPENCLAW_FORCE_CONFIG_REGEN=1)..."
  else
    echo "Generating config from template..."
  fi
  
  # Template file must exist
  if [ ! -f /app/openclaw.json.template ]; then
    echo "Error: Template file /app/openclaw.json.template not found" >&2
    exit 1
  fi

  # Export variables for envsubst (only the ones we need)
  export NEARAI_API_KEY
  export OPENCLAW_GATEWAY_TOKEN
  export OPENCLAW_GATEWAY_BIND="${OPENCLAW_GATEWAY_BIND:-lan}"

  # Use envsubst to substitute environment variables in the template
  # OpenClaw supports ${VAR_NAME} syntax natively, so we can use the template directly
  if command -v envsubst >/dev/null 2>&1; then
    envsubst < /app/openclaw.json.template > /home/agent/.openclaw/openclaw.json
  else
    echo "Error: envsubst command not found (gettext-base package required)" >&2
    exit 1
  fi

  chown agent:agent /home/agent/.openclaw/openclaw.json
  chmod 600 /home/agent/.openclaw/openclaw.json
  echo "Config file created at /home/agent/.openclaw/openclaw.json"
fi

# Create workspace directory if it doesn't exist
# Note: Directory is already created and owned by agent in Dockerfile, but ensure it exists
mkdir -p /home/agent/openclaw
chmod 700 /home/agent/openclaw 2>/dev/null || true

# Execute the command with automatic restart (openclaw is installed globally)
# The loop keeps the container alive and restarts the gateway if it exits
RESTART_DELAY="${OPENCLAW_RESTART_DELAY:-5}"

while true; do
  echo "Starting: $*"
  runuser -u agent -- "$@" || true
  EXIT_CODE=$?
  echo "Process exited with code $EXIT_CODE. Restarting in ${RESTART_DELAY}s..."
  sleep "$RESTART_DELAY"
done
