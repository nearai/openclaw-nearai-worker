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
    echo "${SSH_PUBKEY}" > /home/agent/.ssh/authorized_keys
    if [ -n "${BASTION_SSH_PUBKEY:-}" ]; then
      echo "${BASTION_SSH_PUBKEY}" >> /home/agent/.ssh/authorized_keys
    fi
    # Ensure correct permissions for StrictModes (home directory must not be world-writable)
    chmod 755 /home/agent
    chmod 700 /home/agent/.ssh
    chmod 600 /home/agent/.ssh/authorized_keys
    chown -R agent:agent /home/agent/.ssh
    echo "SSH authorized_keys configured successfully"

    # Create privilege separation directory required by sshd
    mkdir -p /run/sshd
    chmod 0755 /run/sshd

    # Unlock agent account to allow SSH key-based login (account may be locked by default)
    passwd -d agent 2>/dev/null || usermod -U agent 2>/dev/null || true

    # Start SSH daemon on port 2222 (non-privileged); listen on all interfaces for external access
    # sshd forks/daemonizes, so the child process keeps running after entrypoint enters the restart loop
    echo "Starting SSH daemon on port 2222..."
    SSHD_OUTPUT=$(/usr/sbin/sshd -f /dev/null \
      -o Port=2222 \
      -o ListenAddress=0.0.0.0 \
      -o HostKey=/home/agent/ssh/ssh_host_ed25519_key \
      -o AuthorizedKeysFile=/home/agent/.ssh/authorized_keys \
      -o PasswordAuthentication=no \
      -o PermitRootLogin=no \
      -o PidFile=/home/agent/ssh/sshd.pid \
      -o StrictModes=yes 2>&1) && SSHD_RC=0 || SSHD_RC=$?
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
  echo "Warning: NEARAI_API_KEY environment variable is not provided. Using placeholder 'nearai-api-key'." >&2
  echo "Warning: The service may not function correctly without a valid API key." >&2
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

# Default NEAR AI Cloud API base URL (export so envsubst sees it)
if [ -z "${NEARAI_API_URL:-}" ]; then
  NEARAI_API_URL=https://cloud-api.near.ai/v1
  export NEARAI_API_URL
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
  export NEARAI_API_URL
  export OPENCLAW_GATEWAY_TOKEN
  export OPENCLAW_GATEWAY_BIND="${OPENCLAW_GATEWAY_BIND:-lan}"

  # Use envsubst to substitute environment variables in the template
  # OpenClaw supports ${VAR_NAME} syntax natively, so we can use the template directly
  # Write to tmp file then mv to prevent symlink attacks (entrypoint runs as root,
  # but /home/agent/.openclaw is agent-owned — a symlink there could overwrite system files)
  if command -v envsubst >/dev/null 2>&1; then
    envsubst < /app/openclaw.json.template > /home/agent/.openclaw/openclaw.json.tmp
  else
    echo "Error: envsubst command not found (gettext-base package required)" >&2
    exit 1
  fi

  chown agent:agent /home/agent/.openclaw/openclaw.json.tmp
  chmod 600 /home/agent/.openclaw/openclaw.json.tmp
  mv -f /home/agent/.openclaw/openclaw.json.tmp /home/agent/.openclaw/openclaw.json
  echo "Config file created at /home/agent/.openclaw/openclaw.json"
fi

# Generate streaming config if it doesn't exist (separate from openclaw.json to avoid schema conflicts)
if [ ! -f /home/agent/.openclaw/streaming.json ] || [ "${FORCE_REGEN}" = "1" ]; then
  if [ -f /app/streaming.json ]; then
    cp /app/streaming.json /home/agent/.openclaw/streaming.json.tmp
    chown agent:agent /home/agent/.openclaw/streaming.json.tmp
    chmod 600 /home/agent/.openclaw/streaming.json.tmp
    mv -f /home/agent/.openclaw/streaming.json.tmp /home/agent/.openclaw/streaming.json
    echo "Streaming config created at /home/agent/.openclaw/streaming.json"
  fi
fi

# Create workspace directory if it doesn't exist
# Note: Directory is already created and owned by agent in Dockerfile, but ensure it exists
mkdir -p /home/agent/openclaw
chmod 700 /home/agent/openclaw 2>/dev/null || true

# Copy workspace bootstrap files (SOUL.md, TOOLS.md, etc.) if they don't already exist
# These are injected into the system prompt by OpenClaw automatically
if [ -d /app/workspace ]; then
  for f in /app/workspace/*.md; do
    [ -f "$f" ] || continue
    fname=$(basename "$f")
    if [ ! -f "/home/agent/openclaw/$fname" ]; then
      cp "$f" "/home/agent/openclaw/$fname"
      chown agent:agent "/home/agent/openclaw/$fname"
      echo "Bootstrap file $fname installed to workspace"
    fi
  done

  # Copy pre-installed skills to managed location (shared across all agents)
  if [ -d /app/workspace/skills ]; then
    mkdir -p /home/agent/.openclaw/skills
    for skill_dir in /app/workspace/skills/*/; do
      [ -d "$skill_dir" ] || continue
      skill_name=$(basename "$skill_dir")
      if [ ! -d "/home/agent/.openclaw/skills/$skill_name" ]; then
        cp -r "$skill_dir" "/home/agent/.openclaw/skills/$skill_name"
        echo "Skill '$skill_name' installed to managed skills"
      fi
    done
    chown -R agent:agent /home/agent/.openclaw/skills
  fi
fi

# ============================================
# Auto-approve Device Pairing (for multi-tenant deployment)
# ============================================
# When OPENCLAW_AUTO_APPROVE_DEVICES=1, automatically approve the FIRST device pairing request only.
# Subsequent devices require manual approval for security.
# This is useful for headless/automated deployments where initial setup needs automation.
#
# NOTE: Since openclaw 2026.2.15, the CLI resolves gateway targets using the bind mode
# (lan/loopback). When bind=lan, the CLI connects via the LAN IP, and the gateway treats
# it as a remote client requiring manual pairing — a chicken-and-egg problem.
# Fix: force the CLI to connect via loopback (ws://127.0.0.1:<port>) so the gateway
# recognizes it as a local client and auto-approves the pairing silently.
# See: openclaw #16299, #11448, #16434
AUTO_APPROVE_DEVICES="${OPENCLAW_AUTO_APPROVE_DEVICES:-0}"
AUTO_APPROVE_FLAG="/home/agent/.openclaw/.device_approved"

start_auto_approve_daemon() {
  if [ "$AUTO_APPROVE_DEVICES" = "1" ]; then
    echo "Starting auto-approve daemon for first device pairing..."
    (
      # Wait for gateway to start
      sleep 10

      # Read gateway port and token from config for loopback CLI connection.
      # The CLI must connect via loopback so the gateway sees it as a local client
      # and auto-approves the pairing (isLocalDirectRequest → silent: true).
      GATEWAY_PORT=$(jq -r '.gateway.port // 18789' /home/agent/.openclaw/openclaw.json 2>/dev/null || echo 18789)
      GATEWAY_TOKEN=$(jq -r '.gateway.auth.token // empty' /home/agent/.openclaw/openclaw.json 2>/dev/null || true)

      if [ -z "$GATEWAY_TOKEN" ]; then
        echo "Warning: Could not read gateway token from config. Auto-approve daemon exiting." >&2
        exit 1
      fi

      LOOPBACK_ARGS="--url ws://127.0.0.1:${GATEWAY_PORT} --token ${GATEWAY_TOKEN}"

      while true; do
        # Check if we already approved a device - if so, exit daemon
        if [ -f "$AUTO_APPROVE_FLAG" ]; then
          echo "First device already approved. Auto-approve daemon exiting."
          exit 0
        fi

        # Get pending device requests (connect via loopback for auto-pairing)
        PENDING=$(runuser -p -u agent -- env HOME=/home/agent openclaw devices list --json $LOOPBACK_ARGS 2>/dev/null || echo '{"pending":[]}')

        # Get the first pending request ID only
        FIRST_REQUEST_ID=$(echo "$PENDING" | jq -r '.pending[0]?.requestId // empty' 2>/dev/null)

        if [ -n "$FIRST_REQUEST_ID" ]; then
          echo "Auto-approving first device pairing request: $FIRST_REQUEST_ID"
          if runuser -p -u agent -- env HOME=/home/agent openclaw devices approve "$FIRST_REQUEST_ID" $LOOPBACK_ARGS 2>/dev/null; then
            # Mark that we've approved a device
            touch "$AUTO_APPROVE_FLAG"
            chown agent:agent "$AUTO_APPROVE_FLAG" 2>/dev/null || true
            echo "First device approved. Subsequent devices require manual approval."
            echo "Auto-approve daemon exiting."
            exit 0
          fi
        fi

        # Check every 5 seconds
        sleep 5
      done
    ) &
    echo "Auto-approve daemon started (will approve first device only)"
  fi
}

# Final ownership fix: ensure everything is owned by agent before dropping privileges
# (config generation and bootstrap above may have created files as root)
# Pre-create subdirs the gateway needs — prevents root-owned dirs at runtime
mkdir -p /home/agent/.openclaw/{identity,credentials,cron,agents,canvas}
chown -R agent:agent /home/agent/.openclaw /home/agent/openclaw

start_auto_approve_daemon

# Config integrity check — restore from template if critical keys are clobbered
# (e.g., AI agent used config.patch/exec to modify openclaw.json and stripped defaults)
validate_config() {
  local cfg="/home/agent/.openclaw/openclaw.json"
  if [ ! -f "$cfg" ]; then
    echo "Warning: Config file missing" >&2
    return 1
  fi
  local primary
  primary=$(jq -r '.agents.defaults.model.primary // empty' "$cfg" 2>/dev/null) || true
  if [ -z "$primary" ]; then
    echo "Warning: agents.defaults.model.primary is missing — config may be clobbered" >&2
    return 1
  fi
  return 0
}

restore_config() {
  echo "Restoring config from template..."
  export OPENCLAW_GATEWAY_BIND="${OPENCLAW_GATEWAY_BIND:-lan}"
  envsubst < /app/openclaw.json.template > /home/agent/.openclaw/openclaw.json.tmp
  chown agent:agent /home/agent/.openclaw/openclaw.json.tmp
  chmod 600 /home/agent/.openclaw/openclaw.json.tmp
  mv -f /home/agent/.openclaw/openclaw.json.tmp /home/agent/.openclaw/openclaw.json
  echo "Config restored from template"
}

# Execute the command with automatic restart (openclaw is installed globally)
# The loop keeps the container alive and restarts the gateway if it exits
RESTART_DELAY="${OPENCLAW_RESTART_DELAY:-5}"

while true; do
  echo "Starting: $*"
  # Fix ownership before each launch — subdirs may have been created as root
  chown -R agent:agent /home/agent/.openclaw /home/agent/openclaw 2>/dev/null || true
  # Validate config integrity before each launch
  if ! validate_config; then
    restore_config
  fi
  # The -p flag preserves environment variables (including PATH set in Dockerfile)
  runuser -p -u agent -- "$@" && EXIT_CODE=$? || EXIT_CODE=$?
  echo "Process exited with code $EXIT_CODE. Restarting in ${RESTART_DELAY}s..."
  sleep "$RESTART_DELAY"
done
