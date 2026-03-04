#!/usr/bin/env bash
set -euo pipefail

# IronClaw local development entrypoint.
# Adapted from ironclaw-worker/entrypoint.sh — same env var mapping,
# simplified for local use (no SSH by default, no OAuth).
#
# Security: Never log, echo, or print the values of:
#   NEARAI_API_KEY, OPENCLAW_GATEWAY_TOKEN, SECRETS_MASTER_KEY

# Ensure volume mount points are writable by agent
mkdir -p /home/agent/.ironclaw /home/agent/workspace

# ============================================
# SSH Server (optional, only if SSH_PUBKEY set)
# ============================================
if [ -n "${SSH_PUBKEY:-}" ]; then
    echo "Configuring SSH..."
    mkdir -p /home/agent/.ssh
    echo "${SSH_PUBKEY}" > /home/agent/.ssh/authorized_keys
    if [ -n "${BASTION_SSH_PUBKEY:-}" ]; then
        echo "${BASTION_SSH_PUBKEY}" >> /home/agent/.ssh/authorized_keys
    fi
    chmod 755 /home/agent
    chmod 700 /home/agent/.ssh
    chmod 600 /home/agent/.ssh/authorized_keys
    chown -R agent:agent /home/agent/.ssh

    if [ ! -f /home/agent/ssh/ssh_host_ed25519_key ]; then
        mkdir -p /home/agent/ssh
        ssh-keygen -t ed25519 -f /home/agent/ssh/ssh_host_ed25519_key -N ""
        chown agent:agent /home/agent/ssh/ssh_host_ed25519_key*
    fi

    mkdir -p /run/sshd && chmod 0755 /run/sshd
    passwd -d agent 2>/dev/null || usermod -U agent 2>/dev/null || true

    /usr/sbin/sshd -f /dev/null \
        -o Port=2222 \
        -o ListenAddress=0.0.0.0 \
        -o HostKey=/home/agent/ssh/ssh_host_ed25519_key \
        -o AuthorizedKeysFile=/home/agent/.ssh/authorized_keys \
        -o PasswordAuthentication=no \
        -o PermitRootLogin=no \
        -o PidFile=/home/agent/ssh/sshd.pid \
        -o StrictModes=yes \
        -o UsePAM=yes \
        -o AcceptEnv="LANG LC_*" \
        -o PrintMotd=no 2>&1 && echo "SSH daemon started on port 2222" \
        || echo "Warning: Failed to start SSH daemon" >&2
fi

# ============================================
# IronClaw Configuration (env var mapping)
# ============================================
# Same mapping as ironclaw-worker/entrypoint.sh

# Database: libSQL embedded (no external DB dependency)
export DATABASE_BACKEND=libsql
export LIBSQL_PATH=/home/agent/.ironclaw/ironclaw.db

# Gateway: bind to all interfaces
export GATEWAY_ENABLED=true
export GATEWAY_HOST=0.0.0.0
export GATEWAY_PORT=18789
export GATEWAY_AUTH_TOKEN="${OPENCLAW_GATEWAY_TOKEN:-changeme}"

# Disable interactive REPL (no TTY in container)
export CLI_ENABLED=false

# Disable Docker sandbox (no Docker-in-Docker)
export SANDBOX_ENABLED=false

# NEAR AI: map compose-api env vars to IronClaw config
NEARAI_API_URL="${NEARAI_API_URL:-https://cloud-api.near.ai/v1}"
# Strip trailing /v1 — IronClaw adds it internally
export NEARAI_BASE_URL="${NEARAI_API_URL%/v1}"

# Pass the API key directly
if [ -n "${NEARAI_API_KEY:-}" ]; then
    export NEARAI_API_KEY="${NEARAI_API_KEY}"
else
    echo "Warning: NEARAI_API_KEY not set. IronClaw may not function correctly." >&2
fi

# Model: default to "auto" for auto-routing
export NEARAI_MODEL="${NEARAI_MODEL:-auto}"

# Secrets store: generate-once master key for AES-256-GCM encryption.
# Persisted on the config volume so it survives container restarts.
MASTER_KEY_FILE="/home/agent/.ironclaw/.master_key"
if [ -z "${SECRETS_MASTER_KEY:-}" ]; then
    if [ -f "$MASTER_KEY_FILE" ]; then
        SECRETS_MASTER_KEY=$(cat "$MASTER_KEY_FILE")
    else
        SECRETS_MASTER_KEY=$(openssl rand -hex 32)
        echo "$SECRETS_MASTER_KEY" > "$MASTER_KEY_FILE"
        chmod 600 "$MASTER_KEY_FILE"
        chown root:root "$MASTER_KEY_FILE"
    fi
    export SECRETS_MASTER_KEY
fi

export RUST_LOG="${RUST_LOG:-ironclaw=debug}"

# Workspace: import custom templates on first boot
export WORKSPACE_IMPORT_DIR=/app/init/workspace

# ============================================
# Final Ownership Fix
# ============================================
chown -R agent:agent /home/agent/.ironclaw /home/agent/workspace

# Lock master key so agent user cannot read it
if [ -f "$MASTER_KEY_FILE" ]; then
    chown root:root "$MASTER_KEY_FILE"
    chmod 600 "$MASTER_KEY_FILE"
fi

# ============================================
# Start IronClaw with auto-restart
# ============================================
RESTART_DELAY="${IRONCLAW_RESTART_DELAY:-5}"
MAX_FAILURES="${IRONCLAW_MAX_FAILURES:-10}"
FAILURE_COUNT=0

export HOME=/home/agent

while true; do
    echo "Starting IronClaw..."
    chown -R agent:agent /home/agent/.ironclaw /home/agent/workspace 2>/dev/null || true
    # Re-lock master key after chown -R
    if [ -f "$MASTER_KEY_FILE" ]; then
        chown root:root "$MASTER_KEY_FILE"
        chmod 600 "$MASTER_KEY_FILE"
    fi
    runuser -p -u agent -- ironclaw run --no-onboard
    EXIT_CODE=$?
    if [ $EXIT_CODE -eq 0 ]; then
        FAILURE_COUNT=0
    else
        FAILURE_COUNT=$((FAILURE_COUNT + 1))
        echo "IronClaw exited with code $EXIT_CODE (failure $FAILURE_COUNT/$MAX_FAILURES)"
    fi
    if [ $FAILURE_COUNT -ge $MAX_FAILURES ]; then
        echo "IronClaw failed $MAX_FAILURES times consecutively. Exiting." >&2
        exit 1
    fi
    echo "Restarting in ${RESTART_DELAY}s..."
    sleep "$RESTART_DELAY"
done
