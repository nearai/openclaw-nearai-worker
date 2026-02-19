#!/bin/sh
set -eu

BASTION_SSH_PORT="${BASTION_SSH_PORT:-2222}"
BASTION_DIR="/app/data/bastion"
API_URL="http://127.0.0.1:${COMPOSE_API_PORT:-8080}"
SYNC_INTERVAL="${BASTION_SYNC_INTERVAL:-5}"

# ── Generate bastion key pair (for hop to workers) ────────────────────
mkdir -p "$BASTION_DIR"

if [ ! -f "$BASTION_DIR/id_ed25519" ]; then
    echo "Generating bastion key pair..."
    ssh-keygen -t ed25519 -f "$BASTION_DIR/id_ed25519" -N "" -C "bastion-internal"
    echo "Bastion public key: $(cat "$BASTION_DIR/id_ed25519.pub")"
fi
# ForceCommand runs as the connecting user, who needs to read the bastion
# key for the second hop. This is an internal container key, not user-facing.
chmod 644 "$BASTION_DIR/id_ed25519"

# ── Generate sshd host key ───────────────────────────────────────────
if [ ! -f "$BASTION_DIR/ssh_host_ed25519_key" ]; then
    echo "Generating sshd host key..."
    ssh-keygen -t ed25519 -f "$BASTION_DIR/ssh_host_ed25519_key" -N ""
fi

# ── Persist env vars for sshd subprocesses ─────────────────────────
# sshd sanitizes the environment before running AuthorizedKeysCommand
# and ForceCommand, so env vars like ADMIN_TOKEN are not available.
# Write them to files that the scripts can read.
echo "${ADMIN_TOKEN}" > "$BASTION_DIR/admin-token"
echo "${API_URL}" > "$BASTION_DIR/api-url"
chmod 644 "$BASTION_DIR/admin-token" "$BASTION_DIR/api-url"

# ── sshd prerequisites ──────────────────────────────────────────────
mkdir -p /run/sshd /var/empty
chmod 0755 /run/sshd /var/empty

# ── User sync ────────────────────────────────────────────────────────
# sshd requires connecting usernames to exist in /etc/passwd.
# Instance names are dynamic, so we sync them from compose-api.

sync_users() {
    RESULT=$(curl -sf "${API_URL}/instances" \
        -H "Authorization: Bearer ${ADMIN_TOKEN}" 2>/dev/null) || return 0
    echo "$RESULT" | jq -r '.instances[].name // empty' 2>/dev/null | while read -r name; do
        [ -z "$name" ] && continue
        if ! id "$name" >/dev/null 2>&1; then
            # Shell must be valid: ForceCommand is invoked as "<shell> -c <cmd>".
            # /bin/false would silently discard the ForceCommand.
            adduser -D -s /bin/sh -H -h /var/empty "$name" 2>/dev/null || true
            # Unlock: sshd rejects locked accounts (password field '!' in shadow).
            # passwd -d clears the password, which unlocks the account.
            # Safe because PasswordAuthentication=no — only key auth is allowed.
            passwd -d "$name" 2>/dev/null || true
        fi
    done
}

# Wait for compose-api to be ready before first sync
echo "Waiting for compose-api..."
ATTEMPTS=0
while ! curl -sf "${API_URL}/health" >/dev/null 2>&1; do
    ATTEMPTS=$((ATTEMPTS + 1))
    if [ "$ATTEMPTS" -ge 60 ]; then
        echo "Warning: compose-api not reachable after 60s, starting anyway"
        break
    fi
    sleep 1
done

sync_users
echo "Initial user sync complete"

# Background sync loop — creates system users for new instances
(while true; do sleep "$SYNC_INTERVAL"; sync_users; done) &

# ── Start sshd ───────────────────────────────────────────────────────
echo "Starting SSH bastion on port ${BASTION_SSH_PORT}..."
exec /usr/sbin/sshd -D -e \
    -o "Port=${BASTION_SSH_PORT}" \
    -o "ListenAddress=0.0.0.0" \
    -o "HostKey=${BASTION_DIR}/ssh_host_ed25519_key" \
    -o "AuthorizedKeysCommand=/usr/local/bin/lookup-keys %u" \
    -o "AuthorizedKeysCommandUser=sshkeys" \
    -o "ForceCommand=/usr/local/bin/connect-worker" \
    -o "PasswordAuthentication=no" \
    -o "PermitRootLogin=no" \
    -o "PermitTTY=yes" \
    -o "AllowTcpForwarding=no" \
    -o "X11Forwarding=no" \
    -o "PrintMotd=no" \
    -o "StrictModes=no"
