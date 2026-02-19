#!/bin/sh
# AuthorizedKeysCommand — called by sshd to look up SSH public keys for a username.
# $1 is the connecting username (instance name).
# Must print authorized_keys lines to stdout. Empty output = deny.

INSTANCE_NAME="$1"
API_URL="http://127.0.0.1:${COMPOSE_API_PORT:-8080}"

RESULT=$(curl -sf "${API_URL}/instances/${INSTANCE_NAME}" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" 2>/dev/null) || exit 0

SSH_KEY=$(echo "$RESULT" | jq -r '.ssh_pubkey // empty' 2>/dev/null)

if [ -n "$SSH_KEY" ]; then
    echo "$SSH_KEY"
fi
