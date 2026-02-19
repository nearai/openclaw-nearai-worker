#!/bin/sh
# AuthorizedKeysCommand — called by sshd to look up SSH public keys for a username.
# $1 is the connecting username (instance name).
# Must print authorized_keys lines to stdout. Empty output = deny.

INSTANCE_NAME="$1"
BASTION_DIR="/app/data/bastion"
API_URL=$(cat "$BASTION_DIR/api-url" 2>/dev/null) || exit 0
ADMIN_TOKEN=$(cat "$BASTION_DIR/admin-token" 2>/dev/null) || exit 0

RESULT=$(curl -sf "${API_URL}/instances/${INSTANCE_NAME}" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" 2>/dev/null) || exit 0

SSH_KEY=$(echo "$RESULT" | jq -r '.ssh_pubkey // empty' 2>/dev/null)

if [ -n "$SSH_KEY" ]; then
    echo "$SSH_KEY"
fi
