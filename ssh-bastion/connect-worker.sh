#!/bin/sh
# ForceCommand — proxies the SSH session to the worker container.
# $USER is the SSH username (instance name).
# $SSH_ORIGINAL_COMMAND is set when the client ran "ssh host command" or scp.

API_URL="http://127.0.0.1:${COMPOSE_API_PORT:-8080}"
BASTION_KEY="/app/data/bastion/id_ed25519"

RESULT=$(curl -sf "${API_URL}/instances/${USER}" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" 2>/dev/null)

if [ -z "$RESULT" ]; then
    echo "Instance not found: ${USER}" >&2
    exit 1
fi

SSH_PORT=$(echo "$RESULT" | jq -r '.ssh_port // empty' 2>/dev/null)

if [ -z "$SSH_PORT" ]; then
    echo "Could not resolve SSH port for: ${USER}" >&2
    exit 1
fi

SSH_OPTS="-i ${BASTION_KEY} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p ${SSH_PORT}"

if [ -n "${SSH_ORIGINAL_COMMAND:-}" ]; then
    # Remote command or scp
    exec ssh $SSH_OPTS agent@127.0.0.1 "${SSH_ORIGINAL_COMMAND}"
else
    # Interactive shell
    exec ssh -t $SSH_OPTS agent@127.0.0.1
fi
