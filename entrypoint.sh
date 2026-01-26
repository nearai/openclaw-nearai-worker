#!/bin/bash
set -eu -o pipefail

# Security: Prevent accidental exposure of sensitive environment variables
# Never log, echo, or print the values of these variables:
# - NEARAI_API_KEY
# - SLACK_BOT_TOKEN
# - SLACK_APP_TOKEN
# - CLAWDBOT_GATEWAY_TOKEN
# - SLACK_SIGNING_SECRET
#
# Only log variable names in error messages, never their values.
#
# WARNING: Do not enable debug mode (set -x) as it will expose all variable values
# in the shell output. If debugging is needed, use explicit echo statements
# that only print variable names, not values.

# Validate required environment variables
if [ -z "${NEARAI_API_KEY:-}" ]; then
  echo "Error: NEARAI_API_KEY environment variable is required" >&2
  exit 1
fi

if [ -z "${SLACK_BOT_TOKEN:-}" ]; then
  echo "Error: SLACK_BOT_TOKEN environment variable is required" >&2
  exit 1
fi

if [ -z "${SLACK_APP_TOKEN:-}" ]; then
  echo "Error: SLACK_APP_TOKEN environment variable is required" >&2
  exit 1
fi

if [ -z "${CLAWDBOT_GATEWAY_TOKEN:-}" ]; then
  echo "Error: CLAWDBOT_GATEWAY_TOKEN environment variable is required" >&2
  exit 1
fi

# Create config directory if it doesn't exist
mkdir -p /home/node/.clawdbot

# Generate config from template if it doesn't exist or if forced
# Set CLAWDBOT_FORCE_CONFIG_REGEN=1 to force regeneration even if config exists
FORCE_REGEN="${CLAWDBOT_FORCE_CONFIG_REGEN:-0}"
if [ ! -f /home/node/.clawdbot/clawdbot.json ] || [ "${FORCE_REGEN}" = "1" ]; then
  if [ "${FORCE_REGEN}" = "1" ]; then
    echo "Force regenerating config from template (CLAWDBOT_FORCE_CONFIG_REGEN=1)..."
  else
    echo "Generating config from template..."
  fi
  
  # Template file must exist
  if [ ! -f /app/clawdbot.json.template ]; then
    echo "Error: Template file /app/clawdbot.json.template not found" >&2
    exit 1
  fi
  
  # Export variables for envsubst (only the ones we need)
  export NEARAI_API_KEY
  export SLACK_BOT_TOKEN
  export SLACK_APP_TOKEN
  export CLAWDBOT_GATEWAY_TOKEN
  
  # Use envsubst to substitute environment variables in the template
  # Clawdbot supports ${VAR_NAME} syntax natively, so we can use the template directly
  if command -v envsubst >/dev/null 2>&1; then
    envsubst < /app/clawdbot.json.template > /home/node/.clawdbot/clawdbot.json
  else
    echo "Error: envsubst command not found (gettext-base package required)" >&2
    exit 1
  fi
  
  chown node:node /home/node/.clawdbot/clawdbot.json
  echo "Config file created at /home/node/.clawdbot/clawdbot.json"
fi

# Create workspace directory if it doesn't exist
mkdir -p /home/node/clawd
chown -R node:node /home/node/clawd

# Execute the command (clawdbot is installed globally)
exec "$@"
