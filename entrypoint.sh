#!/bin/bash
set -e

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

# Create config directory if it doesn't exist
mkdir -p /home/node/.clawdbot

# Generate config from template if it doesn't exist
if [ ! -f /home/node/.clawdbot/clawdbot.json ]; then
  echo "Generating config from template..."
  
  # Template file must exist
  if [ ! -f /app/clawdbot.json.template ]; then
    echo "Error: Template file /app/clawdbot.json.template not found" >&2
    exit 1
  fi
  
  # Export variables for envsubst (only the ones we need)
  export NEARAI_API_KEY
  export SLACK_BOT_TOKEN
  export SLACK_APP_TOKEN
  export CLAWDBOT_GATEWAY_TOKEN="${CLAWDBOT_GATEWAY_TOKEN:-}"
  
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
