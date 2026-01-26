# Clawdbot NEAR AI Worker

AI Worker built with Clawdbot and NEAR AI Cloud API, configured for Slack integration.

## Features

- **NEAR AI Cloud Integration**: Uses NEAR AI Cloud as the model provider
- **Slack Bot**: Pre-configured Slack bot for team collaboration
- **Docker Ready**: Easy deployment with Docker and Docker Compose
- **TEE Infrastructure**: Ansible playbooks for deployment on TEE infrastructure

## Quick Start

### Prerequisites

- Docker and Docker Compose
- NEAR AI Cloud API key
- Slack Bot Token and App Token

### Environment Variables

Create a `.env` file (copy from `env.example`):

```bash
cp env.example .env
# Edit .env with your credentials
```

Required variables:
- `NEARAI_API_KEY`: NEAR AI Cloud API key
- `SLACK_BOT_TOKEN`: Slack bot token (xoxb-...)
- `SLACK_APP_TOKEN`: Slack app token (xapp-...)
- `CLAWDBOT_GATEWAY_TOKEN`: Gateway authentication token

Optional variables:
- `SLACK_SIGNING_SECRET`: Slack signing secret (for HTTP mode)
- `CLAWDBOT_FORCE_CONFIG_REGEN`: Set to `1` to force regeneration of config from template (default: `0`)

### Building

```bash
# Build the Docker image
docker build -t clawdbot-nearai-worker:latest -f Dockerfile .

# Or use docker-compose (builds automatically):
docker-compose build
```

### Running

```bash
# Start the service (builds if needed)
docker-compose up -d

# Or start in foreground to see logs:
docker-compose up
```

### View Logs

```bash
docker-compose logs -f clawdbot-gateway
```

### Testing

```bash
# Check configuration
docker-compose exec clawdbot-gateway clawdbot doctor

# List available models
docker-compose exec clawdbot-gateway clawdbot models list
```

## Configuration

The configuration is automatically generated from environment variables on first run. The entrypoint script creates `/home/node/.clawdbot/clawdbot.json` with:

- **NEAR AI Cloud** as the model provider
- **GLM-4.7** (`zai-org/GLM-4.7`) as the default model
- **Slack** configured with `dmPolicy: "pairing"` (DMs require approval) and `groupPolicy: "allowlist"` (groups require explicit allowlist, bot is mention-gated).

### Updating Configuration

**Important**: The configuration file is only generated once. If you change environment variables after the first run, the configuration will **not** be automatically updated.

To update the configuration after changing environment variables, you have three options:

1. **Force regeneration** (recommended): Set `CLAWDBOT_FORCE_CONFIG_REGEN=1` and restart the container:
   ```bash
   # In docker-compose.yml, add to environment:
   CLAWDBOT_FORCE_CONFIG_REGEN: "1"
   
   # Or when running:
   docker-compose run -e CLAWDBOT_FORCE_CONFIG_REGEN=1 clawdbot-gateway
   ```

2. **Delete and regenerate**: Remove the config file and restart:
   ```bash
   docker-compose exec clawdbot-gateway rm /home/node/.clawdbot/clawdbot.json
   docker-compose restart clawdbot-gateway
   ```

3. **Manual edit**: Edit the config file directly:
   ```bash
   docker-compose exec clawdbot-gateway vi /home/node/.clawdbot/clawdbot.json
   ```

### Customizing Configuration

After the first run, you can edit `/home/node/.clawdbot/clawdbot.json` directly, or modify the `entrypoint.sh` script to change the default configuration.

## Deployment on TEE Infrastructure

Quick deployment:

```bash
cd ../cvm-ansible-playbooks
export NEARAI_API_KEY="sk-your-key"
export SLACK_BOT_TOKEN="xoxb-your-token"
export SLACK_APP_TOKEN="xapp-your-token"
export CLAWDBOT_GATEWAY_TOKEN="your-gateway-token"
ansible-playbook -i inventory.ini playbooks/deploy/clawdbot_nearai_worker_prod.yaml
```

## Slack Setup

1. Create a Slack App at https://api.slack.com/apps
2. Enable **Socket Mode** (recommended) or HTTP mode
3. Get **Bot Token** (`xoxb-...`) and **App Token** (`xapp-...`)
4. Install the app to your workspace
5. Invite the bot to channels: `/invite @YourBotName`

## Ports

- **18789**: Gateway WebSocket and HTTP API
- **18790**: Browser bridge (if enabled)

## Troubleshooting

### Check Container Status

```bash
docker-compose ps
```

### View Logs

```bash
docker-compose logs -f clawdbot-gateway
```

⚠️ **Security Note**: Container logs may contain sensitive information. Ensure logs are properly secured and not exposed publicly.

### Verify Configuration

```bash
docker-compose exec clawdbot-gateway clawdbot doctor
```

### List Models

```bash
docker-compose exec clawdbot-gateway clawdbot models list
```

### Security Best Practices

- **Never log sensitive values**: The entrypoint script is designed to never log API keys, tokens, or secrets
- **Secure log storage**: Ensure Docker logs are stored securely and access is restricted
- **Environment variables**: Use `.env` files with proper permissions (chmod 600) or secret management systems
- **Container inspection**: Be cautious when using `docker inspect` or `docker exec` as these may expose environment variables

## Common Commands

- `docker build -t clawdbot-nearai-worker:latest -f Dockerfile .` - Build the Docker image
- `docker-compose up -d` - Start the service
- `docker-compose down` - Stop the service
- `docker-compose logs -f clawdbot-gateway` - View logs
- `docker-compose exec clawdbot-gateway clawdbot doctor` - Test configuration
- `docker-compose exec clawdbot-gateway clawdbot models list` - List available models
- `docker-compose exec clawdbot-gateway /bin/bash` - Open shell in container
- `docker-compose down -v` - Remove containers and volumes

## License

See the main Clawdbot repository for license information.
