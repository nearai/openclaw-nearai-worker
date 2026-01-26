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

Optional variables:
- `CLAWDBOT_GATEWAY_TOKEN`: Gateway authentication token
- `SLACK_SIGNING_SECRET`: Slack signing secret (for HTTP mode)

### Building

```bash
# Build the Docker image
make build

# Or manually:
docker build -t clawdbot-nearai-worker:latest -f Dockerfile .

# Or use docker-compose (builds automatically):
docker-compose build
```

### Running

```bash
# Start the service (builds if needed)
make run

# Or manually:
docker-compose up -d
```

### View Logs

```bash
make logs
```

### Testing

```bash
# Check configuration
make test

# List available models
make models
```

## Configuration

The configuration is automatically generated from environment variables on first run. The entrypoint script creates `/home/node/.clawdbot/clawdbot.json` with:

- **NEAR AI Cloud** as the model provider
- **GLM-4.7** (`zai-org/GLM-4.7`) as the default model
- **Slack** configured for open access (all channels and users)

### Customizing Configuration

After the first run, you can edit `/home/node/.clawdbot/clawdbot.json` directly, or modify the `entrypoint.sh` script to change the default configuration.

## Deployment on TEE Infrastructure

See the [Ansible Deployment Guide](../cvm-ansible-playbooks/docs/clawdbot-deployment.md) for instructions on deploying to TEE infrastructure.

Quick deployment:

```bash
cd ../cvm-ansible-playbooks
export NEARAI_API_KEY="sk-your-key"
export SLACK_BOT_TOKEN="xoxb-your-token"
export SLACK_APP_TOKEN="xapp-your-token"
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

### Verify Configuration

```bash
docker-compose exec clawdbot-gateway clawdbot doctor
```

### List Models

```bash
docker-compose exec clawdbot-gateway clawdbot models list
```

## Makefile Commands

- `make build` - Build the Docker image
- `make run` - Start the service
- `make stop` - Stop the service
- `make logs` - View logs
- `make test` - Test configuration
- `make models` - List available models
- `make shell` - Open shell in container
- `make clean` - Remove containers and volumes
- `make help` - Show all commands

## License

See the main Clawdbot repository for license information.
