# OpenClaw NEAR AI Worker

AI Worker built with OpenClaw and NEAR AI Cloud API.

## Features

- **NEAR AI Cloud Integration**: Uses NEAR AI Cloud as the model provider
- **Docker Ready**: Easy deployment with Docker and Docker Compose

## Quick Start

### Prerequisites

- Docker and Docker Compose
- NEAR AI Cloud API key

### Environment Variables

Create a `.env` file (copy from `env.example`):

```bash
cp env.example .env
# Edit .env with your credentials
```

Required variables:
- `NEARAI_API_KEY`: NEAR AI Cloud API key

Optional variables:
- `OPENCLAW_FORCE_CONFIG_REGEN`: Set to `1` to force regeneration of config from template (default: `0`)

### Running

```bash
# Start the service (builds if needed)
docker compose up -d

# Or start in foreground to see logs:
docker compose up
```

### View Logs

```bash
docker compose logs -f openclaw-gateway
```

### Testing

```bash
# Check configuration
docker compose exec openclaw-gateway openclaw doctor

# List available models
docker compose exec openclaw-gateway openclaw models list
```

## Configuration

The configuration is automatically generated from environment variables on first run. The entrypoint script creates `/home/node/.openclaw/openclaw.json` with:

- **NEAR AI Cloud** as the model provider
- **GLM-4.7** (`zai-org/GLM-4.7`) as the default model

### Updating Configuration

**Important**: The configuration file is only generated once. If you change environment variables after the first run, the configuration will **not** be automatically updated.

To update the configuration after changing environment variables, you have three options:

1. **Force regeneration** (recommended): Set `OPENCLAW_FORCE_CONFIG_REGEN=1` and restart the container:
   ```bash
   # In docker compose.yml, add to environment:
   OPENCLAW_FORCE_CONFIG_REGEN: "1"
   
   # Or when running:
   docker compose run -e OPENCLAW_FORCE_CONFIG_REGEN=1 openclaw-gateway
   ```

2. **Delete and regenerate**: Remove the config file and restart:
   ```bash
   docker compose exec openclaw-gateway rm /home/node/.openclaw/openclaw.json
   docker compose restart openclaw-gateway
   ```

3. **Manual edit**: Edit the config file directly:
   ```bash
   docker compose exec openclaw-gateway vi /home/node/.openclaw/openclaw.json
   ```

### Customizing Configuration

After the first run, you can edit `/home/node/.openclaw/openclaw.json` directly, or modify the `entrypoint.sh` script to change the default configuration.

## Deployment on TEE Infrastructure

This Docker image can be deployed on TEE (Trusted Execution Environment) infrastructure for enhanced security. The container runs with the same configuration and can be deployed using your preferred container orchestration platform on TEE-enabled infrastructure.

Key considerations for TEE deployment:
- Ensure all required environment variables are securely provided
- Use secure secret management systems for API keys and tokens
- Configure appropriate network policies and access controls
- Monitor container health using the built-in healthcheck

## Ports

- **18789**: Gateway WebSocket and HTTP API
- **18790**: Browser bridge (if enabled)

## Troubleshooting

### Check Container Status

```bash
docker compose ps
```

### View Logs

```bash
docker compose logs -f openclaw-gateway
```

⚠️ **Security Note**: Container logs may contain sensitive information. Ensure logs are properly secured and not exposed publicly.

### Verify Configuration

```bash
docker compose exec openclaw-gateway openclaw doctor
```

### List Models

```bash
docker compose exec openclaw-gateway openclaw models list
```

### Security Best Practices

- **Never log sensitive values**: The entrypoint script is designed to never log API keys, tokens, or secrets
- **Secure log storage**: Ensure Docker logs are stored securely and access is restricted
- **Environment variables**: Use `.env` files with proper permissions (chmod 600) or secret management systems
- **Container inspection**: Be cautious when using `docker inspect` or `docker exec` as these may expose environment variables

## Common Commands (docker compose)

- `docker build -t openclaw-nearai-worker:latest -f Dockerfile .` - Build the Docker image
- `docker compose up -d` - Start the service
- `docker compose down` - Stop the service
- `docker compose logs -f openclaw-gateway` - View logs
- `docker compose exec openclaw-gateway openclaw doctor` - Test configuration
- `docker compose exec openclaw-gateway openclaw models list` - List available models
- `docker compose exec openclaw-gateway /bin/bash` - Open shell in container
- `docker compose down -v` - Remove containers and volumes

## Commands (CVM)

- `ssh -o ProxyCommand="openssl s_client -quiet -connect %h:443 -servername %h" root@<instance-id>-22.infra.near.ai` - SSH login to CVM instance
- `docker exec openclaw-gateway openclaw models list` - List available models
- `docker exec openclaw-gateway openclaw logs` - View logs
- `docker exec openclaw-gateway openclaw config` - Show config
- `docker exec openclaw-gateway openclaw sysinfo` - Show system info
- `docker exec -it openclaw-gateway /bin/bash` - Open shell in container


## License

MIT License - see [LICENSE](LICENSE) file for details.
