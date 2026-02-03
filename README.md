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
- `OPENCLAW_GATEWAY_BIND`: Gateway bind address — `lan` (default) or `loopback`. See [Gateway binding and security](#gateway-binding-and-security).
- `SSH_PUBKEY`: Your SSH public key (e.g. contents of `~/.ssh/id_ed25519.pub`). When set, enables SSH server on port 2222 for key-based login as user `agent`. See [SSH access](#ssh-access).

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

The configuration is automatically generated from environment variables on first run. The entrypoint script creates `/home/agent/.openclaw/openclaw.json` with:

- **NEAR AI Cloud** as the model provider
- **GLM-4.7** (`zai-org/GLM-4.7`) as the default primary model
- Three models available for agents: GLM-4.7, DeepSeek V3.1, and Qwen3 30B A3B Instruct

### Available Models

The worker is preconfigured with the following models from NEAR AI Cloud. You can use any of them when sending requests to the gateway or when configuring agents.

| Model | ID | Context | Reasoning | Description |
|-------|-----|---------|-----------|-------------|
| **GLM-4.7** (default) | `nearai/zai-org/GLM-4.7` | 200K tokens | No | Z.ai GLM 4.7 — strong agentic coding, tool use, and reasoning. Default primary model. |
| **DeepSeek V3.1** | `nearai/deepseek-ai/DeepSeek-V3.1` | 128K tokens | Yes | Hybrid model with thinking and non-thinking modes. Good for complex reasoning and tool use. |
| **Qwen3 30B A3B Instruct** | `nearai/Qwen/Qwen3-30B-A3B-Instruct-2507` | 262K tokens | No | MoE model with long context. Efficient for instruction following and multilingual tasks. |

**Using a specific model**

- **Primary model**: The default primary model is GLM-4.7. To change it, edit `openclaw.json` (or the template) and set `agents.defaults.model.primary` to one of the IDs above (e.g. `nearai/deepseek-ai/DeepSeek-V3.1`).
- **Per-request**: When calling the gateway API (chat completions or responses), specify the `model` parameter in your request body with the desired model ID.
- **List at runtime**: Run `openclaw models list` inside the container to see all configured models and their IDs.

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
   docker compose exec openclaw-gateway rm /home/agent/.openclaw/openclaw.json
   docker compose restart openclaw-gateway
   ```

3. **Manual edit**: Edit the config file directly:
   ```bash
   docker compose exec openclaw-gateway vi /home/agent/.openclaw/openclaw.json
   ```

### Customizing Configuration

After the first run, you can edit `/home/agent/.openclaw/openclaw.json` directly to:
- Change the **primary model** (`agents.defaults.model.primary`) to any of the available model IDs (see [Available Models](#available-models))
- Add or remove models in `agents.defaults.models`
- Adjust concurrency, workspace paths, or gateway settings


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
- **2222**: SSH (when `SSH_PUBKEY` is set). Published as `0.0.0.0:2222` so the container is reachable from outside the host.

## Gateway binding and security

The gateway bind setting controls which network interfaces the gateway listens on:

- **`lan`** (default): Listens on all interfaces (0.0.0.0). The gateway is reachable from any device on the local network (and from the internet if the host is exposed).
- **`loopback`**: Listens only on localhost (127.0.0.1). Access is limited to the same host. Use this when only local processes or port-forwarding need the gateway.

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

- **Never log sensitive values**: The entrypoint script is designed to never log API keys, tokens, SSH keys, or secrets
- **Secure log storage**: Ensure Docker logs are stored securely and access is restricted
- **Environment variables**: Use `.env` files with proper permissions (chmod 600) or secret management systems
- **Container inspection**: Be cautious when using `docker inspect` or `docker exec` as these may expose environment variables
- **Gateway binding**: The default is `lan`; follow the guidance in [Gateway binding and security](#gateway-binding-and-security). Set `OPENCLAW_GATEWAY_BIND=loopback` to restrict to localhost only.
- **SSH**: Only enable SSH when needed by setting `SSH_PUBKEY`. Use key-based auth only; ensure port 2222 is not exposed to the internet unless you intend external access and have secured the host.

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
