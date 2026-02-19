# OpenClaw NEAR AI Worker

AI Worker built with OpenClaw and NEAR AI Cloud API.

## Repository layout

| Directory | Purpose |
|-----------|---------|
| **worker/** | OpenClaw worker Docker image (Dockerfile, entrypoint, config template). Single-tenant runs use this. |
| **compose-api/** | Multi-tenant Compose API (Rust/Axum). Spawns one Docker Compose project per user; requires Docker socket. |
| **deploy/** | Deployment configs and scripts: compose files (single-tenant, multi-tenant, nginx/HTTPS), nginx template, env examples, `deploy.sh`, `build-image.sh`. |

## Features

- **NEAR AI Cloud Integration**: Uses NEAR AI Cloud as the model provider
- **Docker Ready**: Easy deployment with Docker and Docker Compose

## Quick Start

### Prerequisites

- Docker and Docker Compose
- NEAR AI Cloud API key

### Environment Variables

Create a `.env` file (copy from `worker/env.example`):

```bash
cp worker/env.example .env
# Edit .env with your credentials
```

Required variables:
- `NEARAI_API_KEY`: NEAR AI Cloud API key

Optional variables:
- `OPENCLAW_FORCE_CONFIG_REGEN`: Set to `1` to force regeneration of config from template (default: `0`)
- `OPENCLAW_GATEWAY_BIND`: Gateway bind address — `lan` (default) or `loopback`. See [Gateway binding and security](#gateway-binding-and-security).
- `SSH_PUBKEY`: Your SSH public key (e.g. contents of `~/.ssh/id_ed25519.pub`). When set, enables SSH server on port 2222 for key-based login as user `agent`. See [SSH access](#ssh-access).

### Running

From the repo root:

```bash
# Start the service (builds worker image if needed)
docker compose -f deploy/docker-compose.yml up -d

# Or start in foreground to see logs:
docker compose -f deploy/docker-compose.yml up
```

### View Logs

```bash
docker compose -f deploy/docker-compose.yml logs -f openclaw-gateway
```

---

## Multi-Tenant Deployment

For deploying multiple isolated OpenClaw instances (one per user), use the multi-tenant setup with the Compose API.

### Prerequisites

- Docker and Docker Compose
- NEAR AI Cloud API key
- A server with Compose API port (default 47392) and 19001-19999 (user instances) accessible; for HTTPS, nginx and certbot on the host

### Setup

1. **Configure environment:**
   ```bash
   cp deploy/env.prod.example deploy/.env.prod
   # Edit deploy/.env.prod:
   # - OPENCLAW_HOST_ADDRESS (your server's public IP/hostname)
   # - ADMIN_TOKEN will be auto-generated if not set
   # Note: NEARAI_API_KEY is provided per-user in the create request
   ```

2. **Deploy** (from repo root):
   ```bash
   chmod +x deploy/dev.sh
   ./deploy/dev.sh
   ```

3. **Create users via Compose API:**
   ```bash
   # Set your admin token (from deploy/.env.prod)
   export ADMIN_TOKEN="your-token-here"
   
   # Create a user (with their NEAR AI API key and optional SSH public key)
   curl -X POST http://<server>:47392/users \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer $ADMIN_TOKEN" \
     -d '{
       "user_id": "alice",
       "nearai_api_key": "sk-user-nearai-api-key",
       "ssh_pubkey": "ssh-ed25519 AAAA... user@host"
     }'
   
   # Response includes gateway port, SSH port, and connection info:
   # {
   #   "user_id": "alice",
   #   "token": "abc123...",
   #   "gateway_port": 19001,
   #   "ssh_port": 19002,
   #   "url": "http://<server>:19001",
   #   "dashboard_url": "http://<server>:19001/?token=abc123...",
   #   "ssh_command": "ssh -p 19002 agent@<server>",
   #   "status": "running"
   # }
   ```

### Compose API Authentication

All API endpoints (except `/health`) require authentication via Bearer token:
```bash
curl -H "Authorization: Bearer $ADMIN_TOKEN" http://<server>:47392/users
```

The `ADMIN_TOKEN` must be a 32-character hex string. Generate one with:
```bash
openssl rand -hex 16
```

### Compose API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Health check (no auth required) |
| `POST` | `/users` | Create user (`{"user_id": "...", "nearai_api_key": "...", "ssh_pubkey": "..."}`) |
| `GET` | `/users` | List all users |
| `GET` | `/users/{id}` | Get user details |
| `DELETE` | `/users/{id}` | Delete user and container |
| `POST` | `/users/{id}/restart` | Restart user's container |
| `POST` | `/users/{id}/stop` | Stop user's container |
| `POST` | `/users/{id}/start` | Start user's container |

### User Access

Each user gets two consecutive ports:
- **Gateway port** (e.g., 19001): Web UI and API access at `http://<server>:<gateway_port>`
- **SSH port** (e.g., 19002): SSH access via `ssh -p <ssh_port> agent@<server>`

The SSH public key provided during user creation is injected into the container, allowing key-based SSH authentication.

### HTTPS with nginx and certbot

Production HTTPS uses **nginx** on the host with **certbot** for Let’s Encrypt. No reverse proxy runs in Docker.

1. **Set domain in env**
   - In `.env.prod`: `OPENCLAW_DOMAIN=openclaw.example.com` (your domain).

2. **Start the stack** (management API only; nginx runs on the host)
   ```bash
   docker compose -f docker-compose.nginx.yml --env-file .env.prod up -d
   ```
   The API listens on `127.0.0.1:47392` so only nginx can reach it.

3. **Configure nginx**
   - Copy `nginx-openclaw.conf` into your nginx config (e.g. `/etc/nginx/sites-available/openclaw`).
   - Replace `OPENCLAW_DOMAIN` in the file with your domain (e.g. `openclaw.example.com`).
   - Enable the site and reload nginx: `sudo nginx -t && sudo systemctl reload nginx`.

4. **Get certificates**
   ```bash
   sudo certbot --nginx -d openclaw.example.com -d "*.openclaw.example.com"
   ```
   Certbot will add `listen 443 ssl` and certificate paths to the server block.

5. **DNS**
   - A record: `openclaw.example.com` → your server IP.
   - A record: `*.openclaw.example.com` → your server IP.

After this, the main domain serves the Compose API over HTTPS, and each user gets a subdomain (e.g. `alice.openclaw.example.com`) proxied to their OpenClaw instance automatically.

### Device Pairing

- The **first device** connecting to each user's instance is auto-approved
- Subsequent devices require manual approval via Telegram bot or CLI:
  ```bash
  # Via container CLI (gateway container name is openclaw-<user_id>-gateway-1)
  docker exec -u agent openclaw-<user_id>-gateway-1 openclaw devices list
  docker exec -u agent openclaw-<user_id>-gateway-1 openclaw devices approve <request-id>
  ```

### Firewall Configuration

Ensure these ports are open:
- `47392` - Compose API (or bind to localhost only when behind nginx)
- `19001-19999` - User OpenClaw instances (gateway + SSH ports)

---

### Testing

```bash
# Check configuration (single-tenant: use deploy/docker-compose.yml)
docker compose -f deploy/docker-compose.yml exec openclaw-gateway openclaw doctor

# List available models
docker compose -f deploy/docker-compose.yml exec openclaw-gateway openclaw models list
```

## Configuration

The configuration is automatically generated from environment variables on first run. The entrypoint script creates `/home/agent/.openclaw/openclaw.json` with:

- **NEAR AI Cloud** as the model provider
- **auto** (`nearai/auto`) as the default primary model, letting NEAR AI Cloud route to the best available model

### Available Models

The worker is preconfigured to use NEAR AI Cloud's `auto` routing, which automatically selects the best available model for each request.

| Model | ID | Description |
|-------|-----|-------------|
| **auto** (default) | `nearai/auto` | NEAR AI Cloud model routing — automatically selects the best available model. |

**Using a specific model**

- **Primary model**: The default is `nearai/auto`. To use a specific NEAR AI model, edit `openclaw.json` (or the template) and set `agents.defaults.model.primary` to a specific model ID, then add the model to `models.providers.nearai.models`.
- **Per-request**: When calling the gateway API (chat completions or responses), specify the `model` parameter in your request body with the desired model ID.
- **List at runtime**: Run `openclaw models list` inside the container to see all configured models and their IDs.

### Updating Configuration

**Important**: The configuration file is only generated once. If you change environment variables after the first run, the configuration will **not** be automatically updated.

To update the configuration after changing environment variables, you have three options:

1. **Force regeneration** (recommended): Set `OPENCLAW_FORCE_CONFIG_REGEN=1` and restart the container:
   ```bash
   # In deploy/docker-compose.yml, add to environment:
   OPENCLAW_FORCE_CONFIG_REGEN: "1"
   
   # Or when running:
   docker compose -f deploy/docker-compose.yml run -e OPENCLAW_FORCE_CONFIG_REGEN=1 openclaw-gateway
   ```

2. **Delete and regenerate**: Remove the config file and restart:
   ```bash
   docker compose -f deploy/docker-compose.yml exec openclaw-gateway rm /home/agent/.openclaw/openclaw.json
   docker compose -f deploy/docker-compose.yml restart openclaw-gateway
   ```

3. **Manual edit**: Edit the config file directly:
   ```bash
   docker compose -f deploy/docker-compose.yml exec openclaw-gateway vi /home/agent/.openclaw/openclaw.json
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

## Built-in tools (su, sudo)

- **su**: The `su` command is available (`login` package installed), but the `root` account is password-locked by default, so `su -` to root will typically **not** work unless you explicitly set a root password or adjust PAM policy.
- **sudo**: The `agent` user has passwordless `sudo` enabled unconditionally (via `/etc/sudoers.d/agent`). Use `sudo su -` to become root, or `sudo <command>` for one-off elevation.

## Troubleshooting

### Check Container Status

```bash
docker compose -f deploy/docker-compose.yml ps
```

### View Logs

```bash
docker compose -f deploy/docker-compose.yml logs -f openclaw-gateway
```

⚠️ **Security Note**: Container logs may contain sensitive information. Ensure logs are properly secured and not exposed publicly.

### Verify Configuration

```bash
docker compose -f deploy/docker-compose.yml exec openclaw-gateway openclaw doctor
```

### List Models

```bash
docker compose -f deploy/docker-compose.yml exec openclaw-gateway openclaw models list
```

### Security Best Practices

- **Never log sensitive values**: The entrypoint script is designed to never log API keys, tokens, SSH keys, or secrets
- **Secure log storage**: Ensure Docker logs are stored securely and access is restricted
- **Environment variables**: Use `.env` files with proper permissions (chmod 600) or secret management systems
- **Container inspection**: Be cautious when using `docker inspect` or `docker exec` as these may expose environment variables
- **Gateway binding**: The default is `lan`; follow the guidance in [Gateway binding and security](#gateway-binding-and-security). Set `OPENCLAW_GATEWAY_BIND=loopback` to restrict to localhost only.
- **SSH**: Only enable SSH when needed by setting `SSH_PUBKEY`. Use key-based auth only; ensure port 2222 is not exposed to the internet unless you intend external access and have secured the host.

## Common Commands (docker compose)

All from repo root. Single-tenant (one worker):

- `docker build -t openclaw-nearai-worker:latest ./worker` - Build the worker image
- `docker compose -f deploy/docker-compose.yml up -d` - Start the service
- `docker compose -f deploy/docker-compose.yml down` - Stop the service
- `docker compose -f deploy/docker-compose.yml logs -f openclaw-gateway` - View logs
- `docker compose -f deploy/docker-compose.yml exec openclaw-gateway openclaw doctor` - Test configuration
- `docker compose -f deploy/docker-compose.yml exec openclaw-gateway openclaw models list` - List available models
- `docker compose -f deploy/docker-compose.yml exec openclaw-gateway /bin/bash` - Open shell in container
- `docker compose -f deploy/docker-compose.yml down -v` - Remove containers and volumes

Multi-tenant (Compose API + per-user workers):

- `./deploy/dev.sh` - Build all images and start the local development stack
- `./deploy/dev.sh --no-build` - Start without rebuilding images
- `./deploy/dev.sh --down` - Tear down the stack

## Commands (CVM)

- `ssh -o ProxyCommand="openssl s_client -quiet -connect %h:443 -servername %h" root@<instance-id>-22.infra.near.ai` - SSH login to CVM instance
- `docker exec openclaw-gateway openclaw models list` - List available models
- `docker exec openclaw-gateway openclaw logs` - View logs
- `docker exec openclaw-gateway openclaw config` - Show config
- `docker exec openclaw-gateway openclaw sysinfo` - Show system info
- `docker exec -it openclaw-gateway /bin/bash` - Open shell in container

## License

MIT License - see [LICENSE](LICENSE) file for details.
