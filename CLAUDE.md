# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

OpenClaw NEAR AI Worker — a Dockerized AI worker that runs an [OpenClaw](https://openclaw.dev) gateway backed by NEAR AI Cloud as the model provider. There is no application source code (no Python/JS app); the repo is entirely infrastructure: a Dockerfile, entrypoint script, config template, Docker Compose file, and CI pipeline.

## Key Files

- `Dockerfile` — Builds the worker image (Node 24 base, installs `openclaw` from npm globally, creates `agent` user UID 1001)
- `entrypoint.sh` — Runs as root: sets up SSH (if `SSH_PUBKEY` set), generates `openclaw.json` from template via `envsubst`, then loops `runuser -p -u agent -- "$@"` with auto-restart
- `openclaw.json.template` — Config template with `${NEARAI_API_KEY}`, `${OPENCLAW_GATEWAY_TOKEN}`, `${OPENCLAW_GATEWAY_BIND}` placeholders
- `docker-compose.yml` — Single service `openclaw-gateway`, two named volumes (`openclaw-config`, `openclaw-workspace`), ports 18789/18790/2222
- `build-image.sh` — Reproducible build script using `docker buildx` + `skopeo` for OCI archive output with `--push` option
- `.github/workflows/build.yml` — CI: builds on push to `main` or `v*` tags, pushes to Docker Hub, generates Sigstore attestation

## Build & Run Commands

```bash
# Local development — start in foreground
docker compose up

# Start detached
docker compose up -d

# Build image locally (requires docker, skopeo, jq, git)
./build-image.sh

# Build and push to registry
./build-image.sh --push <repo>:<tag>

# Standalone Docker build (without reproducibility tooling)
docker build -t openclaw-nearai-worker:latest -f Dockerfile .
```

## Debugging Inside the Container

> **Full debugging guide**: See [`worker/DEBUGGING.md`](worker/DEBUGGING.md) for comprehensive instructions on debugging chat completions, model behavior, session inspection, raw stream capture, and common failure patterns.

```bash
docker compose exec openclaw-gateway openclaw doctor      # verify config
docker compose exec openclaw-gateway openclaw models list  # list models
docker compose exec openclaw-gateway /bin/bash             # shell access
docker compose logs -f openclaw-gateway                    # tail logs
```

### OpenClaw Logs

The gateway writes detailed logs to `/tmp/openclaw/openclaw-YYYY-MM-DD.log` inside the container. These are raw JSON — use `openclaw logs` for formatted output.

```bash
# Formatted log tail (built-in, much easier to read than raw JSON)
docker compose exec openclaw-gateway runuser -p -u agent -- openclaw logs --limit 50 --plain

# Follow live (formatted)
docker compose exec openclaw-gateway runuser -p -u agent -- openclaw logs --follow --plain

# Raw log with jq (agent runs only, skip ws noise)
docker compose exec openclaw-gateway bash -c \
  'tail -f /tmp/openclaw/openclaw-$(date -u +%Y-%m-%d).log' \
  | jq -r --unbuffered 'select(."0" | test("agent")) | [._meta.date[11:19], (."1" | if type == "string" then . else "" end)] | join(" ")'

# Check for errors (API failures, tool errors, permission issues)
docker compose exec openclaw-gateway bash -c 'grep -i "error\|fail\|400\|500" /tmp/openclaw/openclaw-$(date -u +%Y-%m-%d).log | tail -20'
```

### Session Inspection

```bash
# List sessions (shows token counts, model, context window %)
docker compose exec openclaw-gateway runuser -p -u agent -- openclaw sessions

# Detailed session metadata via RPC (JSON)
docker compose exec openclaw-gateway runuser -p -u agent -- openclaw gateway call sessions.list

# Full conversation history (messages, tool calls, usage, errors)
docker compose exec openclaw-gateway bash -c \
  'cat /home/agent/.openclaw/agents/main/sessions/SESSION_ID.jsonl | jq'

# Token usage & costs (last 7 days)
docker compose exec openclaw-gateway runuser -p -u agent -- openclaw gateway usage-cost --json --days 7
```

### Channel & Plugin Status

```bash
docker compose exec openclaw-gateway openclaw channels status   # channel health
docker compose exec openclaw-gateway openclaw channels list     # configured channels
docker compose exec openclaw-gateway openclaw plugins list      # loaded plugins
```

### Config Inspection

```bash
# Check current runtime config values
docker compose exec openclaw-gateway bash -c 'runuser -p -u agent -- openclaw config get agents.defaults'
docker compose exec openclaw-gateway bash -c 'runuser -p -u agent -- openclaw config get models'

# Check workspace bootstrap files
docker compose exec openclaw-gateway ls -la /home/agent/openclaw/
```

### Permission Issues

Files under `/home/agent/.openclaw/` can sometimes be created as root by the gateway process. Fix with:

```bash
docker compose exec openclaw-gateway chown -R agent:agent /home/agent/.openclaw
```

The entrypoint pre-creates common subdirs (`identity/`, `credentials/`, `cron/`, `agents/`, `canvas/`) with correct ownership, and runs `chown` before each gateway launch to catch files created during previous runs.

## Local Testing (Control UI)

### First-time setup

1. Build the local image and start with fresh volumes:
   ```bash
   docker build -t openclaw-nearai-worker:local -f Dockerfile .
   docker compose down -v
   OPENCLAW_FORCE_CONFIG_REGEN=1 docker compose up -d
   ```

2. Get the gateway token:
   ```bash
   docker compose exec openclaw-gateway openclaw dashboard
   ```

3. Open the tokenized URL in your browser:
   ```
   http://localhost:18789/?token=<token-from-step-2>
   ```

4. The browser will show "pairing required". Approve the device via loopback:
   ```bash
   # Since openclaw 2026.2.15, CLI must connect via loopback for auto-pairing.
   # With bind=lan, the CLI uses the LAN IP by default, which requires manual pairing.
   TOKEN=$(docker compose exec openclaw-gateway bash -c 'jq -r .gateway.auth.token /home/agent/.openclaw/openclaw.json')
   docker compose exec openclaw-gateway runuser -p -u agent -- env HOME=/home/agent \
     openclaw devices list --url ws://127.0.0.1:18789 --token "$TOKEN"
   docker compose exec openclaw-gateway runuser -p -u agent -- env HOME=/home/agent \
     openclaw devices approve <request-id> --url ws://127.0.0.1:18789 --token "$TOKEN"
   ```

   Alternatively, set `OPENCLAW_AUTO_APPROVE_DEVICES=1` in your `.env` to auto-approve the first device.

5. The Control UI should now connect. Refresh the page if needed.

### Forcing config regeneration

Config is generated once and persisted in the `openclaw-config` Docker volume. To regenerate from template:

```bash
# Option A: Set env var (regenerates on next start)
OPENCLAW_FORCE_CONFIG_REGEN=1 docker compose up -d

# Option B: Remove volumes entirely (fresh start, loses sessions)
docker compose down -v && docker compose up -d
```

### Troubleshooting

- **`token_mismatch`**: Token changed after config regen. Get the new token with `openclaw dashboard`.
- **`pairing required`**: New browser/device needs approval. Must use loopback connection (see step 4 above). Or set `OPENCLAW_AUTO_APPROVE_DEVICES=1` to auto-approve the first device.
- **Docker Desktop for Mac**: Host connections appear as `remote=149.154.166.110` inside the container — this is normal Docker Desktop VM NAT behavior, not external traffic.
- **Page won't load with `--bind loopback`**: Docker port forwarding can't reach container's loopback. Use `--bind lan` (the default).

### Restarting the Gateway

The container does **not** use systemd — `openclaw gateway install/restart/start/stop` will not work. Use Docker commands instead:

```bash
# Restart the container (quickest way to restart the gateway)
docker compose restart openclaw-gateway

# Full recreate (re-runs entrypoint setup from scratch)
docker compose down && docker compose up -d

# If the gateway is crash-looping, check logs first:
docker compose logs --tail=50 openclaw-gateway
```

The entrypoint's `while true` loop automatically restarts the gateway on exit with a 5-second delay (configurable via `OPENCLAW_RESTART_DELAY`). If the gateway process crashes, it recovers without needing a container restart.

## Architecture Notes

- **No application code to lint or test** — the repo contains only Docker/shell infrastructure. There are no unit tests, linters, or build steps beyond the Docker image build.
- **Config generation is one-shot** — `entrypoint.sh` only generates `openclaw.json` on first run (or when `OPENCLAW_FORCE_CONFIG_REGEN=1`). The config lives in the `openclaw-config` Docker volume.
- **Process runs as non-root** — entrypoint runs as root for setup, then enters a `while true` restart loop that runs the gateway as `agent` (UID 1001) via `runuser`. The loop auto-restarts the gateway on crash with a configurable delay (`OPENCLAW_RESTART_DELAY`, default 5s).
- **init: true (tini) as PID 1** — Docker Compose sets `init: true` so tini runs as PID 1, properly reaping zombie processes and forwarding signals. The entrypoint restart loop provides automatic recovery. To restart the gateway: `docker compose restart openclaw-gateway`. For a full recreate: `docker compose down && docker compose up -d`.
- **No systemd** — systemd was evaluated (PR #37) but rejected because it requires `privileged: true` in Docker, which is a security concern. OpenClaw's `openclaw gateway run` (foreground mode) is the intended Docker approach. The `openclaw gateway install/restart/start/stop` subcommands are designed for bare-metal systemd hosts, not containers.
- **Reproducible builds** — `build-image.sh` uses buildx with `SOURCE_DATE_EPOCH=0` and `rewrite-timestamp=true` for deterministic image digests. CI generates Sigstore provenance attestations.
- **Gateway auth** — a random 32-byte hex token is auto-generated on first run if `OPENCLAW_GATEWAY_TOKEN` is not set.
- **Streaming** — `patch-streaming.js` injects per-model streaming control into pi-ai's `openai-completions.js` at build time. Each model in `agents.defaults.models` can set `"streaming": true` or `"streaming": false` (default). When `false`, the patch forces `stream: false` on the API call and synthesizes stream events from the complete response. When `true`, the original pi-ai streaming behavior is used. The config is read from `/home/agent/.openclaw/openclaw.json` on every API call, so changes take effect without restart. Separate settings exist for channel-level delivery: `blockStreamingDefault` (agent-level, `"off"`/`"on"`) and `streamMode` (Telegram-only, `"off"`/`"partial"`/`"block"`).
- **Device pairing and loopback** — Since openclaw 2026.2.15, the CLI resolves gateway targets using the `bind` mode. With `bind=lan`, the CLI connects via the LAN IP, and the gateway treats it as a remote client requiring manual pairing. To run CLI commands inside the container (e.g., for auto-approve), use `--url ws://127.0.0.1:18789 --token <token>` so the gateway recognizes it as a local client and auto-approves. See openclaw #16299, #11448.
- **Auto-updates disabled** — `update.checkOnStart` is set to `false` in the config template. Openclaw's self-update mechanism can reinstall the npm package at runtime, which nukes the streaming patch applied by `patch-streaming.js` during the Docker build. Since the image is built with a pinned version and a build-time patch, runtime updates must be disabled. See [openclaw#6318](https://github.com/openclaw/openclaw/issues/6318).

## Environment Variables

Required: `NEARAI_API_KEY`

Optional: `OPENCLAW_FORCE_CONFIG_REGEN`, `OPENCLAW_GATEWAY_BIND` (`lan`|`loopback`), `SSH_PUBKEY`, `OPENCLAW_GATEWAY_TOKEN`, `OPENCLAW_AUTO_APPROVE_DEVICES` (auto-approve first device pairing)

## Security Considerations

- `entrypoint.sh` must never log API keys, tokens, or SSH keys — only log variable *names* in error messages.
- Do not enable `set -x` in entrypoint — it exposes all variable values.
