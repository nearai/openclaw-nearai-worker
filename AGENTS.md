## Cursor Cloud specific instructions

This is a Docker/shell infrastructure repo with no application source code. See `CLAUDE.md` for full project overview and `README.md` for usage.

### Services overview

| Service | Source | Build | Test |
|---------|--------|-------|------|
| **worker** | `worker/` | `docker build -t openclaw-nearai-worker:local ./worker` | N/A (Docker image only) |
| **compose-api** | `compose-api/` (Rust/Axum) | `docker build -t openclaw-compose-api:local ./compose-api` | `cd compose-api && cargo test` |
| **ssh-bastion** | `ssh-bastion/` | `docker build -t openclaw-ssh-bastion:local ./ssh-bastion` | N/A |
| **ingress** | `ingress/` | `docker build -t openclaw-ingress:local ./ingress` | N/A |
| **updater** | `updater/` | `docker build -f updater/Dockerfile -t openclaw-updater:local .` | N/A |

### Automated tests

The only automated tests are in `compose-api/`: run `cargo test` from that directory. Requires Rust 1.93+.

### Running services

- **Single-tenant** (one worker): `NEARAI_API_KEY=<key> docker compose -f deploy/docker-compose.yml up -d`
- **Multi-tenant** (full stack): `./deploy/dev.sh` (builds all images, starts local registry + compose-api + bastion + nginx + updater)
- See `README.md` for full commands and `CLAUDE.md` for debugging.

### Docker-in-Docker setup (Cloud Agent VM)

The Cloud Agent sandbox is a Docker container inside a Firecracker VM. To run Docker:

1. Docker must be installed with `fuse-overlayfs` storage driver (`/etc/docker/daemon.json` → `{"storage-driver": "fuse-overlayfs"}`).
2. `iptables-legacy` must be the active alternative (`update-alternatives --set iptables /usr/sbin/iptables-legacy`).
3. Start dockerd manually: `sudo dockerd &>/tmp/dockerd.log &` then wait ~3s.
4. Fix socket permissions: `sudo chmod 666 /var/run/docker.sock`.

### Gotchas

- The `NEARAI_API_KEY` env var warning from docker compose (`"variable is not set"`) is cosmetic when using a dummy key — the gateway still starts and serves the Control UI.
- `OPENCLAW_FORCE_CONFIG_REGEN=1` is needed when restarting with fresh volumes to regenerate `openclaw.json` from the template.
- `OPENCLAW_AUTO_APPROVE_DEVICES=1` auto-approves the first browser device pairing — useful for testing the Control UI without manual approval.
- No linters exist in this repo. The only "build" step is Docker image builds. The only tests are `cargo test` in `compose-api/`.
