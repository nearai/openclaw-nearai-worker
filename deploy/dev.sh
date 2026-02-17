#!/bin/bash
set -eu -o pipefail

# ============================================
# OpenClaw Local Development Stack
# ============================================
# Builds images from source and runs the full management stack locally.
#
# Usage:
#   ./deploy/dev.sh              # build + start
#   ./deploy/dev.sh --build-only # build images, push to registry
#   ./deploy/dev.sh --no-build   # start without rebuilding
#   ./deploy/dev.sh --down       # tear down the stack
#   ./deploy/dev.sh --clean      # tear down + remove volumes

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

COMPOSE_FILE="deploy/docker-compose.local.yml"
ENV_FILE="deploy/.env.dstack.local"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

BUILD_ONLY=0
NO_BUILD=0
DOWN=0
CLEAN=0

while [[ $# -gt 0 ]]; do
  case $1 in
    --build-only) BUILD_ONLY=1; shift ;;
    --no-build)   NO_BUILD=1;   shift ;;
    --down)       DOWN=1;       shift ;;
    --clean)      CLEAN=1;      shift ;;
    *)
      log_error "Unknown option: $1"
      echo "Usage: $0 [--build-only] [--no-build] [--down] [--clean]"
      exit 1
      ;;
  esac
done

# ── Pre-flight checks ──────────────────────────────────────────────

if ! command -v docker &> /dev/null; then
  log_error "Docker is not installed."
  exit 1
fi

if ! docker compose version &> /dev/null; then
  log_error "Docker Compose V2 is not available."
  exit 1
fi

if ! docker info &> /dev/null; then
  log_error "Docker daemon is not running."
  exit 1
fi

# ── Tear down ───────────────────────────────────────────────────────

if [ "$CLEAN" -eq 1 ]; then
  log_info "Tearing down the stack and removing volumes..."
  docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" down -v
  exit 0
fi

if [ "$DOWN" -eq 1 ]; then
  log_info "Tearing down the stack..."
  docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" down
  exit 0
fi

# ── Build images ────────────────────────────────────────────────────

if [ "$NO_BUILD" -eq 0 ]; then
  log_info "Building openclaw-nearai-worker:local ..."
  docker build -t openclaw-nearai-worker:local ./worker

  log_info "Building openclaw-compose-api:local ..."
  docker build --build-arg CACHEBUST="$(date +%s)" -t openclaw-compose-api:local ./compose-api

  log_info "Building openclaw-updater:local ..."
  docker build -f updater/Dockerfile -t openclaw-updater:local .

  # Build ironclaw worker if source is available (sibling repo)
  IRONCLAW_SRC="${IRONCLAW_SRC:-$(cd "$REPO_ROOT/.." && pwd)/ironclaw}"
  if [ -d "$IRONCLAW_SRC/src" ]; then
    log_info "Building ironclaw-nearai-worker:local (source: $IRONCLAW_SRC) ..."
    docker buildx build \
      --build-context ironclaw="$IRONCLAW_SRC" \
      -t ironclaw-nearai-worker:local \
      ./ironclaw-worker
  else
    log_warn "Ironclaw source not found at $IRONCLAW_SRC — skipping ironclaw image build"
  fi

  log_info "All images built."
fi

# ── Push images to local registry ──────────────────────────────────

if [ "$NO_BUILD" -eq 0 ]; then
  log_info "Starting local registry..."
  docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" up -d registry

  log_info "Waiting for registry to be ready..."
  REGISTRY_TIMEOUT=30
  REGISTRY_ELAPSED=0
  while [ "$REGISTRY_ELAPSED" -lt "$REGISTRY_TIMEOUT" ]; do
    if curl -sf --max-time 2 http://localhost:5050/v2/ > /dev/null 2>&1; then
      break
    fi
    sleep 1
    REGISTRY_ELAPSED=$((REGISTRY_ELAPSED + 1))
  done

  if [ "$REGISTRY_ELAPSED" -ge "$REGISTRY_TIMEOUT" ]; then
    log_error "Registry did not become ready within ${REGISTRY_TIMEOUT}s"
    exit 1
  fi

  log_info "Pushing openclaw-compose-api to local registry..."
  docker tag openclaw-compose-api:local localhost:5050/openclaw-compose-api:latest
  docker push localhost:5050/openclaw-compose-api:latest

  log_info "Pushing openclaw-nearai-worker to local registry..."
  docker tag openclaw-nearai-worker:local localhost:5050/openclaw-nearai-worker:latest
  docker push localhost:5050/openclaw-nearai-worker:latest

  log_info "Pushing openclaw-updater to local registry..."
  docker tag openclaw-updater:local localhost:5050/openclaw-updater:latest
  docker push localhost:5050/openclaw-updater:latest

  if docker image inspect ironclaw-nearai-worker:local > /dev/null 2>&1; then
    log_info "Pushing ironclaw-nearai-worker to local registry..."
    docker tag ironclaw-nearai-worker:local localhost:5050/ironclaw-nearai-worker:latest
    docker push localhost:5050/ironclaw-nearai-worker:latest
  fi
fi

if [ "$BUILD_ONLY" -eq 1 ]; then
  log_info "Build complete (--build-only). Images pushed to localhost:5050."
  exit 0
fi

# ── Start stack ─────────────────────────────────────────────────────

# DEPLOY_DIR must be an absolute host path so the updater's self-update
# helper container can re-mount it correctly (Docker Desktop remaps `.`
# relative to the helper's cwd, which is inside a container).
export DEPLOY_DIR="$REPO_ROOT/deploy"

log_info "Starting local stack..."
docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" up -d

# ── Health check ────────────────────────────────────────────────────

log_info "Waiting for compose-api health..."
HEALTH_URL="http://localhost:8080/health"
TIMEOUT=60
ELAPSED=0

while [ "$ELAPSED" -lt "$TIMEOUT" ]; do
  if curl -sf --max-time 2 "$HEALTH_URL" > /dev/null 2>&1; then
    log_info "compose-api is healthy (${ELAPSED}s)"
    break
  fi
  sleep 2
  ELAPSED=$((ELAPSED + 2))
done

if [ "$ELAPSED" -ge "$TIMEOUT" ]; then
  log_warn "compose-api did not become healthy within ${TIMEOUT}s — check 'docker compose logs compose-api'"
fi

# ── Summary ─────────────────────────────────────────────────────────

echo ""
log_info "============================================"
log_info "Local stack is running"
log_info "============================================"
echo ""
echo "  API:         http://localhost:8080"
echo "  Health:      http://localhost:8080/health"
echo "  Registry:    http://localhost:5050"
echo "  Admin token: 00000000000000000000000000000000"
echo ""
echo "Examples:"
echo "  curl http://localhost:8080/health"
echo "  curl -H 'Authorization: Bearer 00000000000000000000000000000000' http://localhost:8080/instances"
echo "  curl http://localhost:5050/v2/_catalog"
echo ""
echo "Tear down:"
echo "  ./deploy/dev.sh --down          # keep volumes"
echo "  ./deploy/dev.sh --clean         # remove volumes too"
echo ""
