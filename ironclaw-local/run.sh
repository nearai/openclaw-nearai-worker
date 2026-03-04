#!/usr/bin/env bash
set -euo pipefail

# IronClaw local Docker test environment.
# See README.md for full documentation.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Source .env if it exists (NEARAI_API_KEY, NEARAI_API_URL, IRONCLAW_DIR, etc.)
if [ -f "$SCRIPT_DIR/.env" ]; then
    set -a
    # shellcheck source=/dev/null
    source "$SCRIPT_DIR/.env"
    set +a
fi

IMAGE=ironclaw:local
CONTAINER=ironclaw-local
CONFIG_VOL=ironclaw-local-config
WORKSPACE_VOL=ironclaw-local-workspace
PORT="${IRONCLAW_LOCAL_PORT:-18789}"
ENV_FILE="$SCRIPT_DIR/.env.local"

# Validate IRONCLAW_DIR points to the ironclaw source
check_ironclaw_dir() {
    if [ -z "${IRONCLAW_DIR:-}" ]; then
        echo "Error: IRONCLAW_DIR not set"
        echo "Set it in .env or export it:"
        echo "  echo 'IRONCLAW_DIR=/path/to/ironclaw' >> .env"
        echo "  # or"
        echo "  IRONCLAW_DIR=/path/to/ironclaw ./run.sh build"
        exit 1
    fi
    if [ ! -f "$IRONCLAW_DIR/Cargo.toml" ]; then
        echo "Error: $IRONCLAW_DIR does not look like an ironclaw repo (no Cargo.toml)"
        exit 1
    fi
}

case "${1:-help}" in
    build)
        check_ironclaw_dir
        echo "Building IronClaw from source (libsql, BuildKit cache)..."
        echo "  Source: $IRONCLAW_DIR"
        echo "  Image:  $IMAGE"
        DOCKER_BUILDKIT=1 docker buildx build \
            --build-context "ironclaw=$IRONCLAW_DIR" \
            -f "$SCRIPT_DIR/Dockerfile" \
            -t "$IMAGE" \
            "$SCRIPT_DIR"
        echo ""
        echo "Build complete: $IMAGE"
        ;;

    start)
        if [ -z "${NEARAI_API_KEY:-}" ]; then
            echo "Error: NEARAI_API_KEY not set"
            echo "  Add it to .env or export it"
            exit 1
        fi

        # Auto-generate auth token on first start
        if [ ! -f "$ENV_FILE" ]; then
            echo "OPENCLAW_GATEWAY_TOKEN=$(openssl rand -hex 32)" > "$ENV_FILE"
            echo "Generated new gateway auth token"
        fi
        # shellcheck source=/dev/null
        source "$ENV_FILE"

        # Stop existing container if running
        docker rm -f "$CONTAINER" 2>/dev/null || true

        docker run -d --name "$CONTAINER" \
            -p "$PORT:18789" \
            -e NEARAI_API_KEY="$NEARAI_API_KEY" \
            -e OPENCLAW_GATEWAY_TOKEN="$OPENCLAW_GATEWAY_TOKEN" \
            -e NEARAI_API_URL="${NEARAI_API_URL}" \
            -e NEARAI_MODEL="${NEARAI_MODEL:-auto}" \
            -e RUST_LOG="${RUST_LOG:-ironclaw=debug}" \
            -v "$CONFIG_VOL:/home/agent/.ironclaw" \
            -v "$WORKSPACE_VOL:/home/agent/workspace" \
            --init \
            "$IMAGE"

        echo ""
        echo "IronClaw local: http://localhost:${PORT}?token=${OPENCLAW_GATEWAY_TOKEN}"
        echo ""
        echo "  ./run.sh logs    - tail logs"
        echo "  ./run.sh shell   - exec into container"
        echo "  ./run.sh stop    - stop container"
        ;;

    stop)
        docker rm -f "$CONTAINER" 2>/dev/null && echo "Stopped $CONTAINER" || echo "Not running"
        ;;

    logs)
        docker logs -f "$CONTAINER"
        ;;

    shell)
        docker exec -it -u agent "$CONTAINER" bash
        ;;

    reset)
        docker rm -f "$CONTAINER" 2>/dev/null || true
        docker volume rm "$CONFIG_VOL" "$WORKSPACE_VOL" 2>/dev/null || true
        rm -f "$ENV_FILE"
        echo "Volumes and token cleared (fresh instance)."
        echo "Run: ./run.sh build && ./run.sh start"
        ;;

    restart)
        docker rm -f "$CONTAINER" 2>/dev/null || true
        exec "$0" start
        ;;

    url)
        if [ -f "$ENV_FILE" ]; then
            # shellcheck source=/dev/null
            source "$ENV_FILE"
            echo "http://localhost:${PORT}?token=${OPENCLAW_GATEWAY_TOKEN}"
        else
            echo "Not started yet. Run: ./run.sh start"
            exit 1
        fi
        ;;

    *)
        echo "IronClaw Local Docker Test Environment"
        echo ""
        echo "Usage: $0 <command>"
        echo ""
        echo "Commands:"
        echo "  build     Build image from source (fast rebuilds via BuildKit cache)"
        echo "  start     Start container, print gateway URL with auth token"
        echo "  stop      Stop and remove container"
        echo "  restart   Stop + start (keeps data volumes)"
        echo "  logs      Tail container logs"
        echo "  shell     Exec bash as agent user in running container"
        echo "  reset     Stop + wipe data volumes (simulates fresh instance)"
        echo "  url       Print the gateway URL with auth token"
        echo ""
        echo "Required in .env:"
        echo "  IRONCLAW_DIR          Path to the ironclaw source repo"
        echo "  NEARAI_API_KEY        NEAR AI API key from cloud.near.ai"
        echo ""
        echo "Optional in .env:"
        echo "  NEARAI_API_URL        NEAR AI API endpoint"
        echo "  IRONCLAW_LOCAL_PORT   Gateway port (default: 18789)"
        echo "  NEARAI_MODEL          LLM model (default: auto)"
        echo "  RUST_LOG              Log level (default: ironclaw=debug)"
        echo ""
        echo "Quick start:"
        echo "  echo 'IRONCLAW_DIR=/path/to/ironclaw' >> .env"
        echo "  echo 'NEARAI_API_KEY=sk-...' >> .env"
        echo "  ./run.sh build && ./run.sh start"
        ;;
esac
