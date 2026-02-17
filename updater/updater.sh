#!/usr/bin/env bash
set -euo pipefail

# ── Configuration (all from environment) ──────────────────────────────

# Soft defaults — allow empty during chicken-and-egg transition
COMPOSE_API_IMAGE="${UPDATER_COMPOSE_API_IMAGE:-}"
WORKER_IMAGE="${UPDATER_WORKER_IMAGE:-}"
CHANNEL="${UPDATER_CHANNEL:-latest}"
POLL_INTERVAL="${UPDATER_POLL_INTERVAL:-300}"
COMPOSE_FILE="${UPDATER_COMPOSE_FILE:?UPDATER_COMPOSE_FILE is required}"
ENV_FILE="${UPDATER_ENV_FILE:?UPDATER_ENV_FILE is required}"
BASE_ENV_FILE="${UPDATER_BASE_ENV_FILE:-}"
COMPOSE_PROJECT="${UPDATER_COMPOSE_PROJECT:-}"
COSIGN_IDENTITY="${UPDATER_COSIGN_IDENTITY_REGEXP:-}"
HOST_DEPLOY_DIR="${UPDATER_HOST_DEPLOY_DIR:-}"

# Auto-detect dstack mode by checking well-known path
DSTACK_ENV_PATH="/app/deploy/.host-shared/.decrypted-env"
if [ -z "$BASE_ENV_FILE" ] && [ -f "$DSTACK_ENV_PATH" ]; then
    BASE_ENV_FILE="$DSTACK_ENV_PATH"
fi
if [ -z "$COMPOSE_PROJECT" ] && [ -n "$BASE_ENV_FILE" ]; then
    COMPOSE_PROJECT="dstack"
fi

# Fill missing required vars from base env (chicken-and-egg fix)
if [ -n "$BASE_ENV_FILE" ] && [ -f "$BASE_ENV_FILE" ]; then
    _read_base() { grep "^${1}=" "$BASE_ENV_FILE" 2>/dev/null | head -1 | cut -d'=' -f2-; }
    [ -z "$COMPOSE_API_IMAGE" ] && COMPOSE_API_IMAGE="$(_read_base COMPOSE_API_IMAGE_REPO)"
    [ -z "$COSIGN_IDENTITY" ]   && COSIGN_IDENTITY="$(_read_base UPDATER_COSIGN_IDENTITY)"
    unset -f _read_base
fi

# Validate required configuration
[ -z "$COMPOSE_API_IMAGE" ] && { echo "FATAL: UPDATER_COMPOSE_API_IMAGE is required" >&2; exit 1; }
if [ "${UPDATER_SKIP_VERIFY:-0}" != "1" ]; then
    [ -z "$COSIGN_IDENTITY" ] && { echo "FATAL: UPDATER_COSIGN_IDENTITY_REGEXP is required" >&2; exit 1; }
fi
COSIGN_ISSUER="${UPDATER_COSIGN_ISSUER:-https://token.actions.githubusercontent.com}"
HEALTH_URL="${UPDATER_HEALTH_URL:-http://127.0.0.1:8080/health}"
HEALTH_TIMEOUT="${UPDATER_HEALTH_TIMEOUT:-60}"
STATE_FILE="${UPDATER_STATE_FILE:-/app/data/updater-state.json}"
SELF_CHECK_INTERVAL="${UPDATER_SELF_CHECK_INTERVAL:-1}"  # every poll cycle
BUNDLED_COMPOSE="/app/compose/docker-compose.dstack.yml"

# ── Logging ───────────────────────────────────────────────────────────

log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] [updater] $*"; }
log_error() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] [updater] ERROR: $*" >&2; }

# ── State management ──────────────────────────────────────────────────

init_state() {
    mkdir -p "$(dirname "$STATE_FILE")"
    if [ ! -f "$STATE_FILE" ]; then
        echo '{}' > "$STATE_FILE"
    fi
}

read_state() {
    local key="$1"
    jq -r ".[\"$key\"] // empty" "$STATE_FILE" 2>/dev/null || echo ""
}

write_state() {
    local key="$1" value="$2"
    local tmp="${STATE_FILE}.tmp"
    jq --arg k "$key" --arg v "$value" '.[$k] = $v' "$STATE_FILE" > "$tmp" && mv "$tmp" "$STATE_FILE"
}

# ── Registry helpers ──────────────────────────────────────────────────

# Parse image into registry/repo components
# e.g. "docker.io/user/repo" → registry="registry-1.docker.io" repo="user/repo"
parse_image() {
    local image="$1"
    local registry repo

    if [[ "$image" == *"/"*"/"* ]]; then
        # Two+ slashes: explicit registry/namespace/repo
        registry="${image%%/*}"
        repo="${image#*/}"
    elif [[ "$image" == *"/"* ]]; then
        local first="${image%%/*}"
        if [[ "$first" == *.* ]] || [[ "$first" == *:* ]] || [[ "$first" == "localhost" ]]; then
            # First component is a registry (contains dot, port, or is localhost)
            registry="$first"
            repo="${image#*/}"
        else
            # Docker Hub user/repo
            registry="registry-1.docker.io"
            repo="${image}"
        fi
    else
        registry="registry-1.docker.io"
        repo="library/${image}"
    fi

    # Docker Hub alias
    if [ "$registry" = "docker.io" ]; then
        registry="registry-1.docker.io"
    fi

    echo "$registry" "$repo"
}

# Get a Docker Hub auth token for pulling manifests
get_auth_token() {
    local repo="$1"
    curl -fsSL "https://auth.docker.io/token?service=registry.docker.io&scope=repository:${repo}:pull" \
        | jq -r '.token'
}

# Fetch the remote digest for a given image:tag
fetch_remote_digest() {
    local image="$1" tag="$2"
    local registry repo token digest

    read -r registry repo <<< "$(parse_image "$image")"

    # Use http:// for localhost registries, https:// for everything else
    local scheme="https"
    if [[ "$registry" == localhost:* ]] || [[ "$registry" == "localhost" ]] \
       || [[ "$registry" == 127.0.0.1:* ]] || [[ "$registry" == "127.0.0.1" ]]; then
        scheme="http"
    fi

    if [ "$registry" = "registry-1.docker.io" ]; then
        token="$(get_auth_token "$repo")"
        digest="$(curl -fsSL \
            -H "Authorization: Bearer $token" \
            -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
            -H "Accept: application/vnd.oci.image.index.v1+json" \
            --head \
            "https://${registry}/v2/${repo}/manifests/${tag}" 2>/dev/null \
            | grep -i 'docker-content-digest' \
            | awk '{print $2}' \
            | tr -d '\r')"
    else
        digest="$(curl -fsSL \
            -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
            -H "Accept: application/vnd.oci.image.index.v1+json" \
            --head \
            "${scheme}://${registry}/v2/${repo}/manifests/${tag}" 2>/dev/null \
            | grep -i 'docker-content-digest' \
            | awk '{print $2}' \
            | tr -d '\r')"
    fi

    echo "$digest"
}

# ── Cosign verification ──────────────────────────────────────────────

verify_attestation() {
    local image_ref="$1"

    if [ "${UPDATER_SKIP_VERIFY:-0}" = "1" ]; then
        log "SKIP_VERIFY: skipping cosign verification for ${image_ref}"
        return 0
    fi

    log "Verifying cosign signature for ${image_ref}..."

    if cosign verify \
        --certificate-identity-regexp="$COSIGN_IDENTITY" \
        --certificate-oidc-issuer="$COSIGN_ISSUER" \
        "$image_ref" > /dev/null 2>&1; then
        log "Signature verified successfully"
        return 0
    else
        log_error "Signature verification FAILED for ${image_ref}"
        return 1
    fi
}

# ── Health check ─────────────────────────────────────────────────────

wait_for_healthy() {
    local timeout="$1"
    local elapsed=0
    local interval=2

    log "Waiting up to ${timeout}s for health check at ${HEALTH_URL}..."

    while [ "$elapsed" -lt "$timeout" ]; do
        if curl -fsSL --max-time 5 "$HEALTH_URL" > /dev/null 2>&1; then
            log "Health check passed after ${elapsed}s"
            return 0
        fi
        sleep "$interval"
        elapsed=$((elapsed + interval))
    done

    log_error "Health check failed after ${timeout}s"
    return 1
}

# ── Compose helper ───────────────────────────────────────────────────

# Run docker compose up with the correct env-file flags.
# In dstack mode (BASE_ENV_FILE set), passes both base and overrides
# so that overrides win. In standalone mode, passes only ENV_FILE.
compose_up() {
    local project_flag=()
    if [ -n "$COMPOSE_PROJECT" ]; then
        project_flag=(-p "$COMPOSE_PROJECT")
    fi

    if [ -n "$BASE_ENV_FILE" ]; then
        docker compose "${project_flag[@]}" -f "$COMPOSE_FILE" \
            --env-file "$BASE_ENV_FILE" \
            --env-file "$ENV_FILE" \
            up "$@"
    else
        docker compose "${project_flag[@]}" -f "$COMPOSE_FILE" \
            --env-file "$ENV_FILE" \
            up "$@"
    fi
}

# Build compose CLI flags as a string (for passing to helper containers)
compose_base_args() {
    local args=""
    [ -n "$COMPOSE_PROJECT" ] && args="-p $COMPOSE_PROJECT "
    args="$args-f $COMPOSE_FILE "
    if [ -n "$BASE_ENV_FILE" ]; then
        args="$args--env-file $BASE_ENV_FILE --env-file $ENV_FILE"
    else
        args="$args--env-file $ENV_FILE"
    fi
    echo "$args"
}

# ── Env file helpers ─────────────────────────────────────────────────

# Read a value: check overrides first, fall back to base env
read_env_var() {
    local key="$1"
    local val=""
    # Check overrides file first
    if [ -f "$ENV_FILE" ]; then
        val="$(grep "^${key}=" "$ENV_FILE" 2>/dev/null | head -1 | cut -d'=' -f2-)"
    fi
    # Fall back to base env if set and no override found
    if [ -z "$val" ] && [ -n "$BASE_ENV_FILE" ] && [ -f "$BASE_ENV_FILE" ]; then
        val="$(grep "^${key}=" "$BASE_ENV_FILE" 2>/dev/null | head -1 | cut -d'=' -f2-)"
    fi
    echo "$val"
}

# Set a value in the overrides env file (add or replace)
write_env_var() {
    local key="$1" value="$2"
    touch "$ENV_FILE"
    if grep -q "^${key}=" "$ENV_FILE" 2>/dev/null; then
        local tmp="${ENV_FILE}.tmp"
        sed "s|^${key}=.*|${key}=${value}|" "$ENV_FILE" > "$tmp" && mv "$tmp" "$ENV_FILE"
    else
        echo "${key}=${value}" >> "$ENV_FILE"
    fi
}

# ── Bootstrap ────────────────────────────────────────────────────────

bootstrap() {
    log "Checking if bootstrap is needed..."

    # Always copy bundled compose file to the deploy volume so that
    # compose_up can reconcile all services (ingress, datadog, etc.)
    # even when Docker state persists across CVM re-deploys.
    local compose_dir
    compose_dir="$(dirname "$COMPOSE_FILE")"
    mkdir -p "$compose_dir"

    if [ -f "$BUNDLED_COMPOSE" ]; then
        cp "$BUNDLED_COMPOSE" "$COMPOSE_FILE"
        log "Bootstrap: wrote compose file to $COMPOSE_FILE"
    else
        log_error "Bootstrap: bundled compose file not found at $BUNDLED_COMPOSE"
        return 1
    fi

    local fresh_deploy=true
    if docker ps --filter "label=com.docker.compose.service=compose-api" --format '{{.Names}}' | grep -q .; then
        fresh_deploy=false
    fi

    # Start/reconcile all services (idempotent — running services stay untouched)
    log "Bootstrap: ensuring all services are running..."
    compose_up -d --remove-orphans

    if [ "$fresh_deploy" = true ]; then
        if wait_for_healthy "$HEALTH_TIMEOUT"; then
            log "Bootstrap: all services started successfully"
        else
            log_error "Bootstrap: compose-api failed health check"
            return 1
        fi
    else
        log "Bootstrap: reconciled services (compose-api was already running)"
    fi
}

# ── Update logic ─────────────────────────────────────────────────────

update_compose_api() {
    local remote_digest running_digest image_ref old_digest

    # 1. Fetch remote digest
    remote_digest="$(fetch_remote_digest "$COMPOSE_API_IMAGE" "$CHANNEL")"
    if [ -z "$remote_digest" ]; then
        log_error "Failed to fetch remote digest for ${COMPOSE_API_IMAGE}:${CHANNEL}"
        return 1
    fi

    # 2. Get currently running digest
    running_digest="$(read_state "compose_api_digest")"
    if [ -z "$running_digest" ]; then
        # First run: resolve from running container
        running_digest="$(docker inspect compose-api --format '{{.Image}}' 2>/dev/null || echo "")"
    fi

    # 3. Compare
    if [ "$remote_digest" = "$running_digest" ]; then
        return 0
    fi

    log "New compose-api image detected: ${remote_digest} (current: ${running_digest:-unknown})"
    image_ref="${COMPOSE_API_IMAGE}@${remote_digest}"

    # 4. Pull
    log "Pulling ${image_ref}..."
    if ! docker pull "$image_ref"; then
        log_error "Failed to pull ${image_ref}"
        return 1
    fi

    # 5. Verify attestation
    if ! verify_attestation "$image_ref"; then
        log_error "Skipping update — attestation failed"
        return 1
    fi

    # 6. Save rollback target
    old_digest="$running_digest"
    old_image="$(read_env_var "COMPOSE_API_IMAGE")"

    # 7. Write new image to env file
    write_env_var "COMPOSE_API_IMAGE" "$image_ref"

    # 8. Apply update
    log "Applying compose-api update..."
    if ! compose_up -d --no-deps compose-api; then
        log_error "docker compose up failed, attempting rollback..."
        rollback_compose_api "$old_image" "$old_digest"
        return 1
    fi

    # 9. Health check
    if wait_for_healthy "$HEALTH_TIMEOUT"; then
        log "compose-api updated successfully to ${remote_digest}"
        write_state "compose_api_digest" "$remote_digest"
        write_state "last_update" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        return 0
    else
        log_error "Health check failed after update, rolling back..."
        rollback_compose_api "$old_image" "$old_digest"
        return 1
    fi
}

rollback_compose_api() {
    local old_image="$1" old_digest="$2"

    if [ -n "$old_image" ]; then
        write_env_var "COMPOSE_API_IMAGE" "$old_image"
    fi

    log "Rolling back compose-api..."
    compose_up -d --no-deps compose-api || true

    if wait_for_healthy "$HEALTH_TIMEOUT"; then
        log "Rollback successful"
    else
        log_error "CRITICAL: Rollback also failed! Manual intervention required."
    fi

    # Skip next few checks to avoid a tight retry loop
    write_state "backoff_until" "$(date -u -d "+30 minutes" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v+30M +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "")"
}

update_worker_image() {
    [ -z "$WORKER_IMAGE" ] && return 0

    local remote_digest current_digest image_ref

    remote_digest="$(fetch_remote_digest "$WORKER_IMAGE" "$CHANNEL")"
    if [ -z "$remote_digest" ]; then
        log_error "Failed to fetch remote digest for ${WORKER_IMAGE}:${CHANNEL}"
        return 1
    fi

    current_digest="$(read_state "worker_digest")"
    if [ "$remote_digest" = "$current_digest" ]; then
        return 0
    fi

    log "New worker image detected: ${remote_digest} (current: ${current_digest:-unknown})"
    image_ref="${WORKER_IMAGE}@${remote_digest}"

    # Pull and verify
    log "Pulling ${image_ref}..."
    if ! docker pull "$image_ref"; then
        log_error "Failed to pull ${image_ref}"
        return 1
    fi

    if ! verify_attestation "$image_ref"; then
        log_error "Skipping worker image update — attestation failed"
        return 1
    fi

    # Update the env var used by compose-api for new instances
    write_env_var "OPENCLAW_IMAGE" "$image_ref"
    write_state "worker_digest" "$remote_digest"
    log "Worker image updated to ${image_ref}"

    # Restart compose-api so it picks up the new default image
    log "Restarting compose-api to pick up new worker image..."
    compose_up -d --no-deps compose-api

    if wait_for_healthy "$HEALTH_TIMEOUT"; then
        log "compose-api restarted with new worker image"
    else
        log_error "compose-api failed health check after worker image update"
    fi

    return 0
}

update_self() {
    local updater_image="${UPDATER_SELF_IMAGE:-}"
    [ -z "$updater_image" ] && return 0

    local remote_digest current_digest image_ref

    remote_digest="$(fetch_remote_digest "$updater_image" "$CHANNEL")"
    if [ -z "$remote_digest" ]; then
        return 1
    fi

    current_digest="$(read_state "updater_digest")"
    if [ "$remote_digest" = "$current_digest" ]; then
        return 0
    fi

    log "New updater image detected: ${remote_digest}"
    image_ref="${updater_image}@${remote_digest}"

    if ! docker pull "$image_ref"; then
        log_error "Failed to pull updater image"
        return 1
    fi

    if ! verify_attestation "$image_ref"; then
        log_error "Skipping self-update — attestation failed"
        return 1
    fi

    # Resolve own container ID (needed for --volumes-from in both sync and helper)
    local self_cid
    self_cid="$(docker ps -q --filter "label=com.docker.compose.service=openclaw-updater" | head -1)"
    if [ -z "$self_cid" ]; then
        log_error "Cannot determine own container ID for self-update"
        return 1
    fi

    # Extract updated compose file from new image.
    # Uses --volumes-from so the temp container gets the same mounts as us,
    # which works with bind mounts (standard server, local dev) and named
    # volumes (dstack CVM bootstrap) without needing host-side paths.
    log "Syncing compose file from new image..."
    docker run --rm \
        --volumes-from "$self_cid" \
        --entrypoint sh "$image_ref" \
        -c "cp /app/compose/docker-compose.dstack.yml $(dirname "$COMPOSE_FILE")/"

    write_env_var "UPDATER_IMAGE" "$image_ref"
    write_state "updater_digest" "$remote_digest"
    log "Self-updating to ${image_ref}..."

    # Launch a sibling helper container to run `docker compose up` for us.
    # We can't do it directly because compose stop+remove kills this process
    # before create+start can execute, leaving the new container in "Created" state.
    docker rm -f openclaw-updater-helper 2>/dev/null || true

    local compose_args
    compose_args="$(compose_base_args)"

    # Pass DEPLOY_DIR so compose resolves the host-side bind mount correctly
    local helper_env=""
    [ -n "$HOST_DEPLOY_DIR" ] && helper_env="-e DEPLOY_DIR=${HOST_DEPLOY_DIR}"

    if ! docker run --rm -d \
        --name openclaw-updater-helper \
        --volumes-from "$self_cid" \
        $helper_env \
        --entrypoint sh \
        "$image_ref" \
        -c "sleep 3 && docker compose $compose_args up -d --remove-orphans --no-deps openclaw-updater && sleep 2"; then
        log_error "Failed to launch self-update helper container"
        return 1
    fi

    log "Self-update helper launched, this container will be replaced shortly"
}

# ── Main loop ────────────────────────────────────────────────────────

main() {
    log "Starting openclaw-updater"
    if [ -n "$BASE_ENV_FILE" ]; then
        log "  mode:              dstack (base + overrides)"
        log "  base env:          ${BASE_ENV_FILE}"
        log "  overrides env:     ${ENV_FILE}"
    else
        log "  mode:              standalone"
        log "  env file:          ${ENV_FILE}"
    fi
    log "  compose project:   ${COMPOSE_PROJECT:-<auto>}"
    log "  compose-api image: ${COMPOSE_API_IMAGE}"
    log "  worker image:      ${WORKER_IMAGE:-<not configured>}"
    log "  channel:           ${CHANNEL}"
    log "  poll interval:     ${POLL_INTERVAL}s"
    log "  cosign identity:   ${COSIGN_IDENTITY}"

    init_state

    # Bootstrap: deploy all services if compose-api isn't running yet
    bootstrap || true

    # Seed current digest from running container on first start
    if [ -z "$(read_state "compose_api_digest")" ]; then
        local current
        current="$(docker inspect compose-api --format '{{.Image}}' 2>/dev/null || echo "")"
        if [ -n "$current" ]; then
            write_state "compose_api_digest" "$current"
            log "Seeded compose-api digest from running container: ${current}"
        fi
    fi

    # Self-update first, before touching any other services
    update_self || true

    local self_check_counter=0

    while true; do
        # Check backoff
        local backoff_until
        backoff_until="$(read_state "backoff_until")"
        if [ -n "$backoff_until" ]; then
            local now
            now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
            if [[ "$now" < "$backoff_until" ]]; then
                log "In backoff period until ${backoff_until}, skipping..."
                sleep "$POLL_INTERVAL"
                continue
            else
                write_state "backoff_until" ""
            fi
        fi

        # 1. Check compose-api
        update_compose_api || true

        # 2. Check worker image
        update_worker_image || true

        # 3. Check self (less frequently)
        self_check_counter=$((self_check_counter + 1))
        if [ "$self_check_counter" -ge "$SELF_CHECK_INTERVAL" ]; then
            self_check_counter=0
            update_self || true
        fi

        sleep "$POLL_INTERVAL"
    done
}

main "$@"
