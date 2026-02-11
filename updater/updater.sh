#!/usr/bin/env bash
set -euo pipefail

# ── Configuration (all from environment) ──────────────────────────────

COMPOSE_API_IMAGE="${UPDATER_COMPOSE_API_IMAGE:?UPDATER_COMPOSE_API_IMAGE is required}"
WORKER_IMAGE="${UPDATER_WORKER_IMAGE:-}"
CHANNEL="${UPDATER_CHANNEL:-latest}"
POLL_INTERVAL="${UPDATER_POLL_INTERVAL:-300}"
COMPOSE_FILE="${UPDATER_COMPOSE_FILE:?UPDATER_COMPOSE_FILE is required}"
ENV_FILE="${UPDATER_ENV_FILE:?UPDATER_ENV_FILE is required}"
COSIGN_IDENTITY="${UPDATER_COSIGN_IDENTITY_REGEXP:?UPDATER_COSIGN_IDENTITY_REGEXP is required}"
COSIGN_ISSUER="${UPDATER_COSIGN_ISSUER:-https://token.actions.githubusercontent.com}"
HEALTH_URL="${UPDATER_HEALTH_URL:-http://127.0.0.1:8080/health}"
HEALTH_TIMEOUT="${UPDATER_HEALTH_TIMEOUT:-60}"
STATE_FILE="${UPDATER_STATE_FILE:-/app/data/updater-state.json}"
SELF_CHECK_INTERVAL="${UPDATER_SELF_CHECK_INTERVAL:-288}"  # every 24h at 5min polls

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
        registry="${image%%/*}"
        repo="${image#*/}"
    elif [[ "$image" == *"/"* ]]; then
        registry="registry-1.docker.io"
        repo="${image}"
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
            "https://${registry}/v2/${repo}/manifests/${tag}" 2>/dev/null \
            | grep -i 'docker-content-digest' \
            | awk '{print $2}' \
            | tr -d '\r')"
    fi

    echo "$digest"
}

# ── Cosign verification ──────────────────────────────────────────────

verify_attestation() {
    local image_ref="$1"
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

# ── Env file helpers ─────────────────────────────────────────────────

# Read a value from the env file
read_env_var() {
    local key="$1"
    if [ -f "$ENV_FILE" ]; then
        grep "^${key}=" "$ENV_FILE" 2>/dev/null | head -1 | cut -d'=' -f2-
    fi
}

# Set a value in the env file (add or replace)
write_env_var() {
    local key="$1" value="$2"
    if grep -q "^${key}=" "$ENV_FILE" 2>/dev/null; then
        local tmp="${ENV_FILE}.tmp"
        sed "s|^${key}=.*|${key}=${value}|" "$ENV_FILE" > "$tmp" && mv "$tmp" "$ENV_FILE"
    else
        echo "${key}=${value}" >> "$ENV_FILE"
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
    if ! docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" up -d --no-deps compose-api; then
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
    docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" up -d --no-deps compose-api || true

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
    docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" up -d --no-deps compose-api

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

    write_env_var "UPDATER_IMAGE" "$image_ref"
    write_state "updater_digest" "$remote_digest"
    log "Self-updating to ${image_ref}..."

    # This will replace our own container — Docker handles the transition
    docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" up -d --no-deps openclaw-updater
}

# ── Main loop ────────────────────────────────────────────────────────

main() {
    log "Starting openclaw-updater"
    log "  compose-api image: ${COMPOSE_API_IMAGE}"
    log "  worker image:      ${WORKER_IMAGE:-<not configured>}"
    log "  channel:           ${CHANNEL}"
    log "  poll interval:     ${POLL_INTERVAL}s"
    log "  cosign identity:   ${COSIGN_IDENTITY}"

    init_state

    # Seed current digest from running container on first start
    if [ -z "$(read_state "compose_api_digest")" ]; then
        local current
        current="$(docker inspect compose-api --format '{{.Image}}' 2>/dev/null || echo "")"
        if [ -n "$current" ]; then
            write_state "compose_api_digest" "$current"
            log "Seeded compose-api digest from running container: ${current}"
        fi
    fi

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
