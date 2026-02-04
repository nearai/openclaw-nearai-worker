#!/bin/bash
set -eu -o pipefail

# ============================================
# OpenClaw Multi-Tenant Deployment Script
# ============================================
# This script sets up a multi-tenant OpenClaw deployment on a bare metal server.
# Users access their containers directly via IP:port (gateway + SSH).
#
# Features:
#   - Management API with token-based authentication
#   - Each user gets 2 ports: gateway (web UI) + SSH access
#   - SSH public key support for secure container access
#
# Prerequisites:
#   - Docker and Docker Compose installed
#   - openssl (for generating ADMIN_TOKEN if not set)
#
# Usage:
#   ./deploy.sh [--build-only] [--no-start]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

BUILD_ONLY=0
NO_START=0

# Parse arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --build-only)
      BUILD_ONLY=1
      shift
      ;;
    --no-start)
      NO_START=1
      shift
      ;;
    *)
      log_error "Unknown option: $1"
      echo "Usage: $0 [--build-only] [--no-start]"
      exit 1
      ;;
  esac
done

# ============================================
# Pre-flight Checks
# ============================================
log_info "Running pre-flight checks..."

# Check Docker
if ! command -v docker &> /dev/null; then
  log_error "Docker is not installed. Please install Docker first."
  exit 1
fi

# Check Docker Compose
if ! docker compose version &> /dev/null; then
  log_error "Docker Compose is not available. Please install Docker Compose V2."
  exit 1
fi

# Check Docker daemon
if ! docker info &> /dev/null; then
  log_error "Docker daemon is not running or you don't have permission to access it."
  exit 1
fi

log_info "Pre-flight checks passed"

# ============================================
# Environment Configuration
# ============================================
ENV_FILE=".env.prod"

if [ ! -f "$ENV_FILE" ]; then
  log_warn "Environment file $ENV_FILE not found"
  
  if [ -f "env.prod.example" ]; then
    log_info "Creating $ENV_FILE from template..."
    cp env.prod.example "$ENV_FILE"
    log_warn "Please edit $ENV_FILE with your configuration before proceeding"
    log_warn "Required: OPENCLAW_HOST_ADDRESS (your server's public IP)"
    exit 1
  else
    log_error "No environment template found. Please create $ENV_FILE manually."
    exit 1
  fi
fi

# Load environment
set -a
source "$ENV_FILE"
set +a

# Validate required variables
if [ -z "${ADMIN_TOKEN:-}" ]; then
  log_warn "ADMIN_TOKEN is not set in $ENV_FILE"
  log_info "Generating a new ADMIN_TOKEN..."
  NEW_TOKEN=$(openssl rand -hex 16)
  echo "" >> "$ENV_FILE"
  echo "# Auto-generated admin token" >> "$ENV_FILE"
  echo "ADMIN_TOKEN=$NEW_TOKEN" >> "$ENV_FILE"
  export ADMIN_TOKEN="$NEW_TOKEN"
  log_info "Generated and saved ADMIN_TOKEN to $ENV_FILE"
fi

# Get host address (default to localhost if not set)
HOST_ADDRESS="${OPENCLAW_HOST_ADDRESS:-localhost}"

log_info "Environment loaded: OPENCLAW_HOST_ADDRESS=$HOST_ADDRESS"
log_info "ADMIN_TOKEN is configured (use with 'Authorization: Bearer \$ADMIN_TOKEN')"

# ============================================
# Build OpenClaw Worker Image
# ============================================
log_info "Building OpenClaw worker image..."
docker build -t openclaw-nearai-worker:local .

# ============================================
# Build Management API Image
# ============================================
log_info "Building Management API image..."
docker build -t openclaw-management-api:local ./management-api

if [ "$BUILD_ONLY" -eq 1 ]; then
  log_info "Build complete (--build-only specified)"
  exit 0
fi

# ============================================
# Create Docker Network
# ============================================
log_info "Ensuring Docker network exists..."
docker network create openclaw-network 2>/dev/null || true

# ============================================
# Create Required Directories
# ============================================
log_info "Creating required directories..."
mkdir -p data

# ============================================
# Start Services
# ============================================
if [ "$NO_START" -eq 1 ]; then
  log_info "Services not started (--no-start specified)"
  log_info "Run: docker compose -f docker-compose.simple.yml up -d"
  exit 0
fi

log_info "Starting services..."
docker compose -f docker-compose.simple.yml --env-file "$ENV_FILE" up -d

# ============================================
# Wait for Services
# ============================================
log_info "Waiting for services to be ready..."
sleep 5

# Check Management API
if docker ps --filter "name=openclaw-management-api" --format "{{.Status}}" | grep -q "Up"; then
  log_info "Management API is running"
else
  log_warn "Management API may not be running correctly"
fi

# Test Management API health
sleep 3
if curl -s http://localhost:8080/health | grep -q "OK"; then
  log_info "Management API health check passed"
else
  log_warn "Management API health check failed - service may still be starting"
fi

# ============================================
# Summary
# ============================================
echo ""
log_info "============================================"
log_info "Deployment Complete!"
log_info "============================================"
echo ""
echo "Services:"
echo "  - Management API: http://localhost:8080"
echo "  - Management API: http://$HOST_ADDRESS:8080 (external)"
echo ""
echo "Authentication:"
echo "  All API requests require: Authorization: Bearer \$ADMIN_TOKEN"
echo "  Your ADMIN_TOKEN is stored in $ENV_FILE"
echo ""
echo "API Usage Examples:"
echo ""
echo "  # Set your admin token (from $ENV_FILE):"
echo "  export ADMIN_TOKEN=\"$ADMIN_TOKEN\""
echo ""
echo "  # Create a user (with their NEAR AI API key and optional SSH public key):"
echo "  curl -X POST http://$HOST_ADDRESS:8080/users \\"
echo "    -H 'Content-Type: application/json' \\"
echo "    -H \"Authorization: Bearer \$ADMIN_TOKEN\" \\"
echo "    -d '{"
echo "      \"user_id\": \"alice\","
echo "      \"nearai_api_key\": \"sk-user-nearai-api-key\","
echo "      \"ssh_pubkey\": \"ssh-ed25519 AAAA... user@host\""
echo "    }'"
echo ""
echo "  # Response includes gateway and SSH ports:"
echo "  # {"
echo "  #   \"user_id\": \"alice\","
echo "  #   \"token\": \"...\","
echo "  #   \"gateway_port\": 19001,"
echo "  #   \"ssh_port\": 19002,"
echo "  #   \"url\": \"http://$HOST_ADDRESS:19001\","
echo "  #   \"dashboard_url\": \"http://$HOST_ADDRESS:19001/?token=...\","
echo "  #   \"ssh_command\": \"ssh -p 19002 agent@$HOST_ADDRESS\","
echo "  #   \"status\": \"running\""
echo "  # }"
echo ""
echo "  # List all users:"
echo "  curl -H \"Authorization: Bearer \$ADMIN_TOKEN\" http://$HOST_ADDRESS:8080/users"
echo ""
echo "  # Get user details:"
echo "  curl -H \"Authorization: Bearer \$ADMIN_TOKEN\" http://$HOST_ADDRESS:8080/users/alice"
echo ""
echo "  # Delete a user:"
echo "  curl -X DELETE -H \"Authorization: Bearer \$ADMIN_TOKEN\" http://$HOST_ADDRESS:8080/users/alice"
echo ""
echo "User Container Access:"
echo "  - Gateway: http://$HOST_ADDRESS:{gateway_port}"
echo "  - SSH:     ssh -p {ssh_port} agent@$HOST_ADDRESS"
echo "  - Ports are allocated in pairs starting at 19001 (gateway), 19002 (ssh)"
echo ""
log_info "Note: Ensure firewall allows ports 8080 and 19001-19999"
log_info "Note: Each user gets 2 consecutive ports (gateway + SSH)"
log_info "Note: Only the Management API has Docker socket access"
