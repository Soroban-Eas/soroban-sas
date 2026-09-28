#!/usr/bin/env bash
set -euo pipefail

# Validate the local Soroban Docker Compose stack without requiring deployed
# contracts or a funded account.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

TIMEOUT="${DOCKER_SMOKE_TIMEOUT:-60}"
KEEP_STACK="${KEEP_DOCKER_STACK:-false}"

info() { printf '\033[1;34m[docker-smoke]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[docker-smoke]\033[0m %s\n' "$*" >&2; exit 1; }

cleanup() {
    if [[ "$KEEP_STACK" != true ]]; then
        docker compose down -v --remove-orphans >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

command -v docker >/dev/null 2>&1 || die "docker is required"
docker compose version >/dev/null 2>&1 || die "Docker Compose is required"
docker compose config -q

info "starting Stellar Quickstart"
docker compose up -d
"$SCRIPT_DIR/wait_for_localnet.sh" --timeout "$TIMEOUT"

status="$(docker compose ps --format json)"
[[ -n "$status" ]] || die "docker compose reported no services"
printf '%s\n' "$status" | jq -e 'if type == "array" then any(.[]; (.Service == "stellar-quickstart" and (.Health == "healthy" or .State == "running"))) else (.Service == "stellar-quickstart" and (.Health == "healthy" or .State == "running")) end' >/dev/null \
    || die "stellar-quickstart is not healthy"

info "Docker Compose smoke test passed"