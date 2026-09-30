#!/usr/bin/env bash
#
# scripts/docker_preflight.sh — Pre-flight checks for Docker environment.
#
# Ensures Docker is installed, running, and ready to start services cleanly.
# Cleans up any leftover containers, networks, or volumes from previous runs.
#
set -euo pipefail

info() { printf '\033[1;34m[docker-preflight]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*" >&2; }
err()  { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; }

# Check if docker is installed
if ! command -v docker >/dev/null 2>&1; then
    err "Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if docker daemon is running
if ! docker info >/dev/null 2>&1; then
    err "Docker daemon is not running. Please start Docker."
    exit 1
fi

# Check if docker compose is available
if ! docker compose version >/dev/null 2>&1; then
    err "Docker Compose is not available. Please ensure Docker Compose plugin is installed."
    exit 1
fi

info "Docker environment check passed"

# Clean up any leftover containers, networks, or volumes
info "Cleaning up any leftover Docker resources..."
if docker compose ps -q 2>/dev/null | grep -q .; then
    warn "Found running services, stopping them..."
    docker compose down -v --remove-orphans 2>/dev/null || true
fi

# Check for orphaned containers from previous runs
ORPHANED=$(docker ps -a --filter "name=stellar-quickstart" --format "{{.ID}}" 2>/dev/null || true)
if [[ -n "$ORPHANED" ]]; then
    warn "Removing orphaned stellar-quickstart containers..."
    echo "$ORPHANED" | xargs -r docker rm -f >/dev/null 2>&1 || true
fi

# Remove any conflicting networks
NETWORKS=$(docker network ls --filter "name=soroban-sas" --format "{{.ID}}" 2>/dev/null || true)
if [[ -n "$NETWORKS" ]]; then
    info "Cleaning up old networks..."
    echo "$NETWORKS" | xargs -r docker network rm >/dev/null 2>&1 || true
fi

info "Docker environment is clean and ready"
exit 0
