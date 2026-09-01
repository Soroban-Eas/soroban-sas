#!/usr/bin/env bash
#
# scripts/bootstrap.sh — installs toolchain dependencies for soroban-sas.
#
# Adds the wasm32-unknown-unknown compilation target and installs the Stellar CLI.
#
# Usage:
#   ./scripts/bootstrap.sh [--install]
#
set -euo pipefail

step() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
info() { printf '\033[1;34m[bootstrap]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<EOF
Usage: ./scripts/bootstrap.sh [--install] [-h|--help]

Installs required toolchain components:
  - wasm32-unknown-unknown target via rustup
  - stellar-cli via cargo

Flags:
  --install    Run installation of missing toolchain targets and CLI
  -h, --help   Show this help message
EOF
}

INSTALL=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --install) INSTALL=true; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown argument: $1 (see --help)" ;;
    esac
done

step "Checking Rust & Cargo"
command -v rustup >/dev/null 2>&1 || die "rustup not found. Install Rust via https://rustup.rs"
command -v cargo >/dev/null 2>&1 || die "cargo not found. Install Rust via https://rustup.rs"

step "Checking wasm32-unknown-unknown target"
if rustup target list --installed 2>/dev/null | grep -q '^wasm32-unknown-unknown$'; then
    info "wasm32-unknown-unknown target is already installed"
else
    info "installing wasm32-unknown-unknown target"
    rustup target add wasm32-unknown-unknown
fi

step "Checking Stellar CLI"
CLI_FOUND=""
for candidate in stellar soroban; do
    if command -v "$candidate" >/dev/null 2>&1; then
        CLI_FOUND="$candidate"
        break
    fi
done

if [[ -n "$CLI_FOUND" ]]; then
    info "Found CLI '$CLI_FOUND' at $(command -v "$CLI_FOUND")"
else
    info "Installing stellar-cli (cargo install --locked stellar-cli)"
    cargo install --locked stellar-cli
fi

step "Environment bootstrap complete!"
