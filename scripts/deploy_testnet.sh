#!/usr/bin/env bash
#
# scripts/deploy_testnet.sh — testnet deployment wrapper for the soroban-sas suite.
#
# Delegates to the authoritative deployment script scripts/deploy.sh targeting
# the Stellar Testnet. Builds, deploys, initializes, and connects:
#   1. schema-registry                       (no dependencies)
#   2. sas                                   (needs registry address)
#   3. soroban-sas-indexer                   (needs sas address)
#
# Usage:
#   ./scripts/deploy_testnet.sh [--secret-key S...] [--rpc-url URL] \
#                               [--env-file FILE] [--skip-build] \
#                               [--export-secret]
#
# Accepts any arguments supported by scripts/deploy.sh.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$SCRIPT_DIR/deploy.sh" --network testnet "$@"
