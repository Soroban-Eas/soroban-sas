#!/usr/bin/env bash
#
# scripts/wait_for_localnet.sh — wait for LocalNet Soroban RPC readiness.
#
# Probes Soroban JSON-RPC endpoints (getHealth, getNetwork, getLatestLedger)
# until Soroban RPC is ready, the network is active, and the ledger is advancing.
#
# Usage:
#   ./scripts/wait_for_localnet.sh [--rpc-url URL] [--timeout SECONDS] [--interval SECONDS] [--min-ledger N]
#
# Flags:
#   --rpc-url <URL>        Soroban RPC endpoint (default: http://localhost:8000/soroban/rpc).
#   --timeout <SECONDS>    Maximum seconds to wait before failing (default: 60).
#   --interval <SECONDS>   Seconds between probe attempts (default: 2).
#   --min-ledger <N>       Minimum ledger sequence required (default: 1).
#   -h, --help             Show this help message.
#
# Exit codes:
#   0  Soroban RPC is healthy and ledger >= min-ledger.
#   1  Timed out or failed to reach readiness.
#
set -euo pipefail

RPC_URL="http://localhost:8000/soroban/rpc"
TIMEOUT=60
INTERVAL=2
MIN_LEDGER=1

info() { printf '\033[1;34m[localnet]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*" >&2; }
err()  { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; }

usage() {
    sed -n '2,20p' "$0" | grep '^#' | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --rpc-url)     RPC_URL="${2:?--rpc-url requires a value}"; shift 2 ;;
        --timeout)     TIMEOUT="${2:?--timeout requires a value}"; shift 2 ;;
        --interval)    INTERVAL="${2:?--interval requires a value}"; shift 2 ;;
        --min-ledger)  MIN_LEDGER="${2:?--min-ledger requires a value}"; shift 2 ;;
        -h|--help)     usage; exit 0 ;;
        *)             err "unknown argument: $1 (see --help)"; exit 1 ;;
    esac
done

# Normalize RPC URL: if passed http://localhost:8000 without /soroban/rpc, append it if root returns 404/empty
if [[ "$RPC_URL" =~ :8000/?$ ]]; then
    RPC_URL="${RPC_URL%/}/soroban/rpc"
fi

info "Waiting for Soroban RPC readiness at $RPC_URL (timeout: ${TIMEOUT}s)..."

START_TIME=$(date +%s)
LAST_ERROR="No response received yet"
LAST_RESPONSE=""
INITIAL_LEDGER=-1

while true; do
    CURRENT_TIME=$(date +%s)
    ELAPSED=$((CURRENT_TIME - START_TIME))
    if [[ $ELAPSED -ge $TIMEOUT ]]; then
        err "Timed out waiting for Soroban RPC readiness after ${ELAPSED}s (limit: ${TIMEOUT}s)."
        printf '\n\033[1;31m--- Diagnostics ---\033[0m\n' >&2
        printf '  Target RPC URL:       %s\n' "$RPC_URL" >&2
        printf '  Last Error:           %s\n' "$LAST_ERROR" >&2
        if [[ -n "$LAST_RESPONSE" ]]; then
            printf '  Last RPC Response:    %s\n' "$LAST_RESPONSE" >&2
        fi
        printf '\n\033[1;33mTroubleshooting hints:\033[0m\n' >&2
        printf '  - Check if container is running:  docker compose ps\n' >&2
        printf '  - Inspect container logs:         docker compose logs stellar-quickstart\n' >&2
        printf '  - Verify mapped port (8000:8000): curl -v http://localhost:8000/\n' >&2
        exit 1
    fi

    # 1. Probe getHealth
    HEALTH_RESP=$(curl -s -m 3 -X POST -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","id":1,"method":"getHealth"}' "$RPC_URL" 2>&1) || {
        LAST_ERROR="Failed to connect to RPC endpoint: $HEALTH_RESP"
        sleep "$INTERVAL"
        continue
    }
    LAST_RESPONSE="$HEALTH_RESP"

    if ! printf '%s' "$HEALTH_RESP" | grep -q '"status":[[:space:]]*"healthy"'; then
        LAST_ERROR="RPC responded but status is not healthy: $HEALTH_RESP"
        sleep "$INTERVAL"
        continue
    fi

    # 2. Probe getNetwork
    NETWORK_RESP=$(curl -s -m 3 -X POST -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","id":2,"method":"getNetwork"}' "$RPC_URL" 2>&1) || {
        LAST_ERROR="Failed to fetch getNetwork: $NETWORK_RESP"
        sleep "$INTERVAL"
        continue
    }

    PASSPHRASE=$(printf '%s' "$NETWORK_RESP" | python3 -c 'import sys, json; data=json.load(sys.stdin); print(data.get("result", {}).get("passphrase", ""))' 2>/dev/null || echo "")
    PROTOCOL=$(printf '%s' "$NETWORK_RESP" | python3 -c 'import sys, json; data=json.load(sys.stdin); print(data.get("result", {}).get("protocolVersion", ""))' 2>/dev/null || echo "")

    if [[ -z "$PASSPHRASE" ]]; then
        LAST_ERROR="getNetwork returned invalid result (no passphrase): $NETWORK_RESP"
        sleep "$INTERVAL"
        continue
    fi

    # 3. Probe getLatestLedger
    LEDGER_RESP=$(curl -s -m 3 -X POST -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","id":3,"method":"getLatestLedger"}' "$RPC_URL" 2>&1) || {
        LAST_ERROR="Failed to fetch getLatestLedger: $LEDGER_RESP"
        sleep "$INTERVAL"
        continue
    }

    SEQUENCE=$(printf '%s' "$LEDGER_RESP" | python3 -c 'import sys, json; data=json.load(sys.stdin); print(data.get("result", {}).get("sequence", 0))' 2>/dev/null || echo "0")

    if [[ "$SEQUENCE" -lt "$MIN_LEDGER" ]]; then
        LAST_ERROR="Latest ledger sequence ($SEQUENCE) is below required minimum ($MIN_LEDGER)"
        sleep "$INTERVAL"
        continue
    fi

    if [[ "$INITIAL_LEDGER" -eq -1 ]]; then
        INITIAL_LEDGER="$SEQUENCE"
    fi

    # Success!
    printf '\n\033[1;32m[localnet] Soroban RPC is fully ready!\033[0m\n'
    printf '  %-20s %s\n' "RPC Endpoint:" "$RPC_URL"
    printf '  %-20s %s\n' "Network Passphrase:" "$PASSPHRASE"
    printf '  %-20s %s\n' "Protocol Version:" "$PROTOCOL"
    printf '  %-20s %s\n' "Latest Ledger:" "$SEQUENCE"
    printf '  %-20s %ss\n' "Elapsed Time:" "$ELAPSED"
    exit 0
done
