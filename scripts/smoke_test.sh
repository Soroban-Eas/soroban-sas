#!/usr/bin/env bash
#
# scripts/smoke_test.sh — end-to-end attestation lifecycle smoke test.
#
# Exercises the full cycle on Testnet (or any network): register schema,
# issue attestation, verify, revoke, verify revoked.
#
# Reads SAS_CONTRACT_ID, SCHEMA_REGISTRY_CONTRACT_ID, SECRET_KEY, and
# RPC_URL from .env or environment variables.
#
# Usage:
#   ./scripts/smoke_test.sh [--secret-key S...] [--rpc-url URL] [--env-file FILE]
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
info() { printf '\033[1;34m[smoke]\033[0m %s\n' "$*"; }
step() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
err()  { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; }
die()  { err "$*"; exit 1; }

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
SECRET_KEY="${SECRET_KEY:-${SOROBAN_SECRET_KEY:-${ADMIN_SECRET_KEY:-}}}"
RPC_URL="${RPC_URL:-${SOROBAN_RPC_URL:-https://soroban-testnet.stellar.org:443}}"
ENV_FILE=".env"
SAS_ID="${SAS_CONTRACT_ID:-}"
REGISTRY_ID="${SCHEMA_REGISTRY_CONTRACT_ID:-}"
NETWORK_PASSPHRASE="${SOROBAN_NETWORK_PASSPHRASE:-Test SDF Network ; September 2015}"

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --secret-key)     SECRET_KEY="${2:?--secret-key requires a value}"; shift 2 ;;
        --rpc-url)        RPC_URL="${2:?--rpc-url requires a value}"; shift 2 ;;
        --env-file)       ENV_FILE="${2:?--env-file requires a value}"; shift 2 ;;
        -h|--help)
            sed -n '2,20p' "$0" | grep '^#' | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *)                die "unknown argument: $1" ;;
    esac
done

# ---------------------------------------------------------------------------
# Source .env if present and vars are still empty
# ---------------------------------------------------------------------------
if [[ -f "$ENV_FILE" ]]; then
    # shellcheck disable=SC1090
    source "$ENV_FILE"
    SAS_ID="${SAS_ID:-${SAS_CONTRACT_ID:-}}"
    REGISTRY_ID="${REGISTRY_ID:-${SCHEMA_REGISTRY_CONTRACT_ID:-}}"
    SECRET_KEY="${SECRET_KEY:-${ADMIN_SECRET_KEY:-}}"
    RPC_URL="${RPC_URL:-${SOROBAN_RPC_URL:-}}"
    NETWORK_PASSPHRASE="${NETWORK_PASSPHRASE:-${SOROBAN_NETWORK_PASSPHRASE:-}}"
fi

# ---------------------------------------------------------------------------
# Validate required vars
# ---------------------------------------------------------------------------
[[ -n "$SECRET_KEY" ]] || die "no secret key. Pass --secret-key or set SECRET_KEY / SOROBAN_SECRET_KEY"
[[ -n "$SAS_ID" ]]     || die "SAS_CONTRACT_ID not set (deploy first or pass via env)"
[[ -n "$REGISTRY_ID" ]] || die "SCHEMA_REGISTRY_CONTRACT_ID not set (deploy first or pass via env)"

# Detect CLI: soroban or stellar
CLI_BIN=""
for candidate in soroban stellar; do
    if command -v "$candidate" >/dev/null 2>&1; then
        CLI_BIN="$candidate"
        break
    fi
done
[[ -n "$CLI_BIN" ]] || die "neither 'soroban' nor 'stellar' CLI found"

info "using CLI: $CLI_BIN"
info "SAS contract: $SAS_ID"
info "Registry:     $REGISTRY_ID"

NET_ARGS=(--source-account "$SECRET_KEY" --rpc-url "$RPC_URL" --network-passphrase "$NETWORK_PASSPHRASE")

invoke() {
    local id="$1"
    shift
    "$CLI_BIN" contract invoke --id "$id" "${NET_ARGS[@]}" -- "$@"
}

# ---------------------------------------------------------------------------
# Step 1: Register a schema
# ---------------------------------------------------------------------------
step "Step 1: Register schema"
SCHEMA_UID="$(invoke "$REGISTRY_ID" register \
    --owner "$SECRET_KEY" \
    --schema '"string name,bool verified"' \
    --resolver "$SECRET_KEY" \
    --revocable true)"
info "schema registered: $SCHEMA_UID"

# ---------------------------------------------------------------------------
# Step 2: Issue an attestation
# ---------------------------------------------------------------------------
step "Step 2: Issue attestation"
# Build an Attestation contract type. The CLI accepts JSON for contract types.
# We use a fixed test UID for the attestation.
ATT_UID="$(printf '0000000000000000000000000000000000000000000000000000000000000001' | xxd -r -p | xxd -p -c 64)"

# Use the CLI's --json flag to pass a structured Attestation.
ATTESTATION_UID="$(invoke "$SAS_ID" attest \
    --attestation '{
        "uid": {"bytes": "'"$ATT_UID"'"},
        "schema_uid": {"bytes": "'"$(echo "$SCHEMA_UID" | tr -d '"')"'"},
        "time": 0,
        "expiration_time": 0,
        "revocation_time": 0,
        "ref_uid": {"bytes": "0000000000000000000000000000000000000000000000000000000000000000"},
        "recipient": "'"$SECRET_KEY"'",
        "attester": "'"$SECRET_KEY"'",
        "revocable": true,
        "data": {"bytes": ""}
    }')"
info "attestation issued: $ATTESTATION_UID"

# ---------------------------------------------------------------------------
# Step 3: Verify attestation
# ---------------------------------------------------------------------------
step "Step 3: Verify attestation"
VERIFY_RESULT="$(invoke "$SAS_ID" verify_attestation --uid "$ATTESTATION_UID")"
info "verify_attestation returned: $VERIFY_RESULT"
if [[ "$VERIFY_RESULT" != "true" ]]; then
    die "verify_attestation should return true, got: $VERIFY_RESULT"
fi
info "PASS: attestation is valid"

# ---------------------------------------------------------------------------
# Step 4: Revoke attestation
# ---------------------------------------------------------------------------
step "Step 4: Revoke attestation"
invoke "$SAS_ID" revoke --uid "$ATTESTATION_UID" >/dev/null
info "attestation revoked"

# ---------------------------------------------------------------------------
# Step 5: Verify revocation
# ---------------------------------------------------------------------------
step "Step 5: Verify revocation"
VERIFY_REVOKED="$(invoke "$SAS_ID" verify_attestation --uid "$ATTESTATION_UID")"
info "verify_attestation after revocation: $VERIFY_REVOKED"
if [[ "$VERIFY_REVOKED" != "false" ]]; then
    die "verify_attestation should return false after revocation, got: $VERIFY_REVOKED"
fi
info "PASS: attestation is revoked"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
printf '\n\033[1;32m[smoke] All steps passed\033[0m\n'
printf '  schema:   %s\n' "$SCHEMA_UID"
printf '  attestation: %s\n' "$ATTESTATION_UID"
exit 0
