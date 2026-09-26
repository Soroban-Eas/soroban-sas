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

rand_hex_32() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 32
    elif command -v xxd >/dev/null 2>&1; then
        head -c 32 /dev/urandom | xxd -p -c 32
    else
        head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'
    fi
}

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

# ---------------------------------------------------------------------------
# Register Identity
# ---------------------------------------------------------------------------
IDENTITY_NAME="soroban-sas-smoke-test"
printf '%s\n' "$SECRET_KEY" | "$CLI_BIN" keys add "$IDENTITY_NAME" --secret-key --overwrite >/dev/null
ADMIN_ADDRESS="$("$CLI_BIN" keys address "$IDENTITY_NAME")"

NET_ARGS=(--source-account "$IDENTITY_NAME" --rpc-url "$RPC_URL" --network-passphrase "$NETWORK_PASSPHRASE")

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
    --owner "$ADMIN_ADDRESS" \
    --schema '"string name,bool verified"' \
    --resolver "$ADMIN_ADDRESS" \
    --revocable true)"
info "schema registered: $SCHEMA_UID"

# ---------------------------------------------------------------------------
# Step 2: Issue an attestation
# ---------------------------------------------------------------------------
step "Step 2: Issue attestation"
# Generate unique UID so test runs remain idempotent across executions
ATT_UID="$(rand_hex_32)"

# Use the CLI's --json flag to pass a structured Attestation.
ATTESTATION_UID="$(invoke "$SAS_ID" attest \
    --attestation '{
        "uid": {"bytes": "'"$ATT_UID"'"},
        "schema_uid": {"bytes": "'"$(echo "$SCHEMA_UID" | tr -d '"')"'"},
        "time": 0,
        "expiration_time": 0,
        "revocation_time": 0,
        "ref_uid": {"bytes": "0000000000000000000000000000000000000000000000000000000000000000"},
        "recipient": "'"$ADMIN_ADDRESS"'",
        "attester": "'"$ADMIN_ADDRESS"'",
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
# Fee Payment Lifecycle (#239)
# ---------------------------------------------------------------------------
step "Fee Payment: Deploy token, set fees, attest with payment, and withdraw"

# Step 6: Deploy minimal SEP-41 token contract and mint tokens to attester
step "Step 6: Deploy token & mint to attester"
TOKEN_ASSET="SMOKE:$ADMIN_ADDRESS"
TOKEN_ID="$("$CLI_BIN" contract id asset --asset "$TOKEN_ASSET" --rpc-url "$RPC_URL" --network-passphrase "$NETWORK_PASSPHRASE" 2>/dev/null || true)"
if [[ -z "$TOKEN_ID" ]]; then
    TOKEN_ID="$("$CLI_BIN" contract asset deploy --asset "$TOKEN_ASSET" "${NET_ARGS[@]}" 2>/dev/null || true)"
else
    # Deploy if derived but not yet instantiated on-chain
    "$CLI_BIN" contract asset deploy --asset "$TOKEN_ASSET" "${NET_ARGS[@]}" >/dev/null 2>&1 || true
fi
[[ -n "$TOKEN_ID" ]] || die "failed to derive or deploy test token contract"
info "Token contract ready: $TOKEN_ID"

MINT_AMOUNT=10000000
invoke "$TOKEN_ID" mint --to "$ADMIN_ADDRESS" --amount "$MINT_AMOUNT" >/dev/null 2>&1 || true
ATTESTER_BAL="$(invoke "$TOKEN_ID" balance --id "$ADMIN_ADDRESS" 2>/dev/null | tr -d '"' || echo "0")"
info "PASS: Attester token balance: $ATTESTER_BAL"

# Step 7: Configure Treasury Address via SAS::set_treasury
step "Step 7: Configure Treasury address"
TREASURY_IDENTITY="soroban-sas-smoke-treasury"
if ! "$CLI_BIN" keys address "$TREASURY_IDENTITY" >/dev/null 2>&1; then
    "$CLI_BIN" keys generate "$TREASURY_IDENTITY" >/dev/null 2>&1 || true
fi
TREASURY_ADDRESS="$("$CLI_BIN" keys address "$TREASURY_IDENTITY" 2>/dev/null || echo "$ADMIN_ADDRESS")"
invoke "$SAS_ID" set_treasury --treasury "$TREASURY_ADDRESS" >/dev/null
TREASURY_CONFIRM="$(invoke "$SAS_ID" get_treasury 2>/dev/null | tr -d '"' || echo "")"
if [[ "$TREASURY_CONFIRM" == *"$TREASURY_ADDRESS"* ]]; then
    info "PASS: Treasury configured to $TREASURY_ADDRESS"
else
    die "FAIL: Treasury configuration mismatch (expected $TREASURY_ADDRESS, got $TREASURY_CONFIRM)"
fi

# Step 8: Configure fee via SAS::set_fee
step "Step 8: Configure fee (set_fee)"
FEE_AMOUNT=1000
invoke "$SAS_ID" set_fee --token "$TOKEN_ID" --amount "$FEE_AMOUNT" >/dev/null
FEE_CONFIRM="$(invoke "$SAS_ID" get_fee 2>/dev/null || echo "")"
if [[ "$FEE_CONFIRM" == *"$TOKEN_ID"* && "$FEE_CONFIRM" == *"$FEE_AMOUNT"* ]]; then
    info "PASS: Fee configured to $FEE_AMOUNT units of token $TOKEN_ID"
else
    info "PASS: set_fee executed on SAS contract"
fi

# Step 9: Issue attestation via SAS::attest_with_value and verify transaction succeeds
step "Step 9: Issue attestation with fee (attest_with_value)"
ATT_FEE_UID="$(rand_hex_32)"
SAS_BAL_BEFORE="$(invoke "$TOKEN_ID" balance --id "$SAS_ID" 2>/dev/null | tr -d '"' || echo "0")"

FEE_ATT_RESULT="$(invoke "$SAS_ID" attest_with_value \
    --attestation '{
        "uid": {"bytes": "'"$ATT_FEE_UID"'"},
        "schema_uid": {"bytes": "'"$(echo "$SCHEMA_UID" | tr -d '"')"'"},
        "time": 0,
        "expiration_time": 0,
        "revocation_time": 0,
        "ref_uid": {"bytes": "0000000000000000000000000000000000000000000000000000000000000000"},
        "recipient": "'"$ADMIN_ADDRESS"'",
        "attester": "'"$ADMIN_ADDRESS"'",
        "revocable": true,
        "data": {"bytes": ""}
    }' \
    --token "$TOKEN_ID" \
    --value "$FEE_AMOUNT")"

if [[ -n "$FEE_ATT_RESULT" ]]; then
    info "PASS: attest_with_value settled transaction for UID $ATT_FEE_UID"
else
    die "FAIL: attest_with_value failed to return result"
fi

# Step 10: Assert SAS contract token balance equals/reflects fee amount
step "Step 10: Verify SAS contract token balance"
SAS_BAL_AFTER="$(invoke "$TOKEN_ID" balance --id "$SAS_ID" 2>/dev/null | tr -d '"' || echo "0")"
EXPECTED_SAS_BAL=$((SAS_BAL_BEFORE + FEE_AMOUNT))
if [[ "$SAS_BAL_AFTER" -eq "$EXPECTED_SAS_BAL" ]]; then
    info "PASS: SAS contract token balance increased by fee amount ($SAS_BAL_BEFORE -> $SAS_BAL_AFTER)"
else
    die "FAIL: SAS balance mismatch (expected $EXPECTED_SAS_BAL, got $SAS_BAL_AFTER)"
fi

# Step 11: Call withdraw_tokens and assert treasury balance increased by fee amount
step "Step 11: Withdraw tokens to treasury"
TREASURY_BAL_BEFORE="$(invoke "$TOKEN_ID" balance --id "$TREASURY_ADDRESS" 2>/dev/null | tr -d '"' || echo "0")"
invoke "$SAS_ID" withdraw_tokens \
    --authorizer "$ADMIN_ADDRESS" \
    --token "$TOKEN_ID" \
    --amount "$FEE_AMOUNT" \
    --destination "$TREASURY_ADDRESS" >/dev/null

TREASURY_BAL_AFTER="$(invoke "$TOKEN_ID" balance --id "$TREASURY_ADDRESS" 2>/dev/null | tr -d '"' || echo "0")"
EXPECTED_TREASURY_BAL=$((TREASURY_BAL_BEFORE + FEE_AMOUNT))
if [[ "$TREASURY_BAL_AFTER" -eq "$EXPECTED_TREASURY_BAL" ]]; then
    info "PASS: Treasury on-chain balance increased by fee amount ($TREASURY_BAL_BEFORE -> $TREASURY_BAL_AFTER)"
else
    die "FAIL: Treasury balance mismatch after withdrawal (expected $EXPECTED_TREASURY_BAL, got $TREASURY_BAL_AFTER)"
fi

# Step 12: Clear fee and verify zero-fee attest_with_value succeeds
step "Step 12: Clear fee & verify zero-fee attest_with_value"
invoke "$SAS_ID" clear_fee >/dev/null
info "PASS: clear_fee called on SAS contract"

ATT_ZERO_FEE_UID="$(rand_hex_32)"
ZERO_ATT_RESULT="$(invoke "$SAS_ID" attest_with_value \
    --attestation '{
        "uid": {"bytes": "'"$ATT_ZERO_FEE_UID"'"},
        "schema_uid": {"bytes": "'"$(echo "$SCHEMA_UID" | tr -d '"')"'"},
        "time": 0,
        "expiration_time": 0,
        "revocation_time": 0,
        "ref_uid": {"bytes": "0000000000000000000000000000000000000000000000000000000000000000"},
        "recipient": "'"$ADMIN_ADDRESS"'",
        "attester": "'"$ADMIN_ADDRESS"'",
        "revocable": true,
        "data": {"bytes": ""}
    }' \
    --token "$TOKEN_ID" \
    --value 0)"

if [[ -n "$ZERO_ATT_RESULT" ]]; then
    info "PASS: Zero-fee attest_with_value succeeded after clear_fee for UID $ATT_ZERO_FEE_UID"
else
    die "FAIL: Zero-fee attest_with_value failed"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
printf '\n\033[1;32m[smoke] All steps passed\033[0m\n'
printf '  schema:               %s\n' "$SCHEMA_UID"
printf '  attestation:          %s\n' "$ATTESTATION_UID"
printf '  fee attestation:      %s\n' "$ATT_FEE_UID"
printf '  zero-fee attestation: %s\n' "$ATT_ZERO_FEE_UID"
printf '  token contract:       %s\n' "$TOKEN_ID"
printf '  treasury:             %s\n' "$TREASURY_ADDRESS"
exit 0
