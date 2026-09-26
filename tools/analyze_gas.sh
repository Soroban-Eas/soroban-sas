#!/usr/bin/env bash
#
# tools/analyze_gas.sh — gas/budget profiling for the soroban-sas contracts.
#
# Builds optimized WASM for schema-registry, sas, and indexer, deploys fresh
# instances to a running network, exercises the core entry points listed in
# issue #254 (including multi_attest at batch sizes 1/10/50/100), and writes
# a Markdown table of measured CPU instructions / memory bytes / ledger
# read-write bytes to gas_report.md.
#
# This measures against whatever network RPC_URL points at (a local
# `docker-compose up stellar-quickstart` instance by default, or Testnet if
# you override RPC_URL/NETWORK_PASSPHRASE and provide a funded SECRET_KEY).
# It deploys its own throwaway contract instances for each run rather than
# reusing a pre-existing deployment, so the report reflects the WASM
# currently checked out.
#
# Usage:
#   ./tools/analyze_gas.sh [--secret-key S...] [--rpc-url URL] [--out FILE]
#
# Env vars (fall back to .env, matching scripts/deploy.sh's key names):
#   SECRET_KEY / SOROBAN_SECRET_KEY / ADMIN_SECRET_KEY   funded source account
#   RPC_URL / SOROBAN_RPC_URL                             (default: local quickstart)
#   SOROBAN_NETWORK_PASSPHRASE                            (default: Standalone Network passphrase)
#
# Exit codes: 0 on success, 1 on any build/deploy/measurement failure.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

# ---------------------------------------------------------------------------
# Logging helpers (mirrors scripts/deploy.sh / scripts/smoke_test.sh style)
# ---------------------------------------------------------------------------
info() { printf '\033[1;34m[gas]\033[0m %s\n' "$*" >&2; }
step() { printf '\n\033[1;36m==> %s\033[0m\n' "$*" >&2; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*" >&2; }
err()  { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; }
die()  { err "$*"; exit 1; }

usage() { sed -n '2,20p' "$0" | grep '^#' | sed 's/^# \{0,1\}//'; }

# ---------------------------------------------------------------------------
# Defaults / argument parsing
# ---------------------------------------------------------------------------
SECRET_KEY="${SECRET_KEY:-${SOROBAN_SECRET_KEY:-${ADMIN_SECRET_KEY:-}}}"
RPC_URL="${RPC_URL:-${SOROBAN_RPC_URL:-http://localhost:8000/soroban/rpc}}"
NETWORK_PASSPHRASE="${SOROBAN_NETWORK_PASSPHRASE:-Standalone Network ; February 2017}"
OUT_FILE="gas_report.md"
ENV_FILE=".env"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --secret-key) SECRET_KEY="${2:?--secret-key requires a value}"; shift 2 ;;
        --rpc-url)    RPC_URL="${2:?--rpc-url requires a value}"; shift 2 ;;
        --out)        OUT_FILE="${2:?--out requires a value}"; shift 2 ;;
        --env-file)   ENV_FILE="${2:?--env-file requires a value}"; shift 2 ;;
        -h|--help)    usage; exit 0 ;;
        *)            die "unknown argument: $1" ;;
    esac
done

if [[ -f "$ENV_FILE" ]]; then
    # shellcheck disable=SC1090
    source "$ENV_FILE"
    SECRET_KEY="${SECRET_KEY:-${ADMIN_SECRET_KEY:-}}"
    RPC_URL="${RPC_URL:-${SOROBAN_RPC_URL:-http://localhost:8000/soroban/rpc}}"
    NETWORK_PASSPHRASE="${NETWORK_PASSPHRASE:-${SOROBAN_NETWORK_PASSPHRASE:-Standalone Network ; February 2017}}"
fi

[[ -n "$SECRET_KEY" ]] || die "no secret key. Pass --secret-key or set SECRET_KEY / SOROBAN_SECRET_KEY / ADMIN_SECRET_KEY"

CLI_BIN=""
for candidate in stellar soroban; do
    if command -v "$candidate" >/dev/null 2>&1; then
        CLI_BIN="$candidate"
        break
    fi
done
[[ -n "$CLI_BIN" ]] || die "neither 'stellar' nor 'soroban' CLI found on PATH"
command -v jq >/dev/null 2>&1 || die "jq is required to parse simulated transaction resource footprints"

info "using CLI: $CLI_BIN"
info "RPC: $RPC_URL"

# ---------------------------------------------------------------------------
# Step 1: Build optimized WASM
# ---------------------------------------------------------------------------
step "Step 1: Build optimized WASM for schema-registry, sas, indexer"
cargo build --release --target wasm32-unknown-unknown \
    --package schema-registry --package sas --package soroban-sas-indexer

RELEASE_DIR="target/wasm32-unknown-unknown/release"
if command -v wasm-opt >/dev/null 2>&1; then
    for wasm in schema_registry sas soroban_sas_indexer; do
        wasm-opt -Oz "$RELEASE_DIR/$wasm.wasm" -o "$RELEASE_DIR/$wasm.opt.wasm"
    done
    REGISTRY_WASM="$RELEASE_DIR/schema_registry.opt.wasm"
    SAS_WASM="$RELEASE_DIR/sas.opt.wasm"
    INDEXER_WASM="$RELEASE_DIR/soroban_sas_indexer.opt.wasm"
else
    warn "wasm-opt not found on PATH; deploying unoptimized release WASM. Install wasm-opt for representative production-size gas numbers."
    REGISTRY_WASM="$RELEASE_DIR/schema_registry.wasm"
    SAS_WASM="$RELEASE_DIR/sas.wasm"
    INDEXER_WASM="$RELEASE_DIR/soroban_sas_indexer.wasm"
fi

# ---------------------------------------------------------------------------
# Step 2: Identity + network args
# ---------------------------------------------------------------------------
step "Step 2: Configure identity"
IDENTITY_NAME="soroban-sas-gas-analysis"
printf '%s\n' "$SECRET_KEY" | "$CLI_BIN" keys add "$IDENTITY_NAME" --secret-key --overwrite >/dev/null
ADMIN_ADDRESS="$("$CLI_BIN" keys address "$IDENTITY_NAME")"
NET_ARGS=(--source-account "$IDENTITY_NAME" --rpc-url "$RPC_URL" --network-passphrase "$NETWORK_PASSPHRASE")

rand_hex_32() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 32
    else
        head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'
    fi
}

# ---------------------------------------------------------------------------
# Step 3: Deploy fresh contract instances and wire them together
# ---------------------------------------------------------------------------
step "Step 3: Deploy schema-registry, sas, indexer"
deploy() {
    "$CLI_BIN" contract deploy --wasm "$1" "${NET_ARGS[@]}" 2>/dev/null | tail -1 | tr -d '\r'
}

REGISTRY_ID="$(deploy "$REGISTRY_WASM")"
SAS_ID="$(deploy "$SAS_WASM")"
INDEXER_ID="$(deploy "$INDEXER_WASM")"
[[ -n "$REGISTRY_ID" && -n "$SAS_ID" && -n "$INDEXER_ID" ]] || die "one or more contract deployments failed"
info "schema-registry: $REGISTRY_ID"
info "sas:             $SAS_ID"
info "indexer:         $INDEXER_ID"

"$CLI_BIN" contract invoke --id "$SAS_ID" "${NET_ARGS[@]}" -- init --admin "$ADMIN_ADDRESS" --schema_registry "$REGISTRY_ID" >/dev/null
"$CLI_BIN" contract invoke --id "$INDEXER_ID" "${NET_ARGS[@]}" -- init --admin "$ADMIN_ADDRESS" --sas "$SAS_ID" >/dev/null

# ---------------------------------------------------------------------------
# Step 4: Register a schema used by all benchmark attestations
# ---------------------------------------------------------------------------
step "Step 4: Register benchmark schema"
SCHEMA_UID="$("$CLI_BIN" contract invoke --id "$REGISTRY_ID" "${NET_ARGS[@]}" -- register \
    --owner "$ADMIN_ADDRESS" \
    --schema '"string name,bool verified"' \
    --resolver "$ADMIN_ADDRESS" \
    --revocable true | tr -d '"')"
info "schema: $SCHEMA_UID"

ZERO_UID="0000000000000000000000000000000000000000000000000000000000000000"

attestation_json() {
    local uid="$1" payload_hex="$2"
    printf '{"uid":{"bytes":"%s"},"schema_uid":{"bytes":"%s"},"time":0,"expiration_time":0,"revocation_time":0,"ref_uid":{"bytes":"%s"},"recipient":"%s","attester":"%s","revocable":true,"data":{"bytes":"%s"}}' \
        "$uid" "$SCHEMA_UID" "$ZERO_UID" "$ADMIN_ADDRESS" "$ADMIN_ADDRESS" "$payload_hex"
}

# ---------------------------------------------------------------------------
# Step 5: Measure. For each scenario, build (simulate-only) the invocation
# twice: once with --cost to get the human-readable CPU/mem summary on
# stderr, and once with --build-only to decode the simulated transaction's
# Soroban resource footprint (read/write bytes) via `stellar xdr decode`.
# Both are best-effort: if either output shape doesn't match what this
# script expects, the corresponding column falls back to "n/a" rather than
# aborting the whole run, since these are diagnostic numbers, not
# correctness checks.
# ---------------------------------------------------------------------------
step "Step 5: Measure entry point costs"

declare -a ROWS=()

extract_cost_stderr() {
    # $1 = path to captured stderr from a --cost invocation.
    local file="$1"
    local cpu mem
    cpu="$(grep -oE 'cpu_insns[^0-9]*[0-9]+' "$file" | grep -oE '[0-9]+$' | head -1 || true)"
    mem="$(grep -oE 'mem_bytes[^0-9]*[0-9]+' "$file" | grep -oE '[0-9]+$' | head -1 || true)"
    printf '%s|%s\n' "${cpu:-n/a}" "${mem:-n/a}"
}

extract_resource_footprint() {
    # $1 = base64 tx envelope XDR (from --build-only). Prints "read|write".
    local xdr="$1" json read write
    json="$("$CLI_BIN" xdr decode --type TransactionEnvelope --input single-base64 --output json "$xdr" 2>/dev/null || true)"
    if [[ -z "$json" ]]; then
        printf 'n/a|n/a\n'
        return
    fi
    read="$(printf '%s' "$json" | jq -r '
        .. | objects | (.disk_read_bytes // .read_bytes // .diskReadBytes // empty)
    ' 2>/dev/null | head -1)"
    write="$(printf '%s' "$json" | jq -r '
        .. | objects | (.write_bytes // .writeBytes // empty)
    ' 2>/dev/null | head -1)"
    printf '%s|%s\n' "${read:-n/a}" "${write:-n/a}"
}

measure() {
    # $1 = row label, remaining args = contract id + invoke args (after --).
    local label="$1"; shift
    local contract_id="$1"; shift

    local cost_file
    cost_file="$(mktemp)"
    "$CLI_BIN" contract invoke --id "$contract_id" --cost --send=no "${NET_ARGS[@]}" -- "$@" \
        >/dev/null 2>"$cost_file" || warn "simulation failed for: $label"
    local cpu_mem
    cpu_mem="$(extract_cost_stderr "$cost_file")"
    rm -f "$cost_file"

    local build_xdr rw
    build_xdr="$("$CLI_BIN" contract invoke --id "$contract_id" --build-only "${NET_ARGS[@]}" -- "$@" 2>/dev/null || true)"
    if [[ -n "$build_xdr" ]]; then
        rw="$(extract_resource_footprint "$build_xdr")"
    else
        rw="n/a|n/a"
    fi

    local cpu="${cpu_mem%%|*}" mem="${cpu_mem##*|}"
    local read_b="${rw%%|*}" write_b="${rw##*|}"
    ROWS+=("| \`$label\` | $cpu | $read_b | $write_b | $mem |")
    info "$label -> cpu=$cpu read=$read_b write=$write_b mem=$mem"
}

measure "SchemaRegistry::register" "$REGISTRY_ID" register \
    --owner "$ADMIN_ADDRESS" --schema '"string bench"' --resolver "$ADMIN_ADDRESS" --revocable true

MIN_UID="$(rand_hex_32)"
measure "SAS::attest (minimal payload)" "$SAS_ID" attest \
    --attestation "$(attestation_json "$MIN_UID" "")"

BIG_UID="$(rand_hex_32)"
BIG_PAYLOAD="$(head -c 10240 /dev/zero | od -An -tx1 | tr -d ' \n')"
measure "SAS::attest (10KB payload)" "$SAS_ID" attest \
    --attestation "$(attestation_json "$BIG_UID" "$BIG_PAYLOAD")"

measure "SAS::revoke" "$SAS_ID" revoke --uid "$MIN_UID"

for batch_size in 1 10 50 100; do
    ATTS="["
    for ((i = 0; i < batch_size; i++)); do
        [[ $i -gt 0 ]] && ATTS+=","
        ATTS+="$(attestation_json "$(rand_hex_32)" "")"
    done
    ATTS+="]"
    measure "SAS::multi_attest (n=$batch_size)" "$SAS_ID" multi_attest --attestations "$ATTS"
done

measure "Indexer::get_attestations_by_recipient (1 chunk)" "$INDEXER_ID" get_attestations_by_recipient \
    --recipient "$ADMIN_ADDRESS"

# ---------------------------------------------------------------------------
# Step 6: Write the report
# ---------------------------------------------------------------------------
step "Step 6: Write $OUT_FILE"
{
    printf '# Gas & Resource Report\n\n'
    printf 'Generated by `tools/analyze_gas.sh` against `%s`.\n\n' "$RPC_URL"
    printf '| Entrypoint | CPU Instructions | Read Bytes | Write Bytes | Mem Bytes |\n'
    printf '|---|---|---|---|---|\n'
    for row in "${ROWS[@]}"; do
        printf '%s\n' "$row"
    done
    printf '\n`n/a` means this run could not extract that metric from the CLI'\''s output for the installed `stellar`/`soroban` CLI version — it is not a measurement of zero cost.\n'
} > "$OUT_FILE"

info "wrote $OUT_FILE"
