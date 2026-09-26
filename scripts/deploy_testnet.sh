#!/usr/bin/env bash
#
# scripts/deploy_testnet.sh — idempotent Testnet deployment for the
# soroban-sas suite.
#
# Wraps the authoritative deployment script scripts/deploy.sh, targeting the
# Stellar Testnet by default, and adds three things deploy.sh does not do on
# its own:
#
#   1. Idempotency by contract-id file: if testnet.env already has all three
#      contract IDs, deployment is skipped entirely and the script jumps
#      straight to post-deploy verification.
#   2. A dedicated result file, testnet.env, instead of the shared .env used
#      by scripts/deploy.sh for local/mainnet workflows.
#   3. A post-deploy verification pass that invokes SchemaRegistry::sasreg,
#      SAS::sasv1, and Indexer::get_sas, and prints PASS/FAIL for each of the
#      three contracts (identity + wiring), exiting non-zero on any failure.
#
# Friendbot funding, Testnet RPC/passphrase defaults, and wiring
# (SAS::set_indexer + Indexer::init) are handled by scripts/deploy.sh itself
# and are not duplicated here.
#
# Usage:
#   ./scripts/deploy_testnet.sh [--secret-key S...] [--rpc-url URL] \
#                               [--env-file FILE] [--skip-build] \
#                               [--export-secret] [--force]
#
# Flags specific to this wrapper:
#   --env-file FILE   Where contract IDs are read from / written to
#                      (default: testnet.env, not deploy.sh's default .env).
#   --force           Re-deploy even if --env-file already has all three
#                      contract IDs populated.
#
# All other flags are forwarded verbatim to scripts/deploy.sh (see
# `./scripts/deploy.sh --help`).
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

info() { printf '\033[1;34m[deploy-testnet]\033[0m %s\n' "$*" >&2; }
step() { printf '\n\033[1;36m==> %s\033[0m\n' "$*" >&2; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*" >&2; }
err()  { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; }

ENV_FILE="testnet.env"
FORCE=false
PASSTHROUGH=()
SECRET_KEY="${SOROBAN_SECRET_KEY:-${ADMIN_SECRET_KEY:-}}"

# Separate our own flags (--env-file, --force) from everything else, which
# is forwarded to deploy.sh unmodified. --secret-key and --rpc-url are
# intercepted (not just forwarded) because verification also needs them.
RPC_URL_OVERRIDE=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --env-file)   ENV_FILE="${2:?--env-file requires a value}"; shift 2 ;;
        --force)      FORCE=true; shift ;;
        --secret-key) SECRET_KEY="${2:?--secret-key requires a value}"; PASSTHROUGH+=("--secret-key" "$2"); shift 2 ;;
        --rpc-url)    RPC_URL_OVERRIDE="${2:?--rpc-url requires a value}"; PASSTHROUGH+=("--rpc-url" "$2"); shift 2 ;;
        -h|--help)    sed -n '2,32p' "$0" | grep '^#' | sed 's/^# \{0,1\}//'; exit 0 ;;
        *)            PASSTHROUGH+=("$1"); shift ;;
    esac
done

TESTNET_RPC_URL="${RPC_URL_OVERRIDE:-https://soroban-testnet.stellar.org:443}"
TESTNET_PASSPHRASE="Test SDF Network ; September 2015"

# ---------------------------------------------------------------------------
# CLI + identity resolution — needed for post-deploy verification, including
# on the fully-idempotent skip path where deploy.sh never runs.
# ---------------------------------------------------------------------------
CLI_BIN=""
for candidate in soroban stellar; do
    if command -v "$candidate" >/dev/null 2>&1; then
        CLI_BIN="$candidate"
        break
    fi
done
[[ -n "$CLI_BIN" ]] || { err "neither 'soroban' nor 'stellar' CLI found. Install with: cargo install --locked stellar-cli"; exit 1; }

# read_env_var FILE KEY -> prints the unquoted value, or empty string.
read_env_var() {
    local file="$1" key="$2"
    [[ -f "$file" ]] || return 0
    local line
    line="$(grep "^${key}=" "$file" 2>/dev/null | tail -n 1 | cut -d= -f2-)"
    line="${line%\"}"
    line="${line#\"}"
    printf '%s' "$line"
}

REGISTRY_ID="$(read_env_var "$ENV_FILE" SCHEMA_REGISTRY_CONTRACT_ID)"
SAS_ID="$(read_env_var "$ENV_FILE" SAS_CONTRACT_ID)"
INDEXER_ID="$(read_env_var "$ENV_FILE" INDEXER_CONTRACT_ID)"

ALREADY_DEPLOYED=false
if [[ -n "$REGISTRY_ID" && -n "$SAS_ID" && -n "$INDEXER_ID" ]]; then
    ALREADY_DEPLOYED=true
fi

if [[ "$ALREADY_DEPLOYED" == true && "$FORCE" != true ]]; then
    step "Found existing contract IDs in $ENV_FILE — skipping deployment"
    info "  schema-registry: $REGISTRY_ID"
    info "  sas:             $SAS_ID"
    info "  indexer:         $INDEXER_ID"
    info "(pass --force to re-deploy anyway)"
else
    if [[ "$ALREADY_DEPLOYED" == true ]]; then
        step "Re-deploying (--force) despite existing $ENV_FILE"
    else
        step "No complete contract set found in $ENV_FILE — deploying"
    fi
    "$SCRIPT_DIR/deploy.sh" --network testnet --env-file "$ENV_FILE" "${PASSTHROUGH[@]}"

    REGISTRY_ID="$(read_env_var "$ENV_FILE" SCHEMA_REGISTRY_CONTRACT_ID)"
    SAS_ID="$(read_env_var "$ENV_FILE" SAS_CONTRACT_ID)"
    INDEXER_ID="$(read_env_var "$ENV_FILE" INDEXER_CONTRACT_ID)"
fi

for pair in "schema-registry:$REGISTRY_ID" "sas:$SAS_ID" "indexer:$INDEXER_ID"; do
    label="${pair%%:*}"
    id="${pair#*:}"
    [[ "$id" =~ ^C[A-Z2-7]{55}$ ]] || { err "missing or invalid $label contract id in $ENV_FILE after deployment: '$id'"; exit 1; }
done

# ---------------------------------------------------------------------------
# Post-deploy verification: SchemaRegistry::sasreg, SAS::sasv1,
# Indexer::get_sas, plus the SAS<->Indexer binding. Uses a read-only
# simulated invoke, so it needs *a* source identity but never signs or
# submits a transaction.
# ---------------------------------------------------------------------------
if [[ -z "$SECRET_KEY" ]]; then
    err "no secret key provided for verification. Pass --secret-key S... or an existing identity name, or export SOROBAN_SECRET_KEY (or ADMIN_SECRET_KEY)"
    exit 1
fi

VERIFY_IDENTITY=""
CLEANUP_IDENTITY=""
cleanup() {
    if [[ -n "$CLEANUP_IDENTITY" ]]; then
        "$CLI_BIN" keys rm "$CLEANUP_IDENTITY" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

if [[ "$SECRET_KEY" =~ ^S[A-Z2-7]{55}$ ]]; then
    VERIFY_IDENTITY="tmp-verify-$RANDOM$RANDOM"
    printf '%s\n' "$SECRET_KEY" | "$CLI_BIN" keys add "$VERIFY_IDENTITY" --secret-key >/dev/null
    CLEANUP_IDENTITY="$VERIFY_IDENTITY"
else
    VERIFY_IDENTITY="$SECRET_KEY"
fi

VERIFY_ARGS=(--source-account "$VERIFY_IDENTITY" --rpc-url "$TESTNET_RPC_URL" --network-passphrase "$TESTNET_PASSPHRASE")

verify_invoke() {
    local id="$1"
    shift
    "$CLI_BIN" contract invoke --id "$id" "${VERIFY_ARGS[@]}" -- "$@" 2>/dev/null
}

strip_quotes() {
    local v="$1"
    v="${v%\"}"
    v="${v#\"}"
    printf '%s' "$v"
}

step "Post-deploy verification"
OVERALL_OK=true

report() {
    local label="$1" ok="$2" detail="${3:-}"
    if [[ "$ok" == true ]]; then
        printf '  %-32s %s\n' "$label" "PASS" >&2
    else
        printf '  %-32s %s %s\n' "$label" "FAIL" "$detail" >&2
        OVERALL_OK=false
    fi
}

if out="$(verify_invoke "$REGISTRY_ID" sasreg)" && [[ "$(strip_quotes "$out")" == "true" ]]; then
    report "schema-registry (sasreg)" true
else
    report "schema-registry (sasreg)" false "unexpected response: ${out:-<none>}"
fi

if out="$(verify_invoke "$SAS_ID" sasv1)" && [[ "$(strip_quotes "$out")" == "true" ]]; then
    report "sas (sasv1)" true
else
    report "sas (sasv1)" false "unexpected response: ${out:-<none>}"
fi

INDEXER_SAS=""
if out="$(verify_invoke "$INDEXER_ID" get_sas)"; then
    INDEXER_SAS="$(strip_quotes "$out")"
fi
if [[ -n "$INDEXER_SAS" && "$INDEXER_SAS" != "null" ]]; then
    report "indexer (get_sas)" true
else
    report "indexer (get_sas)" false "unexpected response: ${out:-<none>}"
fi

if [[ -n "$INDEXER_SAS" && "$INDEXER_SAS" == "$SAS_ID" ]]; then
    report "wiring: indexer -> sas" true
else
    report "wiring: indexer -> sas" false "indexer.get_sas()='${INDEXER_SAS:-<none>}' expected '$SAS_ID'"
fi

SAS_INDEXER=""
if out="$(verify_invoke "$SAS_ID" get_indexer)"; then
    SAS_INDEXER="$(strip_quotes "$out")"
fi
if [[ -n "$SAS_INDEXER" && "$SAS_INDEXER" == "$INDEXER_ID" ]]; then
    report "wiring: sas -> indexer" true
else
    report "wiring: sas -> indexer" false "sas.get_indexer()='${SAS_INDEXER:-<none>}' expected '$INDEXER_ID'"
fi

printf '\n' >&2
if [[ "$OVERALL_OK" == true ]]; then
    info "all post-deploy checks passed"
    info "contract IDs are in $ENV_FILE"
    exit 0
else
    err "one or more post-deploy checks failed — see PASS/FAIL report above"
    exit 1
fi
