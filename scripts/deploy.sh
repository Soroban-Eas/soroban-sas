#!/usr/bin/env bash
#
# scripts/deploy.sh — one-shot build + deploy for the soroban-sas suite.
#
# Builds optimized WASM for the three workspace contracts and deploys them to
# the target network in dependency order:
#
#   1. schema-registry                       (no dependencies)
#   2. sas                                   (needs registry address)
#        └─ SAS::init(admin, registry)
#   3. indexer                               (needs sas address)
#        └─ Indexer::init(admin, sas)
#
# On success the contract IDs, network settings and the admin public address
# are merged into .env using the exact key names from .env.example:
#
#   SOROBAN_RPC_URL, SOROBAN_NETWORK_PASSPHRASE,
#   SAS_CONTRACT_ID, SCHEMA_REGISTRY_CONTRACT_ID, INDEXER_CONTRACT_ID,
#   ADMIN_PUBLIC_ADDRESS
#
# Usage:
#   ./scripts/deploy.sh [--network testnet|mainnet] [--secret-key S...] \
#                       [--rpc-url URL] [--env-file FILE] [--skip-build] [--json]
#                       [--rpc-url URL] [--env-file FILE] [--skip-build] \
#                       [--export-secret]
#
# Flags:
#   --network <testnet|mainnet>  Target network (default: testnet).
#   --secret-key <S...>          Funded source account secret key. Falls back
#                                to $SOROBAN_SECRET_KEY, then $ADMIN_SECRET_KEY,
#                                so the key can stay out of shell history.
#   --rpc-url <URL>              Override the network's default RPC endpoint
#                                (e.g. a local validator or custom provider).
#   --env-file <FILE>            Where to write results (default: .env).
#   --skip-build                 Reuse previously built WASM artifacts.
#   --json                       Emit a single machine-readable JSON summary
#                                on stdout instead of the human-readable
#                                report. All progress/log output still goes
#                                to stderr, so `--json` output stays parseable
#                                even when piped, e.g.:
#                                  ./scripts/deploy.sh --json > deployment.json
#   --export-secret              Opt-in: write ADMIN_SECRET_KEY to .env.
#                                By default only the admin public address is
#                                stored; use this flag when plaintext export
#                                is required for local development.
#   -h, --help                   Show this help.
#
# A child process cannot export variables into the shell that launched it, so
# on success the script prints the exact command to activate the results:
#
#   source .env
#
# Exit codes: 0 success, 1 any build/deploy/init/env-write failure (the script
# stops at the first failing step).

set -euo pipefail

# ---------------------------------------------------------------------------
# Pretty logging helpers
# ---------------------------------------------------------------------------
# All progress logging goes to stderr — stdout is reserved for --json output
# so a caller can safely do: ./scripts/deploy.sh --json > deployment.json
info() { printf '\033[1;34m[deploy]\033[0m %s\n' "$*" >&2; }
step() { printf '\n\033[1;36m==> %s\033[0m\n' "$*" >&2; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*" >&2; }
err()  { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; }
die()  { err "$*"; exit 1; }

usage() { sed -n '2,55p' "$0" | grep '^#' | sed 's/^# \{0,1\}//'; }

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
NETWORK="testnet"
SECRET_KEY="${SOROBAN_SECRET_KEY:-${ADMIN_SECRET_KEY:-}}"
RPC_URL_OVERRIDE=""
ENV_FILE=".env"
SKIP_BUILD=false
JSON_OUTPUT=false
EXPORT_SECRET=false

TESTNET_RPC_URL="https://soroban-testnet.stellar.org:443"
TESTNET_PASSPHRASE="Test SDF Network ; September 2015"
MAINNET_RPC_URL="https://soroban-rpc.stellar.org:443"
MAINNET_PASSPHRASE="Public Global Stellar Network ; September 2015"

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --network)    NETWORK="${2:?--network requires a value}"; shift 2 ;;
        --secret-key) SECRET_KEY="${2:?--secret-key requires a value}"; shift 2 ;;
        --rpc-url)    RPC_URL_OVERRIDE="${2:?--rpc-url requires a value}"; shift 2 ;;
        --env-file)   ENV_FILE="${2:?--env-file requires a value}"; shift 2 ;;
        --skip-build) SKIP_BUILD=true; shift ;;
        --json)       JSON_OUTPUT=true; shift ;;
        -h|--help)    usage; exit 0 ;;
        *)            die "unknown argument: $1 (see --help)" ;;
        --network)        NETWORK="${2:?--network requires a value}"; shift 2 ;;
        --secret-key)     SECRET_KEY="${2:?--secret-key requires a value}"; shift 2 ;;
        --rpc-url)        RPC_URL_OVERRIDE="${2:?--rpc-url requires a value}"; shift 2 ;;
        --env-file)       ENV_FILE="${2:?--env-file requires a value}"; shift 2 ;;
        --skip-build)     SKIP_BUILD=true; shift ;;
        --export-secret)  EXPORT_SECRET=true; shift ;;
        -h|--help)        usage; exit 0 ;;
        *)                die "unknown argument: $1 (see --help)" ;;
    esac
done

case "$NETWORK" in
    testnet) RPC_URL="$TESTNET_RPC_URL"; PASSPHRASE="$TESTNET_PASSPHRASE" ;;
    mainnet) RPC_URL="$MAINNET_RPC_URL"; PASSPHRASE="$MAINNET_PASSPHRASE" ;;
    *) die "unsupported network '$NETWORK' (expected testnet or mainnet)" ;;
esac
if [[ -n "$RPC_URL_OVERRIDE" ]]; then
    RPC_URL="$RPC_URL_OVERRIDE"
fi

# ---------------------------------------------------------------------------
# Tooling checks
# ---------------------------------------------------------------------------
# The Soroban CLI was renamed `soroban` -> `stellar` in v23; support both.
CLI_BIN=""
for candidate in soroban stellar; do
    if command -v "$candidate" >/dev/null 2>&1; then
        CLI_BIN="$candidate"
        break
    fi
done
[[ -n "$CLI_BIN" ]] || die "neither 'soroban' nor 'stellar' CLI found. Install with: cargo install --locked stellar-cli"
info "using CLI: $CLI_BIN ($(command -v "$CLI_BIN"))"

command -v cargo >/dev/null 2>&1 || die "cargo not found. Install Rust: https://rustup.rs"

# ---------------------------------------------------------------------------
# Repo root + artifact paths (crate name '-' becomes '_' in wasm filenames)
# ---------------------------------------------------------------------------
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

WASM_DIR="target/wasm32-unknown-unknown/release"
WASM_REGISTRY="$WASM_DIR/schema_registry.wasm"
WASM_SAS="$WASM_DIR/sas.wasm"
WASM_INDEXER="$WASM_DIR/soroban_sas_indexer.wasm"

# ---------------------------------------------------------------------------
# Source account: validate key, derive the admin G... address
# ---------------------------------------------------------------------------
if [[ -z "$SECRET_KEY" ]]; then
    die "no secret key provided. Pass --secret-key S... or export SOROBAN_SECRET_KEY (or ADMIN_SECRET_KEY)"
fi
if [[ ! "$SECRET_KEY" =~ ^S[A-Z2-7]{55}$ ]]; then
    die "secret key must be an ed25519 strkey seed (S...) — got '${SECRET_KEY:0:4}...' with wrong format"
fi

step "Deriving admin address from the provided secret key"
# Register the key under a well-known local identity so the CLI can resolve
# both the signing source and the matching G... address. The identity lives
# in ~/.config/stellar/identity/ and is refreshed on every run.
IDENTITY_NAME="soroban-sas-deploy-$NETWORK"
printf '%s\n' "$SECRET_KEY" | "$CLI_BIN" keys add "$IDENTITY_NAME" --secret-key --overwrite >/dev/null
ADMIN_ADDRESS="$("$CLI_BIN" keys address "$IDENTITY_NAME")"
[[ "$ADMIN_ADDRESS" =~ ^G[A-Z2-7]{55}$ ]] || die "failed to derive admin address from secret key"
info "admin address: $ADMIN_ADDRESS"

ENV_WORK=""
cleanup() {
    [[ -n "$ENV_WORK" ]] && rm -f "$ENV_WORK" "$ENV_WORK.next"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Testnet convenience: top up via Friendbot if needed (best-effort — ignored
# when the account is already funded). Mainnet accounts must be funded by the
# operator beforehand.
# ---------------------------------------------------------------------------
if [[ "$NETWORK" == "testnet" ]]; then
    step "Ensuring testnet account is funded (Friendbot, best-effort)"
    if curl -fsS -o /dev/null "https://friendbot.stellar.org?addr=$ADMIN_ADDRESS"; then
        info "account funded via Friendbot"
    else
        warn "Friendbot did not fund the account (probably already funded) — continuing"
    fi
fi

# ---------------------------------------------------------------------------
# Build optimized WASM for all three contracts (workspace release profile:
# opt-level=z, lto, panic=abort)
# ---------------------------------------------------------------------------
if [[ "$SKIP_BUILD" == true ]]; then
    step "Skipping build (--skip-build)"
else
    step "Building optimized WASM (release profile, wasm32-unknown-unknown)"
    if ! rustup target list --installed 2>/dev/null | grep -q '^wasm32-unknown-unknown$'; then
        info "installing wasm32-unknown-unknown target"
        rustup target add wasm32-unknown-unknown
    fi
    cargo build -p schema-registry -p sas -p soroban-sas-indexer \
        --release --target wasm32-unknown-unknown
fi

for wasm in "$WASM_REGISTRY" "$WASM_SAS" "$WASM_INDEXER"; do
    [[ -f "$wasm" ]] || die "missing WASM artifact: $wasm (run without --skip-build)"
done
info "artifacts:"
info "  registry: $WASM_REGISTRY ($(wc -c <"$WASM_REGISTRY") bytes)"
info "  sas:      $WASM_SAS ($(wc -c <"$WASM_SAS") bytes)"
info "  indexer:  $WASM_INDEXER ($(wc -c <"$WASM_INDEXER") bytes)"

# ---------------------------------------------------------------------------
# Shared transaction arguments + helpers
# ---------------------------------------------------------------------------
NET_ARGS=(--source-account "$SECRET_KEY" --rpc-url "$RPC_URL" --network-passphrase "$PASSPHRASE")

# deploy_contract WASM LABEL -> echoes ONLY the new C... contract id on
# stdout. All human-readable logging goes to stderr, because this function's
# stdout is captured via command substitution.
deploy_contract() {
    local wasm="$1" label="$2"
    step "Deploying $label ($wasm)" >&2
    local out id
    if ! out="$("$CLI_BIN" contract deploy --wasm "$wasm" "${NET_ARGS[@]}")"; then
        die "deploying $label failed — aborting before any dependent step"
    fi
    id="$(printf '%s\n' "$out" | tail -n 1 | tr -d '[:space:]')"
    [[ "$id" =~ ^C[A-Z2-7]{55}$ ]] ||
        die "could not parse $label contract id from CLI output: '$out'"
    info "$label deployed: $id" >&2
    printf '%s' "$id"
}

invoke() {
    local id="$1"
    shift
    "$CLI_BIN" contract invoke --id "$id" "${NET_ARGS[@]}" -- "$@"
}

# ---------------------------------------------------------------------------
# 1/3 — schema-registry (no dependencies)
# ---------------------------------------------------------------------------
REGISTRY_ID="$(deploy_contract "$WASM_REGISTRY" "schema-registry")"

step "Initializing SchemaRegistry::init(admin)"
invoke "$REGISTRY_ID" init --admin "$ADMIN_ADDRESS" ||
    die "SchemaRegistry::init failed"
info "SchemaRegistry initialized"

# ---------------------------------------------------------------------------
# 2/3 — sas (depends on registry)
# ---------------------------------------------------------------------------
SAS_ID="$(deploy_contract "$WASM_SAS" "sas")"

step "Calling SAS::init(admin, registry_address)"
invoke "$SAS_ID" init --admin "$ADMIN_ADDRESS" --registry "$REGISTRY_ID" ||
    die "SAS::init failed — sas deployed at $SAS_ID but is NOT initialized"
info "SAS initialized with registry $REGISTRY_ID"

# ---------------------------------------------------------------------------
# 3/3 — indexer (depends on sas)
# ---------------------------------------------------------------------------
INDEXER_ID="$(deploy_contract "$WASM_INDEXER" "indexer")"

step "Calling Indexer::init(admin, sas_address)"
invoke "$INDEXER_ID" init --admin "$ADMIN_ADDRESS" --sas "$SAS_ID" ||
    die "Indexer::init failed — indexer deployed at $INDEXER_ID but is NOT initialized"
info "Indexer initialized with sas $SAS_ID"

step "Binding SAS to the deployed indexer"
invoke "$SAS_ID" set_indexer --indexer "$INDEXER_ID" ||
    die "SAS::set_indexer failed — indexer was initialized but SAS was not bound"

step "Verifying the SAS <-> Indexer binding"
SAS_BOUND="$(invoke "$SAS_ID" get_indexer)"
INDEXER_BOUND="$(invoke "$INDEXER_ID" get_sas)"
if [[ "$SAS_BOUND" != "$INDEXER_ID" || "$INDEXER_BOUND" != "$SAS_ID" ]]; then
    die "binding verification failed: SAS.get_indexer=$SAS_BOUND, Indexer.get_sas=$INDEXER_BOUND. Re-run with the same admin key, then call 'stellar contract invoke --id $SAS_ID -- set_indexer --indexer $INDEXER_ID' and verify with 'stellar contract invoke --id $INDEXER_ID -- get_sas'"
fi
info "SAS and Indexer are bidirectionally bound"

# ---------------------------------------------------------------------------
# Write .env — merge into any existing file without clobbering unrelated
# variables. Managed keys use the exact names from .env.example.
#
# All managed keys are applied to a single in-memory copy of the file and
# flushed to disk in one atomic rename, so a reader (or a crash mid-write)
# never observes a partially-updated file.
# ---------------------------------------------------------------------------
step "Writing deployment results to $ENV_FILE"

MANAGED_KEYS=(
    SOROBAN_RPC_URL
    SOROBAN_NETWORK_PASSPHRASE
    SCHEMA_REGISTRY_CONTRACT_ID
    SAS_CONTRACT_ID
    INDEXER_CONTRACT_ID
    ADMIN_SECRET_KEY
)
MANAGED_VALUES=(
    "\"$RPC_URL\""
    "\"$PASSPHRASE\""
    "$REGISTRY_ID"
    "$SAS_ID"
    "$INDEXER_ID"
    "$SECRET_KEY"
)

ENV_WORK="$(mktemp "${ENV_FILE}.XXXXXX")"

if [[ -f "$ENV_FILE" ]]; then
    cp "$ENV_FILE" "$ENV_FILE.bak"
    warn "existing $ENV_FILE backed up to $ENV_FILE.bak"
    cp "$ENV_FILE" "$ENV_WORK"
else
    : > "$ENV_WORK"
fi

# upsert_env KEY VALUE — replace the key's line in place (preserving every
# other line: comments, blank lines, unrelated vars), or append it when
# missing. Operates on the local $ENV_WORK scratch copy only.
upsert_env() {
    local key="$1" written="$2"
    if grep -q "^${key}=" "$ENV_WORK"; then
        local current
        current="$(grep "^${key}=" "$ENV_WORK" | head -n 1 | cut -d= -f2-)"
        if [[ -n "$current" && "$current" != "$written" ]]; then
            warn "overwriting $key in $ENV_FILE:"
            warn "  old: $key=$current"
            warn "  new: $key=$written"
        fi
        awk -v k="$key" -v v="$written" '
            index($0, k "=") == 1 { print k "=" v; updated = 1; next }
            { print }
            END { if (!updated) print k "=" v }
        ' "$ENV_WORK" > "$ENV_WORK.next"
        mv "$ENV_WORK.next" "$ENV_WORK"
    else
        printf '%s=%s\n' "$key" "$written" >> "$ENV_WORK"
    fi
}

for i in "${!MANAGED_KEYS[@]}"; do
    upsert_env "${MANAGED_KEYS[$i]}" "${MANAGED_VALUES[$i]}"
done

chmod 600 "$ENV_WORK" 2>/dev/null || true
mv "$ENV_WORK" "$ENV_FILE"

ENV_FILE_ABS="$(cd "$(dirname "$ENV_FILE")" && pwd)/$(basename "$ENV_FILE")"
upsert_env "SOROBAN_RPC_URL"             "$RPC_URL"    true
upsert_env "SOROBAN_NETWORK_PASSPHRASE"  "$PASSPHRASE" true
upsert_env "SCHEMA_REGISTRY_CONTRACT_ID" "$REGISTRY_ID"
upsert_env "SAS_CONTRACT_ID"             "$SAS_ID"
upsert_env "INDEXER_CONTRACT_ID"         "$INDEXER_ID"
upsert_env "ADMIN_PUBLIC_ADDRESS"        "$ADMIN_ADDRESS"

if [[ "$EXPORT_SECRET" == true ]]; then
    upsert_env "ADMIN_SECRET_KEY"        "$SECRET_KEY"
    chmod 600 "$ENV_FILE" 2>/dev/null || true
    warn "ADMIN_SECRET_KEY written to $ENV_FILE (chmod 600)"
else
    # Remove any stale ADMIN_SECRET_KEY from a previous run.
    if [[ -f "$ENV_FILE" ]] && grep -q "^ADMIN_SECRET_KEY=" "$ENV_FILE"; then
        sed -i '/^ADMIN_SECRET_KEY=/d' "$ENV_FILE"
        warn "removed ADMIN_SECRET_KEY from $ENV_FILE (use --export-secret to keep it)"
    fi
fi

# ---------------------------------------------------------------------------
# Summary — human-readable report on stdout, or a single JSON object on
# stdout when --json was requested. Progress/log lines always go to stderr
# (see the logging helpers above), so both modes stay clean when redirected.
# ---------------------------------------------------------------------------
if [[ "$JSON_OUTPUT" == true ]]; then
    printf '{\n'
    printf '  "network": "%s",\n' "$NETWORK"
    printf '  "rpcUrl": "%s",\n' "$RPC_URL"
    printf '  "networkPassphrase": "%s",\n' "$PASSPHRASE"
    printf '  "admin": "%s",\n' "$ADMIN_ADDRESS"
    printf '  "contracts": {\n'
    printf '    "schemaRegistry": "%s",\n' "$REGISTRY_ID"
    printf '    "sas": "%s",\n' "$SAS_ID"
    printf '    "indexer": "%s"\n' "$INDEXER_ID"
    printf '  },\n'
    printf '  "envFile": "%s",\n' "$ENV_FILE_ABS"
    printf '  "activationCommand": "source %s"\n' "$ENV_FILE"
    printf '}\n'
else
    step "Deployment complete on $NETWORK"
    printf '\n'
    printf '  %-16s %s\n' "schema-registry:" "$REGISTRY_ID"
    printf '  %-16s %s\n' "sas:" "$SAS_ID"
    printf '  %-16s %s\n' "indexer:" "$INDEXER_ID"
    printf '  %-16s %s\n' "admin:" "$ADMIN_ADDRESS"
    printf '  %-16s %s\n' "network:" "$NETWORK ($RPC_URL)"
    printf '\n'
fi

info "results written to: $ENV_FILE_ABS (key names match .env.example)"
info "this script cannot export variables into your shell — activate the"
info "deployment yourself by running:"
info ""
info "    source $ENV_FILE"
info ""
info "next step: use soroban-sas-cli against these contracts,"
step "Deployment complete on $NETWORK"
printf '\n'
printf '  %-16s %s\n' "schema-registry:" "$REGISTRY_ID"
printf '  %-16s %s\n' "sas:" "$SAS_ID"
printf '  %-16s %s\n' "indexer:" "$INDEXER_ID"
printf '  %-16s %s\n' "admin:" "$ADMIN_ADDRESS"
printf '  %-16s %s\n' "network:" "$NETWORK ($RPC_URL)"
printf '\n'
info "results written to $ENV_FILE (key names match .env.example)"
if [[ "$EXPORT_SECRET" == true ]]; then
    info "ADMIN_SECRET_KEY is in $ENV_FILE — guard this file carefully"
else
    info "signing uses the '$IDENTITY_NAME' CLI identity (no secret key stored in .env)"
fi
info "next step: source $ENV_FILE and use soroban-sas-cli against these contracts,"
info "e.g.: cargo run -p soroban-sas-cli -- schema register ..."

