#!/usr/bin/env bash
set -euo pipefail

# Scrape SAS contract events into PostgreSQL. The event JSON is retained so
# consumers can decode XDR fields later without losing source data.

RPC_URL="${SOROBAN_RPC_URL:-}"
SAS_CONTRACT_ID="${SAS_CONTRACT_ID:-}"
DATABASE_URL="${DATABASE_URL:-}"
START_LEDGER="${START_LEDGER:-1}"
STATE_FILE="${SCRAPER_STATE_FILE:-.attestation-scraper-ledger}"
PAGE_SIZE="${SCRAPER_PAGE_SIZE:-1000}"

die() { printf '[scraper] error: %s\n' "$*" >&2; exit 1; }
info() { printf '[scraper] %s\n' "$*"; }

usage() {
    cat <<'EOF'
Usage: scripts/scrape_attestations.sh

Required environment:
  SOROBAN_RPC_URL       Soroban JSON-RPC endpoint
  SAS_CONTRACT_ID       SAS contract to scrape
  DATABASE_URL          PostgreSQL connection URL

Optional environment:
  START_LEDGER          First ledger when no state file exists (default: 1)
  SCRAPER_STATE_FILE    Cursor file (default: .attestation-scraper-ledger)
  SCRAPER_PAGE_SIZE     getEvents page size (default: 1000)

The scraper is safe to restart: events are keyed by contract, ledger,
transaction hash, and event index, and the cursor advances only after a
page has been committed successfully.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help) usage; exit 0 ;;
        *) die "unknown argument: $1 (see --help)" ;;
    esac
done

[[ -n "$RPC_URL" ]] || die "SOROBAN_RPC_URL is required"
[[ -n "$SAS_CONTRACT_ID" ]] || die "SAS_CONTRACT_ID is required"
[[ -n "$DATABASE_URL" ]] || die "DATABASE_URL is required"
command -v curl >/dev/null 2>&1 || die "curl is required"
command -v jq >/dev/null 2>&1 || die "jq is required"
command -v psql >/dev/null 2>&1 || die "psql is required"
[[ "$START_LEDGER" =~ ^[0-9]+$ ]] || die "START_LEDGER must be an integer"
[[ "$PAGE_SIZE" =~ ^[1-9][0-9]*$ ]] || die "SCRAPER_PAGE_SIZE must be a positive integer"

psql "$DATABASE_URL" -v ON_ERROR_STOP=1 <<'SQL'
CREATE TABLE IF NOT EXISTS sas_attestation_events (
    sas_contract_id TEXT NOT NULL,
    ledger BIGINT NOT NULL,
    transaction_hash TEXT NOT NULL,
    event_index INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    event JSONB NOT NULL,
    scraped_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (sas_contract_id, ledger, transaction_hash, event_index)
);
CREATE INDEX IF NOT EXISTS sas_attestation_events_type_ledger_idx
    ON sas_attestation_events (event_type, ledger);
SQL

cursor="$START_LEDGER"
if [[ -f "$STATE_FILE" ]]; then
    cursor="$(<"$STATE_FILE")"
fi
[[ "$cursor" =~ ^[0-9]+$ ]] || die "cursor file '$STATE_FILE' must contain an integer"

while :; do
    end_ledger=$((cursor + 999))
    request="$(jq -cn \
        --argjson start "$cursor" \
        --argjson end "$end_ledger" \
        --argjson limit "$PAGE_SIZE" \
        --arg contract "$SAS_CONTRACT_ID" \
        '{jsonrpc:"2.0",id:1,method:"getEvents",params:{startLedger:$start,endLedger:$end,filters:[{type:"contract",contractIds:[$contract]}],limit:$limit}}')"
    response="$(curl --fail-with-body --silent --show-error -X POST "$RPC_URL" \
        -H 'Content-Type: application/json' --data "$request")"
    [[ "$(jq -r '.error // empty' <<<"$response")" == "" ]] || {
        jq -e '.error' <<<"$response" >&2
        exit 1
    }

    event_count="$(jq '.result.events // [] | length' <<<"$response")"
    while IFS= read -r event; do
        [[ -n "$event" ]] || continue
        ledger="$(jq -r '.ledger // 0' <<<"$event")"
        tx_hash="$(jq -r '.txHash // .transactionHash // "unknown"' <<<"$event")"
        event_index="$(jq -r '.eventIndex // .index // 0' <<<"$event")"
        event_type="$(jq -r '.topic[0] // "unknown"' <<<"$event")"
        psql "$DATABASE_URL" -v ON_ERROR_STOP=1 \
            -v contract="$SAS_CONTRACT_ID" -v ledger="$ledger" \
            -v tx_hash="$tx_hash" -v event_index="$event_index" \
            -v event_type="$event_type" -v event_json="$event" <<'SQL'
INSERT INTO sas_attestation_events
    (sas_contract_id, ledger, transaction_hash, event_index, event_type, event)
VALUES (:'contract', :'ledger', :'tx_hash', :'event_index',
        :'event_type', :'event_json'::jsonb)
ON CONFLICT (sas_contract_id, ledger, transaction_hash, event_index)
DO UPDATE SET event = EXCLUDED.event, event_type = EXCLUDED.event_type,
              scraped_at = now();
SQL
    done < <(jq -c '.result.events // [] | .[]' <<<"$response")

    if [[ "$event_count" -ge "$PAGE_SIZE" ]]; then
        die "received $event_count events in ledger window $cursor-$end_ledger; reduce SCRAPER_PAGE_SIZE or use a narrower START_LEDGER window"
    fi
    printf '%s\n' "$((end_ledger + 1))" >"$STATE_FILE"
    info "stored $event_count event(s), cursor=$((end_ledger + 1))"
    [[ "$end_ledger" -ge "$(jq -r '.result.latestLedger // 0' <<<"$response")" ]] && break
    cursor=$((end_ledger + 1))
done