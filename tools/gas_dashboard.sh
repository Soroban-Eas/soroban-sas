#!/usr/bin/env bash
#
# tools/gas_dashboard.sh — ASCII / Markdown gas profiling history dashboard
#
# Reads all JSON snapshots from gas_profile_history/ (or a custom dir) and
# renders a table showing every measured entrypoint across the last N runs,
# optionally highlighting regressions.
#
# Usage:
#   ./tools/gas_dashboard.sh [OPTIONS]
#
# Options:
#   --dir DIR         History directory  (default: gas_profile_history)
#   --runs N          Number of most recent runs to display (default: 5, 0 = all)
#   --format FMT      Output format: ascii (default) | markdown | csv | json
#   --threshold PCT   Regression threshold in % (default: 10)
#   --out FILE        Write output to FILE instead of stdout
#   --metric M        Metric to compare: cpu (default) | mem | both
#   -h, --help        Show this help
#
# Requirements: bash 4+, jq
#
# Exit codes:
#   0  Normal exit (no regressions, or regressions within threshold)
#   2  One or more regressions detected above the threshold
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------
info() { printf '\033[1;34m[gas-dashboard]\033[0m %s\n' "$*" >&2; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*" >&2; }
err()  { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; }

# ---------------------------------------------------------------------------
# Defaults / argument parsing
# ---------------------------------------------------------------------------
HISTORY_DIR="$REPO_ROOT/gas_profile_history"
RUNS=5
FORMAT="ascii"
THRESHOLD=10
OUT_FILE=""
METRIC="cpu"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dir)        HISTORY_DIR="${2:?--dir requires a value}"; shift 2 ;;
        --runs)       RUNS="${2:?--runs requires a value}"; shift 2 ;;
        --format)     FORMAT="${2:?--format requires a value}"; shift 2 ;;
        --threshold)  THRESHOLD="${2:?--threshold requires a value}"; shift 2 ;;
        --out)        OUT_FILE="${2:?--out requires a value}"; shift 2 ;;
        --metric)     METRIC="${2:?--metric requires a value}"; shift 2 ;;
        -h|--help)    sed -n '2,30p' "$0" | grep '^#' | sed 's/^# \{0,1\}//'; exit 0 ;;
        *)            err "unknown argument: $1"; exit 1 ;;
    esac
done

command -v jq >/dev/null 2>&1 || { err "jq is required"; exit 1; }

[[ -d "$HISTORY_DIR" ]] || { warn "history directory '$HISTORY_DIR' does not exist. Run gas profiling tests first."; exit 0; }

# ---------------------------------------------------------------------------
# Collect JSON files, newest last
# ---------------------------------------------------------------------------
mapfile -t ALL_FILES < <(find "$HISTORY_DIR" -maxdepth 1 -name '*.json' | sort)

if [[ ${#ALL_FILES[@]} -eq 0 ]]; then
    warn "no snapshots found in '$HISTORY_DIR'. Run gas profiling tests first."
    exit 0
fi

if [[ "$RUNS" -gt 0 && ${#ALL_FILES[@]} -gt $RUNS ]]; then
    START=$(( ${#ALL_FILES[@]} - RUNS ))
    SELECTED_FILES=("${ALL_FILES[@]:$START}")
else
    SELECTED_FILES=("${ALL_FILES[@]}")
fi

info "found ${#ALL_FILES[@]} snapshot(s); displaying last ${#SELECTED_FILES[@]}"

# ---------------------------------------------------------------------------
# Load snapshots into parallel arrays
# ---------------------------------------------------------------------------
declare -a RUN_TIMESTAMPS=()
declare -a RUN_GIT_REVS=()
declare -A MEASUREMENTS=()   # key: "<run_idx>:<entrypoint>"  value: "cpu|mem"
declare -a ALL_ENTRYPOINTS=()

for i in "${!SELECTED_FILES[@]}"; do
    file="${SELECTED_FILES[$i]}"
    ts="$(jq -r '.timestamp // "unknown"' "$file")"
    rev="$(jq -r '.git_rev // "unknown"' "$file")"
    RUN_TIMESTAMPS+=("$ts")
    RUN_GIT_REVS+=("$rev")

    while IFS= read -r row; do
        ep="$(jq -r '.entrypoint' <<< "$row")"
        cpu="$(jq -r '.cpu_insns' <<< "$row")"
        mem="$(jq -r '.mem_bytes' <<< "$row")"
        MEASUREMENTS["$i:$ep"]="$cpu|$mem"
        # Collect unique entrypoints (preserve first-seen order)
        if ! printf '%s\n' "${ALL_ENTRYPOINTS[@]:-}" | grep -qxF "$ep"; then
            ALL_ENTRYPOINTS+=("$ep")
        fi
    done < <(jq -c '.measurements[]' "$file")
done

NUM_RUNS="${#SELECTED_FILES[@]}"

# ---------------------------------------------------------------------------
# Regression detection
# ---------------------------------------------------------------------------
REGRESSION_COUNT=0
declare -A REGRESSION_FLAG=()   # key: entrypoint, value: "cpu" | "mem" | "both"

if [[ $NUM_RUNS -ge 2 ]]; then
    LAST=$((NUM_RUNS - 1))
    PREV=$((NUM_RUNS - 2))
    for ep in "${ALL_ENTRYPOINTS[@]}"; do
        prev_val="${MEASUREMENTS["$PREV:$ep"]:-}"
        last_val="${MEASUREMENTS["$LAST:$ep"]:-}"
        [[ -z "$prev_val" || -z "$last_val" ]] && continue

        prev_cpu="${prev_val%%|*}"
        prev_mem="${prev_val##*|}"
        last_cpu="${last_val%%|*}"
        last_mem="${last_val##*|}"

        reg=""
        if [[ "$prev_cpu" -gt 0 ]]; then
            delta=$(( (last_cpu - prev_cpu) * 100 / prev_cpu ))
            if [[ $delta -gt $THRESHOLD ]]; then
                reg="${reg}cpu"
            fi
        fi
        if [[ "$prev_mem" -gt 0 ]]; then
            delta=$(( (last_mem - prev_mem) * 100 / prev_mem ))
            if [[ $delta -gt $THRESHOLD ]]; then
                reg="${reg}${reg:+/}mem"
            fi
        fi

        if [[ -n "$reg" ]]; then
            REGRESSION_FLAG["$ep"]="$reg"
            REGRESSION_COUNT=$(( REGRESSION_COUNT + 1 ))
        fi
    done
fi

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
format_num() {
    # Add thousands separator to a number using printf grouping (locale-aware).
    local n="$1"
    if [[ -z "$n" || "$n" == "null" ]]; then
        printf '%10s' "—"
    else
        printf '%10d' "$n"
    fi
}

# Build a short header label from timestamp: keep just date + time.
short_label() {
    local ts="$1" rev="$2"
    local date="${ts%%T*}"
    local time="${ts#*T}"; time="${time%Z}"
    printf '%s %s (%.7s)' "$date" "${time:0:5}" "$rev"
}

# ---------------------------------------------------------------------------
# Render output
# ---------------------------------------------------------------------------
render_ascii() {
    local col_ep=50
    # Build header
    local header="| $(printf '%-*s' $col_ep 'Entrypoint')"
    local separator="+-$(printf '%0.s-' $(seq 1 $col_ep))"
    for i in "${!SELECTED_FILES[@]}"; do
        local lbl
        lbl="$(short_label "${RUN_TIMESTAMPS[$i]}" "${RUN_GIT_REVS[$i]}")"
        header+=" | $(printf '%28s' "$lbl")"
        separator+="-+-$(printf '%0.s-' $(seq 1 28))"
    done
    header+=" |"
    separator+="-+"

    printf '%s\n' "$separator"
    printf '%s\n' "$header"
    printf '%s\n' "$separator"

    for ep in "${ALL_ENTRYPOINTS[@]}"; do
        local reg="${REGRESSION_FLAG[$ep]:-}"
        local flag=""
        [[ -n "$reg" ]] && flag=" ⚠ $reg"
        local row
        row="| $(printf '%-*s' $col_ep "${ep}${flag}")"
        for i in "${!SELECTED_FILES[@]}"; do
            val="${MEASUREMENTS["$i:$ep"]:-}"
            if [[ -z "$val" ]]; then
                row+=" | $(printf '%28s' '—')"
            else
                local cpu="${val%%|*}" mem="${val##*|}"
                case "$METRIC" in
                    mem)  row+=" | $(printf '%14s / %12s' "$(format_num "$mem")" 'B mem')" ;;
                    both) row+=" | $(printf '%12s cpu %12s mem' "$(format_num "$cpu")" "$(format_num "$mem")")" ;;
                    *)    row+=" | $(printf '%12s cpu  %12s B' "$(format_num "$cpu")" "$(format_num "$mem")")" ;;
                esac
            fi
        done
        row+=" |"
        printf '%s\n' "$row"
    done

    printf '%s\n' "$separator"

    if [[ $REGRESSION_COUNT -gt 0 ]]; then
        printf '\n⚠  %d entrypoint(s) regressed by more than %d%% vs the previous run.\n' "$REGRESSION_COUNT" "$THRESHOLD"
    else
        printf '\n✓  No regressions detected (threshold: %d%%).\n' "$THRESHOLD"
    fi
}

render_markdown() {
    printf '# Gas Profiling History Dashboard\n\n'
    printf 'Generated by `tools/gas_dashboard.sh` · showing last %d run(s)\n\n' "$NUM_RUNS"

    local header="| Entrypoint"
    local separator="|:--------"
    for i in "${!SELECTED_FILES[@]}"; do
        local lbl
        lbl="$(short_label "${RUN_TIMESTAMPS[$i]}" "${RUN_GIT_REVS[$i]}")"
        header+=" | $lbl (CPU / Mem)"
        separator+=" |------:"
    done
    header+=" |"
    separator+=" |"
    printf '%s\n%s\n' "$header" "$separator"

    for ep in "${ALL_ENTRYPOINTS[@]}"; do
        local reg="${REGRESSION_FLAG[$ep]:-}"
        local label="$ep"
        [[ -n "$reg" ]] && label="⚠ **${ep}** ($reg regression)"
        local row="| \`$label\`"
        for i in "${!SELECTED_FILES[@]}"; do
            local val="${MEASUREMENTS["$i:$ep"]:-}"
            if [[ -z "$val" ]]; then
                row+=" | —"
            else
                local cpu="${val%%|*}" mem="${val##*|}"
                row+=" | ${cpu} / ${mem}"
            fi
        done
        row+=" |"
        printf '%s\n' "$row"
    done

    printf '\n'
    if [[ $REGRESSION_COUNT -gt 0 ]]; then
        printf '> ⚠ **%d entrypoint(s) regressed** by more than %d%% vs the previous run.\n' \
            "$REGRESSION_COUNT" "$THRESHOLD"
    else
        printf '> ✓ No regressions detected (threshold: %d%%).\n' "$THRESHOLD"
    fi
}

render_csv() {
    local header="entrypoint"
    for i in "${!SELECTED_FILES[@]}"; do
        header+=",cpu_${RUN_TIMESTAMPS[$i]},mem_${RUN_TIMESTAMPS[$i]}"
    done
    printf '%s\n' "$header"

    for ep in "${ALL_ENTRYPOINTS[@]}"; do
        local row="\"$ep\""
        for i in "${!SELECTED_FILES[@]}"; do
            local val="${MEASUREMENTS["$i:$ep"]:-}"
            if [[ -z "$val" ]]; then
                row+=",,"
            else
                row+=",${val%%|*},${val##*|}"
            fi
        done
        printf '%s\n' "$row"
    done
}

render_json_summary() {
    printf '{\n  "runs": [\n'
    for i in "${!SELECTED_FILES[@]}"; do
        [[ $i -gt 0 ]] && printf ',\n'
        printf '    {"timestamp":"%s","git_rev":"%s","file":"%s"}' \
            "${RUN_TIMESTAMPS[$i]}" "${RUN_GIT_REVS[$i]}" "$(basename "${SELECTED_FILES[$i]}")"
    done
    printf '\n  ],\n  "regressions": %d,\n  "threshold_pct": %d\n}\n' \
        "$REGRESSION_COUNT" "$THRESHOLD"
}

# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------
if [[ -n "$OUT_FILE" ]]; then
    case "$FORMAT" in
        markdown) render_markdown > "$OUT_FILE" ;;
        csv)      render_csv      > "$OUT_FILE" ;;
        json)     render_json_summary > "$OUT_FILE" ;;
        *)        render_ascii    > "$OUT_FILE" ;;
    esac
    info "wrote $OUT_FILE"
else
    case "$FORMAT" in
        markdown) render_markdown ;;
        csv)      render_csv ;;
        json)     render_json_summary ;;
        *)        render_ascii ;;
    esac
fi

# Exit 2 when regressions detected (allows CI to gate on this).
[[ $REGRESSION_COUNT -gt 0 ]] && exit 2 || exit 0
