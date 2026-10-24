#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 1 || ! -f "$1" ]]; then
  echo "Usage: scripts/triage-differential-schema.sh PATH_TO_CRASH_FILE" >&2
  exit 2
fi
repo_root="$(cd "$(dirname "$0")/.." && pwd)"
case "$(realpath "$1")" in
  "$repo_root"/fuzz/artifacts/*|"$repo_root"/fuzz/corpus/*) ;;
  *) echo "Crash input must be inside fuzz/artifacts or fuzz/corpus" >&2; exit 2 ;;
esac
cd "$repo_root"
cargo fuzz tmin differential_schema_fuzz "$1"
