#!/usr/bin/env bash
set -euo pipefail

# Failure reproduction script for stateful indexer fuzzing.
#
# This script deterministically replays stateful operation sequences
# (Insert, Revoke, ReadPage, SimulateStorageExpiry) across simulated ledgers
# to verify and reproduce protocol invariants.
#
# Usage:
#   # Run acceptance verification (50,000 operations)
#   ./scripts/reproduce_stateful_fuzz.sh --ops 50000
#
#   # Reproduce a specific failing seed
#   ./scripts/reproduce_stateful_fuzz.sh --seed 0x5EEDF00D12345678 --ops 5000
#
#   # Replay a libfuzzer raw crash artifact
#   ./scripts/reproduce_stateful_fuzz.sh --file fuzz/crash-12345
#
#   # Verbose step-by-step tracing
#   ./scripts/reproduce_stateful_fuzz.sh --ops 20 --verbose

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

info() { printf '\033[1;34m[stateful-fuzz-repro]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[stateful-fuzz-repro]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[stateful-fuzz-repro]\033[0m %s\n' "$*" >&2; exit 1; }

info "Building stateful indexer fuzzer in release mode..."
cargo build --release --manifest-path fuzz/Cargo.toml --bin stateful_indexer_fuzz

info "Executing stateful fuzzer runner with arguments: $*"
RUST_BACKTRACE=1 cargo run --release --manifest-path fuzz/Cargo.toml --bin stateful_indexer_fuzz -- "$@"
