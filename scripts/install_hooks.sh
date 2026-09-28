#!/usr/bin/env bash
#
# scripts/install_hooks.sh — enable the repository's git hooks (.githooks/).
#
# Points this clone's `core.hooksPath` at .githooks so git runs:
#
#   pre-commit  cargo fmt --check on staged Rust changes, bash -n on staged scripts
#   pre-push    cargo fmt --check + cargo clippy -D warnings (CI's gates)
#
# The setting is local to this clone (.git/config); nothing is written to
# global git config, and hooks already in .git/hooks are left untouched.
#
# Usage:
#   ./scripts/install_hooks.sh              # install (idempotent)
#   ./scripts/install_hooks.sh --check      # exit 1 unless installed
#   ./scripts/install_hooks.sh --uninstall  # restore git's default hooks dir
#
set -euo pipefail

readonly HOOKS_DIR=".githooks"
readonly HOOKS=(pre-commit pre-push)

info() { printf '\033[1;34m[hooks]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; exit 1; }

usage() { sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; }

MODE="install"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --check)     MODE="check"; shift ;;
        --uninstall) MODE="uninstall"; shift ;;
        -h|--help)   usage; exit 0 ;;
        *) die "unknown argument: $1 (see --help)" ;;
    esac
done

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" ||
    die "not inside a git repository"
cd "$REPO_ROOT"

current="$(git config --local --get core.hooksPath || true)"

case "$MODE" in
    check)
        if [[ "$current" == "$HOOKS_DIR" ]]; then
            info "hooks installed (core.hooksPath=$HOOKS_DIR)"
            exit 0
        fi
        die "hooks not installed (core.hooksPath='${current:-<unset>}'). Run: ./scripts/install_hooks.sh"
        ;;
    uninstall)
        if [[ "$current" == "$HOOKS_DIR" ]]; then
            git config --local --unset core.hooksPath
            info "hooks uninstalled; git uses .git/hooks again"
        else
            info "hooks were not installed; nothing to do"
        fi
        exit 0
        ;;
esac

for hook in "${HOOKS[@]}"; do
    [[ -f "$HOOKS_DIR/$hook" ]] || die "missing hook script: $HOOKS_DIR/$hook"
    chmod +x "$HOOKS_DIR/$hook"
done

if [[ -n "$current" && "$current" != "$HOOKS_DIR" ]]; then
    die "core.hooksPath is already set to '$current'. Unset it first (git config --unset core.hooksPath) if you want these hooks."
fi

if [[ "$current" == "$HOOKS_DIR" ]]; then
    info "hooks already installed (core.hooksPath=$HOOKS_DIR)"
else
    git config --local core.hooksPath "$HOOKS_DIR"
    info "installed: ${HOOKS[*]} (core.hooksPath=$HOOKS_DIR)"
fi
info "bypass once with --no-verify, or set SAS_SKIP_HOOKS=1"
