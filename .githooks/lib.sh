#!/usr/bin/env bash
#
# .githooks/lib.sh — shared helpers for the soroban-sas git hooks.
#
# Sourced by .githooks/pre-commit and .githooks/pre-push; not a hook itself.
# Install the hooks with ./scripts/install_hooks.sh (see
# docs/local-development.md#git-hooks).

hook_info() { printf '\033[1;34m[%s]\033[0m %s\n' "$HOOK_NAME" "$*" >&2; }
hook_fail() { printf '\033[1;31m[%s]\033[0m %s\n' "$HOOK_NAME" "$*" >&2; }

# SAS_SKIP_HOOKS=1 bypasses every check, for the rare case where
# `git commit --no-verify` / `git push --no-verify` is not an option (e.g. a
# GUI client). CI still runs the same checks, so nothing skipped here can
# reach `main` unnoticed.
hooks_disabled() {
    [[ "${SAS_SKIP_HOOKS:-0}" == "1" ]]
}

# Git for Windows and some GUI clients start hooks with a PATH that lacks
# rustup's shims even when cargo works in the user's own shell. Fall back to
# the default rustup install location before giving up.
ensure_cargo() {
    if command -v cargo >/dev/null 2>&1; then
        return 0
    fi
    local cargo_home="${CARGO_HOME:-$HOME/.cargo}"
    if [[ -x "$cargo_home/bin/cargo" || -x "$cargo_home/bin/cargo.exe" ]]; then
        PATH="$cargo_home/bin:$PATH"
        export PATH
        return 0
    fi
    hook_fail "cargo not found on PATH or in $cargo_home/bin."
    hook_fail "Install Rust (./scripts/bootstrap.sh --install) or bypass once with --no-verify."
    return 1
}

# Runs "$@", and on failure prints the command plus a remediation hint.
run_check() {
    local hint="$1"
    shift
    hook_info "running: $*"
    if ! "$@"; then
        hook_fail "check failed: $*"
        hook_fail "$hint"
        return 1
    fi
}

# `bash -n` every listed shell script that still exists on disk.
check_shell_syntax() {
    local status=0 script
    for script in "$@"; do
        [[ -f "$script" ]] || continue
        if ! bash -n "$script"; then
            hook_fail "shell syntax error in $script"
            status=1
        fi
    done
    return "$status"
}
