#!/usr/bin/env bash
#
# scripts/check_release_version.sh - verify the repository is ready to be
# released as a given version.
#
# For a release tag vX.Y.Z (or a bare X.Y.Z) it checks that:
#   1. the root package and every workspace member in Cargo.toml declare
#      exactly version X.Y.Z,
#   2. Cargo.lock records X.Y.Z for each of those crates, so a `--locked`
#      build of the tagged commit does not need to rewrite the lockfile, and
#   3. CHANGELOG.md has a "## [X.Y.Z]" section.
#
# Every problem is reported before the script exits, not just the first.
#
# Usage:
#   scripts/check_release_version.sh <tag-or-version> [--root <dir>]
#
# Exit code: 0 when the checks pass, 1 when any check fails, 2 on invalid usage.
#
set -euo pipefail

die() {
    printf 'check_release_version.sh: %s\n' "$*" >&2
    exit 2
}

INPUT=""
ROOT=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h | --help)
            sed -n '3,/^set -euo/p' "${BASH_SOURCE[0]}" | sed '$d' | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        --root)
            [[ $# -ge 2 ]] || die "--root needs a value"
            ROOT="$2"
            shift 2
            ;;
        -*)
            die "unknown option: $1"
            ;;
        *)
            [[ -z "$INPUT" ]] || die "unexpected extra argument: $1"
            INPUT="$1"
            shift
            ;;
    esac
done

[[ -n "$INPUT" ]] || die "missing <tag-or-version> (see --help)"

VERSION="${INPUT#v}"
SEMVER_RE='^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$'
[[ "$VERSION" =~ $SEMVER_RE ]] || die "'$INPUT' is not a semantic version (expected X.Y.Z)"

if [[ -z "$ROOT" ]]; then
    ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fi
[[ -f "$ROOT/Cargo.toml" ]] || die "no Cargo.toml in $ROOT"

PROBLEMS=0
problem() {
    printf '  FAIL: %s\n' "$*" >&2
    PROBLEMS=$((PROBLEMS + 1))
}

# Prints the value of `key` in the [package] table of a manifest.
package_field() {
    local file="$1" key="$2"
    tr -d '\r' <"$file" | awk -v key="$key" '
        /^\[/ { in_pkg = ($0 == "[package]") }
        # No early exit: quitting before the input is drained would SIGPIPE
        # the upstream `tr` and trip `set -o pipefail`.
        in_pkg && !done && $0 ~ "^" key "[[:space:]]*=" {
            if (match($0, /"[^"]*"/)) {
                print substr($0, RSTART + 1, RLENGTH - 2)
            }
            done = 1
        }
    '
}

# Prints the workspace member paths declared in the root manifest.
workspace_members() {
    tr -d '\r' <"$ROOT/Cargo.toml" | awk '
        /^\[/ { in_ws = ($0 == "[workspace]"); collecting = 0 }
        in_ws && /^members[[:space:]]*=/ { collecting = 1 }
        collecting {
            line = $0
            while (match(line, /"[^"]*"/)) {
                print substr(line, RSTART + 1, RLENGTH - 2)
                line = substr(line, RSTART + RLENGTH)
            }
            if ($0 ~ /\]/) { collecting = 0 }
        }
    '
}

# Prints the version Cargo.lock records for a path crate named $1.
locked_version() {
    local name="$1"
    [[ -f "$ROOT/Cargo.lock" ]] || return 0
    tr -d '\r' <"$ROOT/Cargo.lock" | awk -v name="$name" '
        /^\[\[package\]\]/ { in_pkg = 1; pkg_name = ""; pkg_ver = ""; has_source = 0; next }
        in_pkg && /^name = / { pkg_name = $3; gsub(/"/, "", pkg_name) }
        in_pkg && /^version = / { pkg_ver = $3; gsub(/"/, "", pkg_ver) }
        in_pkg && /^source = / { has_source = 1 }
        in_pkg && /^$/ {
            if (!done && pkg_name == name && !has_source) { print pkg_ver; done = 1 }
            in_pkg = 0
        }
        END {
            if (in_pkg && !done && pkg_name == name && !has_source) { print pkg_ver }
        }
    '
}

check_crate() {
    local label="$1" manifest="$2"
    local name declared locked

    if [[ ! -f "$manifest" ]]; then
        problem "$label: manifest not found at ${manifest#"$ROOT"/}"
        return
    fi

    name="$(package_field "$manifest" name)"
    declared="$(package_field "$manifest" version)"
    if [[ -z "$declared" ]]; then
        problem "$label: no literal version in [package]"
    elif [[ "$declared" != "$VERSION" ]]; then
        problem "$label: Cargo.toml version is $declared, expected $VERSION"
    fi

    if [[ -n "$name" ]]; then
        locked="$(locked_version "$name")"
        if [[ -z "$locked" ]]; then
            problem "$label: '$name' is missing from Cargo.lock"
        elif [[ "$locked" != "$VERSION" ]]; then
            problem "$label: Cargo.lock records $locked for '$name', expected $VERSION"
        fi
    fi
}

printf 'Checking release %s in %s\n' "$VERSION" "$ROOT"

check_crate "workspace root" "$ROOT/Cargo.toml"

members_found=0
while IFS= read -r member; do
    [[ -n "$member" ]] || continue
    members_found=$((members_found + 1))
    check_crate "$member" "$ROOT/$member/Cargo.toml"
done < <(workspace_members)

if [[ "$members_found" -eq 0 ]]; then
    problem "no workspace members found in Cargo.toml"
fi

if [[ -f "$ROOT/CHANGELOG.md" ]]; then
    if ! tr -d '\r' <"$ROOT/CHANGELOG.md" | grep -qF "## [$VERSION]"; then
        problem "CHANGELOG.md has no '## [$VERSION]' section"
    fi
else
    problem "CHANGELOG.md not found"
fi

if [[ "$PROBLEMS" -gt 0 ]]; then
    printf '%d problem(s) found; the repository is not ready to release %s.\n' "$PROBLEMS" "$VERSION" >&2
    exit 1
fi

printf 'OK: %d crate(s), Cargo.lock and CHANGELOG.md all agree on %s.\n' "$((members_found + 1))" "$VERSION"
