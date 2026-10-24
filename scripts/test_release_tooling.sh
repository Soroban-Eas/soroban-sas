#!/usr/bin/env bash
#
# scripts/test_release_tooling.sh - behavioural tests for
# scripts/release_notes.sh and scripts/check_release_version.sh.
#
# Each case runs against a throwaway git repository or fixture workspace, so
# nothing here depends on the real history, tags or manifests of this checkout.
#
# Usage:
#   ./scripts/test_release_tooling.sh
#
# Exit code: 0 if every case passes, 1 otherwise.
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

PASSED=0
FAILED=0
pass() { printf '  ok   %s\n' "$*"; PASSED=$((PASSED + 1)); }
fail() { printf '  FAIL %s\n' "$*" >&2; FAILED=$((FAILED + 1)); }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Captured by `run`.
OUT=""
ERR=""
STATUS=0

# run <command...> - runs the command, capturing stdout, stderr and status
# without tripping `set -e`.
run() {
    local out_file="$WORK/out.$$" err_file="$WORK/err.$$"
    STATUS=0
    "$@" >"$out_file" 2>"$err_file" || STATUS=$?
    OUT="$(cat "$out_file")"
    ERR="$(cat "$err_file")"
}

assert_status() {
    local expected="$1" label="$2"
    if [[ "$STATUS" -eq "$expected" ]]; then
        pass "$label"
    else
        fail "$label (exit $STATUS, expected $expected)"
        printf '       stderr: %s\n' "$ERR" >&2
    fi
}

assert_out_has() {
    local needle="$1" label="$2"
    if grep -qF -- "$needle" <<<"$OUT"; then
        pass "$label"
    else
        fail "$label (missing: $needle)"
        printf '%s\n' "$OUT" | sed 's/^/       | /' >&2
    fi
}

assert_out_lacks() {
    local needle="$1" label="$2"
    if grep -qF -- "$needle" <<<"$OUT"; then
        fail "$label (unexpected: $needle)"
        printf '%s\n' "$OUT" | sed 's/^/       | /' >&2
    else
        pass "$label"
    fi
}

assert_err_has() {
    local needle="$1" label="$2"
    if grep -qF -- "$needle" <<<"$ERR"; then
        pass "$label"
    else
        fail "$label (stderr missing: $needle)"
        printf '       stderr: %s\n' "$ERR" >&2
    fi
}

# Line number of the first line equal to $1 in $OUT (0 when absent).
line_of() {
    grep -nxF -- "$1" <<<"$OUT" | head -n1 | cut -d: -f1 || true
}

# ---------------------------------------------------------------------------
# release_notes.sh
# ---------------------------------------------------------------------------

commit() {
    git commit -q --allow-empty -m "$1"
}

# new_notes_repo -> builds a repository with two releases and cd's into it.
new_notes_repo() {
    local dir="$WORK/notes-repo"
    rm -rf "$dir"
    mkdir -p "$dir/scripts"
    cp "$REPO_ROOT/scripts/release_notes.sh" "$dir/scripts/"
    cd "$dir"
    git init -q
    git config user.email "release-test@example.invalid"
    git config user.name "release test"
    git config commit.gpgsign false
    git config tag.gpgsign false
    git config core.autocrlf false

    commit "feat: ancient history before the first release"
    git tag v0.9.0

    commit "feat(registry): add attester access control lists (#443)"
    commit "fix(sas): reject unlisted attesters (#443)"
    commit "perf: cache the schema lookup"
    commit "docs: describe schema lineage"
    commit "test(registry): cover multi-generation lineage"
    commit "ci: run release tooling tests"
    commit "chore: tidy imports"
    commit "fix!: drop the legacy register entrypoint"
    git commit -q --allow-empty -m "feat: new record layout" -m "BREAKING CHANGE: SchemaRecord gains parent_schema_uid"
    commit "Updated the readme by hand"
    commit "chore(release): v1.0.0"

    # CRLF on purpose: Windows checkouts convert the changelog.
    printf '# Changelog\r\n\r\n## [Unreleased]\r\n\r\n## [1.0.0] - 2026-01-01\r\n\r\n### Added\r\n- A highlight line\r\n\r\n## [0.9.0] - 2025-01-01\r\n\r\n- Older entry\r\n' >CHANGELOG.md
    git add CHANGELOG.md
    commit "docs: add the 1.0.0 changelog"
    git tag v1.0.0
}

echo "release_notes.sh"
new_notes_repo

run bash ./scripts/release_notes.sh v1.0.0 --repo example/sas
assert_status 0 "generates notes for an existing tag"
assert_out_has "# SAS v1.0.0" "title carries the tag"
assert_out_has "## Features" "has a Features section"
assert_out_has "- **registry:** add attester access control lists (#443)" "scope is rendered in bold"
assert_out_has "## Bug Fixes" "has a Bug Fixes section"
assert_out_has "- **sas:** reject unlisted attesters (#443)" "fix entry is listed"
assert_out_has "## Performance" "has a Performance section"
assert_out_has "## Documentation" "has a Documentation section"
assert_out_has "## Tests" "has a Tests section"
assert_out_has "## Build and CI" "has a Build and CI section"
assert_out_has "## Maintenance" "has a Maintenance section"
assert_out_has "- tidy imports" "unscoped entry has no scope prefix"
assert_out_has "## Other Changes" "non-conventional commits are kept"
assert_out_has "- Updated the readme by hand" "non-conventional subject is listed verbatim"
assert_out_lacks "ancient history" "commits before the previous tag are excluded"
assert_out_lacks "chore(release)" "release bookkeeping commits are skipped"
assert_out_has "**Full Changelog**: https://github.com/example/sas/compare/v0.9.0...v1.0.0" "compare link spans the previous tag"

run bash ./scripts/release_notes.sh v1.0.0
assert_out_lacks "Full Changelog" "no compare link without a repository"

# Breaking changes.
run bash ./scripts/release_notes.sh v1.0.0
assert_out_has "## Breaking Changes" "has a Breaking Changes section"
assert_out_has "drop the legacy register entrypoint" "bang commits are breaking"
assert_out_has "  - SchemaRecord gains parent_schema_uid" "BREAKING CHANGE footer text is shown"
breaking_line="$(line_of '## Breaking Changes')"
features_line="$(line_of '## Features')"
fixes_line="$(line_of '## Bug Fixes')"
if [[ "$breaking_line" -gt 0 && "$breaking_line" -lt "$features_line" && "$features_line" -lt "$fixes_line" ]]; then
    pass "sections are ordered Breaking, Features, Bug Fixes"
else
    fail "sections are ordered Breaking, Features, Bug Fixes ($breaking_line, $features_line, $fixes_line)"
fi
# Breaking entries must not be repeated in their type bucket.
fixes_block="$(sed -n "${fixes_line},\$p" <<<"$OUT" | sed '/^## Performance/,$d')"
if grep -qF "drop the legacy" <<<"$fixes_block"; then
    fail "breaking fix is not repeated under Bug Fixes"
else
    pass "breaking fix is not repeated under Bug Fixes"
fi

# Changelog highlights.
assert_out_has "## Highlights" "includes the CHANGELOG section"
assert_out_has "- A highlight line" "CHANGELOG body is included"
assert_out_lacks "Older entry" "CHANGELOG stops at the next version heading"
if grep -q $'\r' <<<"$OUT"; then
    fail "carriage returns from a CRLF changelog are stripped"
else
    pass "carriage returns from a CRLF changelog are stripped"
fi

# Version spelling.
run bash ./scripts/release_notes.sh 1.0.0
assert_status 0 "accepts a bare version"
assert_out_has "# SAS v1.0.0" "bare version is normalised to a tag"

# Explicit previous tag and full history.
run bash ./scripts/release_notes.sh v1.0.0 --previous none
assert_out_has "ancient history" "--previous none includes the full history"
run bash ./scripts/release_notes.sh v1.0.0 --previous v1.0.0
assert_out_has "No changes were recorded" "an empty range says so"

# A tag that does not exist yet previews from HEAD.
commit "feat(sdk): something after the release"
run bash ./scripts/release_notes.sh v1.1.0
assert_status 0 "previews a tag that does not exist yet"
assert_out_has "something after the release" "preview includes commits since the last tag"
assert_out_lacks "access control lists" "preview excludes the previous release"

# Checksums.
printf 'abc123  sas.opt.wasm\r\ndef456  schema_registry.opt.wasm\r\n' >"$WORK/checksums.sha256"
run bash ./scripts/release_notes.sh v1.0.0 --checksums "$WORK/checksums.sha256"
assert_out_has "## Checksums" "appends a Checksums section"
assert_out_has "abc123  sas.opt.wasm" "checksum lines are included"

# Invalid usage.
run bash ./scripts/release_notes.sh
assert_status 2 "missing tag is a usage error"
run bash ./scripts/release_notes.sh v1.0
assert_status 2 "a non-semver tag is rejected"
assert_err_has "not a semantic version" "non-semver error is explained"
run bash ./scripts/release_notes.sh v1.0.0 --bogus
assert_status 2 "unknown options are rejected"
run bash ./scripts/release_notes.sh v1.0.0 --previous v0.0.1
assert_status 2 "an unknown previous tag is rejected"
run bash ./scripts/release_notes.sh v1.0.0 --checksums "$WORK/does-not-exist"
assert_status 2 "a missing checksums file is rejected"
run bash ./scripts/release_notes.sh v1.0.0 extra
assert_status 2 "a second positional argument is rejected"
run bash ./scripts/release_notes.sh --help
assert_status 0 "--help succeeds"
assert_out_has "Usage:" "--help prints usage"

# ---------------------------------------------------------------------------
# check_release_version.sh
# ---------------------------------------------------------------------------

# new_workspace <version> -> a fixture workspace with two members, all at
# <version>, and returns its path in $WS.
WS=""
new_workspace() {
    local version="$1"
    WS="$WORK/ws"
    rm -rf "$WS"
    mkdir -p "$WS/contracts/alpha" "$WS/packages/beta"
    cat >"$WS/Cargo.toml" <<EOF
[workspace]
members = [
    "contracts/alpha",
"packages/beta",
]
exclude = ["fuzz"]
resolver = "2"

[package]
name = "fixture-root"
version = "$version"
edition = "2021"

[workspace.dependencies]
serde = "1"
EOF
    cat >"$WS/contracts/alpha/Cargo.toml" <<EOF
[package]
name = "alpha"
version = "$version"
edition = "2021"

[dependencies]
beta = { path = "../../packages/beta", version = "0.0.1" }
EOF
    cat >"$WS/packages/beta/Cargo.toml" <<EOF
[package]
name = "beta"
version = "$version"
edition = "2021"
EOF
    cat >"$WS/Cargo.lock" <<EOF
# This file is automatically @generated by Cargo.
version = 3

[[package]]
name = "alpha"
version = "$version"
dependencies = [
 "beta",
]

[[package]]
name = "beta"
version = "$version"

[[package]]
name = "fixture-root"
version = "$version"

[[package]]
name = "serde"
version = "9.9.9"
source = "registry+https://github.com/rust-lang/crates.io-index"
EOF
    printf '# Changelog\n\n## [Unreleased]\n\n## [%s] - 2026-01-01\n\n- entry\n' "$version" >"$WS/CHANGELOG.md"
}

check() {
    run bash "$REPO_ROOT/scripts/check_release_version.sh" "$@" --root "$WS"
}

echo "check_release_version.sh"

new_workspace 1.0.0
check v1.0.0
assert_status 0 "passes when every version agrees"
assert_out_has "OK: 3 crate(s)" "counts the root and both members"
check 1.0.0
assert_status 0 "accepts a bare version"

check v1.0.1
assert_status 1 "fails when the requested version differs"
assert_err_has "workspace root: Cargo.toml version is 1.0.0, expected 1.0.1" "root mismatch is reported"
assert_err_has "contracts/alpha: Cargo.toml version is 1.0.0, expected 1.0.1" "member mismatch is reported"
assert_err_has "Cargo.lock records 1.0.0 for 'beta'" "lockfile mismatch is reported"
assert_err_has "CHANGELOG.md has no '## [1.0.1]' section" "missing changelog section is reported"
assert_err_has "7 problem(s) found" "every problem is reported, not just the first"

new_workspace 1.0.0
sed -i 's/^version = "1.0.0"/version = "0.9.0"/' "$WS/packages/beta/Cargo.toml"
check v1.0.0
assert_status 1 "fails when one member lags behind"
assert_err_has "packages/beta: Cargo.toml version is 0.9.0, expected 1.0.0" "names the lagging member"

new_workspace 1.0.0
sed -i '/name = "alpha"/{n;s/1.0.0/0.9.0/}' "$WS/Cargo.lock"
check v1.0.0
assert_status 1 "fails when Cargo.lock is stale"
assert_err_has "Cargo.lock records 0.9.0 for 'alpha'" "names the stale lock entry"

new_workspace 1.0.0
printf '# Changelog\n\n## [Unreleased]\n' >"$WS/CHANGELOG.md"
check v1.0.0
assert_status 1 "fails without a changelog section"

new_workspace 1.0.0
rm "$WS/CHANGELOG.md"
check v1.0.0
assert_status 1 "fails without a changelog file"

new_workspace 1.0.0
rm "$WS/packages/beta/Cargo.toml"
check v1.0.0
assert_status 1 "fails when a member manifest is missing"

new_workspace 1.0.0
sed -i '/name = "beta"/,/^$/d' "$WS/Cargo.lock"
check v1.0.0
assert_status 1 "fails when a crate is missing from Cargo.lock"
assert_err_has "'beta' is missing from Cargo.lock" "names the missing lock entry"

new_workspace 1.0.0
sed -i 's/$/\r/' "$WS/Cargo.toml" "$WS/contracts/alpha/Cargo.toml" "$WS/packages/beta/Cargo.toml" "$WS/Cargo.lock" "$WS/CHANGELOG.md"
check v1.0.0
assert_status 0 "handles CRLF checkouts"

new_workspace 1.0.0-rc.1
check v1.0.0-rc.1
assert_status 0 "accepts pre-release versions"

new_workspace 1.0.0
run bash "$REPO_ROOT/scripts/check_release_version.sh" v1.0 --root "$WS"
assert_status 2 "rejects a non-semver version"
run bash "$REPO_ROOT/scripts/check_release_version.sh" --root "$WS"
assert_status 2 "missing version is a usage error"
run bash "$REPO_ROOT/scripts/check_release_version.sh" v1.0.0 --root "$WORK/nowhere"
assert_status 2 "a root without Cargo.toml is a usage error"

# The checkout under test must itself be releasable as its own version.
echo "this repository"
repo_version="$(awk '/^\[package\]/{p=1;next} /^\[/{p=0} p && /^version/{gsub(/"/,"",$3); print $3; exit}' "$REPO_ROOT/Cargo.toml" | tr -d '\r')"
if [[ -n "$repo_version" ]]; then
    run bash "$REPO_ROOT/scripts/check_release_version.sh" "v$repo_version" --root "$REPO_ROOT"
    assert_status 0 "manifests, Cargo.lock and CHANGELOG.md agree on v$repo_version"
else
    fail "could not read the root package version"
fi

echo
printf '%d passed, %d failed\n' "$PASSED" "$FAILED"
[[ "$FAILED" -eq 0 ]]
