#!/usr/bin/env bash
#
# scripts/test_git_hooks.sh — behavioural tests for .githooks/ and
# scripts/install_hooks.sh.
#
# Each case runs in a throwaway git repository with a stub `cargo` placed
# first on PATH. The stub records every invocation and fails on demand, so
# the tests check which commands the hooks run and how they react to
# failures without compiling the workspace.
#
# Usage:
#   ./scripts/test_git_hooks.sh
#
# Exit code: 0 if every case passes, 1 otherwise.
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

PASSED=0
FAILED=0
pass() { printf '\033[1;32m  ✓ %s\033[0m\n' "$*"; PASSED=$((PASSED + 1)); }
fail() { printf '\033[1;31m  ✗ %s\033[0m\n' "$*" >&2; FAILED=$((FAILED + 1)); }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Stub cargo: appends its argv to $CARGO_LOG; exits 1 when its first
# argument (fmt, clippy, test) is listed in $FAKE_CARGO_FAIL.
FAKE_BIN="$WORK/bin"
mkdir -p "$FAKE_BIN"
cat > "$FAKE_BIN/cargo" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$CARGO_LOG"
for cmd in ${FAKE_CARGO_FAIL:-}; do
    if [[ "$1" == "$cmd" ]]; then
        echo "stub cargo: forced failure of '$1'" >&2
        exit 1
    fi
done
exit 0
EOF
chmod +x "$FAKE_BIN/cargo"
export PATH="$FAKE_BIN:$PATH"
export CARGO_LOG="$WORK/cargo.log"
unset SAS_SKIP_HOOKS SAS_HOOK_CLIPPY SAS_HOOK_TEST FAKE_CARGO_FAIL

# new_repo -> creates a fresh repository with the hooks installed and cd's in.
new_repo() {
    local dir="$WORK/repo-$RANDOM$RANDOM"
    mkdir -p "$dir/scripts"
    cp -R "$REPO_ROOT/.githooks" "$dir/.githooks"
    cp "$REPO_ROOT/scripts/install_hooks.sh" "$dir/scripts/"
    cd "$dir"
    git init -q
    git config user.email "hooks-test@example.invalid"
    git config user.name "hooks test"
    git config commit.gpgsign false
    git config core.autocrlf false
    echo "# test" > README.md
    git add README.md
    git commit -q --no-verify -m "initial"
    ./scripts/install_hooks.sh >/dev/null
    : > "$CARGO_LOG"
}

commit_count() { git rev-list --count HEAD; }

cargo_called_with() { grep -qxF -- "$1" "$CARGO_LOG"; }

# ---------------------------------------------------------------------------
echo "install_hooks.sh"
# ---------------------------------------------------------------------------
new_repo
if [[ "$(git config --local core.hooksPath)" == ".githooks" ]]; then
    pass "sets core.hooksPath to .githooks"
else
    fail "core.hooksPath not set after install"
fi

if ./scripts/install_hooks.sh >/dev/null && [[ "$(git config --local core.hooksPath)" == ".githooks" ]]; then
    pass "re-running install is a no-op"
else
    fail "second install run failed or changed core.hooksPath"
fi

if ./scripts/install_hooks.sh --check >/dev/null 2>&1; then
    pass "--check succeeds when installed"
else
    fail "--check failed although hooks are installed"
fi

./scripts/install_hooks.sh --uninstall >/dev/null
if ! git config --local --get core.hooksPath >/dev/null; then
    pass "--uninstall unsets core.hooksPath"
else
    fail "--uninstall left core.hooksPath set"
fi

if ! ./scripts/install_hooks.sh --check >/dev/null 2>&1; then
    pass "--check fails when not installed"
else
    fail "--check succeeded although hooks are not installed"
fi

git config --local core.hooksPath custom-hooks
if ! ./scripts/install_hooks.sh >/dev/null 2>&1 && [[ "$(git config --local core.hooksPath)" == "custom-hooks" ]]; then
    pass "refuses to overwrite a different core.hooksPath"
else
    fail "overwrote an existing custom core.hooksPath"
fi

# ---------------------------------------------------------------------------
echo "pre-commit"
# ---------------------------------------------------------------------------
new_repo
echo "more docs" >> README.md
git add README.md
if git commit -q -m "docs only" && [[ ! -s "$CARGO_LOG" ]]; then
    pass "non-Rust commit does not invoke cargo"
else
    fail "docs-only commit failed or invoked cargo"
fi

new_repo
mkdir -p src && echo "fn main() {}" > src/main.rs
git add src/main.rs
if git commit -q -m "add rust" && cargo_called_with "fmt --all -- --check"; then
    pass "staged .rs runs cargo fmt --all -- --check"
else
    fail "staged .rs did not run the formatting check"
fi
if ! grep -q '^clippy' "$CARGO_LOG"; then
    pass "clippy is not run on commit by default"
else
    fail "clippy ran on commit without SAS_HOOK_CLIPPY=1"
fi

new_repo
echo '[package]' > Cargo.toml
git add Cargo.toml
if git commit -q -m "manifest" && cargo_called_with "fmt --all -- --check"; then
    pass "staged Cargo.toml runs the formatting check"
else
    fail "staged Cargo.toml did not run the formatting check"
fi

new_repo
before="$(commit_count)"
echo "fn main(){}" > lib.rs
git add lib.rs
if ! FAKE_CARGO_FAIL="fmt" git commit -q -m "badly formatted" 2>/dev/null && [[ "$(commit_count)" == "$before" ]]; then
    pass "formatting failure blocks the commit"
else
    fail "commit went through despite a formatting failure"
fi

if SAS_SKIP_HOOKS=1 FAKE_CARGO_FAIL="fmt" git commit -q -m "skip hooks" 2>/dev/null && [[ "$(commit_count)" == "$((before + 1))" ]]; then
    pass "SAS_SKIP_HOOKS=1 bypasses the checks"
else
    fail "SAS_SKIP_HOOKS=1 did not bypass the checks"
fi

new_repo
echo "fn main(){}" > lib.rs
git add lib.rs
if SAS_HOOK_CLIPPY=1 git commit -q -m "with clippy" && cargo_called_with "clippy --workspace --all-targets -- -D warnings"; then
    pass "SAS_HOOK_CLIPPY=1 also runs clippy with -D warnings"
else
    fail "SAS_HOOK_CLIPPY=1 did not run clippy"
fi

new_repo
before="$(commit_count)"
printf '#!/usr/bin/env bash\nif then\n' > broken.sh
git add broken.sh
if ! git commit -q -m "broken script" 2>/dev/null && [[ "$(commit_count)" == "$before" ]]; then
    pass "shell syntax error blocks the commit"
else
    fail "commit went through despite a shell syntax error"
fi

new_repo
printf '#!/usr/bin/env bash\necho ok\n' > fine.sh
git add fine.sh
if git commit -q -m "valid script" && [[ ! -s "$CARGO_LOG" ]]; then
    pass "valid shell script commits without invoking cargo"
else
    fail "valid shell script was rejected or invoked cargo"
fi

# ---------------------------------------------------------------------------
echo "pre-push"
# ---------------------------------------------------------------------------
new_repo
head_sha="$(git rev-parse HEAD)"
zero_sha="0000000000000000000000000000000000000000"
push_line="refs/heads/main $head_sha refs/heads/main $zero_sha"
delete_line="(delete) $zero_sha refs/heads/old $head_sha"

if echo "$push_line" | .githooks/pre-push origin url >/dev/null 2>&1 &&
    cargo_called_with "fmt --all -- --check" &&
    cargo_called_with "clippy --workspace --all-targets -- -D warnings"; then
    pass "runs cargo fmt --check and clippy -D warnings"
else
    fail "did not run both CI gates"
fi
if ! grep -q '^test' "$CARGO_LOG"; then
    pass "tests are not run by default"
else
    fail "tests ran without SAS_HOOK_TEST=1"
fi

: > "$CARGO_LOG"
if ! echo "$push_line" | FAKE_CARGO_FAIL="clippy" .githooks/pre-push origin url >/dev/null 2>&1; then
    pass "clippy failure blocks the push"
else
    fail "push allowed despite a clippy failure"
fi

: > "$CARGO_LOG"
if ! echo "$push_line" | FAKE_CARGO_FAIL="fmt" .githooks/pre-push origin url >/dev/null 2>&1 &&
    ! grep -q '^clippy' "$CARGO_LOG"; then
    pass "formatting failure blocks the push before clippy runs"
else
    fail "formatting failure did not stop the push early"
fi

: > "$CARGO_LOG"
if echo "$push_line" | SAS_HOOK_TEST=1 .githooks/pre-push origin url >/dev/null 2>&1 &&
    cargo_called_with "test --workspace"; then
    pass "SAS_HOOK_TEST=1 also runs cargo test --workspace"
else
    fail "SAS_HOOK_TEST=1 did not run the tests"
fi

: > "$CARGO_LOG"
if echo "$delete_line" | .githooks/pre-push origin url >/dev/null 2>&1 && [[ ! -s "$CARGO_LOG" ]]; then
    pass "branch-deletion push skips the checks"
else
    fail "branch-deletion push ran cargo"
fi

: > "$CARGO_LOG"
if echo "$push_line" | SAS_SKIP_HOOKS=1 FAKE_CARGO_FAIL="fmt clippy" .githooks/pre-push origin url >/dev/null 2>&1 &&
    [[ ! -s "$CARGO_LOG" ]]; then
    pass "SAS_SKIP_HOOKS=1 bypasses the checks"
else
    fail "SAS_SKIP_HOOKS=1 did not bypass the push checks"
fi

# ---------------------------------------------------------------------------
printf '\n%d passed, %d failed\n' "$PASSED" "$FAILED"
[[ $FAILED -eq 0 ]]
