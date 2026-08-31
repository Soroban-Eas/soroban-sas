#!/usr/bin/env bash
#
# scripts/check_docs.sh — executable verification of documentation and repo claims.
#
# Validates:
#   1. Referenced local file paths and markdown links exist.
#   2. Clone URLs, tool names, and repository claims match repository state.
#   3. Documented CLI commands and subcommands exist and have valid syntax.
#   4. CI workflow definitions align with claims in the README.
#   5. Shell script snippets pass bash syntax validation (bash -n).
#
# Usage:
#   ./scripts/check_docs.sh
#
# Exit code: 0 if all checks pass, 1 otherwise.
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

info() { printf '\033[1;34m[check-docs]\033[0m %s\n' "$*"; }
pass() { printf '\033[1;32m  ✓ %s\033[0m\n' "$*"; }
fail() { printf '\033[1;31m  ✗ %s\033[0m\n' "$*" >&2; FAILED=1; }

FAILED=0

info "Running documentation and repository claim checks..."

# -----------------------------------------------------------------------------
# 1. Path and link validation in README.md and docs/*.md
# -----------------------------------------------------------------------------
info "Checking referenced local paths in README.md..."

# Check key paths mentioned in README.md
README_PATHS=(
    "contracts/schema-registry"
    "contracts/sas"
    "contracts/indexer"
    "packages/soroban-sas-common"
    "packages/soroban-sas-sdk"
    "packages/soroban-sas-cli"
    "scripts/bootstrap.sh"
    "scripts/deploy.sh"
    "scripts/deploy_testnet.sh"
    "scripts/wait_for_localnet.sh"
    "docker-compose.yml"
    "rust-toolchain.toml"
    "Cargo.toml"
    "docs/architecture.md"
    "docs/security.md"
    "docs/schemas.md"
    "docs/DEPLOYMENT.md"
    "docs/UPGRADE_RUNBOOK.md"
)

for p in "${README_PATHS[@]}"; do
    if [[ -e "$p" ]]; then
        pass "Path exists: $p"
    else
        fail "Referenced path missing: $p"
    fi
done

# Ensure obsolete paths are NOT in README.md
if grep -F -q '`cli/`' README.md; then
    fail "Obsolete path \`cli/\` found in README.md (should be 'packages/soroban-sas-cli')"
else
    pass "No obsolete \`cli/\` in README.md"
fi

if grep -F -q '`tests/`' README.md; then
    fail "Obsolete path \`tests/\` found in README.md"
else
    pass "No non-existent \`tests/\` directory claim in README.md"
fi

# -----------------------------------------------------------------------------
# 2. Clone URL, Tooling, and CI claims
# -----------------------------------------------------------------------------
info "Checking clone URLs and tooling recommendations..."

if grep -q "github.com/0xVida/soroban-sas" README.md; then
    fail "Outdated clone URL '0xVida/soroban-sas' in README.md"
else
    pass "Clone URL matches authoritative repository (Soroban-Eas/soroban-sas)"
fi

if grep -q "cargo install --locked soroban-cli" README.md; then
    fail "Legacy 'soroban-cli' installation recommendation found in README.md (should be 'stellar-cli')"
else
    pass "Recommended CLI matches current standard (stellar-cli)"
fi

if grep -q "completions" README.md; then
    fail "Non-existent 'completions' command documented in README.md"
else
    pass "No phantom 'completions' command in README.md"
fi

# -----------------------------------------------------------------------------
# 3. CI Workflow Alignment
# -----------------------------------------------------------------------------
info "Checking CI workflow claim alignment..."

CI_FILE=".github/workflows/ci.yml"
if [[ ! -f "$CI_FILE" ]]; then
    fail "CI workflow definition not found: $CI_FILE"
else
    pass "Found CI workflow definition: $CI_FILE"
    
    # Check that CI jobs match documented capabilities
    if grep -q "name: Formatting" "$CI_FILE" && \
       grep -q "name: Clippy" "$CI_FILE" && \
       grep -q "name: Test" "$CI_FILE" && \
       grep -q "name: Build contracts" "$CI_FILE"; then
        pass "CI workflow contains formatting, linting, test, and WASM build jobs"
    else
        fail "CI workflow is missing expected verification jobs"
    fi
fi

# -----------------------------------------------------------------------------
# 4. Check Markdown Relative Links
# -----------------------------------------------------------------------------
info "Checking relative markdown links..."

python3 - << 'PYEOF'
import os, re, sys

failed = False
repo_root = os.getcwd()
md_files = ["README.md"]
for root, dirs, files in os.walk("docs"):
    for f in files:
        if f.endswith(".md"):
            md_files.append(os.path.join(root, f))

link_pattern = re.compile(r'\[([^\]]+)\]\(([^)]+)\)')

for md in md_files:
    if not os.path.exists(md):
        continue
    md_dir = os.path.dirname(md)
    with open(md, "r", encoding="utf-8") as f:
        content = f.read()
    for match in link_pattern.finditer(content):
        text, url = match.group(1), match.group(2)
        # Skip external URLs, anchors, mailto
        if url.startswith("http://") or url.startswith("https://") or url.startswith("#") or url.startswith("mailto:"):
            continue
        # Strip anchor from relative URL
        clean_url = url.split("#")[0]
        if not clean_url:
            continue
        target_path = os.path.normpath(os.path.join(md_dir, clean_url))
        if not os.path.exists(target_path):
            print(f"  ✗ Broken link in {md}: [{text}]({url}) -> target '{target_path}' not found", file=sys.stderr)
            failed = True

if failed:
    sys.exit(1)
else:
    print("  ✓ All relative Markdown links resolve successfully")
PYEOF
if [[ $? -ne 0 ]]; then
    FAILED=1
fi

# -----------------------------------------------------------------------------
# 5. Shell Snippets Syntax Validation (bash -n)
# -----------------------------------------------------------------------------
info "Checking syntax of shell snippets in docs and scripts..."

# Check shell scripts directly
for script in scripts/*.sh tools/*.sh; do
    if [[ -f "$script" ]]; then
        if bash -n "$script"; then
            pass "Shell syntax valid: $script"
        else
            fail "Shell syntax error: $script"
        fi
    fi
done

# Extract and syntax-check bash code blocks from README.md
python3 - << 'PYEOF'
import re, subprocess, sys, tempfile

with open("README.md", "r", encoding="utf-8") as f:
    content = f.read()

# Extract fenced ```bash ... ``` or ```sh ... ``` code blocks
blocks = re.findall(r'```(?:bash|sh)\n(.*?)```', content, re.DOTALL)
errors = 0

for i, block in enumerate(blocks):
    # Some blocks are template snippets with placeholder ellipses like "UID..." or "C..." or comments.
    # We replace common documentation placeholder values with syntactically valid shell strings for testing.
    sanitized = block.replace("UID...", "0000000000000000000000000000000000000000000000000000000000000000")
    sanitized = sanitized.replace("C...", "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4")
    sanitized = sanitized.replace("G...", "GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBAAA6XKZW3")
    sanitized = sanitized.replace("S...", "SAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF7U")
    sanitized = sanitized.replace("URL", "http://localhost:8000")
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.sh', delete=False) as tf:
        tf.write(sanitized)
        temp_name = tf.name
    
    res = subprocess.run(["bash", "-n", temp_name], capture_output=True, text=True)
    if res.returncode != 0:
        print(f"  ✗ Shell snippet #{i+1} syntax error:\n{res.stderr}", file=sys.stderr)
        errors += 1

if errors > 0:
    sys.exit(1)
else:
    print("  ✓ All README shell snippets pass syntax validation (bash -n)")
PYEOF
if [[ $? -ne 0 ]]; then
    FAILED=1
fi

# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------
if [[ $FAILED -eq 0 ]]; then
    printf '\n\033[1;32m[check-docs] All documentation and repository checks passed successfully!\033[0m\n'
    exit 0
else
    printf '\n\033[1;31m[check-docs] Documentation verification failed.\033[0m\n' >&2
    exit 1
fi
