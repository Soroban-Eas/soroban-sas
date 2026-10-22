#!/usr/bin/env bash
#
# scripts/test_issue_templates.sh — structural tests for .github/ISSUE_TEMPLATE/.
#
# GitHub silently falls back to a blank issue when an issue form is malformed,
# so a broken template would go unnoticed until a contributor reported it.
# These checks validate the feature request form and the chooser config with
# plain grep/sed (no YAML dependency), and then prove the validator itself
# works by feeding it deliberately broken copies of the form.
#
# Usage:
#   ./scripts/test_issue_templates.sh
#
# Exit code: 0 if every case passes, 1 otherwise.
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEMPLATE_DIR="$REPO_ROOT/.github/ISSUE_TEMPLATE"
FORM="$TEMPLATE_DIR/feature_request.yml"
CONFIG="$TEMPLATE_DIR/config.yml"
TAB="$(printf '\t')"

PASSED=0
FAILED=0
pass() { printf '  ok   %s\n' "$*"; PASSED=$((PASSED + 1)); }
fail() { printf '  FAIL %s\n' "$*" >&2; FAILED=$((FAILED + 1)); }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# validate_form FILE: prints one line per problem to stderr and returns
# non-zero if the issue form is malformed.
validate_form() {
    local file="$1" errs=0 key t id types ids non_md id_count label_count dups
    err() { printf '       %s\n' "$*" >&2; errs=$((errs + 1)); }

    if [[ ! -f "$file" ]]; then
        err "file not found: $file"
        return 1
    fi

    # Work on an LF copy so a CRLF checkout (core.autocrlf on Windows) is
    # judged on its content, not its line endings.
    tr -d '\r' < "$file" > "$WORK/normalized.yml"
    file="$WORK/normalized.yml"

    for key in name description title labels body; do
        grep -Eq "^${key}:" "$file" || err "missing top-level key '$key'"
    done
    grep -Eq '^title: "[a-z]+: *"$' "$file" \
        || err "title must be a conventional-commit prefix such as \"feat: \""
    grep -q "$TAB" "$file" && err "contains a tab character (YAML forbids tabs)"

    types="$(grep -E '^  - type: ' "$file" | sed -E 's/^  - type: *//; s/\r$//' || true)"
    [[ -n "$types" ]] || err "body has no elements"
    while IFS= read -r t; do
        [[ -n "$t" ]] || continue
        case "$t" in
            markdown | textarea | input | dropdown | checkboxes) ;;
            *) err "unknown element type '$t'" ;;
        esac
    done <<< "$types"

    ids="$(grep -E '^    id: ' "$file" | sed -E 's/^    id: *//; s/\r$//' || true)"
    while IFS= read -r id; do
        [[ -n "$id" ]] || continue
        [[ "$id" =~ ^[A-Za-z0-9_-]+$ ]] || err "invalid id '$id'"
    done <<< "$ids"
    dups="$(printf '%s\n' "$ids" | sort | uniq -d)"
    [[ -z "$dups" ]] || err "duplicate ids: $(printf '%s' "$dups" | tr '\n' ' ')"

    # Every input element needs an id and a label; markdown needs neither.
    non_md="$(printf '%s\n' "$types" | grep -vc -E '^(markdown)?$' || true)"
    id_count="$(printf '%s\n' "$ids" | grep -c . || true)"
    label_count="$(grep -Ec '^      label: ' "$file" || true)"
    [[ "$non_md" == "$id_count" ]] || err "$non_md input elements but $id_count ids"
    [[ "$non_md" == "$label_count" ]] || err "$non_md input elements but $label_count labels"

    # The fields that make a request actionable must exist and be mandatory.
    for id in problem proposal; do
        grep -Eq "^    id: ${id}\$" "$file" || err "missing required field id '$id'"
    done
    grep -Eq '^    validations:' "$file" || err "no field declares validations"
    grep -Eq '^      required: true' "$file" || err "no field is marked required"

    grep -q 'SECURITY.md' "$file" || err "intro must point security reports to SECURITY.md"

    return $((errs > 0))
}

echo "feature_request.yml"
if validate_form "$FORM"; then
    pass "form passes every structural check"
else
    fail "form is malformed (see problems above)"
fi

echo "validator rejects broken forms"
expect_rejected() {
    local label="$1" sed_expr="$2" broken="$WORK/broken.yml"
    sed -E "$sed_expr" "$FORM" > "$broken"
    if validate_form "$broken" > /dev/null 2>&1; then
        fail "$label was accepted"
    else
        pass "$label is rejected"
    fi
}
expect_rejected "missing body key" 's/^body:/bodies:/'
expect_rejected "missing title" 's/^title:.*/title_removed: x/'
expect_rejected "non-conventional title" 's/^title: .*/title: "Feature"/'
expect_rejected "tab indentation" "s/^  - type: dropdown/${TAB}- type: dropdown/"
expect_rejected "unknown element type" '0,/^  - type: textarea/s//  - type: textfield/'
expect_rejected "duplicate id" 's/^    id: proposal$/    id: problem/'
expect_rejected "missing required field id" 's/^    id: proposal$/    id: idea/'
expect_rejected "no required fields" 's/required: true/required: false/'
expect_rejected "missing security pointer" 's/SECURITY\.md/the policy/g'
if validate_form "$WORK/does-not-exist.yml" > /dev/null 2>&1; then
    fail "missing file was accepted"
else
    pass "missing file is rejected"
fi

echo "config.yml"
if [[ -f "$CONFIG" ]]; then
    pass "chooser config exists"
    tr -d '\r' < "$CONFIG" > "$WORK/config.yml"
    CONFIG="$WORK/config.yml"
    grep -Eq '^blank_issues_enabled: (true|false)$' "$CONFIG" \
        && pass "blank_issues_enabled is an explicit boolean" \
        || fail "blank_issues_enabled must be true or false"
    grep -Eq '^contact_links:' "$CONFIG" \
        && pass "contact_links is declared" \
        || fail "contact_links is missing"
    if grep -E '^    url: ' "$CONFIG" | grep -qv 'url: https://'; then
        fail "every contact link must use https"
    else
        pass "every contact link uses https"
    fi
    grep -q 'security/policy' "$CONFIG" \
        && pass "security reports are routed away from public issues" \
        || fail "no security contact link"
    grep -q "$TAB" "$CONFIG" \
        && fail "config.yml contains a tab character" \
        || pass "config.yml has no tab characters"
else
    fail "config.yml is missing"
fi

printf '\n%d passed, %d failed\n' "$PASSED" "$FAILED"
[[ "$FAILED" -eq 0 ]]
