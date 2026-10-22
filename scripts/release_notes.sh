#!/usr/bin/env bash
#
# scripts/release_notes.sh - generate Markdown release notes for a version tag.
#
# The notes combine three sources:
#   1. The matching "## [X.Y.Z]" section of CHANGELOG.md, when there is one.
#   2. Every non-merge commit between the previous release tag and <tag>,
#      grouped by Conventional Commit type (feat, fix, perf, ...). Commits
#      that are not Conventional Commits are listed under "Other Changes", so
#      nothing is silently dropped.
#   3. Optionally, the SHA-256 checksums of the release artifacts.
#
# Breaking changes (a "!" after the type or scope, or a "BREAKING CHANGE:"
# footer) are pulled out into their own section at the top.
#
# Usage:
#   scripts/release_notes.sh <tag> [options]
#
# Options:
#   --previous <tag>     Compare against this tag instead of the nearest
#                        earlier v* tag. Use "none" to include all history.
#   --checksums <file>   Append the contents of this file (for example the
#                        sha256sum output) as a "Checksums" section.
#   --repo <owner/name>  Repository for the "Full Changelog" compare link.
#                        Defaults to $GITHUB_REPOSITORY, then to the origin
#                        remote when it points at GitHub.
#   -h, --help           Show this help.
#
# <tag> may be given with or without the leading "v". If the tag does not
# exist yet, HEAD stands in for it, so the notes can be previewed before
# tagging.
#
# Output goes to stdout. Exit code: 0 on success, 2 on invalid usage.
#
set -euo pipefail

usage() {
    sed -n '3,/^set -euo/p' "${BASH_SOURCE[0]}" | sed '$d' | sed 's/^# \{0,1\}//'
}

die() {
    printf 'release_notes.sh: %s\n' "$*" >&2
    exit 2
}

TAG=""
PREVIOUS=""
CHECKSUMS=""
REPO="${GITHUB_REPOSITORY:-}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h | --help)
            usage
            exit 0
            ;;
        --previous)
            [[ $# -ge 2 ]] || die "--previous needs a value"
            PREVIOUS="$2"
            shift 2
            ;;
        --checksums)
            [[ $# -ge 2 ]] || die "--checksums needs a value"
            CHECKSUMS="$2"
            shift 2
            ;;
        --repo)
            [[ $# -ge 2 ]] || die "--repo needs a value"
            REPO="$2"
            shift 2
            ;;
        -*)
            die "unknown option: $1"
            ;;
        *)
            [[ -z "$TAG" ]] || die "unexpected extra argument: $1"
            TAG="$1"
            shift
            ;;
    esac
done

[[ -n "$TAG" ]] || die "missing <tag> (see --help)"

VERSION="${TAG#v}"
SEMVER_RE='^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$'
[[ "$VERSION" =~ $SEMVER_RE ]] || die "'$TAG' is not a semantic version tag (expected vX.Y.Z)"
TAG="v$VERSION"

if [[ -n "$CHECKSUMS" && ! -f "$CHECKSUMS" ]]; then
    die "checksums file not found: $CHECKSUMS"
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# --- Resolve the commit range ------------------------------------------------

if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
    END_REF="$TAG"
    TAG_EXISTS=1
else
    END_REF="HEAD"
    TAG_EXISTS=0
fi

if [[ -z "$PREVIOUS" ]]; then
    if [[ "$TAG_EXISTS" -eq 1 ]]; then
        # Nearest release tag reachable from the commit before the tag.
        PREVIOUS="$(git describe --tags --abbrev=0 --match 'v[0-9]*' "${END_REF}^" 2>/dev/null || true)"
    else
        PREVIOUS="$(git describe --tags --abbrev=0 --match 'v[0-9]*' "$END_REF" 2>/dev/null || true)"
    fi
elif [[ "$PREVIOUS" == "none" ]]; then
    PREVIOUS=""
else
    git rev-parse -q --verify "refs/tags/$PREVIOUS" >/dev/null ||
        die "previous tag not found: $PREVIOUS"
fi

if [[ -n "$PREVIOUS" ]]; then
    RANGE="$PREVIOUS..$END_REF"
else
    RANGE="$END_REF"
fi

# --- Classify commits --------------------------------------------------------

# Associative arrays need bash 4+, which every supported runner provides
# (GitHub Actions, Git for Windows, current Linux distributions).
declare -A BUCKET=()
declare -A TITLE=(
    [features]="Features"
    [fixes]="Bug Fixes"
    [perf]="Performance"
    [docs]="Documentation"
    [refactor]="Refactoring"
    [tests]="Tests"
    [build]="Build and CI"
    [chore]="Maintenance"
    [other]="Other Changes"
)
ORDER=(features fixes perf docs refactor tests build chore other)
BREAKING=""

bucket_for_type() {
    case "$1" in
        feat) echo features ;;
        fix) echo fixes ;;
        perf) echo perf ;;
        docs) echo docs ;;
        refactor) echo refactor ;;
        test | tests) echo tests ;;
        build | ci) echo build ;;
        chore | style | revert) echo chore ;;
        *) echo other ;;
    esac
}

CONVENTIONAL_RE='^([a-zA-Z]+)(\(([^)]*)\))?(!)?:[[:space:]]+(.+)$'
RS=$'\x1e'
US=$'\x1f'

while IFS= read -r -d "$RS" record; do
    # git log separates records with a trailing newline; drop it.
    record="${record#$'\n'}"
    [[ -n "$record" ]] || continue

    hash="${record%%"$US"*}"
    rest="${record#*"$US"}"
    subject="${rest%%"$US"*}"
    body="${rest#*"$US"}"

    # Release bookkeeping commits are not release content.
    if [[ "$subject" =~ ^chore\(release\) ]]; then
        continue
    fi

    breaking_note=""
    while IFS= read -r line; do
        if [[ "$line" =~ ^BREAKING( |-)CHANGE:[[:space:]]*(.*)$ ]]; then
            breaking_note="${BASH_REMATCH[2]}"
            break
        fi
    done <<<"$body"

    bang=""
    if [[ "$subject" =~ $CONVENTIONAL_RE ]]; then
        ctype="$(printf '%s' "${BASH_REMATCH[1]}" | tr '[:upper:]' '[:lower:]')"
        scope="${BASH_REMATCH[3]}"
        bang="${BASH_REMATCH[4]}"
        description="${BASH_REMATCH[5]}"
        bucket="$(bucket_for_type "$ctype")"
        if [[ -n "$scope" ]]; then
            entry="- **${scope}:** ${description} (${hash})"
        else
            entry="- ${description} (${hash})"
        fi
    else
        bucket="other"
        entry="- ${subject} (${hash})"
    fi

    if [[ -n "$bang" || -n "$breaking_note" ]]; then
        if [[ -n "$breaking_note" ]]; then
            BREAKING+="${entry}"$'\n'"  - ${breaking_note}"$'\n'
        else
            BREAKING+="${entry}"$'\n'
        fi
    else
        BUCKET[$bucket]+="${entry}"$'\n'
    fi
done < <(git log --no-merges --format="%h${US}%s${US}%b${RS}" "$RANGE")

# --- Changelog section -------------------------------------------------------

CHANGELOG_SECTION=""
if [[ -f CHANGELOG.md ]]; then
    CHANGELOG_SECTION="$(
        tr -d '\r' <CHANGELOG.md | awk -v header="## [${VERSION}]" '
            index($0, header) == 1 { capture = 1; next }
            capture && /^## \[/ { exit }
            capture { print }
        '
    )"
    # Drop leading blank lines (command substitution already trims trailing ones).
    CHANGELOG_SECTION="$(printf '%s\n' "$CHANGELOG_SECTION" | sed -e '/./,$!d')"
fi

# --- Compare link ------------------------------------------------------------

if [[ -z "$REPO" ]]; then
    origin="$(git remote get-url origin 2>/dev/null || true)"
    if [[ "$origin" =~ github\.com[:/]([^/]+/[^/.]+)(\.git)?/?$ ]]; then
        REPO="${BASH_REMATCH[1]}"
    fi
fi

# --- Render ------------------------------------------------------------------

printf '# SAS %s\n\n' "$TAG"

if [[ -n "$CHANGELOG_SECTION" ]]; then
    printf '## Highlights\n\n%s\n\n' "$CHANGELOG_SECTION"
fi

if [[ -n "$BREAKING" ]]; then
    printf '## Breaking Changes\n\n%s\n' "$BREAKING"
fi

any=0
[[ -n "$BREAKING" ]] && any=1
for key in "${ORDER[@]}"; do
    if [[ -n "${BUCKET[$key]:-}" ]]; then
        any=1
        printf '## %s\n\n%s\n' "${TITLE[$key]}" "${BUCKET[$key]}"
    fi
done

if [[ "$any" -eq 0 ]]; then
    printf '## Changes\n\nNo changes were recorded for this release.\n\n'
fi

if [[ -n "$CHECKSUMS" ]]; then
    printf '## Checksums\n\nSHA-256 of the release artifacts:\n\n```\n'
    tr -d '\r' <"$CHECKSUMS"
    printf '```\n\n'
fi

if [[ -n "$REPO" && -n "$PREVIOUS" ]]; then
    printf '**Full Changelog**: https://github.com/%s/compare/%s...%s\n' "$REPO" "$PREVIOUS" "$TAG"
fi
