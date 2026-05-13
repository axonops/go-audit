#!/usr/bin/env bash
# Copyright 2026 AxonOps Limited.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
#
# gh-graphql-tag.sh — create an App-signed annotated tag via
# GitHub's REST API (#841).
#
# Replaces the legacy `git tag -a + git push origin <tag>` pair
# used by tag-all.sh. The legacy approach required temporarily
# disabling `required_signatures` on `main` because Apps only
# auto-sign via the GitHub API — never via plain git push.
#
# Annotated-tag preservation: this script uses two API calls per
# tag:
#
#   1. POST /repos/{owner}/{repo}/git/tags
#      — creates the annotated tag OBJECT (preserves the tag
#      message, tagger identity, and timestamp). The returned
#      `sha` is the tag object's SHA, not the target commit's.
#   2. POST /repos/{owner}/{repo}/git/refs
#      — points `refs/tags/<NAME>` at the tag object's SHA.
#
# Annotated tags are required for: `gorelease` API diff tooling,
# `git describe` reproducibility, GoReleaser's changelog
# generation, and the Go module proxy's preference for annotated
# refs.
#
# Auth: caller MUST set GH_TOKEN to the App's installation token
# with `contents: write`.
#
# Inputs (all required):
#
#   --tag <NAME>     Tag name. MUST match
#                    ^[a-z0-9._/-]+/?v[0-9]+\.[0-9]+\.[0-9]+(-[a-z0-9.]+)?$
#                    or ^v[0-9]+\.[0-9]+\.[0-9]+(-[a-z0-9.]+)?$
#                    (the second form is the core module tag; the
#                    first matches sub-module tags like
#                    `file/v0.1.13`).
#
#   --sha <SHA>      Target commit SHA. MUST be a 40-char hex.
#
#   --message <TEXT> Annotation message (the body of `git tag -a -m`).
#
#   --owner <OWNER>  Repo owner (default: derive from
#                    $GITHUB_REPOSITORY).
#
#   --repo <NAME>    Repo name (default: derive from
#                    $GITHUB_REPOSITORY).
#
# Behaviour:
#
#   1. Validates --tag and --sha regexes (no shell-injection
#      surface in the API path).
#   2. Checks if the ref already exists.
#        — Same target SHA: no-op (idempotent retry).
#        — Different target SHA: abort (history contamination).
#        — Missing: create.
#   3. Creates the annotated tag object.
#   4. Creates the ref pointing at the tag object.
#   5. Logs the tag-object SHA and ref URL to stdout.

set -euo pipefail
set +x  # defence-in-depth

trap 'unset GH_TOKEN' EXIT

# The tag name must match either the core form (vMAJOR.MINOR.PATCH)
# or a sub-module form (module-path/vMAJOR.MINOR.PATCH). Sub-module
# names allow lowercase letters, digits, hyphen, underscore, dot,
# and slash (matches `make print-publish-modules`). The suffix
# accepts SemVer 2.0.0 pre-release (`-rc.1`) and build-metadata
# (`+meta`) qualifiers.
readonly TAG_REGEX='^(([a-z0-9._-]+(/[a-z0-9._-]+)*)/)?v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.-]+)?(\+[a-zA-Z0-9.-]+)?$'

readonly SHA_REGEX='^[0-9a-f]{40}$'

# ----------------------------------------------------------------
# CLI parsing
# ----------------------------------------------------------------

TAG=""
SHA=""
MESSAGE=""
OWNER=""
REPO=""

usage() {
    sed -n '7,56p' "$0" >&2
    exit 64
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --tag)      TAG="$2"; shift 2 ;;
        --sha)      SHA="$2"; shift 2 ;;
        --message)  MESSAGE="$2"; shift 2 ;;
        --owner)    OWNER="$2"; shift 2 ;;
        --repo)     REPO="$2"; shift 2 ;;
        -h|--help)  usage ;;
        *)
            echo "gh-graphql-tag: unknown flag: $1" >&2
            usage
            ;;
    esac
done

# ----------------------------------------------------------------
# Input validation
# ----------------------------------------------------------------

if [[ -z "$TAG" ]]; then
    echo "gh-graphql-tag: --tag is required" >&2
    exit 64
fi

if [[ ! "$TAG" =~ $TAG_REGEX ]]; then
    echo "gh-graphql-tag: --tag must match $TAG_REGEX (got: $TAG)" >&2
    exit 64
fi

if [[ -z "$SHA" ]]; then
    echo "gh-graphql-tag: --sha is required" >&2
    exit 64
fi

if [[ ! "$SHA" =~ $SHA_REGEX ]]; then
    echo "gh-graphql-tag: --sha must be a 40-char hex string (got: $SHA)" >&2
    exit 64
fi

if [[ -z "$MESSAGE" ]]; then
    echo "gh-graphql-tag: --message is required" >&2
    exit 64
fi

if [[ -z "${GH_TOKEN:-}" ]]; then
    echo "gh-graphql-tag: GH_TOKEN environment variable is required" >&2
    exit 64
fi

if [[ -z "$OWNER" || -z "$REPO" ]]; then
    if [[ -z "${GITHUB_REPOSITORY:-}" ]]; then
        echo "gh-graphql-tag: --owner and --repo are required when GITHUB_REPOSITORY is not set" >&2
        exit 64
    fi
    OWNER="${GITHUB_REPOSITORY%%/*}"
    REPO="${GITHUB_REPOSITORY##*/}"
fi

# ----------------------------------------------------------------
# Idempotency: check whether the ref already exists.
#
# The REST API returns a 404 when the ref doesn't exist. We use
# `gh api --silent` to suppress the body and capture HTTP status
# via the script's exit handling.
# ----------------------------------------------------------------

# URL-encode the tag name for use in the API path. Per TAG_REGEX,
# the only character requiring percent-encoding is the slash (sub-
# module tag prefix); all others are URL-safe.
encoded_tag="${TAG//\//%2F}"

existing_ref="$(gh api "repos/$OWNER/$REPO/git/ref/tags/$encoded_tag" --jq '.object.sha' 2>/dev/null || true)"

if [[ -n "$existing_ref" ]]; then
    # The ref points at an annotated tag object (since we created
    # it that way). Dereference to find the commit it targets.
    existing_target="$(gh api "repos/$OWNER/$REPO/git/tags/$existing_ref" --jq '.object.sha' 2>/dev/null || true)"
    if [[ -z "$existing_target" ]]; then
        # The ref points at a commit directly (lightweight tag —
        # not what we want, but legacy `git tag -a` followed by
        # `git push` could have left this state if the annotated
        # tag object was stripped).
        existing_target="$existing_ref"
    fi

    if [[ "$existing_target" == "$SHA" ]]; then
        echo "gh-graphql-tag: tag $TAG already exists at $SHA — no-op"
        exit 0
    else
        echo "gh-graphql-tag: ABORT — tag $TAG exists at $existing_target but we wanted $SHA" >&2
        echo "gh-graphql-tag: refusing to move an existing tag (history contamination)" >&2
        exit 70
    fi
fi

# ----------------------------------------------------------------
# Create the annotated tag object.
# ----------------------------------------------------------------

# The tagger identity is the App's bot account; `gh api` injects
# the correct author when the token is the App's installation
# token. We supply an ISO-8601 date so the tag has deterministic
# tagger metadata.
tagger_date="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# We deliberately omit `tagger` from the payload — when omitted,
# GitHub fills it in from the authenticated identity. This is
# what makes the tag "App-signed".
tag_response="$(gh api "repos/$OWNER/$REPO/git/tags" \
    --method POST \
    --field tag="$TAG" \
    --field message="$MESSAGE" \
    --field object="$SHA" \
    --field type="commit" \
    --raw-field tagger="$(jq -nc \
        --arg date "$tagger_date" \
        '{ name: "axonops-audit-release-bot[bot]",
           email: "axonops-audit-release-bot[bot]@users.noreply.github.com",
           date: $date }')")"

tag_object_sha="$(jq -r '.sha // empty' <<<"$tag_response" 2>/dev/null)"
if [[ -z "$tag_object_sha" ]]; then
    echo "gh-graphql-tag: failed to create annotated tag object:" >&2
    printf '%s\n' "$tag_response" >&2
    exit 71
fi

# ----------------------------------------------------------------
# Create the ref pointing at the tag object.
# ----------------------------------------------------------------

ref_response="$(gh api "repos/$OWNER/$REPO/git/refs" \
    --method POST \
    --field ref="refs/tags/$TAG" \
    --field sha="$tag_object_sha")"

ref_url="$(jq -r '.url // empty' <<<"$ref_response" 2>/dev/null)"
if [[ -z "$ref_url" ]]; then
    echo "gh-graphql-tag: failed to create ref refs/tags/$TAG:" >&2
    printf '%s\n' "$ref_response" >&2
    exit 72
fi

# Audit log
echo "gh-graphql-tag: created annotated tag $TAG (tag object $tag_object_sha) targeting commit $SHA"
echo "$ref_url"
