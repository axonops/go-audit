#!/usr/bin/env bash
# Copyright 2026 AxonOps Limited.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
#
# gh-graphql-commit.sh — create an App-signed commit on a branch
# via GitHub's GraphQL createCommitOnBranch mutation (#841).
#
# Replaces the legacy `git commit + git push` pair used by the
# unified release flow's update-deps-pr job. The legacy approach
# required temporarily disabling `required_signatures` on the
# branch because Apps only auto-sign via GraphQL — never via plain
# git push.
#
# Auth: caller MUST set GH_TOKEN to the App's installation token
# (mintable via actions/create-github-app-token). The token's
# installation must include `contents: write` on this repository.
# That is the same scope `git push` required.
#
# Inputs (all required):
#
#   --branch <NAME>      Branch to commit on. MUST match
#                        ^release/v[0-9]+\.[0-9]+\.x$ — the script
#                        rejects anything else (security #841).
#
#   --message <TEXT>     Commit message subject. Body is optional;
#                        if multi-line, the first line is the
#                        subject (standard git convention).
#
#   --owner <OWNER>      Repository owner (default: derive from
#                        $GITHUB_REPOSITORY in workflow context).
#
#   --repo <NAME>        Repository name (default: derive from
#                        $GITHUB_REPOSITORY).
#
#   --auto-create-branch When set, the branch will be created from
#                        the default branch's HEAD if it doesn't
#                        exist. Without this flag, the script fails
#                        if the branch is missing.
#
# Behaviour:
#
#   1. Validates --branch against the regex.
#   2. Validates GH_TOKEN is non-empty.
#   3. Enumerates working-tree changes via `git status --porcelain`.
#   4. Rejects any change outside the allowlist:
#        go.mod, go.sum
#        */go.mod, */go.sum
#        */*/go.mod, */*/go.sum
#      Anything else (a stray .env, an accidental binary, a YAML
#      change) fails the script. This is defence-in-depth against
#      a future change to update-deps.sh writing outside its
#      intended scope.
#   5. Captures the current head OID of --branch (or the repo
#      default branch if --auto-create-branch is set and the
#      branch doesn't exist).
#   6. Builds the createCommitOnBranch fileChanges input:
#        additions: base64(file content) for each added/modified
#        deletions: filename for each deleted file
#   7. Submits the mutation with expectedHeadOid = captured OID.
#   8. On STALE_DATA error (someone else pushed between fetch and
#      mutate), refetches the head OID and retries ONCE. Fails on
#      a second STALE_DATA.
#   9. Asserts the response contains a non-null commit.oid; logs
#      it to stdout for the workflow run-log audit trail.

set -euo pipefail
set +x  # defence-in-depth: ensure no caller has enabled tracing

# Cleanup: scrub GH_TOKEN from environment on exit even though the
# workflow runner will reclaim it. Belts and braces.
trap 'unset GH_TOKEN' EXIT

readonly BRANCH_REGEX='^release/v[0-9]+\.[0-9]+\.x$'

readonly ALLOWLIST=(
    'go.mod'
    'go.sum'
    '*/go.mod'
    '*/go.sum'
    '*/*/go.mod'
    '*/*/go.sum'
)

# ----------------------------------------------------------------
# CLI parsing
# ----------------------------------------------------------------

BRANCH=""
MESSAGE=""
OWNER=""
REPO=""
AUTO_CREATE_BRANCH=0

usage() {
    sed -n '7,42p' "$0" >&2
    exit 64
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --branch)              BRANCH="$2"; shift 2 ;;
        --message)             MESSAGE="$2"; shift 2 ;;
        --owner)               OWNER="$2"; shift 2 ;;
        --repo)                REPO="$2"; shift 2 ;;
        --auto-create-branch)  AUTO_CREATE_BRANCH=1; shift ;;
        -h|--help)             usage ;;
        *)
            echo "gh-graphql-commit: unknown flag: $1" >&2
            usage
            ;;
    esac
done

# ----------------------------------------------------------------
# Input validation
# ----------------------------------------------------------------

if [[ -z "$BRANCH" ]]; then
    echo "gh-graphql-commit: --branch is required" >&2
    exit 64
fi

if [[ ! "$BRANCH" =~ $BRANCH_REGEX ]]; then
    echo "gh-graphql-commit: --branch must match $BRANCH_REGEX (got: $BRANCH)" >&2
    exit 64
fi

if [[ -z "$MESSAGE" ]]; then
    echo "gh-graphql-commit: --message is required" >&2
    exit 64
fi

if [[ -z "${GH_TOKEN:-}" ]]; then
    echo "gh-graphql-commit: GH_TOKEN environment variable is required" >&2
    exit 64
fi

if [[ -z "$OWNER" || -z "$REPO" ]]; then
    if [[ -z "${GITHUB_REPOSITORY:-}" ]]; then
        echo "gh-graphql-commit: --owner and --repo are required when GITHUB_REPOSITORY is not set" >&2
        exit 64
    fi
    OWNER="${GITHUB_REPOSITORY%%/*}"
    REPO="${GITHUB_REPOSITORY##*/}"
fi

# ----------------------------------------------------------------
# Enumerate working-tree changes + allowlist guard
# ----------------------------------------------------------------

# NUL-separated to handle paths containing spaces, tabs, newlines,
# or quote characters. --untracked-files=no so we don't include
# anything stray that wasn't deliberately staged by the caller.
declare -a additions
declare -a deletions

# Read NUL-delimited records into an array. Each record is the
# raw porcelain entry: "XY path\0" — where X is index status and
# Y is working-tree status.
porcelain_raw=$(git status -z --porcelain --untracked-files=no)
if [[ -z "$porcelain_raw" ]]; then
    echo "gh-graphql-commit: no changes to commit" >&2
    exit 65
fi

allowlist_match() {
    local path="$1"
    local pattern
    for pattern in "${ALLOWLIST[@]}"; do
        # shellcheck disable=SC2053 # intentional glob match
        if [[ "$path" == $pattern ]]; then
            return 0
        fi
    done
    return 1
}

# Parse the NUL-delimited stream. Each record is "XY pathNUL"
# except renames/copies which use the form "XY new\0old\0" — but
# we reject renames anyway. We accept any combination of M, A, D
# on the staged (X) or working-tree (Y) column.
while IFS= read -r -d '' line; do
    status="${line:0:2}"
    path="${line:3}"

    # Collapse the XY pair to a single decision: any 'M', 'A', or
    # 'D' in either column maps to add or delete respectively.
    # 'R' (rename) or '?' (untracked, filtered earlier) is rejected.
    has_M=0; has_A=0; has_D=0; has_R=0
    case "${status:0:1}" in M) has_M=1 ;; A) has_A=1 ;; D) has_D=1 ;; R) has_R=1 ;; esac
    case "${status:1:1}" in M) has_M=1 ;; A) has_A=1 ;; D) has_D=1 ;; R) has_R=1 ;; esac

    if (( has_R )); then
        echo "gh-graphql-commit: refusing rename in release commit (status='$status' path='$path')" >&2
        exit 65
    fi

    if (( has_D )) && ! (( has_M || has_A )); then
        if ! allowlist_match "$path"; then
            echo "gh-graphql-commit: refusing deletion outside allowlist: $path" >&2
            exit 65
        fi
        deletions+=("$path")
    elif (( has_M || has_A )); then
        if ! allowlist_match "$path"; then
            echo "gh-graphql-commit: refusing file outside allowlist: $path" >&2
            exit 65
        fi
        additions+=("$path")
    else
        echo "gh-graphql-commit: unrecognised porcelain status '$status' for path: $path" >&2
        exit 65
    fi
done < <(printf '%s' "$porcelain_raw")

# ----------------------------------------------------------------
# Resolve expected head OID
# ----------------------------------------------------------------

resolve_head_oid() {
    local branch="$1"
    gh api "repos/$OWNER/$REPO/git/ref/heads/$branch" \
        --jq '.object.sha' 2>/dev/null || true
}

EXPECTED_HEAD_OID="$(resolve_head_oid "$BRANCH")"

if [[ -z "$EXPECTED_HEAD_OID" ]]; then
    if [[ "$AUTO_CREATE_BRANCH" -eq 1 ]]; then
        # Create the branch from the repo default branch's HEAD.
        DEFAULT_BRANCH="$(gh api "repos/$OWNER/$REPO" --jq '.default_branch')"
        DEFAULT_OID="$(gh api "repos/$OWNER/$REPO/git/ref/heads/$DEFAULT_BRANCH" --jq '.object.sha')"
        gh api "repos/$OWNER/$REPO/git/refs" \
            --method POST \
            --field ref="refs/heads/$BRANCH" \
            --field sha="$DEFAULT_OID" \
            >/dev/null
        EXPECTED_HEAD_OID="$DEFAULT_OID"
        echo "gh-graphql-commit: created branch $BRANCH from $DEFAULT_BRANCH ($DEFAULT_OID)"
    else
        echo "gh-graphql-commit: branch $BRANCH does not exist; pass --auto-create-branch to create it" >&2
        exit 66
    fi
fi

# ----------------------------------------------------------------
# Build the createCommitOnBranch payload
# ----------------------------------------------------------------

build_payload() {
    local head_oid="$1"
    local payload
    payload="$(jq -nc \
        --arg owner "$OWNER" \
        --arg repo "$REPO" \
        --arg branch "refs/heads/$BRANCH" \
        --arg head_oid "$head_oid" \
        --arg message "$MESSAGE" \
        '{
            input: {
                branch: {
                    repositoryNameWithOwner: ($owner + "/" + $repo),
                    branchName: ($branch | sub("^refs/heads/"; ""))
                },
                expectedHeadOid: $head_oid,
                message: { headline: $message },
                fileChanges: { additions: [], deletions: [] }
            }
        }')"

    local path content_b64
    for path in "${additions[@]:-}"; do
        [[ -z "$path" ]] && continue
        content_b64="$(base64 -w0 < "$path")"
        payload="$(jq -c \
            --arg p "$path" --arg c "$content_b64" \
            '.input.fileChanges.additions += [{ path: $p, contents: $c }]' \
            <<<"$payload")"
    done
    for path in "${deletions[@]:-}"; do
        [[ -z "$path" ]] && continue
        payload="$(jq -c \
            --arg p "$path" \
            '.input.fileChanges.deletions += [{ path: $p }]' \
            <<<"$payload")"
    done

    printf '%s' "$payload"
}

# ----------------------------------------------------------------
# Submit the mutation (with one STALE_DATA retry)
# ----------------------------------------------------------------

submit_mutation() {
    local payload="$1"

    # Pass query+variables together so gh handles the wire format.
    # `gh api graphql` expects the GraphQL document via -f query=...
    # and variable values via -F (raw) for top-level structured input.
    # We pre-marshalled the variables in payload's .input above.
    local query='mutation($input: CreateCommitOnBranchInput!) {
      createCommitOnBranch(input: $input) {
        commit { oid url }
      }
    }'

    local variables
    variables="$(jq -c '{ input: .input }' <<<"$payload")"

    gh api graphql \
        --raw-field query="$query" \
        --raw-field variables="$variables"
}

response="$(submit_mutation "$(build_payload "$EXPECTED_HEAD_OID")" 2>&1 || true)"

# STALE_DATA retry: the head OID we passed is no longer current
# (someone or some prior workflow run pushed to the branch). Refetch
# and retry exactly once. Use jq for typed discrimination so a
# legitimate commit message or response field containing the literal
# string "STALE_DATA" cannot false-positive.
is_stale_data() {
    jq -e '.errors[]? | select(.type == "STALE_DATA")' >/dev/null 2>&1 <<<"$1"
}

if is_stale_data "$response"; then
    echo "gh-graphql-commit: STALE_DATA on first attempt; refetching head OID and retrying once"
    EXPECTED_HEAD_OID="$(resolve_head_oid "$BRANCH")"
    if [[ -z "$EXPECTED_HEAD_OID" ]]; then
        echo "gh-graphql-commit: branch disappeared between attempts" >&2
        exit 67
    fi
    response="$(submit_mutation "$(build_payload "$EXPECTED_HEAD_OID")" 2>&1 || true)"
fi

# Surface any GraphQL "errors" array as a non-zero exit.
if jq -e '.errors // empty | length > 0' >/dev/null 2>&1 <<<"$response"; then
    echo "gh-graphql-commit: GraphQL error response:" >&2
    printf '%s\n' "$response" >&2
    exit 68
fi

# Assert the response contains a non-null commit.oid. A response
# without commit.oid means the API reported success but did not
# create the commit — a real failure mode of GraphQL mutations.
new_oid="$(jq -r '.data.createCommitOnBranch.commit.oid // empty' <<<"$response" 2>/dev/null)"
if [[ -z "$new_oid" ]]; then
    echo "gh-graphql-commit: response missing commit.oid:" >&2
    printf '%s\n' "$response" >&2
    exit 69
fi

# Audit log: print the new commit OID and URL for the workflow run.
echo "gh-graphql-commit: created commit $new_oid on branch $BRANCH"
echo "$response" | jq -r '.data.createCommitOnBranch.commit.url'
