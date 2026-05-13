#!/usr/bin/env bash
# Creates and pushes annotated tags for every published module at a
# given commit SHA. Idempotent: a tag that already exists AT THE
# SAME SHA is skipped silently; a tag that exists at a different SHA
# aborts with a hard failure (a contamination needing human attention).
#
# Usage:
#   scripts/release/tag-all.sh <VERSION> <SHA>
#
# Reads the canonical module list from `make print-publish-modules`.
# Pushes in stable alphabetical-by-prefix order so partial-failure
# diagnostics are deterministic.
#
# Partial-push behaviour: tags are pushed one at a time. A network
# failure mid-loop leaves a partial push set on origin — already-pushed
# tags are NOT rolled back (they cannot safely be; deletion does not
# unpublish from proxy.golang.org). On any failure the script emits a
# copy-paste recovery script to $GITHUB_STEP_SUMMARY (when set)
# listing the missing tags so the operator can finish the push from a
# clean checkout.
set -euo pipefail

readonly VERSION="${1:-}"
readonly SHA="${2:-}"

if [[ -z "$VERSION" || -z "$SHA" ]]; then
  echo "Usage: $0 <VERSION> <SHA>" >&2
  exit 2
fi
if ! [[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.\-]+)?$ ]]; then
  echo "tag-all: invalid version format: $VERSION" >&2
  exit 2
fi
if ! git cat-file -e "${SHA}^{commit}" 2>/dev/null; then
  echo "tag-all: SHA $SHA is not a known commit" >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# Up-to-date local refs so existing-tag detection is accurate.
git fetch --tags --quiet origin

modules="$(cd "$repo_root" && make -s --no-print-directory print-publish-modules | sort -t'|' -k3,3)"
if [[ -z "$modules" ]]; then
  echo "tag-all: 'make print-publish-modules' produced no output" >&2
  exit 2
fi

# Pre-flight: same conflict-check as the workflow's preflight job, in
# idempotent mode (existing tags at the target SHA are fine).
"$repo_root/scripts/release/check-tag-conflicts.sh" "$VERSION" "$SHA"

failed=()
remaining=()
skipped=()

while IFS='|' read -r dir module_path tag_prefix; do
  [[ -z "$dir" ]] && continue
  tag="${tag_prefix}${VERSION}"

  if git rev-parse --verify --quiet "refs/tags/$tag" >/dev/null; then
    existing_sha="$(git rev-list -n1 "$tag")"
    if [[ "$existing_sha" == "$SHA" ]]; then
      echo "tag-all: $tag already at $SHA — skipping (idempotent no-op)"
      skipped+=("$tag")
      continue
    fi
    echo "tag-all: $tag exists at $existing_sha but expected $SHA — ABORT" >&2
    failed+=("$tag")
    break
  fi

  remaining+=("$tag")
done <<<"$modules"

# Bail out early if the conflict pre-check found a SHA mismatch.
if (( ${#failed[@]} > 0 )); then
  exit 1
fi

# Create each tag via gh-graphql-tag.sh (#841): one REST POST to
# create the annotated tag object, then one POST to point
# refs/tags/<tag> at it. The helper is App-signed end-to-end, so
# required_signatures stays ON during a release. Failures are
# collected per-tag; operators see the full picture instead of
# fail-fast.
pushed=()
for tag in "${remaining[@]}"; do
  if "$repo_root/scripts/release/gh-graphql-tag.sh" \
       --tag "$tag" \
       --sha "$SHA" \
       --message "Release $tag"; then
    pushed+=("$tag")
    echo "tag-all: created and pushed $tag"
  else
    echo "tag-all: failed to create $tag via gh-graphql-tag.sh" >&2
    failed+=("$tag")
  fi
done

if (( ${#failed[@]} > 0 )); then
  echo "" >&2
  echo "tag-all: ${#failed[@]} tag(s) failed: ${failed[*]}" >&2
  echo "DO NOT delete already-pushed tags." >&2
  if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    {
      echo '## Tag-all partial failure'
      echo
      echo "Pushed (${#pushed[@]}):"
      for t in "${pushed[@]}"; do echo "- \`$t\` @ \`$SHA\`"; done
      echo
      echo "Failed (${#failed[@]}):"
      for t in "${failed[@]}"; do echo "- \`$t\`"; done
      echo
      echo '### Recovery'
      echo 'After investigating the cause, push the missing tags from a clean checkout at the same SHA:'
      echo
      echo '```bash'
      echo "git fetch origin"
      for t in "${failed[@]}"; do
        echo "git tag -a \"$t\" -m \"Release $t\" \"$SHA\""
        echo "git push origin \"$t\""
      done
      echo '```'
    } >> "$GITHUB_STEP_SUMMARY"
  fi
  exit 1
fi

echo "tag-all: ${#pushed[@]} pushed, ${#skipped[@]} idempotent skips."
