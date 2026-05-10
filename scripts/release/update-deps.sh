#!/usr/bin/env bash
# Pins every published-module go.mod (plus the capstone example) to a
# given VERSION for every cross-reference to another published
# axonops/audit module. Used by the release.yml `update-deps-pr` job
# to produce the single commit that the release PR contains.
#
# Usage:
#   scripts/release/update-deps.sh <VERSION>
#
# Reads the canonical module list from `make print-publish-modules`.
# Iterates every published module and rewrites its `require` directive
# for every OTHER published module to `@VERSION`. Stale go.sum entries
# for those paths are stripped so the next `go mod download` after the
# new tag publishes re-populates them with the correct hash. Tidy is
# intentionally NOT run — at this point in the release flow VERSION
# is not yet a tag on origin, so tidy would fail to resolve.
#
# Also updates `examples/17-capstone/go.mod` (it's not published, but
# its dependency pins move with the release).
set -euo pipefail

readonly VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
  echo "Usage: $0 <VERSION>" >&2
  exit 2
fi
if ! [[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.\-]+)?$ ]]; then
  echo "update-deps: invalid version format: $VERSION" >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

# Build the published-module path list once.
published_paths=()
while IFS='|' read -r dir module_path tag_prefix; do
  [[ -z "$dir" ]] && continue
  published_paths+=("$module_path")
done < <(make -s --no-print-directory print-publish-modules)

if (( ${#published_paths[@]} == 0 )); then
  echo "update-deps: 'make print-publish-modules' produced no output" >&2
  exit 2
fi

# Modules to rewrite: every published module + the capstone example.
# Skip the core module itself (`.`) — core has no axonops/audit
# require directives to update.
targets=()
while IFS='|' read -r dir module_path tag_prefix; do
  [[ -z "$dir" ]] && continue
  [[ "$dir" == "." ]] && continue
  targets+=("$dir")
done < <(make -s --no-print-directory print-publish-modules)
targets+=("examples/17-capstone")

# Version-pin semantics: workspace OFF so each module resolves on
# its own go.mod, GOPROXY=direct so the script doesn't depend on
# the proxy having indexed the previous release, GOFLAGS=-mod=mod
# so `go mod edit` can rewrite the require directives.
#
# The chicken-and-egg: at this point in the release flow, the
# new tag (e.g. v0.1.12) does NOT yet exist on origin — it's
# created by the `tag-all-modules` job AFTER this PR auto-merges
# (release.yml:553-...). So `go mod tidy` would fail trying to
# resolve every inter-module require@VERSION. Skip tidy and
# manually drop any stale go.sum entries for the inter-module
# axonops/audit paths; the CI job that runs on the release PR
# operates in workspace mode (`make workspace`) and resolves
# inter-module deps locally, so a missing-checksum is not an
# error there. The first downstream consumer that fetches
# v$VERSION populates a fresh entry in their own go.sum.
export GOWORK=off
export GOPROXY=direct
export GOFLAGS=-mod=mod

for target in "${targets[@]}"; do
  if [[ ! -f "$target/go.mod" ]]; then
    echo "update-deps: $target/go.mod missing — skipping"
    continue
  fi
  echo "==> $target"
  pushd "$target" >/dev/null

  for path in "${published_paths[@]}"; do
    # Anchored regex: the path is followed by a single space then `v`
    # then a digit, ensuring `audit` doesn't false-positive on
    # `audit-extra`. Comment lines are skipped because go.mod
    # comments use `//` which doesn't satisfy the leading-whitespace
    # + path constraint here.
    if grep -qE "^[[:space:]]*${path}[[:space:]]v[0-9]" go.mod; then
      go mod edit -require "${path}@${VERSION}"
      echo "  pinned $path → $VERSION"
      # Strip any existing go.sum entries for this path so they
      # don't reference the previous version's hash. The first
      # `go mod download` after the new tag publishes will re-add
      # the correct entries.
      if [[ -f go.sum ]]; then
        # Match the path at the start of the line followed by space
        # — same anchoring as above.
        sed -i "/^${path//\//\\/} /d" go.sum
      fi
    fi
  done

  popd >/dev/null
done

echo "update-deps: pinned $VERSION in ${#targets[@]} go.mod files."
