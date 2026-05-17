#!/usr/bin/env bash
# Copyright 2026 AxonOps Limited.
# SPDX-License-Identifier: Apache-2.0
#
# bump-example-deps.sh — bump every github.com/axonops/audit* require
# line in an example's go.mod to a given VERSION via `go get`. Used by
# .github/workflows/release-examples-verify.yml and by the local
# `make verify-examples-published` target to simulate a consumer
# doing `go get` after a release.
#
# Usage:
#   scripts/release/bump-example-deps.sh <EXAMPLE_DIR> <VERSION>
#
# Example:
#   scripts/release/bump-example-deps.sh /tmp/verify-09-multi-output v0.1.13
#
# Notes:
#   * Uses `go get <mod>@<version>` (not `go mod edit -require`) so the
#     proxy is actually hit and go.sum is updated — exactly what a real
#     consumer's first `go get` does.
#   * Forces GOWORK=off so a stray go.work outside the target dir does
#     NOT shadow the published versions with local replacements.
#   * Validates VERSION format to protect against injection via the
#     workflow's workflow_dispatch input.
set -euo pipefail

readonly EXAMPLE_DIR="${1:-}"
readonly VERSION="${2:-}"

if [[ -z "$EXAMPLE_DIR" || -z "$VERSION" ]]; then
  echo "Usage: $0 <EXAMPLE_DIR> <VERSION>" >&2
  exit 2
fi
if [[ ! -d "$EXAMPLE_DIR" ]]; then
  echo "bump-example-deps: not a directory: $EXAMPLE_DIR" >&2
  exit 2
fi
if [[ ! -f "$EXAMPLE_DIR/go.mod" ]]; then
  echo "bump-example-deps: no go.mod in: $EXAMPLE_DIR" >&2
  exit 2
fi
if ! [[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.\-]+)?$ ]]; then
  echo "bump-example-deps: invalid version format: $VERSION" >&2
  exit 2
fi

# Collect every audit-module require line. The regex requires a
# version column on the same line — this skips comment lines like
# "// github.com/axonops/audit/foo: deprecated" that would otherwise
# match the prefix pattern.
mapfile -t modules < <(
  awk '/^[[:space:]]*github\.com\/axonops\/audit[a-z0-9\/_-]*[[:space:]]+v[0-9]/ {print $1}' \
    "$EXAMPLE_DIR/go.mod" | sort -u
)

if [[ ${#modules[@]} -eq 0 ]]; then
  echo "bump-example-deps: no github.com/axonops/audit requires in $EXAMPLE_DIR/go.mod" >&2
  exit 0
fi

echo "bump-example-deps: bumping ${#modules[@]} modules in $EXAMPLE_DIR to $VERSION"
cd "$EXAMPLE_DIR"

# Disable workspace so the bumped versions are honoured, not shadowed
# by any go.work in a parent directory.
export GOWORK=off
# Force fresh proxy fetch on every invocation — verifies the proxy
# actually has the version, not just the local module cache.
export GOFLAGS="-mod=mod${GOFLAGS:+ $GOFLAGS}"

# Single `go get` call with every module pinned at the same version.
# Doing them one-by-one risked transitive resolution pinning the base
# module to @latest while a sub-module was being bumped.
args=()
for mod in "${modules[@]}"; do
  args+=("$mod@$VERSION")
done
echo "  go get ${args[*]}"
go get "${args[@]}"

echo "bump-example-deps: done"
