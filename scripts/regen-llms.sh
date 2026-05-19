#!/usr/bin/env bash
# Copyright 2026 AxonOps Limited.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Regenerates llms-full.txt at the repo root by concatenating the
# source documents listed in LLMS_SOURCES below. The output is a
# single file consumable by AI coding assistants and IDE-integrated
# RAG tools (per the llmstxt.org spec, paired with llms.txt).
#
# Usage:
#   scripts/regen-llms.sh           # rewrite llms-full.txt in place
#   scripts/regen-llms.sh --check   # verify in sync; exit 1 on drift
#
# Token budget is enforced at 200,000 via a 4-bytes-per-token
# heuristic. Real tokenisers will report ~10-25% fewer tokens than
# this estimate; the budget is a guard against accidental bloat, not
# a precise measurement. Tools with smaller context windows (e.g.
# 128k) cannot consume llms-full.txt whole today; consumers SHOULD
# either chunk the file or fall back to llms.txt for those tools.
set -euo pipefail

# Pin the locale so `find` and `sort` produce stable, byte-ordered
# output regardless of the contributor's environment. Without this,
# regenerating on a non-C locale can produce a diff against CI.
export LC_ALL=C

readonly TOKEN_BUDGET=200000

usage() {
  cat >&2 <<EOF
Usage: $0 [--check]
  (no args)  rewrite llms-full.txt at repo root
  --check    verify llms-full.txt is in sync; exit 1 if regen would diff
EOF
  exit 2
}

mode="rewrite"
case "${1:-}" in
  --check) mode="check" ;;
  -h|--help) usage ;;
  "") ;;
  *) usage ;;
esac

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"

# Source files concatenated into llms-full.txt, in reading order.
# llms.txt is the curated index; the rest expand into the full
# consumer-facing documentation set in roughly Diátaxis order
# (tutorial -> how-to -> reference -> explanation).
LLMS_SOURCES=(
  llms.txt
  README.md
  ARCHITECTURE.md
  doc.go
  # Tutorial
  docs/quickstart-http-service.md
  docs/migrating-from-application-logging.md
  docs/code-generation.md
  docs/testing.md
  # How-to: outputs
  docs/outputs.md
  docs/output-configuration.md
  docs/stdout-output.md
  docs/file-output.md
  docs/syslog-output.md
  docs/webhook-output.md
  docs/loki-output.md
  # How-to: integration features
  docs/http-middleware.md
  docs/event-routing.md
  docs/sensitivity-labels.md
  docs/hmac-integrity.md
  docs/secrets.md
  docs/metrics-monitoring.md
  docs/sanitizer.md
  # How-to: extension
  docs/writing-custom-outputs.md
  docs/writing-custom-secret-providers.md
  # How-to: operations
  docs/deployment.md
  docs/troubleshooting.md
  # Reference
  docs/taxonomy-validation.md
  docs/error-reference.md
  docs/reserved-standard-fields.md
  docs/json-format.md
  docs/cef-format.md
  docs/validation.md
  # Explanation
  docs/async-delivery.md
  docs/event-emission-paths.md
)

# Verify every source file exists before doing any work.
for src in "${LLMS_SOURCES[@]}"; do
  if [[ ! -f "$repo_root/$src" ]]; then
    echo "regen-llms: source file not found: $src" >&2
    exit 1
  fi
done

# Drift guard: every Markdown file under docs/ MUST either be in
# LLMS_SOURCES or in the allowlist below. New docs added to docs/
# without an explicit decision either land in llms-full.txt or are
# allowlisted as out-of-scope — silent omission is not OK.
LLMS_DOCS_ALLOWLIST=(
  docs/development-workflow.md  # internal contributor workflow
  docs/releasing.md             # internal release engineering
  docs/v1-changes.md            # release notes
  docs/threat-model.md          # security disclosure
  docs/schema-artifacts.md      # internal artefact format reference
  docs/wal-design.md            # internal design doc (also very large)
  docs/performance.md           # benchmark methodology
  docs/performance-results.md   # benchmark numbers
  docs/playground.md            # short note on Go Playground compatibility
)

# Sub-directory allowlist (prefix match). Anything under these
# prefixes is exempt from the unexplained-extras guard.
LLMS_DOCS_DIR_ALLOWLIST=(
  docs/adr/    # architecture decision records, internal
  docs/perf/   # performance spike write-ups, internal
)

mapfile -t actual_docs < <(cd "$repo_root" && find docs -name '*.md' | sort)
for doc in "${actual_docs[@]}"; do
  found=0
  for src in "${LLMS_SOURCES[@]}" "${LLMS_DOCS_ALLOWLIST[@]}"; do
    if [[ "$src" == "$doc" ]]; then
      found=1
      break
    fi
  done
  if [[ "$found" -eq 0 ]]; then
    for prefix in "${LLMS_DOCS_DIR_ALLOWLIST[@]}"; do
      if [[ "$doc" == "$prefix"* ]]; then
        found=1
        break
      fi
    done
  fi
  if [[ "$found" -eq 0 ]]; then
    echo "regen-llms: $doc is not in LLMS_SOURCES or any allowlist." >&2
    echo "  Add it to scripts/regen-llms.sh (either include it in the" >&2
    echo "  concatenation, allowlist the file in LLMS_DOCS_ALLOWLIST," >&2
    echo "  or allowlist its directory in LLMS_DOCS_DIR_ALLOWLIST)." >&2
    exit 1
  fi
done

tmp_out="$(mktemp)"
trap 'rm -f "$tmp_out"' EXIT

{
  echo "# audit - complete documentation"
  echo "# Generated by scripts/regen-llms.sh - do not edit by hand."
  echo "# To regenerate: make regen-llms"
  echo "# Source files: ${#LLMS_SOURCES[@]}"
  echo ""
  for src in "${LLMS_SOURCES[@]}"; do
    echo "---"
    echo ""
    echo "# === $src ==="
    echo ""
    cat "$repo_root/$src"
    # Ensure separation between sections regardless of whether the
    # source file ended with a trailing newline.
    echo ""
  done
} > "$tmp_out"

bytes=$(wc -c < "$tmp_out" | tr -d ' ')
tokens_est=$((bytes / 4))
if [[ "$tokens_est" -gt "$TOKEN_BUDGET" ]]; then
  echo "regen-llms: llms-full.txt exceeds ${TOKEN_BUDGET}-token budget" >&2
  echo "  bytes:        $bytes" >&2
  echo "  tokens (est): $tokens_est" >&2
  echo "  budget:       $TOKEN_BUDGET" >&2
  echo "  Trim a source doc or drop one from LLMS_SOURCES." >&2
  exit 1
fi

target="$repo_root/llms-full.txt"

if [[ "$mode" == "check" ]]; then
  if [[ ! -f "$target" ]]; then
    echo "regen-llms: llms-full.txt is missing." >&2
    echo "Run: make regen-llms" >&2
    exit 1
  fi
  if ! diff -u "$target" "$tmp_out" >/dev/null; then
    echo "regen-llms: llms-full.txt is OUT OF SYNC with the source docs." >&2
    echo "Run: make regen-llms" >&2
    diff -u "$target" "$tmp_out" >&2 || true
    exit 1
  fi
  echo "regen-llms: llms-full.txt is in sync ($bytes bytes; tokens (est): $tokens_est / $TOKEN_BUDGET)."
  exit 0
fi

# Rewrite mode: only touch the file if content changed, to avoid
# pointless mtime churn in git status.
if diff -q "$target" "$tmp_out" >/dev/null 2>&1; then
  echo "regen-llms: llms-full.txt already up to date ($bytes bytes; tokens (est): $tokens_est / $TOKEN_BUDGET)."
else
  # install rather than cp so the destination gets sane (644) perms;
  # mktemp creates the source with 600 which would otherwise propagate.
  install -m 644 "$tmp_out" "$target"
  echo "regen-llms: llms-full.txt regenerated ($bytes bytes; tokens (est): $tokens_est / $TOKEN_BUDGET)."
fi
