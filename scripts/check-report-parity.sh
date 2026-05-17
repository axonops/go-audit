#!/usr/bin/env bash
# Verify that the shared report-rendering helpers are byte-identical
# between cmd/bdd-report and cmd/junit-report. The two tools render
# different input formats but share the security-critical escape and
# writer code; divergence creates a Markdown- or HTML-injection risk
# in one tool but not the other.
#
# When intentional changes land, update BOTH files together. The diff
# below tells you exactly what drifted.
#
# Run via `make check-report-parity` (wired into `make check`).

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
status=0

for f in render.go writer.go; do
    bdd="$ROOT/cmd/bdd-report/$f"
    jun="$ROOT/cmd/junit-report/$f"
    if ! diff -u "$bdd" "$jun"; then
        echo "ERROR: $f differs between cmd/bdd-report and cmd/junit-report." >&2
        echo "       The shared helpers must be byte-identical. Apply the same" >&2
        echo "       change to both files." >&2
        status=1
    fi
done

if [ $status -eq 0 ]; then
    echo "check-report-parity: cmd/bdd-report and cmd/junit-report helpers match."
fi
exit $status
