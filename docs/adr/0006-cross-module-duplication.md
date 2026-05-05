# ADR-0006: Cross-Module Code Duplication — Document, Don't Extract

## Status

Accepted — 2026-05-05

## Context

Three small pieces of unexported logic are duplicated across the
audit library's published Go modules:

1. **Backoff/jitter** — `syslog/reconnect.go:backoffDuration`,
   `webhook/http.go:webhookBackoff`, `loki/http.go:lokiBackoff`.
   Same algorithm (exponential with jitter), variant caps (30 s for
   persistent TCP reconnection in syslog, 5 s for per-request HTTP
   in webhook and loki).

2. **`dropLimiter`** — `droplimit.go` (core) plus reciprocal copies
   in `file/`, `webhook/`, `syslog/`, `loki/droplimit.go`. Identical
   type definition and `record()` method body across all five files;
   the core copy carries a longer comment block on lock-free
   semantics that the sub-module copies omit.

3. **`intPtrOrDefault`** — register-time YAML helper duplicated
   verbatim across `file/register.go`, `syslog/register.go`,
   `webhook/register.go`, `loki/register.go`. Maps optional `*int`
   pointers to defaulted values, with a `-1` sentinel to distinguish
   "explicit YAML zero" (rejected by validation) from "not set"
   (replaced by default).

The duplication exists because Go's `internal/` package mechanism
does not cross module boundaries. Each output module
(`audit/file`, `audit/syslog`, `audit/webhook`, `audit/loki`) is
independently versioned and published, and so cannot import an
`internal/` package from a sibling module. This forces every
module that needs the same unexported helper to keep its own copy.

The choice is between:

- **(a) Extract to a published shared module** — e.g.
  `github.com/axonops/audit/internalshared`. Pros: one source of
  truth. Cons: a new module to version, publish, security-review,
  and synchronise across 4+ consumers. Each consumer then carries
  a third-party-style dependency on a sibling module.

- **(b) Keep the duplication, document the SYNC contract** — every
  copy carries a `// SYNC:` comment listing its sibling files and
  the reason for the duplication, plus a CI check that verifies the
  marker is present.

## Decision

We choose **(b)**: keep the duplication and document the SYNC
contract.

The total scope is ~80 lines of code distributed across 12 files
(5 dropLimiter + 3 backoff + 4 intPtrOrDefault). The cost of
introducing a new published shared module — its own go.mod, its
own version line, its own security review, its own SBOM entry,
its own dependency arrow on every consuming sub-module — is
disproportionate to the scope.

The SYNC-comment-plus-CI-check pattern was already partially
established by the four sub-module `dropLimiter` copies, which
each carried a "this is a copy of `droplimit.go`" comment back
to the core. This decision codifies the existing pattern,
extends it to the other two duplicated pieces, and adds CI
enforcement.

## Consequences

### Mechanical contract

Every duplicated file MUST carry a top-of-file or function-level
comment of the form:

```go
// SYNC: <description of duplication>
//
// <list of sibling files>.
// The <type/helper> is unexported and cannot be shared across
// Go modules (each output module is independently versioned and
// published). Keep all <N> copies in sync when making changes
// (#542).
```

The marker is `^// SYNC:` — anchored at column 0 to avoid false
positives inside string literals or doc-comment paragraphs.

### CI enforcement

`make check-sync-comments` (defined in `Makefile`, wired into the
`check-static` aggregator) greps every file in the
duplication-by-necessity list for the SYNC marker and exits 1
if any is missing. The list is hand-maintained in the Makefile
target body; adding a new piece of duplicated logic in a future
PR requires extending the list as part of that PR.

### What CI does NOT enforce

The check verifies marker **presence**, not body **equivalence**.
Two copies of `intPtrOrDefault` could legally have different
implementations and the CI would still pass. This is a deliberate
trade-off: AST-level diff tooling would be disproportionate for
~20 lines of code per copy. The marker is a trip-wire that
prompts a reviewer to diff bodies cross-file when any listed file
changes; correctness of the cross-file invariant is a code-review
responsibility, not a CI responsibility.

### When to revisit this decision

The decision should be revisited if:

- The duplicated scope grows materially (say > 5 distinct pieces
  or > 300 lines of duplication total). At that point the
  shared-module overhead becomes proportionate.
- Drift causes a real bug in production. The presence-only check
  would have caught a missing comment but not a body that
  diverged from its siblings; if drift bites, the right response
  may be a body-equivalence tool or extraction to a shared
  module.
- A genuinely useful third-party module already exists for one
  of the pieces (most likely backoff — there are mature Go
  libraries for exponential-backoff-with-jitter), in which case
  consuming the third-party would dominate either home-grown
  approach.

## Related

- Issue #542 — original tracking.
- PR #818 — implements this ADR.
- Master tracker #472 — v1.0 release readiness.
- ADR-0001 through ADR-0005 — prior architectural decisions.
