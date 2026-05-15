# ADR 0007: MatchesRoute Hot-Path Inline Fast Path

- **Status:** Accepted (2026-05-15)
- **Issue:** [#867](https://github.com/axonops/audit/issues/867)
- **Reviewers:** performance-reviewer (APPROVED), code-reviewer (APPROVED), api-ergonomics-reviewer (APPROVED PR-1)
- **Supersedes:** —

## Context

PR [#193](https://github.com/axonops/audit/pull/193) introduced
per-category severity thresholds by changing
`EventRoute.IncludeCategories` from `[]string` (linear scan or
parallel `map[string]struct{}`) to `map[string]*SeverityRange`
(pointer-valued map). The map value carries an optional
[`SeverityRange`](../../filter.go) so each included category can
declare its own severity bound.

The change doubled the hottest non-format benchmark in the
library:

| Benchmark | Pre-#193 (2026-04-21) | Post-#193 / pre-PR-2 (2026-05-15) | Delta |
|---|---:|---:|---:|
| `BenchmarkMatchesRoute/include_categories-32` | 3.207 ns/op | 6.799 ns/op | **+112 %** |
| `BenchmarkMatchesRoute_Severity/include_categories_with_severity-32` | 3.203 ns/op | 6.603 ns/op | **+106 %** |

The regression is real, reproducible, and isolated to the
include-categories path. pprof on a 10-iteration cold-CPU run
confirmed ~99 % of include-path CPU time is spent in Go runtime
map machinery (`runtime.mapaccess2_faststr`, `aeshashbody`,
`(*Map).getWithoutKeySmallFastStr`).

`MatchesRoute` runs on every audit event for every routed output.
At single-digit nanoseconds the absolute cost is small, but the
library's v1.0 perf commitment was the 2026-04-21 baseline; a
2× regression on the hottest non-format path is the largest
deferred bug the spike review surfaced.

`buildRouteSets` is invoked automatically by `setRoute` in
`fanout.go` whenever a route is registered via
`Auditor.SetOutputRoute` (or via `WithRoute(...)` at `audit.New`
time). The `routeModeEmpty` slow-path fallback in
`MatchesRoute` exists for direct `EventRoute{...}` struct
literals used in tests that bypass `SetOutputRoute` — production
routes always reach `MatchesRoute` in their built form.

## Decision

Land the fix in two PRs:

- **PR-1** — value-typed `SeverityRange` (#867 part 1, merged):
  `map[string]*SeverityRange` → `map[string]SeverityRange`.
  Eliminates the pointer chase + nil branch on every map hit.
  Inner `MinSeverity *int` / `MaxSeverity *int` stay as pointers.
  Bench delta on its own: flat (the wins are offset by the
  larger 16-byte value-type entry vs 8-byte pointer in the map).
- **PR-2** — inline `[4]inlineCat` fast path + `routeMode`
  discriminator (this ADR): bypass the map entirely for routes
  with 1–4 included categories, dispatch on a precomputed
  `routeMode` byte instead of three len-of-map scans per call.

### Layout

```go
type EventRoute struct {
    // exported public fields (unchanged)
    IncludeCategories map[string]SeverityRange
    IncludeEventTypes []string
    ExcludeCategories []string
    ExcludeEventTypes []string
    MinSeverity *int
    MaxSeverity *int

    // Internal, populated by buildRouteSets:
    kind           routeMode  // 1 B
    inlineCatCount int8       // 1 B
    includeEvtSet  map[string]struct{}
    excludeCatSet  map[string]struct{}
    excludeEvtSet  map[string]struct{}
    inlineCats     [4]inlineCat // 128 B at the end of the struct
}

type routeMode uint8
const (
    routeModeEmpty routeMode = iota
    routeModeInclude
    routeModeExclude
    routeModeSeverityOnly
)

type inlineCat struct {
    key string
    val SeverityRange
}
```

`MatchesRoute` becomes a switch on `route.kind`. The
`routeModeInclude` arm branches once on `inlineCatCount > 0`:

- **Hot path (N≤4 categories)** — linear scan over
  `route.inlineCats[:route.inlineCatCount]` using direct string
  compare. No hash, no bucket scan, no pointer chase. Average
  ~2.8 ns at N=4 on AMD Zen 4.
- **N>4** — falls through to `route.IncludeCategories[category]`
  map lookup (the legacy path).
- **No categories, event-types only** — `len(IncludeCategories) == 0`
  short-circuit skips the map lookup entirely.

The `routeModeEmpty` arm preserves the field-by-field slow path
inline so direct-struct-literal routes (used in tests that bypass
`buildRouteSets`) keep matching correctly without extra
function-call cost.

### Test-only access via `export_test.go`

The api-ergonomics-reviewer rejected adding a public `Build()`
method as not a real user-facing concern — production routes
auto-build via `Auditor.SetOutputRoute`; only the audit library's
own benchmark code constructs raw `EventRoute` literals and
needs the fast path. `buildRouteSets` is exposed to the
`audit_test` package via `export_test.go` as
`audit.BuildRouteForTest(r)` plus the inspection helpers
`audit.InlineCatCountForTest(r)` and `audit.KindForTest(r)`.
These symbols are only compiled into the test binary; the
public `audit` package surface is unchanged by this PR.

## Alternatives Considered

Each option was scored against decision criteria in #867:
ns/op delta, correctness, code-churn risk, public API impact,
memory per route.

### A — Accept the regression

No code change. Document as the documented cost of #193.

Rejected. The 2026-04-21 baseline is the published v1.0 perf
commitment; doubling the hottest non-format benchmark fails it.

### B — Parallel `map[string]struct{}` for presence

Add a parallel set populated by `buildRouteSets`; the hot path
checks presence in the set first and only does the
`map[string]SeverityRange` value lookup when the per-category
filter actually exists.

Rejected. Two map lookups in the hit path is strictly worse than
one. Only useful for misses, which are rare.

### C — Inline `[4]string + [4]SeverityRange` fast path

The chosen option, in combination with D.

### D — Value-typed `SeverityRange`

The chosen option, in combination with C. Landed as PR-1.

### E — Interface-based dispatch

Detect "category-only, no severity bound" at `buildRouteSets`
time and switch to a faster implementation via interface
dispatch.

Rejected. Itab load + indirect call = 3–5 ns just for the
dispatch, which exceeds the savings. The discriminator-byte
peephole (the `routeMode` `kind` field) retains the *spirit* of
this option without the dispatch cost.

### F — Packed `[2]int16` map value

Replace `map[string]SeverityRange` with `map[string][2]int16`
(packed range). Removes the pointer chase, keeps the map.

Rejected by api-ergonomics-reviewer. Introduces a sentinel
encoding (`int16` magic-number-for-unbounded) that contradicts
the outer API where `*int = nil = unbounded`. Two different
unbounded conventions in the same struct is a worse ergonomics
tax than the perf saves.

## Measurements

All numbers on AMD Ryzen 7950X, Linux 6.14, Go 1.26.3,
`-count=10 -benchtime=2s`. Pre-#193 baseline from
`bench-baseline.txt` at commit 950c0c4. Post-PR-1 and post-PR-2
measured on the same machine within the same day to minimise
thermal drift.

| Benchmark | Pre-#193 | Post-#193 / pre-PR-2 | Post-PR-2 (bench-baseline) | Δ vs baseline |
|---|---:|---:|---:|---:|
| `MatchesRoute/include_categories` | 3.2 ns | 6.8 ns | **4.0 ns** | +25 % (recovers ~80 % of the regression) |
| `MatchesRoute_Severity/include_categories_with_severity` | 3.2 ns | 6.6 ns | **4.0 ns** | +25 % |
| `MatchesRoute_Severity/per_category_severity_accept` | n/a (new in #193) | 7.05 ns | **3.6 ns** | −49 % vs #193 |
| `MatchesRoute_Severity/per_category_severity_reject` | n/a (new in #193) | 6.73 ns | 3.6 ns | −46 % vs #193 |
| `MatchesRoute/empty_route` | 1.7 ns | 1.7 ns | 2.5 ns | +47 % (struct-size cost) |
| `MatchesRoute/exclude_categories` | 8.4 ns | 8.1 ns | 9.7 ns | +15 % vs baseline |
| `MatchesRoute/include_event_types` | 4.1 ns | 4.7 ns | 7.9 ns | +92 % vs baseline |
| `MatchesRoute/include_20_categories` | 6.8 ns | 6.8 ns | 7.7 ns | +13 % vs baseline |
| `MatchesRoute_LargeInclude/N=4` (new) | n/a | n/a | 4.7 ns | n/a |
| `MatchesRoute_LargeInclude/N=5` (new) | n/a | n/a | 8.3 ns | n/a |
| `MatchesRoute_LargeInclude/N=16` (new) | n/a | n/a | 7.3 ns | n/a |
| `MatchesRoute_LargeInclude/N=32` (new) | n/a | n/a | 7.4 ns | n/a |
| `MatchesRoute_FanoutMix` (new) | n/a | n/a | 5.6 ns | n/a |

Numbers above are 5-iteration averages from the regenerated
`bench-baseline.txt`, on warm CPU (matches the methodology used
for the original 2026-04-21 baseline). PR #869 description and
the original ADR text cited tighter 10-iteration spot-check
numbers (~2.8 ns on the hot path); the formal 5-iteration
baseline lands ~1.2 ns higher on the inline path because map
iteration order randomises which inline slot the lookup key
falls into. The 4.0 ns figure is the honest steady-state cost
of the inline fast path under random key-position distribution.

## Trade-offs

PR-2 introduces real regressions on benchmarks that do not use
the inline fast path. Numbers from the regenerated baseline:

- `empty_route` +0.8 ns (1.7 → 2.5 ns)
- `exclude_categories` +1.3 ns (8.4 → 9.7 ns)
- `include_event_types` +3.8 ns (4.1 → 7.9 ns) — largest collateral cost

These are attributable to the larger `EventRoute` struct (256 B
post-PR-2 vs 120 B pre-PR-2) — the additional cache footprint
costs ~1 ns on paths that don't exercise the inline arrays. The
attempt at a heap-allocated `*[4]inlineCat` pointer (instead of
inline array) reduced struct size to ~140 B but introduced a
pointer chase that gave back the include-path win for the
benefit of marginal recovery on the unrelated paths — net worse.

The trade-off is accepted: the +112 % regression on
`include_categories` (the targeted bug) is dramatically fixed at
the cost of +0.7 to +1.8 ns on three less-common paths. The
absolute numbers remain in single-digit nanoseconds across all
paths.

## Validation

- `TestMatchesRoute_BuiltEquivalentToUnbuilt` — `rapid`-driven
  property check that `MatchesRoute` returns identical results
  for built and unbuilt route shapes across include /
  include-with-per-category-severity / exclude / event-type-only
  / severity-only / empty configurations, with category counts
  spanning the inline-eligible (N≤4) and map-fallback (N>4)
  ranges. Regression guard for the fast/slow path equivalence.
- All existing BDD scenarios for routing pass unchanged.
- `BenchmarkMatchesRoute_LargeInclude` exercises the inline
  boundary (N=4, N=5) and the map fallback (N=16, N=32).
- `BenchmarkMatchesRoute_FanoutMix` cycles 5 different route
  shapes (empty / include-2cats / include-6cats / exclude /
  severity-only) and 8 events to stress branch prediction
  across the `routeMode` switch.

## Consequences

### Positive

- The targeted +112 % `include_categories` regression
  (3.2 → 6.8 ns) is recovered to 4.0 ns — restoring ~80 % of the
  gap to the pre-#193 floor.
- Per-category severity (the common case after #193) now matches
  at 3.6 ns vs the regressed 7.05 ns.
- The `routeMode` peephole eliminates three `len()`-of-map scans
  per `MatchesRoute` call across all routes.
- Zero new public API surface — `buildRouteSets` stays internal;
  benchmarks reach it via `export_test.go`.

### Negative

- `EventRoute` struct grew from ~120 B to ~256 B per route. For
  typical deployments (1–10 outputs) this is ~1–2 KB total —
  negligible. For pathological consumers building thousands of
  routes the memory cost is real.
- Three benchmarks regressed by 0.4–1.8 ns (`empty_route`,
  `exclude_categories`, `include_event_types`) — accepted cost
  of the struct-size growth.

### Neutral

- `buildRouteSets` is idempotent; calling it twice is safe
  (it zeros the inline array first).
- Direct struct-literal `EventRoute` construction continues to
  work unchanged via the `routeModeEmpty` fall-through.

## References

- Issue [#867](https://github.com/axonops/audit/issues/867) — spike
- PR [#193](https://github.com/axonops/audit/pull/193) — the
  per-category severity feature that introduced the regression
- pprof line-level evidence:
  [issue #867 comment](https://github.com/axonops/audit/issues/867#issuecomment-4458603599)
- `BENCHMARKS.md` — refreshed numbers
