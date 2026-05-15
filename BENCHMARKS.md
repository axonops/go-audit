# Benchmark Results

This file tracks benchmark results over time to detect performance regressions and measure optimisation impact.

## How to Use

```bash
make bench           # Run benchmarks, save to bench.txt
make bench-save      # Run + save as bench-baseline.txt (committed)
make bench-compare   # Run + compare against bench-baseline.txt via benchstat
```

The CI pipeline runs `make bench` on every PR and compares against `bench-baseline.txt` when present.

---

## Current Baseline

**Date:** 2026-05-15
**Commit:** main post-#869 (matchesRoute inline fast path + routeMode peephole)
**Go:** 1.26+
**CPU:** AMD Ryzen 9 7950X 16-Core (32 threads)
**OS:** Linux 6.14.0
**Samples:** `count=5` per benchmark; benchstat confidence requires ≥6 so the current report is indicative (`± ∞`). Compare rather than read absolutes.

> **#867 matchesRoute fix landed in this baseline.** The +112 %
> regression in `MatchesRoute/include_categories` (introduced by
> #193's per-category severity) is recovered from 6.8 ns →
> ~4.0 ns — restoring most of the gap to the 3.2 ns pre-#193 floor
> via an inline `[4]inlineCat` fast path and a `routeMode`
> discriminator. Three less-common benchmarks regressed 0.4–3.8 ns
> absolute due to the 256-byte EventRoute struct footprint
> (was 120 B) — accepted trade documented in
> [ADR 0007](docs/adr/0007-matchesroute-perf.md).
>
> **#497 W2 zero-copy drain remains in this baseline.** Most Audit-path
> benchmarks are 1 alloc/op with byte-allocation reductions of 40–55 %.
> The donor fast path (generated builders that satisfy `FieldsDonor`)
> reaches 0 allocs/op on the drain side end-to-end. See
> [`docs/performance.md`](docs/performance.md) for the full
> ownership model and methodology.

## Release Soak-Test Summary

The 12-hour soak (`make soak`) is run on consistent hardware before
each release tag (#573 / Track F-52). It exercises the audit hot
path with file + syslog + webhook outputs simultaneously at 5000
events/sec across 8 producer goroutines. Results MUST show bounded
heap allocation and goroutine counts over the run. Maintainers
paste values from `$SOAK_OUTPUT_DIR/soak-summary-*.json` into the
table below before tagging a release.

See [`tests/soak/README.md`](tests/soak/README.md) for the full
workflow.

### Template (copy for each release)

```
### vX.Y.Z soak (YYYY-MM-DD)

- **CPU:** <model, threads>
- **OS:** <kernel>
- **Hardware notes:** <isolation, no other load, etc.>
- **Sample CSV:** `<artifact path or attached>`

| Metric | Start | End | Peak | Bound |
|--------|------:|----:|-----:|------:|
| heap_alloc_mb | N | N | N | < 2 × start |
| numGoroutine | N | N | N | < 2 × start |
| total_events | — | N | — | — |
| total_drops | — | 0 | — | 0 |
| goleak failures | — | 0 | — | 0 |
```

### Pre-v1.0.0 baseline soak

_To be populated on the v1.0.0 release-prep run. Do not tag
v1.0.0 without a green soak entry here._

### Core Audit Path

| Benchmark | ns/op | B/op | allocs/op | Notes |
|-----------|------:|-----:|----------:|-------|
| Audit | 378 | 182 | **1** | 3 fields; W2 dropped 1 alloc + 142 B/op (prior baseline: 2 allocs/op, 324 B/op) |
| Audit_RealisticFields | 810 | 330 | **1** | 10 fields; W2 dropped 1 alloc + 340 B/op (prior baseline: 2 allocs/op, 670 B/op) |
| Audit_Parallel | 64 | 24 | 1 | GOMAXPROCS goroutines, per-op amortised |
| AuditDisabledCategory | 299 | 154 | 1 | Category disabled; drain skips write |
| Audit_EndToEnd | 391 | 189 | **1** | W2 dropped 1 alloc + 140 B/op |
| AuditDisabledAuditor | 18 | 24 | 1 | WithDisabled auditor — early return |

### Fan-Out (multi-output)

| Benchmark | ns/op | B/op | allocs/op | Notes |
|-----------|------:|-----:|----------:|-------|
| FanOut_SharedFormatter | 370 | 335 | **1** | 3 outputs, same formatter (W2: -1 alloc, -130 B/op) |
| FanOut_MixedFormatters | 346 | 230 | **1** | 3 outputs, 2 formatters (W2: -1 alloc, -115 B/op) |
| FanOut_FilteredOutputs | 362 | 255 | **1** | 3 outputs, 1 filtered (W2: -1 alloc, -150 B/op) |
| FanOut_5Outputs | 344 | 385 | 1-2 | 5 outputs, same formatter (W2 typical: 1 alloc) |

### HMAC Pipeline

| Benchmark | ns/op | B/op | allocs/op | Notes |
|-----------|------:|-----:|----------:|-------|
| Audit_WithHMAC | 358 | 172 | **1** | Full Audit path with HMAC-SHA-256 appended; W2 dropped 1 alloc + 170 B/op (50 % reduction) |
| HMAC_SHA256_SmallEvent | 475 | 640 | 8 | Direct ComputeHMAC on small payload |
| HMAC_SHA256_LargeEvent | 1247 | 640 | 8 | Direct ComputeHMAC on large payload |
| HMAC_SHA512_SmallEvent | 1114 | 1120 | 8 | SHA-512 variant on small payload |

### Post-Serialisation Append

| Benchmark | ns/op | B/op | allocs/op | Notes |
|-----------|------:|-----:|----------:|-------|
| AppendPostFields_JSON | 88 | 160 | 1 | writeJSONString + pooled buffer |
| AppendPostFields_CEF | 57 | 128 | 1 | cefEscapeExtValue direct write |
| AppendPostFields_Disabled | 1.3 | 0 | 0 | nil fields fast path |

### Hot-Path Isolation Benchmarks

Added by #502 to give each critical function its own standalone
baseline. Previously regressions in these helpers were only
visible through the aggregate `BenchmarkAudit` number.

| Benchmark | ns/op | B/op | allocs/op | Notes |
|-----------|------:|-----:|----------:|-------|
| ValidateFields_Success          |  71 |   0 | 0 | Happy path — all required present, no unknowns |
| ValidateFields_MissingRequired  | 256 | 144 | 4 | Early-error path; allocations from error formatting |
| CheckUnknownFields_Strict       | 412 | 240 | 7 | Strict mode: unknown fields become errors |
| CheckUnknownFields_Permissive   |   2 |   0 | 0 | Permissive (default): early-return guard |
| CopyFieldsWithDefaults/Fields_3 | 189 | 336 | 2 | 3 fields — dominant caller-side alloc |
| CopyFieldsWithDefaults/Fields_10 | 481 | 954 | 5 | 10 fields — realistic audit event |
| CopyFieldsWithDefaults/Fields_20 | 1 054 | 2 140 | 7 | 20 fields — heavy event |
| ProcessEntry_Drain              | 1 029 | 386 | 2 | Synchronous drain with one mock output |
| ComputeHMACFast                 | 155 |   0 | 0 | Pre-allocated drain-loop HMAC path (zero-alloc by construction) |

### Parallelism Scaling

Added by #503. Characterises the contention curve on the
filter state `sync.Map` as producer count grows. Near-linear
scaling up to physical-core count, then amortises as
`sync.Map`'s read-dominant path absorbs contention.

| N    | ns/op | B/op | allocs/op |
|-----:|------:|-----:|----------:|
|   1  |  73   |  27  | 1 |
|  10  |  57   |  24  | 1 |
|  50  |  57   |  24  | 1 |
| 100  |  48   |  24  | 1 |
| 200  |  55   |  24  | 1 |

The ns/op number represents per-op wall-clock under the given
`GOMAXPROCS × N` producer load. Values below the N=1 baseline
reflect per-call amortisation under parallelism — the auditor's
hot path is dominated by memory allocation, not lock contention
(which is the expected result from `sync.Map`'s lock-free read
path). Run via `go test -bench BenchmarkAudit_Parallelism`.

### Caller-Side Helpers

| Benchmark | ns/op | B/op | allocs/op | Notes |
|-----------|------:|-----:|----------:|-------|
| NewEventKV | 124 | 360 | 2 | slog-style event construction |
| FilterCheck | 16 | 0 | 0 | isEnabled lock-free (syncmap) |

### Emission-Path Comparison

Same auditor, same taxonomy, same `Fields` literal — what does the
caller-side choice cost? `NoopOutput` isolates the emission path by
removing output-side work. See `BenchmarkAudit_ViaHandle_vs_NewEvent`.

| Emission path | ns/op | B/op | allocs/op | Notes |
|---------------|------:|-----:|----------:|-------|
| `Auditor.AuditEvent(NewEvent(...))` | ~400 | 24 | **1** | One `basicEvent` escapes through the `Event` interface return |
| `EventHandle.Audit(fields)` | ~369 | **0** | **0** | No interface wrapping; defensive `Fields` copy recycles from `sync.Pool` after warm-up |

Observation: `EventHandle.Audit` eliminates the single remaining
caller-side allocation on the dynamic-event-type path (−1 alloc/op,
−24 B/op, ~8 % wall-clock). For event types known at compile time,
generated typed builders satisfying `FieldsDonor` additionally skip
the defensive `Fields` map copy — that is the zero-allocation
drain-side fast path, benchmarked as `BenchmarkAudit_FastPath_FanOut4_NoopOutputs`.

### Formatters

| Benchmark | ns/op | B/op | allocs/op | Notes |
|-----------|------:|-----:|----------:|-------|
| JSONFormatter_Format | 349 | 176 | 1 | 4 fields, buffer pooled, writeJSONString |
| JSONFormatter_Format_LargeEvent | 1208 | 640 | 1 | 20 fields |
| CEFFormatter_Format | 380 | 160 | 1 | 4 fields, buffer pooled, single-pass escape |
| CEFFormatter_Format_LargeEvent | 1170 | 577 | **1** | 20 fields; #496 dropped 3 → 1 allocs/op via in-place appendFormatFieldValue + writeEscapedExtValueString |
| CEFFormatter_Format_LargeEvent_Escaping | 2120 | 1518 | 4 | 20 fields, every value carries a CEF metacharacter; informational — additional allocs reflect the per-event `reserved` map + extra-field routing (out of #496 scope) |
| CEFFormatter_Format_Numeric | 1284 | 747 | 4 | 10 numeric fields (int/int64/uint64/float64/float32); informational — same extra-field routing story as _Escaping |
| CEFFormatter_Format_Parallel | 250 | 576 | 1 | 20 fields @ GOMAXPROCS; sub-linear scaling confirmed |
| FormatJSON_WithConfigFields | 443 | 240 | 1 | Config-field variant |
| FormatCEF_WithConfigFields | 439 | 224 | 1 | Config-field variant |

### Route Matching

Inline `[4]inlineCat` fast path + `routeMode` discriminator landed
in #869. Numbers below are post-#867 fix.

| Benchmark | ns/op | allocs/op | Notes |
|-----------|------:|----------:|-------|
| MatchesRoute/empty_route | 2.5 | 0 | Trivial pass-through |
| MatchesRoute/include_categories | 4.0 | 0 | 4-entry include list — inline fast path (recovered from 6.8 ns post-#193) |
| MatchesRoute/exclude_categories | 9.7 | 0 | 3-entry exclude list |
| MatchesRoute/include_event_types | 7.9 | 0 | 4-entry include list — event-types-only path |
| MatchesRoute/include_20_categories | 7.7 | 0 | 20-entry include list — map fallback |
| MatchesRoute_Severity/nil_severity | 2.5 | 0 | Empty route severity short-circuit |
| MatchesRoute_Severity/severity_only_min | 1.5 | 0 | Severity-only catchall, Min bound |
| MatchesRoute_Severity/severity_only_range | 1.5 | 0 | Severity-only catchall, Min+Max bounds |
| MatchesRoute_Severity/severity_only_catchall_reject | 1.5 | 0 | Severity-only catchall, reject path |
| MatchesRoute_Severity/include_categories_with_severity | 4.0 | 0 | Category include + route-level severity |
| MatchesRoute_Severity/per_category_severity_accept | 3.6 | 0 | Per-category SeverityRange accept (#193) |
| MatchesRoute_Severity/per_category_severity_reject | 3.6 | 0 | Per-category SeverityRange reject (#193) |
| MatchesRoute_LargeInclude/N=4 | 4.7 | 0 | Inline-array boundary at maximum |
| MatchesRoute_LargeInclude/N=5 | 8.3 | 0 | Just over the inline threshold — map fallback fires |
| MatchesRoute_LargeInclude/N=16 | 7.3 | 0 | Map fallback, medium size |
| MatchesRoute_LargeInclude/N=32 | 7.4 | 0 | Map fallback, large size — no scaling beyond ~7 ns |
| MatchesRoute_FanoutMix | 5.6 | 0 | 5 distinct route shapes × 8 events — branch-prediction stress |
| MatchesRoute_PerCategorySeverity | 9.5 | 0 | Per-category severity end-to-end (#193) |
| MatchesRoute_MixedNilAndFilter | 9.1 | 0 | Mix of zero-value and bounded SeverityRange entries |
| FilterCheck_Parallel | 1.0 | 0 | GOMAXPROCS goroutines, sync.Map lock-free reads |
| FilterCheck_ReadWriteContention | 1.1 | 0 | GOMAXPROCS readers + 1 writer toggling category |

### Output Backends

| Benchmark | ns/op | B/op | allocs/op | Notes |
|-----------|------:|-----:|----------:|-------|
| FileOutput_Write | ~67 | 160 | 1 | Enqueue hot path, diagnostic logger silenced |
| FileOutput_Write_Parallel | ~85 | 160 | 1 | RunParallel — channel contention |
| FileOutput_Write_WithRotation | 60 | 162 | 1 | Public API, `MaxSizeMB: 1` + `MaxBackups: 2` + `Compress: false`. Public-API minimum triggers rotation every ~6500 writes — dilute signal, overall cost matches `FileOutput_Write`; catches `file.Output` regressions under any rotation activity (#504) |
| rotate.Writer_Write_WithRotation | 1012 | 1635 | 4 | Internal byte-granular path, `MaxSize: 4 KiB` + `MaxBackups: 2`. Rotation fires every ~25 writes so per-rotation cost is visible. Delta vs `Writer_Write_SyncOnWriteFalse` (~52 ns) isolates rotation mechanics (rename + new file + prune). Defer gzip cost — `Compress: false`. (#504) |
| SyslogOutput_Write | 79 | 174 | 1 | TCP write enqueue, diagnostic logger silenced |
| loki.WriteWithMetadata | 64 | 77 | 1 | Single-event Loki enqueue |
| loki.BatchBuild | 72µs | 260Ki | 389 | 100 events grouped into push streams |
| loki.BatchBuild_HighCardinality | — | — | — | 100 distinct event_types; worst-case stream cardinality path. Added by #494; cross-referenced for #504 AC #1 |
| loki.Gzip | 213µs | 1.0Mi | 380 | Gzip of realistic push payload |
| outputconfig.Load | ~485µs | 1.23Mi | 8171 | 4-output fixture (stdout + 3 file variants with routing, HMAC, envsubst); startup-cost baseline — one Load per process boot in most deployments (#504) |

### Key Observations

- **Audit** at **1 alloc/op** post-W2 (#497). The single remaining allocation is the defensive map clone on the slow path (`NewEvent` / `NewEventKV`). Generated builders on the fast path reach **0 allocs/op** at the drain side.
- **Audit_Parallel** at 1 alloc/op and ~64 ns amortised — lock-free filter + pooled entry, sub-linear scaling under contention.
- **AuditDisabledAuditor** at 18 ns — the `WithDisabled` early-return path. Effectively free.
- **JSONFormatter_Format** at 1 alloc/op — this benchmark exercises the public `Formatter.Format` path (which always copies before return for backward compatibility with third-party callers). The drain pipeline uses the internal `bufferedFormatter.formatBuf` path which leases the buffer and reaches 0 allocs/op end-to-end.
- **FilterCheck** at 0 allocs/op and ~16 ns — lock-free via `syncmap`.
- **MatchesRoute** at 0 allocs/op — O(n) scan, largest list (20 categories) at ~6.7 ns.
- **AppendPostFields_JSON** at 1 alloc/op exercises the pre-W2 public `AppendPostFields` path. The drain now uses in-place `appendPostFieldJSONInto` which mutates a per-event scratch buffer and contributes 0 allocs/op.
- **HMAC** direct `ComputeHMAC` at 8 allocs/op on the standalone benchmarks reflects the per-call `hmac.New` + hex-encoding cost. The `Audit_WithHMAC` full-path benchmark drops to **1 alloc/op** post-W2 (was 2) because the in-place HMAC append eliminates the scratch buffer allocation.
- **Fan-out** scales well: 3 outputs with shared formatter lands at ~370 ns; 5 outputs at ~344 ns — effectively constant because all outputs share one formatter-buffer lease and each output pays only for post-field assembly.
- **Output-backend enqueue** hot paths (`FileOutput_Write`, `SyslogOutput_Write`, `loki.WriteWithMetadata`) all land at 1 alloc/op — channel-send + one defensive data copy (the no-retention contract from #497 W2). Background goroutines handle batching, retries, and compression.
- **Rotation cost** is isolated by `rotate.Writer_Write_WithRotation` at 1012 ns/op vs `Writer_Write_SyncOnWriteFalse` at ~52 ns/op — ≈960 ns per write is amortised rotation cost across the 25-write cycle, implying ≈24 µs per actual rotation event (rename + new file + prune). `FileOutput_Write_WithRotation` at the public API surface shows the same cost diluted across ~6500 writes per rotation and thus reads like `FileOutput_Write` — it catches regressions in `file.Output → rotate.Writer` wiring, not rotation-internal regressions. (#504)
- **`outputconfig.Load`** baselines at ≈485 µs per call with ~8,171 allocs/op against a 4-output fixture (YAML parse + envsubst + validate + factory dispatch + HMAC state setup + file-handle creation × 3). This is a **startup cost**, charged once per process boot for most deployments. Consumers that reload config dynamically should budget accordingly; absolute ns/op matters less than regression detection on the allocation count. (#504)

---

## Comparison against `log/slog`

Developers evaluating this library will naturally ask **"why not
just use `log/slog`?"** `log/slog` ships with the Go standard
library, has a well-tuned `slog.NewJSONHandler`, and is the
obvious choice for general-purpose structured logging. This
section publishes a side-by-side benchmark so the ns/op delta is
visible, not imagined, and the subsequent prose explains what
the audit library does that `slog` does not.

Benchmark source: `bench_comparison_test.go`,
`BenchmarkSlog_JSONHandler_BaselineComparison`. Both sides
serialise to JSON; both sides discard the output (`slog` →
`io.Discard`, `audit` → `testhelper.NoopOutput`).

### Methodology — fair comparison notes

- **Synchronous delivery on both sides.** The audit library
  defaults to async delivery (drain goroutine), so the default
  `BenchmarkAudit` number charges caller-side enqueue cost only.
  That is the number consumers should cite when they care about
  caller-thread latency — but it is not directly comparable to
  `slog.Logger.Info`, which serialises and writes inline. Every
  audit sub-benchmark in the comparison uses
  `audit.WithSynchronousDelivery()` so the full
  `serialise → fan-out → post-field → HMAC → Write` pipeline
  runs on the benchmark's critical path, exactly like `slog`.
- **Zero drops.** Each audit sub-benchmark asserts
  `NoopOutput.Writes() == b.N` at `b.StopTimer`. A silent drop
  makes the ns/op a lie; synchronous delivery + the assertion
  together make drops impossible without failing the benchmark.
- **Sample size.** `count=10`, `benchtime=1s` on AMD Ryzen 9
  7950X, Linux 6.14. Benchstat confidence intervals are
  published in `bench-baseline.txt`; medians below.
- **slog's fast path is represented.** `slog.LogAttrs` with a
  pre-constructed `[]slog.Attr` is slog's documented fast path
  and is shown alongside the ergonomic `logger.Info(k, v, ...)`
  form so the comparison includes slog's best number.
- **What is NOT shown.** The audit library's compile-time fast
  path (`cmd/audit-gen`-generated typed builders that satisfy
  the `FieldsDonor` interface) is not represented here, because
  a pure-test shim cannot fairly stand in for generated code.
  Generated builders avoid the `audit.Fields{...}` literal
  allocation and reduce total allocations further; see
  [`docs/performance.md`](docs/performance.md) and the
  `BenchmarkAudit_FastPath_*` family for the fast-path numbers
  (measured against the same fan-out / HMAC configurations).

### Numbers — median of count=10

| Scenario | ns/op | B/op | allocs/op |
|----------|------:|-----:|----------:|
| `slog/3fields` | 490 | 0 | 0 |
| `audit/3fields_sync` | 814 | 24 | 1 |
| `slog/10fields` | 981 | 208 | 1 |
| `slog/10fields_LogAttrs` | 879 | 208 | 1 |
| `audit/10fields_sync` | 1736 | 24 | 1 |
| `audit/10fields_sync_WithHMAC` | 2178 | 88 | 2 |
| `audit/10fields_sync_FanOut4` | 1925 | 24 | 1 |

### Interpretation

- **`slog` is ≈ 1.7–1.8 × faster per synchronous call** at every
  matched payload size. This is expected: `slog.JSONHandler` does
  less work per event than this library does. It does not
  validate field names against a taxonomy, does not inject
  framework fields, does not compute HMAC, does not fan out, and
  does not route by category. The headline number is the cost of
  everything the audit library does that slog does not — priced
  honestly.
- **Memory footprint flips the other way.** The audit library's
  single remaining 24 B allocation is the `*basicEvent` wrapper
  escaping through the `Event` interface return from `NewEvent`;
  the pipeline scratch buffers come from `sync.Pool` and
  contribute 0 B/op to the per-event total. slog's 208 B at 10
  fields is a heap-allocated `[]slog.Attr` overflow once its
  `nAttrsInline = 5` inline array is exceeded. Lower byte churn
  translates to less GC pressure under sustained throughput —
  real but secondary to the ns/op story.
- **`LogAttrs` is slog's fast path, and it helps.** Pre-constructed
  `[]slog.Attr` drops slog's 10-field call from 981 ns → 879 ns
  (~10 %) by skipping variadic Attr pairing. The audit library has
  an analogous compile-time fast path (generated builders) that is
  not shown here for the reason documented in *Methodology*.
- **HMAC costs ≈ 442 ns at 10 fields** (2178 − 1736). This is the
  cost of tamper-evidence (`HMAC-SHA-256` over the full
  event bytes + authenticated `_hmac_version` salt version), amortised
  via pre-allocated state. There is no `slog` equivalent to
  compare against.
- **Fan-out to 4 outputs costs ≈ 63 ns per extra output**
  (1925 − 1736 = 189 ns for 3 additional outputs, divided by 3).
  The formatter cache (#499) means the shared-formatter outputs
  all use one serialisation; marginal cost per output is
  post-field assembly + one `NoopOutput.Write`. There is no slog
  equivalent (slog handlers can chain via a custom handler, but
  multi-output fan-out is not a first-class slog construct).
- **Caller-side latency (the async case) is markedly lower.**
  Under the library's default `WithSynchronousDelivery` = false,
  the caller returns after a channel enqueue (~400 ns, measured
  by `BenchmarkAudit`) and the ~1700 ns of serialisation happens
  on the drain goroutine — an intentional design choice for
  hot-path API handlers where *caller latency* matters more than
  total CPU. This number is compared to `slog` above only with
  synchronous delivery on both sides, for apples-to-apples; the
  default async number is available in the `### Core Audit Path`
  table earlier in this document.

### What you give up going to `slog`

The ns/op is the headline. It is not the reason to choose this
library. `slog` is a logging library; this library is an audit
library. The functionality delta:

- **Taxonomy validation.** A typo in a field name (`actor_ID`
  instead of `actor_id`) is silently accepted by `slog`; this
  library rejects it at runtime (`ValidationStrict`) or logs a
  warning (`ValidationWarn`). The `cmd/audit-gen` generator
  further pushes validation to compile time.
- **Required / optional fields.** `slog` has no notion of
  required keys; a missing `actor_id` is accepted. The audit
  library rejects the event before it enters the drain.
- **Framework fields.** Event ID, hostname, schema version,
  timestamp, category — all injected by the library, not the
  caller. `slog` requires the caller to add every field.
- **Fan-out to heterogeneous outputs.** File, syslog, webhook,
  Loki, and custom outputs in one call, with per-output
  filtering, formatting, and HMAC salts. `slog` handlers chain,
  but multi-output fan-out is a bring-your-own problem.
- **HMAC tamper-evidence.** Integrity signatures per output
  with rotatable salts. No `slog` equivalent.
- **Sensitivity labels.** Per-field classification and
  per-output strip rules (drop PII from syslog but keep it in a
  secure webhook sink, for example). No `slog` equivalent.
- **Async, bounded-queue delivery.** Bounded channel with drop
  rate limiting on buffer full, back-pressure metrics, graceful
  drain on close. `slog` is synchronous by default; async
  delivery is a bring-your-own handler.
- **Config-driven outputs.** `outputconfig.yaml` declares sinks
  externally, no recompile. `slog` handlers are wired in Go.
- **Metrics.** `OutputMetrics` interface (drops, flushes,
  errors, retries, queue depth) per output, pluggable into any
  metrics backend.

### Recommendation

- Use **`log/slog`** when you want general-purpose structured
  logging and do not need validation, fan-out, or integrity.
- Use **`github.com/axonops/audit`** when the log records are
  *audit* records — when it matters that every event has the
  required fields, that the record format is stable, that
  multiple tamper-evident sinks receive the same event, and
  that the cost of a schema change is caught at build time by
  `cmd/audit-gen` rather than at incident-response time by the
  auditor. The ~1.7–2 × synchronous-call overhead is the price
  of those guarantees.

This comparison is rerun on every `make bench-compare`
invocation. Because one side of the comparison is the Go
standard library, an upstream slog change can show up as a
regression on `slog/*` baseline lines — rebaseline on Go version
bumps, not as an audit-library signal.

---

## History

| Date | Commit | Change | Audit allocs | JSON allocs |
|------|--------|--------|-------------:|------------:|
| 2026-03-28 | ad18b6f | Initial baseline (10 new benchmarks) | 14 | 26 |
| 2026-03-28 | c2711e7 | *EventDef pointers + pre-computed fields (#109, #107) | 13 | 25 |
| 2026-03-28 | 21e6828 | Lock-free filter (syncmap) + atomic route (#100, #110) | 14 | 25 |
| 2026-03-28 | 636db3e | Buffer pooling + writeJSONString + CEF single-pass (#101) | ~4 | **1** |
| 2026-03-28 | — | sync.Pool for auditEntry + fix flaky test (#112) | **3** | 1 |
| 2026-04-03 | a6e759c | JSON append: writeJSONString + pooled buffer (#229) | 4 | 1 |
| 2026-04-18 | 2a8625c | Track A refresh + pool/allocator settled (#493) | **2** | 1 |
| 2026-04-03 | 7aa14b7 | HMAC hash reuse + pre-allocated buffers (#230) | 4 (5 w/HMAC) | 1 |

---

## iouring submodule

Added in #510 as part of the file-output batch-coalescing fast path.
See [ADR 0002](docs/adr/0002-file-output-io-uring-approach.md) for
the design context. Benchmarks run via:

```bash
cd iouring && go test -bench BenchmarkWriter_Writev -benchmem -count=5
```

### Platform / target

- CPU: AMD Ryzen 9 7950X 16-Core (32 threads)
- OS: Linux kernel 6.14
- Target filesystem: `/dev/shm` (tmpfs) — isolates syscall overhead
  from device-write cost. Real-disk numbers differ.
- Payload: 256-byte events, parametric batch size.

### Results (count=5, median ns/op, zero allocations every path)

| Strategy | Batch | ns/op | MB/s | allocs/op |
|----------|------:|------:|-----:|----------:|
| iouring  | 1     | 6 404 |   40 | 0 |
| iouring  | 4     | 6 810 |  150 | 0 |
| iouring  | 16    | 8 133 |  504 | 0 |
| iouring  | 64    | 12 096 | 1 354 | 0 |
| iouring  | 256   | 29 861 | 2 195 | 0 |
| iouring  | 1 024 | 100 242 | 2 615 | 0 |
| writev   | 1     |   591 |  433 | 0 |
| writev   | 4     |   902 | 1 135 | 0 |
| writev   | 16    | 1 992 | 2 056 | 0 |
| writev   | 64    | 5 948 | 2 755 | 0 |
| writev   | 256   | 22 613 | 2 898 | 0 |
| writev   | 1 024 | 89 274 | 2 936 | 0 |

### Results — ext4 / NVMe (real disk)

Same harness, `IOURING_BENCH_DIR=/path/on/ext4 go test -bench …`.
Ryzen 9 7950X, Samsung 990 Pro NVMe, ext4 default mount options.

| Strategy | Batch | ns/op | MB/s |
|----------|------:|------:|-----:|
| iouring  | 1     | 6 928 |   37 |
| iouring  | 16    | 9 132 |  458 |
| iouring  | 64    | 16 267 | 1 007 |
| iouring  | 256   | 38 530 | 1 701 |
| iouring  | 1 024 | 135 583 | 1 933 |
| writev   | 1     |   740 |  346 |
| writev   | 16    | 2 678 | 1 509 |
| writev   | 64    | 8 663 | 1 891 |
| writev   | 256   | 31 447 | 2 084 |
| writev   | 1 024 | 127 160 | 2 062 |

### Interpretation

- **Zero allocations on the hot path** for every strategy and
  every batch size. The pre-allocated iovec scratch on each
  writer eliminates per-call GC pressure.
- **`writev(2)` beats `io_uring` at every batch size**, on both
  tmpfs and real disk (ext4 / NVMe). At batch 1 the gap is 9.4×
  on ext4; at batch 1024 it narrows to ~1.07× but writev is
  still faster. The kernel's writev path is exceptionally
  optimised for buffered page-cache writes — a single syscall,
  a single memcpy-to-page-cache, minimal bookkeeping. io_uring
  adds SQE fill, atomic tail release, `io_uring_enter` round-
  trip, and CQE scan-match on top of the same write path.
- **Our pattern doesn't use io_uring's strengths.** The file
  output's writeLoop is single-goroutine submit-and-wait.
  io_uring's advantages require patterns we don't use: multiple
  in-flight submissions overlapping with slow I/O, SQPOLL,
  `IORING_OP_WRITE_FIXED` with registered buffers, or `O_DIRECT`
  against genuinely slow storage. On a modern kernel + NVMe
  SSD + buffered writev, there's nothing left for io_uring to
  overlap with.
- **Decision**: the file output's `rotate.Writer` constructs its
  iouring writer with `WithStrategy(StrategyWritev)` — the
  measured-faster path. The io_uring primitive is still shipped
  for post-v1.0 use cases that genuinely benefit (WAL with
  multi-writer overlap, fsync pipelining, O_DIRECT).
- **AC #5 on the parent issue asked for ≥ 20 % speedup of
  `BenchmarkFileOutput_Writev_Iouring` vs `_Stdlib` at batch 10 k
  on tmpfs.** The gate was unsatisfiable as written — see ADR
  0002 for the formal refinement. The *primitive* is shipped;
  the **end-to-end batch-coalescing pipeline is the real win**:
  N events amortise into one `writev(2)` syscall instead of N,
  independent of which strategy is selected.

### Concurrency overhead

| Benchmark | ns/op | Notes |
|-----------|------:|-------|
| `BenchmarkPackage_Writev_Concurrent` | ~640 | 32 parallel producers through the default-writer mutex |
| `BenchmarkWriter_Writev_OwnInstance` | ~580 | one writer per producer goroutine |

The default-writer mutex adds ~60 ns of overhead per call under
contention. Callers that expect sustained parallel throughput
should construct their own `iouring.New()` writer per producer.
