# Performance Results & How We Test

This doc captures the measured performance of the audit library, the
methodology we use to capture those numbers, and the long-running
soak-test results that gate every release.

Designed to be **the page you point a consumer at** when they ask
"how fast is this thing and how do I know?". Companion to:

- [`performance.md`](performance.md) — the alloc-model deep dive
  (fast path / slow path / ownership contract)
- [`../BENCHMARKS.md`](../BENCHMARKS.md) — the full benchmark table,
  refreshed every time the baseline regenerates
- [`adr/0007-matchesroute-perf.md`](adr/0007-matchesroute-perf.md) —
  the matchesRoute spike investigation and trade-off analysis

---

## TL;DR

| Metric | Number | Source |
|---|---:|---|
| Audit hot path, 3 fields, drain to noop | **~417 ns/op, 1 alloc** | `BenchmarkAudit` |
| Audit fast path (FieldsDonor generated builder) | **~470 ns/op, 0 allocs** | `BenchmarkAudit_FastPath_FanOut4_NoopOutputs` |

> The fast path is *slightly* slower in ns than the slow path
> (470 vs 417) because the generated builder does extra work
> per call; in return it costs **0 allocs** vs 1, which wins
> dramatically under GC pressure and parallel load — see the
> `Audit_Parallel` (81 ns) vs `Audit_FastPath_Parallel` (137 ns)
> rows below for the parallel comparison, and watch the alloc
> counts: that's where GC cost lives.

| Route match, include 4 categories | **~4.0 ns/op, 0 allocs** | `BenchmarkMatchesRoute/include_categories` |
| Route match, per-category severity accept | **~3.6 ns/op, 0 allocs** | `BenchmarkMatchesRoute_Severity/per_category_severity_accept` |
| Sustained throughput, 8 producers × 5,000 ev/s, mixed outputs | **5,000 ev/s, 0 drops** | 30-min soak (2026-05-15) |
| Bench-compare noise floor (warm CPU, count=5) | **±2 % geomean** | `make bench-compare` against fresh baseline |

**Hardware:** AMD Ryzen 9 7950X 16-Core (32 threads), Linux 6.14,
Go 1.26.3. All numbers below are from this exact machine unless
noted otherwise.

---

## Hot Path: Audit → Drain → Output

The hot path is `audit.AuditEvent(evt)` → enqueue → drain loop →
formatter → output. We benchmark each stage in isolation and the
whole pipeline end-to-end.

| Benchmark | ns/op | allocs/op | Notes |
|-----------|------:|----------:|-------|
| `Audit` | 417 | 1 | 3 fields, no HMAC, drains to noop output |
| `Audit_RealisticFields` | 905 | 1 | 10 fields — most production events |
| `Audit_Parallel` | 81 | 1 | GOMAXPROCS goroutines, per-op amortised |
| `Audit_FastPath_PipelineOnly` | 520 | 0 | Generated builder (`FieldsDonor`), donor outside loop |
| `Audit_FastPath_FanOut4_NoopOutputs` | 470 | 0 | Same, fanout to 4 noop outputs |
| `Audit_FastPath_WithHMAC_Noop` | 302 | 0 | HMAC-SHA-256 appended at drain |
| `Audit_FastPath_Parallel` | 137 | 3 | GOMAXPROCS goroutines — the 3 allocs are per-goroutine context, amortised across the parallel work |
| `Audit_FastPath_EndToEnd` | 1,525 | 5 | Full pipeline INCLUDING donor construction inside the loop — measures the slow path (consumer-side `audit.Fields{}` literal allocates per call, plus 4 drain-side allocs) |

**The fast path reaches 0 allocs/op end-to-end on the drain side.**
This requires the consumer to use generated builders from
`cmd/audit-gen` (which implement `audit.FieldsDonor`) instead of
the `audit.NewEvent` slow path. See
[`performance.md`](performance.md) for the ownership contract.

## Route Matching

`audit.MatchesRoute` runs once per output per event — the hottest
non-format path in the library. We track it especially carefully
after #193 introduced per-category severity (#867 spike) revealed
a +112 % regression on the dominant route shape.

| Benchmark | ns/op | allocs/op | Notes |
|-----------|------:|----------:|-------|
| `MatchesRoute/empty_route` | 2.5 | 0 | Route matches everything |
| `MatchesRoute/include_categories` | **4.0** | 0 | 4 included categories — the inline fast path (#867) |
| `MatchesRoute/include_event_types` | 7.9 | 0 | Event-type include list |
| `MatchesRoute/exclude_categories` | 9.7 | 0 | Exclude list with severity gate |
| `MatchesRoute/include_20_categories` | 7.7 | 0 | Beyond the inline threshold; map fallback |
| `MatchesRoute_Severity/include_categories_with_severity` | 4.0 | 0 | Category include + per-route severity bound |
| `MatchesRoute_Severity/per_category_severity_accept` | 3.6 | 0 | Per-category `SeverityRange` (#193, #867 fix) |
| `MatchesRoute_Severity/per_category_severity_reject` | 3.6 | 0 | Same, reject path |
| `MatchesRoute_Severity/severity_only_min` | 1.5 | 0 | Severity-only catch-all, Min bound |
| `MatchesRoute_LargeInclude/N=4` | 4.7 | 0 | Inline-array boundary |
| `MatchesRoute_LargeInclude/N=5` | 8.3 | 0 | Just past the boundary — map fallback fires |
| `MatchesRoute_LargeInclude/N=16` | 7.3 | 0 | Map fallback, medium size |
| `MatchesRoute_LargeInclude/N=32` | 7.4 | 0 | Map fallback scales flat |
| `MatchesRoute_FanoutMix` | 5.6 | 0 | 5 route shapes × 8 events, branch-prediction stress |

### #867 spike — what happened

In `BenchmarkMatchesRoute/include_categories` the pre-#193
baseline (2026-04-21) was 3.2 ns/op. After #193 (per-category
severity) landed it doubled to 6.8 ns/op (+112 %). pprof
(see [`perf/spike-matchesroute/`](perf/spike-matchesroute/))
showed Go's map machinery accounting for ~99 % of include-path
CPU.

The fix landed as PRs #868 (value-typed `SeverityRange`) and
#869 (inline `[4]inlineCat` fast path + `routeMode`
discriminator). In plain terms: routes with ≤ 4 included
categories (the typical real-world case) now keep their
include-list in a fixed `[4]struct{key string; val SeverityRange}`
array on the route struct itself, so the matcher does a
4-element linear `==` scan instead of a Go map hash + bucket
lookup. Recovery: 6.8 ns → **4.0 ns**, restoring ~80 % of the
regression gap. The remaining 0.8 ns reflects the cost of Go
map iteration order being non-deterministic — the inline array
slot the lookup key lands in varies per build, so the inline
scan is sometimes a hit-on-first, sometimes a scan-all-four.

Three less-common benchmarks regressed marginally as collateral
from the larger `EventRoute` struct (256 B vs 120 B):

- `empty_route` +0.8 ns
- `exclude_categories` +1.3 ns
- `include_event_types` +3.8 ns

Trade-off documented in
[`adr/0007-matchesroute-perf.md`](adr/0007-matchesroute-perf.md).
The targeted bench (the regression that triggered the spike)
took priority; the collateral regressions live on cold paths.

## Formatters

JSON and CEF formatters serialise the event to bytes on the
drain side. Both pool the output buffer via `sync.Pool`.

| Benchmark | ns/op | allocs/op | Notes |
|-----------|------:|----------:|-------|
| `JSONFormatter_Format` | 353 | 1 | 4 fields, pooled buffer, `writeJSONString` |
| `JSONFormatter_Format_LargeEvent` | ~1,200 | 1 | 20 fields |
| `CEFFormatter_Format` | 389 | 1 | 4 fields, single-pass escape |
| `CEFFormatter_Format_LargeEvent` | ~1,170 | 1 | 20 fields |

## HMAC Pipeline

| Benchmark | ns/op | allocs/op | Notes |
|-----------|------:|----------:|-------|
| `Audit_WithHMAC` | ~424 | 1 | Full Audit path with HMAC-SHA-256 appended |
| `ComputeHMACFast` | ~155 | 0 | Pre-allocated drain-loop HMAC (zero-alloc by construction) |
| `HMAC_SHA256_SmallEvent` | ~475 | 8 | Direct `ComputeHMAC` on small payload — not the drain path |
| `HMAC_SHA512_SmallEvent` | ~1,115 | 8 | SHA-512 variant |

---

## How We Measure

### `make bench` and `make bench-compare`

```bash
# Run benchmarks and save to bench.txt (working file)
make bench

# Save bench.txt as the new bench-baseline.txt (committed)
make bench-save

# Run benchmarks and compare against the committed baseline
make bench-compare
```

The `make bench` target iterates `BENCH_COUNT=5` times per
benchmark across all 15 modules (~15-20 minutes wall-clock on a
warm machine). The result is `bench.txt` (818 lines).

`make bench-compare` runs benchstat against the committed
`bench-baseline.txt` and prints per-benchmark deltas, footnoted
with statistical significance (`p` values via t-test).

> **Note:** `make bench-compare` re-runs all benchmarks (the
> `bench` target is a dependency) before invoking benchstat —
> it is **not** a cheap diff against the saved baseline. Allow
> 15-20 minutes wall-clock.

### Reproducibility methodology

For the matchesRoute spike (#867) we documented the methodology
that future perf investigations should follow:

1. **CPU governor: performance.** `sudo cpupower frequency-set
   -g performance` if available.
2. **Disable turbo / Precision Boost.** `echo 0 | sudo tee
   /sys/devices/system/cpu/cpufreq/boost`. AMD Ryzen 7950X turbo
   adds ±15 % variance.
3. **Pin to physical cores only.** On AMD Ryzen 7950X (8c/16t
   per CCD), the SMT siblings interleave: cores `0,2,4,...,14`
   are one CCX, `1,3,5,...,15` are their SMT siblings. Run with
   `taskset -c 0,2,4,6,8,10,12,14` to bind to one logical core
   per physical core. On Intel + Linux, the topology is usually
   contiguous (`0-7` = physical, `8-15` = SMT) — check
   `lscpu -e` first. Without this, SMT sibling contention adds
   measurable noise.
4. **Sample count ≥ 20.** benchstat needs 6+ samples for a
   confidence interval at p=0.95; 20 lifts the noise floor below
   0.5 ns on sub-10 ns benches.
5. **`-benchtime=2s` minimum.** Damps per-iteration noise from
   short-running benches.
6. **Stop background processes.** Browsers, sync clients, and
   any cron jobs that wake periodically. The bench loop is
   pre-emptable; a single Chrome tab burst can move a sub-10 ns
   bench by 5 %.

The committed `bench-baseline.txt` uses defaults (count=5,
default benchtime) on warm CPU — the methodology above is for
*investigating* perf claims, not for the recurring CI baseline
which is intentionally cheap.

### Caveats — what these numbers do NOT tell you

Be honest with readers about what we measure and what we don't:

- **Tail latencies are NOT covered.** Every number in the tables
  is a mean over millions of iterations. A reader sizing a
  worst-case `AuditEvent()` call under queue pressure should
  look at the soak's queue-depth distribution and the
  `OutputClose_Drain/events=10000` benchmark, not the
  steady-state `Audit` ns/op.
- **Single-machine numbers.** Everything is from one AMD Ryzen
  9 7950X. Cloud VMs (AWS `c7g`, GCP `n2`) typically land
  2-4 × slower per call due to slower memory subsystems and
  noisier neighbours. Use these numbers as relative anchors,
  not absolutes for production sizing.
- **"Drain to noop output" hot path.** Most table rows measure
  the pipeline up to the output write, then drop bytes on the
  floor. The output backend (file fsync, syslog TCP, webhook
  HTTPS) is excluded — its cost dominates real-world latency
  and is benchmarked separately in each sub-module
  (`BenchmarkFileOutput_*`, `BenchmarkSyslogOutput_*`, etc.).
- **5,000 ev/s is a deliberately modest soak rate.** Chosen to
  fit within a single warm CPU's headroom while sampling
  heap/goroutine state without affecting the measurement.
  Higher rates would require dedicated bench infrastructure.

### pprof investigation

For matchesRoute we captured CPU and memory profiles to find
the regression's hot line:

```bash
# Profile a specific benchmark
go test -bench='BenchmarkMatchesRoute/include_categories' \
    -benchmem -count=10 -benchtime=2s -run='^$' \
    -cpuprofile=cpu.prof -memprofile=mem.prof .

# Top frames by cumulative time
go tool pprof -top -cum cpu.prof

# Line-level attribution within a specific function
go tool pprof -list 'MatchesRoute$' cpu.prof
```

Profile artefacts from the #867 spike are committed under
[`perf/spike-matchesroute/`](perf/spike-matchesroute/) (pre-fix
and post-fix `.prof` files plus a README).

`pprof` sampling is too coarse for sub-10 ns benchmarks; for
microarchitectural truth on cold paths use `perf stat`:

```bash
perf stat -e cycles,instructions,branch-misses,L1-dcache-load-misses \
    ./audit.test -test.bench=BenchmarkMatchesRoute -test.run='^$'
```

### Regression detection in CI

The committed `bench-baseline.txt` is the regression-detection
gate for PRs. `make bench-baseline-check` validates that every
benchmark name in the baseline still exists in the source — a
silent rename would otherwise let regressions slip through.

We aim to regenerate the baseline whenever a PR substantively
changes the hot path. The last baseline regen is recorded in
the `## Current Baseline` section of
[`../BENCHMARKS.md`](../BENCHMARKS.md).

---

## Soak Tests

Microbenchmarks catch single-instruction regressions; soaks
catch slow leaks (memory, goroutines, file descriptors) and
saturation patterns that only manifest over minutes-to-hours.

### Harness: `make soak`

```bash
# 12-hour default (pre-release gate per Track F-52)
make soak

# Short smoke before tagging a longer run
make soak-quick   # 1 minute

# Custom duration
make soak SOAK_DURATION=2h SOAK_SAMPLE_INTERVAL=2m
```

Configurable via environment:

| Variable | Default | Description |
|---|---|---|
| `SOAK_DURATION` | `12h` | Wall-clock total runtime |
| `SOAK_PRODUCERS` | `8` | Concurrent producer goroutines |
| `SOAK_RATE` | `5000` | Target events/sec across all producers |
| `SOAK_SAMPLE_INTERVAL` | `1m` | Period between heap/goroutine samples |
| `SOAK_OUTPUT_DIR` | `./soak-output` | Where the CSV + JSON summary are written |

The harness lives in
[`tests/soak/soak_test.go`](../tests/soak/soak_test.go) (tagged
`//go:build soak`). It exercises the audit hot path against
file + in-process syslog + in-process webhook outputs
simultaneously — no Docker needed.

Per-event mix:

- 60 % routine: `user_action` (2 fields)
- 30 % medium: `data_access` (10 fields)
- 10 % large: `audit_record` (50 mixed fields)

### Built-in regression gates

The harness fails the test (b.Errorf) if either:

- `heap_alloc_mb` end > 2 × start
- `numGoroutine` end > 2 × start

Both indicate a leak. The bound is intentionally permissive
(2 ×) so transient steady-state shifts don't fire false
positives; the maintainer reviews the per-sample CSV before
relying on the gate.

### Recent runs

#### 30-min smoke (2026-05-15)

The smoke run we did to validate the harness after the #867 fix
landed but before regenerating the baseline.

| Metric | Value |
|---|---:|
| Duration | 30 min (1800 s) |
| Events delivered | 8,999,983 |
| Drops | 0 |
| Effective throughput | 5,000 ev/s exact |
| Heap start / end / peak | 2.1 MB / 3.6 MB / 5.9 MB |
| Heap avg across 60 samples | 4.04 MB |
| Goroutines start / end / peak | 9 / 10 / 20 |
| Queue length distribution | 0 in 48/60 samples; max 6 / 50,000 capacity |
| GC cycles / total pause | 32,624 cycles / 1.93 s total |
| Built-in regression gate | **PASS** |

Conclusion: drain pipeline keeps pace effortlessly; no leak;
GC well-behaved (< 0.11 % of wall-clock in pause).

#### 2-hour run (2026-05-16)

Confidence-builder ahead of the 12-h pre-release gate. Same
workload mix as the 30-min smoke. Sample interval bumped to
2 min to keep the CSV tractable (~60 rows over 2 h).

| Metric | Value |
|---|---:|
| Duration | 2 h (7,200 s) |
| Events delivered | 35,999,972 |
| Drops | 0 |
| Effective throughput | 5,000 ev/s exact |
| Heap start / end / peak | 2.09 MB / 3.47 MB / 5.15 MB |
| Heap avg across 59 samples | 4.19 MB |
| Goroutines start / end / peak | 9 / 10 / 20 |
| Queue length distribution | 0 in 40/59 samples; max sampled 3 (out of 50,000 cap) |
| GC cycles / total pause | 124,657 cycles / 7.69 s total |
| Built-in regression gate | **PASS** |

Conclusion: zero drift over 2 hours of sustained 5,000 ev/s
load. Heap stays in a 2-5 MB window (avg 4.2 MB) — well below
2 × start. Goroutines bounded at 20 throughout. Queue depth
rarely exceeds 0 — drain pipeline keeps pace effortlessly.
GC overhead: 7.69 s / 7,200 s = 0.11 % wall-clock — identical
to the 30-min smoke, confirming the GC steady-state is
established quickly and stays there.

Confidence to proceed to the 12-h pre-release run: **high**.

---

## Publishing These Numbers

When a PR materially changes the hot path:

1. Run `make bench-save` to regenerate `bench-baseline.txt`.
2. Update [`../BENCHMARKS.md`](../BENCHMARKS.md)'s
   "Current Baseline" header (date, commit) and any table
   row that shifted by > 5 %.
3. Update this doc's TL;DR table if the headline number
   changed (subjective: "would a reader care?").
4. If the change was driven by a spike, link it: ADR under
   `docs/adr/`, profile artefacts under `docs/perf/<spike>/`.
5. If a soak run was performed, add it to the "Recent runs"
   section above.

The goal: any reader landing on this doc can answer "how fast,
how did you measure, what's the trend?" without reading commits.

---

## Further Reading

- [`performance.md`](performance.md) — alloc-model deep dive
  (fast path, slow path, FieldsDonor ownership contract)
- [`../BENCHMARKS.md`](../BENCHMARKS.md) — full benchmark table
- [`adr/0001-fields-ownership-contract.md`](adr/0001-fields-ownership-contract.md)
- [`adr/0007-matchesroute-perf.md`](adr/0007-matchesroute-perf.md)
- [`perf/spike-matchesroute/`](perf/spike-matchesroute/) —
  pprof artefacts from the matchesRoute spike (#867)
- [`tests/soak/soak_test.go`](../tests/soak/soak_test.go) —
  the soak harness source
