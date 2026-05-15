# Spike #867 — matchesRoute pprof artefacts

Committed under AC #1 of issue
[#867](https://github.com/axonops/audit/issues/867): "CPU and memory
profiles captured for BenchmarkMatchesRoute on a cold CPU; profile
artefacts committed under `docs/perf/spike-matchesroute/` for
traceability."

## Files

| File | Captured | Bench config | Top finding |
|---|---|---|---|
| `pre-fix-cpu.prof` | 2026-05-15 (PR-1 main) | `-count=10 -benchtime=2s` | `runtime.mapaccess2_faststr` 46.67% of total; `aeshashbody` 18.55%; line 305 (`route.IncludeCategories[category]`) at 191.91 s cumulative — the regression smoking gun |
| `pre-fix-mem.prof` | 2026-05-15 (PR-1 main) | `-count=10 -benchtime=2s` | 0 allocs/op on every sub-benchmark (no allocation regression — pure CPU) |
| `post-fix-cpu.prof` | 2026-05-15 (PR-2 branch) | `-count=10 -benchtime=2s` | `runtime.mapaccess2_faststr` drops from the top frames for the inline-eligible path; `matchesInclude` dispatched via routeMode switch |
| `post-fix-mem.prof` | 2026-05-15 (PR-2 branch) | `-count=10 -benchtime=2s` | 0 allocs/op preserved |

## How to inspect

```bash
# Top frames by cumulative time
go tool pprof -top -cum docs/perf/spike-matchesroute/post-fix-cpu.prof

# Line-level attribution within MatchesRoute
go tool pprof -list 'MatchesRoute$' docs/perf/spike-matchesroute/post-fix-cpu.prof

# Compare pre-fix vs post-fix line-level
go tool pprof -list 'MatchesRoute$' docs/perf/spike-matchesroute/pre-fix-cpu.prof  > /tmp/pre.txt
go tool pprof -list 'MatchesRoute$' docs/perf/spike-matchesroute/post-fix-cpu.prof > /tmp/post.txt
diff /tmp/pre.txt /tmp/post.txt
```

## Capture environment

- CPU: AMD Ryzen 9 7950X (Zen 4)
- OS: Linux 6.14
- Go: 1.26.3
- CPU governor: default (not pinned to `performance`)
- Turbo: default (not disabled)
- Pinning: none (no `taskset`)
- Benchmark warmth: warm CPU (run after other bench suites)

The post-PR-2 cold-CPU bench regen described in ADR 0007 will
produce a third capture under `cold-cpu-cpu.prof` / `cold-cpu-mem.prof`
when it lands as a follow-up commit on main with the refreshed
`bench-baseline.txt` and `BENCHMARKS.md` table.

See [`docs/adr/0007-matchesroute-perf.md`](../../adr/0007-matchesroute-perf.md)
for the full investigation, options considered, and trade-off
analysis.
