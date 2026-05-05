[← Back to README](../README.md)

# Event Emission Paths

The `audit` library exposes three ways to emit an event. Each
trades type-safety, metadata access, and allocation cost
differently. This document describes each path, when to use it,
and the measured cost so you can choose deliberately.

## Three paths at a glance

| Path | Type-safety | Metadata access | Caller-side allocs | Drain-side allocs | Best for |
|------|------------|-----------------|--------------------|--------------------|----------|
| Generated builders ([`cmd/audit-gen`](code-generation.md)) | Compile-time | Full | 1 alloc (the typed builder struct + Fields literal) | 0 (the `FieldsDonor` fast path transfers ownership) | Event types known at compile time |
| [`EventHandle`](https://pkg.go.dev/github.com/axonops/audit#EventHandle) (via [`Auditor.Handle`](https://pkg.go.dev/github.com/axonops/audit#Auditor.Handle) / [`MustHandle`](https://pkg.go.dev/github.com/axonops/audit#Auditor.MustHandle)) | Validated once at startup | Full (cached on the handle) | 0 (post-warm-up; no interface escape) | 1 (defensive Fields copy) | Event types known at startup but not at compile time |
| [`NewEvent`](https://pkg.go.dev/github.com/axonops/audit#NewEvent) / [`NewEventKV`](https://pkg.go.dev/github.com/axonops/audit#NewEventKV) | Runtime only | None (taxonomy-agnostic) | 1 (`basicEvent` interface escape); `NewEventKV` adds the intermediate `Fields` map | 1 (defensive Fields copy) | Ad-hoc / exploratory emission, plugin code, tooling |

Cost differences are small in absolute terms (tens of ns/op). The
recommendation is about CONTRACT first — type safety, metadata
access, error semantics — and allocation cost second. High-throughput
callers on the dynamic path will see the difference at scale; most
callers will not.

## Path 1 — Generated typed builders

The recommended path when event types are known at compile time.
[`cmd/audit-gen`](code-generation.md) reads the YAML taxonomy and
emits typed Go builders: required fields are constructor parameters,
optional fields are setter methods, and the generated event satisfies
the unexported `donateFields()` sentinel that lets the drain take
ownership of the `Fields` map without copying — the **`FieldsDonor`
fast path**.

```bash
# Run audit-gen once; check the generated file in (or regenerate
# via `go generate` from a //go:generate directive on a stub file).
go run github.com/axonops/audit/cmd/audit-gen \
    -taxonomy taxonomy.yaml \
    -out audit_generated.go
```

```go
// In a file in the same package as audit_generated.go:
auditor.AuditEvent(
    NewUserCreateEvent("alice", "success").
        SetTargetID("user-42"),
)
```

What you get:

- **Compile-time field safety.** Misspelling a field name or missing
  a required field is a compile error, not a runtime audit-validation
  error.
- **Full metadata.** Generated events carry `Description()`,
  `Categories()`, and `FieldInfoMap()` — middleware that redacts
  based on field sensitivity labels can introspect without an extra
  taxonomy lookup.
- **Zero drain-side allocations** after warm-up: the drain takes
  ownership of the donor's `Fields` map instead of defensively
  copying.

See [`docs/code-generation.md`](code-generation.md) for the
audit-gen workflow.

## Path 2 — `EventHandle`

Use when the event type is known at **startup** but not at compile
time — typically when the type name comes from configuration, a
database, or a plugin registry.

```go
// At startup (DI wiring).
loginHandle := auditor.MustHandle("user_login")

// Per request.
_ = loginHandle.Audit(audit.Fields{
    "actor_id": userID,
    "outcome":  "success",
})
```

The handle validates the event type once at construction; per-event
calls go straight into the audit pipeline without re-validating the
name and without the `basicEvent` heap allocation that `NewEvent`
pays via interface escape.

`MustHandle` panics on unknown event type — acceptable in startup /
DI code where misconfiguration should fail fast at boot. Use
`Handle` (returns an error) when handle lookup is data-driven and
the error must surface.

A handle's metadata accessors (`Description`, `Categories`,
`FieldInfoMap`) return the same values the generated builder would —
both paths are taxonomy-aware.

## Path 3 — `NewEvent` / `NewEventKV`

The dynamic escape hatch. Use when the event type or the field set
is fully dynamic — for example, in tooling that replays events from
a wire log, in test code, or in plugin code that does not know the
event type at startup.

```go
// Map literal — most flexible.
_ = auditor.AuditEvent(audit.NewEvent("user_login", audit.Fields{
    "actor_id": userID,
    "outcome":  "success",
}))

// Alternating key-value pairs (slog convention) — concise but
// returns an error on odd-arity input or non-string keys.
ev, err := audit.NewEventKV("user_login",
    "actor_id", userID,
    "outcome", "success",
)
if err != nil {
    return err
}
_ = auditor.AuditEvent(ev)
```

Both functions return a taxonomy-agnostic event:
`Description()` returns `""`, `Categories()` returns `nil`,
`FieldInfoMap()` returns `nil`. To access metadata dynamically, pair
with [`Auditor.Handle`](https://pkg.go.dev/github.com/axonops/audit#Auditor.Handle).

`NewEventKV` allocates the intermediate `Fields` map plus the
`basicEvent` returned by `NewEvent` — two heap allocations per call
(plus any-boxing of non-string values). For literal known-good call
sites in tests or examples,
[`MustNewEventKV`](https://pkg.go.dev/github.com/axonops/audit#MustNewEventKV)
panics on programmer error and reads as a single-line expression.

## Decision

Walk the questions top to bottom:

1. **Are the event types known at compile time?** → Use generated
   builders. Type-safe, zero drain-side allocations, full metadata.
2. **Are they known at startup but not at compile time?** → Use
   `EventHandle`. Validated once, zero per-call allocations, full
   metadata.
3. **Are they fully dynamic?** → Use `NewEvent` (preferred for the
   common map case) or `NewEventKV` (when the slog-style varargs
   reads better than a map literal).

Mixed code is fine: most consumers use generated builders for
core events and reach for `EventHandle` or `NewEvent` only for
the genuinely dynamic cases.

## Allocation cost

Numbers are approximate — see [`BENCHMARKS.md`](../BENCHMARKS.md)
for the canonical figures per release. The runs below are from
AMD Ryzen 9 7950X / Go 1.26.2 with `NoopOutput` to isolate
emission-path cost from output cost.

`BenchmarkAudit_ViaHandle_vs_NewEvent` (same auditor, same fields,
3-field event):

```
NewEvent + AuditEvent      ~440 ns/op      24 B/op      1 allocs/op
EventHandle.Audit          ~415 ns/op       0 B/op      0 allocs/op
```

The single allocation difference is the `basicEvent` that escapes
through the `Event` interface return of `NewEvent`. `EventHandle.Audit`
calls into the audit pipeline directly without the interface
wrapping.

`BenchmarkAudit_FastPath_PipelineOnly` (10-field event constructed
once outside the loop, donor implementing `FieldsDonor`):

```
Generated builder fast path    ~520 ns/op      0 B/op      0 allocs/op
```

> **Caveat:** this benchmark deliberately re-uses a single builder
> across iterations to isolate pipeline cost. **Production callers
> MUST construct a fresh builder per `AuditEvent` call** — the
> drain takes ownership of the donor's `Fields` map and may
> recycle it via `sync.Pool`. Reusing a builder violates the
> single-use contract; the benchmark only does so to expose the
> pipeline floor.

The benchmark uses 10 fields where the previous one uses 3, so
the higher ns/op is field-count overhead, not path overhead. The
generated-builder advantage is on the **drain side** — the drain
takes ownership of the `Fields` map without copying — which is
invisible to the caller-side benchmarks above. Throughput-sensitive
consumers (>10K events/s) should pair generated builders with the
FastPath benchmark methodology in
[`docs/performance.md`](performance.md).

## Common gotchas

- **`AuditEvent` is non-blocking and can drop on backpressure.**
  All three paths feed the same async pipeline. When the internal
  buffer is full, the event is dropped and a metric is recorded;
  the call returns nil regardless. Consumers that need synchronous
  delivery semantics MUST opt in via
  [`audit.WithSynchronousDelivery`](https://pkg.go.dev/github.com/axonops/audit#WithSynchronousDelivery).
  This affects every emission path equally — not specific to one
  path's choice.
- **`MustHandle` panics on unknown types.** Use it in startup code
  where boot-time misconfiguration should fail loudly. Use `Handle`
  (returns an error) when the handle lookup is data-driven.
- **`NewEventKV` returns `error`; `NewEvent` does not.** The
  asymmetry trips people up. `NewEvent` cannot fail —
  malformed `Fields` are caught at audit-validation time. `NewEventKV`
  can fail at construction (odd-arity input or non-string keys), so
  it returns an `(Event, error)` pair. For literal call sites with
  known-good input, `MustNewEventKV` panics on error and reads as a
  one-line expression.
- **`NewEvent` / `NewEventKV` events have no metadata.**
  `Description()`, `Categories()`, and `FieldInfoMap()` return zero
  values. Middleware that needs metadata must either use generated
  builders, use `EventHandle`, or look up metadata via
  `Auditor.Handle` separately.
- **Defensive-copy semantics.** All paths defensively copy the
  caller's `Fields` map on enqueue, except generated builders that
  satisfy the `FieldsDonor` sentinel. Mutations to the caller's map
  after `AuditEvent` returns do not affect the queued event.
- **Generated builders are single-use per `AuditEvent` call.** After
  the auditor takes ownership of the donor's fields, the builder
  must not be reused (the `Fields` map may be cleared and recycled
  by `sync.Pool`). Construct a fresh builder per emission. Tests
  may reuse builders by violating this — see
  `BenchmarkAudit_FastPath_PipelineOnly` — but production code
  should not.

## See also

- [`docs/code-generation.md`](code-generation.md) — audit-gen
  workflow and generated builder reference.
- [`docs/performance.md`](performance.md) — full benchmark
  methodology and throughput targets.
- [`BENCHMARKS.md`](../BENCHMARKS.md) — canonical benchmark
  numbers per release.
- [`audit.Event`](https://pkg.go.dev/github.com/axonops/audit#Event)
  — interface every emission path produces.
- [`audit.Auditor.AuditEvent`](https://pkg.go.dev/github.com/axonops/audit#Auditor.AuditEvent)
  / [`audit.Auditor.AuditEventContext`](https://pkg.go.dev/github.com/axonops/audit#Auditor.AuditEventContext)
  — the entry points every path feeds.
