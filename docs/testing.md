[&larr; Back to README](../README.md)

# Testing Audit Events in Your Application

- [What Is audittest?](#what-is-audittest)
- [Why a Test Package?](#why-a-test-package)
- [Quick Start](#quick-start)
- [Dependency Injection](#dependency-injection)
- [Two Constructor Patterns](#two-constructor-patterns)
- [Recorded Event API](#recorded-event-api)
- [Assertion Helpers](#assertion-helpers)
- [Waiting for Async Events](#waiting-for-async-events)
- [Testing Sensitivity Stripping](#testing-sensitivity-stripping)
- [Metrics Assertions](#metrics-assertions)
- [OutputMetricsRecorder](#outputmetricsrecorder)
- [Table-Driven Tests](#table-driven-tests)
- [Common Gotchas](#common-gotchas)

## What Is audittest?

The `audittest` package provides an in-memory audit logger for your
unit and integration tests. It captures events and metrics in memory for
assertion, with the same validation and pipeline as production.

## Why a Test Package?

Testing audit logging without `audittest` requires ~25 lines of
boilerplate per test: implementing `audit.Output`, creating a full
logger, dealing with async drain timing, parsing raw JSON, and
asserting on `map[string]interface{}`.

`audittest` reduces this to one line:

```go
auditor, events, metrics := audittest.New(t, taxonomyYAML)
```

## Quick Start

```go
func TestCreateUser(t *testing.T) {
    auditor, events, metrics := audittest.New(t, taxonomyYAML)

    svc := NewUserService(auditor)
    svc.CreateUser("alice", "alice@example.com")

    // Assert immediately — New uses synchronous delivery by default.
    require.Equal(t, 1, events.Count())
    evt := events.Events()[0]
    assert.Equal(t, "user_create", evt.EventType)
    assert.True(t, evt.HasField("actor_id", "alice"))
    assert.Equal(t, 1, metrics.EventDeliveries("recorder", "success"))
}
```

### Synchronous Delivery (Default)

Both `New` and `NewQuick` default to synchronous delivery:
events are available in the `Recorder` immediately after `AuditEvent()`
returns. No `Close()` call is needed before assertions.
`New` registers `t.Cleanup(auditor.Close)` to clean up resources
after the test completes. Use `WithAsync()` to opt into asynchronous
delivery for tests that exercise drain timeout or buffer backpressure.

### Silent Diagnostics (Default)

Test auditors silence diagnostic logs (lifecycle messages, shutdown
notices) by default. Use `WithVerbose()` to re-enable diagnostic
output when debugging auditor behaviour in tests.

## Dependency Injection

The Quick Start above uses `NewUserService(auditor)` — this is the
correct pattern. Your service takes a `*audit.Auditor` as a constructor
parameter, not from a package-level global:

```go
// Correct: inject the auditor
type UserService struct {
    audit *audit.Auditor
}

func NewUserService(auditor *audit.Auditor) *UserService {
    return &UserService{audit: auditor}
}
```

```go
// Wrong: package-level global logger
var auditor *audit.Auditor // data races in parallel tests

type UserService struct{}
```

Why this matters for testing:

- **Injected logger**: each test creates its own `audittest.New`,
  passes it to the service, and asserts on its own events. Tests run in
  parallel safely.
- **Global logger**: all tests share the same logger. Events from one
  test appear in another's assertions. `t.Parallel()` causes data races.

Structure your code with constructor injection from the start — it is
the only pattern that makes audit testing reliable.

## Two Constructor Patterns

### New — full integration test

Uses your real taxonomy YAML. Generated typed builders work because
they compile from the same taxonomy:

```go
auditor, events, metrics := audittest.New(t, taxonomyYAML)
```

### NewQuick — quick smoke test

Creates a permissive auditor — any fields accepted, no required field
enforcement:

```go
auditor, events, _ := audittest.NewQuick(t, "user_create", "auth_failure")
```

### WithAuditOption — pass-through for advanced options

For options not covered by the `audittest.With*` helpers, use
`WithAuditOption` to pass an arbitrary `audit.Option` through:

```go
auditor, events, _ := audittest.New(t, taxonomyYAML,
    audittest.WithAuditOption(audit.WithAppName("my-service")),
    audittest.WithAuditOption(audit.WithHost("test-host")),
)
```

## Recorded Event API

| Method | Returns | Purpose |
|--------|---------|---------|
| `evt.EventType` | `string` | Event type name |
| `evt.Severity` | `int` | Resolved severity (0-10) |
| `evt.Timestamp` | `time.Time` | When the event was processed |
| `evt.Fields` | `map[string]any` | Non-framework field values |
| `evt.Field(key)` | `any` | Single field value (nil if absent) |
| `evt.StringField(key)` | `string` | String value (empty if missing or wrong type) |
| `evt.IntField(key)` | `int` | Int value with float64 coercion (0 if missing) |
| `evt.FloatField(key)` | `float64` | Float value (0 if missing or wrong type) |
| `evt.BoolField(key)` | `bool` | Bool value (false if missing or wrong type) |
| `evt.UserFields()` | `map[string]any` | Fields with framework fields removed |
| `evt.HasField(key, val)` | `bool` | Deep-equal check |
| `evt.RawJSON` | `[]byte` | Original serialised bytes |
| `evt.ParseErr` | `error` | Non-nil if JSON deserialisation failed; assert nil before inspecting other fields |

> **Note:** Always check `evt.ParseErr == nil` before asserting on
> other fields. A non-nil `ParseErr` means the formatter produced
> invalid JSON; other fields are zero-valued in that case.

## Assertion Helpers

The `Recorder` provides assertion helpers that accept `testing.TB`,
producing clear failure messages including a dump of all recorded events:

```go
// Require exactly 1 event of the given type (Fatal on mismatch).
evt := events.RequireEvent(t, "user_create")

// Require exactly N events total (Fatal on mismatch).
all := events.RequireEvents(t, 3)

// Require no events recorded (Fatal if any).
events.RequireEmpty(t)

// Assert that at least one event of the type has matching fields (Error on failure).
events.AssertContains(t, "user_create", audit.Fields{
    "actor_id": "alice",
    "outcome":  "success",
})
```

### Recorder utility methods

| Method | Returns | Purpose |
|--------|---------|---------|
| `events.First()` | `(RecordedEvent, bool)` | Earliest event, or false if empty |
| `events.Last()` | `(RecordedEvent, bool)` | Most recent event, or false if empty |
| `events.FindByType(t)` | `[]RecordedEvent` | All events matching the type |
| `events.FindByField(k, v)` | `[]RecordedEvent` | All events where field k == v |
| `events.Count()` | `int` | Total recorded events |
| `events.Reset()` | — | Clear all events |

## Waiting for Async Events

Synchronous delivery (the default for `New` and `NewQuick`) removes
timing concerns from most tests. When you need to exercise async-only
behaviour — drain timeout, buffer backpressure, or a hot path that
itself emits from a goroutine — use `Recorder.WaitForN` to block
until events land in the recorder without resorting to `time.Sleep`:

```go
func TestAsyncHotPath(t *testing.T) {
    auditor, events, _ := audittest.New(t, taxonomyYAML, audittest.WithAsync())

    // Your service emits from a goroutine. Inlined here for clarity.
    go func() {
        for i := 0; i < 5; i++ {
            _ = auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
                "outcome":  "success",
                "actor_id": "alice",
            }))
        }
    }()

    // Block until 5 events have been recorded, or fail at 2 seconds.
    if !events.WaitForN(t, 5, 2*time.Second) {
        t.Fatalf("expected 5 events, got %d", events.Count())
    }
    // Safe to assert now — the drain has delivered the target count.
    assert.Equal(t, 5, events.Count())
}
```

`WaitForN` returns `true` once `Recorder.Count() >= n`, or `false` on
timeout. The poll interval is 10ms, matching
`testify/assert.Eventually`. If the target is already reached when
`WaitForN` is called, it returns immediately without sleeping — so
it is cheap to sprinkle through tests as a "wait-until-ready"
barrier.

> **Synchronous auditors do not need WaitForN.** Events are in the
> recorder before `AuditEvent` returns. Prefer `Count()` /
> `RequireEvents` there.

## Testing Sensitivity Stripping

Use `audittest.WithExcludeLabels` to verify your application's
compliance wiring — that fields you tagged `pii` (or `financial`,
etc.) in the taxonomy never reach an output you configured to exclude
that label. You are testing **your** integration, not the library's
strip logic.

When your application tags fields with sensitivity labels and routes
some outputs with `audit.WithExcludeLabels`,
`audittest.WithExcludeLabels` lets you assert the stripping behaviour
directly against the recorder:

```go
var taxonomyYAML = []byte(`
version: 1
sensitivity:
  labels:
    pii:
      fields: [email, phone]
categories:
  write:
    - user_create
events:
  user_create:
    fields:
      outcome: {required: true}
      actor_id: {required: true}
      email: {}
`)

func TestComplianceOutput_StripsPII(t *testing.T) {
    auditor, events, _ := audittest.New(t, taxonomyYAML,
        audittest.WithExcludeLabels("recorder", "pii"),
    )

    _ = auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
        "outcome":  "success",
        "actor_id": "alice",
        "email":    "alice@example.com",
    }))

    evt := events.Events()[0]
    assert.Nil(t, evt.Field("email"), "pii-labelled field must be stripped")
    assert.Equal(t, "alice", evt.StringField("actor_id"), "non-pii preserved")
}
```

Multiple calls accumulate:

```go
audittest.New(t, taxonomyYAML,
    audittest.WithExcludeLabels("recorder", "pii"),
    audittest.WithExcludeLabels("recorder", "financial"),
)
```

The first argument — `"recorder"` — is the name of the output to
apply the exclusion to. `audittest.New` and `audittest.NewQuick`
create a single recorder with the default name `"recorder"`; pass
that name, or whatever was supplied to [`NewNamedRecorder`][nnr]. A
mismatch causes `tb.Fatalf` at construction time (for both `New` and
`NewQuick`) so typos surface immediately.

[nnr]: https://pkg.go.dev/github.com/axonops/audit/audittest#NewNamedRecorder

> **Taxonomy validation still applies.** Every label listed in
> `WithExcludeLabels` MUST be defined in the taxonomy's
> `sensitivity:` section; otherwise `audit.New` returns an error
> and the test fails.

## Metrics Assertions

The `MetricsRecorder` captures all metric calls:

| Method | Returns | Purpose |
|--------|---------|---------|
| `metrics.SubmittedCount()` | `int` | Events submitted via AuditEvent |
| `metrics.EventDeliveries(output, status)` | `int` | Delivery attempts per output/status |
| `metrics.ValidationErrors(eventType)` | `int` | Validation rejections |
| `metrics.FilteredCount(eventType)` | `int` | Globally filtered events |
| `metrics.BufferDrops()` | `int` | Buffer-full drops |
| `metrics.OutputErrors(output)` | `int` | Output write errors |
| `metrics.OutputFiltered(output)` | `int` | Per-output route-filtered events |
| `metrics.SerializationErrors(eventType)` | `int` | Serialisation errors |
| `metrics.FileRotations(path)` | `int` | File rotation count |
| `metrics.SyslogReconnects(addr, success)` | `int` | Syslog reconnection count |

## OutputMetricsRecorder

For testing custom outputs that use `audit.OutputMetrics`, use
`OutputMetricsRecorder`:

```go
om := audittest.NewOutputMetricsRecorder()
// Pass om to your output via fctx.OutputMetrics in your factory,
// or via the per-module WithOutputMetrics option for direct-Go
// construction (e.g. file.WithOutputMetrics(om)).

om.DropCount()   // recorded drops
om.FlushCount()  // recorded flushes
om.ErrorCount()  // recorded errors
om.RetryCount()  // recorded retries
om.Reset()       // clear all counters
```

## Table-Driven Tests

Use `events.Reset()` and `metrics.Reset()` to clear captured state
between sub-tests without creating a new auditor:

```go
for _, tc := range tests {
    t.Run(tc.name, func(t *testing.T) {
        events.Reset()
        metrics.Reset()
        svc.Do(tc.action)
        // assert on events and metrics for this sub-test only
    })
}
```

## Common Gotchas

### JSON float64 coercion

JSON round-tripping stores all numbers as `float64`. When asserting
on numeric fields, use `evt.IntField("count")` instead of comparing
`evt.Field("count")` to an `int` literal — the latter will fail
because the underlying value is `float64(42)`, not `int(42)`.

### Close not needed with synchronous delivery

Both `New` and `NewQuick` default to synchronous delivery.
Events are available immediately after `AuditEvent()` returns. You
do NOT need to call `auditor.Close()` before assertions. The
`t.Cleanup(auditor.Close)` registered by `New` handles resource
cleanup automatically.

Only call `Close()` before assertions when using `WithAsync()`.

### WaitForN always times out

If `WaitForN` never returns `true`, the three likely causes — in
descending order of frequency:

1. **Forgot `WithAsync()`.** The default is synchronous delivery; events
   are recorded before `AuditEvent` returns, so `WaitForN` is
   unnecessary and a bug-hunting test may never reach the target if
   your code path never emits.
2. **Target count exceeds buffer.** With `WithAsync()` and a small
   queue, events may be dropped via `ErrQueueFull` before the drain
   runs. Check metrics for drops.
3. **Emitting goroutine panics before emitting `n` events.** Add an
   error check to the emitter and log the panic.

### CEF formatter limitation

The `Recorder` only parses JSON-formatted events. If you use
`audit.WithFormatter(audit.CEFFormatter{})`, captured events will
have `ParseErr` set and structured fields will be zero-valued.
Use `evt.RawJSON` for format-level assertions with non-JSON formatters.

## Further Reading

- [Progressive Example: Testing](../examples/17-testing/) — three testing patterns
- [API Reference: audittest](https://pkg.go.dev/github.com/axonops/audit/audittest)
