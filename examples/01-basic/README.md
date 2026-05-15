[← Back to examples](../README.md)

> **Next:** [02 — Code Generation](../02-code-generation/)
# Example 01: Basic Audit Logging (Programmatic)

The minimum viable audit event: create an auditor, emit an event, and see
the JSON output. No YAML files, no code generation, no configuration —
just Go code.

This example uses `DevTaxonomy()` and `NewStdout()` so you can see how
the library works in a playground. From the next example onwards,
you'll define your events and outputs in YAML files instead — that's
how you'd use audit in a real application.

## What You'll Learn

- Creating an auditor with two lines of setup
- Emitting events with `NewEventKV()` (slog-style) and `NewEvent()` (map-style)
- How the auditor delivers events asynchronously
- Why `Close()` matters

## Prerequisites

- Go 1.26+

## Files

| File | Purpose |
|------|---------|
| `main.go` | Auditor setup, event emission |

## Key Concepts

### DevTaxonomy — Quick Setup for Exploration

`DevTaxonomy()` creates a permissive taxonomy that accepts any fields
on the listed event types. It exists so you can experiment without
writing YAML or worrying about field validation:

```go
stdout, err := audit.NewStdout()
// handle err …
auditor, err := audit.New(
    audit.WithTaxonomy(audit.DevTaxonomy("user_create", "auth_failure")),
    audit.WithAppName("audit-demo"),
    audit.WithHost("localhost"),
    audit.WithOutputs(stdout),
)
```

`New()` takes functional options. `WithTaxonomy()` tells the auditor
what events are valid. `WithAppName()` and `WithHost()` populate the
compliance framework fields stamped on every event — both are
required (see `ErrAppNameRequired` / `ErrHostRequired`). `WithOutputs()`
tells the auditor where to send events. `NewStdout()` constructs a
JSON-to-stdout output — no file rotation, no network, no
configuration. Pair it with `NewStderr()` or `NewWriter(w io.Writer)`
when you need different destinations.

In production, you'd define your taxonomy in a YAML file with required
fields and severity levels, then use `audit-gen` to generate type-safe
builders. The [Code Generation](../02-code-generation/) example shows how.

### Emitting Events

Two styles, same result:

**slog-style key-value pairs** (concise):
```go
err := auditor.AuditEvent(audit.MustNewEventKV("user_create",
    "outcome", "success",
    "actor_id", "alice",
))
```

`MustNewEventKV` panics on programmer errors (odd arg count, non-string key). For dynamic input use `audit.NewEventKV(...)` which returns `(Event, error)`.

**Fields map** (explicit):
```go
err := auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
    "outcome":  "failure",
    "actor_id": "unknown",
}))
```

`AuditEvent()` validates the fields against the taxonomy, serializes the
event to JSON, and **enqueues it to an internal buffer**. The actual
write to stdout happens asynchronously on a background goroutine.

This means `AuditEvent()` is fast — it doesn't block on I/O. The
trade-off: output may appear slightly after the `fmt.Println` that
precedes it in your code.

> **For production workloads**, prefer generated typed builders
> (see [`02-code-generation/`](../02-code-generation/)) or, when the
> event type is only known at startup, a pre-validated
> [`EventHandle`](https://pkg.go.dev/github.com/axonops/audit#EventHandle).
> `NewEvent` and `NewEventKV` each pay one heap allocation per call
> (the `basicEvent` interface escape); the other paths do not. The
> [performance guide](../../docs/performance.md) has the full
> breakdown.

### Closing the Auditor

```go
defer func() { _ = auditor.Close() }()
```

`Close()` waits for buffered events to flush, then shuts down the
background goroutine and closes all outputs. Without `Close()`, buffered
events may be lost.

### Severity

Every audit event has an integer severity from 0 (informational) to 10
(critical). You'll see `"severity":5` in every JSON event in this
example — that's the default when no severity is configured.

Severity becomes useful for routing: you can send high-severity events
to a SIEM webhook while keeping low-severity events in local files.
You'll learn how to set per-category severity levels and route by
threshold in the [Event Routing](../10-event-routing/) example.

### Buffer Full and Delivery Guarantees

audit uses an internal buffer (default 10,000 events) between
`AuditEvent()` and the output writes. If your application emits events
faster than outputs can drain them, the buffer fills up and `AuditEvent()`
returns `audit.ErrQueueFull`.

This is deliberate — audit logging must not silently drop events. Your
application decides how to handle back-pressure:

```go
if err := auditor.AuditEvent(audit.NewEvent("user_create", fields)); err != nil {
    if errors.Is(err, audit.ErrQueueFull) {
        // Buffer is full — outputs can't keep up.
        // Log to stderr, increment a metric, or slow down.
    }
}
```

Delivery to outputs is **at-most-once within a process lifetime**: if
the application crashes before `Close()` flushes the buffer, in-flight
events are lost. For stronger guarantees, use the webhook output with
retries or a durable syslog relay.

## Run It

```bash
go run .
```

## Expected Output

```
WARN audit: using DevTaxonomy — not suitable for production; all event types accepted without schema enforcement
INFO audit: auditor created queue_size=10000 shutdown_timeout=5s validation_mode=permissive outputs=1 synchronous=false
--- Valid event ---

--- Auth failure event ---
INFO audit: shutdown started
{"timestamp":"...","event_type":"user_create","severity":5,"app_name":"audit-demo","host":"localhost","timezone":"Local","pid":...,"actor_id":"alice","outcome":"success","event_category":"dev"}
{"timestamp":"...","event_type":"auth_failure","severity":5,"app_name":"audit-demo","host":"localhost","timezone":"Local","pid":...,"actor_id":"unknown","outcome":"failure","event_category":"dev"}
INFO audit: shutdown complete duration=...
```

The first two `WARN` / `INFO` lines are emitted at construction time
by the auditor's diagnostic logger — they confirm the dev-mode
taxonomy and the queue / shutdown configuration. The JSON events
appear between the shutdown messages because `AuditEvent()` enqueues
asynchronously and `Close()` drains the buffer before finishing.
This is normal — `Close()` guarantees all buffered events are
delivered before it returns.

## When to Graduate from DevTaxonomy

`DevTaxonomy()` accepts any event type with any fields. That's
deliberate — it lets you explore the library without authoring a
schema first. But every guarantee the library provides (typo
rejection, required-field enforcement, sensitivity labelling,
CEF severity resolution) requires a real taxonomy.

The next example — [02-code-generation](../02-code-generation/) —
shows how to author a `taxonomy.yaml` and generate typed event
builders so the schema is enforced at compile time. The 4-step
migration recipe is in
[`docs/taxonomy-validation.md`](../../docs/taxonomy-validation.md#migrating-from-devtaxonomy-to-a-strict-taxonomy).

## Further Reading

- [Taxonomy Validation](../../docs/taxonomy-validation.md) — how the library validates events
- [Async Delivery](../../docs/async-delivery.md) — buffering, backpressure, and shutdown
- [API Reference](https://pkg.go.dev/github.com/axonops/audit) — full godoc
