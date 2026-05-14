[← Back to examples](../README.md)

> **Previous:** [14 — Buffering](../14-buffering/) |
> **Next:** [16 — Health Endpoint](../16-health-endpoint/)
# Example 15: HTTP Middleware

Automatic HTTP audit logging: the middleware captures request metadata,
handlers set domain hints (who did it, what happened), and health
checks are silently skipped.

> **Note:** This example uses the programmatic API for output setup
> because it captures audit output to a buffer for the self-contained
> demo. In your application, you'd configure outputs in `outputs.yaml`
> as shown in the previous examples.

## What You'll Learn

- Wrapping an HTTP handler with `audit.Middleware`
- Writing an `EventBuilder` to map requests to audit events
- Setting `Hints` from handlers via `HintsFromContext`
- Skipping specific paths (like health checks)
- What `TransportMetadata` captures automatically

## Prerequisites

- Go 1.26+
- Completed: [Formatters](../04-formatters/)

## Files

| File | Purpose |
|------|---------|
| `main.go` | HTTP server with audit middleware and programmatic test requests |

## Key Concepts

### Wrapping Your HTTP Handler

`audit.Middleware` wraps any `http.Handler`. For each request it
automatically captures timing, status code, client IP, and other
transport metadata:

```go
handler := audit.Middleware(logger, buildEvent)(mux)
```

Your handlers don't need to know about audit logging at all. They just
set a few hints on the request context, and the middleware takes care of
the rest.

### The EventBuilder

The `EventBuilder` is a function you write. The middleware calls it
after every request with the hints your handler set and the transport
metadata it captured. You decide what audit event to produce:

```go
func buildEvent(
    hints *audit.Hints,
    transport *audit.TransportMetadata,
) (eventType string, fields audit.Fields, skip bool) {
    // Skip health checks.
    if transport.Path == "/healthz" {
        return "", nil, true
    }

    fields = audit.Fields{
        "outcome":     hints.Outcome,
        "method":      transport.Method,
        "path":        transport.Path,
        "status_code": transport.StatusCode,
        "source_ip":   transport.ClientIP,
        "duration_ms": transport.Duration.Milliseconds(),
    }
    if hints.ActorID != "" {
        fields["actor_id"] = hints.ActorID
    }
    if hints.TargetID != "" {
        fields["target_id"] = hints.TargetID
    }
    return "http_request", fields, false
}
```

Return `skip: true` to suppress the audit event for that request — no
event is emitted at all.

### Setting Hints from Handlers

Your handlers communicate domain knowledge to the EventBuilder through
hints. The middleware injects a `Hints` struct into the request context:

```go
mux.HandleFunc("POST /items", func(w http.ResponseWriter, r *http.Request) {
    if hints := audit.HintsFromContext(r.Context()); hints != nil {
        hints.ActorID = "alice"
        hints.Outcome = "success"
        hints.TargetID = "item-42"
    }
    w.WriteHeader(http.StatusCreated)
})
```

The handler doesn't import the auditor or construct audit events. It just
sets hints — who did it, did it succeed, what was affected.

Available hints:

| Field | Purpose |
|-------|---------|
| `ActorID` | Who performed the action |
| `Outcome` | `"success"` or `"failure"` |
| `TargetID` | The resource affected |
| `TargetType` | Type of resource (e.g., `"item"`, `"user"`) |
| `EventType` | Override the event type (used by auth middleware — see [Capstone](../20-capstone/)) |
| `ActorType` | `"user"`, `"service"`, `"api_key"`, etc. |
| `AuthMethod` | How the actor authenticated (e.g., `"bearer"`, `"api_key"`) |
| `Role` | Actor's role at request time |
| `Reason` | Why something happened (e.g., `"not found"`) |
| `Error` | Error message if the operation failed |
| `Extra` | Arbitrary key-value pairs for domain-specific fields |

### What the Middleware Captures Automatically

| Field | Source |
|-------|--------|
| `Method` | HTTP method (`GET`, `POST`, etc.) |
| `Path` | URL path |
| `StatusCode` | Response status code |
| `Duration` | Time the handler took |
| `ClientIP` | From `X-Forwarded-For` → `X-Real-IP` → `RemoteAddr` |
| `UserAgent` | `User-Agent` header |
| `RequestID` | `X-Request-ID` header (generated if missing) |

### Middleware Placement

Place the audit middleware at the outermost layer — it needs to wrap
everything including auth middleware so it can capture the final response
status code. The [Capstone](../20-capstone/) example shows this with auth
middleware and audit middleware composed together.

## Run It

```bash
go run .
```

## Expected Output

```
INFO audit: auditor created queue_size=10000 shutdown_timeout=5s validation_mode=strict outputs=1 synchronous=false
GET http://127.0.0.1:.../healthz -> 200
GET http://127.0.0.1:.../items -> 200
POST http://127.0.0.1:.../items -> 201
INFO audit: shutdown started
INFO audit: shutdown complete duration=...
--- Audit events ---
{"timestamp":"...","event_type":"http_request","severity":5,"pid":...,"method":"GET","outcome":"success","path":"/items","duration_ms":0,"status_code":200,"actor_id":"alice","source_ip":"127.0.0.1"}
{"timestamp":"...","event_type":"http_request","severity":5,"pid":...,"method":"POST","outcome":"success","path":"/items","duration_ms":0,"status_code":201,"actor_id":"alice","source_ip":"127.0.0.1","target_id":"item-42"}

Note: /healthz produced no audit event (skipped by EventBuilder).
```

Three HTTP requests, but only two audit events. The health check was
skipped because the `EventBuilder` returned `nil` for requests to
`/healthz`.

## Further Reading

- [HTTP Middleware](../../docs/http-middleware.md) — full middleware reference, Hints API, EventBuilder
- [Async Delivery](../../docs/async-delivery.md) — how middleware events flow through the pipeline

