[← Back to examples](../README.md)

> **Previous:** [16 — Health Endpoint](../16-health-endpoint/) |
> **Next:** [18 — Migration](../18-migration/)
# Example 17: Testing

How to test code that uses audit. The `audittest` package provides
an in-memory test logger that captures events and metrics for assertion.

## What You'll Learn

- Using `audittest.New` for full integration tests
- Using `audittest.NewQuick` for smoke tests with a permissive taxonomy
- Asserting on captured events and metrics
- Table-driven tests with `Reset()`
- Testing validation error paths

## Prerequisites

- Go 1.26+
- Completed: [Code Generation](../02-code-generation/)

## Files

| File | Purpose |
|------|---------|
| `taxonomy.yaml` | Event definitions (embedded in binary) |
| `audit_generated.go` | Generated typed builders and constants |
| `main.go` | UserService with audit logging |
| `main_test.go` | Tests using audittest |

## Key Concepts

The patterns below address the core challenge of testing audit
pipelines. Each pattern maps to a distinct testing need.

### The Testing Problem

Your service emits audit events. You need to verify in unit tests
that the right events are emitted with the right fields. Without
`audittest`, you'd need to create a mock output, wire up a full
logger, deal with async timing, parse raw JSON, and assert on
untyped maps. That's ~25 lines of boilerplate per test.

### The Solution: audittest

The `audittest` package gives you an in-memory audit logger that
works exactly like production — same validation, same taxonomy
enforcement — but events land in a `Recorder` instead of being
written anywhere. By default, delivery is synchronous, so events
are available immediately after `AuditEvent()` returns.

### Pattern 1: Full Integration Test

Use the same taxonomy YAML your production code uses. Generated
typed builders work in tests because they're compiled from the same
taxonomy.

```go
func TestCreateUser(t *testing.T) {
    auditor, events, metrics := audittest.New(t, taxonomyYAML)

    svc := NewUserService(auditor)
    err := svc.CreateUser("alice", "alice@example.com")
    require.NoError(t, err)

    // Synchronous delivery — assert immediately, no Close needed.
    require.Equal(t, 1, events.Count())
    evt := events.Events()[0]
    assert.Equal(t, EventUserCreate, evt.EventType)
    assert.True(t, evt.HasField(FieldActorID, "alice"))
    assert.Equal(t, 1, metrics.EventDeliveries("recorder", "success"))
}
```

### Pattern 2: Quick Smoke Test

When you just want to verify an event was emitted without caring
about field validation:

```go
func TestAuditHappens(t *testing.T) {
    auditor, events, _ := audittest.NewQuick(t, "user_create")

    svc := NewUserService(auditor)
    _ = svc.CreateUser("alice", "alice@example.com")

    // Synchronous delivery — assert immediately.
    assert.Equal(t, 1, events.Count())
}
```

`NewQuick` creates a permissive logger — any fields accepted,
no required field enforcement.

### Pattern 3: Metrics Assertions

Verify that metrics are recorded correctly — validation errors,
buffer drops, delivery counts:

```go
func TestValidationError(t *testing.T) {
    auditor, _, metrics := audittest.New(t, taxonomyYAML)

    // Emit event missing required field "actor_id"
    err := auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
        "outcome": "success",
        // actor_id missing — validation error
    }))
    require.Error(t, err)
    assert.Contains(t, err.Error(), "missing required")

    assert.Equal(t, 1, metrics.ValidationErrors("user_create"))
}
```

### Synchronous Delivery (Default)

Both `New` and `NewQuick` default to synchronous delivery — events
are available in the `Recorder` immediately after `AuditEvent()`
returns. No `Close()` call is needed before assertions. `New`
registers `t.Cleanup(auditor.Close)` to clean up resources after
the test completes.

Use `WithAsync()` only when testing async-specific behaviour such
as drain timeout or buffer backpressure. With `WithAsync()`, you
MUST call `auditor.Close()` before assertions.

### Table-Driven Tests with Reset

Use `events.Reset()` and `metrics.Reset()` to clear captured state
between sub-tests without creating a new auditor:

```go
for _, tc := range tests {
    t.Run(tc.name, func(t *testing.T) {
        events.Reset()
        metrics.Reset()
        svc.Do(tc.action)
        // assert on events for this sub-test only
    })
}
```

### RecordedEvent API

Each captured event provides structured access:

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
| `evt.HasField(key, val)` | `bool` | Deep-equal check on field value |
| `evt.RawJSON` | `[]byte` | Original serialised bytes |
| `evt.ParseErr` | `error` | JSON deserialisation error (nil on success) |

### Dependency Injection

The key to testable audit logging is dependency injection. Your
service takes `*audit.Auditor` as a parameter — in production you
pass a real logger, in tests you pass the audittest logger:

```go
type UserService struct {
    auditor *audit.Auditor
}

func NewUserService(auditor *audit.Auditor) *UserService {
    return &UserService{auditor: auditor}
}
```

## Run the Tests

```bash
go test -v .
```

## Expected Output

```
=== RUN   TestCreateUser_EmitsAuditEvent
--- PASS: TestCreateUser_EmitsAuditEvent
=== RUN   TestLogin_Failure_EmitsAuthEvent
--- PASS: TestLogin_Failure_EmitsAuthEvent
=== RUN   TestLogin_Success_NoAuditEvent
--- PASS: TestLogin_Success_NoAuditEvent
=== RUN   TestAuditEventEmitted_Quick
--- PASS: TestAuditEventEmitted_Quick
=== RUN   TestValidationError_MissingRequiredField
--- PASS: TestValidationError_MissingRequiredField
PASS
```

All five tests pass, each demonstrating a different testing pattern.

## Further Reading

- [Testing](../../docs/testing.md) — full audittest reference and testing patterns
- [Troubleshooting](../../docs/troubleshooting.md) — common issues and solutions
