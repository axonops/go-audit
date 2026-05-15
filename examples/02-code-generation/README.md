[← Back to examples](../README.md)

> **Previous:** [01 — Basic](../01-basic/) |
> **Next:** [03 — File Output](../03-file-output/)
# Example 02: Code Generation

Define your audit events in a YAML file, generate type-safe Go
constants, and configure outputs in a separate YAML file. This is the
recommended workflow for audit — all subsequent examples follow it.

> **Coming from example 01?** If you started with
> `audit.DevTaxonomy()`, this example is the migration target. Take
> the event types you've been emitting, list them in
> `taxonomy.yaml` with their required fields, regenerate, and swap
> the `WithTaxonomy(...)` call. The full 4-step recipe lives in
> [`docs/taxonomy-validation.md`](../../docs/taxonomy-validation.md#migrating-from-devtaxonomy-to-a-strict-taxonomy).

## What You'll Learn

- Why audit events are defined in YAML and embedded in the binary
- How `audit-gen` generates type-safe constants and event builders from your taxonomy
- The two-file pattern: `taxonomy.yaml` (events) + `outputs.yaml` (destinations)
- Loading output configuration with `outputconfig.Load`

## Prerequisites

- Go 1.26+
- Completed: [Basic](../01-basic/)

## Files

| File | Purpose |
|------|---------|
| `taxonomy.yaml` | Defines what events your application can produce |
| `outputs.yaml` | Defines where audit events are sent |
| `audit_generated.go` | Generated constants and typed builders — committed, DO NOT EDIT |
| `main.go` | Loads both YAMLs, emits events using typed builders |

## Key Concepts

### Defining Events in YAML

In the [Basic](../01-basic/) example, we defined the taxonomy inline in Go.
That works, but real applications have dozens or hundreds of event types
with compliance requirements. A YAML file is easier for teams to review
and maintain:

```yaml
version: 1

categories:
  write:
    severity: 3
    events:
      - user_create
      - user_delete
  read:
    severity: 1
    events:
      - user_read
  security:
    severity: 8
    events:
      - auth_failure
      - auth_success

events:
  user_create:
    description: "A new user account was created"
    fields:
      outcome:
        required: true
      actor_id:
        required: true
      # target_id, reason, source_ip are reserved standard fields —
      # available on every event without declaration.

  # ... (auth_failure, auth_success, user_read, user_delete defined similarly)
```

Each event belongs to a category and declares its fields in a `fields:`
map. The `description` field is used by `audit-gen` as the Go doc
comment for the generated constant.

### Field Declaration Syntax

| Syntax | Meaning |
|--------|---------|
| `field_name:` or `field_name: {}` | Optional, no labels |
| `field_name: {required: true}` | Required — must be in every `AuditEvent()` call |
| `field_name: {labels: [pii]}` | Optional with sensitivity label |
| `field_name: {required: true, labels: [pii]}` | Required with label |

Sensitivity labels are covered in the [Sensitivity Labels](../11-sensitivity-labels/)
example. For now, the key point is: `required: true` means the field
must always be present; everything else is optional.

### Why Embed the Taxonomy?

The taxonomy is loaded into the binary at compile time using
`//go:embed`:

```go
//go:embed taxonomy.yaml
var taxonomyYAML []byte

tax, err := audit.ParseTaxonomyYAML(taxonomyYAML)
```

This is deliberate. The taxonomy defines your audit contract — what
events exist, what fields are required. It's part of your source code:

- **Self-contained binary** — no "file not found" in production
- **Immutable after build** — the event schema can't be accidentally
  modified on disk after deployment
- **Version-controlled** — changes go through code review, not config
  management

### Generating Code with audit-gen

`audit-gen` reads your taxonomy YAML and generates Go constants and
typed event builders:

```go
//go:generate go run github.com/axonops/audit/cmd/audit-gen -input taxonomy.yaml -output audit_generated.go -package main
```

This produces `audit_generated.go` with five sections — event type
constants, category constants, field name constants, taxonomy metadata,
and **typed event builders**:

```go
const (
    // EventAuthFailure — An authentication attempt failed
    EventAuthFailure = "auth_failure"
    // EventUserCreate — A new user account was created
    EventUserCreate = "user_create"
    // ... (one constant per event type)
)

const (
    CategoryRead     = "read"
    CategorySecurity = "security"
    CategoryWrite    = "write"
)

const (
    FieldActorID  = "actor_id"
    FieldOutcome  = "outcome"
    FieldReason   = "reason"
    FieldSourceIP = "source_ip"
    FieldTargetID = "target_id"
    // ...
)

// Metadata: the complete taxonomy schema, using the constants above.
var EventFields = map[string]struct {
    Required []string
    Optional []string
}{
    EventUserCreate: {
        Required: []string{FieldActorID, FieldOutcome},
        Optional: []string{},
    },
    EventAuthFailure: {
        Required: []string{FieldActorID, FieldOutcome},
        Optional: []string{},
    },
    // ...
}

var CategoryEvents = map[string][]string{
    CategoryWrite:    {EventUserCreate, EventUserDelete},
    CategorySecurity: {EventAuthFailure, EventAuthSuccess},
    // ...
}
```

**Typed event builders** are generated for each event type. Required
fields become constructor parameters; optional fields get chainable
setter methods:

```go
// NewUserCreateEvent creates a EventUserCreate event with required fields.
func NewUserCreateEvent(actorID string, outcome string) *UserCreateEvent {
    return &UserCreateEvent{fields: audit.Fields{
        FieldActorID: actorID,
        FieldOutcome: outcome,
    }}
}

// SetTargetID sets the reserved standard field "target_id".
func (e *UserCreateEvent) SetTargetID(v string) *UserCreateEvent {
    e.fields[FieldTargetID] = v
    return e
}
```

Each builder implements the `audit.Event` interface (`EventType()`,
`Fields()`), so it passes directly to `auditor.AuditEvent()`.

Now a typo like `NewUserCrateEvent` fails the build instead of silently
passing as a runtime validation error. The metadata vars reference
the generated constants — `EventUserCreate` not `"user_create"` —
so the entire taxonomy is type-safe. When sensitivity labels are
defined, `FieldLabels` and `Label` constants are also generated — see
the [Sensitivity Labels](../11-sensitivity-labels/) example.

**Code generation is optional.** The basic example used raw strings and
it worked fine. But once you have more than a handful of event types,
generated constants are worth the small overhead of running
`go generate` when the taxonomy changes.

The generated file is committed to version control, so the example
compiles without running `go generate` first. `go generate` runs
`audit-gen` via `go run`, which downloads and caches the tool
automatically — no separate install step.

### Standard Fields on Every Builder

Fields like `target_id`, `reason`, and `source_ip` are **reserved
standard fields** — always available without taxonomy declaration. The
code generator produces setter methods (`.SetTargetID()`, `.SetReason()`,
`.SetSourceIP()`) on every builder regardless of whether those fields
appear in the taxonomy. See [example 05 — Standard Fields](../05-standard-fields/) for the
full explanation.

### Configuring Outputs in YAML

Where events are sent is defined in a separate file, `outputs.yaml`:

```yaml
version: 1
app_name: example
host: localhost
outputs:
  console:
    type: stdout
```

This is loaded at startup with `outputconfig.Load`:

```go
//go:embed outputs.yaml
var outputsYAML []byte

loaded, err := outputconfig.Load(ctx, outputsYAML, tax)
```

Or use the facade — one call instead of three steps:

```go
auditor, err := outputconfig.New(ctx, taxonomyYAML, "outputs.yaml")
```

### Two Files, Two Purposes

The pattern from here on is always the same:

| File | Purpose | Changes when... |
|------|---------|-----------------|
| `taxonomy.yaml` | What events exist | You add/remove event types or fields |
| `outputs.yaml` | Where events are sent | You add outputs, change destinations, adjust routing |

They're separate because they change for different reasons. Adding a new
event type doesn't affect where events are sent. Adding a syslog output
doesn't change what events exist.

### Using Typed Event Builders

`audit-gen` generates a constructor and setter methods for each event
type. Required fields are constructor parameters (compile-time
enforcement); optional fields use chainable setters:

```go
if err := auditor.AuditEvent(NewUserCreateEvent("alice", "success").
    SetTargetID("user-42")); err != nil {
    log.Printf("audit error: %v", err)
}

if err := auditor.AuditEvent(NewAuthFailureEvent("unknown", "failure").
    SetReason("invalid credentials").
    SetSourceIP("192.168.1.100")); err != nil {
    log.Printf("audit error: %v", err)
}

if err := auditor.AuditEvent(NewUserReadEvent("success").
    SetActorID("bob")); err != nil {
    log.Printf("audit error: %v", err)
}
```

Compare with the raw-string approach from the basic example:

```go
auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
    "outcome":  "success",
    "actor_id": "alice",
}))
```

The typed builders add two layers of compile-time safety: a typo in
the event name (`NewUserCrateEvent`) or a missing required field both
fail the build. With `audit.NewEvent`, those errors are caught at
runtime by taxonomy validation.

## Run It

```bash
# Run the example (audit_generated.go is already committed):
go run .

# To regenerate after editing taxonomy.yaml:
go generate .
```

## Expected Output

```
INFO audit: auditor created queue_size=10000 shutdown_timeout=5s validation_mode=strict outputs=1 synchronous=false
--- Using typed event builders ---
INFO audit: shutdown started
{"timestamp":"...","event_type":"user_create","severity":3,"app_name":"example","host":"localhost","timezone":"Local","pid":...,"actor_id":"alice","outcome":"success","target_id":"user-42","event_category":"write"}
{"timestamp":"...","event_type":"auth_failure","severity":8,"app_name":"example","host":"localhost","timezone":"Local","pid":...,"actor_id":"unknown","outcome":"failure","reason":"invalid credentials","source_ip":"192.168.1.100","event_category":"security"}
{"timestamp":"...","event_type":"user_read","severity":1,"app_name":"example","host":"localhost","timezone":"Local","pid":...,"outcome":"success","actor_id":"bob","event_category":"read"}
INFO audit: shutdown complete duration=...
```

The `app_name`, `host`, and `pid` are framework fields — set once in
`outputs.yaml` and automatically included in every event. The
`event_category` field is automatically populated from the taxonomy's
category definitions. Each event's `severity` reflects the per-category
default declared in `taxonomy.yaml` (write=3, read=1, security=8) — see
[Event Routing](../10-event-routing/) for severity-based routing. The
`INFO audit:` lines are lifecycle diagnostics on stderr — see
[example 01](../01-basic/) for details.

## Further Reading

- [Code Generation](../../docs/code-generation.md) — full audit-gen reference
- [Output Configuration YAML](../../docs/output-configuration.md) — outputs.yaml schema
- [Taxonomy Validation](../../docs/taxonomy-validation.md) — validation rules and modes

