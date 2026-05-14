[← Back to examples](../README.md)

> **Previous:** [04 — Formatters](../04-formatters/) |
> **Next:** [06 — Syslog Output](../06-syslog-output/)
# Example 05: Standard Fields & Framework Configuration

## What You'll Learn

- Why 31 standard audit fields are built into every event
- How to use standard field setters without declaring fields in your taxonomy
- How framework fields (`app_name`, `host`, `timezone`, `pid`) identify every event's origin
- How to configure deployment-wide defaults via `standard_fields` in YAML
- How standard fields map to CEF extension keys for SIEM auto-correlation

## The Problem

Every audit application needs the same core fields: who did it (`actor_id`),
where did it come from (`source_ip`), what was affected (`target_id`), why
(`reason`). Without a shared vocabulary, every team invents their own names
— `user`, `src`, `ip_address`, `remote_addr` — and SIEM correlation breaks.

## The Solution: Reserved Standard Fields

audit defines **31 well-known audit field names** that are always
available on every event without taxonomy declaration:

| Category | Fields |
|----------|--------|
| **Identity** | `actor_id`, `actor_uid`, `role`, `target_id`, `target_uid`, `target_type`, `target_role` |
| **Context** | `action`, `outcome`, `reason`, `message` |
| **Network** | `source_ip`, `source_host`, `source_port`, `dest_ip`, `dest_host`, `dest_port`, `protocol`, `transport` |
| **HTTP** | `request_id`, `session_id`, `user_agent`, `referrer`, `method`, `path` |
| **Temporal** | `start_time`, `end_time` |
| **File** | `file_name`, `file_path`, `file_hash`, `file_size` |

These fields:
- Are accepted by the auditor in any validation mode (strict, warn, permissive)
- Have generated setter methods on every builder (`.SetSourceIP()`, `.SetReason()`, etc.)
- Map to standard ArcSight CEF extension keys for automatic SIEM integration
- Can be made mandatory per-event by declaring them `required: true` in the taxonomy
- Can be labeled with sensitivity classifications for per-output stripping

You do **not** declare them in your taxonomy. They are always there.

## Framework Fields

In addition to the 31 standard fields, every event includes **framework
fields** that identify the deployment:

| Field | Set By | JSON Key | CEF Key | Purpose |
|-------|--------|----------|---------|---------|
| `app_name` | `outputs.yaml` | `app_name` | `deviceProcessName` | Which application |
| `host` | `outputs.yaml` | `host` | `dvchost` | Which host |
| `timezone` | `outputs.yaml` | `timezone` | `dtz` | Which timezone |
| `pid` | Auto-detected | `pid` | `dvcpid` | Which process |

Framework fields are:
- Set once at logger construction (not per-event)
- Always present in serialised output (`app_name` and `host` are required at construction; `timezone` and `pid` are auto-populated when not set)
- Cannot be stripped by sensitivity label exclusions
- Cannot be declared as user fields in the taxonomy

Because these four fields are guaranteed present in every serialised
event, your SIEM index mappings, dashboard queries, and alert rules
can reference them without null-handling — there is no path through
the auditor that emits an event missing `app_name`, `host`, `timezone`,
or `pid`.

## Taxonomy

The taxonomy only declares what is specific to your application:

```yaml
# taxonomy.yaml — only declare YOUR fields, not standard ones
version: 1

categories:
  write:
    - user_create
  security:
    severity: 8
    events:
      - auth_failure

events:
  user_create:
    description: "A new user account was created"
    fields:
      outcome:  { required: true }
      actor_id: { required: true }

  auth_failure:
    description: "An authentication attempt failed"
    fields:
      outcome:  { required: true }
      actor_id: { required: true }
```

Notice: no `source_ip`, `target_id`, or `reason` declarations. They are
reserved standard fields — always available.

## Output Configuration

The `outputs.yaml` configures framework fields and optional standard field
defaults:

```yaml
# outputs.yaml
version: 1
app_name: standard-fields-demo
host: "${HOSTNAME:-localhost}"
timezone: "${TZ:-UTC}"

# Deployment-wide defaults for standard fields.
# Applied to every event unless the event sets its own value.
standard_fields:
  source_ip: "${DEFAULT_SOURCE_IP:-10.0.0.1}"

outputs:
  console:
    type: stdout
```

- `app_name` and `host` are **required** — every deployment must identify itself.
- `timezone` is optional in YAML — auto-detected from the system when absent, but always present in serialised output.
- `standard_fields` maps reserved standard field names to default values.
  Environment variables are supported. Per-event values always override defaults.

## Wiring Standard Field Defaults

The `standard_fields` YAML section is handled automatically by
`outputconfig.New` — no manual wiring needed:

```go
auditor, err := outputconfig.New(ctx, taxonomyYAML, "outputs.yaml")
```

The facade reads the `standard_fields` map, creates a
`WithStandardFieldDefaults` option, and passes it to `New`
alongside the output registrations and config options.

## Using Standard Field Setters

The generated builders have setter methods for all 31 standard fields,
regardless of whether the field appears in your taxonomy:

```go
// SetTargetID, SetSourceIP, SetReason are generated on every builder.
// They are available because target_id, source_ip, reason are
// reserved standard fields — no taxonomy declaration needed.
err := auditor.AuditEvent(
    NewUserCreateEvent("alice", "success").
        SetTargetID("user-42").
        SetReason("admin request"),
)
```

Standard field defaults from `outputs.yaml` are applied automatically:

```go
// source_ip is not set here — the default "10.0.0.1" applies.
err := auditor.AuditEvent(
    NewAuthFailureEvent("unknown", "failure").
        SetReason("invalid credentials"),
)
```

Per-event values override defaults:

```go
// Explicit source_ip overrides the default.
err := auditor.AuditEvent(
    NewAuthFailureEvent("bob", "failure").
        SetReason("expired token").
        SetSourceIP("192.168.1.100"),
)
```

## Run It

```bash
go run .
```

## Expected Output

```
INFO audit: auditor created queue_size=10000 shutdown_timeout=5s validation_mode=strict outputs=1 synchronous=false
--- Event with standard fields ---
--- Event with default source_ip ---
--- Event with explicit source_ip ---
INFO audit: shutdown started
{"timestamp":"...","event_type":"user_create","severity":5,"app_name":"standard-fields-demo","host":"...","timezone":"UTC","pid":...,"actor_id":"alice","outcome":"success","reason":"admin request","source_ip":"10.0.0.1","target_id":"user-42","event_category":"write"}
{"timestamp":"...","event_type":"auth_failure","severity":8,"app_name":"standard-fields-demo","host":"...","timezone":"UTC","pid":...,"actor_id":"unknown","outcome":"failure","reason":"invalid credentials","source_ip":"10.0.0.1","event_category":"security"}
{"timestamp":"...","event_type":"auth_failure","severity":8,"app_name":"standard-fields-demo","host":"...","timezone":"UTC","pid":...,"actor_id":"bob","outcome":"failure","reason":"expired token","source_ip":"192.168.1.100","event_category":"security"}
INFO audit: shutdown complete duration=...
```

> Events appear during `Close()` because `AuditEvent()` enqueues
> asynchronously. The `---` markers print immediately but events flush
> during shutdown. This is normal — see [example 01](../01-basic/).

Notice:
- `app_name`, `host`, `timezone`, `pid` appear in every event (framework fields)
- `source_ip` defaults to `10.0.0.1` when not set explicitly
- `target_id` and `reason` appear only when set — no null values
- Framework fields appear before user fields in consistent order

## CEF Output

If you configured a CEF formatter, the same events would use ArcSight
standard extension keys:

```
CEF:0|...|user_create|...|5|rt=... act=user_create deviceProcessName=standard-fields-demo dvchost=... dtz=UTC dvcpid=... suser=alice outcome=success reason=admin request src=10.0.0.1 duser=user-42 cat=write
```

SIEMs automatically map these keys: `suser` → Source User, `src` → Source IP,
`duser` → Destination User, `deviceProcessName` → Application. No custom
field extraction rules needed.

## Key Concepts

| Concept | What It Means |
|---------|---------------|
| **Reserved standard fields** | 31 well-known audit field names always available without declaration |
| **Framework fields** | `app_name`, `host`, `timezone`, `pid` — deployment identity in every event |
| **Standard field defaults** | YAML `standard_fields:` section for deployment-wide values |
| **Generated setters** | `.SetSourceIP()`, `.SetReason()`, etc. on every builder |
| **CEF mapping** | Standard fields map to ArcSight extension keys automatically |

## Further Reading

- [Taxonomy Validation](../../docs/taxonomy-validation.md)
- [JSON Format: Field Order](../../docs/json-format.md)
- [CEF Format: Field Mapping](../../docs/cef-format.md)
- [Output Configuration: Framework Fields](../../docs/output-configuration.md)

