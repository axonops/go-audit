[← Back to examples](../README.md)

> **Previous:** [03 — File Output](../03-file-output/) |
> **Next:** [05 — Standard Fields](../05-standard-fields/)
# Example 04: Formatters

Output the same events in two formats side by side: JSON for log
aggregators and CEF for SIEM tools like Splunk, ArcSight, or QRadar.

## What You'll Learn

- Configuring per-output formatters in `outputs.yaml`
- What CEF (Common Event Format) is and when to use it
- How JSON and CEF output differ
- How field names map between audit and CEF

## Prerequisites

- Go 1.26+
- Completed: [Code Generation](../02-code-generation/)

## Files

| File | Purpose |
|------|---------|
| `taxonomy.yaml` | Event definitions (embedded) |
| `outputs.yaml` | Two file outputs with different formatters |
| `audit_generated.go` | Generated constants (committed) |
| `main.go` | Emits events, prints both files |

## Key Concepts

### Per-Output Formatters in YAML

Each output can have its own `formatter:` block. Outputs without one
use JSON by default:

```yaml
version: 1
outputs:
  json_file:
    type: file
    file:
      path: "./json-audit.log"
    # No formatter — uses JSON by default.

  cef_file:
    type: file
    file:
      path: "./cef-audit.log"
    formatter:
      type: cef
      vendor: "Example"
      product: "AuditDemo"
      version: "1.0"
```

### What is CEF?

Common Event Format (CEF) is a standard log format used by SIEM tools.
If your organization uses Splunk, ArcSight, QRadar, or similar security
information tools, they likely expect CEF-formatted events.

A CEF line looks like:

```
CEF:0|Example|AuditDemo|1.0|user_create|user_create|5|rt=... suser=alice outcome=success
```

The `Vendor|Product|Version` triple identifies your application in the
SIEM. The extensions (`suser=alice`, `outcome=success`) are the event
fields mapped to CEF key names.

### CEF Field Mapping

The formatter automatically translates audit field names to standard
CEF extension keys via `FieldMapping` (configurable):

| audit field | CEF key |
|----------------|---------|
| `actor_id` | `suser` |
| `source_ip` | `src` |
| `request_id` | `externalId` |
| `user_agent` | `requestClientApplication` |
| `method` | `requestMethod` |
| `path` | `request` |
| `outcome` | `outcome` |

Fields without a mapping are passed through with their original names.

Framework extensions are emitted unconditionally and cannot be
overridden via `FieldMapping`:

| Framework field | CEF key | Description |
|-----------------|---------|-------------|
| timestamp | `rt` | Receipt time (Unix milliseconds) |
| `event_type` | `act` | Device action |
| `event_category` | `cat` | Appended when event belongs to a category |

### JSON Formatter Options

You can also customize the JSON formatter:

```yaml
formatter:
  type: json
  timestamp: unix_ms      # unix milliseconds instead of RFC3339
  omit_empty: true         # skip fields with zero values
```

Most applications leave the JSON default as-is.

## Run It

```bash
go run .
```

## Expected Output

```
INFO audit: auditor created queue_size=10000 shutdown_timeout=5s validation_mode=strict outputs=2 synchronous=false
INFO audit: shutdown started
INFO audit: shutdown complete duration=...

--- json-audit.log ---
{"timestamp":"...","event_type":"user_create","severity":3,"app_name":"example","host":"localhost","timezone":"Local","pid":...,"actor_id":"alice","outcome":"success","event_category":"write"}
{"timestamp":"...","event_type":"auth_failure","severity":8,"app_name":"example","host":"localhost","timezone":"Local","pid":...,"actor_id":"unknown","outcome":"failure","event_category":"security"}
{"timestamp":"...","event_type":"auth_success","severity":8,"app_name":"example","host":"localhost","timezone":"Local","pid":...,"actor_id":"bob","outcome":"success","event_category":"security"}

--- cef-audit.log ---
CEF:0|Example|AuditDemo|1.0|user_create|A new user account was created|3|rt=... act=user_create deviceProcessName=example dvchost=localhost dvcpid=... suser=alice outcome=success cat=write
CEF:0|Example|AuditDemo|1.0|auth_failure|An authentication attempt failed|8|rt=... act=auth_failure deviceProcessName=example dvchost=localhost dvcpid=... suser=unknown outcome=failure cat=security
CEF:0|Example|AuditDemo|1.0|auth_success|An authentication attempt succeeded|8|rt=... act=auth_success deviceProcessName=example dvchost=localhost dvcpid=... suser=bob outcome=success cat=security
```

Both files contain the same three events in different formats. The CEF
output uses the `suser` extension key for `actor_id`, and the
`Vendor|Product|Version` header from the YAML config. The
`cat` extension (ArcSight `deviceEventCategory`) appears in CEF because
`event_category` is automatically mapped.

## Further Reading

- [JSON Format](../../docs/json-format.md) — JSON formatter options and field ordering
- [CEF Format](../../docs/cef-format.md) — CEF structure, field mapping, and SIEM integration
- [Output Configuration YAML](../../docs/output-configuration.md) — formatter: block syntax

