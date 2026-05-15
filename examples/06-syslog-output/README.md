[← Back to examples](../README.md)

> **Previous:** [05 — Standard Fields](../05-standard-fields/) |
> **Next:** [07 — Webhook Output](../07-webhook-output/)
# Example 06: Syslog Output

Sends audit events to a syslog server as
[RFC 5424](https://datatracker.ietf.org/doc/html/rfc5424) structured
syslog messages over TCP. The example embeds a local TCP receiver so
it's fully self-contained — no external syslog server or Docker needed.

## What You'll Learn

1. How audit events are formatted as **RFC 5424 syslog messages**
2. How the syslog output handles **transport options** (TCP, UDP,
   TCP+TLS)
3. What the **facility** and **APP-NAME** header fields mean
4. How **automatic reconnection** works when the syslog server is
   temporarily unavailable
5. How to pair syslog with the **CEF formatter** for SIEM integration

## Prerequisites

None — the example embeds its own TCP syslog receiver.

For a real deployment, you'd point the output at your syslog
infrastructure (rsyslog, syslog-ng, Splunk, Graylog, or any
RFC 5424-compatible receiver).

## Files

| File | Purpose |
|------|---------|
| [`main.go`](main.go) | Creates an auditor with syslog output, starts a local TCP receiver, emits 4 events |
| [`outputs.yaml`](outputs.yaml) | Syslog output YAML configuration |
| [`taxonomy.yaml`](taxonomy.yaml) | 4 event types across 2 categories (security and write) |
| [`audit_generated.go`](audit_generated.go) | Generated typed builders |

## Running the Example

```bash
go run .
```

**Output** (4 RFC 5424 messages — note how the PRI field changes based
on event severity):

```
--- RFC 5424 messages received by syslog server ---
Note: PRI = facility(local0=128) + syslog severity
  <131> = LOG_ERR (audit severity 8-9)
  <132> = LOG_WARNING (audit severity 6-7)
  <133> = LOG_NOTICE (audit severity 4-5)

[Message 1]  auth_login (severity 5 → LOG_NOTICE)
<133>1 2026-04-05T... dev-machine audit-example 12345 audit-example - {"event_type":"auth_login","severity":5,...,"actor_id":"alice","outcome":"success","event_category":"security"}

[Message 2]  user_create (severity 5 → LOG_NOTICE)
<133>1 2026-04-05T... dev-machine audit-example 12345 audit-example - {"event_type":"user_create","severity":5,...,"actor_id":"bob","outcome":"success","event_category":"write"}

[Message 3]  auth_failure (severity 8 → LOG_ERR)
<131>1 2026-04-05T... dev-machine audit-example 12345 audit-example - {"event_type":"auth_failure","severity":8,...,"actor_id":"mallory","outcome":"failure","reason":"invalid_password","event_category":"security"}

[Message 4]  config_change (severity 7 → LOG_WARNING)
<132>1 2026-04-05T... dev-machine audit-example 12345 audit-example - {"event_type":"config_change","severity":7,...,"actor_id":"alice","outcome":"success","setting":"max_retries","event_category":"write"}

Total: 4 RFC 5424 messages received
```

Notice how each message has a different PRI value:
- `<133>` for severity 5 events (128 + 5 = LOG_NOTICE)
- `<132>` for severity 7 events (128 + 4 = LOG_WARNING)
- `<131>` for severity 8 events (128 + 3 = LOG_ERR)

SIEM systems can filter and route on these syslog severity levels without
parsing the JSON body.

## Key Concepts

### Understanding the RFC 5424 Message Format

Each syslog message follows the
[RFC 5424](https://datatracker.ietf.org/doc/html/rfc5424) structure:

```
<PRIORITY>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
```

Breaking down a real message from this example:

```
<134>1 2026-04-05T12:00:00+02:00 dev-machine audit-example 12345 audit-example - {...JSON...}
 │   │ │                         │            │             │     │              │ └─ MSG: the audit event JSON
 │   │ │                         │            │             │     │              └── SD: no structured data ("-")
 │   │ │                         │            │             │     └───────────────── MSGID: same as APP-NAME
 │   │ │                         │            │             └─────────────────────── PROCID: process ID
 │   │ │                         │            └───────────────────────────────────── APP-NAME: from config
 │   │ │                         └────────────────────────────────────────────────── HOSTNAME: from outputs.yaml
 │   │ └──────────────────────────────────────────────────────────────────────────── TIMESTAMP: RFC 3339
 │   └────────────────────────────────────────────────────────────────────────────── VERSION: always 1
 └────────────────────────────────────────────────────────────────────────────────── PRIORITY: facility × 8 + severity
```

### Understanding the PRIORITY Field

The `<NNN>` at the start of every syslog message is the **PRIORITY**
(PRI) — a single number that encodes two pieces of information:

1. **Facility** — which subsystem generated the message (configured in
   your `outputs.yaml`)
2. **Severity** — how critical the message is (derived automatically
   from the audit event's severity field)

The formula is: **`PRI = facility_number × 8 + syslog_severity`**

**Facility** is a syslog concept from
[RFC 5424](https://datatracker.ietf.org/doc/html/rfc5424). It tells
the syslog receiver which part of the system generated the message.
For audit logging, you typically use `local0` through `local7` (these
are reserved for local/custom use). Each facility name maps to a
number:

| Facility | Number | `Number × 8` |
|----------|--------|--------------|
| `local0` (default) | 16 | 128 |
| `local1` | 17 | 136 |
| `auth` | 4 | 32 |

So when you see `<133>`, that's `128 + 5` — facility `local0` (128)
plus syslog severity `notice` (5).

**Severity** is mapped automatically from your taxonomy's audit event
severity (0-10) to the RFC 5424 syslog severity scale (0-7):

| Audit Severity | Syslog Severity | RFC 5424 Name | PRI with local0 |
|---------------|----------------|---------------|-----------------|
| 10 | 2 | Critical | `<130>` |
| 8-9 | 3 | Error | `<131>` |
| 6-7 | 4 | Warning | `<132>` |
| 4-5 | 5 | Notice | `<133>` |
| 1-3 | 6 | Informational | `<134>` |
| 0 | 7 | Debug | `<135>` |

In this example:
- `auth_login` has no explicit severity → inherits category default (5)
  → PRI = 128 + 5 = `<133>` (notice)
- `auth_failure` has `severity: 8` → PRI = 128 + 3 = `<131>` (error)
- `config_change` has `severity: 7` → PRI = 128 + 4 = `<132>` (warning)

This means your SIEM can filter and route events at the syslog protocol
level — `auth_failure` events arrive as LOG_ERR and can trigger alerts,
while `auth_login` events arrive as LOG_NOTICE and go to standard
logging. No JSON parsing needed.

`LOG_EMERG` (0) and `LOG_ALERT` (1) are intentionally excluded — they
are reserved for system-level emergencies (kernel panics, hardware
failure) and can trigger console broadcasts and pager alerts on many
syslog receivers.

### Transport Options

| Transport | YAML `network:` | Use case | Reliability |
|-----------|-----------------|----------|-------------|
| **TCP** | `"tcp"` | Default. Reliable delivery with connection-oriented transport | Connection-based; reconnects on failure |
| **UDP** | `"udp"` | Fire-and-forget. No connection overhead, but messages may be silently lost or truncated | No delivery guarantee; messages > ~2048 bytes may be truncated ([RFC 5424 §6.1](https://datatracker.ietf.org/doc/html/rfc5424#section-6.1)) |
| **TCP+TLS** | `"tcp+tls"` | Encrypted transport. Required for compliance (PCI DSS, SOC 2) when events cross network boundaries | TLS 1.3 by default; supports mTLS with client certificates |

### Facility Values

The `facility` field identifies the type of program generating the
message. For audit logging, `local0` through `local7` are recommended
(they're reserved for local use):

| Facility | Numeric | Common use |
|----------|---------|------------|
| `local0` | 16 | **Default.** General audit logging |
| `local1`–`local7` | 17–23 | Additional audit streams or application tiers |
| `auth` | 4 | Authentication subsystem |
| `authpriv` | 10 | Private authentication messages |
| `daemon` | 3 | System daemons |

Full list: `kern`, `user`, `mail`, `daemon`, `auth`, `syslog`, `lpr`,
`news`, `uucp`, `cron`, `authpriv`, `ftp`, `local0`–`local7`.

### Automatic Reconnection

If the syslog server becomes unavailable, the output automatically
reconnects with bounded exponential backoff:

- **Base delay:** 100ms
- **Maximum delay:** 30s
- **Backoff factor:** 2× with random jitter ([0.5, 1.0) multiplier)
- **Max attempts:** Configurable via `max_retries` (default: 10)

During reconnection, the mutex is released so `auditor.Close()` can
interrupt the backoff sleep. The event that triggered the reconnection
is retried once on the new connection.

### YAML Configuration Explained

```yaml
outputs:
  siem:
    type: syslog               # Register with: import _ "github.com/axonops/audit/outputs" (all types) or _ "github.com/axonops/audit/syslog" (this type only)
    syslog:
      network: "tcp"           # Transport: "tcp" (default), "udp", or "tcp+tls"
      address: "localhost:1514" # Required: host:port of the syslog server
      app_name: "audit-example" # RFC 5424 APP-NAME (default: "audit")
      facility: "local0"       # Syslog facility (default: "local0")
      max_retries: 3           # Reconnection attempts (default: 10)
```

### CEF Formatter Pairing

Syslog + CEF is the standard pattern for SIEM integration. The CEF
(Common Event Format) formatter produces messages that tools like
ArcSight, Splunk, and QRadar can parse natively:

```yaml
outputs:
  siem:
    type: syslog
    syslog:
      network: "tcp+tls"
      address: "siem.internal:6514"
      facility: "local0"
    formatter:
      type: cef
      vendor: "MyCompany"
      product: "MyApp"
      version: "1.0"
```

See [Example 05: Formatters](../04-formatters/) for JSON vs CEF
comparison.

## Blank Import Required

Every output (including stdout) lives in a separate Go module and
requires a blank import to register its factory. The easiest path is
the convenience package that registers all built-in outputs:

```go
import _ "github.com/axonops/audit/outputs"
```

If you prefer to register only this example's output (smaller binary
for constrained deployments), import the syslog sub-module directly:

```go
import _ "github.com/axonops/audit/syslog"
```

Syslog itself lives in `github.com/axonops/audit/syslog`, which
depends on the `github.com/axonops/srslog` library for RFC 5424
formatting. The blank import triggers the `init()` function that
registers the `"syslog"` output factory.

## Further Reading

- [Syslog Output Reference](../../docs/syslog-output.md) — complete configuration, TLS, reconnection, production patterns
- [RFC 5424: The Syslog Protocol](https://datatracker.ietf.org/doc/html/rfc5424) — the standard this output implements
- [RFC 5425: TLS Transport Mapping for Syslog](https://datatracker.ietf.org/doc/html/rfc5425) — TLS transport standard
- [Output Types Overview](../../docs/outputs.md) — all five output types
- [Example 05: Formatters](../04-formatters/) — JSON vs CEF side-by-side
- [Output Configuration YAML](../../docs/output-configuration.md) — full YAML reference
