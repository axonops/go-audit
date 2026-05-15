[← Back to examples](../README.md)

> **Previous:** [07 — Webhook Output](../07-webhook-output/) |
> **Next:** [09 — Multi-Output](../09-multi-output/)
# Example 08: Loki Output

Sends audit events to [Grafana Loki](https://grafana.com/oss/loki/)
with stream labels for structured querying, gzip compression, and
batched delivery.

## What You'll Learn

1. How audit events are pushed to Loki as JSON log lines
2. How **stream labels** make events queryable by event type, category,
   application, and host — without scanning every log line
3. How to **search by labels** using LogQL to find specific audit events
4. How the YAML configuration controls batching, compression, and labels
5. What the actual data looks like in Loki — streams, labels, and payloads

## Prerequisites

Start a local Loki instance:

```bash
docker run -d --name loki -p 3100:3100 grafana/loki:3.0.0
```

## Files

| File | Purpose |
|------|---------|
| [`main.go`](main.go) | Creates an auditor with a Loki output and audits 5 events |
| [`outputs.yaml`](outputs.yaml) | YAML configuration for the Loki output |
| [`taxonomy.yaml`](taxonomy.yaml) | Event type definitions with required fields |
| [`README.md`](README.md) | This file |

## Running the Example

```bash
go run .
```

**Output:**

```
Audited: user_create by alice
Audited: user_create by bob
Audited: auth_failure by mallory
Audited: permission_denied by mallory
Audited: user_update by alice
Audited: health_check by alice
Audited: health_check by bob

Waiting for Loki delivery...
Done. Query your events:
  # All events (categorised + uncategorised):
  curl -s -H 'X-Scope-OrgID: example' 'http://localhost:3100/loki/api/v1/query_range?query={job="audit-example"}&limit=20' | jq .
  # Only categorised "write" events:
  curl -s -H 'X-Scope-OrgID: example' 'http://localhost:3100/loki/api/v1/query_range?query={event_category="write"}&limit=10' | jq .
  # Only uncategorised events (no event_category label):
  curl -s -H 'X-Scope-OrgID: example' 'http://localhost:3100/loki/api/v1/query_range?query={job="audit-example"}+|+json+|+event_category=""&limit=10' | jq .
  # All events by alice (across all categories):
  curl -s -H 'X-Scope-OrgID: example' 'http://localhost:3100/loki/api/v1/query_range?query={job="audit-example"}+|+json+|+actor_id="alice"&limit=10' | jq .
```

## What Happens Under the Hood

When you run this example, here's what happens:

1. **Taxonomy loaded** — `taxonomy.yaml` defines 4 event types across
   2 categories (`write` and `security`), each with required fields
2. **Loki output created** — `outputs.yaml` configures the Loki push
   URL, stream labels, batching, and compression
3. **Events audited** — 5 events are sent through the auditor. Each
   event is validated against the taxonomy, serialised as JSON, and
   enqueued in the Loki output's internal buffer
4. **Batch flushed** — the batch loop groups events by their stream
   labels and pushes them to Loki as a gzip-compressed JSON payload
5. **Events queryable** — within 1-2 seconds, the events are queryable
   via Loki's LogQL API

## Why Loki Is JSON-Only

Unlike other outputs (file, syslog, webhook), Loki outputs do **not**
support a `formatter:` block. Loki is locked to JSON because LogQL
queries use `| json` to parse event fields from stored log lines:

```logql
{job="audit-example"} | json | actor_id = "alice"
```

If events were CEF-formatted, this query would silently return no
results. The library enforces this at config load time — specifying
`formatter: cef` on a Loki output returns an error.

You can still customise JSON options (e.g. `timestamp: unix_ms`) by
explicitly setting `formatter: { type: json, timestamp: unix_ms }` on
the Loki output.

## Understanding Stream Labels

Events are grouped into **Loki streams** based on their label values.
Each unique combination of labels creates a separate stream:

```
Stream 1: {event_type="user_create", event_category="write", app_name="audit-example", ...}
  → alice's user_create
  → bob's user_create

Stream 2: {event_type="auth_failure", event_category="security", ...}
  → mallory's auth_failure

Stream 3: {event_type="permission_denied", event_category="security", ...}
  → mallory's permission_denied

Stream 4: {event_type="user_update", event_category="write", ...}
  → alice's user_update
```

The labels come from three sources:

| Source | Labels | Set when |
|--------|--------|----------|
| **Static** (config) | `job="audit-example"`, `environment="development"` | Config load time |
| **Framework** (logger) | `app_name="audit-example"`, `host="dev-machine"`, `pid="12345"` | Auditor construction |
| **Per-event** (metadata) | `event_type`, `event_category`, `severity` | Each audit event |

### PID — Why It Matters for Auditing

The `pid` (process ID) label is automatically captured via
`os.Getpid()` at logger construction. It identifies **which process
instance** generated each audit event. This is critical for:

- **Forensics** — after an incident, correlate events to the exact
  process that was running at the time
- **Multi-instance deployments** — when multiple instances of the same
  service are running, PID distinguishes their audit trails
- **Process lifecycle tracking** — a PID change indicates a process
  restart, which may be relevant during incident investigation

Query events from a specific process:

```logql
{app_name="audit-example", pid="12345"}
```

By default PID is included as a stream label. In high-cardinality
environments (many short-lived processes), you can exclude it:

```yaml
labels:
  dynamic:
    pid: false   # events still contain pid in the JSON body
```

Even when excluded from labels, the `pid` field still appears in
every JSON log line and is queryable via LogQL's `| json` parser:

```logql
{app_name="audit-example"} | json | pid=12345
```

**This is the key insight:** labels are indexed by Loki. Querying by
label is instant — Loki doesn't need to scan every log line. User
fields (`actor_id`, `outcome`, `resource_id`) stay in the JSON log
line and are queryable via LogQL's `| json` parser.

## Querying Events by Labels

### Query all events

```bash
curl -s -H 'X-Scope-OrgID: example' \
  'http://localhost:3100/loki/api/v1/query_range?query={job="audit-example"}&limit=10' \
  | jq '.data.result[] | {stream: .stream, count: (.values | length)}'
```

**Output — 5 streams, 7 total events** (4 categorised streams + 1 uncategorised stream):

```json
{
  "stream": {
    "app_name": "audit-example",
    "environment": "development",
    "event_category": "write",
    "event_type": "user_create",
    "host": "dev-machine",
    "job": "audit-example",
    "severity": "5"
  },
  "count": 2
}
{
  "stream": {
    "event_category": "write",
    "event_type": "user_update",
    ...
  },
  "count": 1
}
{
  "stream": {
    "event_category": "security",
    "event_type": "auth_failure",
    ...
  },
  "count": 1
}
{
  "stream": {
    "event_category": "security",
    "event_type": "permission_denied",
    ...
  },
  "count": 1
}
{
  "stream": {
    "app_name": "audit-example",
    "environment": "development",
    "event_type": "health_check",
    "host": "dev-machine",
    "job": "audit-example",
    "severity": "5"
  },
  "count": 2
}
```

### Search by `event_type` — find only authentication failures

```bash
curl -s -H 'X-Scope-OrgID: example' \
  'http://localhost:3100/loki/api/v1/query_range?query={event_type="auth_failure"}&limit=10' \
  | jq '.data.result[].values[][1]' -r | jq .
```

**Output — only the auth_failure event, not user_create or others:**

```json
{
  "timestamp": "2026-04-05T04:44:48.654192049+02:00",
  "event_type": "auth_failure",
  "severity": 5,
  "app_name": "audit-example",
  "host": "dev-machine",
  "timezone": "Local",
  "pid": 1695131,
  "actor_id": "mallory",
  "outcome": "failure",
  "reason": "invalid_password",
  "event_category": "security"
}
```

### Search by `event_category` — find all security events

```bash
curl -s -H 'X-Scope-OrgID: example' \
  'http://localhost:3100/loki/api/v1/query_range?query={event_category="security"}&limit=10' \
  | jq '.data.result[].values[][1]' -r | jq .
```

**Output — both security events (auth_failure + permission_denied), but no write events:**

```json
{
  "event_type": "auth_failure",
  "actor_id": "mallory",
  "outcome": "failure",
  "reason": "invalid_password",
  "event_category": "security"
}
{
  "event_type": "permission_denied",
  "actor_id": "mallory",
  "outcome": "failure",
  "resource": "admin_panel",
  "event_category": "security"
}
```

### Search by `app_name` — isolate events from this application

```bash
curl -s -H 'X-Scope-OrgID: example' \
  'http://localhost:3100/loki/api/v1/query_range?query={app_name="audit-example"}&limit=10' \
  | jq '.data.result | length' -r
```

**Output:** `4` (4 streams containing 5 events from this app)

### Combine labels with LogQL JSON parsing

Find user_create events by alice specifically:

```bash
curl -s -H 'X-Scope-OrgID: example' \
  'http://localhost:3100/loki/api/v1/query_range?query={event_type="user_create"}+|+json+|+actor_id="alice"&limit=10' \
  | jq '.data.result[].values[][1]' -r | jq .
```

**Output — only alice's user_create, not bob's:**

```json
{
  "timestamp": "2026-04-05T04:44:48.654167649+02:00",
  "event_type": "user_create",
  "severity": 5,
  "app_name": "audit-example",
  "host": "dev-machine",
  "actor_id": "alice",
  "outcome": "success",
  "resource_id": "user-42",
  "event_category": "write"
}
```

### Uncategorised events — health_check has no event_category

The `health_check` event type is intentionally NOT in any category.
In Loki, this means:

- It has **no `event_category` label** — it won't appear in
  `{event_category="write"}` or `{event_category="security"}` queries
- It has **no `event_category` field** in the JSON log line
- It forms its **own stream** in Loki (separate from categorised events)

**Find only uncategorised events:**

```bash
curl -s -H 'X-Scope-OrgID: example' \
  'http://localhost:3100/loki/api/v1/query_range?query={job="audit-example"}+|+json+|+event_category=""&limit=10' \
  | jq '.data.result[].values[][1]' -r | jq .
```

**Output — only health_check events (no event_category field):**

```json
{
  "timestamp": "...",
  "event_type": "health_check",
  "severity": 5,
  "app_name": "audit-example",
  "host": "dev-machine",
  "actor_id": "alice",
  "outcome": "success",
  "component": "database"
}
```

Notice: no `event_category` field. Categorised events like
`user_create` have `"event_category": "write"` — health_check doesn't.

**Find ALL events by alice (categorised + uncategorised):**

```bash
curl -s -H 'X-Scope-OrgID: example' \
  'http://localhost:3100/loki/api/v1/query_range?query={job="audit-example"}+|+json+|+actor_id="alice"&limit=10' \
  | jq '.data.result[].values[][1]' -r | jq .
```

This returns alice's `user_create`, `user_update`, AND `health_check`
events — searching by actor works across all categories (and no
category).

## YAML Configuration Explained

Each field in [`outputs.yaml`](outputs.yaml):

```yaml
version: 1

# Framework fields — appear in every event AND as Loki stream labels.
# These identify your application across all outputs.
app_name: "audit-example"    # → stream label app_name="audit-example"
host: "dev-machine"          # → stream label host="dev-machine"

outputs:
  loki_audit:
    type: loki               # Register with: import _ "github.com/axonops/audit/outputs" (all types) or _ "github.com/axonops/audit/loki" (this type only)
    loki:
      url: "http://localhost:3100/loki/api/v1/push"  # Full path required
      tenant_id: "example"   # Sets X-Scope-OrgID header for multi-tenant Loki
      allow_insecure_http: true   # http:// only — use https:// in production
      allow_private_ranges: true  # localhost — blocked by default (SSRF protection)

      # Batching — events are buffered and pushed in batches.
      batch_size: 10         # Push after 10 events (default: 100)
      flush_interval: "1s"   # Or push after 1 second, whichever comes first
      timeout: "5s"          # HTTP request timeout
      max_retries: 2         # Retry on 429/5xx with exponential backoff
      gzip: true             # Compress push payloads (default: true)

      # Stream labels control how events are indexed in Loki.
      labels:
        static:              # Constant labels on every stream
          job: "audit-example"
          environment: "development"
        dynamic:             # Per-event labels — all included by default
          pid: false         # Exclude PID (high cardinality in dev)
          # To exclude other labels: severity: false, host: false, etc.
```

## Blank Import Required

Every output (including stdout) lives in a separate Go module and
requires a blank import to register its factory. The easiest path is
the convenience package that registers all built-in outputs:

```go
import _ "github.com/axonops/audit/outputs"
```

If you prefer to register only Loki (smaller binary for constrained
deployments — Loki pulls in the full HTTP + gzip stack), import the
sub-module directly:

```go
import _ "github.com/axonops/audit/loki"
```

Without either, `outputconfig.Load` returns an error when it
encounters `type: loki` in the YAML.

## What the Event JSON Looks Like

Every audit event is serialised as a JSON log line in Loki. Here's
the complete structure for a `user_create` event:

```json
{
  "timestamp": "2026-04-05T04:44:48.654167649+02:00",
  "event_type": "user_create",
  "severity": 5,
  "app_name": "audit-example",
  "host": "dev-machine",
  "timezone": "Local",
  "pid": 1695131,
  "actor_id": "alice",
  "outcome": "success",
  "resource_id": "user-42",
  "event_category": "write"
}
```

Fields come from different sources:

| Field | Source | Description |
|-------|--------|-------------|
| `timestamp` | Automatic | When the event was processed |
| `event_type` | `audit.NewEvent("user_create", ...)` | The taxonomy event type |
| `severity` | Taxonomy default (5) | Numeric severity level |
| `app_name` | `outputs.yaml` top-level `app_name` | Application name |
| `host` | `outputs.yaml` top-level `host` | Hostname |
| `timezone` | Auto-detected | System timezone |
| `pid` | Auto-captured | Process ID |
| `actor_id` | Event fields | Who performed the action |
| `outcome` | Event fields | success/failure |
| `resource_id` | Event fields | What was affected |
| `event_category` | Taxonomy categories | Which category this event belongs to |

## Multi-Tenancy

The `tenant_id: "example"` field sets the `X-Scope-OrgID` header on
every push request. In multi-tenant Loki, this isolates your events
from other tenants. When querying, you must include the same header:

```bash
# This header is REQUIRED when tenant_id is set:
curl -H 'X-Scope-OrgID: example' 'http://localhost:3100/loki/api/v1/query_range?...'
```

Without the header, Loki returns 401 Unauthorized.

## Fail-Fast on Startup (#286)

The Loki output verifies connectivity to the push API at
construction time by default. `audit.New` returns a wrapped
error if the URL is unreachable, the TLS handshake fails, the
auth credentials are rejected, or the verification budget
elapses — surfacing the misconfiguration at application start-up
instead of as silent event loss on the first flush.

```yaml
loki:
  url: "http://loki:3100/loki/api/v1/push"
  verify_on_startup: true                 # default — fail at New()
  verify_on_startup_timeout: 5s           # default — budget for dial + handshake
```

Set `verify_on_startup: false` for sidecar deployments where Loki
may come up after the application, or for short-lived CLI tools
that must start regardless of receiver availability.

## Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| `401 Unauthorized` | Missing `X-Scope-OrgID` header in query | Add `-H 'X-Scope-OrgID: example'` to curl |
| `401 Unauthorized` | Missing `tenant_id` in config | Add `tenant_id: "example"` to outputs.yaml |
| Events not appearing | Loki ingestion delay | Wait 2-3 seconds after pushing |
| Connection refused | Loki not running | Run `docker run -d --name loki -p 3100:3100 grafana/loki:3.0.0` |
| `must be https` error | Using `http://` without flag | Add `allow_insecure_http: true` (dev only) |
| SSRF blocked | Using localhost without flag | Add `allow_private_ranges: true` (dev only) |

## Cleanup

```bash
docker stop loki && docker rm loki
```

## Further Reading

- [Output Configuration Reference](../../docs/output-configuration.md#loki-output-fields) — all config fields with defaults and bounds
- [Output Types](../../docs/outputs.md#loki-output) — Loki section with security and delivery details
- [Troubleshooting](../../docs/troubleshooting.md#loki-events-not-appearing) — common Loki issues
