[← Back to Output Types](outputs.md)

# Loki Output — Detailed Reference

The Loki output pushes audit events to [Grafana Loki](https://grafana.com/oss/loki/)
via the HTTP Push API. Events are batched, grouped into streams by
label values, gzip-compressed, and delivered with exponential backoff
retry.

- [Why Loki for Audit Logging?](#why-loki-for-audit-logging)
- [Quick Start](#quick-start)
- [How It Works](#how-it-works)
- [Buffering Architecture](#buffering-architecture)
- [Stream Labels](#stream-labels)
- [Complete Configuration Reference](#complete-configuration-reference)
- [Authentication](#authentication)
- [TLS Configuration](#tls-configuration)
- [Multi-Tenancy](#multi-tenancy)
- [Batching and Delivery](#batching-and-delivery)
- [Retry and Error Handling](#retry-and-error-handling)
- [Security](#security)
- [Querying Events with LogQL](#querying-events-with-logql)
- [Production Configuration](#production-configuration)
- [Performance Tuning](#performance-tuning)
- [Metrics and Monitoring](#metrics-and-monitoring)
- [Troubleshooting](#troubleshooting)

---

## Why Loki for Audit Logging?

Loki is purpose-built for log aggregation with these properties that
make it ideal for audit trails:

- **Stream labels** derived from event metadata (`event_type`,
  `severity`, `event_category`) make audit events instantly queryable
  without scanning every log line
- **Immutable storage** — once ingested, events cannot be modified,
  providing tamper evidence for compliance
- **Multi-tenancy** via `X-Scope-OrgID` isolates different
  applications or environments in a shared Loki cluster
- **Grafana integration** provides dashboards, alerting, and LogQL
  exploration — see [Grafana Dashboard for audit](https://github.com/axonops/audit/issues/273)
- **Cost-effective** — Loki indexes only labels (not full-text),
  making it significantly cheaper than traditional SIEM at scale

---

## Quick Start

```bash
# 1. Install the module
go get github.com/axonops/audit/loki

# 2. Import for side-effect registration
import _ "github.com/axonops/audit/loki"

# 3. Add to your outputs.yaml
# See Complete Configuration Reference below
```

For a working example with code, see the
[progressive example](../examples/14-loki-output/).

---

## How It Works

When you audit an event, here's what happens:

```
Your code                    audit core              Loki output
─────────                    ──────────────             ───────────
auditor.AuditEvent(event) →   validate + serialize →     WriteWithMetadata()
                                                          ↓
                                                        enqueue in buffer
                                                          ↓ (non-blocking)
                                                        batchLoop goroutine
                                                          ↓
                                                        group by stream labels
                                                          ↓
                                                        build JSON push payload
                                                          ↓
                                                        gzip compress
                                                          ↓
                                                        POST to Loki
                                                          ↓
                                                        retry on 429/5xx
```

The Loki output runs its own goroutine (`batchLoop`) that:
1. Reads events from an internal buffered channel
2. Groups them by stream labels (events with the same label values
   go into the same stream)
3. Flushes when: batch size reached, byte limit reached, or timer fires
4. Builds the Loki push API JSON payload
5. Gzip-compresses it
6. POSTs it to Loki with retry on failure

---

## Buffering Architecture

The Loki output has its own internal buffer separate from the core
logger buffer. This is [Level 2](async-delivery.md#two-level-buffering)
in the pipeline:

```
Core drain goroutine ──► WriteWithMetadata()
                            → copies event bytes
                            → enqueues to Loki channel (capacity: buffer_size, default 10,000)
                            → returns immediately (non-blocking)

Loki batchLoop goroutine
  → reads from channel
  → accumulates into batch
  → flushes on: batch_size (100) | max_batch_bytes (1 MiB) | flush_interval (5s) | shutdown
  → groups events by stream labels
  → gzip compresses
  → HTTP POST to Loki
  → retries on 429/5xx
```

### `buffer_size` vs `batch_size`

These are different things:

| Config | Default | What It Controls |
|--------|---------|------------------|
| `buffer_size` | 10,000 | How many events can **queue up** waiting to be sent. This is the channel capacity. |
| `batch_size` | 100 | How many events are grouped into a **single HTTP POST**. This is the flush threshold. |

With the defaults, up to 100 batches of events (10,000 ÷ 100) can be
queued before drops begin. Increasing `buffer_size` absorbs longer
outages; decreasing `batch_size` or `flush_interval` drains the buffer
faster.

### Drop Behaviour

If the internal buffer fills (e.g., Loki is down and retries are
consuming time), new events are **dropped silently** — the
`WriteWithMetadata()` call returns `nil` to avoid blocking the core
drain goroutine. This isolation ensures that a Loki outage does not
affect delivery to other outputs.

A rate-limited `slog.Warn` fires at most once per 10 seconds during
sustained drops. The `RecordDrop()` metric fires on **every**
drop — use metrics, not log lines, for precise monitoring.

### Relationship to Core Buffer

The Loki `buffer_size` is independent of the core `auditor.queue_size`
(`WithQueueSize`). Both default to 10,000 but they serve different
pipeline stages. See
[Two-Level Buffering](async-delivery.md#two-level-buffering) for the
full architecture diagram and memory sizing guidance.

---

## Stream Labels

### What Are Stream Labels?

Stream labels are key-value pairs that identify a log stream in Loki.
They are **indexed** — Loki can instantly find events matching a label
query without scanning every log line. This is the primary mechanism
for searching audit events.

### Label Sources

audit generates labels from three sources:

| Source | Labels | Set when | Example |
|--------|--------|----------|---------|
| **Static** | Configured in YAML | Config load | `job="audit"`, `environment="prod"` |
| **Framework** | From auditor options | Auditor construction | `app_name="myservice"`, `host="prod-01"`, `pid="12345"` |
| **Per-event** | From event metadata | Each audit event | `event_type="user_create"`, `event_category="write"`, `severity="5"` |

### The Seven Dynamic Labels

| Label | Source | Typical values | Why it matters |
|-------|--------|---------------|----------------|
| `app_name` | `WithAppName()` or YAML `app_name` | `"myservice"`, `"auth-gateway"` | Isolate events from different applications |
| `host` | `WithHost()` or YAML `host` | `"prod-01"`, `"us-east-1a"` | Identify which server generated the event |
| `timezone` | `WithTimezone()` or auto-detected | `"UTC"`, `"Europe/London"` | **Forensics** — correlate events across regions; compliance requirement for unambiguous timestamps. See [Why Timezone?](#why-timezone-is-always-included) |
| `pid` | Auto-captured `os.Getpid()` | `"12345"` | **Forensics** — identify which process instance generated each event. Critical for multi-instance deployments and incident investigation. A PID change indicates a process restart. |
| `event_type` | From `audit.NewEvent(type, ...)` | `"user_create"`, `"auth_failure"` | Primary query axis — what happened |
| `event_category` | From taxonomy categories | `"write"`, `"security"` | Group related event types for broad queries |
| `severity` | From taxonomy/category/event | `"0"` to `"10"` | Filter by importance level |

### Stream Label vs JSON Log Line

This is a critical distinction:

```
STREAM LABELS (indexed, fast query via {selector}):
  event_type="user_create"
  event_category="write"
  app_name="myservice"
  host="prod-01"
  timezone="UTC"
  pid="12345"
  severity="5"
  job="audit"            ← static label
  environment="prod"     ← static label

JSON LOG LINE (full event, searched via | json or |= text):
  {
    "timestamp": "2026-04-05T...",
    "event_type": "user_create",
    "severity": 5,
    "app_name": "myservice",
    "host": "prod-01",
    "pid": 12345,
    "actor_id": "alice",          ← NOT a label
    "outcome": "success",         ← NOT a label
    "resource_id": "user-42",     ← NOT a label
    "event_category": "write"
  }
```

User fields (`actor_id`, `outcome`, `resource_id`) are **never** labels.
To search by them, use LogQL's JSON parser:

```logql
{event_type="user_create"} | json | actor_id="alice"
```

### Uncategorised Events in Loki

Events that are not assigned to any category in the taxonomy are
**uncategorised** — they have no `event_category` value. In Loki,
this means:

- The `event_category` label is **absent** from the stream (not
  empty — absent entirely)
- The `event_category` field is **omitted** from the JSON log line
- Uncategorised events end up in a **separate stream** from
  categorised events (even if all other labels match)

**This does NOT affect searchability.** All events — categorised and
uncategorised — are fully queryable. You just need the right LogQL
pattern:

```logql
# Find ALL events (categorised + uncategorised) for an actor:
{app_name="myservice"} | json | actor_id="alice"

# Find only categorised events in the "write" category:
{event_category="write"}

# Find only uncategorised events (no event_category label):
{app_name="myservice"} | json | event_category=""

# Or via label negation (events NOT in any known category):
{app_name="myservice", event_category!="write", event_category!="security"}
```

The label negation approach works because Loki's `!=` matcher matches
streams where the label is absent OR has a different value.
Uncategorised events (no `event_category` label) match
`event_category!="write"`.

**What does "separate streams" actually mean?**

A Loki stream is a sequence of log lines that share the same label
set. Loki stores and indexes each stream independently. When
uncategorised events lack the `event_category` label, they form a
label set that differs from categorised events — so Loki puts them
in a separate stream.

In practice, this has **no negative impact**:

- **Query performance** is unaffected — Loki is designed to handle
  thousands of streams efficiently. One extra stream per unique
  uncategorised event type is negligible
- **Storage** is unaffected — log lines are compressed per-stream,
  and uncategorised events compress just as well
- **You don't need to avoid uncategorised events** — they are a
  normal and expected part of audit logging (health checks, system
  events, custom events not yet categorised)

The only practical effect is that `{event_category="write"}` won't
return uncategorised events, which is the correct behaviour — they
genuinely have no category. Use `{app_name="myservice"}` or the
JSON parser to search across all events regardless of category.

### Excluding Dynamic Labels

All seven dynamic labels are included by default. Set to `false` to
exclude:

```yaml
labels:
  dynamic:
    pid: false       # exclude PID (high cardinality across processes)
    severity: false   # exclude severity from labels
```

**When excluded**, the field still appears in every JSON log line. It
is just not indexed as a Loki label. You can still query it:

```logql
# pid excluded from labels, but still in JSON:
{app_name="myservice"} | json | pid=12345
```

### Cardinality Considerations

Each unique combination of label values creates a separate Loki stream.
Loki has configurable limits on active stream count (typically 5,000
per tenant by default). High-cardinality labels create too many streams
and degrade performance or trigger rejection.

**Safe labels** (bounded cardinality):
- `event_type` — bounded by your taxonomy definition
- `event_category` — bounded by your taxonomy definition
- `severity` — bounded (0-10)
- `app_name` — bounded (one per service)
- `host` — bounded (one per server)

**Potentially dangerous labels** (unbounded cardinality):
- `pid` — changes on every process restart. Safe for long-lived
  services, risky for short-lived workers (serverless, cron jobs).
  Exclude with `pid: false` if you see "too many streams" errors.

---

## Complete Configuration Reference

### YAML Configuration

```yaml
outputs:
  loki_audit:
    type: loki
    loki:
      # --- Required ---
      url: "https://loki.example.com/loki/api/v1/push"

      # --- Authentication (choose one) ---
      basic_auth:
        username: "${LOKI_USERNAME}"
        password: "${LOKI_PASSWORD}"
      # bearer_token: "${LOKI_TOKEN}"     # alternative to basic_auth

      # --- Multi-tenancy ---
      tenant_id: "${LOKI_TENANT:-}"       # X-Scope-OrgID header

      # --- Stream labels ---
      labels:
        static:
          job: "audit"
          environment: "${ENVIRONMENT:-production}"
        dynamic:                          # all included by default
          # pid: false                    # exclude if high cardinality

      # --- Batching ---
      batch_size: 100                     # events per push (default: 100)
      max_batch_bytes: 1048576            # bytes per push (default: 1 MiB)
      max_event_bytes: 1048576            # per-event cap; oversized rejected with ErrEventTooLarge (#688)
      flush_interval: "5s"               # time-based flush (default: "5s")
      buffer_size: 10000                  # internal buffer (default: 10,000)

      # --- HTTP ---
      timeout: "10s"                      # request timeout (default: "10s")
      max_retries: 3                      # retry on 429/5xx (default: 3)
      gzip: true                          # compress payloads (default: true)

      # --- Custom headers ---
      headers:
        X-Custom-Header: "my-value"

      # --- TLS ---
      tls_ca: "/etc/audit/ca.pem"
      tls_cert: "/etc/audit/client.pem"   # for mTLS
      tls_key: "/etc/audit/client-key.pem"
      tls_policy:
        allow_tls12: false                # TLS 1.3 only by default
        allow_weak_ciphers: false

      # --- Development only ---
      # allow_insecure_http: true         # MUST NOT be true in production
      # allow_private_ranges: true        # disables SSRF protection

    # --- Per-output features ---
    route:
      include_categories:
        security: {}
    exclude_labels:
      - pii
    hmac:
      enabled: true
      salt: "${HMAC_SALT}"
      version: "v1"
      algorithm: "HMAC-SHA-256"
```

### Formatter Restriction

Loki outputs are locked to JSON format. Specifying `formatter: cef` (or
any non-JSON formatter) on a Loki output returns an error at config load
time:

```text
audit: output config validation failed: output "loki_audit": loki does not support custom formatters; loki requires JSON format for label extraction and LogQL queries
```

**Why?** Loki depends on JSON for two reasons:

1. **LogQL `| json`** — the primary query pattern for extracting event
   fields from stored log lines requires JSON-formatted entries
2. **Flat field access** — LogQL `| json | actor_id = "alice"` works
   only with JSON; CEF extension key-value pairs are not natively
   parseable by Loki

> Note: Stream labels (`event_type`, `app_name`, etc.) are derived from
> Go metadata structs, not from the formatted log line. The formatter
> restriction exists because of LogQL's JSON dependency for querying
> stored events, not label derivation.

To customise JSON options (e.g. `timestamp: unix_ms` or
`omit_empty: true`), set `formatter: { type: json, ... }` explicitly on
the Loki output.

### Field Reference

| Field | Type | Default | Range | Description |
|-------|------|---------|-------|-------------|
| `url` | string | (required) | — | Full Loki push API endpoint including path (`/loki/api/v1/push`). MUST be `https://` unless `allow_insecure_http` is set. |
| `basic_auth.username` | string | — | — | HTTP basic auth username. MUST NOT be empty when `basic_auth` is present. MUST NOT be set alongside `bearer_token`. |
| `basic_auth.password` | string | — | — | HTTP basic auth password. |
| `bearer_token` | string | — | — | Sets `Authorization: Bearer <token>`. MUST NOT be set alongside `basic_auth`. |
| `tenant_id` | string | — | — | Sets `X-Scope-OrgID` header for Loki multi-tenancy. When set, queries MUST include the same header. |
| `headers` | map | — | — | Custom HTTP headers. MUST NOT include `Authorization`, `X-Scope-OrgID`, `Content-Type`, `Content-Encoding`, or `Host` — use the dedicated fields. |
| `labels.static` | map | — | — | Constant labels on every stream. Keys MUST match `[a-zA-Z_][a-zA-Z0-9_]*`. Values MUST NOT be empty or contain control characters (0x00-0x1F). |
| `labels.dynamic` | map | all included | — | Per-event label toggles. Valid keys: `app_name`, `host`, `timezone`, `pid`, `event_type`, `event_category`, `severity`. Set to `false` to exclude. Unknown keys are rejected. |
| `gzip` | bool | `true` | — | Gzip compress push request bodies. **Note**: the YAML key is `gzip`, not `compress`. |
| `batch_size` | int | `100` | 1 – 10,000 | Maximum events per push request. |
| `max_batch_bytes` | int | `1048576` | 1,024 – 10,485,760 | Maximum uncompressed payload bytes per push (1 MiB default, 10 MiB max). |
| `max_event_bytes` | int | `1048576` | 1,024 – 10,485,760 | Per-event size cap at `Write()`. Oversized events rejected with `audit.ErrEventTooLarge` — also satisfies `errors.Is(err, audit.ErrValidation)` (#688). |
| `flush_interval` | duration | `"5s"` | 100ms – 5m | Time between flushes when batch is not full. |
| `timeout` | duration | `"10s"` | 1s – 5m | HTTP request timeout. |
| `max_retries` | int | `3` | 1 – 20 | Retry attempts on 429 or 5xx responses. |
| `buffer_size` | int | `10000` | 100 – 1,000,000 | Internal async buffer capacity. Events are dropped when full. |
| `tls_ca` | string | — | — | CA certificate path for TLS verification. |
| `tls_cert` | string | — | — | Client certificate path for mTLS. MUST be set together with `tls_key`. |
| `tls_key` | string | — | — | Client key path for mTLS. MUST be set together with `tls_cert`. |
| `tls_policy.allow_tls12` | bool | `false` | — | Allow TLS 1.2 in addition to TLS 1.3. |
| `tls_policy.allow_weak_ciphers` | bool | `false` | — | Allow weaker cipher suites when TLS 1.2 is enabled. |
| `allow_insecure_http` | bool | `false` | — | Allow `http://` URLs. **MUST NOT** be `true` in production. |
| `allow_private_ranges` | bool | `false` | — | Allow private/loopback IP ranges. Disables SSRF protection. |
| `verify_on_startup` | bool | `true` | `true` or `false` | When `true` (default), `New()` performs a TCP dial — and, for `https://` URLs, a TLS handshake — against the Loki endpoint before returning, so a misconfigured or unreachable destination fails fast at startup rather than silently dropping events at the first push. Set to `false` for sidecar/lazy-start deployments where Loki may not yet be running when the application starts; the runtime retry path handles delivery once Loki becomes available. The probe applies the SAME SSRF policy as the runtime transport: `allow_private_ranges: false` rejects loopback / RFC 1918 at probe time too. |
| `verify_on_startup_timeout` | duration | `5s` | any positive duration | Bounds the construction-time probe. Independent of `timeout` (which governs runtime requests). Operators on slow WAN paths can raise this; CI/local development is fine with the default. Ignored when `verify_on_startup: false`. |

---

## Authentication

### Basic Auth (Grafana Cloud)

```yaml
loki:
  url: "https://logs-prod-us-central1.grafana.net/loki/api/v1/push"
  basic_auth:
    username: "${GRAFANA_CLOUD_USER}"   # numeric user ID
    password: "${GRAFANA_CLOUD_KEY}"    # API key
```

### Bearer Token

```yaml
loki:
  url: "https://loki.internal:3100/loki/api/v1/push"
  bearer_token: "${LOKI_TOKEN}"
```

### No Authentication

For Loki instances without auth (development, private networks):

```yaml
loki:
  url: "http://loki.internal:3100/loki/api/v1/push"
  allow_insecure_http: true    # only if using http://
  allow_private_ranges: true   # only if Loki is on private network
```

**Mutual exclusivity**: `basic_auth` and `bearer_token` MUST NOT both
be set. The library rejects this at construction time.

---

## TLS Configuration

### Server Certificate Verification

```yaml
loki:
  url: "https://loki.internal:3100/loki/api/v1/push"
  tls_ca: "/etc/audit/internal-ca.pem"
```

### Mutual TLS (mTLS)

```yaml
loki:
  url: "https://loki.internal:3100/loki/api/v1/push"
  tls_ca: "/etc/audit/ca.pem"
  tls_cert: "/etc/audit/client-cert.pem"
  tls_key: "/etc/audit/client-key.pem"
```

### TLS Policy

By default, only TLS 1.3 is accepted. For legacy infrastructure:

```yaml
loki:
  tls_policy:
    allow_tls12: true          # accept TLS 1.2 connections
    allow_weak_ciphers: false  # keep strong ciphers even with TLS 1.2
```

---

## Multi-Tenancy

Loki supports multi-tenancy via the `X-Scope-OrgID` header. Set
`tenant_id` to isolate your events:

```yaml
loki:
  tenant_id: "team-security"
```

**Critical**: when querying events pushed with a `tenant_id`, you MUST
include the same header in your query:

```bash
curl -H 'X-Scope-OrgID: team-security' \
  'http://loki:3100/loki/api/v1/query_range?query={job="audit"}&limit=10'
```

Without the header, Loki returns 401 or empty results depending on
its configuration.

---

## Batching and Delivery

Events are delivered in batches. A batch is flushed when ANY of these
conditions is met:

| Trigger | Default | Description |
|---------|---------|-------------|
| **Count** | 100 events | `batch_size` events accumulated |
| **Bytes** | 1 MiB | `max_batch_bytes` uncompressed bytes |
| **Timer** | 5 seconds | `flush_interval` elapsed since last flush |
| **Shutdown** | — | `auditor.Close()` flushes remaining events |

### Delivery Guarantee

**At-least-once** — a batch may be delivered more than once if Loki
accepts the payload but the acknowledgement is lost. Design your log
pipeline to tolerate duplicate entries.

### Buffer Drops

If events arrive faster than batches can be delivered, the internal
buffer fills. When full, new events are **dropped** (the `Write` call
returns `nil` to avoid blocking the audit pipeline).

A `slog.Warn` diagnostic message fires **at most once per 10 seconds**
during sustained drops, reporting the accumulated drop count:

```
WARN audit: loki buffer full, events dropped  dropped=1523  buffer_size=10000
```

This rate-limiting prevents the warning itself from becoming a
performance bottleneck under backpressure. The `RecordDrop()`
metric fires on **every** drop regardless of the warning interval —
use metrics, not log lines, for precise drop monitoring.

Monitor drops via `OutputMetrics.RecordDrop()`. Increase
`buffer_size` if you see drops.

---

## Retry and Error Handling

| Response | Action | Description |
|----------|--------|-------------|
| **2xx** | Success | Event delivered. `RecordFlush()` called. |
| **429** | Retry | Rate limited. Respects `Retry-After` header (capped at 30s). |
| **5xx** | Retry | Server error. Exponential backoff. |
| **4xx** (not 429) | Drop | Client error (bad config). `RecordDrop()` called. No retry. |
| **Network error** | Retry | Connection refused, DNS failure, etc. |
| **Redirect** | Drop | All redirects are rejected (SSRF protection). |

### Exponential Backoff

- **Base**: 100ms
- **Factor**: 2x per attempt
- **Cap**: 5 seconds
- **Jitter**: [0.5, 1.0) multiplicative (via `crypto/rand`)
- **Max attempts**: `max_retries` (default 3, max 20)

After all retries are exhausted, the batch is dropped and
`RecordDrop()` is called for each event.

---

## Security

### Production Checklist — Dangerous Opt-In Flags

The Loki output exposes two flags that relax the default safe posture.
Both default to OFF; setting either to `true` is acceptable ONLY in
the deployment patterns listed.

| Flag | Default | When `true` is acceptable | When `true` is a misconfiguration |
|---|---|---|---|
| `allow_insecure_http` | `false` (HTTPS-only) | Local development; CI smoke tests against an in-cluster Loki on a closed network. Operator owns the Loki cluster. | Any production deployment. Audit events traverse the network in cleartext and operator credentials (basic auth, bearer token, tenant ID) ride the same plaintext channel — exposed to any in-network attacker. |
| `allow_private_ranges` | `false` (SSRF block list active) | In-cluster Loki addressed by RFC1918 / IPv6 ULA where the SSRF guard would otherwise block. The Loki target is operator-deployed inside the same network policy zone. | Any URL whose authority is influenced by configuration templated from external systems; multi-tenant clusters where another tenant could sit on the same private range. |

Cloud-metadata, link-local, CGNAT, multicast, and unspecified-address
blocks remain active **even when `allow_private_ranges: true`** — see
the SSRF Protection table below for the full block list and the
unconditional reason labels.

Before flipping either flag in production, the operator MUST:

1. Document the specific Loki host and rationale in the deployment
   manifest (Helm values, Terraform, Kubernetes ConfigMap).
2. Set the Loki receiver behind authentication
   (`basic_auth.username` / `basic_auth.password`, or a bearer token,
   or mTLS via `tls_cert` + `tls_key`) so the relaxed network posture
   does not become an open ingest path.
3. Pin egress to the Loki host via NetworkPolicy / firewall rules.

See [SECURITY.md](../SECURITY.md) and [docs/threat-model.md](threat-model.md)
for the broader posture.

### SSRF Protection

Private, loopback, and reserved IP ranges are **blocked by default**.
Blocks marked with ★ apply **even when `allow_private_ranges: true`**
— set that flag only to permit RFC 1918 / loopback in private
network deployments.

| Block | Range / Address | ★ Always | Reason label |
|-------|----------------|----------|--------------|
| Private (RFC 1918) | `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` | | `private` |
| IPv6 ULA | `fc00::/7` | | `private` |
| Loopback | `127.0.0.0/8`, `::1` | | `loopback` |
| Link-local | `169.254.0.0/16`, `fe80::/10` | ★ | `link_local` |
| Cloud metadata IPv4 | `169.254.169.254` | ★ | `cloud_metadata` |
| Cloud metadata IPv6 (AWS IMDSv2) | `fd00:ec2::254` | ★ | `cloud_metadata` |
| CGNAT (RFC 6598) | `100.64.0.0/10` | ★ | `cgnat` |
| Deprecated site-local IPv6 | `fec0::/10` | ★ | `deprecated_site_local` |
| Multicast | `224.0.0.0/4`, `ff00::/8` | ★ | `multicast` |
| Unspecified | `0.0.0.0`, `::` | ★ | `unspecified` |
| IPv4-mapped IPv6 | `::ffff:a.b.c.d` | Normalised to IPv4 before classification | *(per above)* |

SSRF rejections return `*audit.SSRFBlockedError` (wrapping
`audit.ErrSSRFBlocked`). Use `errors.As` to switch on `.Reason` for
metric labelling or per-reason alerting:

```go
var ssrfErr *audit.SSRFBlockedError
if errors.As(err, &ssrfErr) {
    metricSSRFBlocked.With("reason", string(ssrfErr.Reason)).Inc()
}
```

### Redirect Blocking

HTTP redirects are **never followed**. This prevents SSRF via open
redirects where an attacker controls the Loki URL and redirects to
an internal service.

For any 3xx response that still reaches the response-drain path (such
as a non-redirect `300 Multiple Choices`), the body is drained **at
most 4 KiB**. Without this cap an attacker-controlled endpoint could
force up to `maxResponseBody` (64 KiB) of traffic per retry
(issue #484).

### Credential Redaction

`Config.String()`, `fmt.Sprintf("%+v", cfg)`, and `fmt.Sprintf("%#v", cfg)`
all redact credentials. Passwords and bearer tokens never appear in
log output or error messages.

### Restricted Headers

The `headers` map MUST NOT include these library-managed headers:
`Authorization`, `X-Scope-OrgID`, `Content-Type`, `Content-Encoding`, `Host`.
Use the dedicated config fields instead.

---

## Querying Events with LogQL

### By Event Type

```logql
{event_type="auth_failure"}
```

Returns only authentication failure events — user_create, user_update,
etc. are excluded.

### By Category

```logql
{event_category="security"}
```

Returns all security events (auth_failure, permission_denied, etc.)
but not write events (user_create, user_update).

### By Application and Host

```logql
{app_name="myservice", host="prod-01"}
```

### By PID (Process Instance)

```logql
{pid="12345"}
```

Useful for forensics — correlate events to a specific process instance.

### Combining Labels with JSON Field Search

```logql
{event_type="user_create"} | json | actor_id="alice"
```

The `| json` stage parses the log line as JSON, then
`actor_id="alice"` filters on the parsed field.

### Aggregation Queries

```logql
# Count events per type in the last hour
sum by (event_type) (count_over_time({job="audit"}[1h]))

# Rate of security events per minute
rate({event_category="security"}[5m])

# Count of failures
count_over_time({job="audit"} | json | outcome="failure" [1h])
```

---

## Production Configuration

### Grafana Cloud

```yaml
outputs:
  loki_prod:
    type: loki
    loki:
      url: "https://logs-prod-us-central1.grafana.net/loki/api/v1/push"
      basic_auth:
        username: "${GRAFANA_CLOUD_USER}"
        password: "${GRAFANA_CLOUD_KEY}"
      batch_size: 100
      flush_interval: "5s"
      timeout: "30s"
      max_retries: 5
      gzip: true
      labels:
        static:
          job: "audit"
          environment: "${ENVIRONMENT}"
          cluster: "${CLUSTER_NAME}"
```

### Private Loki Cluster with mTLS

```yaml
outputs:
  loki_internal:
    type: loki
    loki:
      url: "https://loki.internal:3100/loki/api/v1/push"
      tenant_id: "${SERVICE_NAME}"
      tls_ca: "/etc/audit/ca.pem"
      tls_cert: "/etc/audit/client.pem"
      tls_key: "/etc/audit/client-key.pem"
      batch_size: 200
      max_batch_bytes: 5242880          # 5 MiB
      flush_interval: "10s"
      buffer_size: 50000
      max_retries: 5
      labels:
        static:
          job: "audit"
          environment: "production"
```

### Development

```yaml
outputs:
  loki_dev:
    type: loki
    loki:
      url: "http://localhost:3100/loki/api/v1/push"
      allow_insecure_http: true
      allow_private_ranges: true
      batch_size: 1                     # immediate delivery for debugging
      flush_interval: "100ms"
      labels:
        static:
          job: "audit-dev"
        dynamic:
          pid: false                    # exclude PID in dev
```

---

## Performance Tuning

| Parameter | Trade-off |
|-----------|-----------|
| `batch_size` ↑ | Fewer HTTP requests, higher latency per event |
| `batch_size` ↓ | More HTTP requests, lower latency |
| `max_batch_bytes` ↑ | Larger payloads, more memory per batch |
| `flush_interval` ↑ | Longer delays before events reach Loki |
| `flush_interval` ↓ | More frequent pushes, higher overhead |
| `buffer_size` ↑ | Handles burst traffic, more memory |
| `gzip: false` | Less CPU, larger network payloads |
| `timeout` ↑ | Tolerates slow Loki, longer shutdown drain |

**Recommended production defaults**: the library defaults (batch_size=100,
flush_interval=5s, buffer_size=10000, gzip=true) are suitable for most
deployments up to ~1000 events/second.

---

## Metrics and Monitoring

### Loki-Specific Metrics

The Loki output receives per-output metrics via the unified
`audit.OutputMetrics` interface. Wire it through
`outputconfig.WithOutputMetrics(factory)` — see
[Metrics and Monitoring](metrics-monitoring.md#per-output-metrics-outputmetrics)
for the factory pattern and complete interface documentation.

### What to Alert On

| Metric | Condition | Action |
|--------|-----------|--------|
| `RecordDrop` rate > 0 | Events being lost | Increase `buffer_size`, check Loki health, reduce event volume |
| `RecordFlush` duration > timeout | Pushes timing out | Increase `timeout`, check network latency to Loki |
| `RecordFlush` batch_size consistently = max | Batches always full | Increase `batch_size` or decrease `flush_interval` |

---

## Troubleshooting

| Error / Symptom | Cause | Fix |
|-----------------|-------|-----|
| `loki: url must not be empty` | No URL configured | Set `url` in loki config block |
| `loki: url must be https` | Using `http://` without flag | Use `https://` or set `allow_insecure_http: true` (dev only) |
| `loki: url must not contain credentials` | URL has `user:pass@host` | Use `basic_auth` block instead |
| `loki: basic_auth and bearer_token are mutually exclusive` | Both set | Choose one authentication method |
| `loki: basic_auth.username must not be empty` | Empty username | Set the username |
| `loki: tls_cert and tls_key must both be set or both empty` | Only one provided | Provide both cert and key, or neither |
| `loki: static label name "X" is invalid` | Label has hyphens/dots/spaces | Use only `[a-zA-Z_][a-zA-Z0-9_]*` |
| `loki: static label "X" has empty value` | Empty string value | Provide a non-empty value |
| `loki: static label "X" value contains control characters` | Newlines or other control chars | Remove control characters |
| `loki: header "X" contains CR/LF` | CRLF injection attempt | Remove `\r\n` from header values |
| `loki: header "Authorization" is managed by the library` | Set restricted header via `headers` | Use `basic_auth` or `bearer_token` instead |
| `loki: unknown dynamic label "X"` | Typo in dynamic label name | Valid: `app_name`, `host`, `timezone`, `pid`, `event_type`, `event_category`, `severity` |
| `loki: batch_size X out of range` | Value < 1 or > 10000 | Set within range |
| Events not appearing in Loki | Ingestion delay | Wait 2-5 seconds, or query with wider time range |
| Events not appearing | `tenant_id` mismatch | Query MUST include `X-Scope-OrgID` header matching `tenant_id` |
| Events not appearing | `allow_private_ranges` not set | Set `allow_private_ranges: true` for local/private Loki |
| 429 errors, events dropped | Loki rate limiting | Check `RecordDrop`; increase `flush_interval` or reduce event volume |
| High cardinality rejection | Too many unique label combos | Exclude high-cardinality labels (e.g., `pid: false`) |
| Events dropped silently | Internal buffer full | Increase `buffer_size`; monitor `RecordDrop` |

---

## Why Timezone Is Always Included

The `timezone` field is a framework field that is **always** populated
in every audit event — either from the user's YAML configuration or
auto-detected from the system timezone at auditor construction.

Timezone is included because:

- **Forensic correlation** — when audit events from servers in
  different regions need to be correlated, timezone context resolves
  timestamp ambiguity. A `user_create` event at `12:00:00` could be
  noon UTC or noon US/Eastern — the timezone field disambiguates
- **Compliance** — SOC 2 and PCI DSS require audit timestamps to be
  unambiguous. Timezone context prevents misinterpretation of local
  timestamps during audits
- **Incident response** — during cross-timezone incidents, the timezone
  field immediately identifies which region or datacenter generated
  each event without parsing the timestamp offset
- **Tamper detection** — a timezone mismatch between a server's known
  location and the event's timezone may indicate log injection or
  process migration

As a Loki dynamic label, timezone enables efficient cross-region
queries:

```logql
{timezone="Europe/London"} | json | event_type="auth_failure"
```

To exclude timezone from Loki labels (keeping it in the JSON log line
only): `labels.dynamic.timezone: false`.

---

## HMAC Integrity with Loki

When HMAC is enabled on a Loki output, the `_hmac` and `_hmac_version`
fields are appended to every event before delivery. These fields
appear in the JSON log line stored in Loki and are queryable via
LogQL:

```logql
{app_name="my-app"} | json | _hmac_version="v1"
```

The HMAC is computed over the serialised payload **after** sensitivity
label stripping and **after** `_hmac_version` is appended, but **before**
`_hmac` is appended. `_hmac_version` is authenticated by the HMAC — see
[docs/hmac-integrity.md](hmac-integrity.md) for the full
canonicalisation contract. This means:

- Events stored in Loki can be independently verified by stripping
  **only** the `_hmac` field (keeping `_hmac_version` in place), recomputing
  the HMAC with the same salt, and comparing
- If the Loki output strips PII fields (via `exclude_labels`), the
  HMAC covers the stripped payload — the HMAC will differ from a
  full-output HMAC using the same salt
- Different HMAC salts per output produce different HMACs for the
  same event, enabling per-destination tamper detection

See [HMAC Integrity](hmac-integrity.md) for the full HMAC reference.

## Multi-Output Patterns with Loki

Loki works alongside any combination of file, syslog, and webhook
outputs. Common patterns:

### Redundant Storage (File + Loki)

```yaml
outputs:
  local_archive:
    type: file
    file:
      path: "/var/log/audit/events.log"
  loki_query:
    type: loki
    loki:
      url: "https://loki.internal/loki/api/v1/push"
```

The file provides guaranteed local retention; Loki provides real-time
querying via LogQL and Grafana dashboards.

### SIEM + Query (Syslog + Loki)

```yaml
outputs:
  siem:
    type: syslog
    syslog:
      network: "tcp+tls"
      address: "siem.internal:6514"
    formatter:
      type: cef
    route:
      include_categories: {security: {}}
  loki_all:
    type: loki
    loki:
      url: "https://loki.internal/loki/api/v1/push"
```

Security events go to the SIEM in CEF format; all events go to Loki
in JSON for operational querying.

### Failure Isolation

Each output is independent. A Loki outage (unreachable server, full
buffer, HTTP errors) does **not** block or affect delivery to file,
syslog, or webhook outputs. Events dropped by one output are still
delivered to all others.

---

## Related Documentation

- [Output Types Overview](outputs.md) — summary of all outputs
- [Output Configuration Reference](output-configuration.md) — YAML field tables
- [Progressive Example](../examples/14-loki-output/) — working code with real query output
- [Grafana Dashboard Issue](https://github.com/axonops/audit/issues/273) — pre-built dashboard for audit
- [Event Routing](event-routing.md) — per-output event filtering
- [Sensitivity Labels](sensitivity-labels.md) — per-output field stripping
- [HMAC Integrity](hmac-integrity.md) — tamper detection on Loki events
- [Async Delivery](async-delivery.md) — buffer architecture and delivery guarantees
- [Deployment Guide](deployment.md) — systemd / Kubernetes / Docker patterns; capacity planning

Install: `go get github.com/axonops/audit/loki`
