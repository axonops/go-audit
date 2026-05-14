[← Back to Output Types](outputs.md)

# Webhook Output — Detailed Reference

The webhook output batches audit events as
[NDJSON](https://github.com/ndjson/ndjson-spec) (newline-delimited
JSON) and POSTs them to an HTTPS endpoint. Failed batches are retried
with exponential backoff. Private and loopback addresses are blocked
by default (SSRF protection).

- [Why Webhook for Audit Logging?](#why-webhook-for-audit-logging)
- [Quick Start](#quick-start)
- [How It Works](#how-it-works)
- [Buffering Architecture](#buffering-architecture)
- [NDJSON Format](#ndjson-format)
- [Complete Configuration Reference](#complete-configuration-reference)
- [Authentication](#authentication)
- [TLS Configuration](#tls-configuration)
- [Batching and Delivery](#batching-and-delivery)
- [Retry and Error Handling](#retry-and-error-handling)
- [SSRF Protection](#ssrf-protection)
- [Buffer Drops](#buffer-drops)
- [Metrics and Monitoring](#metrics-and-monitoring)
- [Production Configuration](#production-configuration)
- [Troubleshooting](#troubleshooting)
- [Related Documentation](#related-documentation)

## Why Webhook for Audit Logging?

Webhooks deliver audit events to any HTTP endpoint in real time — no
protocol-specific infrastructure required:

- **Real-time alerting** — push high-severity events to PagerDuty,
  Slack, or custom alerting pipelines
- **Universal integration** — any system with an HTTP endpoint can
  receive audit events (Elasticsearch, Datadog, custom APIs)
- **Batched efficiency** — multiple events per HTTP request reduces
  overhead compared to per-event delivery
- **Standard format** — NDJSON is supported by all major log aggregators

## Quick Start

```bash
go get github.com/axonops/audit/webhook
```

```yaml
# outputs.yaml
version: 1
app_name: "my-app"
host: "my-host"
outputs:
  alerts:
    type: webhook
    webhook:
      url: "https://ingest.example.com/audit"
```

```go
import _ "github.com/axonops/audit/webhook"  // registers "webhook" factory
```

**[→ Progressive example with embedded HTTP receiver](../examples/08-webhook-output/)**

## How It Works

```mermaid
flowchart LR
    A[AuditEvent] --> B[Drain goroutine]
    B --> C[JSON serialize]
    C --> D[Buffer channel]
    D --> E[Batch loop]
    E -->|count/timer/close| F[Build NDJSON]
    F --> G[HTTP POST]
    G -->|2xx| H[Success]
    G -->|5xx| I[Retry with backoff]
    G -->|429| K[Retry with backoff,<br/>honouring Retry-After]
    G -->|4xx| J[Drop batch]
```

1. `AuditEvent()` enqueues the event in the auditor's internal buffer
2. The drain goroutine serialises the event and sends it to the
   webhook's buffer channel
3. The batch loop accumulates events until a flush trigger fires
4. Events are joined as NDJSON and POSTed to the configured URL
5. On transient failure (5xx, 429), the batch is retried with
   exponential backoff. On 429, a `Retry-After` header is also
   honoured (see [Retry-After on 429](#retry-after-on-429))
6. On permanent failure (4xx), the batch is dropped

## Buffering Architecture

The webhook output has its own internal buffer separate from the core
logger buffer. This is [Level 2](async-delivery.md#two-level-buffering)
in the pipeline:

```
Core drain goroutine ──► Write()
                            → copies event bytes
                            → enqueues to webhook channel (capacity: buffer_size, default 10,000)
                            → returns immediately (non-blocking)

Webhook batchLoop goroutine
  → reads from channel
  → accumulates into batch
  → flushes on: batch_size (100) | max_batch_bytes (1 MiB) | flush_interval (5s) | shutdown
  → joins events as NDJSON
  → HTTP POST to endpoint
  → retries on 429/5xx
```

### Max Event Size (`max_event_bytes`)

**Since #688**, `Write()` rejects events whose byte length exceeds
`max_event_bytes` (default 1 MiB) with an error wrapping
`audit.ErrEventTooLarge` and `audit.ErrValidation`. The event is
not enqueued; `OutputMetrics.RecordDrop()` is called; the
diagnostic logger records the reject.

```go
if errors.Is(err, audit.ErrEventTooLarge) {
    // The event was too large for this output's MaxEventBytes.
}
```

This is a **defence against consumer-controlled memory pressure**
— a buggy caller passing a 10 MiB event into a 10 000-slot buffer
could pin ~100 GiB before backpressure. Range 1 KiB – 10 MiB.

### Byte-threshold batching (`max_batch_bytes`)

Since #687, the webhook output flushes when accumulated event bytes
cross `max_batch_bytes` (default 1 MiB) — even if `batch_size` has
not been reached. This matches the convention already used by Loki
and syslog and prevents unbounded HTTP POST body sizes when events
are large.

- **Default**: 1 MiB
- **Range**: 1 KiB – 10 MiB
- **Oversized single events**: a single event whose byte length
  alone exceeds `max_batch_bytes` is **flushed alone** — never
  dropped. The HTTP POST contains exactly that one event.

Operators running Loki + syslog + webhook side-by-side see the
same knob across all three outputs.

### `buffer_size` vs `batch_size`

These are different things:

| Config | Default | What It Controls |
|--------|---------|------------------|
| `buffer_size` | 10,000 | How many events can **queue up** waiting to be sent. This is the channel capacity. |
| `batch_size` | 100 | How many events are grouped into a **single HTTP POST**. This is the flush threshold. |

With the defaults, up to 100 batches of events (10,000 / 100) can be
queued before drops begin. Increasing `buffer_size` absorbs longer
outages; decreasing `batch_size` or `flush_interval` drains the buffer
faster.

### Drop Behaviour

If the internal buffer fills (e.g., the endpoint is down and retries
are consuming time), new events are **dropped silently** — the
`Write()` call returns `nil` to avoid blocking the core drain
goroutine. This isolation ensures that a webhook outage does not
affect delivery to other outputs.

A rate-limited `slog.Warn` fires at most once per 10 seconds during
sustained drops. The `RecordDrop()` metric fires on **every**
drop — use metrics, not log lines, for precise monitoring.

### Relationship to Core Buffer

The webhook `buffer_size` is independent of the core
`auditor.queue_size` (`WithQueueSize`). Both default to 10,000
but they serve different pipeline stages. See
[Two-Level Buffering](async-delivery.md#two-level-buffering) for the
full architecture diagram and memory sizing guidance.

## NDJSON Format

Each HTTP request body contains one JSON object per line:

```
{"timestamp":"...","event_type":"auth_login","severity":5,...}\n
{"timestamp":"...","event_type":"user_create","severity":5,...}\n
```

The Content-Type header is `application/x-ndjson` for the default
[`JSONFormatter`](https://pkg.go.dev/github.com/axonops/audit#JSONFormatter).
When a different formatter is configured on the output, the
Content-Type follows that formatter's declared type. The library
discovers this via [`Formatter.ContentType()`](https://pkg.go.dev/github.com/axonops/audit#Formatter)
and propagates it to the webhook at auditor construction.

| Formatter | `Content-Type` |
|-----------|----------------|
| [`JSONFormatter`](https://pkg.go.dev/github.com/axonops/audit#JSONFormatter) | `application/x-ndjson` |
| [`CEFFormatter`](https://pkg.go.dev/github.com/axonops/audit#CEFFormatter) | `text/plain` |
| Custom `Formatter` | Whatever the implementation returns from `ContentType()` |

The CEF wire format is one CEF record per line, newline-separated,
matching the convention accepted by ArcSight SmartConnector and
Splunk HEC raw endpoints. Operators sending CEF to a receiver that
demands a different MIME type can override Content-Type via the
output's `headers` configuration — operator-supplied headers take
precedence over the formatter's default.

NDJSON is:
- **Streamable** — receivers can process lines as they arrive
- **Efficient** — no wrapping array or delimiters beyond `\n`
- **Standard** — supported by Elasticsearch Bulk API, Loki, Datadog,
  and most log aggregators

## Complete Configuration Reference

| Field | Type | Default | Range | Description |
|-------|------|---------|-------|-------------|
| `url` | string | *(required)* | — | HTTP endpoint. MUST be `https://` unless `allow_insecure_http` is true |
| `batch_size` | int | `100` | 1–10,000 | Maximum events per HTTP request |
| `max_event_bytes` | int | `1048576` (1 MiB) | 1 KiB – 10 MiB | Per-event size cap at `Write()`. Oversized events rejected with `audit.ErrEventTooLarge` — also satisfies `errors.Is(err, audit.ErrValidation)` (#688) |
| `max_batch_bytes` | int | `1048576` (1 MiB) | 1 KiB – 10 MiB | Accumulated event-bytes flush threshold. Oversized single events flush alone; never dropped. See [Byte-threshold batching](#byte-threshold-batching-max_batch_bytes) |
| `buffer_size` | int | `10,000` | 1–1,000,000 | Internal async buffer capacity. Events dropped when full |
| `flush_interval` | duration | `"5s"` | — | Maximum time between batch flushes |
| `timeout` | duration | `"10s"` | — | HTTP request timeout (full request/response lifecycle) |
| `max_retries` | int | `3` | 0–20 | Retry count for 5xx and 429 responses. 0 defaults to 3. Values > 20 rejected |
| `headers` | map | *(none)* | — | Custom HTTP headers on every request |
| `tls_ca` | string | *(none)* | — | Path to CA certificate for server verification |
| `tls_cert` | string | *(none)* | — | Path to client certificate for mTLS |
| `tls_key` | string | *(none)* | — | Path to client private key for mTLS |
| `tls_policy` | object | *(nil — TLS 1.3 only)* | — | TLS version and cipher policy |
| `tls_policy.allow_tls12` | bool | `false` | — | Allow TLS 1.2 fallback |
| `tls_policy.allow_weak_ciphers` | bool | `false` | — | Allow weaker cipher suites with TLS 1.2 |
| `allow_insecure_http` | bool | `false` | — | Permit `http://` URLs. MUST NOT be true in production |
| `allow_private_ranges` | bool | `false` | — | Disable SSRF protection for private/loopback ranges |
| `verify_on_startup` | bool | `true` | `true` or `false` | When `true` (default), `New()` performs a TCP dial — and, for `https://` URLs, a TLS handshake — against the webhook endpoint before returning, so a misconfigured or unreachable destination fails fast at startup rather than silently dropping events at the first flush. Set to `false` for sidecar/lazy-start deployments where the receiver may not yet be running when the application starts; the runtime retry path handles delivery once the receiver becomes available. The probe applies the SAME SSRF policy as the runtime transport: `allow_private_ranges: false` rejects loopback / RFC 1918 at probe time too. |
| `verify_on_startup_timeout` | duration | `5s` | any positive duration | Bounds the construction-time probe. Independent of `timeout` (which governs runtime requests). Operators on slow WAN paths can raise this; CI/local development is fine with the default. Ignored when `verify_on_startup: false`. |

### Validation Rules

- `url` MUST NOT be empty and MUST be a valid URL
- URL scheme MUST be `http` or `https`
- HTTPS is required unless `allow_insecure_http` is true
- URL MUST NOT contain embedded credentials (use `headers` instead)
- Header names and values MUST NOT contain CRLF characters
- `tls_cert` and `tls_key` MUST both be set or both empty
- `batch_size`, `buffer_size`, `max_retries` are rejected if above
  their upper bounds

## Authentication

Use custom HTTP headers for authentication:

### Bearer Token

```yaml
webhook:
  url: "https://ingest.example.com/audit"
  headers:
    Authorization: "Bearer ${WEBHOOK_TOKEN}"
```

### Splunk HEC

```yaml
webhook:
  url: "https://splunk.internal:8088/services/collector/event"
  headers:
    Authorization: "Splunk ${SPLUNK_HEC_TOKEN}"
```

### API Key

```yaml
webhook:
  url: "https://api.example.com/v1/audit"
  headers:
    X-API-Key: "${API_KEY}"
```

> **Note:** Header values containing `auth`, `key`, `secret`, or
> `token` (case-insensitive) are automatically redacted in log output
> to prevent credential leakage.

## TLS Configuration

### Server Verification Only

```yaml
webhook:
  url: "https://ingest.example.com/audit"
  tls_ca: "/etc/audit/ca.pem"
```

### Mutual TLS (mTLS)

```yaml
webhook:
  url: "https://ingest.example.com/audit"
  tls_ca: "/etc/audit/ca.pem"
  tls_cert: "/etc/audit/client-cert.pem"
  tls_key: "/etc/audit/client-key.pem"
```

### TLS Version Policy

```yaml
webhook:
  url: "https://legacy-endpoint.internal/audit"
  tls_policy:
    allow_tls12: true
    allow_weak_ciphers: false
```

> **Warning:** Enabling `allow_tls12` widens the attack surface.
> `allow_weak_ciphers` MUST NOT be enabled in production.

> **Note:** TLS certificates are loaded once at output construction.
> Certificate rotation requires restarting the application.

## Batching and Delivery

### Flush Triggers

A batch is flushed when ANY of these conditions is met:

| Trigger | Config | Default |
|---------|--------|---------|
| Event count reaches `batch_size` | `batch_size` | 100 |
| Timer reaches `flush_interval` | `flush_interval` | 5s |
| `auditor.Close()` called | — | Final flush |

The timer resets after every flush, whether triggered by count or timer.

### Delivery Guarantee

**At-least-once delivery.** A batch may be delivered more than once if
the server accepts the payload but the HTTP acknowledgement is lost
(network timeout, connection reset). Design your receiver to handle
duplicate batches with idempotent processing.

### Request Structure

Each POST request contains:

| Header | Value |
|--------|-------|
| `Content-Type` | Formatter-driven (`application/x-ndjson` for JSON, `text/plain` for CEF — see [Wire Format](#wire-format)) |
| Custom headers | From `headers:` config |

Body: one JSON object per line (NDJSON), terminated with `\n`.

## Retry and Error Handling

| Response | Action | Retried? |
|----------|--------|----------|
| **2xx** | Success — batch delivered | No |
| **429** (Too Many Requests) | Retry with backoff | Yes |
| **5xx** (Server Error) | Retry with backoff | Yes |
| **4xx** (not 429) | Drop batch — configuration or auth error | No |
| **3xx** (Redirect) | Rejected — SSRF protection blocks redirects | No |

### Backoff Parameters

| Parameter | Value |
|-----------|-------|
| Base delay | 100ms |
| Maximum delay | 5s |
| Backoff factor | 2x per attempt |
| Jitter | Random multiplier in [0.5, 1.0) via `crypto/rand` |
| Max attempts | `max_retries` (total attempts including initial) |

### `Retry-After` on 429

When the server returns `429 Too Many Requests` with a
[`Retry-After`](https://www.rfc-editor.org/rfc/rfc9110#section-10.2.3)
header, the webhook output honours it as a **minimum** wait before
the next attempt. The effective backoff for the next retry is
`max(computed_backoff, parsed_retry_after)` — whichever is longer
wins, where `parsed_retry_after` is the header value in seconds.

| Behaviour | Value |
|-----------|-------|
| Header format supported | Delta-seconds only (e.g. `Retry-After: 30`) |
| Header format **not** supported | HTTP-date form (e.g. `Retry-After: Wed, 21 Oct 2026 07:28:00 GMT`) — treated as if absent |
| Cap | 30 seconds (server-supplied values above the cap are clamped) |
| Lifecycle | Single-use — consumed by the next retry, then cleared. A subsequent 429 without the header reverts to standard backoff. |
| Malformed / non-positive / negative | Treated as if absent — standard backoff applies |

The cap prevents a hostile or misbehaving server from forcing the
client to stall indefinitely. With `max_retries=3`, the total time
a single batch can spend waiting on hostile `Retry-After` headers
is therefore bounded by `3 × 30s = 90s` before the batch is dropped.

```mermaid
flowchart TD
    A[POST batch] --> B{Response?}
    B -->|2xx| C[Success]
    B -->|429| G[Read Retry-After<br/>cap at 30s]
    G --> D{Retries left?}
    B -->|5xx| D
    D -->|Yes| E["Sleep max(<br/>computed backoff,<br/>Retry-After)"]
    E --> A
    D -->|No| F[Drop batch]
    B -->|4xx| F
    B -->|3xx redirect| F
```

## SSRF Protection

The webhook output blocks requests to private and loopback addresses
by default, preventing
[Server-Side Request Forgery](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)
attacks:

| Blocked range | CIDR / Address | Always blocked? | Reason label |
|--------------|----------------|-----------------|--------------|
| Loopback IPv4 | `127.0.0.0/8` | Unless `allow_private_ranges` | `loopback` |
| Loopback IPv6 | `::1` | Unless `allow_private_ranges` | `loopback` |
| Private (A) | `10.0.0.0/8` | Unless `allow_private_ranges` | `private` |
| Private (B) | `172.16.0.0/12` | Unless `allow_private_ranges` | `private` |
| Private (C) | `192.168.0.0/16` | Unless `allow_private_ranges` | `private` |
| IPv6 ULA | `fc00::/7` | Unless `allow_private_ranges` | `private` |
| Link-local IPv4 | `169.254.0.0/16` | **Always** (includes cloud metadata) | `link_local` |
| Link-local IPv6 | `fe80::/10` | **Always** | `link_local` |
| Cloud metadata IPv4 | `169.254.169.254` | **Always** (even with `allow_private_ranges`) | `cloud_metadata` |
| Cloud metadata IPv6 (AWS) | `fd00:ec2::254` | **Always** (even with `allow_private_ranges`) | `cloud_metadata` |
| CGNAT (RFC 6598) | `100.64.0.0/10` | **Always** | `cgnat` |
| Deprecated site-local | `fec0::/10` | **Always** | `deprecated_site_local` |
| Multicast IPv4 | `224.0.0.0/4` | **Always** | `multicast` |
| Multicast IPv6 | `ff00::/8` | **Always** | `multicast` |
| Unspecified | `0.0.0.0`, `::` | **Always** | `unspecified` |
| IPv4-mapped IPv6 | `::ffff:a.b.c.d` | Normalised to IPv4 before classification | *(per above)* |

SSRF rejections return `*audit.SSRFBlockedError` (wrapping
`audit.ErrSSRFBlocked`). The `Reason` field matches the labels above
— suitable for use as a Prometheus metric label:

```go
var ssrfErr *audit.SSRFBlockedError
if errors.As(err, &ssrfErr) {
    metricSSRFBlocked.With("reason", string(ssrfErr.Reason)).Inc()
}
```

Additional protections:
- **Redirects rejected** — HTTP redirects are never followed (301/302/303/307/308 block)
- **3xx body drain capped** — for any 3xx response that reaches the
  response-drain path, the body is drained at most **4 KiB**. Without
  this cap an attacker-controlled endpoint could force up to
  `maxResponseDrain` (1 MiB) of traffic per retry (issue #484).
- **Keep-alives disabled** — prevents DNS rebinding attacks
- **Credentials in URL rejected** — `https://user:pass@host` returns
  an error; use `headers` instead

## Buffer Drops

The webhook's internal buffer has a fixed capacity (`buffer_size`,
default 10,000). When full, new events are **dropped** and
`OutputMetrics.RecordDrop()` is called.

Common causes:
- Webhook endpoint is down and retries are exhausting capacity
- Event volume exceeds the endpoint's processing speed
- `flush_interval` is too long for the event rate

Fix: increase `buffer_size`, reduce `flush_interval`, or scale the
receiving endpoint.

## Metrics and Monitoring

The webhook output receives per-output metrics via the unified
`audit.OutputMetrics` interface. Wire it through
`outputconfig.WithOutputMetrics(factory)` — see
[Metrics and Monitoring](metrics-monitoring.md#per-output-metrics-outputmetrics)
for the factory pattern and complete interface documentation.

### What to Monitor

| Metric | Condition | Action |
|--------|-----------|--------|
| `RecordDrop` rate > 0 | Events being lost | Increase `buffer_size`, check endpoint health |
| `RecordFlush` duration > timeout | Requests timing out | Increase `timeout`, check network latency |
| `RecordFlush` batch_size = max | Batches always full | Increase `batch_size` or decrease `flush_interval` |

## Production Configuration

### Production Checklist — Dangerous Opt-In Flags

The webhook output exposes two flags that relax the default safe
posture. Both default to OFF; setting either to `true` is acceptable
ONLY in the deployment patterns listed.

| Flag | Default | When `true` is acceptable | When `true` is a misconfiguration |
|---|---|---|---|
| `allow_insecure_http` | `false` (HTTPS-only) | Local development; CI smoke tests against an in-cluster mock receiver on a closed network. Operator owns both endpoints. | Any production deployment, any cross-network traffic, anywhere the receiver is exposed beyond a single trust domain. Audit events traverse the network in cleartext. |
| `allow_private_ranges` | `false` (SSRF block list active) | Calling an in-cluster receiver by RFC1918 address (`10.x`, `192.168.x`, `172.16-31.x`) where the SSRF guard would otherwise block. Receiver is operator-owned and within the same network policy zone. | Any URL whose authority is influenced by user input; any URL pointing at a service the operator did not deploy themselves; deployments where operator-owned and tenant-owned traffic share the same egress namespace. |

Before flipping either flag in production, the operator MUST:

1. Document the specific receiver address and rationale in the
   deployment's Terraform / Helm / Kubernetes manifest comment.
2. Set the receiver behind authentication (`headers.Authorization`
   or mTLS — `tls_cert` + `tls_key`) so that the relaxed network
   posture does not become an open egress for arbitrary callers.
3. Pin the receiver host in NetworkPolicy / egress firewall rules
   to limit the blast radius if the URL is ever templated from
   untrusted input.

See [SECURITY.md](../SECURITY.md) and [docs/threat-model.md](threat-model.md)
for the broader posture; the SSRF block list itself is documented in
[#-ssrf-protection](#ssrf-protection).

### Minimum Secure Configuration

```yaml
outputs:
  audit_alerts:
    type: webhook
    webhook:
      url: "https://${WEBHOOK_ENDPOINT}/audit"
      headers:
        Authorization: "Bearer ${WEBHOOK_TOKEN}"
      timeout: "10s"
      max_retries: 3
```

### High-Volume Configuration

```yaml
outputs:
  audit_ingest:
    type: webhook
    webhook:
      url: "https://ingest.internal/audit"
      batch_size: 500
      buffer_size: 100000
      flush_interval: "2s"
      timeout: "30s"
      max_retries: 5
      tls_ca: "/etc/audit/tls/ca.pem"
```

### Multi-Destination Configuration

```yaml
outputs:
  # High-severity alerts to PagerDuty
  pagerduty:
    type: webhook
    webhook:
      url: "https://events.pagerduty.com/v2/enqueue"
      headers:
        Content-Type: "application/json"
    route:
      min_severity: 8

  # All events to Elasticsearch
  elasticsearch:
    type: webhook
    webhook:
      url: "https://elastic.internal:9200/audit-events/_bulk"
      batch_size: 200
      flush_interval: "3s"
```

## Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| `audit: webhook url must not be empty` | Missing `url` in config | Add the `url` field to the webhook block |
| `audit: webhook url must be https (got "http"); set AllowInsecureHTTP for testing` | Using `http://` without flag | Use `https://` or add `allow_insecure_http: true` (dev only) |
| `audit: webhook url must not contain credentials; use Headers for auth` | Embedded user:pass in URL | Move credentials to `headers:` block |
| `audit: ssrf: dial blocked` | SSRF protection blocked private/loopback address | Add `allow_private_ranges: true` (dev only) |
| Events not arriving | Buffer full, events being dropped | Check `RecordDrop`; increase `buffer_size` |
| Batches rejected with 401 | Auth token expired or invalid | Update the `Authorization` header value |
| Batches rejected with 413 | Payload too large | Decrease `batch_size` |
| High latency, timeouts | Endpoint slow or unreachable | Increase `timeout`; check endpoint health |

## Related Documentation

- [Output Types Overview](outputs.md) — summary of all five outputs
- [Output Configuration Reference](output-configuration.md) — YAML field tables
- [Progressive Example](../examples/08-webhook-output/) — working code with embedded HTTP receiver
- [NDJSON Specification](https://github.com/ndjson/ndjson-spec) — payload format
- [OWASP SSRF](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery) — SSRF attack reference
- [RFC 8446: TLS 1.3](https://datatracker.ietf.org/doc/html/rfc8446)
- [Async Delivery](async-delivery.md) — buffer sizing and graceful shutdown
- [Deployment Guide](deployment.md) — systemd / Kubernetes / Docker patterns; capacity planning
