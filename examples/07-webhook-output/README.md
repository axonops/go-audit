[← Back to examples](../README.md)

> **Previous:** [06 — Syslog Output](../06-syslog-output/) |
> **Next:** [08 — Loki Output](../08-loki-output/)
# Example 07: Webhook Output

Sends audit events as
[NDJSON](https://github.com/ndjson/ndjson-spec) (newline-delimited
JSON) batches to an HTTP endpoint with retry, custom headers, and SSRF
protection. The example embeds a local HTTP server so it's fully
self-contained — no external webhook receiver needed.

## What You'll Learn

1. How audit events are **batched** and delivered as NDJSON payloads
2. How **flush triggers** work (event count, timer, or close)
3. How **custom HTTP headers** are used for authentication and
   correlation
4. How **SSRF protection** blocks private/loopback addresses by default
5. How **retry with backoff** handles transient failures (5xx, 429)
6. What the raw **NDJSON payload** looks like on the receiver side

## Prerequisites

None — the example embeds its own HTTP server.

For a real deployment, you'd point the output at your alerting endpoint,
log aggregator, or any HTTP-based receiver.

## Files

| File | Purpose |
|------|---------|
| [`main.go`](main.go) | Creates an auditor with webhook output, starts a local HTTP receiver, emits 4 events |
| [`outputs.yaml`](outputs.yaml) | Webhook output YAML configuration with batching and custom headers |
| [`taxonomy.yaml`](taxonomy.yaml) | 4 event types across 2 categories with varying severity levels |
| [`audit_generated.go`](audit_generated.go) | Generated typed builders |

## Running the Example

```bash
go run .
```

**Output** (1 NDJSON batch containing 4 events):

```
--- NDJSON batches received by webhook server ---

[Batch 1] 4 events, headers: Content-Type=application/x-ndjson, X-Audit-Source=webhook-example, X-Custom-Token=demo-token-123
  Event 1: {"timestamp":"...","event_type":"auth_login","severity":5,...,"actor_id":"alice","outcome":"success","event_category":"security"}
  Event 2: {"timestamp":"...","event_type":"user_create","severity":5,...,"actor_id":"bob","outcome":"success","event_category":"write"}
  Event 3: {"timestamp":"...","event_type":"auth_failure","severity":8,...,"actor_id":"mallory","outcome":"failure","reason":"invalid_password","event_category":"security"}
  Event 4: {"timestamp":"...","event_type":"data_export","severity":7,...,"actor_id":"alice","outcome":"success","format":"csv","row_count":"1500","event_category":"write"}

Total: 1 batches, 4 events received
```

Notice:
- All 4 events are delivered in a **single batch** (batch_size=10, we only had 4 events)
- The **Content-Type** is `application/x-ndjson` — one JSON object per line
- **Custom headers** (`X-Audit-Source`, `X-Custom-Token`) are present on every request
- Events have **different severity levels** (5 for normal, 7 for data_export, 8 for auth_failure)

## Key Concepts

### NDJSON Format

The webhook output sends events as
[NDJSON](https://github.com/ndjson/ndjson-spec) — one JSON object per
line, with a newline (`\n`) separator. The HTTP body looks like:

```
{"timestamp":"...","event_type":"auth_login","severity":5,...}\n
{"timestamp":"...","event_type":"user_create","severity":5,...}\n
{"timestamp":"...","event_type":"auth_failure","severity":8,...}\n
{"timestamp":"...","event_type":"data_export","severity":7,...}\n
```

This format is efficient (no wrapping array), streamable, and widely
supported by log aggregators (Elasticsearch, Loki, Datadog, etc.).

### Content-Type Tracks the Formatter (#463)

The default JSON formatter sends `Content-Type: application/x-ndjson`.
If you switch the webhook to a CEF formatter, the wire body becomes
newline-separated CEF records and the `Content-Type` automatically
flips to `text/plain` — the convention accepted by ArcSight
SmartConnector and Splunk HEC raw endpoints.

```yaml
audit_webhook:
  type: webhook
  formatter:
    type: cef
    vendor: "MyCompany"
    product: "MyApp"
    version: "1.0"
  webhook:
    url: "https://logs.example.com/audit"
    # request Content-Type becomes "text/plain" automatically
```

Operators whose receiver demands a specific MIME type can override
via the `headers:` config — operator headers take precedence over
the formatter's default. See
[docs/webhook-output.md](../../docs/webhook-output.md#ndjson-format)
for the full table.

### Batch Triggers

Events are buffered internally and flushed as a batch when ANY of these
conditions is met:

| Trigger | Config field | Default | This example |
|---------|-------------|---------|--------------|
| **Event count** | `batch_size` | 100 | 10 |
| **Time elapsed** | `flush_interval` | 5s | 1s |
| **Auditor closed** | `auditor.Close()` | — | Triggers final flush |

In this example, `auditor.Close()` triggers the flush because we emit
only 4 events (below the batch_size threshold of 10) and close
immediately (before the 1s timer fires).

### Custom HTTP Headers

Use `headers:` to add authentication tokens, correlation IDs, or any
custom metadata to every webhook request:

```yaml
webhook:
  headers:
    Authorization: "Bearer ${WEBHOOK_TOKEN}"
    X-Correlation-ID: "audit-pipeline"
    X-Custom-Header: "my-value"
```

Header values are plain strings in YAML. For secrets, use environment
variables and expand them in your Go code before passing to the
programmatic API, or reference them via `${VAR}` syntax in YAML (which
expands after parsing).

### SSRF Protection

By default, the webhook output **blocks requests to private and
loopback addresses** to prevent Server-Side Request Forgery (SSRF):

| Blocked range | CIDR | Reason |
|--------------|------|--------|
| Loopback | `127.0.0.0/8` | Prevents localhost access |
| Private (Class A) | `10.0.0.0/8` | RFC 1918 private range |
| Private (Class B) | `172.16.0.0/12` | RFC 1918 private range |
| Private (Class C) | `192.168.0.0/16` | RFC 1918 private range |
| Link-local | `169.254.0.0/16` | Always blocked |
| Cloud metadata | `169.254.169.254` | Always blocked (AWS/GCP/Azure metadata) |

This example uses `allow_private_ranges: true` and
`allow_insecure_http: true` for local development. In production:

- **Always use HTTPS** — `allow_insecure_http` MUST NOT be `true`
- **Keep SSRF protection enabled** — only disable for local dev/testing

### Fail-Fast on Startup (#286)

The webhook output verifies connectivity at construction time by
default. `audit.New` returns a wrapped error if the URL is
unreachable, the TLS handshake fails, the SSRF policy rejects
the host, or the verification budget elapses — surfacing the
misconfiguration at application start-up instead of as silent
event loss on the first flush.

```yaml
webhook:
  url: "https://ingest.example.com/audit"
  verify_on_startup: true                 # default — fail at New()
  verify_on_startup_timeout: 5s           # default — budget for dial + handshake
```

Set `verify_on_startup: false` for sidecar deployments where the
receiver may come up after the application, or for short-lived
CLI tools that must start regardless of receiver availability.

### Retry with Backoff

When the webhook endpoint returns an error, the output retries with
exponential backoff:

| Response | Action |
|----------|--------|
| **2xx** | Success — batch delivered |
| **429** (Too Many Requests) | Retry with backoff, honouring the `Retry-After` response header (capped at 30 s, delta-seconds form only — see #291) |
| **5xx** (Server Error) | Retry with backoff |
| **4xx** (Client Error, not 429) | No retry — batch dropped (configuration or auth problem) |
| **Redirect** (3xx) | Rejected — SSRF protection blocks redirects |

Backoff: 100ms base, 2x factor, 5s cap, random jitter.

### Delivery Guarantee

The webhook output provides **at-least-once delivery**: a batch may be
delivered more than once if the server accepts the payload but the
acknowledgement is lost. Design your receiver to handle duplicate
batches (idempotent processing).

### Buffer Drops

If events arrive faster than batches can be sent, the internal buffer
fills and events are **dropped**. The `OutputMetrics.RecordDrop()`
callback fires when this happens. Increase `buffer_size` if you see
drops:

```yaml
webhook:
  buffer_size: 50000   # default: 10,000, max: 1,000,000
```

### YAML Configuration Explained

```yaml
outputs:
  alerts:
    type: webhook              # Register with: import _ "github.com/axonops/audit/outputs" (all types) or _ "github.com/axonops/audit/webhook" (this type only)
    webhook:
      url: "http://localhost:9090/audit"  # Required. Must be https:// in production
      batch_size: 10           # Events per batch (default: 100, max: 10,000)
      flush_interval: "1s"     # Flush after this duration (default: "5s")
      timeout: "5s"            # HTTP request timeout (default: "10s")
      max_retries: 2           # Retry on 5xx/429 (default: 3, max: 20)
      allow_insecure_http: true   # Dev only — MUST be false in production
      allow_private_ranges: true  # Dev only — SSRF protection off
      headers:                 # Custom headers on every request
        X-Audit-Source: "webhook-example"
        X-Custom-Token: "demo-token-123"
```

## Blank Import Required

Every output (including stdout) requires a blank import to register
its factory. The easiest path is the convenience package that
registers all built-in outputs:

```go
import _ "github.com/axonops/audit/outputs"
```

If you prefer to register only webhook (smaller binary for
constrained deployments), import the sub-module directly:

```go
import _ "github.com/axonops/audit/webhook"
```

Without either, `outputconfig.Load` returns an error when it
encounters `type: webhook` in the YAML.

## Further Reading

- [Webhook Output Reference](../../docs/webhook-output.md) — complete configuration, TLS, retry, SSRF, production patterns
- [NDJSON Specification](https://github.com/ndjson/ndjson-spec) — the payload format
- [Output Types Overview](../../docs/outputs.md) — all five output types
- [Example 14: Loki Output](../08-loki-output/) — structured querying with stream labels
- [Output Configuration YAML](../../docs/output-configuration.md) — full YAML reference
