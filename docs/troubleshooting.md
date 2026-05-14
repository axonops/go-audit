[&larr; Back to README](../README.md)

# Troubleshooting

- [Events Not Appearing in Output](#events-not-appearing-in-output)
- [ErrQueueFull at Runtime](#errqueuefull-at-runtime)
- [Drain Timeout at Shutdown](#drain-timeout-at-shutdown)
- [Validation Errors on Valid-Looking Events](#validation-errors-on-valid-looking-events)
- [Syslog Connection Failures](#syslog-connection-failures)
- [Webhook Events Not Delivered](#webhook-events-not-delivered)
- [Loki Events Not Appearing](#loki-events-not-appearing)
- [File Output Not Writing](#file-output-not-writing)
- [Goroutine Leak in Tests](#goroutine-leak-in-tests)
- [Secret Provider Failures](#secret-provider-failures)

---

## 🔇 Events Not Appearing in Output

This is the most common problem. Work through this checklist:

| Check | How to Verify | Fix |
|-------|--------------|-----|
| **`auditor.Close()` not called** | Events are async — they sit in the buffer until the drain goroutine processes them. If your program exits without calling `Close()`, buffered events are lost. | Call `auditor.Close()` before exit. See [Graceful Shutdown](async-delivery.md#-graceful-shutdown). |
| **Auditor disabled** | A disabled logger silently discards all events. | Remove `WithDisabled()` from your `New` call, or set `auditor: { enabled: true }` in your outputs YAML. |
| **Category disabled at runtime** | If `DisableCategory()` was called, events in that category are silently discarded. | Check your code for `DisableCategory()` calls. All categories are enabled by default. |
| **Per-output route filtering** | An output with `route: include_categories: {security: {}}` only receives security events — write events are silently filtered. | Check your output YAML `route:` block. Remove the route to receive all events. See [Event Routing](event-routing.md). |
| **Output disabled in YAML** | `enabled: false` on an output silently disables it. | Check your output YAML for `enabled: false`. |
| **Sensitivity label stripping** | `exclude_labels: [pii]` removes PII-labeled fields — the event is delivered but with fewer fields than expected. | Check your output YAML `exclude_labels`. The event itself is delivered; only labeled fields are stripped. See [Sensitivity Labels](sensitivity-labels.md). |
| **Wrong output type blank import** | If you use `type: file` in YAML but forgot `_ "github.com/axonops/audit/file"`, `outputconfig.Load` returns an error. | Add the blank import for every output type you use. See [Output Configuration](output-configuration.md#-factory-registry). |

> 💡 **Quick diagnostic:** Add a `stdout` output with no route. If
> events appear on stdout but not in your file/syslog/webhook, the
> problem is in the output configuration, not the audit pipeline.

---

## 📦 ErrQueueFull at Runtime

```
audit: queue full
```

The core intake queue is at capacity. Events are being produced
faster than the drain goroutine can process them.

| Cause | Fix |
|-------|-----|
| **Burst of events** | Increase `queue_size` in your outputs YAML `auditor:` section, or use `WithQueueSize()` (default: 10,000, max: 1,000,000) |
| **Output error loop** | If an output is failing on every write, the drain goroutine spends time on error handling. Check `RecordOutputError` metrics. |

All non-stdout outputs now have their own internal async buffers, so
a slow output destination does not block the drain goroutine. If you
see per-output drops (`RecordDrop()` via `OutputMetrics`), that output
is overwhelmed — increase its `buffer_size` or check destination health.

Monitor `RecordBufferDrop()` in your metrics to catch core queue drops
before users notice. See [Metrics & Monitoring](metrics-monitoring.md)
and [Two-Level Buffering](async-delivery.md#two-level-buffering) for
the complete pipeline architecture and tuning guidance.

---

## ⏱️ Drain Timeout at Shutdown

```
INFO audit: shutdown started
WARN audit: drain timeout expired, N events lost
```

`Auditor.Close()` waited up to `ShutdownTimeout` (default: 5 seconds)
but couldn't flush all buffered events in time.

| Cause | Fix |
|-------|-----|
| **Too many buffered events** | Reduce event volume before shutdown, or increase `WithShutdownTimeout` (max: 60s) |
| **Slow output during shutdown** | A syslog server or webhook endpoint is slow to accept the final batch. Check connectivity. |
| **`ShutdownTimeout` too short** | Increase `WithShutdownTimeout` for high-volume applications |

> ⚠️ Events lost to drain timeout are gone permanently. This is the
> at-most-once delivery guarantee. Monitor this via your metrics.

---

## ❌ Validation Errors on Valid-Looking Events

```
audit: unknown event type "user_created"
audit: event "user_create": missing required field "actor_id"
audit: event "user_create": unknown field "actorid"
```

| Error | Cause | Fix |
|-------|-------|-----|
| **Unknown event type** | The event type string doesn't match any event in your taxonomy. Likely a typo. | Use generated constants (`EventUserCreate`) instead of string literals. Check your taxonomy YAML `events:` section. |
| **Missing required field** | A field marked `required: true` in the taxonomy is not present in the event. | Add the missing field. Check your taxonomy for which fields are required. |
| **Unknown field** (strict mode) | A field not declared in the taxonomy was included. In `strict` mode (default), this is rejected. | Either add the field to your taxonomy, or switch to `warn` or `permissive` validation mode. See [Validation Modes](taxonomy-validation.md#-validation-modes). |

> 💡 **Use code generation** to eliminate these errors entirely.
> Generated builders have required fields as constructor parameters
> — you can't forget them — and only accept declared fields as
> setters — you can't add unknown ones. See [Code Generation](code-generation.md).

---

## 📡 Syslog Connection Failures

```
audit: output "siem": dial tcp syslog.example.com:6514: connection refused
```

The syslog output dials the server immediately at startup. If the
server is unreachable, `New()` (or `outputconfig.Load()`) fails.

| Cause | Fix |
|-------|-----|
| **Server not running** | Start the syslog server before the application |
| **Wrong address/port** | Check `syslog.address` in your output YAML |
| **TLS certificate mismatch** | Verify `tls_ca` points to the correct CA that signed the server's certificate |
| **mTLS client cert rejected** | Verify `tls_cert` and `tls_key` are valid and accepted by the server |
| **Firewall blocking** | Check network connectivity to the syslog address and port |
| **TLS version mismatch** | If the server only supports TLS 1.2, set `tls_policy.allow_tls12: true` |

After startup, TCP and TLS connections are re-established
automatically on failure (up to `max_retries` attempts, default: 10).
Monitor `RecordReconnect` on `syslog.ReconnectRecorder` to track
reconnection events.

---

## 🌐 Webhook Events Not Delivered

```
audit: output "alerts": POST https://ingest.example.com/audit: 403 Forbidden
```

| Cause | Fix |
|-------|-----|
| **Missing authentication** | Set `headers: { Authorization: "Bearer <token>" }` in webhook YAML |
| **HTTPS required** | The webhook output requires `https://` by default. Set `allow_insecure_http: true` only for local development. |
| **SSRF protection blocking** | Private/loopback IPs are blocked by default. Set `allow_private_ranges: true` for local development. |
| **Server returning errors** | 4xx errors are not retried (client error). 5xx errors are retried up to `max_retries` times. Check the server-side logs. |
| **Buffer full** | The webhook has its own internal buffer. If events arrive faster than batches can be sent, events are dropped. Monitor `RecordDrop` and increase `buffer_size` if needed. |
| **Redirect blocked** | Webhook follows no redirects. Make sure the URL is the final endpoint, not a redirect. |

---

## 🔶 Loki Events Not Appearing

| Cause | Fix |
|-------|-----|
| **Missing blank import** | Add `_ "github.com/axonops/audit/loki"` to register the Loki output type. |
| **`allow_private_ranges` not set** | For local development with `localhost:3100`, set `allow_private_ranges: true`. Private IPs are blocked by default (SSRF protection). |
| **`allow_insecure_http` not set** | For `http://` URLs, set `allow_insecure_http: true`. HTTPS is required by default. |
| **Loki ingestion delay** | Loki has a short delay between push and query availability. Wait 2-5 seconds, or query with a wider time range. |
| **Tenant ID mismatch** | If `tenant_id` is set, queries MUST include the `X-Scope-OrgID` header with the same value. |
| **429 rate limiting** | Loki is rate-limiting pushes. Monitor `RecordDrop` metrics. Increase `flush_interval` or reduce event volume. |
| **High cardinality rejection** | Too many unique label combinations. Exclude high-cardinality labels: set `pid: false` or `severity: false` in `labels.dynamic`. |
| **Buffer full, events dropped** | The internal buffer is full. Monitor `RecordDrop` and increase `buffer_size`. |
| **Redirect blocked** | Loki output never follows HTTP redirects. Ensure the URL is the final endpoint. |

---

## 📁 File Output Not Writing

| Cause | Fix |
|-------|-----|
| **Parent directory doesn't exist** | The library creates the file but not the directory. Create the parent directory before starting. |
| **Permission denied** | Check file system permissions. Default file permissions are `0600`. |
| **Symlink in path** | The file output rejects paths containing symlinks (security measure). Use the resolved absolute path. |
| **Disk full** | Check available disk space. Rotation only triggers at `max_size_mb` — if the disk fills before that, writes fail. |
| **Path contains unexpanded env var** | If using `${VAR}` syntax, make sure the variable is set. Unset variables expand to empty string, which may create an invalid path. |

---

## 🧪 Goroutine Leak in Tests

```
goleak: found unexpected goroutines
```

If you use `goleak.VerifyNone(t)` (recommended), a leaked drain
goroutine will cause test failures.

| Cause | Fix |
|-------|-----|
| **`auditor.Close()` not called** | The drain goroutine runs until `Close()` is called. Always call `Close()` in tests. |
| **`Close()` called too late** | `goleak` checks at test end. If `Close()` is deferred but another deferred function runs first, the goroutine may still be active. Put `Close()` as the first defer or use `t.Cleanup()`. |
| **Using `audittest.New`** | The `audittest` constructors default to synchronous delivery and register `t.Cleanup(auditor.Close)` automatically. With the default synchronous mode, no explicit `Close()` is needed before assertions. If you use `WithAsync()`, call `auditor.Close()` before assertions to drain the buffer. See [Testing](testing.md). |

---

## Reserved Standard Field Declared as Bare Optional

**Symptom:** `taxonomy validation failed: event "X" field "Y" is a reserved standard field`

**Cause:** You declared a reserved standard field (like `source_ip`, `actor_id`, `reason`) as a bare optional in your taxonomy. Reserved standard fields are always available without declaration.

**Fix:** Either remove the declaration, add `required: true`, or add sensitivity labels:
```yaml
# WRONG — bare optional, rejected:
source_ip: {}

# RIGHT — remove entirely (field is always available):
# (just don't declare it)

# RIGHT — make it mandatory:
source_ip: { required: true }

# RIGHT — add sensitivity labels:
source_ip:
  labels: [pii]
```

## Missing app_name or host in Outputs YAML

**Symptom:** `output config validation failed: app_name is required and must be non-empty`

**Cause:** Your `outputs.yaml` is missing the required `app_name` or `host` top-level field.

**Fix:** Add both to the top of your outputs YAML:
```yaml
version: 1
app_name: my-service
host: "${HOSTNAME:-localhost}"
outputs:
  # ...
```

## Secret Provider Failures

Secret resolution errors occur during `outputconfig.Load` when ref+
URIs in the YAML configuration cannot be resolved. `Load` fails hard
-- no partial configuration is returned.

### 403 Authentication Failure

```
audit/secrets: secret resolution failed: authentication failed (403)
```

| Cause | Fix |
|-------|-----|
| **Token expired** | Generate a new token and set `BAO_TOKEN` / `VAULT_TOKEN` before restarting |
| **Token lacks read capability** | Verify the token's policy grants `read` on the secret path: `bao token lookup` or `vault token lookup`, then check the attached policies |
| **Wrong namespace** | If using OpenBao/Vault namespaces, verify `Config.Namespace` matches the namespace where the secret is stored |

### 404 Path Not Found

```
audit/secrets: secret not found at path: path returned 404
```

| Cause | Fix |
|-------|-----|
| **CLI path instead of API path** | The most common mistake. The CLI path `secret/audit/hmac` maps to API path `secret/data/audit/hmac`. Ref URIs MUST use the API path with the `/data/` segment. |
| **Secret does not exist** | Verify the secret exists: `bao kv get secret/audit/hmac` or `vault kv get secret/audit/hmac` |
| **KV engine not mounted** | Verify the secret engine is mounted: `bao secrets list` or `vault secrets list` |

### Timeout During Resolution

```
secret resolution cancelled (field outputs.siem.webhook.headers.Authorization): context deadline exceeded
```

The default secret resolution timeout is `10s`
(`outputconfig.DefaultSecretTimeout`). All provider calls share this
single timeout budget.

| Cause | Fix |
|-------|-----|
| **Server unreachable** | Check network connectivity to the OpenBao/Vault address |
| **DNS resolution slow** | Verify DNS resolves the server hostname promptly |
| **Many secrets to resolve** | If the config references many secrets across different paths, increase the timeout with `outputconfig.WithSecretTimeout(30 * time.Second)` |
| **TLS handshake timeout** | The provider's HTTP transport has a 10-second TLS handshake timeout. Check that the server's TLS certificate is valid and the CA is correct. |

### Unresolved Ref After Resolution

```
audit/secrets: unresolved secret reference in config: field outputs.siem.webhook.headers.Authorization still contains a secret reference
```

| Cause | Fix |
|-------|-----|
| **No provider registered** | Add `outputconfig.WithSecretProvider(provider)` to the `Load` call |
| **Wrong scheme** | Check the scheme in the ref URI matches the provider's `Scheme()` return value (`openbao` or `vault`) |
| **Ref embedded in a larger string** | `ref+` MUST be at the start of the string value. `"Bearer ref+vault://..."` does not parse as a ref. Store the complete value as the secret. |
| **Typo in ref+ prefix** | Check for `Ref+`, `REF+`, or `ref +` -- the prefix MUST be exactly `ref+` (lowercase, no space) |

### SSRF Blocking the Connection

```
audit/secrets: secret resolution failed: loopback address 127.0.0.1 blocked
```

| Cause | Fix |
|-------|-----|
| **Local development server** | Set `AllowPrivateRanges: true` in the provider `Config`. This permits loopback and RFC 1918 addresses. |
| **Cloud metadata blocked** | Connections to `169.254.169.254` are always blocked, even with `AllowPrivateRanges: true`. This is intentional -- cloud metadata endpoints MUST NOT be reachable from secret providers. |

---

## 📚 Further Reading

- [Outputs § Failure Mode Matrix](outputs.md#-failure-mode-matrix) — concrete behaviour per output × failure mode (down, slow, auth, disk full, TLS expired, DNS, rate-limited)
- [Error Reference](error-reference.md) — all sentinel errors with recovery guidance
- [Async Delivery](async-delivery.md) — buffering, drain, shutdown
- [Metrics & Monitoring](metrics-monitoring.md) — tracking drops and errors
- [Output Configuration](output-configuration.md) — YAML reference
- [Secret Provider Integration](secrets.md) — ref+ URI syntax, provider setup, security model
