[&larr; Back to README](../README.md)

# Error Reference

- [How to Check Errors](#how-to-check-errors)
- [Core Errors](#core-errors)
- [Configuration Errors](#configuration-errors)
- [Output Errors](#output-errors)
- [Secret Resolution Errors](#secret-resolution-errors)
- [Taxonomy Errors](#taxonomy-errors)

## Error Format Convention

Every error returned by the library is prefixed with the dotted Go
import path of the module that produced it — matching stdlib
precedent (`net/http:`, `crypto/tls:`, `encoding/json:`):

| Module | Prefix |
|---|---|
| Core `audit` | `audit:` |
| File output | `audit/file:` |
| Syslog output | `audit/syslog:` |
| Webhook output | `audit/webhook:` |
| Loki output | `audit/loki:` |
| Output config loader | `audit/outputconfig:` |
| Secrets core | `audit/secrets:` |
| Secrets — HashiCorp Vault | `audit/secrets/vault:` |
| Secrets — OpenBao | `audit/secrets/openbao:` |

Every configuration-validation error wraps `audit.ErrConfigInvalid`
(directly or via a module-specific sub-sentinel). This gives you a
single `errors.Is` match across every config-facing surface:

```go
if errors.Is(err, audit.ErrConfigInvalid) {
    // any configuration validation failure — outputs, secrets, outputconfig
}
```

`outputconfig.ErrOutputConfigInvalid` is a sub-sentinel that itself
wraps `audit.ErrConfigInvalid`, so it also matches the generic form.
Pattern parallels stdlib's `fs.ErrNotExist` / `os.ErrNotExist`.

## How to Check Errors

All audit errors are sentinel values. Use `errors.Is` to check
for specific error types — never compare error strings:

```go
err := auditor.AuditEvent(event)
if errors.Is(err, audit.ErrQueueFull) {
    // handle buffer full
}
if errors.Is(err, audit.ErrClosed) {
    // auditor was already closed
}
```

Errors that wrap a sentinel (e.g., taxonomy validation) include
detail in the message. Use `errors.Is` to check the category, then
read the `.Error()` string for specifics.

---

## Core Errors

### `ErrQueueFull`

```
audit: queue full
```

| | |
|---|---|
| **When** | `AuditEvent()` is called but the async buffer channel is at capacity |
| **Meaning** | The event was **dropped** — it will not be delivered to any output |
| **Transient?** | Yes — resolves when the drain goroutine catches up |
| **What to do** | Log a warning, increment a metric (`RecordBufferDrop` fires automatically). Do NOT retry immediately — the queue is full and retrying worsens the backlog. If this happens frequently, increase `WithQueueSize` (or `auditor.queue_size` in YAML) or investigate slow outputs. See [Two-Level Buffering](async-delivery.md#two-level-buffering) for the pipeline architecture. |

### `ErrClosed`

```
audit: auditor is closed
```

| | |
|---|---|
| **When** | `AuditEvent()` is called after `Auditor.Close()` has been called |
| **Meaning** | The auditor has been shut down — no more events can be emitted |
| **Transient?** | No — permanent. The auditor cannot be reopened. |
| **What to do** | This usually means your shutdown ordering is wrong. Make sure you stop generating events (e.g., stop the HTTP server) before calling `auditor.Close()`. See [Graceful Shutdown](async-delivery.md#graceful-shutdown). |

### `ErrDuplicateDestination`

```
audit: duplicate destination
```

| | |
|---|---|
| **When** | `New()` is called with two outputs that write to the same destination (e.g., two file outputs with the same path, two syslog outputs with the same address) |
| **Meaning** | Auditor creation failed — duplicate outputs would cause data corruption or interleaved writes |
| **Transient?** | No — permanent configuration error |
| **What to do** | Check your output configuration for duplicate paths, addresses, or URLs. Each output must write to a unique destination. |

---

## Configuration Errors

### `ErrConfigInvalid`

```
audit: config validation failed
```

| | |
|---|---|
| **When** | `New()` is called with an invalid `Config` struct, an out-of-range option value, or an `EventRoute` that does not validate against the taxonomy |
| **Meaning** | Auditor creation failed — one or more config values are out of range |
| **Transient?** | No — permanent configuration error |
| **What to do** | Check the error message for details. Common causes: `QueueSize` exceeds 1,000,000, `ShutdownTimeout` exceeds 60 seconds, `Version` is not 1, an empty/over-length `WithAppName` / `WithHost` / `WithTimezone` value, an `EventRoute` that mixes include and exclude or references unknown taxonomy entries. The wrapped error message tells you which field is invalid. |
| **Sentinel coverage** (#556) | Wrapped via `%w` by every option-validator that fails: `WithAppName` empty / over-length, `WithHost` empty / over-length, `WithTimezone` empty / over-length, `WithStandardFieldDefaults` invalid key, `EventRoute` include/exclude mix, `EventRoute` severity out-of-range, `EventRoute` references unknown taxonomy entries. Use `errors.Is(err, audit.ErrConfigInvalid)` to discriminate any of these from `ErrTaxonomyRequired` / `ErrAppNameRequired` / `ErrHostRequired` (which mark missing-option failures, distinct from invalid-value failures). |

### `ErrTaxonomyRequired`

```
audit: taxonomy is required: use WithTaxonomy
```

| | |
|---|---|
| **When** | `New()` is called without [`WithTaxonomy`] (and without [`WithDisabled`]) |
| **Meaning** | Auditor creation failed — validation and routing require a taxonomy |
| **Transient?** | No — permanent configuration error |
| **What to do** | Add `audit.WithTaxonomy(tax)` to the `audit.New(...)` call, or use [`WithDisabled`] for a no-op auditor. Sibling of `ErrAppNameRequired` / `ErrHostRequired`; all three mark missing required options and support `errors.Is` discrimination. |

### `ErrAppNameRequired`

```
audit: app_name is required: use WithAppName
```

| | |
|---|---|
| **When** | `New()` is called without [`WithAppName`] (and without [`WithDisabled`]) |
| **Meaning** | Auditor creation failed — every emitted event carries `app_name` as a framework field, and a blank value undermines attribution |
| **Transient?** | No — permanent configuration error |
| **What to do** | Add `audit.WithAppName("your-service-name")` to the `audit.New(...)` call. Matches the `app_name:` requirement on the [`outputconfig.Load`] YAML construction path, so the two paths share the same invariant. |

### `ErrHostRequired`

```
audit: host is required: use WithHost
```

| | |
|---|---|
| **When** | `New()` is called without [`WithHost`] (and without [`WithDisabled`]) |
| **Meaning** | Auditor creation failed — every emitted event carries `host` as a framework field |
| **Transient?** | No — permanent configuration error |
| **What to do** | Add `audit.WithHost(os.Hostname())` or `audit.WithHost("prod-host-01")` to the `audit.New(...)` call. Matches the `host:` requirement on the [`outputconfig.Load`] YAML construction path. |

### `ErrOutputConfigInvalid`

```
audit/outputconfig: output config validation failed
```

| | |
|---|---|
| **Package** | `github.com/axonops/audit/outputconfig` |
| **When** | `outputconfig.Load()` is called with invalid YAML output configuration |
| **Meaning** | Output configuration parsing or validation failed |
| **Transient?** | No — permanent configuration error |
| **What to do** | Check the error message for details. Common causes: unknown output type (forgot a blank import), invalid YAML syntax, missing required fields (e.g., `url` for webhook, `path` for file), unknown YAML keys (check for typos), using removed `default_formatter` key (set `formatter:` on each output instead), non-JSON `formatter` on a Loki output. See [Output Configuration YAML](output-configuration.md). |

#### Representative wrapped error strings

Every YAML shape error follows the gold-standard pattern: **path context · what happened · what is valid · how to fix**. Operators searching logs for an `outputconfig` failure will see one of:

```
audit/outputconfig: output config validation failed: audit: config validation failed: auditor: expected YAML mapping, got string — auditor must be a mapping with fields like queue_size, validation_mode, shutdown_timeout
```

```
audit/outputconfig: output config validation failed: audit: config validation failed: standard_fields: unknown field "..." -- only reserved standard field names are accepted
```

```
audit/outputconfig: output config validation failed: audit: config validation failed: output "siem": unknown output type "websocket" (registered: [stdout, file, syslog, webhook, loki]); add import _ "github.com/axonops/audit/outputs" for all built-in types (or import _ "github.com/axonops/audit/websocket" for only this one)
```

The full chain is preserved so `grep`-friendly searches work end to end.

---

## Output Errors

### `ErrOutputClosed`

```
audit: output is closed
```

| | |
|---|---|
| **When** | `Output.Write()` is called after `Output.Close()` |
| **Meaning** | The output has been shut down — it cannot accept more events |
| **Transient?** | No — permanent |
| **What to do** | This is usually an internal library error. If you see it, it likely means `Close()` was called while events were still being processed. Report it as a bug. |

### `ErrHijackNotSupported`

```
audit: underlying ResponseWriter does not support hijacking
```

| | |
|---|---|
| **When** | The HTTP middleware's response writer wrapper receives a `Hijack()` call, but the underlying `http.ResponseWriter` does not implement `http.Hijacker` |
| **Meaning** | WebSocket upgrade or similar hijack operation is not supported by the server's response writer |
| **Transient?** | No — depends on the HTTP server implementation |
| **What to do** | This is rare. It occurs when the audit middleware wraps a response writer that doesn't support hijacking (e.g., HTTP/2 connections). If you need WebSocket support through the audit middleware, ensure your HTTP server supports hijacking. |

---

## HMAC Errors

HMAC validation errors occur when `outputconfig.Load()` encounters an
invalid HMAC configuration on an output, or when the programmatic API
receives invalid HMAC parameters.

| Error (contains) | When |
|------------------|------|
| `hmac salt.version is required when hmac is enabled` | `hmac.salt.version` is empty or missing |
| `hmac salt.value is required when hmac is enabled` | `hmac.salt.value` is empty or missing |
| `hmac algorithm is required when hmac is enabled` | `hmac.algorithm` is empty or missing |
| `hmac salt.value must be at least` | Salt is shorter than `audit.MinSaltLength` (currently 16) bytes |
| `unknown hmac algorithm` | Algorithm is not in `audit.SupportedHMACAlgorithms()` (currently: HMAC-SHA-256, HMAC-SHA-384, HMAC-SHA-512, HMAC-SHA3-256, HMAC-SHA3-384, HMAC-SHA3-512) |

All HMAC configuration validation errors (from `ValidateHMACConfig`, `outputconfig.Load()`, and `New`) wrap `audit.ErrConfigInvalid`. Use `errors.Is(err, audit.ErrConfigInvalid)` to detect them programmatically. Errors returned by `ComputeHMAC` and `VerifyHMAC` do not wrap this sentinel and must be handled separately.

### `ErrHMACMalformed`

```
audit: hmac value malformed
```

| | |
|---|---|
| **When** | `VerifyHMAC` receives a structurally invalid HMAC value: empty, wrong length for the algorithm's hash size, or containing non-lowercase-hex characters. |
| **Meaning** | The supplied signature cannot possibly be a valid HMAC for the configured algorithm — rejected BEFORE the constant-time compare, since malformed inputs are pre-authentication structural rejects and not timing-sensitive (#483). |
| **Transient?** | No. Fix the caller to supply a well-formed signature. |
| **What to do** | Ensure the HMAC value is lowercase hex and matches the expected length (64 chars for HMAC-SHA-256, 96 for SHA-384, 128 for SHA-512). Uppercase hex is rejected deliberately — `ComputeHMAC` always emits lowercase, so accepting uppercase would invite a "two valid encodings for one MAC" footgun. |
| **Sentinel behaviour** | Always wrapped alongside `ErrValidation` via `errors.Join`. Consumers may test either sentinel with `errors.Is`:<br>`errors.Is(err, audit.ErrHMACMalformed)` → narrow (format-specific)<br>`errors.Is(err, audit.ErrValidation)` → any validation failure, including format |

> Note: a valid-length + valid-hex signature that simply does NOT match the true HMAC returns `(false, nil)` — no error. Only structural rejects return `ErrHMACMalformed`.

---

## Loki Output Errors

| Error | When |
|-------|------|
| `url must not be empty` | Loki output has no URL configured |
| `must be https` | URL uses HTTP without `allow_insecure_http: true` |
| `must not contain credentials` | URL has embedded user:pass |
| `mutually exclusive` | Both `basic_auth` and `bearer_token` are set |
| `unknown dynamic label` | A `labels.dynamic` key is not one of the valid label names |
| `invalid` static label name | Label name doesn't match `[a-zA-Z_][a-zA-Z0-9_]*` |
| `loki does not support custom formatters` | `formatter: cef` or non-JSON on a Loki output |

---

## Webhook Output Errors

| Error | When |
|-------|------|
| `url must not be empty` | Webhook has no URL configured |
| `must be https` | URL uses HTTP without `allow_insecure_http: true` |
| `must not contain credentials` | URL has embedded user:pass |
| `batch_size must be at least 1` | Explicit zero or negative `batch_size` |
| `max_retries must be at least 1` | Negative `max_retries` (zero defaults to 3) |
| `buffer_size must be at least 1` | Explicit zero or negative `buffer_size` |
| `batch_size N exceeds maximum` | `batch_size` > 10,000 |
| `max_retries N exceeds maximum` | `max_retries` > 20 |
| `flush_interval must not be negative` | Negative duration |
| `timeout must not be negative` | Negative duration |
| `CR/LF` in header | Header contains carriage return or line feed |

---

## Syslog Output Errors

| Error | When |
|-------|------|
| `address must not be empty` | No syslog server address |
| `network must be tcp, udp, or tcp+tls` | Invalid transport protocol |
| `unknown syslog facility` | Facility name not in the standard set |
| `max_retries N exceeds maximum 20` | `max_retries` > 20 |
| `tls_cert and tls_key must both be set or both empty` | Only one of cert/key provided |
| `hostname exceeds RFC 5424 maximum` | Hostname > 255 bytes |
| `invalid byte` in hostname | Hostname contains non-PRINTUSASCII characters |

---

## Secret Resolution Errors

Secret resolution errors occur during `outputconfig.Load` when ref+
URIs cannot be resolved. All errors are in `github.com/axonops/audit/secrets`.

### `ErrMalformedRef`

```
audit/secrets: malformed secret reference
```

| | |
|---|---|
| **When** | `ParseRef` encounters a `ref+` URI with structural errors: empty scheme, empty path, empty key, path traversal (`..`), percent-encoded characters, or missing `://` separator |
| **Meaning** | The ref URI syntax is invalid -- the provider is never contacted |
| **Transient?** | No -- fix the ref URI in the YAML configuration |
| **What to do** | Check the exact error message for the specific validation failure. Common causes: missing `#key` fragment, leading `/` in path, consecutive slashes (`//`) in path. See [URI Syntax](secrets.md#uri-syntax). |

### `ErrProviderNotRegistered`

```
audit/secrets: no provider registered for scheme
```

| | |
|---|---|
| **When** | A ref URI references a scheme for which no `WithSecretProvider` was registered |
| **Meaning** | The library cannot resolve this ref because no provider handles the scheme |
| **Transient?** | No -- register the correct provider or fix the scheme in the ref URI |
| **What to do** | The error message includes the scheme and the field path: `audit/secrets: no provider registered for scheme: scheme "openbao" (field outputs.siem.webhook.headers.Authorization)`. Add the missing `outputconfig.WithSecretProvider(provider)` call, or correct the scheme in the ref URI. |

### `ErrSecretNotFound`

```
audit/secrets: secret not found at path
```

| | |
|---|---|
| **When** | The provider received a 404 from the server, or the requested key does not exist at the path |
| **Meaning** | The secret path or key does not exist in the backend |
| **Transient?** | No -- fix the path or key in the ref URI |
| **What to do** | The most common cause is using the CLI path instead of the API path. For KV v2, the CLI path `secret/audit/hmac` maps to API path `secret/data/audit/hmac`. Verify the secret exists with `bao kv get` or `vault kv get`. |

### `ErrSecretResolveFailed`

```
audit/secrets: secret resolution failed
```

| | |
|---|---|
| **When** | Network error, authentication failure (403), unexpected server response, timeout, or response size limit exceeded |
| **Meaning** | The provider contacted the server but the request failed |
| **Transient?** | Possibly -- authentication failures are permanent until the token is rotated; network errors may be transient |
| **What to do** | Check the wrapped error message for specifics: `authentication failed (403)` means the token lacks permission or is expired; `unexpected status N` means the server returned an error; `context deadline exceeded` means the resolution timeout was reached (increase with `WithSecretTimeout`). |

### `ErrUnresolvedRef`

```
audit/secrets: unresolved secret reference in config
```

| | |
|---|---|
| **When** | After all resolution passes, a string value in the config still contains a `ref+` pattern |
| **Meaning** | A ref URI was not resolved -- either no provider was registered, the scheme was wrong, or the ref was embedded in a larger string |
| **Transient?** | No -- fix the configuration or register the required provider |
| **What to do** | The error includes the field path: `field outputs.siem.webhook.headers.Authorization still contains a secret reference`. Check that: (1) a provider for the scheme is registered, (2) the ref is the entire string value (not embedded in a larger string), (3) the `ref+` prefix is exactly lowercase. |

---

## Taxonomy Errors

### `ErrTaxonomyInvalid`

```
audit: taxonomy validation failed
```

| | |
|---|---|
| **When** | `ValidateTaxonomy()` or `WithTaxonomy()` is called with a taxonomy that fails semantic validation |
| **Meaning** | The taxonomy structure is valid YAML but has logical errors |
| **Transient?** | No — permanent. Fix the taxonomy definition. |
| **What to do** | The error message lists all validation failures (one per line). Common causes: category references an event type not defined in `events`, event has a field in both required and optional, severity out of range (0-10), version not 1, reserved standard field declared as bare optional (use `required: true` or add labels), framework field declared as user field. Fix each listed issue in your taxonomy YAML. |

### `ErrInvalidTaxonomyName`

```
audit: invalid taxonomy name
```

| | |
|---|---|
| **When** | A category name, event type key, required/optional field name, or sensitivity label name fails the character-set or length rule. |
| **Meaning** | The offending name contains a character outside `[a-z][a-z0-9_]*` or exceeds 128 bytes. Protects downstream log consumers from bidi overrides, Unicode confusables, CEF/JSON metacharacters, and C0/C1 control bytes (issue #477). |
| **Transient?** | No — permanent. Fix the taxonomy definition. |
| **What to do** | Rename the identifier to use only lowercase letters, digits, and underscores, starting with a letter, and keep it under 128 bytes. See [Taxonomy Validation — Name Character Set and Length](taxonomy-validation.md#️-name-character-set-and-length) for the full rule and rationale. |
| **Sentinel behaviour** | Always wrapped alongside `ErrTaxonomyInvalid` via `errors.Join`. Consumers may test either sentinel with `errors.Is`:<br>`errors.Is(err, audit.ErrInvalidTaxonomyName)` → narrow (name-shape only)<br>`errors.Is(err, audit.ErrTaxonomyInvalid)` → any taxonomy error, including name-shape |

Example error message (with bidi bytes rendered as Go escapes):

```
audit: taxonomy validation failed:
- event type name "user\u202eadmin" is invalid: must match ^[a-z][a-z0-9_]*$
audit: invalid taxonomy name
```

### New validation errors (#237)

```
event "X" field "Y" is a reserved standard field -- it is always available without declaration; to reference it, set required: true or add labels
```

| | |
|---|---|
| **When** | A reserved standard field (actor_id, source_ip, reason, etc.) is declared as a bare optional field in the taxonomy |
| **Meaning** | Reserved standard fields are always available. Bare optional declarations are redundant. |
| **What to do** | Either remove the declaration entirely, add `required: true` to make it mandatory, or add sensitivity labels. |

```
audit: app_name must not be empty
audit: host must not be empty
audit: timezone must not be empty
```

| | |
|---|---|
| **When** | `WithAppName("")`, `WithHost("")`, or `WithTimezone("")` is called |
| **Meaning** | Framework field values cannot be empty strings |
| **What to do** | Provide a non-empty value. In outputs YAML, ensure `app_name` and `host` are set. |

```
audit: standard field default key "X" is not a reserved standard field
```

| | |
|---|---|
| **When** | `WithStandardFieldDefaults` is called with a key that is not one of the 31 reserved standard field names |
| **Meaning** | Only reserved standard fields can have deployment-wide defaults |
| **What to do** | Check the field name against `ReservedStandardFieldNames()`. |

### `ErrInvalidInput`

```
audit: invalid input
```

| | |
|---|---|
| **When** | `ParseTaxonomyYAML()` is called with input that cannot be parsed as valid YAML |
| **Meaning** | The input is structurally invalid — not a YAML problem with your taxonomy, but a YAML syntax or input problem |
| **Transient?** | No — permanent. Fix the input. |
| **What to do** | Common causes: input contains multiple YAML documents (separated by `---`), YAML syntax error (bad indentation, tabs instead of spaces), unknown YAML key (typo in field name — the parser rejects unknown keys). The wrapped error message gives the specific parse error. |

#### Representative wrapped error strings

YAML shape errors raised inside taxonomy parsing follow the gold-standard pattern: **path context · what happened · what is valid · how to fix**. Operators searching for a `ParseTaxonomyYAML` failure will see one of:

```
audit: invalid input: taxonomy: categories must be a YAML mapping — declare like:
  categories:
    read:
      events: [user_view]
```

```
audit: invalid input: category "read": event name must be a string (got uint64) — use bare strings like '- user_create'
```

```
audit: invalid input: category "read": expected a YAML sequence (e.g. '- user_create') or mapping (e.g. 'events: [...]'), got bool
```

```
audit: invalid input: category "read": unknown field "bogus" (valid: events, severity)
```

```
audit: invalid input: category "read": severity must be an integer 0-7 (got string)
```

```
audit: invalid input: categories: emit_event_category: expected boolean (got string) — use true or false
```

```
audit: invalid input: unknown field "..." (valid: categories, events, sensitivity, version)
```

The last form is produced by `ParseTaxonomyYAML` when a typo at the top level reaches `goccy/go-yaml`'s `DisallowUnknownField` — the library appends the `(valid: ...)` suffix via `WrapUnknownFieldError`, which uses typed-error discrimination against `yaml.UnknownFieldError` rather than fragile substring matching, so an upstream rephrasing cannot silently break detection.

### `ErrHandleNotFound`

```
audit: event type not found
```

| | |
|---|---|
| **When** | `Auditor.Handle()` or `Auditor.MustHandle()` is called with an event type name not registered in the taxonomy |
| **Meaning** | The event type string does not match any event defined in the taxonomy |
| **Transient?** | No — permanent. The event type must exist in the taxonomy. |
| **What to do** | Check for typos in the event type name. Use generated constants (`EventUserCreate`) instead of string literals to catch this at compile time. If using `MustHandle()`, note that it **panics** instead of returning an error — use `Handle()` if you want to handle the error gracefully. |

---

### Startup connectivity probe failures (#286)

```
audit/webhook: startup verification failed for https://audit.example.com: dial tcp 203.0.113.10:443: connect: connection refused (set verify_on_startup: false to skip)
audit/loki: startup verification failed for https://loki.example.com: tls handshake: tls: failed to verify certificate (set verify_on_startup: false to skip)
audit/syslog: startup verification failed for tcp+tls://siem.example.com:6514: dial tcp 198.51.100.20:6514: i/o timeout (set verify_on_startup: false to skip)
```

| | |
|---|---|
| **When** | `New()` is called on a webhook, loki, or syslog output and the construction-time probe (TCP dial + optional TLS handshake) fails. Default behaviour: the probe is ON. |
| **Meaning** | The destination is unreachable, the TLS handshake failed, or the SSRF dial control rejected the address. The application cannot start with a broken audit destination — silent event loss is worse than a startup failure. |
| **Transient?** | The cause is. The probe itself is one-shot at startup. Once `New()` returns success, the probe is not re-run. |
| **What to do** | Three options, in order of preference. (1) Fix the configuration — wrong host, wrong port, expired certificate, missing CA bundle. (2) If the destination is correctly configured but legitimately comes up after the application (sidecar containers, K8s startup ordering), set `verify_on_startup: false` on that output's YAML or set `Config.DisableStartupVerification: true` in Go code. The runtime reconnect/retry path handles delivery once the destination becomes available. (3) If the failure is SSRF-related (probe rejected a private address by default), set `allow_private_ranges: true` only if the destination is operator-owned inside the same network policy zone — never for user-influenced URLs. The probe applies the SAME SSRF policy as the runtime transport, so a permissive probe with a strict runtime is impossible by design. |

The probe budget is controlled by `verify_on_startup_timeout` (default `5s`). Operators on slow WAN paths can raise this; CI/local development is fine with the default.

### File output fsync_each_batch failures (#678)

```
audit: output file: sync failed
```

(emitted via `slog.Error` with `error="rotate: sync: <os error>"`
and `batch_size=<n>`; example:
`error="rotate: sync: write /var/log/audit/events.log: no space left on device"`)

| | |
|---|---|
| **When** | `fsync_each_batch: true` is configured (YAML) or `Config.FsyncEachBatch: true` (Go), the writeLoop completes a `writev(2)` successfully, and the subsequent `fsync(2)` returns an error. |
| **Meaning** | The kernel could not commit the page-cache pages to stable storage. Possible causes: ENOSPC (disk full), EIO (underlying device error), EBUSY/EROFS (filesystem remounted read-only), or the Linux "fsync-gate" behaviour where the kernel clears the error state after the first read. The batch is considered failed; events that reached only the page cache may be lost. The failure is reported via `RecordError()` — there is no silent data loss. `LastDeliveryNanos` is NOT advanced (the durability contract was not met). |
| **Transient?** | Depends on the underlying cause. ENOSPC is transient once disk space is freed. EIO usually indicates hardware degradation — investigate disk health. The audit library does not retry inside `writeBatch`; the next batch attempts a fresh `writev(2)` + `fsync(2)`. |
| **What to do** | (1) Check disk space and the audit log filesystem health (`dmesg`, `smartctl`, cloud-provider disk-health alerts). (2) If the failure is `EROFS`, investigate why the filesystem went read-only. (3) Consider whether `fsync_each_batch` is the right choice for the deployment — if storage is unreliable, the per-batch fsync increases the surface for errors; you may prefer to accept the page-cache crash window and run with the default (`fsync_each_batch: false`). (4) If the underlying storage is contended (noisy-neighbour on shared infrastructure), the latency surge from a slow fsync can back-pressure the drain goroutine and cause buffer-full drops; raise `buffer_size` or co-locate the audit log on dedicated storage. |

The path appears in the wrapped `*PathError` from `os.File.Sync` — same redaction posture as `audit: output file: delivery failed` (operator-controlled config; not sensitive).

---

## Further Reading

- [Async Delivery](async-delivery.md) — buffer sizing, delivery guarantee, graceful shutdown
- [Taxonomy YAML Reference](taxonomy-validation.md) — fixing taxonomy validation errors
- [Output Configuration YAML](output-configuration.md) — fixing output config errors
- [Metrics & Monitoring](metrics-monitoring.md) — tracking errors via the Metrics interface
