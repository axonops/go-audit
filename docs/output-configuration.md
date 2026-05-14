[&larr; Back to README](../README.md)

# Output Configuration YAML Reference

The output configuration is a YAML file that defines where your audit
events are sent: which outputs to use, how to format events, how to
route events per-output, and which sensitive fields to strip.

This is a complete reference for everything that can go in an
`outputs.yaml` file.

> ⚠️ **Loaded from the filesystem at runtime — not embedded.**
> Unlike the taxonomy (which is typically `go:embed`-ed into the
> binary), the outputs configuration is intended to be read from
> disk every time the auditor starts so operators can change
> destinations, credentials, and routing without rebuilding the
> application. The file path passed to
> `outputconfig.New(ctx, taxonomyYAML, path)` is passed directly to
> `os.ReadFile` — if relative, it resolves against the process CWD
> at the moment `New` is called (not at program start). Under
> systemd without an explicit `WorkingDirectory=` directive the CWD
> is `/`, and under Docker or Kubernetes the CWD depends on the
> image's `WORKDIR` and any `workingDir:` override. For production
> deployments you SHOULD use an absolute path
> (e.g., `/etc/myapp/outputs.yaml`) or a path resolved against the
> binary's own directory. See
> [Loading Output Configuration](#loading-output-configuration)
> below for the supported loaders.

## Complete Schema

```yaml
version: 1

# Auditor Configuration (optional) ────────────────────────
# Core auditor settings. If omitted, sensible defaults are used.

auditor:
  enabled: true                    # default: true (set false to disable auditing)
  queue_size: 10000                # default: 10,000 (max: 1,000,000)
  shutdown_timeout: "5s"              # default: "5s" (max: "60s")
  validation_mode: strict          # "strict" (default), "warn", "permissive"
  omit_empty: false                # default: false

# Framework Fields ──────────────────────────────────────
# Identify every event's origin. app_name and host are required.
# Environment variables are supported in all values.

app_name: "my-service"               # REQUIRED: application name
host: "${HOSTNAME:-localhost}"        # REQUIRED: hostname / environment
timezone: "${TZ:-UTC}"               # optional in YAML — auto-detected from system if omitted; always present in output

# Standard Field Defaults (optional) ────────────────────
# Deployment-wide default values for reserved standard fields.
# Applied to every event unless the event sets its own value.
# Keys must be reserved standard field names (actor_id, source_ip,
# etc.) — see docs/reserved-standard-fields.md for the full list
# of 31 names plus their Go types and CEF mappings.

standard_fields:
  source_ip: "${DEFAULT_SOURCE_IP:-10.0.0.1}"
  actor_id: "${SERVICE_ACCOUNT:-system}"

# TLS Policy (per-output / per-provider) ────────────────
# TLS policy is configured inside each output block (syslog,
# webhook, loki) and each secret-provider block (vault, openbao).
# There is no root-level tls_policy key — attempting to set one
# fails at startup with an "unknown top-level key" error. See the
# per-output blocks below for examples.

# Outputs ─────────────────────────────────────────────────
# Map of named outputs. Each output has a type, optional config,
# optional formatter override, optional event route, and optional
# sensitivity label exclusions.

outputs:

  # ── Stdout Output ─────────────────────────────────────────
  console:
    type: stdout
    # No additional config needed. Writes to os.Stdout.

  # ── File Output ───────────────────────────────────────────
  audit_file:
    type: file
    enabled: true                  # optional, default true — set false to disable
    file:
      path: "${AUDIT_LOG_DIR:-/var/log/audit}/events.log"   # env vars supported
      max_size_mb: 100             # rotate at this size (default: 100)
      max_backups: 5               # keep this many rotated files (default: 5)
      max_age_days: 30             # delete files older than this (default: 30)
      group_readable: false        # true → mode 0o640 (default false → 0o600)
      compress: true               # gzip rotated files (default: true)
    route:
      exclude_categories:
        - read                     # don't write verbose read events to this file
    exclude_labels:
      - pii                        # strip PII fields before writing

  # ── Syslog Output ─────────────────────────────────────────
  siem:
    type: syslog
    syslog:
      network: "tcp+tls"           # "tcp" (default), "udp", or "tcp+tls"
      address: "${SYSLOG_HOST}:6514"
      app_name: "myapp"            # RFC 5424 APP-NAME — cascades from top-level app_name when omitted (see docs/syslog-output.md#app-name-cascade)
      facility: "local0"           # syslog facility (default: "local0")
      tls_ca: "/etc/audit/ca.pem"
      tls_cert: "/etc/audit/client-cert.pem"   # for mTLS
      tls_key: "/etc/audit/client-key.pem"     # for mTLS
      max_retries: 10              # reconnection attempts (default: 10)
      # Batching (mirrors loki/webhook conventions — #599):
      batch_size: 100              # events per flush (default: 100; set 1 to disable)
      flush_interval: "5s"         # max time between flushes (default: 5s)
      max_batch_bytes: 1048576     # 1 MiB; oversized single events flush alone
      max_event_bytes: 1048576     # 1 MiB per-event size cap; oversized events rejected (#688)
      # tls_policy:                # TLS version policy
      #   allow_tls12: false       # allow TLS 1.2 (default: TLS 1.3 only)
      #   allow_weak_ciphers: false # allow weaker ciphers with TLS 1.2
    formatter:
      type: cef                    # SIEM-native format
      vendor: "MyCompany"
      product: "MyApp"
      version: "1.0"
    route:
      include_categories:
        security: {}             # only security events to SIEM

  # ── Webhook Output ────────────────────────────────────────
  alerts:
    type: webhook
    webhook:
      url: "https://ingest.example.com/audit"
      batch_size: 50               # events per batch (default: 100)
      flush_interval: "5s"         # time-based flush (default: "5s")
      max_batch_bytes: 1048576     # 1 MiB byte-threshold flush; oversized events flush alone (#687)
      max_event_bytes: 1048576     # 1 MiB per-event size cap; oversized events rejected (#688)
      timeout: "10s"               # HTTP request timeout (default: "10s")
      max_retries: 3               # retry attempts (default: 3)
      # buffer_size: 10000        # internal buffer; events dropped when full
      # headers:                   # custom HTTP headers
      #   Authorization: "Bearer ${AUDIT_TOKEN}"
      # tls_ca: "/etc/audit/ca.pem"
      # tls_cert: "/etc/audit/client-cert.pem"
      # tls_key: "/etc/audit/client-key.pem"
      # tls_policy:                # TLS version policy
      #   allow_tls12: false
      #   allow_weak_ciphers: false
      # allow_insecure_http: true  # MUST NOT be true in production
      # allow_private_ranges: true # disable SSRF protection (dev only)
    route:
      min_severity: 7              # only high-severity events
    exclude_labels:
      - pii
      - financial                  # strip sensitive fields

  # ── Loki Output ───────────────────────────────────────────
  loki_audit:
    type: loki
    loki:
      url: "https://loki.example.com/loki/api/v1/push"
      tenant_id: "${LOKI_TENANT:-}"
      batch_size: 100                # events per push (default: 100)
      max_batch_bytes: 1048576       # max payload bytes (default: 1 MiB)
      flush_interval: "5s"           # time-based flush (default: "5s")
      timeout: "10s"                 # HTTP request timeout (default: "10s")
      max_retries: 3                 # retry on 429/5xx (default: 3)
      gzip: true                     # gzip compression (default: true)
      labels:
        static:
          environment: "production"
          job: "audit"
        dynamic:                     # all included by default; set false to exclude
          # pid: false               # exclude pid (high cardinality)
      # basic_auth:
      #   username: "loki-writer"
      #   password: "${LOKI_PASSWORD}"
      # bearer_token: "${LOKI_TOKEN}"
      # tls_ca: "/etc/audit/ca.pem"
      # allow_insecure_http: true    # MUST NOT be true in production
      # allow_private_ranges: true   # disable SSRF protection (dev only)
    route:
      include_categories:
        security: {}
```

## Top-Level Fields

| Field | Required | Description |
|-------|----------|-------------|
| `version` | Yes | Must be `1`. Schema version for future migration. See [Config Schema Versioning](#config-schema-versioning) below. |
| `app_name` | Yes | Application name. Emitted as a framework field in every event. Max 255 bytes. |
| `host` | Yes | Hostname/environment. Emitted as a framework field. Max 255 bytes. Env vars supported. |
| `timezone` | No | Timezone name (e.g. `UTC`, `America/New_York`). Max 64 bytes. Auto-detected from system when absent. |
| `standard_fields` | No | Map of reserved standard field names to deployment-wide default values. Keys must be one of the 31 names listed in [Reserved standard fields](reserved-standard-fields.md). |
| `secrets` | No | Secret provider configuration. Constructs providers from YAML instead of programmatic setup. See [Secrets Configuration](#secrets-configuration). |
| `auditor` | No | Auditor configuration. All fields optional; defaults applied if omitted. |
| `outputs` | Yes | Map of named outputs. At least one must be defined. Maximum: 100. |

> ⚠️ **No root-level `tls_policy` key.** TLS policy is configured inside each output (under `syslog:`, `webhook:`, `loki:`) and each secret provider (under `vault:`, `openbao:`). Setting `tls_policy:` at the root fails at startup with an "unknown top-level key" error. See [Per-Output TLS Policy](#per-output-tls-policy) below.

## Config Schema Versioning

The outputs YAML carries a top-level `version:` field so the
library can recognise the shape of the document and apply
migrations when a future schema change lands.

### What `version: 1` means today

`version: 1` is the only currently-defined schema version. Every
outputs config MUST set `version: 1` explicitly:

```yaml
version: 1
app_name: my-service
host: my-host
outputs:
  ...
```

A missing or wrong `version:` value is rejected at load time
with:

```
audit/outputconfig: output config validation failed: audit: config invalid: unsupported version 0 (expected 1)
audit/outputconfig: output config validation failed: audit: config invalid: unsupported version 2 (expected 1)
```

These errors wrap both
[`outputconfig.ErrOutputConfigInvalid`](https://pkg.go.dev/github.com/axonops/audit/outputconfig#pkg-variables)
and the parent
[`audit.ErrConfigInvalid`](https://pkg.go.dev/github.com/axonops/audit#pkg-variables);
consumers can match either via `errors.Is` without coupling to
the message text.

### Schema version is independent of library release version

The schema version (`version: 1` in YAML) is **not** the library
release version (e.g., v1.0.0, v1.5.0, v2.0.0). They evolve
independently:

- A v1.5 library MAY still use schema `version: 1` — operators
  upgrading the library do NOT need to touch their YAML.
- The schema version bumps only when the YAML shape itself
  changes in a way that older libraries cannot interpret (new
  required field, removed field, or restructured nesting). This
  is a maintainer-side decision; consumers do not need to touch
  the version field on routine library upgrades.
- A library release version bumps for any release reason — bug
  fix, new feature, performance improvement — even when the
  schema is unchanged.

For the lifetime of v1.x of the library, `version: 1` will remain
accepted. Schema-breaking changes are themselves library-major
events: a `version: 2` schema would land in v2.x of the library
(or earlier, with `version: 1` still accepted alongside it).

### Future migration contract

When `version: 2` is introduced, the library will:

1. Accept both `version: 1` and `version: 2` configs side-by-side
   for at least one tagged library release; the deprecation
   timeline for `version: 1` will be announced via the
   `CHANGELOG.md` `### Deprecated` section.
2. Silently upgrade `version: 1` configs to the new internal
   shape — operators do not need to rewrite their YAML.
3. Reject `version: N+1` from a library that only knows up to
   `N`, with a clear "upgrade the library" error.
4. Reject `version: K-M` once support for `K-M` is dropped, with
   a clear "no longer supported" error that names the lowest
   still-accepted version.

The current code path in `outputconfig.Load` performs a single
hardcoded equality check against `1`. When the second schema
version arrives, that check will be replaced with a migration
mechanism analogous to the taxonomy's
[`MigrateTaxonomy`](https://pkg.go.dev/github.com/axonops/audit#MigrateTaxonomy)
— inline version handling rather than a public `RegisterMigration`
API. This keeps migrations as library-implementation detail
rather than a consumer extension point.

The taxonomy schema versioning model is documented in parallel at
[`docs/taxonomy-validation.md` "Taxonomy Schema Versioning"](taxonomy-validation.md#taxonomy-schema-versioning).
The two schemas (taxonomy + outputs) version independently — a
taxonomy bump does not require an outputs config bump and vice
versa.

### When the maintainer adds `version: 2`

The schema-bump workflow for the outputs config is:

1. Replace the hardcoded equality check in `outputconfig.Load`
   with a migration switch (`switch version { case 1: ...; case
   2: ...; default: reject }`).
2. Update the YAML examples under `outputconfig/testdata/` and
   `examples/*/outputs.yaml` to use the new version where
   appropriate (keeping at least one `version: 1` example to
   lock the migration path).
3. Add a regression BDD scenario that loads a `version: 1`
   outputs config and asserts the in-memory `Loaded` shape
   matches a hand-written `version: 2` equivalent.
4. Update this section with the new version literal and the
   shape change.

## Standard Field Defaults

The optional `standard_fields:` block sets deployment-wide default
values for one or more **reserved standard fields** — the 31
predeclared, library-fixed fields that every taxonomy can use
without redeclaring. The block is keyed by reserved standard field
name; values are applied to every emitted event unless the event
itself sets the same field.

```yaml
standard_fields:
  source_ip: "${DEFAULT_SOURCE_IP:-10.0.0.1}"
  actor_id: "${SERVICE_ACCOUNT:-system}"
```

**Keys** must be one of the 31 reserved standard field names —
attempting to use a custom field name fails at startup with the
following error (wrapped through `outputconfig.ErrOutputConfigInvalid`
and `audit.ErrConfigInvalid`):

```
audit/outputconfig: output config validation failed: audit: config
validation failed: standard_fields: unknown field "your_field" --
only reserved standard field names are accepted
```

Use `errors.Is(err, outputconfig.ErrOutputConfigInvalid)` for
programmatic handling. Empty string values are rejected the same
way (a deployment-time empty default is always a configuration
mistake).

**Values** must match the reserved field's declared Go type as
reported by `audit.ReservedStandardFieldType`. For the current 31
reserved fields, the types in use are: `string` (26 fields), `int`
(`dest_port`, `file_size`, `source_port`), and `time.Time`
(`start_time`, `end_time`). The YAML loader accepts the natural
YAML scalar (string for string fields, integer for `int` fields,
RFC 3339 timestamp string for `time.Time` fields) and coerces it
to the declared Go type at load time. Environment-variable
substitution is supported in all string values via `${VAR}` and
`${VAR:-default}`.

**Precedence.**

| Source | Wins when |
|---|---|
| Event setter (`SetActorID(...)`, etc.) | The event sets the field |
| `standard_fields:` default | The event does not set the field |
| Absent (or zero-valued under `omit_empty: false`) | Neither event nor default sets the field |

> 📖 **Reference.** For the canonical list of all 31 reserved
> standard field names, their Go types, and their CEF extension
> keys, see **[`docs/reserved-standard-fields.md`](reserved-standard-fields.md)**.
> That page is the single source of truth for the reserved-field
> contract.

## Auditor Configuration

The optional `auditor:` section configures the core auditor. All
fields are optional — omitted fields use sensible defaults.

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `true` | Set `false` to disable audit logging entirely (no-op auditor). |
| `queue_size` | `10000` | Core async channel capacity (Level 1). Events dropped when full. Maximum: 1,000,000. See [Two-Level Buffering](async-delivery.md#two-level-buffering). |
| `shutdown_timeout` | `"5s"` | How long `Close()` waits for pending events to flush. Maximum: `"60s"`. |
| `validation_mode` | `"strict"` | `"strict"` rejects unknown fields, `"warn"` logs them, `"permissive"` accepts all. |
| `omit_empty` | `false` | `true` to skip zero-value fields in output. Consumers under compliance regimes that require all registered fields SHOULD leave this `false`. Only applies when no per-output `formatter` is configured — when an explicit formatter is present, the formatter's own `omit_empty` takes precedence. |

All values support environment variable substitution:

```yaml
auditor:
  queue_size: ${AUDIT_QUEUE_SIZE:-10000}
  shutdown_timeout: "${AUDIT_DRAIN_TIMEOUT:-5s}"
  enabled: ${AUDIT_ENABLED:-true}
```

## Diagnostic Logger Propagation

The `auditor:` section has no YAML field for the diagnostic logger — a
`*slog.Logger` is a runtime value, not a YAML construct. Configure it
programmatically when loading the output configuration:

```go
logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

loaded, err := outputconfig.Load(
    ctx,
    data,
    taxonomy,
    outputconfig.WithDiagnosticLogger(logger), // construction-time warnings
)

opts := append([]audit.Option{
    audit.WithTaxonomy(taxonomy),
    audit.WithDiagnosticLogger(logger),         // runtime warnings
}, loaded.Options()...)
auditor, err := audit.New(opts...)
```

Pass the same logger to both `outputconfig.WithDiagnosticLogger` and
`audit.WithDiagnosticLogger`. The first routes warnings emitted during
output construction (TLS policy, file permission mode). The second
routes warnings emitted at runtime (connection retries, buffer-full
drops). Using the same logger ensures all library diagnostics reach
one handler.

Supplying only `audit.WithDiagnosticLogger` leaves construction-time
warnings routed through `slog.Default` — a subtle inconsistency if
your application uses a non-default handler. Both options accept nil
(equivalent to `slog.Default`).

## Per-Output TLS Policy

TLS policy is configured inside each TLS-capable block — `syslog:`
(when `network: tcp+tls`), `webhook:` (when `https://`), `loki:`
(when `https://`), and each secret provider (`vault:`, `openbao:`).
There is no root-level `tls_policy:` key — attempting to set one
fails at startup with an "unknown top-level key" error.

Each output or provider that does not specify `tls_policy` defaults
to **TLS 1.3 only** (no TLS 1.2, no weak ciphers). Every `tls_policy`
block stands alone — there is no inheritance from a shared default.

```yaml
outputs:
  siem:
    type: syslog
    syslog:
      network: tcp+tls
      address: siem.example.com:6514
      tls_policy:
        allow_tls12: true          # required for a legacy SIEM target
        allow_weak_ciphers: false  # keep ciphers strict even when TLS 1.2

  alerts:
    type: webhook
    webhook:
      url: https://alerts.example.com/webhook
      # no tls_policy → default TLS 1.3 only, no weak ciphers

secrets:
  my_vault:
    type: vault
    vault:
      address: https://vault.example.com:8200
      tls_policy:
        allow_tls12: false
        allow_weak_ciphers: false
```

| Field | Default | Description |
|-------|---------|-------------|
| `allow_tls12` | `false` | Allow TLS 1.2 connections in addition to TLS 1.3. When `false` (default), only TLS 1.3 is accepted. Set `true` only when connecting to legacy infrastructure that does not support TLS 1.3. |
| `allow_weak_ciphers` | `false` | Allow weaker cipher suites when TLS 1.2 is enabled. Has no effect when `allow_tls12` is `false`. SHOULD NOT be enabled unless required by a specific server. |

> ⚠️ **Security:** The default policy (TLS 1.3 only, no weak ciphers)
> is the most secure configuration. Only relax these settings when
> connecting to infrastructure that cannot be upgraded.

Outputs that do not use TLS (file, stdout, syslog with `network: tcp`
or `network: udp`) have no `tls_policy` field.

### Tested TLS rejection failure modes

The library's TLS-capable outputs reject defective server
certificates from the same shared `audit.TLSPolicy` primitive.
The behaviours below are pinned by BDD scenarios in
[`tests/bdd/features/syslog_output.feature`](../tests/bdd/features/syslog_output.feature),
[`webhook_output.feature`](../tests/bdd/features/webhook_output.feature),
and [`loki_output.feature`](../tests/bdd/features/loki_output.feature)
(see #552):

| Failure mode | Observed behaviour |
|---|---|
| **Expired server certificate** | Client refuses the connection. Syslog (synchronous) returns an error containing `certificate has expired`. Webhook / Loki (asynchronous) drop the event before the HTTPS POST is attempted; the receiver sees zero requests. |
| **Server certificate CN/SAN does not match the dialled host** | Client refuses the connection with `x509: cannot validate certificate for <host>` (or `is valid for <other-name>` on older Go releases). Same delivery semantics as expired. |
| **Stalled TLS handshake (TCP accepted, server never replies)** | Webhook / Loki: client honours its `Timeout` config; the request fails fast and `Close` returns within the bounded shutdown window. Syslog: bounded by `Config.TLSHandshakeTimeout` (#746) — default `10s`, valid range `100ms–60s`, applied to the total TCP-dial-plus-handshake budget on initial `New` and every reconnect. The error wraps a transient connect failure containing the substring `tls handshake timeout` so the existing reconnect path retries. Locked by the BDD scenario "Syslog New returns bounded under a stalled TLS handshake" in [`tests/bdd/features/syslog_output.feature`](../tests/bdd/features/syslog_output.feature). |
| **Reconnect after server kill mid-buffer** | Pre-restart events deliver. Post-restart events deliver after the client reconnects. Submitted-counter accounting holds. See [`tests/bdd/features/syslog_output.feature`](../tests/bdd/features/syslog_output.feature) "Crash and replay" block (#553) for syslog. Webhook/Loki: see `Webhook recovers from rapid server connection drops` and `Loki recovers from rapid server connection drops` (#552). |
| **Three rapid syslog-ng restarts** | Reconnect count stays under the 30-attempt storm threshold; bounded backoff. |
| **Vault / OpenBao secrets endpoint with expired TLS cert** | `outputconfig.Load` fails with an error containing `expired`. The `ref+vault://` and `ref+openbao://` resolution paths refuse to connect; no secret value is returned. See `outputconfig/tests/bdd/features/secret_resolution.feature` scenarios 23–24 (#552 AC#2). |

### Tested file-output OS-level failure modes (#748)

The file output's `writeBatch` calls `OutputMetrics.RecordError` when
the underlying filesystem returns a non-retryable errno. Three OS-level
scenarios in
[`tests/bdd/features/file_output.feature`](../tests/bdd/features/file_output.feature)
pin the behaviour:

| Failure mode | Test mechanism | Scenario |
|---|---|---|
| **Permission denied after rotation** (EACCES) | In-process: configure `MaxSizeMB=1`, write enough events to trigger one rotation, `chmod 0o555` the audit log directory, write another batch large enough to trigger a second rotation. The rotate path's `os.Rename` fails because the directory's write bit is required to add/remove entries; `RecordError` fires for each failed batch. | "File output records RecordError when target directory becomes read-only" |
| **Open-file-limit exhaustion on rotation** (EMFILE) | Subprocess fork: the BDD step shells out to `tests/bdd/cmd/file-emfile-runner`, which exhausts its fd budget with `/dev/null` opens, calls `syscall.Setrlimit(RLIMIT_NOFILE)` below the live count, then triggers an audit. The lazy `openNew` fails with `EMFILE`; subprocess prints `EMFILE_OBSERVED` and exits 0. | "File output records RecordError when fd limit is exhausted on rotation" (`@linux`) |
| **Disk full** (ENOSPC) | Privileged Docker harness: `tests/bdd/docker-compose.file-os.yml` mounts a 256 KiB tmpfs at `/audit-test-tmpfs`. The BDD step runs `tests/bdd/cmd/file-enospc-runner` inside the container via `docker compose exec`; the runner writes events until the tmpfs fills and the kernel returns `ENOSPC`. Stdout marker `ENOSPC_OBSERVED` + exit 0 reports success. | "File output records RecordError on ENOSPC" (`@linux @docker`) |

To run the OS-level scenarios locally:

```bash
# In-process scenario (no Docker needed)
make test-bdd-file

# Docker harness for the ENOSPC scenario
make test-infra-file-os-up
make test-bdd-file-os
make test-infra-file-os-down
```

The MockFileMetrics extension that captures these errors lives at
[`tests/bdd/steps/file_steps.go`](../tests/bdd/steps/file_steps.go)
(`MockFileMetrics.RecordError` + `ErrorCount`).

## Secrets Configuration

The optional `secrets:` section configures secret providers
declaratively in YAML, replacing programmatic provider setup via
`WithSecretProvider`. Providers are constructed, used for `ref+`
URI resolution during `Load`, and closed automatically — callers
do not manage their lifecycle.

```yaml
secrets:
  timeout: "15s"
  openbao:
    address: "${BAO_ADDR}"
    token: "${BAO_TOKEN}"
    allow_insecure_http: true    # dev-only — NEVER in production
    allow_private_ranges: true   # Docker internal network
  vault:
    address: "${VAULT_ADDR}"
    token: "${VAULT_TOKEN}"
```

### Reserved keys

| Key | Description |
|-----|-------------|
| `timeout` | Secret resolution timeout. Min `1s`, max `120s`. Default: `10s`. `WithSecretTimeout` takes precedence when set programmatically. |

All other keys under `secrets:` are treated as provider scheme names.
Supported providers: `openbao`, `vault`. Unknown keys are rejected
with an actionable error.

### Provider fields

Both `openbao` and `vault` accept the same configuration fields:

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `address` | Yes | — | Server URL. HTTPS required unless `allow_insecure_http` is set. |
| `token` | Yes | — | Authentication token. Use `${ENV_VAR}` — never hardcode. |
| `namespace` | No | `""` | Namespace prefix (sent as `X-Vault-Namespace` header). |
| `tls_ca` | No | `""` | Path to custom CA certificate PEM file. |
| `tls_cert` | No | `""` | Path to client certificate for mTLS. Must be paired with `tls_key`. |
| `tls_key` | No | `""` | Path to client private key for mTLS. Must be paired with `tls_cert`. |
| `tls_policy` | No | TLS 1.3 only | Per-provider TLS policy. Configure inside this provider block only; there is no root-level `tls_policy`. |
| `allow_insecure_http` | No | `false` | Permit `http://` URLs. **MUST NOT be `true` in production.** Plaintext HTTP exposes the authentication token to network observers. Use only for local development with Docker Compose. |
| `allow_private_ranges` | No | `false` | Permit connections to RFC 1918 private addresses and loopback. Required for local development where the provider runs on `127.0.0.1` or a Docker network. Cloud metadata endpoints remain blocked. |

> ⚠️ **Security:** Only environment variable substitution (`${VAR}`)
> is applied in the `secrets:` section — `ref+` secret references are
> NOT resolved (this would be circular since providers must exist
> before secrets can be resolved). Tokens MUST come from environment
> variables.

### Duplicate scheme detection

If the same provider scheme appears in both the YAML `secrets:`
section and a programmatic `WithSecretProvider` call, `Load` returns
an error. Choose one or the other for each provider scheme.

## Output Block

Every output has these fields (plus the optional `hmac:` block):

| Field | Required | Description |
|-------|----------|-------------|
| `type` | Yes | Output type: `"stdout"`, `"file"`, `"syslog"`, `"webhook"`, or `"loki"` |
| `enabled` | No | `true` (default) or `false`. Disabled outputs are skipped. |
| `[type_name]` | Depends | Type-specific config block. Key must match `type`. Not needed for `stdout`. |
| `formatter` | No | Per-output formatter. Defaults to JSON if omitted. |
| `route` | No | Per-output event filter. Receives all events if omitted. |
| `exclude_labels` | No | List of sensitivity labels to strip from events before delivery. |
| `hmac` | No | Per-output HMAC integrity config. See [HMAC Integrity](hmac-integrity.md). |

## Formatter Configuration

```yaml
formatter:
  type: json                       # "json" or "cef"

  # JSON-specific fields:
  timestamp: rfc3339nano           # "rfc3339nano" or "unix_ms"
  omit_empty: false                # skip zero-value fields

  # CEF-specific fields:
  vendor: "MyCompany"              # CEF header: vendor name
  product: "MyApp"                 # CEF header: product name
  version: "1.0"                   # CEF header: product version
  omit_empty: false                # skip zero-value extension fields
```

| Field | Applies To | Default | Description |
|-------|-----------|---------|-------------|
| `type` | Both | `"json"` | Format type |
| `timestamp` | JSON only | `"rfc3339nano"` | Timestamp format: `"rfc3339nano"` or `"unix_ms"` |
| `omit_empty` | Both | `false` | Skip fields with zero values |
| `vendor` | CEF only | — | Required for CEF. Organisation name. |
| `product` | CEF only | — | Required for CEF. Application name. |
| `version` | CEF only | — | Required for CEF. Application version. |

> **Note:** Loki outputs do not support custom formatters — they are
> locked to JSON. Specifying a non-JSON `formatter` on a `type: loki`
> output returns an error at config load time. See
> [Loki Output: Formatter Restriction](loki-output.md#formatter-restriction)
> for details.

## Event Route Configuration

Routes control which events reach an output. Include and exclude
modes are mutually exclusive.

```yaml
route:
  # Include mode — only matching events delivered:
  include_categories: {security: {}}
  include_event_types: [auth_failure]

  # Exclude mode — all events except matching:
  exclude_categories: [read]
  exclude_event_types: [health_check]

  # Severity filtering (can combine with either mode):
  min_severity: 7                  # minimum severity (0-10)
  max_severity: 10                 # maximum severity (0-10)
```

| Field | Description |
|-------|-------------|
| `include_categories` | Only deliver events in these categories |
| `include_event_types` | Only deliver these specific event types |
| `exclude_categories` | Deliver everything except events in these categories |
| `exclude_event_types` | Deliver everything except these specific event types |
| `min_severity` | Minimum severity threshold (0-10 inclusive) |
| `max_severity` | Maximum severity threshold (0-10 inclusive) |

Include and exclude modes are mutually exclusive — setting both on the
same route causes a startup error.

**Severity precedence depends on the match path** — route-level
`min_severity`/`max_severity` apply only to `include_event_types`
matches, exclude-mode routes, and severity-only catch-all routes. For
`include_categories`, the per-category bound inside each category's
mapping value is authoritative; route-level severity is NOT applied
to category matches. See
[Event Routing — Severity Precedence](event-routing.md#severity-precedence)
for the full rule and worked examples.

```yaml
# Per-category severity: only security events at severity >= 8.
# The min_severity is INSIDE the category mapping value, not at
# the route level.
route:
  include_categories:
    security:
      min_severity: 8

# Exclude mode + severity: everything except reads, but only severity 5+.
# Route-level severity DOES apply in exclude mode.
route:
  exclude_categories: [read]
  min_severity: 5

# Severity-only catch-all: no include or exclude lists, route-level
# severity is the only gate (the PagerDuty pattern).
route:
  min_severity: 9
```

See [Event Routing](event-routing.md) for detailed examples and
explanations.

## Sensitivity Label Exclusion

```yaml
exclude_labels:
  - pii                            # strip all PII-labeled fields
  - financial                      # strip all financial-labeled fields
```

Labels are defined in the taxonomy YAML (see [Taxonomy Reference](taxonomy-validation.md#sensitivity-labels)).
Framework fields (`timestamp`, `event_type`, `severity`, `duration_ms`)
are never stripped.

See [Sensitivity Labels](sensitivity-labels.md) for details.

## File Output Fields

| Field | Default | Description |
|-------|---------|-------------|
| `path` | (required) | File path. Supports `${VAR}` substitution. Parent directory must exist. |
| `max_size_mb` | `100` | Rotate when file reaches this size in MB. Maximum: 10,240 (10 GB). |
| `max_backups` | `5` | Number of rotated files to keep. Maximum: 100. |
| `max_age_days` | `30` | Delete rotated files older than this. Maximum: 365. |
| `group_readable` | `false` | When `true`, mode is `0o640` (owner + group read). Default `false` is `0o600` (owner only). World-readable and group-writable modes are unsupported (#436). |
| `compress` | `true` | Gzip compress rotated files. |
| `buffer_size` | `10000` | Internal async buffer capacity. Maximum: 100,000. |

## Syslog Output Fields

| Field | Default | Description |
|-------|---------|-------------|
| `network` | `"tcp"` | Transport: `"tcp"`, `"udp"`, or `"tcp+tls"`. |
| `address` | (required) | Host:port. Supports `${VAR}` substitution. |
| `app_name` | top-level `app_name`, else `"audit"` | RFC 5424 APP-NAME field. Cascades from top-level `app_name` when omitted. See [APP-NAME Cascade](syslog-output.md#app-name-cascade). |
| `facility` | `"local0"` | Syslog facility. Valid: kern, user, mail, daemon, auth, syslog, lpr, news, uucp, cron, authpriv, ftp, local0-local7. |
| `tls_ca` | — | CA certificate path for TLS verification. |
| `tls_cert` | — | Client certificate path for mTLS. |
| `tls_key` | — | Client key path for mTLS. |
| `buffer_size` | `10000` | Internal async buffer capacity. Maximum: 100,000. |
| `max_retries` | `10` | Reconnection attempts before giving up. |
| `tls_policy` | — | TLS version policy (nested object). |
| `tls_policy.allow_tls12` | `false` | Allow TLS 1.2 in addition to TLS 1.3. |
| `tls_policy.allow_weak_ciphers` | `false` | Allow weaker cipher suites when TLS 1.2 is enabled. |

## Webhook Output Fields

| Field | Default | Description |
|-------|---------|-------------|
| `url` | (required) | HTTPS endpoint. Must be `https://` unless `allow_insecure_http` is set. |
| `batch_size` | `100` | Events per HTTP POST (Level 2 flush threshold). Maximum: 10,000. See [Two-Level Buffering](async-delivery.md#two-level-buffering). |
| `buffer_size` | `10000` | Internal async buffer capacity (Level 2). Events dropped when full. Maximum: 1,000,000. See [Two-Level Buffering](async-delivery.md#two-level-buffering). |
| `flush_interval` | `"5s"` | Flush after this duration even if batch is not full. |
| `timeout` | `"10s"` | HTTP request timeout. |
| `max_retries` | `3` | Retry attempts with exponential backoff. Maximum: 20. |
| `headers` | — | Map of custom HTTP headers added to every request. |
| `tls_ca` | — | CA certificate path for TLS verification. |
| `tls_cert` | — | Client certificate path for mTLS. |
| `tls_key` | — | Client key path for mTLS. |
| `tls_policy` | — | TLS version policy (nested object). |
| `tls_policy.allow_tls12` | `false` | Allow TLS 1.2 in addition to TLS 1.3. |
| `tls_policy.allow_weak_ciphers` | `false` | Allow weaker cipher suites when TLS 1.2 is enabled. |
| `allow_insecure_http` | `false` | Allow `http://` URLs. MUST NOT be `true` in production. |
| `allow_private_ranges` | `false` | Allow private/loopback IP ranges. Disables SSRF protection. |

## Loki Output Fields

| Field | Default | Description |
|-------|---------|-------------|
| `url` | (required) | Full Loki push API endpoint. MUST be `https://` unless `allow_insecure_http` is set. Include the path: `/loki/api/v1/push`. |
| `basic_auth.username` | — | HTTP basic auth username. MUST NOT be empty when `basic_auth` is set. MUST NOT be set alongside `bearer_token`. |
| `basic_auth.password` | — | HTTP basic auth password. |
| `bearer_token` | — | Sets `Authorization: Bearer <token>`. MUST NOT be set alongside `basic_auth`. |
| `tenant_id` | — | Sets `X-Scope-OrgID` header for Loki multi-tenancy. |
| `headers` | — | Custom HTTP headers. MUST NOT include `Authorization`, `X-Scope-OrgID`, `Content-Type`, `Content-Encoding`, or `Host`. |
| `labels.static` | — | Constant labels on every stream. Keys MUST match `[a-zA-Z_][a-zA-Z0-9_]*`. Values MUST NOT be empty or contain control characters. |
| `labels.dynamic` | all included | Per-event label toggles. Set to `false` to exclude. Valid keys: `app_name`, `host`, `timezone`, `pid`, `event_type`, `event_category`, `severity`. |
| `gzip` | `true` | Gzip compress push request bodies. Note: YAML key is `gzip`, not `compress`. |
| `batch_size` | `100` | Events per push (Level 2 flush threshold). Maximum: 10,000. See [Two-Level Buffering](async-delivery.md#two-level-buffering). |
| `max_batch_bytes` | `1048576` | Max uncompressed payload bytes (1 MiB). Min: 1,024. Max: 10,485,760 (10 MiB). |
| `flush_interval` | `"5s"` | Time-based flush trigger. Min: `"100ms"`. Max: `"5m"`. |
| `timeout` | `"10s"` | HTTP request timeout. Min: `"1s"`. Max: `"5m"`. |
| `max_retries` | `3` | Retry attempts on 429/5xx with exponential backoff. Max: 20. |
| `buffer_size` | `10000` | Internal async buffer capacity (Level 2). Events dropped when full. Min: 100. Max: 1,000,000. See [Two-Level Buffering](async-delivery.md#two-level-buffering). |
| `tls_ca` | — | CA certificate path for TLS verification. |
| `tls_cert` | — | Client certificate path for mTLS. MUST be set together with `tls_key`. |
| `tls_key` | — | Client key path for mTLS. MUST be set together with `tls_cert`. |
| `tls_policy.allow_tls12` | `false` | Allow TLS 1.2 in addition to TLS 1.3. |
| `tls_policy.allow_weak_ciphers` | `false` | Allow weaker cipher suites when TLS 1.2 is enabled. |
| `allow_insecure_http` | `false` | Allow `http://` URLs. MUST NOT be `true` in production. |
| `allow_private_ranges` | `false` | Allow private/loopback IP ranges. Disables SSRF protection. |

## Environment Variable Substitution

Values support `${VAR}` and `${VAR:-default}` syntax:

```yaml
file:
  path: "${AUDIT_LOG_DIR:-/var/log/audit}/events.log"
syslog:
  address: "${SYSLOG_HOST}:${SYSLOG_PORT:-6514}"
```

Expansion happens after YAML parsing for injection safety — the raw
YAML structure is validated first, then string values are expanded.

## Secret Reference Resolution

Any string value in the YAML can be a `ref+SCHEME://PATH#KEY` URI
that resolves to a plaintext secret from OpenBao or HashiCorp Vault
at startup. Secret resolution runs after environment variable
expansion and before output construction.

```yaml
outputs:
  secure_log:
    type: file
    hmac:
      enabled: true
      salt:
        version: "2026-Q1"
        value: "ref+openbao://secret/data/audit/hmac#salt"
      algorithm: HMAC-SHA-256
    file:
      path: "/var/log/audit/secure.log"
  alerts:
    type: webhook
    webhook:
      url: "https://siem.example.com/audit"
      headers:
        Authorization: "ref+vault://secret/data/siem/creds#authorization_header"
```

To enable resolution, register one or more providers via
`outputconfig.WithSecretProvider`:

```go
import "github.com/axonops/audit/secrets/openbao"

provider, err := openbao.New(&openbao.Config{
    Address: os.Getenv("BAO_ADDR"),
    Token:   os.Getenv("BAO_TOKEN"),
})
if err != nil {
    return fmt.Errorf("openbao provider: %w", err)
}
defer provider.Close()

loaded, err := outputconfig.Load(ctx, yamlData, taxonomy,
    outputconfig.WithCoreMetrics(metrics),
    outputconfig.WithSecretProvider(provider),
)
```

A ref URI MUST be the entire string value of a YAML field — substring
replacement is not supported. After all resolution passes, a
safety-net scan rejects any remaining `ref+` URIs in the
configuration.

Environment variables and refs compose: `${VAR}` expands first, so a
ref path can be driven by an environment variable:

```yaml
value: "ref+openbao://${BAO_SECRET_PATH:-secret/data/audit/hmac}#salt"
```

See [Secret Provider Integration](secrets.md) for URI syntax, provider
setup, caching, security model, and error reference.

## Output Factory Registration

Output types must be registered before `outputconfig.Load` can create
them from YAML. The library exposes two registration paths; both
resolve to the same `OutputFactory` contract, but they target
different scenarios.

### Blank-import (default)

The recommended path for production deployments. Importing the
convenience umbrella package registers every built-in output —
`stdout`, `file`, `syslog`, `webhook`, `loki` — via the
sub-modules' `init()` functions:

```go
import _ "github.com/axonops/audit/outputs"
```

This is the pattern every example in this repository uses.

If you are optimising for binary size and know exactly which output
types your YAML references, import only those sub-modules:

```go
import (
    _ "github.com/axonops/audit/file"
    _ "github.com/axonops/audit/syslog"
)
```

`stdout` is part of the core `github.com/axonops/audit` module, not
a sub-module. Using `type: stdout` without importing the `outputs`
umbrella (or calling
`audit.MustRegisterOutputFactory("stdout", audit.StdoutFactory())`
directly) causes `Load` to return an error — no output is silently
dropped.

Double-registration is safe: `audit.RegisterOutputFactory` overwrites
silently by design, so re-registering the same type name with a
different factory replaces it without error.

### `WithFactory` (per-call override)

The `outputconfig.WithFactory(typeName, factory)` LoadOption
registers a factory for a single `Load`/`New`/`NewWithLoad` call,
without mutating the global registry:

```go
// customFileFactory is your audit.OutputFactory implementation;
// yamlBytes is the YAML config (e.g. read from disk or embed).
result, err := outputconfig.Load(
    ctx, yamlBytes, taxonomy,
    outputconfig.WithFactory("file", customFileFactory),
)
```

Per-call factories take precedence over globally-registered ones.
Multiple `WithFactory` calls for the same type name resolve as
last-wins.

### When to use which

| Scenario | Recommended path |
|----------|------------------|
| Default production setup | Blank-import the `outputs` umbrella. |
| Binary-size optimisation | Blank-import only the sub-modules you reference. |
| Test code that should not depend on a sub-module's `init()` side effects | `WithFactory` — keeps the test hermetic. The test does not import the sub-module, so its `init()` does not register a real factory and cannot leak into other tests sharing the global registry. |
| Custom metrics-aware factory for one output type | Blank-import the rest, override that one type with `WithFactory`. |
| Multiple auditors in one process with different factory bindings | `WithFactory` per call. The global registry stores exactly one factory per type name, so two `RegisterOutputFactory` calls for the same type would have the second overwrite the first; `WithFactory` scopes the binding to one `Load` call so the two auditors do not collide. |
| Output type not provided by any sub-module (consumer-defined) | Either `audit.RegisterOutputFactory` from your own `init()`, or `WithFactory` per call — the test-vs-production trade-off above applies. |
| Test cleanup / un-registration between tests | Neither path supports removal. The global registry is append-only (overwrite-with-different-factory works, but there is no `Unregister`). For per-test isolation, prefer `WithFactory` which scopes naturally to the call and never touches the global registry. |
| Resolution order between `init()` and `WithFactory` | Both are resolved at `Load` time. Blank-import order does not matter as long as every needed factory has been registered by the time `Load` runs. `WithFactory` overrides whatever the global registry holds at that moment. |

The two paths can coexist freely. Blank-import sets up sensible
defaults at process start; `WithFactory` selectively overrides those
defaults for a single call.

See:
- [`audit.RegisterOutputFactory`](https://pkg.go.dev/github.com/axonops/audit#RegisterOutputFactory)
  — the global-registry entry point invoked by sub-module `init()`s.
- [`outputconfig.WithFactory`](https://pkg.go.dev/github.com/axonops/audit/outputconfig#WithFactory)
  — the per-call LoadOption.

## Loading Output Configuration

The simplest way to create an auditor from YAML is the
`outputconfig.New` facade — one call, no manual wiring:

```go
//go:embed taxonomy.yaml
var taxonomyYAML []byte

auditor, err := outputconfig.New(ctx, taxonomyYAML, "outputs.yaml")
if err != nil {
    return fmt.Errorf("audit: %w", err)
}
defer func() { _ = auditor.Close() }()
```

Additional `audit.Option` values can be appended and take
last-wins precedence — useful for overriding `audit.WithMetrics`:

```go
auditor, err := outputconfig.New(ctx, taxonomyYAML, "outputs.yaml",
    audit.WithMetrics(metricsRecorder),
)
```

When the consumer needs `LoadOption` values (secret providers,
core-metrics recorder, per-output metrics factory, custom factory
registrations, diagnostic logger), use `outputconfig.NewWithLoad`:

```go
auditor, err := outputconfig.NewWithLoad(ctx, taxonomyYAML, "outputs.yaml",
    []outputconfig.LoadOption{
        outputconfig.WithCoreMetrics(metrics),
        outputconfig.WithSecretProvider(provider),
    },
    audit.WithMetrics(metrics), // applied last — wins over Load-derived options
)
```

For full control (inspecting parsed outputs before construction,
mixing load options into an auditor the consumer builds manually),
use `outputconfig.Load` directly:

```go
//go:embed outputs.yaml
var outputsYAML []byte

taxonomy, err := audit.ParseTaxonomyYAML(taxonomyYAML)
if err != nil {
    return fmt.Errorf("parse taxonomy: %w", err)
}

loaded, err := outputconfig.Load(ctx, outputsYAML, taxonomy,
    outputconfig.WithCoreMetrics(metrics),
)
if err != nil {
    return fmt.Errorf("audit config: %w", err)
}

opts := []audit.Option{audit.WithTaxonomy(taxonomy)}
opts = append(opts, loaded.Options()...)
auditor, err := audit.New(opts...)
```

## Further Reading

- [Progressive Example: File Output](../examples/03-file-output/) — file-specific configuration
- [Progressive Example: Multi-Output](../examples/09-multi-output/) — multiple outputs in one YAML
- [Progressive Example: Capstone](../examples/20-capstone/) — four outputs with HMAC, CEF, Loki, and PII stripping
- [Outputs](outputs.md) — output types and fan-out architecture
- [Event Routing](event-routing.md) — per-output event filtering
- [Sensitivity Labels](sensitivity-labels.md) — per-output field stripping
- [Secret Provider Integration](secrets.md) — ref+ URI syntax, OpenBao/Vault setup, security model
- [API Reference: outputconfig.Load](https://pkg.go.dev/github.com/axonops/audit/outputconfig#Load)
