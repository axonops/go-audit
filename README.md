<div align="center">
  <img src=".github/images/logo-readme.png" alt="audit" width="128">

  # audit

  **Structured, Schema-Enforced Audit Logging for Go Services**

  [![CI](https://github.com/axonops/audit/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/axonops/audit/actions/workflows/ci.yml)
  [![Go Reference](https://pkg.go.dev/badge/github.com/axonops/audit.svg)](https://pkg.go.dev/github.com/axonops/audit)
  [![Go Report Card](https://goreportcard.com/badge/github.com/axonops/audit)](https://goreportcard.com/report/github.com/axonops/audit)
  [![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/axonops/audit/badge)](https://securityscorecards.dev/viewer/?uri=github.com/axonops/audit)
  [![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
  ![Status](https://img.shields.io/badge/status-pre--release-orange)

  [🚀 Quick Start](#quick-start) | [✨ Features](#key-features) | [📚 Examples](examples/) | [📖 API Reference](https://pkg.go.dev/github.com/axonops/audit)
</div>

---
## ⚠️ Status

This library is **pre-release (v0.x)**. The API may change between
minor versions until v1.0.0. Pin your dependency version.

---

## 🔍 Overview

audit logs **who did what, when, and to which resource** — for
compliance, forensics, and accountability. Unlike `log/slog` or `zap`,
audit events are schema-enforced: a code generator turns your YAML
taxonomy into typed Go builders, so missing required fields and
typo'd event names are compile errors. Output destinations (file,
syslog, webhook, Loki) are configured separately at runtime; the
bundled `audittest` package gives in-memory event capture for unit
tests with the same validation path as production.

---

## 💡 Why audit?

- 📋 **Schema enforcement** — every event validated against your taxonomy; missing required fields rejected at compile time
- 🛡️ **SIEM-native output** — [CEF](docs/cef-format.md) understood by Splunk, ArcSight, QRadar; [JSON](docs/json-format.md) for log aggregators
- 📡 **Multi-output fan-out** — [files, syslog, webhooks, Loki, stdout](docs/outputs.md) simultaneously, each with its own formatter and filters
- 🔒 **Sensitive field stripping** — [classify fields as PII/financial](docs/sensitivity-labels.md); strip per-output for GDPR/PCI compliance
- ⚡ **Non-blocking** — sub-microsecond `AuditEvent()`; [async delivery](docs/async-delivery.md) with completeness monitoring
- 🧪 **Production-grade testing** — [`audittest`](docs/testing.md) recorder shares the production validation path — no mock drift

---

## 🚀 Quick Start

YAML-first: define events in a taxonomy, configure outputs, generate type-safe Go code.

### 1️⃣ Define your taxonomy (`taxonomy.yaml`)

```yaml
version: 1
categories:
  write:
    severity: 3
    events: [user_create]
events:
  user_create:
    description: "A new user account was created"
    fields:
      outcome:  { required: true }
      actor_id: { required: true }
```

### 2️⃣ Configure outputs (`outputs.yaml`)

```yaml
version: 1
app_name: my-service
host: "${HOSTNAME:-localhost}"
outputs:
  console:
    type: stdout
```

### 3️⃣ Generate type-safe code

```bash
go run github.com/axonops/audit/cmd/audit-gen \
  -input taxonomy.yaml -output audit_generated.go -package main
```

### 4️⃣ Wire it up and emit events (`main.go`)

```go
package main

import (
    "context"
    _ "embed"
    "log"

    "github.com/axonops/audit/outputconfig"
    _ "github.com/axonops/audit/outputs"
)

//go:embed taxonomy.yaml
var taxonomyYAML []byte

func main() {
    auditor, err := outputconfig.New(context.Background(), taxonomyYAML, "outputs.yaml")
    if err != nil {
        log.Fatal(err)
    }
    defer func() { _ = auditor.Close() }()

    if err := auditor.AuditEvent(
        NewUserCreateEvent("alice", "success").SetTargetID("user-42"),
    ); err != nil {
        log.Printf("audit: %v", err)
    }
}
```

`go run .` prints one JSON event to stdout — see [Output](#output) below for the wire format and [examples/02-code-generation/](examples/02-code-generation/) for the full project.

### 5️⃣ Test your audited code (`main_test.go`)

```go
package main

import (
    "testing"

    "github.com/axonops/audit/audittest"
)

func TestCreateUser_EmitsAudit(t *testing.T) {
    auditor, events, _ := audittest.NewQuick(t, "user_create")
    _ = auditor.AuditEvent(NewUserCreateEvent("alice", "success"))
    events.RequireEvent(t, "user_create")
}
```

`audittest.NewQuick` shares the production validation path — full reference at [docs/testing.md](docs/testing.md) and [examples/04-testing/](examples/04-testing/).

### Output

`go run .` prints one JSON event to stdout (default formatter):

```json
{"timestamp":"...","event_type":"user_create","severity":3,"app_name":"my-service","host":"<your-host>","timezone":"UTC","pid":12345,"actor_id":"alice","outcome":"success","target_id":"user-42","event_category":"write"}
```

> 📐 **Field order is deterministic** — framework fields first, then required and optional fields (alphabetical), then extra fields, then `event_category`. See [JSON format → Field Order](docs/json-format.md#field-order).

> 💡 `app_name` and `host` are **framework fields** set once in `outputs.yaml`; `pid` is auto-captured from `os.Getpid()`. For SIEM-native [CEF output](docs/cef-format.md), add a `formatter: { type: cef, vendor: …, product: … }` block to your output — Splunk, ArcSight, and QRadar parse it natively.

---

## ✨ Key Features

<div align="center">

| Feature | Description | Docs |
|---------|-------------|------|
| 📋 **Taxonomy Validation** | Define event schemas in YAML; every event validated at runtime | [Learn more](docs/taxonomy-validation.md) |
| ⚙️ **Code Generation** | `audit-gen` generates typed builders; typos become compile errors | [Learn more](docs/code-generation.md) |
| ✅ **Pre-deploy Validator** | `audit-validate` validates `outputs.yaml` in CI; distinct exit codes per failure class | [Learn more](docs/validation.md) |
| 🛡️ **CEF Format** | Common Event Format for SIEM platforms (Splunk, ArcSight, QRadar) | [Learn more](docs/cef-format.md) |
| 📄 **JSON Format** | Line-delimited JSON with deterministic field order | [Learn more](docs/json-format.md) |
| 📡 **5 Output Types** | File (rotation), syslog (RFC 5424), webhook (NDJSON), Loki (stream labels), stdout — fan-out to all simultaneously | [Learn more](docs/outputs.md) |
| 🔀 **Event Routing** | Route events by category or severity to specific outputs | [Learn more](docs/event-routing.md) |
| 🔒 **Sensitivity Labels** | Classify fields as PII/financial; strip per-output for compliance | [Learn more](docs/sensitivity-labels.md) |
| ⚡ **Async Delivery** | Sub-microsecond enqueue; background drain goroutine | [Learn more](docs/async-delivery.md) |
| 🌐 **HTTP Middleware** | Automatically captures HTTP request fields for audit logging | [Learn more](docs/http-middleware.md) |
| 📊 **Metrics & Monitoring** | Track dropped events, delivery errors, and output health | [Learn more](docs/metrics-monitoring.md) |
| 📝 **YAML Configuration** | Configure outputs in YAML with environment variable substitution | [Learn more](docs/output-configuration.md) |
| 🔐 **HMAC Integrity** | Per-output tamper detection with NIST-approved algorithms | [Learn more](docs/hmac-integrity.md) |
| 🧪 **Testing Support** | In-memory recorder with same validation as production | [Learn more](docs/testing.md) |

</div>

---

## ❓ Audit logging vs application logging

If you're wondering whether audit logging differs from application
logging, here's the comparison:

| | 🔧 Application Logging | 📋 Audit Logging |
|---|---|---|
| **Purpose** | Debugging, troubleshooting, observability | Compliance, forensics, accountability |
| **Audience** | Developers, SREs | Security teams, auditors, legal |
| **Guarantees** | Best-effort — missing a log line is fine | Schema-enforced — missing a field is a compliance gap |
| **Retention** | Days to weeks | Months to years (regulatory requirements) |
| **Content** | Technical details (errors, stack traces) | Who did what, when, to which resource, and why |
| **Destinations** | Log aggregator (OpenSearch, Datadog, Loki) | SIEM (Splunk, ArcSight, QRadar), compliance archives |

If your application handles user data, financial transactions,
authentication, or access control, regulations like SOX, HIPAA, GDPR,
and PCI-DSS require audit trails. Application loggers (`log/slog`,
`zap`, `zerolog`) do not enforce the structure, completeness, or
delivery guarantees that compliance demands.

---

## 🌐 Building an HTTP service?

Skip ahead to the [HTTP Service Quickstart](docs/quickstart-http-service.md) — a self-contained ~10-minute walkthrough from `go get` to an audited POST endpoint with stdout output, no clicking through other docs.

---

## 📦 Installation

Requires **Go 1.26+**.

```bash
go get github.com/axonops/audit             # core: auditor, taxonomy, validation, formatters, stdout output
go get github.com/axonops/audit/file         # file output with rotation
go get github.com/axonops/audit/syslog       # RFC 5424 syslog (TCP/UDP/TLS/mTLS)
go get github.com/axonops/audit/webhook      # batched HTTP webhook with SSRF protection
go get github.com/axonops/audit/loki         # Grafana Loki with stream labels and gzip
go get github.com/axonops/audit/outputconfig # YAML-based output configuration
```

> 💡 The core module includes `StdoutOutput` (no additional dependency)
> and the `audittest` package for [testing](docs/testing.md).

> 🚀 On Unix the file output uses `writev(2)` via the
> [iouring][iouring] submodule to collapse batched events into a
> single syscall — measured faster than `io_uring` at every batch
> size for our submit-and-wait pattern (see [ADR 0002][adr-0002]).
> On Windows it falls back transparently to buffered writes.
> No configuration needed. The `io_uring` primitive ships in the
> submodule and is available for post-v1.0 async workloads (WAL,
> O_DIRECT) that genuinely benefit.

[iouring]: https://pkg.go.dev/github.com/axonops/audit/iouring
[adr-0002]: docs/adr/0002-file-output-io-uring-approach.md

---

## 🏗️ Module Structure

| Module | Description |
|--------|-------------|
| `github.com/axonops/audit` | Core: Auditor, taxonomy validation, JSON + CEF formatters, HTTP middleware, stdout output, fan-out, routing, `audittest` |
| `github.com/axonops/audit/file` | File output with size-based rotation and gzip compression |
| `github.com/axonops/audit/syslog` | RFC 5424 syslog output (TCP/UDP/TLS/mTLS) |
| `github.com/axonops/audit/webhook` | Batched HTTP webhook with retry and SSRF protection |
| `github.com/axonops/audit/loki` | Grafana Loki output with stream labels, gzip, multi-tenancy |
| `github.com/axonops/audit/outputconfig` | YAML-based output configuration with env var substitution |
| `github.com/axonops/audit/outputs` | **Recommended default** — single blank import registers all output factories |
| `github.com/axonops/audit/secrets` | Secret provider interface for `ref+` URI resolution in YAML config |
| `github.com/axonops/audit/secrets/openbao` | OpenBao KV v2 secret provider |
| `github.com/axonops/audit/secrets/vault` | HashiCorp Vault KV v2 secret provider |
| `github.com/axonops/audit/cmd/audit-gen` | Code generator: YAML taxonomy to typed Go builders |

Outputs are isolated in separate modules so the core library carries
minimal third-party dependencies. The default path is the
convenience package — one blank import registers every built-in
output:

```go
import _ "github.com/axonops/audit/outputs"
```

Production services typically import only the outputs they use —
shaving a few MB of transitive dependencies (`goccy/go-yaml`,
`srslog`, HTTP stacks) per unused output — and the convenience
package is ideal for demos, examples, and apps that use most output
types:

```go
import _ "github.com/axonops/audit/file"   // only if you use type: file
import _ "github.com/axonops/audit/syslog" // only if you use type: syslog
```

---

## 🧪 Testing

The `audittest` package provides an in-memory recorder for testing audit events:

```go
func TestUserCreation(t *testing.T) {
    auditor, events, _ := audittest.NewQuick(t, "user_create")

    // Exercise the code under test...
    err := auditor.AuditEvent(audit.MustNewEventKV("user_create",
        "outcome", "success", "actor_id", "alice"))
    require.NoError(t, err)

    // Assert immediately — NewQuick uses synchronous delivery.
    assert.Equal(t, 1, events.Count())
    assert.Equal(t, "alice", events.Events()[0].StringField("actor_id"))
}
```

See [Example 4](examples/04-testing/) and [Testing docs](docs/testing.md) for more.

---

## 📋 Reserved Standard Fields

Fields like `target_id`, `source_ip`, and `reason` are **reserved
standard fields** — 31 framework-defined fields (`actor_id`,
`outcome`, `target_id`, `source_ip`, `reason`, `request_id`,
`session_id`, `role`, `dest_port`, `start_time`, …) that are always
available on every event without declaration in YAML. Generated
builders expose them as typed setters:
`.SetTargetID(string)`, `.SetSourceIP(string)`, `.SetReason(string)`,
`.SetDestPort(int)`, `.SetStartTime(time.Time)`, etc. The library
rejects taxonomies that re-declare a reserved name. See
[`docs/reserved-standard-fields.md`](docs/reserved-standard-fields.md)
for the full table of 31 names, types, and CEF mappings.

---

## 📚 Documentation

| Resource | Description |
|----------|-------------|
| 📖 [Progressive Examples](examples/) | 20 examples from "hello world" to a [complete inventory demo](examples/17-capstone/), an [/healthz endpoint](examples/18-health-endpoint/), a [slog-coexistence migration demo](examples/19-migration/), and a [drop-in Prometheus reference adapter](examples/20-prometheus-reference/) — every output type, TLS policy, routing, formatters, testing, and buffering |
| 📘 [API Reference](https://pkg.go.dev/github.com/axonops/audit) | pkg.go.dev documentation |
| 🏗️ [Architecture](ARCHITECTURE.md) | Pipeline design, module boundaries, thread safety |
| 🤝 [Contributing](CONTRIBUTING.md) | Development setup, PR process, code standards |
| 🛠 [Development Workflow](docs/development-workflow.md) | Multi-module monorepo workflow — `make workspace`, `go.work`, release-flow implications, build/workspace troubleshooting |
| 🚀 [Deployment Guide](docs/deployment.md) | systemd, Kubernetes, Docker Compose; capacity planning; file-output parent-directory behaviour; secret injection patterns |
| 📝 [Changelog](CHANGELOG.md) | Release history and breaking changes |
| ❌ [Error Reference](docs/error-reference.md) | Every error explained with recovery guidance |
| 🔧 [Troubleshooting](docs/troubleshooting.md) | Common problems and how to fix them |
| 🔒 [Security Policy](SECURITY.md) | Vulnerability reporting |
| ⚡ [Benchmarks](BENCHMARKS.md) | Performance baseline, methodology, and side-by-side comparison against [`log/slog`](BENCHMARKS.md#comparison-against-logslog) |
| 🎮 [Playground note](docs/playground.md) | Why audit examples don't run on play.golang.org, and where to run them instead |

---

## 🙏 Acknowledgements

audit builds on excellent open-source projects. See
[ACKNOWLEDGEMENTS.md](ACKNOWLEDGEMENTS.md) for full attribution and
license details.

- [github.com/goccy/go-yaml](https://github.com/goccy/go-yaml) — YAML parsing (MIT)
- [github.com/axonops/srslog](https://github.com/axonops/srslog) — RFC 5424 syslog (BSD-3-Clause)
- [github.com/axonops/syncmap](https://github.com/axonops/syncmap) — Generic sync.Map (Apache-2.0), fork of [rgooding/go-syncmap](https://github.com/rgooding/go-syncmap)

---

## 📄 License

[Apache License 2.0](LICENSE) — Copyright 2026 AxonOps Limited.

---

<div align="center">
  <sub>Made with ❤️ by <a href="https://axonops.com">AxonOps</a></sub>
</div>
