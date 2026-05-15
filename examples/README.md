[&larr; Back to project README](../README.md)

# audit Examples

Progressive examples from "hello world" to a complete CRUD REST API.
Each example introduces one new concept and builds on the previous.

## Reading Paths

The examples are numbered to follow a single conceptual gradient
from "hello world" to the capstone REST API. The numeric order
groups into seven phases — pick the phase that matches your goal
and read in order within it.

- **Hello — first contact (~10 minutes)** → [01-basic](01-basic/),
  [02-code-generation](02-code-generation/),
  [03-file-output](03-file-output/). Audit your first event
  programmatically, add typed builders via the YAML taxonomy +
  `go generate` flow, then learn the first real output.
- **Core mechanics** → [04-formatters](04-formatters/),
  [05-standard-fields](05-standard-fields/). Pick a wire format
  (JSON vs CEF) and learn the framework-field vocabulary every
  later example uses.
- **Outputs** → [06-syslog-output](06-syslog-output/),
  [07-webhook-output](07-webhook-output/),
  [08-loki-output](08-loki-output/). Each output type's setup,
  failure modes, and configuration.
- **Multi-output and production patterns** →
  [09-multi-output](09-multi-output/),
  [10-event-routing](10-event-routing/),
  [11-sensitivity-labels](11-sensitivity-labels/),
  [12-hmac-integrity](12-hmac-integrity/),
  [13-tls-policy](13-tls-policy/), [14-buffering](14-buffering/).
  Fan-out to multiple outputs, per-output routing, PII stripping,
  tamper detection, TLS hardening, queue tuning.
- **Integration and operational** →
  [15-middleware](15-middleware/),
  [16-health-endpoint](16-health-endpoint/),
  [17-testing](17-testing/). Automatic HTTP audit logging,
  `/healthz` and `/readyz` driven by Auditor introspection,
  assertion patterns for tests.
- **Adoption and reference** →
  [18-migration](18-migration/),
  [19-prometheus-reference](19-prometheus-reference/).
  `log/slog` coexistence pattern, drop-in Prometheus metrics
  adapter.
- **Capstone** → [20-capstone](20-capstone/). Complete inventory
  REST API composing every prior concept — web UI, Postgres, four
  outputs, Grafana dashboards, Prometheus metrics, OpenBao
  secrets.

## Examples

| # | Example | What it teaches |
|---|---------|-----------------|
| 1 | [basic](01-basic/) | Taxonomy, Auditor, AuditEvent(), Fields, validation — programmatic setup |
| 2 | [code-generation](02-code-generation/) | YAML taxonomy, audit-gen, typed builders, go:embed, outputconfig.Load |
| 3 | [file-output](03-file-output/) | File output with rotation and permissions in YAML |
| 4 | [formatters](04-formatters/) | JSON vs CEF with category severity levels |
| 5 | [standard-fields](05-standard-fields/) | Reserved standard fields, framework fields, standard_fields YAML defaults |
| 6 | [syslog-output](06-syslog-output/) | Syslog output with RFC 5424, TCP/UDP/TLS, facility values |
| 7 | [webhook-output](07-webhook-output/) | Webhook output with NDJSON batching, retry, SSRF protection |
| 8 | [loki-output](08-loki-output/) | Loki output with stream labels, batching, gzip, LogQL queries |
| 9 | [multi-output](09-multi-output/) | Fan-out to multiple outputs from one YAML config |
| 10 | [event-routing](10-event-routing/) | Category and severity-based routing in YAML |
| 11 | [sensitivity-labels](11-sensitivity-labels/) | Per-output field stripping with PII and financial labels |
| 12 | [hmac-integrity](12-hmac-integrity/) | Per-output HMAC tamper detection — selective vs global |
| 13 | [tls-policy](13-tls-policy/) | Global and per-output TLS policy configuration |
| 14 | [buffering](14-buffering/) | Two-level buffering, ErrQueueFull, per-output drops, tuning |
| 15 | [middleware](15-middleware/) | Automatic HTTP audit logging with Hints |
| 16 | [health-endpoint](16-health-endpoint/) | `/healthz` and `/readyz` HTTP handlers driven by Auditor introspection |
| 17 | [testing](17-testing/) | Testing audit events with audittest.New |
| 18 | [migration](18-migration/) | Coexistence pattern — `log/slog` and the audit library running side-by-side in an HTTP service |
| 19 | [prometheus-reference](19-prometheus-reference/) | Drop-in `audit.Metrics` + `audit.OutputMetricsFactory` adapter for Prometheus, with `/metrics` HTTP handler |
| 20 | [capstone](20-capstone/) | Complete inventory demo with web UI, Postgres, four outputs, Grafana, Prometheus |

The **basic** example uses the programmatic API to show how the library
works. Every example after that uses YAML files for configuration —
that's how you'd use audit in a real application.

### Buffering and Performance

Examples 7 (webhook) and 8 (Loki) use outputs with internal buffers
and batching. Examples 3 (file) and 6 (syslog) use synchronous outputs
that write directly from the drain goroutine. Example 9 (multi-output)
demonstrates both synchronous and async outputs in a single
configuration — the most direct illustration of the two-level buffering
model. See [Two-Level Buffering](../docs/async-delivery.md#two-level-buffering)
for the architecture explanation, memory sizing, and tuning guidance.

## Getting Started

From a fresh clone:

```bash
# Set up the Go workspace (required for multi-module resolution):
make workspace

# Build all examples to verify they compile:
make test-examples

# Run an individual example:
cd examples/01-basic && go run .
```

## For Consumers Outside the Workspace

If you copy an example to your own project, you'll need to initialise
a Go module and fetch the dependencies:

```bash
go mod init myapp

# Core library + output config loader:
go get github.com/axonops/audit
go get github.com/axonops/audit/outputconfig

# Output types you use (blank imports register them):
go get github.com/axonops/audit/file
go get github.com/axonops/audit/syslog
go get github.com/axonops/audit/webhook
go get github.com/axonops/audit/loki

# Capstone (inventory demo) also needs:
go get github.com/lib/pq
go get github.com/prometheus/client_golang
```
