[&larr; Back to project README](../README.md)

# audit Examples

Progressive examples from "hello world" to a complete CRUD REST API.
Each example introduces one new concept and builds on the previous.

## Start Here — Reading Paths

The full list is below in numeric order, but most readers want one
of these paths through the set. Pick the one that matches your
goal:

- **First contact (~10 minutes)** → [01-basic](01-basic/),
  [02-code-generation](02-code-generation/). Audit your first
  event programmatically, then add typed builders via the YAML
  taxonomy + `go generate` flow.
- **Core mechanics** → [03-file-output](03-file-output/),
  [04-testing](04-testing/), [05-formatters](05-formatters/),
  [06-middleware](06-middleware/). Wiring outputs, asserting
  delivery in tests, picking a wire format, automatic HTTP
  request auditing.
- **Wire an output** → [07-syslog-output](07-syslog-output/),
  [08-webhook-output](08-webhook-output/),
  [09-multi-output](09-multi-output/),
  [14-loki-output](14-loki-output/). Each output type's setup,
  failure modes, and configuration.
- **Production patterns** → [10-event-routing](10-event-routing/),
  [11-sensitivity-labels](11-sensitivity-labels/),
  [12-hmac-integrity](12-hmac-integrity/),
  [13-standard-fields](13-standard-fields/),
  [15-tls-policy](15-tls-policy/), [16-buffering](16-buffering/).
  Per-output routing, PII stripping, tamper detection, fleet
  metadata, TLS hardening, queue tuning.
- **Capstone & advanced** → [17-capstone](17-capstone/),
  [18-health-endpoint](18-health-endpoint/),
  [19-migration](19-migration/),
  [20-prometheus-reference](20-prometheus-reference/). Full
  inventory demo, kubelet health probes, `log/slog`
  coexistence, Prometheus metrics surface.

## Examples

| # | Example | What it teaches |
|---|---------|-----------------|
| 1 | [basic](01-basic/) | Taxonomy, Auditor, AuditEvent(), Fields, validation — programmatic setup |
| 2 | [code-generation](02-code-generation/) | YAML taxonomy, audit-gen, typed builders, go:embed, outputconfig.Load |
| 3 | [file-output](03-file-output/) | File output with rotation and permissions in YAML |
| 4 | [testing](04-testing/) | Testing audit events with audittest.New |
| 5 | [formatters](05-formatters/) | JSON vs CEF with category severity levels |
| 6 | [middleware](06-middleware/) | Automatic HTTP audit logging with Hints |
| 7 | [syslog-output](07-syslog-output/) | Syslog output with RFC 5424, TCP/UDP/TLS, facility values |
| 8 | [webhook-output](08-webhook-output/) | Webhook output with NDJSON batching, retry, SSRF protection |
| 9 | [multi-output](09-multi-output/) | Fan-out to multiple outputs from one YAML config |
| 10 | [event-routing](10-event-routing/) | Category and severity-based routing in YAML |
| 11 | [sensitivity-labels](11-sensitivity-labels/) | Per-output field stripping with PII and financial labels |
| 12 | [hmac-integrity](12-hmac-integrity/) | Per-output HMAC tamper detection — selective vs global |
| 13 | [standard-fields](13-standard-fields/) | Reserved standard fields, framework fields, standard_fields YAML defaults |
| 14 | [loki-output](14-loki-output/) | Loki output with stream labels, batching, gzip, LogQL queries |
| 15 | [tls-policy](15-tls-policy/) | Global and per-output TLS policy configuration |
| 16 | [buffering](16-buffering/) | Two-level buffering, ErrQueueFull, per-output drops, tuning |
| 17 | [capstone](17-capstone/) | Complete inventory demo with web UI, Postgres, four outputs, Grafana |
| 18 | [health-endpoint](18-health-endpoint/) | `/healthz` and `/readyz` HTTP handlers driven by Auditor introspection |
| 19 | [migration](19-migration/) | Coexistence pattern — `log/slog` and the audit library running side-by-side in an HTTP service |
| 20 | [prometheus-reference](20-prometheus-reference/) | Drop-in `audit.Metrics` + `audit.OutputMetricsFactory` adapter for Prometheus, with `/metrics` HTTP handler |

The **basic** example uses the programmatic API to show how the library
works. Every example after that uses YAML files for configuration —
that's how you'd use audit in a real application.

### Buffering and Performance

Examples 8 (webhook) and 14 (Loki) use outputs with internal buffers
and batching. Examples 3 (file) and 7 (syslog) use synchronous outputs
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
