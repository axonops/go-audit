[← Back to examples](../README.md)

> **Previous:** [18 — Migration](../18-migration/) |
> **Next:** [20 — Capstone](../20-capstone/)

---

# Example 19: Prometheus Reference Implementation

This is the **drop-in Prometheus adapter** for the audit library.
Copy [`metrics.go`](metrics.go) into your own project to wire
audit pipeline metrics into a Prometheus registry.

The companion [`main.go`](main.go) is a minimal demo that:

- Registers all `audit_*` Prometheus counters via `promauto`
- Constructs an auditor with the adapter wired into both
  `audit.Metrics` (pipeline-wide) and `audit.OutputMetricsFactory`
  (per-output)
- Emits a successful event and a validation failure
- Exposes `/metrics` on `:2112`

For a production-grade end-to-end example with Postgres, Loki,
HMAC, and Grafana dashboards, see [Example 17 — Capstone](../20-capstone/).

## What metrics you get

**Pipeline-wide** (from `audit.Metrics`):

| Metric | Type | Labels |
|---|---|---|
| `audit_events_total` | Counter | `output`, `status` |
| `audit_output_errors_total` | Counter | `output` |
| `audit_output_filtered_total` | Counter | `output` |
| `audit_validation_errors_total` | Counter | `event_type` |
| `audit_filtered_total` | Counter | `event_type` |
| `audit_serialization_errors_total` | Counter | `event_type` |
| `audit_buffer_drops_total` | Counter | (none) |

**Per-output** (from `audit.OutputMetricsFactory`):

| Metric | Type | Labels |
|---|---|---|
| `audit_output_drops_total` | Counter | `output_type`, `output_name` |
| `audit_output_flush_batch_size` | Histogram | `output_type`, `output_name` |
| `audit_output_flush_duration_seconds` | Histogram | `output_type`, `output_name` |
| `audit_output_retries_total` | Counter | `output_type`, `output_name`, `attempt` |
| `audit_output_errors_by_output_total` | Counter | `output_type`, `output_name` |

`RecordSubmitted` and `RecordQueueDepth` are inherited no-ops from
`audit.NoOpMetrics` — wire them up in `metrics.go` if your
dashboard needs submission and queue-depth telemetry.

## Forward-compatibility

Both `auditMetrics` and `perOutputMetrics` embed the library's
`NoOpMetrics` / `NoOpOutputMetrics` types, so any new method added
to `audit.Metrics` or `audit.OutputMetrics` in a future release
defaults to a no-op. Your build does not break; you opt in to
instrumenting the new method when convenient. See ADR 0005 in the
project root for the full forward-compatibility policy.

## Running

```bash
cd examples/19-prometheus-reference
go generate ./...   # regenerate audit_generated.go from taxonomy.yaml
go run .
```

In another shell:

```bash
curl -s http://localhost:2112/metrics | grep audit_
```

You'll see the eight `audit_*` counters tick on the two emitted
events. Press Ctrl+C in the demo to exit.

## See also

- [`docs/metrics-monitoring.md`](../../docs/metrics-monitoring.md) — full Metrics interface contract, accounting equation, cardinality guidance
- [Example 17 — Capstone](../20-capstone/) — production-grade integration with Postgres, Loki, HMAC, and Grafana dashboards
- [pkg.go.dev: `audit.Metrics`](https://pkg.go.dev/github.com/axonops/audit#Metrics) — interface godoc
