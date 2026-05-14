# Grafana Dashboards for the audit Library

Two production-ready dashboards for visualising and monitoring an
audited Go service:

| File | Source | Audience | What it shows |
|---|---|---|---|
| [`audit-events.json`](audit-events.json) | Loki | Security teams, auditors | Audit-event content: who did what, when, to which resource. Per-category counts, top actors, denied-access timeline, sensitive-event filter. |
| [`audit-metrics.json`](audit-metrics.json) | Prometheus | SREs, platform engineers | Audit-pipeline health: events delivered, output errors, buffer drops, validation errors, per-output flush latency. |

Both dashboards are derived from the production-grade
[capstone example](../../examples/20-capstone/grafana/dashboards/)
and are released as artefacts on every tagged release so ops teams
can import them in minutes without replicating the full capstone
demo state.

## Importing into Grafana

### Option 1: UI import

1. Grafana → **Dashboards** → **New** → **Import**.
2. Click **Upload JSON file** and select the dashboard.
3. Pick datasources (Loki for `audit-events`, Prometheus for
   `audit-metrics`).
4. Click **Import**.

### Option 2: Provisioning

Drop the JSON files into your Grafana provisioning directory:

```bash
cp deploy/grafana/audit-events.json  /etc/grafana/provisioning/dashboards/
cp deploy/grafana/audit-metrics.json /etc/grafana/provisioning/dashboards/
```

Configure a provisioning entry pointing at that directory:

```yaml
# /etc/grafana/provisioning/dashboards/audit.yaml
apiVersion: 1
providers:
  - name: audit
    folder: "Audit"
    type: file
    options:
      path: /etc/grafana/provisioning/dashboards
```

Reload Grafana and the dashboards appear under the "Audit" folder.

## Required datasources

| Dashboard | Datasource type | Notes |
|---|---|---|
| `audit-events.json` | Loki | Default datasource name `Loki` (override per Grafana variable). |
| `audit-metrics.json` | Prometheus | Default datasource name `prometheus`. |

If your Grafana names datasources differently, edit the
`"datasource": "..."` keys in the JSON before import — or use
Grafana's variable-substitution UI on first load.

## Required label conventions

The dashboards assume the audit library is configured with the
canonical Prometheus metric names emitted by the
[reference adapter](../../examples/19-prometheus-reference/metrics.go):

| Metric | Labels | Source |
|---|---|---|
| `audit_events_total` | `output`, `status` | `audit.Metrics.RecordDelivery` |
| `audit_output_errors_total` | `output` | `audit.Metrics.RecordOutputError` |
| `audit_buffer_drops_total` | (none) | `audit.Metrics.RecordBufferDrop` |
| `audit_output_drops_total` | `output_type`, `output_name` | per-output `OutputMetrics.RecordDrop` |
| `audit_output_flush_*` | `output_type`, `output_name` | per-output `OutputMetrics.RecordFlush` |
| `audit_output_retries_total` | `output_type`, `output_name`, `attempt` | per-output `OutputMetrics.RecordRetry` |

The Loki dashboard expects:

- A Loki stream tagged `job="<your-app>-audit"` (the capstone uses
  `inventory-demo-audit`; override the dashboard variable if your
  job name differs).
- Indexed labels: `event_category`, `event_type`, `severity`.
  These come for free if you ship audit events through the
  built-in [Loki output](../../docs/loki-output.md) — its
  default labels include all three.

## Dashboard variables

Both dashboards declare standard variables that filter the panels:

| Variable | Used by | Default | Notes |
|---|---|---|---|
| `event_category` | events | `.*` | Set to `security` to scope dashboards to security events. |
| `event_type` | events | `.*` | Single event type drill-down. |
| `severity` | events | `.*` | Numeric range filter. |
| `output` | metrics | all | Per-output drill-down. |

## Updating from a release

Each tagged release re-publishes the dashboards. Track changes via
the [CHANGELOG](../../CHANGELOG.md). The dashboards follow the
library version — re-import after major upgrades to pick up new
panels (the JSON is idempotent; existing dashboard customisations
are lost on re-import unless you maintain a fork).

## See also

- [Example 17 — Capstone](../../examples/20-capstone/) — full
  end-to-end demo with Postgres, Loki, OpenBao, and Grafana
  pre-wired.
- [Example 20 — Prometheus Reference](../../examples/19-prometheus-reference/)
  — the canonical Prometheus metrics adapter the metrics
  dashboard expects.
- [Metrics & Monitoring](../../docs/metrics-monitoring.md) — full
  metric reference, label cardinality guidance, and the event
  accounting equation.
- [Loki Output](../../docs/loki-output.md) — the audit library's
  Loki delivery, including default stream labels.
