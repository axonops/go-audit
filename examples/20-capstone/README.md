[← Back to examples](../README.md)

> **Previous:** [19 — Prometheus Reference](../19-prometheus-reference/)
# Example 20: Inventory Demo (Capstone)

A complete inventory management application with a web UI, Postgres
database, four simultaneous audit outputs, Grafana dashboards, and
Prometheus metrics. **One command starts everything.**

This is the capstone example — it ties together every audit feature
from the previous 16 examples into a realistic application that you
can explore immediately.

## Quick Start

```bash
docker compose up -d
```

Then open:

- **http://localhost:8080** — Web UI (inventory management)
- **http://localhost:3000/d/audit-events/** — Audit events dashboard (Loki)
- **http://localhost:3000/d/audit-metrics/** — Pipeline health dashboard (Prometheus)
- **http://localhost:8200** — OpenBao UI (token: `demo-root-token`)
- **http://localhost:9090** — Prometheus UI (direct query access)

That's it. Docker Compose builds the app from source, starts Postgres,
OpenBao, Loki, Prometheus, and Grafana, and wires them together. HMAC
salts are generated and stored in OpenBao at startup — no secrets in
config files. All links are also available in the web UI nav bar.

## Three Types of Observability

This demo produces three distinct outputs. They serve different
audiences and answer different questions:

| | Application Logs | Audit Events | Audit Metrics |
|---|---|---|---|
| **Question** | What did the server do? | What did the user do? | Is the audit pipeline healthy? |
| **Audience** | On-call engineer | Compliance officer, security analyst | Platform engineer, SRE |
| **Format** | Unstructured slog output | Schema-validated JSON/CEF | Prometheus counters |
| **Destination** | `docker compose logs app` | Loki → Grafana, audit.log, security.log | Prometheus → Grafana |
| **Example** | "listening on :8080" | "alice created user bob@example.com" | "328 events delivered, 0 drops" |

The audit library provides **Audit Events** (type 2). **Audit Metrics**
(type 3) tell you whether the event pipeline is working. If buffer
drops > 0, you're losing audit events and your compliance is at risk.

## Walkthrough

### 1. Log in

Open http://localhost:8080. Default credentials: **alice / password**.

The login generates an `auth_success` audit event. Try wrong
credentials first to generate an `auth_failure` event — you'll see
it in Grafana moments later.

### 2. Create some data

- **Users tab** — create a user with an email address (this is PII —
  watch how it appears differently on each output)
- **Items tab** — create a few inventory items
- **Orders tab** — create an order linking a user to an item

Every action generates audit events: `user_create`, `item_create`,
`order_create`, etc. These flow to all four outputs simultaneously.

### 3. See audit events and metrics in Grafana

Open http://localhost:3000/d/audit-events/ — the **Audit Events**
dashboard shows WHAT happened (event stream from Loki). You'll see:

- **Events over time** — line chart showing audit activity
- **Events by category** — pie chart (read, write, security, compliance)
- **Events by severity** — bar gauge showing severity distribution
- **Auth failures** — counter for failed authentication attempts
- **Top event types** — which events fire most often
- **Recent events** — live log stream of audit events

Use the **event_category**, **event_type**, and **severity** dropdowns
at the top to filter. The PII stripping panel shows `user_create`
events with email/phone absent — compare with `docker compose logs app`
where the same events have full PII.

Now open http://localhost:3000/d/audit-metrics/ — the **Pipeline
Metrics** dashboard shows WHETHER it's working (Prometheus counters):

- **Health row** — Events Delivered (green), Errors/Drops/Validation (red if > 0)
- **Throughput** — events/sec per output (4 lines = fan-out in action)
- **Filtered events** — proves routing is working (security_feed filters heavily)
- **Loki health** — flush latency, batch sizes, retries, drops
- **File rotations** — tracks log file rotation events

### 4. Trigger security events

- **Wrong credentials** — login with a bad password to generate
  `auth_failure` (severity 9, routed to security.log)
- **Rate limiting** — make 6 rapid failed login attempts to trigger
  `rate_limit_exceeded` (severity 8)
- **Bulk operations** — use the Admin tab's "Bulk Delete" to trigger
  `bulk_delete` (compliance category)

### 5. Inspect the four outputs

Every audit event goes to four outputs simultaneously, each showing
different audit features:

```bash
# stdout — JSON with full PII (visible in container logs)
docker compose logs app | grep event_type

# compliance archive — CEF format with HMAC v1 (SHA-256)
docker compose exec app cat /data/audit.log

# security feed — JSON, severity >= 7 only, HMAC v2 (SHA-512)
docker compose exec app cat /data/security.log

# Loki — JSON with PII stripped (visible in Grafana)
# open http://localhost:3000
```

Notice how the **same event** looks different in each output:
- A `user_create` with an email field appears in **stdout** with the
  full email, in **audit.log** in CEF format with an HMAC signature,
  is **absent** from **security.log** (wrong category — severity 5 < 7),
  and appears in **Loki** with the email field stripped (PII label).

### 6. Understand the metrics pipeline

The Pipeline Metrics dashboard at http://localhost:3000/d/audit-metrics/
shows counters from the `audit.Metrics` interface and per-output
metrics (`file.Metrics`, `audit.OutputMetrics`). All metrics are auto-detected
from a single struct in `metrics.go` via structural typing — no manual
factory registration needed (see [Metrics Auto-Detection](#metrics-auto-detection)).

For raw Prometheus output:

```bash
curl -s http://localhost:8080/metrics | grep audit_
```

### 7. Load test (optional)

```bash
./loadtest.sh
```

Generates 300+ diverse events (logins, CRUD operations, auth failures,
admin actions) to populate the Grafana dashboards with realistic data.

### 8. Clean up

```bash
docker compose down -v
```

## Output Topology

```
                          ┌── stdout (JSON, all events, full PII)
                          │     → docker compose logs app
                          │
  audit event → logger ───┼── audit.log (CEF, all events, HMAC v1)
                          │     → compliance archive, SIEM-ready
                          │
                          ├── security.log (JSON, severity >= 7, HMAC v2)
                          │     → security team, different salt
                          │
                          └── Loki (JSON, all events, PII stripped)
                                → Grafana dashboards
```

| Output | Format | Route | HMAC | PII | Purpose |
|--------|--------|-------|------|-----|---------|
| **console** (stdout) | JSON | all events | none | full | Developer debugging via `docker compose logs` |
| **compliance_archive** (file) | CEF | all events | v1 SHA-256 | full | Compliance archive, SIEM-ready |
| **security_feed** (file) | JSON | security + compliance, severity >= 7 | v2 SHA-512 | full | Security team feed |
| **loki_dashboard** (Loki) | JSON | all events | none | stripped | Grafana dashboards, PII removed |

## Files

| File | Purpose |
|------|---------|
| `Dockerfile` | Multi-stage build — compiles Go binary, runs in Alpine |
| `docker-compose.yml` | App + Postgres + Loki + Grafana — one command starts all |
| `taxonomy.yaml` | 21 event types, 4 categories, sensitivity labels |
| `outputs.yaml` | Four outputs with HMAC, CEF, routing, PII stripping |
| `audit_generated.go` | Generated typed builders (committed) |
| `main.go` | Entry point, signal handling, graceful shutdown |
| `audit_setup.go` | Loads output config, wires metrics via auto-detection |
| `server.go` | HTTP mux, audit middleware, EventBuilder |
| `handlers*.go` | CRUD handlers for users, items, orders |
| `auth.go` | Session-based auth, login/logout, auth failure events |
| `admin.go` | Settings, export, bulk operations |
| `db*.go` | Postgres connection and queries |
| `metrics.go` | Prometheus metrics (core + per-output via structural typing) |
| `main_test.go` | 9 unit tests showing how to test audit events with `audittest` |
| `static/index.html` | Single-page web UI |
| `grafana/` | Pre-provisioned datasources (Loki + Prometheus) and two dashboards |
| `prometheus.yml` | Prometheus scrape configuration |
| `loki-config.yaml` | Loki server configuration |
| `loadtest.sh` | Generates 300+ diverse events for dashboard testing |

## Key Concepts

### Metrics Auto-Detection

The `auditMetrics` struct in `metrics.go` implements both the core
`audit.Metrics` interface and the per-output interfaces (`file.Metrics`,
`audit.OutputMetrics`) via structural typing. When passed to `outputconfig.Load`
via `WithCoreMetrics(m)`, the output factories automatically detect
which interfaces it satisfies:

```go
result, err := outputconfig.Load(ctx, outputsYAML, tax,
    outputconfig.WithCoreMetrics(m),
)
```

No `RegisterOutputFactory` calls needed. Adding a new output type to
`outputs.yaml` is a config change, not a code change.

### Emission Paths

This demo emits every event through generated typed builders in
`audit_generated.go` — `NewUserLoginEvent(...)`, `NewItemCreatedEvent(...)`,
and so on. That path is the library's zero-allocation fast path:
the builders implement the internal `FieldsDonor` sentinel so the
auditor takes ownership of the `Fields` map without a defensive
copy. Compile-time field safety is a bonus.

For dynamic event types — say, a plugin registry that emits event
types discovered at runtime — use
[`auditor.MustHandle("my_event")`](https://pkg.go.dev/github.com/axonops/audit#Auditor.MustHandle)
at registration time, cache the `EventHandle`, and call
`h.Audit(fields)` per event. Do not call `audit.NewEvent(...)` on a
hot path: each call pays one heap allocation via interface escape.

See [`docs/performance.md`](../../docs/performance.md) for the full
breakdown.

### Lifecycle Events (Best Practice)

Always emit audit events for application startup and shutdown. These
are critical for compliance — auditors need to know when the system
was running, and gaps in the audit trail need to be explainable.

```go
// Emit on startup — after the auditor is created, before serving.
auditor.AuditEvent(NewAppStartupEvent("success").
    SetMessage("inventory demo started on " + addr))

// Emit on shutdown — after stopping HTTP, before auditor.Close().
auditor.AuditEvent(NewAppShutdownEvent("success").
    SetMessage("graceful shutdown initiated"))
```

The shutdown event only reaches outputs because `auditor.Close()`
drains the buffer before returning. If you skip `Close()`, the
shutdown event is lost — along with any other buffered events.

See `main.go` for the exact placement in the signal handling flow.

### Authentication and Audit Hints

Auth and audit middleware are composed as HTTP handler layers:

```go
authed := authMiddleware()(mux)
audited := audit.Middleware(auditor, buildAuditEvent)(authed)
```

When authentication fails, the auth middleware sets
`Hints.EventType = "auth_failure"` and returns 401 — the audit
middleware automatically emits the failure event. When authentication
succeeds, it sets `Hints.ActorID` so the audit event records who made
the request. Neither the auth middleware nor the handlers need a direct
reference to the auditor.

### Graceful Shutdown

The shutdown sequence matters:

1. **Stop the HTTP server** — no new requests, no new audit events
2. **Close the auditor** — flushes all buffered events to outputs
3. **Exit**

Without `auditor.Close()`, buffered events are lost and the drain
goroutine leaks. See `main.go` for the signal handling pattern.

## Testing Audit Events

The `main_test.go` file demonstrates how to test audit events in a
real application using `audittest.New`. This is the pattern you
should follow in your own tests.

### Test setup

```go
func newTestServer(t *testing.T, dbSetup func(mock sqlmock.Sqlmock)) *testEnv {
    auditor, rec, _ := audittest.New(t, taxonomyYAML)
    handler := newServer(auditor, db, sessions, rl, settings)
    srv := httptest.NewServer(handler)
    return &testEnv{srv: srv, rec: rec, auditor: auditor}
}
```

The test logger uses the **same taxonomy** as production (embedded via
`go:embed`). Events flow through the same middleware, same handlers,
same `buildAuditEvent` function — the only difference is the output
goes to an in-memory recorder instead of files and Loki.

### Asserting on events

```go
func TestAuthFailure_InvalidAPIKey(t *testing.T) {
    env := newTestServer(t, nil)
    doRequest(t, env.srv.URL, "GET", "/items", "bad-key", nil)

    // New defaults to synchronous delivery — events are
    // available immediately without calling Close.
    require.Equal(t, 1, env.rec.Count())
    evt := env.rec.Events()[0]
    assert.Equal(t, "auth_failure", evt.EventType)
    assert.Equal(t, "failure", evt.StringField("outcome"))
}
```

Key points:
- **No `Close()` needed before assertions** — `audittest.New`
  defaults to synchronous delivery since #425
- **Same validation as production** — missing required fields are
  rejected, unknown event types fail
- **Full middleware stack** — HTTP fields (method, path, status code,
  client IP) are captured automatically

### What the tests cover

| Test | What it verifies |
|------|-----------------|
| `TestAuthFailure_InvalidAPIKey` | Auth middleware emits `auth_failure` with correct fields |
| `TestAuthFailure_NoCredentials` | Missing credentials produce `auth_failure` |
| `TestLogin_Success_EmitsAuthSuccess` | Successful login emits `auth_success` with actor_id |
| `TestLogin_BadPassword_EmitsAuthFailure` | Wrong password emits `auth_failure` |
| `TestCreateItem_EmitsItemCreateEvent` | CRUD handler emits correct event type and target_id |
| `TestCreateUser_EmitsPIIFields` | PII fields (email, phone) are present in events |
| `TestAdminSettings_NonAdmin_Forbidden` | Non-admin gets 403, authorization_failure event |
| `TestAdminSettings_AdminAllowed` | Admin access succeeds, settings_read event |
| `TestConfigChange_EmitsEventWithOldNewValues` | Config change captures old and new values |

Run the tests:

```bash
go test -v -race ./examples/20-capstone/...
```

See [Example 04 — Testing](../17-testing/) for the fundamentals of
`audittest.New` and `audittest.NewQuick`.

## Running Without Docker

If you prefer to run the app directly on your host (for IDE
debugging, faster `go run` cycles, or attaching a profiler), the
backing services still need to be available somewhere — the app
itself talks to Postgres, Loki, and OpenBao. The simplest pattern
is to keep those four containers running while the application
runs on your host:

```bash
# 0. Run all subsequent commands from the capstone directory — the
#    app reads outputs.yaml relative to the current working dir.
cd examples/20-capstone

# 1. Start infrastructure only (postgres + loki + grafana + openbao + seeder).
#    The seeder populates the HMAC salts that outputs.yaml resolves
#    via ref+openbao:// URIs; without it, auditor startup fails.
docker compose up -d postgres loki grafana openbao openbao-seed

# 2. Wait for postgres and the openbao seeder to finish.
docker compose exec postgres pg_isready -U demo -d audit_demo
docker compose wait openbao-seed

# 3. Export the env vars the app would otherwise inherit from the
#    Docker Compose `app` service. Defaults that work in-container
#    (e.g., APP_LOG_PATH=/data/app.log, BAO_ADDR=http://openbao:8200)
#    are wrong on the host — override them explicitly.
export APP_LOG_PATH="$(pwd)/app.log"           # default /data/app.log is Docker-only
export DATABASE_URL="postgres://demo:demo@localhost:5432/audit_demo?sslmode=disable"
export BAO_ADDR="http://localhost:8200"        # default is set inside the compose network
export BAO_TOKEN="demo-root-token"             # matches BAO_DEV_ROOT_TOKEN_ID in compose
export LOKI_URL="http://localhost:3100/loki/api/v1/push"
export LISTEN_ADDR=":8080"

# 4. Run the app on the host. Press Ctrl+C to exit; auditor flushes
#    pending events on shutdown.
go run .
```

The bare-metal run writes three files into the capstone directory:
`app.log` (application logs), `audit.log` (CEF compliance archive
with HMAC v1), and `security.log` (JSON security feed with HMAC v2).
The defaults `AUDIT_LOG_PATH=./audit.log` and
`SECURITY_LOG_PATH=./security.log` apply unless you override them.
Loki ingests audit events directly via the HTTP push URL, so events
land in Grafana the same way they do under Compose.

> ⚠️ **Why `openbao-seed` is required.** The HMAC integrity
> configuration in `outputs.yaml` references secrets via
> `ref+openbao://secret/data/audit/hmac-v1#...` URIs. Without the
> seed step, OpenBao has an empty KV store and the app fails at
> startup with a ref+ resolution error. The Compose service
> `openbao-seed` runs `openbao-seed.sh`, exits cleanly, and is
> referenced by the `app` service via `depends_on`. Outside Compose
> you must run the seeder yourself or seed the same paths manually
> with `bao kv put`.

## Further Reading

- [Metrics and Monitoring](../../docs/metrics-monitoring.md)
- [HTTP Middleware](../../docs/http-middleware.md)
- [Async Delivery](../../docs/async-delivery.md) — graceful shutdown
- [Output Configuration](../../docs/output-configuration.md) — YAML reference
- [HMAC Integrity](../../docs/hmac-integrity.md)
- [Sensitivity Labels](../../docs/sensitivity-labels.md)
- [Loki Output](../../docs/loki-output.md)
