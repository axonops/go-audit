# Quickstart — HTTP Service

This guide takes you from `go get` to a running HTTP service that
audits every request, end to end, in about 10 minutes. It is
self-contained: every file shown here is the complete file you need.
You should not need to read any other audit doc to finish.

## Prerequisites

- Go 1.26+ (`go version` should report `go1.26` or later).
- A new directory: `mkdir myservice && cd myservice && go mod init example.com/myservice`.

## 1. Install the library

```bash
go get github.com/axonops/audit
go get github.com/axonops/audit/outputconfig
go get github.com/axonops/audit/outputs
```

Three modules: the core auditor (`audit`), the YAML config loader
(`outputconfig`), and the convenience package that registers all
built-in output factories (`outputs`).

## 2. Define your taxonomy — `taxonomy.yaml`

The taxonomy declares every event type your service emits and which
fields each event carries. It is embedded in your binary at compile
time via `go:embed`, so the schema can never drift between releases.

```yaml
version: 1

categories:
  access:
    severity: 4
    events:
      - http_request

events:
  http_request:
    description: "An HTTP request was processed"
    fields:
      outcome:     {required: true}
      method:      {required: true}
      path:        {required: true}
      status_code: {}
      duration_ms: {}
```

`outcome`, `method`, `path`, `status_code`, `duration_ms` are all
declared on the event. Reserved standard fields (e.g. `actor_id`,
`source_ip`, `target_id`) are always available without declaration —
see [docs/taxonomy-validation.md](taxonomy-validation.md#reserved-field-names)
for the full list.

## 3. Configure outputs — `outputs.yaml`

Where audit events go. For this quickstart we send to stdout.

```yaml
version: 1
app_name: myservice
host: localhost   # in production, set from ${HOSTNAME} via env-var expansion

outputs:
  console:
    type: stdout
```

`app_name` and `host` are framework fields stamped on every event so
your SIEM can route by service identity. In production they typically
come from `${HOSTNAME}` or a Kubernetes downward-API env var — the
loader expands `${VAR}` and `${VAR:-default}` syntax.

## 4. Generate the typed event builders

Add a `go:generate` directive to your `main.go` (you'll write the
file in the next step). Here is the directive line:

```go
//go:generate go run github.com/axonops/audit/cmd/audit-gen -input taxonomy.yaml -output audit_generated.go -package main
```

After saving `main.go`, run:

```bash
go generate ./...
```

This produces `audit_generated.go` containing:

- `EventHTTPRequest` constant (the event type).
- `FieldOutcome`, `FieldMethod`, `FieldPath`, `FieldStatusCode`,
  `FieldDurationMS`, `FieldActorID`, `FieldTargetID`, … (every field name).
- `NewHTTPRequestEvent(outcome, method, path string)` — typed
  constructor.
- Setter methods (`.SetActorID`, `.SetTargetID`, …) on the builder.

Typos in event or field names are now compile errors instead of
runtime taxonomy-validation failures.

## 5. Wire it up — `main.go`

The complete program. It starts a tiny HTTP server with two routes
(`GET /items`, `POST /items`) and one health check. Every request
except `/healthz` is audited.

```go
package main

import (
	"context"
	_ "embed"
	"fmt"
	"log"
	"net/http"

	"github.com/axonops/audit"
	"github.com/axonops/audit/outputconfig"
	_ "github.com/axonops/audit/outputs" // registers stdout, file, syslog, webhook, loki
)

//go:generate go run github.com/axonops/audit/cmd/audit-gen -input taxonomy.yaml -output audit_generated.go -package main

//go:embed taxonomy.yaml
var taxonomyYAML []byte

// buildEvent runs after every request. It reads transport metadata
// (method, path, status, duration) from the audit middleware and the
// per-request hints (actor, outcome) populated by your handlers.
func buildEvent(hints *audit.Hints, transport *audit.TransportMetadata) (eventType string, fields audit.Fields, skip bool) {
	// Skip health checks — no audit noise.
	if transport.Path == "/healthz" {
		return "", nil, true
	}
	fields = audit.Fields{
		FieldOutcome:    hints.Outcome,
		FieldMethod:     transport.Method,
		FieldPath:       transport.Path,
		FieldStatusCode: transport.StatusCode,
		FieldDurationMS: transport.Duration.Milliseconds(),
	}
	if hints.ActorID != "" {
		fields[FieldActorID] = hints.ActorID
	}
	if hints.TargetID != "" {
		fields[FieldTargetID] = hints.TargetID
	}
	return EventHTTPRequest, fields, false
}

func main() {
	// Single-call facade: parse taxonomy, load outputs, create auditor.
	auditor, err := outputconfig.New(context.Background(), taxonomyYAML, "outputs.yaml")
	if err != nil {
		log.Fatalf("create auditor: %v", err)
	}
	defer func() { _ = auditor.Close() }()

	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	mux.HandleFunc("GET /items", func(w http.ResponseWriter, r *http.Request) {
		if h := audit.HintsFromContext(r.Context()); h != nil {
			h.ActorID = "alice"
			h.Outcome = "success"
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[{"id":"1","name":"widget"}]`))
	})

	mux.HandleFunc("POST /items", func(w http.ResponseWriter, r *http.Request) {
		if h := audit.HintsFromContext(r.Context()); h != nil {
			h.ActorID = "alice"
			h.Outcome = "success"
			h.TargetID = "item-42"
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"42","name":"new-widget"}`))
	})

	handler := audit.Middleware(auditor, buildEvent)(mux)

	fmt.Println("listening on :8080 (Ctrl-C to stop)")
	log.Fatal(http.ListenAndServe(":8080", handler))
}
```

A few things worth noting:

- `audit.Middleware(auditor, buildEvent)` is the ONLY line wiring the
  audit library into the HTTP stack. It MUST sit OUTSIDE any
  panic-recovery middleware — see
  [docs/http-middleware.md](http-middleware.md#placement) for the
  correct ordering with chi/Gin/echo.
- Handlers populate `audit.Hints` via the request context; they never
  call `auditor.AuditEvent` directly. The middleware emits the audit
  event after the handler returns.
- `auditor.Close()` runs on `defer` so buffered events flush before
  the process exits, bounded by the 5-second default
  `shutdown_timeout`. **Caveat:** `log.Fatal` calls `os.Exit` directly,
  bypassing deferred functions — if `ListenAndServe` returns an error
  (port-in-use, permission denied), buffered events are lost. For
  graceful shutdown, replace `log.Fatal(http.ListenAndServe(...))`
  with a `signal.NotifyContext` + `srv.Shutdown(ctx)` pattern; see
  [examples/17-capstone/](../examples/17-capstone/) for a complete
  example.

## 6. Run it

```bash
go generate ./...   # produces audit_generated.go
go run .            # starts the server on :8080
```

In another terminal:

```bash
curl -s http://localhost:8080/healthz
curl -s http://localhost:8080/items
curl -s -X POST http://localhost:8080/items
```

You will see audit events appear on the server's stdout (one per
non-`/healthz` request):

```json
{"timestamp":"2026-04-27T12:34:56.789Z","event_type":"http_request","severity":4,"app_name":"myservice","host":"localhost","timezone":"Local","pid":12345,"actor_id":"alice","outcome":"success","method":"GET","path":"/items","status_code":200,"duration_ms":1,"event_category":"access"}
{"timestamp":"2026-04-27T12:34:56.798Z","event_type":"http_request","severity":4,"app_name":"myservice","host":"localhost","timezone":"Local","pid":12345,"actor_id":"alice","outcome":"success","target_id":"item-42","method":"POST","path":"/items","status_code":201,"duration_ms":1,"event_category":"access"}
```

`/healthz` produces no audit event because `buildEvent` returned
`skip=true` for it. `app_name`, `host`, `pid`, `timezone`, and
`event_category` are framework fields the library adds automatically.

That's the whole integration: 6 steps, ~80 lines of Go, two YAML
files. Every audit event your service emits flows through the
middleware-as-callback pattern, so the audit logic stays in one place.

## What's next

You now have a working integration. From here, pick the next topic
based on what your deployment actually needs:

- **Multiple outputs** — send one stream to a SIEM, another to disk:
  [examples/09-multi-output/](../examples/09-multi-output/).
- **Routing by category or severity** — security events to PagerDuty,
  read events to a colder log:
  [examples/10-event-routing/](../examples/10-event-routing/).
- **Sensitivity labels** — strip PII fields from compliance outputs:
  [examples/11-sensitivity-labels/](../examples/11-sensitivity-labels/).
- **HMAC integrity** — tamper-evident events for regulated
  environments: [examples/12-hmac-integrity/](../examples/12-hmac-integrity/).
- **Production deployment** — systemd, Kubernetes, log directory
  permissions: [docs/output-configuration.md](output-configuration.md).
- **Full reference application** — Postgres-backed CRUD with
  middleware, HMAC, Loki dashboards, Prometheus metrics, and graceful
  shutdown: [examples/17-capstone/](../examples/17-capstone/).
- **Threat model** — actors, guarantees, and what the library does
  not defend against: [docs/threat-model.md](threat-model.md).
