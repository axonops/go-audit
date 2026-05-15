[← Back to examples](../README.md)

> **Previous:** [15 — HTTP Middleware](../15-middleware/) |
> **Next:** [17 — Testing](../17-testing/)
# Example 16: Health Endpoint (`/healthz` and `/readyz`)

Demonstrates how to expose Kubernetes-style liveness and
readiness HTTP probes for a service that uses the audit library.
The handlers query the `Auditor`'s public introspection
primitives — no global state, no monkey-patching, no special
test hooks.

## What You'll Learn

- The difference between liveness and readiness, and what each
  should mean for an audit-using service.
- How to drive `/healthz` from `Auditor.QueueLen()` /
  `Auditor.QueueCap()` AND `Auditor.LastDeliveryAge(name)` for
  per-output staleness.
- How to drive `/readyz` from `Auditor.IsDisabled()` and
  `Auditor.OutputNames()`.
- Why the queue-saturation threshold (90 % by default) and
  staleness threshold (30 s by default) are tuning knobs, not
  contracts — and how to choose them.
- Why per-output staleness catches failure modes that queue
  saturation alone cannot — e.g., a webhook output silently
  exhausting retries while a stdout output drains the queue
  cleanly.

## Liveness vs readiness

| Probe | What it asks | Failure consequence (Kubernetes) |
|---|---|---|
| Liveness (`/healthz`) | "Is this process healthy enough to keep running?" | Pod is restarted. |
| Readiness (`/readyz`) | "Should I send new traffic to this pod?" | Pod stays alive but is removed from the load balancer rotation. |

For an audit-using service the practical mapping is:

- **Liveness fail (queue jammed)** → there is no recovery from
  inside the process. Restart me.
- **Readiness fail (no outputs configured, or auditor disabled)**
  → I cannot accept events right now (e.g., still starting up,
  or a critical config issue caught at startup). Don't send me
  traffic yet, but don't restart — the operator may be in the
  middle of fixing the config.

A common mistake is to wire the same conditions into both
probes. Don't: a fault that is permanent (for the lifetime of
this pod) belongs in `/healthz`; a fault that is transient or
operator-correctable belongs in `/readyz`.

## Run

```bash
go run .
```

In another terminal:

```bash
curl -i http://localhost:8080/healthz
curl -i http://localhost:8080/readyz
```

You should see (note the blank line `curl -i` prints between
headers and body):

```
HTTP/1.1 200 OK
Content-Type: application/json

{"status":"healthy","queue_len":0,"queue_cap":10,"saturation":0.00}
```

```
HTTP/1.1 200 OK
Content-Type: application/json

{"status":"ready","output_count":1,"outputs":["stdout"]}
```

A failing `/readyz` (e.g., `outputs.yaml` deleted before
startup) returns:

```
HTTP/1.1 503 Service Unavailable
Content-Type: application/json

{"status":"not-ready","reason":"no outputs configured"}
```

The example uses a tiny `queue_size: 10` (in `outputs.yaml`) and
emits one event per second from a background goroutine, so the
saturation indicator stays low. To see `/healthz` go red, drop
`queue_size` in `outputs.yaml` to `1` and shorten the
`time.NewTicker(1 * time.Second)` interval in `driveAuditLoop`
(`main.go`) to e.g. `1 * time.Millisecond` — the queue will
saturate and `/healthz` will return 503 with the observed
saturation in the body.

## How it Works

### `/healthz` — liveness

The handler combines two checks: queue saturation (catches the
core pipeline jamming up) and per-output staleness (catches an
async output whose retry-exhausted batches stop reaching the
remote endpoint, even though the queue continues to drain
cleanly into the other outputs).

```go
func healthzHandler(a *audit.Auditor) http.HandlerFunc {
    return func(w http.ResponseWriter, _ *http.Request) {
        queueLen := a.QueueLen()
        queueCap := a.QueueCap()
        var saturation float64
        if queueCap > 0 {
            saturation = float64(queueLen) / float64(queueCap)
        }
        if saturation > 0.90 {
            w.WriteHeader(http.StatusServiceUnavailable)
            // ... queue-saturated body ...
            return
        }
        // Per-output staleness — only meaningful once an output
        // has delivered at least once. LastDeliveryAge returns 0
        // for never-delivered or for outputs that don't implement
        // LastDeliveryReporter; both are treated as healthy here.
        for _, name := range a.OutputNames() {
            age := a.LastDeliveryAge(name)
            if age > 0 && age > 30*time.Second {
                w.WriteHeader(http.StatusServiceUnavailable)
                // ... output-stale body, includes name + age ...
                return
            }
        }
        w.WriteHeader(http.StatusOK)
        // ... healthy body ...
    }
}
```

The 90 % saturation threshold is the default the docs recommend.
**Tune for your workload.** A larger queue tolerates a higher
absolute backlog before declaring a fault; a smaller queue trips
earlier.

**Worked saturation example.** With `queue_size: 10000` and a
sustained drain rate of 5000 events/s, 90 % saturation = 9000
events ≈ 1.8 s of backlog. Choose the threshold so that the
absolute backlog exceeds your Kubernetes probe's
`failureThreshold × periodSeconds` — otherwise transient spikes
will flap the probe. The
[Capacity Planning tier table](../../docs/deployment.md#capacity-planning)
gives concrete `queue_size` values per event-rate tier.

**Picking a staleness threshold.** The threshold MUST exceed
your quietest expected gap between events plus the worst-case
retry-backoff window for your slowest output, or healthy-but-idle
outputs will spuriously trip the probe. 30 s is conservative for
most workloads:

| Workload pattern | Suggested threshold |
|---|---|
| Continuous traffic, high event rate | 5 × the probe interval (e.g., 50 s for a 10 s probe) |
| Sporadic traffic with idle gaps under 1 minute | 30 s (default) |
| Truly bursty traffic (idle for minutes) | The longest plausible idle gap, plus retry-backoff window |

`LastDeliveryAge` returns `0` both for an output that has never
delivered (newly-started auditor) and for an output that does
not implement `LastDeliveryReporter`. The handler treats `0` as
healthy — a baseline must exist before staleness can be
diagnosed. Once an output produces its first successful
delivery, the timestamp advances on every subsequent success and
freezes on every failure, so the age grows unbounded only when
deliveries stop.

### `/readyz` — readiness

```go
func readyzHandler(a *audit.Auditor) http.HandlerFunc {
    return func(w http.ResponseWriter, _ *http.Request) {
        if a.IsDisabled() {
            w.WriteHeader(http.StatusServiceUnavailable)
            return
        }
        if len(a.OutputNames()) == 0 {
            w.WriteHeader(http.StatusServiceUnavailable)
            return
        }
        w.WriteHeader(http.StatusOK)
    }
}
```

Both checks are sub-microsecond reads on internal state. Both
are safe to call concurrently from any goroutine.

**`/readyz` runtime semantics.** The output list is fixed at
auditor construction (in `outputconfig.New`); it does not flip
back to empty if a downstream output starts failing later. So
`/readyz` mostly catches the "auditor was disabled" or
"`outputs.yaml` was missing or empty at startup" case. Runtime
per-output delivery stalls are caught by `/healthz` via
`Auditor.LastDeliveryAge(name)` — see the staleness check
above.

## Production checklist

The example binds everything to one public listener (`:8080`)
for simplicity. Three things to change before deploying:

1. **Probes on a separate listener.** Bind probe traffic to
   localhost (or the pod IP only) so it skips the public
   authentication path:

   ```go
   probeMux := http.NewServeMux()
   probeMux.HandleFunc("/healthz", healthzHandler(auditor))
   probeMux.HandleFunc("/readyz", readyzHandler(auditor))
   probeSrv := &http.Server{
       Addr:              "127.0.0.1:9090",
       Handler:           probeMux,
       ReadHeaderTimeout: 5 * time.Second,
   }
   go probeSrv.ListenAndServe()
   ```

2. **Kubernetes Pod spec.** Reference the probe port from the
   container manifest:

   ```yaml
   livenessProbe:
     httpGet:
       path: /healthz
       port: 9090
       host: 127.0.0.1
     periodSeconds: 10
     failureThreshold: 3
   readinessProbe:
     httpGet:
       path: /readyz
       port: 9090
       host: 127.0.0.1
     periodSeconds: 5
     failureThreshold: 2
   ```

3. **Tune the saturation threshold** for your workload using
   the worked example above.

## What's NOT here

- **Authentication on the probe endpoint**. Production probes
  typically run on a separate listener bound to localhost (or
  the pod IP only) so probe traffic doesn't hit the public
  authentication path. See the Production checklist above.

- **Runtime-configurable thresholds.** This example uses
  package-level `const` values for the saturation and staleness
  thresholds. Real services should expose them as flags or env
  vars so operators can tune without redeploying.

- **Per-output thresholds.** The example uses one staleness
  threshold for every output. A consumer that mixes a busy
  Loki output (events every few seconds) with an archival file
  output (events possibly minutes apart) may want different
  thresholds per output — keep a `map[string]time.Duration` and
  look up the per-output threshold inside the loop.

## Files

| File | Purpose |
|---|---|
| `main.go` | The HTTP server, the two handlers, and a background loop emitting one audit event per second so the queue shows non-zero depth. |
| `taxonomy.yaml` | Minimal taxonomy with one event type (`health_probe`). |
| `audit_generated.go` | `audit-gen` output (run `go generate` to regenerate). |
| `outputs.yaml` | Single stdout output; tiny `queue_size` so the saturation knob is observable. |

## Copying this example to your own project

`go run .` works inside the workspace because `outputconfig.New`
reads `outputs.yaml` from the current working directory. If you
copy this example into your own repository:

1. Follow the [For Consumers Outside the Workspace](../README.md#for-consumers-outside-the-workspace)
   instructions to fetch `github.com/axonops/audit`,
   `github.com/axonops/audit/outputconfig`, and
   `github.com/axonops/audit/outputs`.
2. To regenerate `audit_generated.go`, install the code generator
   first:

   ```bash
   go install github.com/axonops/audit/cmd/audit-gen@latest
   go generate ./...
   ```

3. Either run the binary from the directory containing
   `outputs.yaml`, or pass an absolute path to
   `outputconfig.New`. The taxonomy is embedded via `go:embed`
   and travels with the binary; `outputs.yaml` is a runtime
   config file and does not.

For the complete `Auditor` introspection surface (signatures,
return values, concurrency guarantees) see the
[godoc](https://pkg.go.dev/github.com/axonops/audit#Auditor).
