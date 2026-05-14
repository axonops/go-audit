// Copyright 2026 AxonOps Limited.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Example 18: /healthz and /readyz handlers driven by audit
// introspection.
//
// Demonstrates how to expose Kubernetes-style liveness and
// readiness probes for a service that uses the audit library:
//
//   - /healthz (liveness): returns 503 when EITHER the audit
//     queue is more than 90 % saturated OR any output's last
//     successful delivery is older than the staleness threshold
//     (default 30 s). The two checks together catch both core
//     pipeline jams (queue saturation) and silent per-output
//     stalls (TCP half-open, retries exhausted) that leave the
//     queue draining cleanly to one output while another drops
//     every event. A failing liveness probe tells the
//     orchestrator to restart the pod.
//
//   - /readyz (readiness): returns 503 when the auditor is
//     disabled or no outputs are configured. A failing readiness
//     probe drops the pod from the load balancer rotation but
//     does NOT restart it.
//
// The handlers query Auditor.QueueLen, QueueCap, OutputNames,
// LastDeliveryAge, IsDisabled — all part of the public
// introspection surface (audit/introspect.go).
//
// Run:
//
//	go run .
//
// In another terminal:
//
//	curl -i http://localhost:8080/healthz
//	curl -i http://localhost:8080/readyz
package main

import (
	"context"
	_ "embed"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/axonops/audit"
	"github.com/axonops/audit/outputconfig"
	_ "github.com/axonops/audit/outputs" // registers stdout, file, syslog, webhook, loki
)

//go:generate go run github.com/axonops/audit/cmd/audit-gen -input taxonomy.yaml -output audit_generated.go -package main

//go:embed taxonomy.yaml
var taxonomyYAML []byte

// healthzSaturationThreshold is the queue-fullness fraction
// above which /healthz returns 503. 90 % is the default the
// docs recommend; tune for your workload — a larger queue
// tolerates a higher absolute backlog before declaring a fault.
const healthzSaturationThreshold = 0.90

// healthzStaleThreshold is the maximum age of an output's most
// recent successful delivery before /healthz returns 503. Catches
// silently-failing async outputs (TCP half-open, retries
// exhausted) where Write enqueues succeed but no events ever land
// downstream. 30 s leaves headroom for sub-second NTP slews and
// idle periods between bursts of audit traffic; tune to your
// expected event cadence — shorter for high-volume systems,
// longer for sporadic auditors. The threshold MUST exceed your
// quietest expected gap between events plus retry-backoff window
// or healthy-but-idle outputs will spuriously fail.
const healthzStaleThreshold = 30 * time.Second

func main() {
	auditor, err := outputconfig.New(context.Background(), taxonomyYAML, "outputs.yaml")
	if err != nil {
		log.Fatalf("create auditor: %v", err)
	}
	// Note: log.Fatalf above bypasses deferred Close — fine here
	// because the process exits and the OS reclaims fds. After
	// the auditor is created, real shutdown happens in the SIGINT
	// handler below.

	// Wire the HTTP handlers. The handlers close over the
	// auditor — no global state, no init-order coupling.
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", healthzHandler(auditor))
	mux.HandleFunc("/readyz", readyzHandler(auditor))

	srv := &http.Server{
		Addr:              ":8080",
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	// Drive a few audit events in the background so the example
	// shows realistic queue activity. In production the
	// application would do this via its normal request handlers.
	stop := make(chan struct{})
	go driveAuditLoop(auditor, stop)

	// Graceful shutdown on Ctrl-C.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		close(stop)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	log.Printf("listening on :8080 — try: curl -i http://localhost:8080/healthz")
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server: %v", err)
	}
}

// healthzHandler returns the /healthz liveness handler. It
// reports 503 when EITHER queue saturation exceeds
// healthzSaturationThreshold OR any output's last successful
// delivery is older than healthzStaleThreshold. Either failure
// mode means events are not reaching their destination and the
// pod cannot self-recover.
//
// LastDeliveryAge returns 0 when the output has never delivered
// (boot, no traffic) and when the output does not implement
// LastDeliveryReporter. Both cases are treated as healthy here
// — staleness can only be diagnosed once a positive baseline
// exists.
func healthzHandler(a *audit.Auditor) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		queueLen := a.QueueLen()
		queueCap := a.QueueCap()
		var saturation float64
		if queueCap > 0 {
			saturation = float64(queueLen) / float64(queueCap)
		}

		w.Header().Set("Content-Type", "application/json")
		if saturation > healthzSaturationThreshold {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = fmt.Fprintf(w,
				`{"status":"unhealthy","reason":"queue_saturated","queue_len":%d,"queue_cap":%d,"saturation":%.2f,"threshold":%.2f}`+"\n",
				queueLen, queueCap, saturation, healthzSaturationThreshold)
			return
		}

		// Per-output staleness — catches the silently-failing
		// async output that QueueLen alone cannot detect.
		for _, name := range a.OutputNames() {
			age := a.LastDeliveryAge(name)
			if age > 0 && age > healthzStaleThreshold {
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = fmt.Fprintf(w,
					`{"status":"unhealthy","reason":"output_stale","output":%q,"age_seconds":%.1f,"threshold_seconds":%.0f}`+"\n",
					name, age.Seconds(), healthzStaleThreshold.Seconds())
				return
			}
		}

		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w,
			`{"status":"healthy","queue_len":%d,"queue_cap":%d,"saturation":%.2f}`+"\n",
			queueLen, queueCap, saturation)
	}
}

// readyzHandler returns the /readyz readiness handler. It
// reports 503 when the auditor is disabled or has no outputs
// configured — both are operator-correctable conditions where
// the pod should be drained from load-balancer rotation but
// NOT restarted.
func readyzHandler(a *audit.Auditor) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if a.IsDisabled() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = fmt.Fprintln(w, `{"status":"not-ready","reason":"auditor is disabled"}`)
			return
		}
		outputs := a.OutputNames()
		if len(outputs) == 0 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = fmt.Fprintln(w, `{"status":"not-ready","reason":"no outputs configured"}`)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w,
			`{"status":"ready","output_count":%d,"outputs":%q}`+"\n",
			len(outputs), outputs)
	}
}

// driveAuditLoop emits one audit event per second so the queue
// shows non-zero depth in /healthz responses. Real consumers
// would call AuditEvent from their request handlers.
func driveAuditLoop(a *audit.Auditor, stop <-chan struct{}) {
	t := time.NewTicker(1 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			_ = a.AuditEvent(audit.NewEvent(EventHealthProbe, audit.Fields{
				FieldOutcome:     "success",
				FieldProbeTarget: "self",
			}))
		}
	}
}
