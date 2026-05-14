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

// Prometheus Reference is a focused demo of wiring the audit
// library's pipeline-wide and per-output metrics into a Prometheus
// registry. The adapter (metrics.go) is the drop-in artefact you
// copy into your own project.
//
// Run:
//
//	go generate ./...
//	go run .
//
// Then in another shell:
//
//	curl -s http://localhost:2112/metrics | grep audit_
//
// You'll see audit_events_total, audit_validation_errors_total,
// audit_output_drops_total, audit_output_retries_total, etc.
//
// For a production-grade end-to-end example with Postgres, Loki,
// HMAC, and Grafana dashboards see examples/20-capstone/.
package main

import (
	"context"
	_ "embed"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/axonops/audit"
	"github.com/axonops/audit/outputconfig"
	_ "github.com/axonops/audit/outputs"
)

//go:generate go run github.com/axonops/audit/cmd/audit-gen -input taxonomy.yaml -output audit_generated.go -package main

//go:embed taxonomy.yaml
var taxonomyYAML []byte

func main() {
	// Construct the Prometheus adapter once. It registers all
	// audit_* counters on the default registry.
	metrics := newMetrics()

	// Build the auditor with the adapter wired into both the
	// pipeline-wide Metrics interface and the per-output
	// OutputMetricsFactory.
	auditor, err := outputconfig.NewWithLoad(
		context.Background(), taxonomyYAML, "outputs.yaml",
		[]outputconfig.LoadOption{
			outputconfig.WithCoreMetrics(metrics),
			outputconfig.WithOutputMetrics(metrics.newOutputMetricsFactory()),
		},
	)
	if err != nil {
		log.Fatalf("create auditor: %v", err)
	}
	defer func() { _ = auditor.Close() }()

	// Expose Prometheus metrics on /metrics. In production you
	// would mount this on your existing observability port; for
	// the demo we open :2112.
	go func() {
		http.Handle("/metrics", promhttp.Handler())
		srv := &http.Server{Addr: ":2112", ReadHeaderTimeout: 5 * time.Second}
		if listenErr := srv.ListenAndServe(); listenErr != nil {
			log.Printf("metrics server: %v", listenErr)
		}
	}()

	fmt.Println("--- Emitting audit events; metrics on http://localhost:2112/metrics ---")

	// Emit a successful event — increments audit_events_total
	// for output=console, status=delivered.
	if auditErr := auditor.AuditEvent(
		NewUserCreateEvent("alice", "success").SetTargetID("user-42"),
	); auditErr != nil {
		log.Printf("audit: %v", auditErr)
	}

	// Emit an event with a missing required field — increments
	// audit_validation_errors_total{event_type=auth_failure}.
	if auditErr := auditor.AuditEvent(
		audit.NewEvent("auth_failure", audit.Fields{
			"outcome": "failure",
			// actor_id (required) is intentionally missing
		}),
	); auditErr != nil {
		log.Printf("expected validation failure: %v", auditErr)
	}

	// Give the async pipeline a moment to drain so the metric
	// counters tick before we exit. In production this is
	// unnecessary because Close() blocks on shutdown.
	time.Sleep(100 * time.Millisecond)

	fmt.Println("--- Done. The metrics endpoint stays up; press Ctrl+C to exit. ---")
	select {}
}
