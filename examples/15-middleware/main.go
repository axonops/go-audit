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

// Middleware demonstrates automatic HTTP audit logging: the audit
// middleware captures transport metadata (method, path, status, duration),
// handlers populate domain hints (actor, outcome), and health checks are
// skipped.
//
// Run:
//
//	go generate ./...
//	go run .
package main

import (
	"context"
	_ "embed"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"

	"github.com/axonops/audit"
	"github.com/axonops/audit/outputconfig"
	_ "github.com/axonops/audit/outputs" // registers stdout, file, syslog, webhook, loki
)

//go:generate go run github.com/axonops/audit/cmd/audit-gen -input taxonomy.yaml -output audit_generated.go -package main

//go:embed taxonomy.yaml
var taxonomyYAML []byte

// buildEvent is the EventBuilder callback. The middleware calls it after
// every request with the handler's hints and the captured transport
// metadata. Returning skip=true suppresses the audit event.
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

	// Set up HTTP routes.
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	mux.HandleFunc("GET /items", func(w http.ResponseWriter, r *http.Request) {
		if hints := audit.HintsFromContext(r.Context()); hints != nil {
			hints.ActorID = "alice"
			hints.Outcome = "success"
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[{"id":"1","name":"widget"}]`))
	})

	mux.HandleFunc("POST /items", func(w http.ResponseWriter, r *http.Request) {
		if hints := audit.HintsFromContext(r.Context()); hints != nil {
			hints.ActorID = "alice"
			hints.Outcome = "success"
			hints.TargetID = "item-42"
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"42","name":"new-widget"}`))
	})

	// Wrap with audit middleware.
	handler := audit.Middleware(auditor, buildEvent)(mux)

	// Start a test server and make programmatic requests.
	server := httptest.NewServer(handler)
	defer server.Close()

	client := server.Client()
	makeRequest(client, "GET", server.URL+"/healthz")
	makeRequest(client, "GET", server.URL+"/items")
	makeRequest(client, "POST", server.URL+"/items")

	// Close the auditor to flush buffered events.
	if err := auditor.Close(); err != nil {
		log.Printf("close auditor: %v", err)
	}

	fmt.Println("\nNote: /healthz produced no audit event (skipped by EventBuilder).")
}

func makeRequest(client *http.Client, method, reqURL string) {
	req, err := http.NewRequestWithContext(context.Background(), method, reqURL, http.NoBody)
	if err != nil {
		log.Printf("create request: %v", err)
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("%s %s: %v", method, reqURL, err)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	fmt.Printf("%s %s -> %d\n", method, reqURL, resp.StatusCode)
}
