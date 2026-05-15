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

// Webhook-output demonstrates sending audit events as NDJSON batches
// to an HTTP endpoint with retry, custom headers, and SSRF protection.
// A local HTTP server is embedded so the example is fully self-contained.
package main

import (
	"bufio"
	"context"
	_ "embed"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/axonops/audit"
	"github.com/axonops/audit/outputconfig"
	_ "github.com/axonops/audit/outputs" // registers stdout, file, syslog, webhook, loki
)

//go:generate go run github.com/axonops/audit/cmd/audit-gen -input taxonomy.yaml -output audit_generated.go -package main

//go:embed taxonomy.yaml
var taxonomyYAML []byte

func main() {
	// 1. Start a local HTTP server that receives NDJSON batches.
	//    In production, this would be your alerting endpoint, log
	//    aggregator, or custom webhook receiver.
	receiver := startWebhookReceiver("localhost:9090")

	// Give the listener time to bind.
	time.Sleep(50 * time.Millisecond)

	// 2. Parse taxonomy and load output config.
	// Single-call facade: parse taxonomy, load outputs, create auditor.
	auditor, err := outputconfig.New(context.Background(), taxonomyYAML, "outputs.yaml")
	if err != nil {
		log.Fatalf("create auditor: %v", err)
	}

	// 4. Emit audit events — they are batched internally and POSTed
	//    as NDJSON to our local receiver.
	events := []audit.Event{
		NewAuthLoginEvent("alice", "success"),
		NewUserCreateEvent("bob", "success"),
		NewAuthFailureEvent("mallory", "failure", "invalid_password"),
		NewDataExportEvent("alice", "success", "csv", "1500"),
	}

	for _, e := range events {
		if auditErr := auditor.AuditEvent(e); auditErr != nil {
			log.Printf("audit error: %v", auditErr)
		}
	}

	// 5. Close triggers a final flush of any buffered events.
	if closeErr := auditor.Close(); closeErr != nil {
		log.Printf("close auditor: %v", closeErr)
	}

	// 6. Print what the webhook receiver captured.
	time.Sleep(200 * time.Millisecond)
	batches := receiver.stop()

	fmt.Fprintln(os.Stderr, "\n--- NDJSON batches received by webhook server ---")
	for i, batch := range batches {
		fmt.Fprintf(os.Stderr, "\n[Batch %d] %d events, headers: %s\n",
			i+1, len(batch.events), formatHeaders(batch.headers))
		for j, event := range batch.events {
			fmt.Fprintf(os.Stderr, "  Event %d: %s\n", j+1, truncate(event, 120))
		}
	}
	fmt.Fprintf(os.Stderr, "\nTotal: %d batches, %d events received\n",
		len(batches), countEvents(batches))
}

type webhookBatch struct {
	headers map[string]string
	events  []string
}

type webhookReceiver struct {
	server  *http.Server
	batches []webhookBatch
	mu      sync.Mutex
}

func startWebhookReceiver(addr string) *webhookReceiver {
	r := &webhookReceiver{}

	mux := http.NewServeMux()
	mux.HandleFunc("/audit", func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Read the NDJSON body.
		body, readErr := io.ReadAll(req.Body)
		if readErr != nil {
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}

		// Parse individual JSON lines.
		var events []string
		scanner := bufio.NewScanner(strings.NewReader(string(body)))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				events = append(events, line)
			}
		}

		// Capture headers of interest.
		headers := map[string]string{
			"Content-Type":   req.Header.Get("Content-Type"),
			"X-Audit-Source": req.Header.Get("X-Audit-Source"),
			"X-Custom-Token": req.Header.Get("X-Custom-Token"),
		}

		r.mu.Lock()
		r.batches = append(r.batches, webhookBatch{headers: headers, events: events})
		r.mu.Unlock()

		w.WriteHeader(http.StatusOK)
	})

	r.server = &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = r.server.ListenAndServe() }()
	return r
}

func (r *webhookReceiver) stop() []webhookBatch {
	_ = r.server.Close()
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.batches
}

func formatHeaders(h map[string]string) string {
	var parts []string
	for k, v := range h {
		if v != "" {
			parts = append(parts, fmt.Sprintf("%s=%s", k, v))
		}
	}
	return strings.Join(parts, ", ")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func countEvents(batches []webhookBatch) int {
	total := 0
	for _, b := range batches {
		total += len(b.events)
	}
	return total
}
