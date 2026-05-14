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

// Example 14: Loki Output
//
// Demonstrates sending audit events to Grafana Loki with stream labels,
// gzip compression, and multi-tenant support.
//
// Prerequisites:
//
//	docker run -d --name loki -p 3100:3100 grafana/loki:3.0.0
//
// Run:
//
//	go generate ./...
//	go run .
//
// Query events in Loki:
//
//	curl -s 'http://localhost:3100/loki/api/v1/query_range?query={job="audit-example"}&limit=10' | jq .
package main

import (
	"context"
	_ "embed"
	"fmt"
	"log"
	"time"

	"github.com/axonops/audit/outputconfig"
	_ "github.com/axonops/audit/outputs" // registers stdout, file, syslog, webhook, loki
)

//go:generate go run github.com/axonops/audit/cmd/audit-gen -input taxonomy.yaml -output audit_generated.go -package main

//go:embed taxonomy.yaml
var taxonomyYAML []byte

func main() {
	// Single-call facade: parse taxonomy, load outputs, create auditor.
	auditor, err := outputconfig.New(context.Background(), taxonomyYAML, "outputs.yaml")
	if err != nil {
		log.Fatalf("create auditor: %v", err)
	}
	defer func() {
		if err := auditor.Close(); err != nil {
			log.Printf("close auditor: %v", err)
		}
	}()

	// Categorised events — these get event_category labels in Loki.
	if err := auditor.AuditEvent(
		NewUserCreateEvent("alice", "success").SetResourceID("user-42"),
	); err != nil {
		log.Printf("audit: %v", err)
	}
	fmt.Println("Audited: user_create by alice")

	if err := auditor.AuditEvent(
		NewUserCreateEvent("bob", "success").SetResourceID("user-43"),
	); err != nil {
		log.Printf("audit: %v", err)
	}
	fmt.Println("Audited: user_create by bob")

	if err := auditor.AuditEvent(
		NewAuthFailureEvent("mallory", "failure", "invalid_password"),
	); err != nil {
		log.Printf("audit: %v", err)
	}
	fmt.Println("Audited: auth_failure by mallory")

	if err := auditor.AuditEvent(
		NewPermissionDeniedEvent("mallory", "failure", "admin_panel"),
	); err != nil {
		log.Printf("audit: %v", err)
	}
	fmt.Println("Audited: permission_denied by mallory")

	if err := auditor.AuditEvent(
		NewUserUpdateEvent("alice", "success").SetResourceID("user-42"),
	); err != nil {
		log.Printf("audit: %v", err)
	}
	fmt.Println("Audited: user_update by alice")

	// Uncategorised events — no event_category label in Loki.
	// Useful for operational events that don't need compliance routing.
	if err := auditor.AuditEvent(
		NewHealthCheckEvent("alice", "success", "database"),
	); err != nil {
		log.Printf("audit: %v", err)
	}
	fmt.Println("Audited: health_check (uncategorised)")

	// Wait for the flush interval to deliver the batch.
	fmt.Println("\nWaiting for Loki delivery...")
	time.Sleep(2 * time.Second)

	fmt.Println("Done. Query your events:")
	fmt.Println(`  # All events:`)
	fmt.Println(`  curl -s -H 'X-Scope-OrgID: example' 'http://localhost:3100/loki/api/v1/query_range?query={job="audit-example"}&limit=20' | jq .`)
	fmt.Println(`  # Only "write" category events:`)
	fmt.Println(`  curl -s -H 'X-Scope-OrgID: example' 'http://localhost:3100/loki/api/v1/query_range?query={event_category="write"}&limit=10' | jq .`)
	fmt.Println(`  # Events by alice:`)
	fmt.Println(`  curl -s -H 'X-Scope-OrgID: example' 'http://localhost:3100/loki/api/v1/query_range?query={job="audit-example"}+|+json+|+actor_id="alice"&limit=10' | jq .`)
}
