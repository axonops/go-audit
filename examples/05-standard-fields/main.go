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

// Example 13: Standard Fields & Framework Configuration
//
// This example shows the 31 reserved standard audit fields that are
// always available on every event without taxonomy declaration, and
// the framework fields (app_name, host, timezone, pid) that identify
// every event's origin.
package main

import (
	"context"
	_ "embed"
	"fmt"
	"log"

	"github.com/axonops/audit/outputconfig"
	_ "github.com/axonops/audit/outputs" // registers stdout, file, syslog, webhook, loki
)

//go:generate go run github.com/axonops/audit/cmd/audit-gen -input taxonomy.yaml -output audit_generated.go -package main

//go:embed taxonomy.yaml
var taxonomyYAML []byte

func main() {
	// Parse taxonomy — only outcome and actor_id are declared.
	// All 31 standard fields (source_ip, reason, target_id, etc.)
	// are available automatically.
	// Single-call facade: parse taxonomy, load outputs, create auditor.
	auditor, err := outputconfig.New(context.Background(), taxonomyYAML, "outputs.yaml")
	if err != nil {
		log.Fatalf("create auditor: %v", err)
	}
	defer func() {
		if closeErr := auditor.Close(); closeErr != nil {
			log.Printf("close auditor: %v", closeErr)
		}
	}()

	// Use generated setters for standard fields — no declaration needed.
	// SetTargetID, SetSourceIP, SetReason are available on every builder
	// because they are reserved standard fields.
	fmt.Println("--- Event with standard fields ---")
	if err := auditor.AuditEvent(
		NewUserCreateEvent("alice", "success").
			SetTargetID("user-42").
			SetReason("admin request"),
	); err != nil {
		log.Printf("audit error: %v", err)
	}

	// source_ip is not set here — the standard_fields default applies.
	fmt.Println("--- Event with default source_ip ---")
	if err := auditor.AuditEvent(
		NewAuthFailureEvent("unknown", "failure").
			SetReason("invalid credentials"),
	); err != nil {
		log.Printf("audit error: %v", err)
	}

	// Per-event source_ip overrides the default.
	fmt.Println("--- Event with explicit source_ip ---")
	if err := auditor.AuditEvent(
		NewAuthFailureEvent("bob", "failure").
			SetReason("expired token").
			SetSourceIP("192.168.1.100"),
	); err != nil {
		log.Printf("audit error: %v", err)
	}
}
