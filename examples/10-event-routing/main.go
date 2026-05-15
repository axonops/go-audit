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

// Event-routing demonstrates per-output filtering: security events go
// to one file, write events go to another, and stdout gets everything.
// Routing rules are defined in outputs.yaml.
package main

import (
	"context"
	_ "embed"
	"fmt"
	"log"
	"os"

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

	// Emit one event per category.
	if err := auditor.AuditEvent(NewUserCreateEvent("alice", "success")); err != nil {
		log.Printf("audit error: %v", err)
	}

	if err := auditor.AuditEvent(NewUserReadEvent("success")); err != nil {
		log.Printf("audit error: %v", err)
	}

	if err := auditor.AuditEvent(NewAuthFailureEvent("unknown", "failure")); err != nil {
		log.Printf("audit error: %v", err)
	}

	if err := auditor.Close(); err != nil {
		log.Printf("close auditor: %v", err)
	}

	// Show filtered output.
	printFile("security.log")
	printFile("writes.log")
	printFile("audit-feed.log")
	printFile("critical.log")

	// Clean up.
	_ = os.Remove("./security.log")
	_ = os.Remove("./writes.log")
	_ = os.Remove("./audit-feed.log")
	_ = os.Remove("./critical.log")
}

func printFile(name string) {
	data, err := os.ReadFile(name) //nolint:gosec // name is always a hardcoded literal
	if err != nil {
		log.Printf("read %s: %v", name, err)
		return
	}
	fmt.Printf("\n--- %s ---\n", name)
	fmt.Print(string(data))
}
