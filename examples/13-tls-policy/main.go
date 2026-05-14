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

// TLS-policy demonstrates how to configure global and per-output TLS
// policy in audit. TLS policy controls the minimum TLS version and
// allowed cipher suites for all TLS-enabled outputs (syslog TCP+TLS,
// webhook HTTPS, loki HTTPS).
//
// This example uses stdout output only (no TLS transport) to show that
// the YAML configuration parses correctly. In production, the TLS
// policy would apply to syslog, webhook, and loki outputs that use
// TLS connections.
package main

import (
	"context"
	"crypto/tls"
	_ "embed"
	"fmt"
	"log"
	"os"

	"github.com/axonops/audit"
	"github.com/axonops/audit/outputconfig"
	_ "github.com/axonops/audit/outputs" // registers stdout, file, syslog, webhook, loki
)

//go:generate go run github.com/axonops/audit/cmd/audit-gen -input taxonomy.yaml -output audit_generated.go -package main

//go:embed taxonomy.yaml
var taxonomyYAML []byte

func main() {
	// 1. Parse taxonomy and load output config.
	// Single-call facade: parse taxonomy, load outputs, create auditor.
	auditor, err := outputconfig.New(context.Background(), taxonomyYAML, "outputs.yaml")
	if err != nil {
		log.Fatalf("create auditor: %v", err)
	}

	// 3. Emit a couple of events to stdout.
	if auditErr := auditor.AuditEvent(NewAuthLoginEvent("alice", "success")); auditErr != nil {
		log.Printf("audit error: %v", auditErr)
	}
	if auditErr := auditor.AuditEvent(NewUserCreateEvent("bob", "success")); auditErr != nil {
		log.Printf("audit error: %v", auditErr)
	}

	if closeErr := auditor.Close(); closeErr != nil {
		log.Printf("close auditor: %v", closeErr)
	}

	// 4. Demonstrate TLS policy application programmatically.
	fmt.Fprintln(os.Stderr, "\n--- TLS Policy Demonstration ---")
	demonstrateTLSPolicies()
}

// demonstrateTLSPolicies shows how each TLS policy configuration
// translates to concrete TLS settings.
func demonstrateTLSPolicies() {
	scenarios := []struct {
		policy *audit.TLSPolicy
		name   string
	}{
		{
			policy: nil,
			name:   "Default (nil policy)",
		},
		{
			policy: &audit.TLSPolicy{AllowTLS12: false, AllowWeakCiphers: false},
			name:   "TLS 1.3 only (explicit)",
		},
		{
			policy: &audit.TLSPolicy{AllowTLS12: true, AllowWeakCiphers: false},
			name:   "TLS 1.2 allowed, secure ciphers",
		},
		{
			policy: &audit.TLSPolicy{AllowTLS12: true, AllowWeakCiphers: true},
			name:   "TLS 1.2 allowed, weak ciphers (NOT recommended)",
		},
	}

	for _, s := range scenarios {
		cfg, warnings := s.policy.Apply(nil)
		fmt.Fprintf(os.Stderr, "\n  %s:\n", s.name)
		fmt.Fprintf(os.Stderr, "    MinVersion: %s\n", tlsVersionName(cfg.MinVersion))
		if cfg.CipherSuites == nil {
			fmt.Fprintf(os.Stderr, "    CipherSuites: Go defaults\n")
		} else {
			fmt.Fprintf(os.Stderr, "    CipherSuites: secure suites only (%d suites)\n", len(cfg.CipherSuites))
		}
		for _, w := range warnings {
			fmt.Fprintf(os.Stderr, "    WARNING: %s\n", w)
		}
	}
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}
