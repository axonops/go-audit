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

// Testing demonstrates how to test code that uses audit.
// The main.go defines a UserService that emits audit events.
// The main_test.go shows three testing patterns using audittest.
package main

import (
	"context"
	_ "embed"
	"fmt"
	"log"

	"github.com/axonops/audit"
	"github.com/axonops/audit/outputconfig"
	_ "github.com/axonops/audit/outputs" // registers stdout, file, syslog, webhook, loki
)

//go:generate go run github.com/axonops/audit/cmd/audit-gen -input taxonomy.yaml -output audit_generated.go -package main

//go:embed taxonomy.yaml
var taxonomyYAML []byte

// UserService is a simple service that emits audit events.
// It takes a *audit.Auditor as a dependency — making it testable.
type UserService struct {
	auditor *audit.Auditor
}

// NewUserService creates a UserService with the given auditor.
func NewUserService(auditor *audit.Auditor) *UserService {
	return &UserService{auditor: auditor}
}

// CreateUser creates a user and emits an audit event.
func (s *UserService) CreateUser(actorID, email string) error {
	// ... business logic would go here ...

	return s.auditor.AuditEvent(
		NewUserCreateEvent(actorID, "success").
			SetEmail(email),
	)
}

// Login attempts authentication and emits an audit event on failure.
func (s *UserService) Login(username, password string) error {
	// Simulate failed authentication.
	if password != "correct" {
		return s.auditor.AuditEvent(
			NewAuthFailureEvent(username, "failure").
				SetReason("invalid password"),
		)
	}
	return nil
}

func main() {
	// Single-call facade: parse taxonomy, load outputs, create auditor.
	auditor, err := outputconfig.New(context.Background(), taxonomyYAML, "outputs.yaml")
	if err != nil {
		log.Fatalf("create auditor: %v", err)
	}
	defer func() { _ = auditor.Close() }()

	svc := NewUserService(auditor)
	_ = svc.CreateUser("alice", "alice@example.com")
	_ = svc.Login("bob", "wrong")

	fmt.Println("Events emitted. See main_test.go for how to test this.")
}
