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

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/audit"
	"github.com/axonops/audit/audittest"
)

// --- Pattern 1: Full integration test with real taxonomy ---

func TestCreateUser_EmitsAuditEvent(t *testing.T) {
	// Use the same taxonomy YAML that production code uses.
	auditor, events, metrics := audittest.New(t, taxonomyYAML)

	svc := NewUserService(auditor)
	err := svc.CreateUser("alice", "alice@example.com")
	require.NoError(t, err)

	// Synchronous delivery — events are immediately available.
	// No Close() needed before assertions.
	evt := events.RequireEvent(t, EventUserCreate)
	assert.Equal(t, "alice", evt.StringField(FieldActorID))
	assert.Equal(t, "alice@example.com", evt.StringField(FieldEmail))
	assert.Equal(t, 1, metrics.EventDeliveries("recorder", audit.EventSuccess))
}

func TestLogin_Failure_EmitsAuthEvent(t *testing.T) {
	auditor, events, _ := audittest.New(t, taxonomyYAML)

	svc := NewUserService(auditor)
	err := svc.Login("bob", "wrong-password")
	require.NoError(t, err) // AuditEvent itself shouldn't error

	evt := events.RequireEvent(t, EventAuthFailure)
	assert.Equal(t, "bob", evt.StringField(FieldActorID))
	assert.Equal(t, "invalid password", evt.StringField(FieldReason))
}

func TestLogin_Success_NoAuditEvent(t *testing.T) {
	auditor, events, _ := audittest.New(t, taxonomyYAML)

	svc := NewUserService(auditor)
	err := svc.Login("alice", "correct")
	require.NoError(t, err)

	// Successful login does not emit an audit event.
	events.RequireEmpty(t)
}

// --- Pattern 2: Quick smoke test (permissive taxonomy, any fields accepted) ---

func TestAuditEventEmitted_Quick(t *testing.T) {
	// NewQuick creates a permissive auditor — any fields accepted.
	auditor, events, _ := audittest.NewQuick(t, "user_create")

	svc := NewUserService(auditor)
	_ = svc.CreateUser("charlie", "charlie@example.com")

	// Just verify the event was emitted — no field validation.
	events.RequireEvent(t, "user_create")
}

// --- Pattern 3: One-liner field assertion ---

func TestCreateUser_AssertContains(t *testing.T) {
	auditor, events, _ := audittest.New(t, taxonomyYAML)

	svc := NewUserService(auditor)
	_ = svc.CreateUser("alice", "alice@example.com")

	// One-liner: assert event type + specific fields.
	events.AssertContains(t, EventUserCreate, audit.Fields{
		FieldActorID: "alice",
		FieldEmail:   "alice@example.com",
	})
}

// --- Pattern 4: Validation error testing ---

func TestValidationError_MissingRequiredField(t *testing.T) {
	auditor, events, metrics := audittest.New(t, taxonomyYAML)

	// Emit event missing required field "actor_id" using NewEvent directly.
	err := auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"outcome": "success",
		// actor_id missing — validation error
	}))
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrMissingRequiredField)

	// Event was rejected — nothing in the recorder.
	events.RequireEmpty(t)
	assert.Equal(t, 1, metrics.ValidationErrors("user_create"))
}
