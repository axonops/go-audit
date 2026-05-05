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

package audit_test

// Split out of audit_test.go (#540).

import (
	"testing"
	"time"

	"github.com/axonops/audit"
	"github.com/axonops/audit/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// EventType handle tests
// ---------------------------------------------------------------------------

func TestLogger_Handle_Valid(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	auditor := newTestAuditor(t, out)

	h, err := auditor.Handle("schema_register")
	require.NoError(t, err)
	require.NotNil(t, h)
	assert.Equal(t, "schema_register", h.EventType())
}

func TestLogger_Handle_Error(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	auditor := newTestAuditor(t, out)

	h, err := auditor.Handle("nonexistent")
	require.Error(t, err)
	assert.Nil(t, h)
	assert.ErrorIs(t, err, audit.ErrHandleNotFound)
}

func TestLogger_MustHandle_Valid(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	auditor := newTestAuditor(t, out)

	assert.NotPanics(t, func() {
		h := auditor.MustHandle("schema_register")
		assert.Equal(t, "schema_register", h.EventType())
	})
}

func TestLogger_MustHandle_Panics(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	auditor := newTestAuditor(t, out)

	assert.Panics(t, func() {
		auditor.MustHandle("nonexistent")
	})
}

// TestAuditorHandle_DisabledAuditor_ReturnsNoOpHandle covers #593 B-29:
// Handle on a disabled auditor returns a no-op handle for any event
// type without consulting the taxonomy. All Audit calls on the
// returned handle are silent no-ops, matching AuditEvent semantics.
func TestAuditorHandle_DisabledAuditor_ReturnsNoOpHandle(t *testing.T) {
	t.Parallel()
	auditor, err := audit.New(audit.WithDisabled())
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditor.Close() })

	// Event type not registered in any taxonomy — still succeeds.
	h, err := auditor.Handle("completely_unknown_event")
	require.NoError(t, err, "Handle on disabled auditor must not fail")
	require.NotNil(t, h)
	assert.Equal(t, "completely_unknown_event", h.EventType())

	// Audit via the handle is a silent no-op.
	require.NoError(t, h.Audit(audit.Fields{"anything": "goes"}))

	// MustHandle must also not panic on disabled auditor.
	assert.NotPanics(t, func() {
		h2 := auditor.MustHandle("another_unknown")
		require.NotNil(t, h2)
	})
}

// TestEventHandle_Metadata_FromTaxonomy locks the #597 contract:
// EventHandle exposes Description, Categories, and FieldInfoMap
// resolved from the taxonomy at handle construction. Middleware can
// introspect the registered handle without constructing an event.
func TestEventHandle_Metadata_FromTaxonomy(t *testing.T) {
	t.Parallel()
	out := testhelper.NewMockOutput("test")
	auditor := newTestAuditor(t, out)
	t.Cleanup(func() { _ = auditor.Close() })

	h, err := auditor.Handle("auth_failure")
	require.NoError(t, err)

	// auth_failure must be in at least one category (security) per
	// the test taxonomy.
	cats := h.Categories()
	require.NotEmpty(t, cats, "EventHandle Categories must be populated from taxonomy")

	// FieldInfoMap must include outcome (required) and actor_id per
	// the test taxonomy in internal/testhelper.
	fim := h.FieldInfoMap()
	require.NotNil(t, fim, "EventHandle FieldInfoMap must be populated")
	require.Contains(t, fim, "outcome", "outcome field must be in FieldInfoMap")

	outcomeFI := fim["outcome"]
	assert.Equal(t, "outcome", outcomeFI.Name)
	assert.True(t, outcomeFI.Required, "outcome should be required")

	require.Contains(t, fim, "actor_id", "actor_id field must be in FieldInfoMap")
	assert.Equal(t, "actor_id", fim["actor_id"].Name)
}

// TestEventHandle_Metadata_ReadOnlyContract documents the
// [audit.Event] interface's read-only mutation contract: the
// returned values are shared and MUST NOT be mutated by callers.
// This test asserts the implementation honours the contract by
// returning the same backing data — callers that mutate are
// breaking the contract; we just verify behaviour is consistent.
func TestEventHandle_Metadata_ReadOnlyContract(t *testing.T) {
	t.Parallel()
	out := testhelper.NewMockOutput("test")
	auditor := newTestAuditor(t, out)
	t.Cleanup(func() { _ = auditor.Close() })

	h, err := auditor.Handle("auth_failure")
	require.NoError(t, err)

	// auth_failure has at least one category in the test taxonomy
	// — assert non-empty so a regression in resolveCategoryInfos
	// would surface as a test failure (not a silent skip).
	first := h.Categories()
	require.NotEmpty(t, first, "auth_failure must have at least one category")

	// Repeated calls return the same Description, same Categories
	// shape (length and per-index Name), same FieldInfoMap key set.
	require.Equal(t, h.Description(), h.Description())

	second := h.Categories()
	require.Equal(t, len(first), len(second))
	for i := range first {
		assert.Equal(t, first[i].Name, second[i].Name,
			"Categories at index %d must be stable across calls", i)
	}

	fim1 := h.FieldInfoMap()
	fim2 := h.FieldInfoMap()
	require.Equal(t, len(fim1), len(fim2))
	for k := range fim1 {
		assert.Contains(t, fim2, k)
	}
}

func TestLogger_Handle_Audit(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	auditor := newTestAuditor(t, out)

	h := auditor.MustHandle("auth_failure")
	err := h.Audit(audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
	})
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))

	ev := out.GetEvent(0)
	assert.Equal(t, "auth_failure", ev["event_type"])
}
