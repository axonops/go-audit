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
// EmitStartup without app_name in strict mode
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Multi-output fan-out
// ---------------------------------------------------------------------------

func TestLogger_Audit_MultipleOutputs(t *testing.T) {

	out1 := testhelper.NewMockOutput("out1")
	out2 := testhelper.NewMockOutput("out2")
	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out1, out2),
	)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, auditor.Close()) })

	err = auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
	}))
	require.NoError(t, err)

	require.True(t, out1.WaitForEvents(1, 2*time.Second))
	require.True(t, out2.WaitForEvents(1, 2*time.Second))
	assert.Equal(t, 1, out1.EventCount())
	assert.Equal(t, 1, out2.EventCount())
}

// ---------------------------------------------------------------------------
// OmitEmpty with non-zero values included
// ---------------------------------------------------------------------------

func TestLogger_Audit_OmitEmptyNonZeroIncluded(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	auditor := newTestAuditor(t, out, audit.WithOmitEmpty(), audit.WithValidationMode(audit.ValidationPermissive))

	err := auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
		"count":    42,
		"active":   true,
	}))
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))

	ev := out.GetEvent(0)
	assert.Equal(t, float64(42), ev["count"], "non-zero int should be included with OmitEmpty")
	assert.Equal(t, true, ev["active"], "true bool should be included with OmitEmpty")
}

// ---------------------------------------------------------------------------
// isZeroValue does not panic on func values
// ---------------------------------------------------------------------------

func TestLogger_Audit_FuncFieldOmitEmpty(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	auditor := newTestAuditor(t, out, audit.WithOmitEmpty(), audit.WithValidationMode(audit.ValidationPermissive))

	// A func value should not cause a panic in isZeroValue.
	// With OmitEmpty, isZeroValue returns false for a non-nil func,
	// so the func is included in the map. json.Marshal will fail on
	// func types, causing the event to be dropped. The drain goroutine
	// must survive this without panicking.
	err := auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
		"callback": func() {},
	}))
	require.NoError(t, err)

	// Send sentinel to prove drain goroutine survived the bad event.
	err = auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "sentinel",
	}))
	require.NoError(t, err)
	// Only the sentinel arrives (the func event fails serialization).
	require.True(t, out.WaitForEvents(1, 2*time.Second))
}

// ---------------------------------------------------------------------------
// Shutdown event dropped on full buffer
// ---------------------------------------------------------------------------

func TestLogger_Close_ShutdownEventDroppedOnFullBuffer(t *testing.T) {

	out := &blockingOutput{name: "stuck", blockCh: make(chan struct{})}
	t.Cleanup(func() { close(out.blockCh) })

	auditor, err := audit.New(
		audit.WithQueueSize(1),
		audit.WithShutdownTimeout(50*time.Millisecond),
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)

	// Emit startup so Close will try to emit shutdown.

	// Fill the buffer so emitShutdown's non-blocking send hits default.
	for i := 0; i < 100; i++ {
		_ = auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
			"outcome":  "failure",
			"actor_id": "bob",
		}))
	}

	// Close should not panic or hang even when shutdown event is dropped.
	_ = auditor.Close()
}

// ---------------------------------------------------------------------------
// All categories enabled by default
// ---------------------------------------------------------------------------

func TestLogger_Audit_AllCategoriesEnabledByDefault(t *testing.T) {

	tax := &audit.Taxonomy{
		Version:    1,
		Categories: map[string]*audit.CategoryDef{"write": {Events: []string{"ev1"}}},
		Events: map[string]*audit.EventDef{
			"ev1": {Required: []string{"f1"}},
		},
	}

	out := testhelper.NewMockOutput("test")
	auditor, err := audit.New(
		audit.WithTaxonomy(tax),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, auditor.Close()) })

	// ev1 should be delivered — all categories enabled by default.
	err = auditor.AuditEvent(audit.NewEvent("ev1", audit.Fields{"f1": "val"}))
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))
	assert.Equal(t, 1, out.EventCount(), "event should be delivered — all categories enabled by default")
}

// ---------------------------------------------------------------------------
// No outputs configured
// ---------------------------------------------------------------------------

func TestLogger_Audit_NoOutputs(t *testing.T) {

	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
	)
	require.NoError(t, err)

	// Should not error — events are validated and filtered but go nowhere.
	err = auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
	}))
	assert.NoError(t, err)
	require.NoError(t, auditor.Close())
}

// ---------------------------------------------------------------------------
// Config bounds tests
// ---------------------------------------------------------------------------

func TestNew_QueueSizeExceedsMax(t *testing.T) {
	_, err := audit.New(
		audit.WithQueueSize(audit.MaxQueueSize+1),
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrConfigInvalid)
	assert.Contains(t, err.Error(), "exceeds maximum")
}

func TestNew_ShutdownTimeoutExceedsMax(t *testing.T) {
	_, err := audit.New(
		audit.WithShutdownTimeout(audit.MaxShutdownTimeout+1),
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrConfigInvalid)
	assert.Contains(t, err.Error(), "exceeds maximum")
}

// ---------------------------------------------------------------------------
// OmitEmpty with non-string zero values
// ---------------------------------------------------------------------------

func TestLogger_Audit_OmitEmptyZeroInt(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	auditor := newTestAuditor(t, out, audit.WithOmitEmpty(), audit.WithValidationMode(audit.ValidationPermissive))

	err := auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
		"count":    0,     // zero int should be omitted
		"active":   false, // false bool should be omitted
	}))
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))

	ev := out.GetEvent(0)
	_, hasCount := ev["count"]
	assert.False(t, hasCount, "OmitEmpty should omit zero int")
	_, hasActive := ev["active"]
	assert.False(t, hasActive, "OmitEmpty should omit false bool")
}

// ---------------------------------------------------------------------------
// Shutdown with nil app_name stored
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Unsupported field value type — handled per ValidationMode (#595 B-43)
// ---------------------------------------------------------------------------

func TestLogger_Audit_UnsupportedFieldValueType_Permissive_CoercesAndDelivers(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	auditor := newTestAuditor(t, out, audit.WithValidationMode(audit.ValidationPermissive))

	// A channel is not in the supported Fields value vocabulary
	// (#595 B-43). Permissive mode silently coerces via
	// fmt.Sprintf("%v", v), so the event still delivers; the
	// receiving system sees a stringified channel address. This is
	// formatter-hostile output but preserves the audit-MUST-emit
	// invariant.
	ch := make(chan struct{})
	err := auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
		"bad":      ch,
	}))
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))
	require.Equal(t, 1, out.EventCount(), "permissive mode delivers coerced event")

	ev := out.GetEvent(0)
	require.Contains(t, ev, "bad")
	_, isString := ev["bad"].(string)
	assert.True(t, isString, "permissive coerces unsupported types to string")
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------

func TestLogger_Audit_NilFieldsNoRequiredFields(t *testing.T) {

	// Create a taxonomy with an event that has no required fields.
	tax := &audit.Taxonomy{
		Version:    1,
		Categories: map[string]*audit.CategoryDef{"misc": {Events: []string{"no_req"}}},
		Events: map[string]*audit.EventDef{
			"no_req": {Optional: []string{"info"}},
		},
	}

	out := testhelper.NewMockOutput("test")
	auditor, err := audit.New(
		audit.WithTaxonomy(tax),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, auditor.Close()) })

	// nil fields should work when there are no required fields.
	err = auditor.AuditEvent(audit.NewEvent("no_req", nil))
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))
}
