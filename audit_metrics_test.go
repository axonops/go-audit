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
	"errors"
	"testing"
	"time"

	"github.com/axonops/audit"
	"github.com/axonops/audit/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Metrics instrumentation tests (#36)
// ---------------------------------------------------------------------------

func TestAudit_UnknownEventType_RecordsValidationError(t *testing.T) {
	metrics := testhelper.NewMockMetrics()
	out := testhelper.NewMockOutput("test")
	auditor := newTestAuditor(t, out,
		audit.WithMetrics(metrics))

	_ = auditor.AuditEvent(audit.NewEvent("nonexistent", audit.Fields{}))

	metrics.Mu.Lock()
	defer metrics.Mu.Unlock()
	assert.Equal(t, 1, metrics.ValidationErrors["nonexistent"])
}

func TestAudit_MissingRequiredField_RecordsValidationError(t *testing.T) {
	metrics := testhelper.NewMockMetrics()
	out := testhelper.NewMockOutput("test")
	auditor := newTestAuditor(t, out,
		audit.WithMetrics(metrics))

	_ = auditor.AuditEvent(audit.NewEvent("schema_register", audit.Fields{"outcome": "ok"}))

	metrics.Mu.Lock()
	defer metrics.Mu.Unlock()
	assert.Equal(t, 1, metrics.ValidationErrors["schema_register"])
}

func TestAudit_UnknownFieldStrict_RecordsValidationError(t *testing.T) {
	metrics := testhelper.NewMockMetrics()
	out := testhelper.NewMockOutput("test")
	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
		audit.WithMetrics(metrics),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditor.Close() })

	_ = auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "fail",
		"actor_id": "bob",
		"bogus":    "val",
	}))

	metrics.Mu.Lock()
	defer metrics.Mu.Unlock()
	assert.Equal(t, 1, metrics.ValidationErrors["auth_failure"])
}

func TestAudit_FilteredEvent_RecordsFiltered(t *testing.T) {
	metrics := testhelper.NewMockMetrics()
	out := testhelper.NewMockOutput("test")
	auditor := newTestAuditor(t, out,
		audit.WithMetrics(metrics))

	// Disable "read" category at runtime, then emit an event.
	require.NoError(t, auditor.DisableCategory("read"))
	_ = auditor.AuditEvent(audit.NewEvent("schema_read", audit.Fields{"outcome": "ok"}))

	metrics.Mu.Lock()
	defer metrics.Mu.Unlock()
	assert.Equal(t, 1, metrics.GlobalFiltered["schema_read"])
}

func TestAudit_FilteredEventOverride_RecordsFiltered(t *testing.T) {
	metrics := testhelper.NewMockMetrics()
	out := testhelper.NewMockOutput("test")
	auditor := newTestAuditor(t, out,
		audit.WithMetrics(metrics))

	// Disable a specific event in an enabled category.
	require.NoError(t, auditor.DisableEvent("schema_register"))

	_ = auditor.AuditEvent(audit.NewEvent("schema_register", audit.Fields{
		"outcome":  "ok",
		"actor_id": "alice",
		"subject":  "test",
	}))

	metrics.Mu.Lock()
	defer metrics.Mu.Unlock()
	assert.Equal(t, 1, metrics.GlobalFiltered["schema_register"])
}

func TestProcessEntry_SerializationError_RecordsMetric(t *testing.T) {
	metrics := testhelper.NewMockMetrics()
	out := testhelper.NewMockOutput("test")
	badFormatter := &stubFormatter{
		fn: func(_ time.Time, _ string, _ audit.Fields, _ *audit.EventDef) ([]byte, error) {
			return nil, errors.New("format failed")
		},
	}
	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
		audit.WithFormatter(badFormatter),
		audit.WithMetrics(metrics),
	)
	require.NoError(t, err)

	err = auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "fail",
		"actor_id": "bob",
	}))
	require.NoError(t, err)

	// Close drains the event through processEntry, triggering the
	// serialization error metric.
	require.NoError(t, auditor.Close())

	metrics.Mu.Lock()
	defer metrics.Mu.Unlock()
	assert.Greater(t, metrics.SerializationErrors["auth_failure"], 0)
}

func TestEmitShutdown_BufferFull_RecordsBufferDrop(t *testing.T) {
	metrics := testhelper.NewMockMetrics()
	out := &blockingOutput{name: "stuck", blockCh: make(chan struct{})}
	t.Cleanup(func() { close(out.blockCh) })

	auditor, err := audit.New(
		audit.WithQueueSize(1),
		audit.WithShutdownTimeout(50*time.Millisecond),
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
		audit.WithMetrics(metrics),
	)
	require.NoError(t, err)

	// Fill the buffer.
	for i := 0; i < 100; i++ {
		_ = auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
			"outcome":  "fail",
			"actor_id": "bob",
		}))
	}

	_ = auditor.Close()

	metrics.Mu.Lock()
	defer metrics.Mu.Unlock()
	assert.Greater(t, metrics.BufferDrops, 0, "emitShutdown should call RecordBufferDrop on buffer full")
}

func TestAudit_NilMetrics_NoPanic(t *testing.T) {
	// Verify that all metrics paths handle nil metrics without panic,
	// including the async serialization error path in processEntry.
	badFormatter := &stubFormatter{
		fn: func(_ time.Time, _ string, _ audit.Fields, _ *audit.EventDef) ([]byte, error) {
			return nil, errors.New("format failed")
		},
	}
	out := testhelper.NewMockOutput("test")
	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
		audit.WithFormatter(badFormatter),
		// No WithMetrics -- metrics is nil.
	)
	require.NoError(t, err)

	// Validation error path (unknown event type).
	_ = auditor.AuditEvent(audit.NewEvent("nonexistent", audit.Fields{}))
	// Missing required field path.
	_ = auditor.AuditEvent(audit.NewEvent("schema_register", audit.Fields{"outcome": "ok"}))
	// Filtered event path.
	_ = auditor.AuditEvent(audit.NewEvent("schema_read", audit.Fields{"outcome": "ok"}))
	// Normal path (will trigger serialization error in drain goroutine).
	_ = auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{"outcome": "fail", "actor_id": "bob"}))

	// Close drains the bad event through processEntry -> serialize error
	// with nil metrics. Must not panic.
	require.NoError(t, auditor.Close())
}

// ---------------------------------------------------------------------------
// DeliveryReporter — recordWrite skips core metrics when selfReports=true
// ---------------------------------------------------------------------------

// deliveryReporterOutput is a mock output that implements DeliveryReporter.
// It reports its own delivery, so the core auditor must NOT call RecordDelivery
// or RecordOutputError for it.
type deliveryReporterOutput struct {
	writeErrToReturn error
	testhelper.MockOutput
}

func newDeliveryReporterOutput(name string) *deliveryReporterOutput {
	return &deliveryReporterOutput{
		MockOutput: *testhelper.NewMockOutput(name),
	}
}

func (d *deliveryReporterOutput) ReportsDelivery() bool { return true }

func (d *deliveryReporterOutput) Write(data []byte) error {
	if d.writeErrToReturn != nil {
		return d.writeErrToReturn
	}
	return d.MockOutput.Write(data)
}

var _ audit.DeliveryReporter = (*deliveryReporterOutput)(nil)
var _ audit.Output = (*deliveryReporterOutput)(nil)

func TestWriteToOutput_DeliveryReporter_SuccessSkipsCoreMetrics(t *testing.T) {
	// When an output satisfies DeliveryReporter and ReportsDelivery()
	// returns true, the core auditor must NOT call RecordDelivery on success.
	metrics := testhelper.NewMockMetrics()
	out := newDeliveryReporterOutput("self-reporting")

	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(out, audit.WithRoute(&audit.EventRoute{})),
		audit.WithMetrics(metrics),
	)
	require.NoError(t, err)

	require.NoError(t, auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
	})))
	require.NoError(t, auditor.Close())

	// The self-reporting output received the event.
	assert.Equal(t, 1, out.EventCount())

	// The core auditor must not have called RecordDelivery for this output.
	assert.Equal(t, 0, metrics.GetEventCount("self-reporting", audit.EventSuccess),
		"core auditor must not call RecordDelivery(success) for DeliveryReporter outputs")
	assert.Equal(t, 0, metrics.GetEventCount("self-reporting", audit.EventError),
		"core auditor must not call RecordDelivery(error) for DeliveryReporter outputs")
}

func TestWriteToOutput_DeliveryReporter_ErrorSkipsCoreMetrics(t *testing.T) {
	// When a DeliveryReporter output fails on Write, the core auditor must
	// NOT call RecordDelivery or RecordOutputError — the output is responsible.
	metrics := testhelper.NewMockMetrics()
	out := newDeliveryReporterOutput("self-reporting-fail")
	out.writeErrToReturn = errors.New("delivery failed")

	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(out, audit.WithRoute(&audit.EventRoute{})),
		audit.WithMetrics(metrics),
	)
	require.NoError(t, err)

	require.NoError(t, auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
	})))
	require.NoError(t, auditor.Close())

	// Core auditor must not record any metrics for the self-reporting output.
	assert.Equal(t, 0, metrics.GetEventCount("self-reporting-fail", audit.EventSuccess),
		"core auditor must not call RecordDelivery(success) for DeliveryReporter outputs")
	assert.Equal(t, 0, metrics.GetEventCount("self-reporting-fail", audit.EventError),
		"core auditor must not call RecordDelivery(error) for DeliveryReporter outputs")

	metrics.Mu.Lock()
	errCount := metrics.OutputErrors["self-reporting-fail"]
	metrics.Mu.Unlock()
	assert.Equal(t, 0, errCount,
		"core auditor must not call RecordOutputError for DeliveryReporter outputs")
}

func TestWriteToOutput_NonDeliveryReporter_SuccessRecordsCoreMetrics(t *testing.T) {
	// A plain output (not DeliveryReporter) must have RecordDelivery(success)
	// called by the core auditor on a successful write.
	metrics := testhelper.NewMockMetrics()
	out := testhelper.NewMockOutput("plain")

	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
		audit.WithMetrics(metrics),
	)
	require.NoError(t, err)

	require.NoError(t, auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
	})))
	require.NoError(t, auditor.Close())

	assert.Greater(t, metrics.GetEventCount("plain", audit.EventSuccess), 0,
		"core auditor must call RecordDelivery(success) for plain (non-DeliveryReporter) outputs")
}

// ---------------------------------------------------------------------------
// isZeroValue — integer and float type branches
// ---------------------------------------------------------------------------

// TestIsZeroValue_NumericTypeBranches_Direct exercises the float32,
// uint, and uint64 branches in isZeroValue directly. They are no
// longer reachable through AuditEvent: #595 B-43 coerces those types
// to string in the validator before OmitEmpty consults isZeroValue.
// The branches are kept for forward-compat (a future PR could add
// these types to the supported vocabulary, or callers might invoke
// the helper through a different path), and direct coverage avoids
// dead-code drift.
func TestIsZeroValue_NumericTypeBranches_Direct(t *testing.T) {
	t.Parallel()
	cases := []struct {
		v    any
		name string
		want bool
	}{
		{float32(0), "zero float32", true},
		{float32(3.14), "non-zero float32", false},
		{uint(0), "zero uint", true},
		{uint(99), "non-zero uint", false},
		{uint64(0), "zero uint64", true},
		{uint64(1), "non-zero uint64", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, audit.IsZeroValueForTest(tc.v))
		})
	}
}

func TestLogger_Audit_OmitEmpty_NumericTypeBranches(t *testing.T) {
	// Exercises the int32, float32, uint, uint64 branches in isZeroValue
	// via the OmitEmpty path through the JSON formatter.
	out := testhelper.NewMockOutput("test")
	auditor := newTestAuditor(t, out, audit.WithOmitEmpty(), audit.WithValidationMode(audit.ValidationPermissive))

	tests := []struct {
		name    string
		fields  audit.Fields
		wantKey string
		wantIn  bool
	}{
		{
			name:    "zero int32 omitted",
			fields:  audit.Fields{"outcome": "ok", "actor_id": "x", "val": int32(0)},
			wantKey: "val",
			wantIn:  false,
		},
		{
			name:    "non-zero int32 included",
			fields:  audit.Fields{"outcome": "ok", "actor_id": "x", "val": int32(7)},
			wantKey: "val",
			wantIn:  true,
		},
		// float32, uint, uint64 are not in the #595 B-43 supported
		// Fields value vocabulary and are coerced to string by the
		// validator in non-strict modes — exercising them here would
		// no longer test the OmitEmpty numeric-type branches in
		// isZeroValue. The supported numeric types (int, int32, int64,
		// float64) are covered above and below this comment.
		{
			name:    "zero int64 omitted",
			fields:  audit.Fields{"outcome": "ok", "actor_id": "x", "val": int64(0)},
			wantKey: "val",
			wantIn:  false,
		},
		{
			name:    "non-zero int64 included",
			fields:  audit.Fields{"outcome": "ok", "actor_id": "x", "val": int64(42)},
			wantKey: "val",
			wantIn:  true,
		},
		{
			name:    "zero float64 omitted",
			fields:  audit.Fields{"outcome": "ok", "actor_id": "x", "val": float64(0)},
			wantKey: "val",
			wantIn:  false,
		},
		{
			name:    "non-zero float64 included",
			fields:  audit.Fields{"outcome": "ok", "actor_id": "x", "val": float64(2.71)},
			wantKey: "val",
			wantIn:  true,
		},
		{
			name: "slice value not omitted (default branch)",
			// A non-nil slice hits the default branch in isZeroValue, which
			// returns false (not a zero value), so the field is included.
			fields:  audit.Fields{"outcome": "ok", "actor_id": "x", "val": []string{"a"}},
			wantKey: "val",
			wantIn:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use a fresh output per subtest to avoid event ordering issues.
			subOut := testhelper.NewMockOutput("sub-" + tt.name)
			subLogger, err := audit.New(
				audit.WithOmitEmpty(),
				audit.WithValidationMode(audit.ValidationPermissive),
				audit.WithTaxonomy(testhelper.ValidTaxonomy()),
				audit.WithAppName("test-app"),
				audit.WithHost("test-host"),
				audit.WithOutputs(subOut),
			)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, subLogger.Close()) })

			require.NoError(t, subLogger.AuditEvent(audit.NewEvent("auth_failure", tt.fields)))
			require.True(t, subOut.WaitForEvents(1, 2*time.Second))

			ev := subOut.GetEvent(0)
			_, found := ev[tt.wantKey]
			if tt.wantIn {
				assert.True(t, found, "field %q should be present when non-zero", tt.wantKey)
			} else {
				assert.False(t, found, "field %q should be omitted when zero", tt.wantKey)
			}
		})
	}

	// Prevent unused warning for the outer auditor.
	require.NoError(t, auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{"outcome": "ok", "actor_id": "x"})))
	_ = out
}

// ---------------------------------------------------------------------------
// Metrics tests
// ---------------------------------------------------------------------------

func TestLogger_Audit_MetricsRecordSuccess(t *testing.T) {

	out := testhelper.NewMockOutput("test-out")
	metrics := testhelper.NewMockMetrics()
	auditor := newTestAuditor(t, out,
		audit.WithMetrics(metrics))

	err := auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
	}))
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))

	// Wait for the metric to be recorded — RecordDelivery fires after
	// Write returns, so WaitForEvents alone is insufficient.
	require.True(t, metrics.WaitForMetric("test-out:success", 1, 2*time.Second),
		"timed out waiting for success metric")
}

func TestLogger_Audit_MetricsRecordOutputError(t *testing.T) {

	metrics := testhelper.NewMockMetrics()
	out := &errorWriteOutput{name: "bad-write"}
	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
		audit.WithMetrics(metrics),
	)
	require.NoError(t, err)

	err = auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
	}))
	require.NoError(t, err)

	// Close drains all pending events and completes metric recording.
	require.NoError(t, auditor.Close())

	assert.Greater(t, metrics.GetEventCount("bad-write", audit.EventError), 0)
	assert.Greater(t, metrics.GetOutputErrorCount("bad-write"), 0)
}

type errorWriteOutput struct {
	name string
}

func (e *errorWriteOutput) Write(_ []byte) error { return errors.New("write failed") }
func (e *errorWriteOutput) Close() error         { return nil }
func (e *errorWriteOutput) Name() string         { return e.name }
