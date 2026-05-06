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
	"bytes"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/axonops/audit"
	"github.com/axonops/audit/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// MetadataWriter tests
// ---------------------------------------------------------------------------

// mockMetadataOutput implements both audit.Output and audit.MetadataWriter.
// It captures whether Write or WriteWithMetadata was called and records the
// last data and metadata received. All fields are guarded by mu so that the
// mock is safe to read from the test goroutine after auditor.Close() returns.
type mockMetadataOutput struct { //nolint:govet // fieldalignment: test mock
	mu                      sync.Mutex
	lastMeta                audit.EventMetadata
	calls                   []metadataCall
	lastData                []byte
	name                    string
	WriteErr                error
	callCount               int
	writeCalled             bool
	writeWithMetadataCalled bool
}

type metadataCall struct {
	meta audit.EventMetadata
	data []byte
}

var _ audit.Output = (*mockMetadataOutput)(nil)
var _ audit.MetadataWriter = (*mockMetadataOutput)(nil)

func newMockMetadataOutput(name string) *mockMetadataOutput {
	return &mockMetadataOutput{name: name}
}

func (m *mockMetadataOutput) Write(data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.writeCalled = true
	cp := make([]byte, len(data))
	copy(cp, data)
	m.lastData = cp
	m.callCount++
	return m.WriteErr
}

func (m *mockMetadataOutput) WriteWithMetadata(data []byte, meta audit.EventMetadata) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.writeWithMetadataCalled = true
	cp := make([]byte, len(data))
	copy(cp, data)
	m.lastData = cp
	m.lastMeta = meta
	m.callCount++
	m.calls = append(m.calls, metadataCall{data: cp, meta: meta})
	return m.WriteErr
}

func (m *mockMetadataOutput) Close() error { return nil }
func (m *mockMetadataOutput) Name() string { return m.name }

func (m *mockMetadataOutput) getWriteCalled() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.writeCalled
}

func (m *mockMetadataOutput) getWriteWithMetadataCalled() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.writeWithMetadataCalled
}

func (m *mockMetadataOutput) getLastMeta() audit.EventMetadata {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastMeta
}

func (m *mockMetadataOutput) getLastData() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]byte, len(m.lastData))
	copy(cp, m.lastData)
	return cp
}

func (m *mockMetadataOutput) getCalls() []metadataCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]metadataCall, len(m.calls))
	copy(cp, m.calls)
	return cp
}

// mockMetadataDeliveryOutput implements audit.Output, audit.MetadataWriter,
// and audit.DeliveryReporter — used by test 8 to verify metrics are skipped.
type mockMetadataDeliveryOutput struct {
	mockMetadataOutput
}

var _ audit.Output = (*mockMetadataDeliveryOutput)(nil)
var _ audit.MetadataWriter = (*mockMetadataDeliveryOutput)(nil)
var _ audit.DeliveryReporter = (*mockMetadataDeliveryOutput)(nil)

func newMockMetadataDeliveryOutput(name string) *mockMetadataDeliveryOutput {
	return &mockMetadataDeliveryOutput{
		mockMetadataOutput: mockMetadataOutput{name: name},
	}
}

func (m *mockMetadataDeliveryOutput) ReportsDelivery() bool { return true }

// TestMetadataWriter_ImplementingOutput_ReceivesMetadata verifies that when an
// output implements MetadataWriter, the library calls WriteWithMetadata instead
// of Write. This is the fundamental contract of the interface.
func TestMetadataWriter_ImplementingOutput_ReceivesMetadata(t *testing.T) {
	t.Parallel()
	out := newMockMetadataOutput("meta-out")

	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)

	err = auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
	}))
	require.NoError(t, err)

	// Close flushes all pending events before returning.
	require.NoError(t, auditor.Close())

	assert.True(t, out.getWriteWithMetadataCalled(),
		"WriteWithMetadata must be called for an output implementing MetadataWriter")
	assert.False(t, out.getWriteCalled(),
		"Write must NOT be called when WriteWithMetadata is available")
}

// TestMetadataWriter_NonImplementingOutput_ReceivesPlainWrite verifies that a
// standard output (no MetadataWriter) continues to receive the plain Write call.
func TestMetadataWriter_NonImplementingOutput_ReceivesPlainWrite(t *testing.T) {
	t.Parallel()
	out := testhelper.NewMockOutput("plain-out")

	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)

	err = auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
	}))
	require.NoError(t, err)

	require.NoError(t, auditor.Close())

	assert.Equal(t, 1, out.EventCount(),
		"plain Write must be called for an output that does not implement MetadataWriter")
}

// TestMetadataWriter_EventMetadata_FieldsCorrect verifies that the EventMetadata
// passed to WriteWithMetadata contains accurate values: exact event type string,
// the resolved severity, the correct category, and a non-zero timestamp within
// a reasonable window of the test.
func TestMetadataWriter_EventMetadata_FieldsCorrect(t *testing.T) {
	t.Parallel()

	// Build a taxonomy with an explicit severity so the resolved value is deterministic.
	sev := 8
	tax := &audit.Taxonomy{
		Version: 1,
		Categories: map[string]*audit.CategoryDef{
			"security": {Events: []string{"auth_failure"}, Severity: &sev},
		},
		Events: map[string]*audit.EventDef{
			"auth_failure": {Required: []string{"outcome", "actor_id"}},
		},
	}

	out := newMockMetadataOutput("meta-fields")
	before := time.Now()

	auditor, err := audit.New(
		audit.WithTaxonomy(tax),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)

	err = auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
	}))
	require.NoError(t, err)

	require.NoError(t, auditor.Close())
	after := time.Now()

	require.True(t, out.getWriteWithMetadataCalled(), "WriteWithMetadata must have been called")

	meta := out.getLastMeta()
	assert.Equal(t, "auth_failure", meta.EventType,
		"meta.EventType must match the emitted event type exactly")
	assert.Equal(t, 8, meta.Severity,
		"meta.Severity must match the taxonomy-resolved severity")
	assert.Equal(t, "security", meta.Category,
		"meta.Category must be the category the event was delivered under")
	assert.False(t, meta.Timestamp.IsZero(),
		"meta.Timestamp must not be the zero value")
	assert.False(t, meta.Timestamp.Before(before),
		"meta.Timestamp must not be before the test started")
	assert.False(t, meta.Timestamp.After(after),
		"meta.Timestamp must not be after the test ended")
}

// TestMetadataWriter_MultiCategory_CategoryVaries verifies that when an event
// belongs to two categories, WriteWithMetadata is called twice and each call
// carries a different Category value. The EventType and Severity must be
// identical across both calls.
func TestMetadataWriter_MultiCategory_CategoryVaries(t *testing.T) {
	t.Parallel()

	tax := &audit.Taxonomy{
		Version: 1,
		Categories: map[string]*audit.CategoryDef{
			"security": {Events: []string{"auth_failure"}},
			"access":   {Events: []string{"auth_failure"}},
		},
		Events: map[string]*audit.EventDef{
			"auth_failure": {Required: []string{"outcome"}},
		},
	}

	out := newMockMetadataOutput("multi-cat")

	auditor, err := audit.New(
		audit.WithTaxonomy(tax),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)

	err = auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome": "failure",
	}))
	require.NoError(t, err)

	require.NoError(t, auditor.Close())

	calls := out.getCalls()
	require.Equal(t, 2, len(calls),
		"event in 2 categories must produce 2 WriteWithMetadata calls, got %d", len(calls))

	categories := []string{calls[0].meta.Category, calls[1].meta.Category}
	assert.Contains(t, categories, "security",
		"one call must carry Category=security")
	assert.Contains(t, categories, "access",
		"one call must carry Category=access")
	assert.NotEqual(t, calls[0].meta.Category, calls[1].meta.Category,
		"the two category values must differ")
	assert.Equal(t, "auth_failure", calls[0].meta.EventType)
	assert.Equal(t, "auth_failure", calls[1].meta.EventType)
}

// TestMetadataWriter_UncategorisedEvent_EmptyCategory verifies that an event
// with no taxonomy categories results in a WriteWithMetadata call where
// meta.Category is the empty string.
func TestMetadataWriter_UncategorisedEvent_EmptyCategory(t *testing.T) {
	t.Parallel()

	// data_export is not placed in any category.
	tax := &audit.Taxonomy{
		Version: 1,
		Categories: map[string]*audit.CategoryDef{
			"write": {Events: []string{"user_create"}},
		},
		Events: map[string]*audit.EventDef{
			"user_create": {Required: []string{"outcome"}},
			"data_export": {Required: []string{"outcome"}},
		},
	}

	out := newMockMetadataOutput("uncat")

	auditor, err := audit.New(
		audit.WithTaxonomy(tax),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)

	err = auditor.AuditEvent(audit.NewEvent("data_export", audit.Fields{
		"outcome": "success",
	}))
	require.NoError(t, err)

	require.NoError(t, auditor.Close())

	require.True(t, out.getWriteWithMetadataCalled())

	meta := out.getLastMeta()
	assert.Equal(t, "data_export", meta.EventType)
	assert.Equal(t, "", meta.Category,
		"meta.Category must be empty for an uncategorised event")
}

// TestMetadataWriter_MetricsPreserved verifies that when WriteWithMetadata
// succeeds, the core auditor records RecordDelivery(name, "success"). This mirrors
// the same metrics contract that Write has.
func TestMetadataWriter_MetricsPreserved(t *testing.T) {
	t.Parallel()

	out := newMockMetadataOutput("mw-metrics")
	metrics := testhelper.NewMockMetrics()

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

	require.NoError(t, auditor.Close())

	assert.Greater(t, metrics.GetEventCount("mw-metrics", audit.EventSuccess), 0,
		"RecordDelivery(name, \"success\") must be called after a successful WriteWithMetadata")
	assert.Equal(t, 0, metrics.GetEventCount("mw-metrics", audit.EventError),
		"RecordDelivery(name, \"error\") must not be called on success")
	assert.Equal(t, 0, metrics.GetOutputErrorCount("mw-metrics"),
		"RecordOutputError must not be called on success")
}

// TestMetadataWriter_WriteError_RecordsMetrics verifies that when
// WriteWithMetadata returns an error, the core auditor calls both
// RecordOutputError and RecordDelivery(name, "error"), and does NOT call
// RecordDelivery(name, "success").
func TestMetadataWriter_WriteError_RecordsMetrics(t *testing.T) {
	t.Parallel()

	out := newMockMetadataOutput("mw-err-out")
	out.WriteErr = errors.New("write failed")
	metrics := testhelper.NewMockMetrics()

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

	require.NoError(t, auditor.Close())

	assert.Greater(t, metrics.GetEventCount("mw-err-out", audit.EventError), 0,
		"RecordDelivery(name, \"error\") must be called when WriteWithMetadata returns an error")
	assert.Greater(t, metrics.GetOutputErrorCount("mw-err-out"), 0,
		"RecordOutputError must be called when WriteWithMetadata returns an error")
	assert.Equal(t, 0, metrics.GetEventCount("mw-err-out", audit.EventSuccess),
		"RecordDelivery(name, \"success\") must not be called when WriteWithMetadata returns an error")
}

// TestMetadataWriter_DeliveryReporter_SkipsMetrics verifies that when an
// output implements all three interfaces (Output, MetadataWriter, and
// DeliveryReporter), the core auditor skips its own RecordDelivery and
// RecordOutputError calls — regardless of whether WriteWithMetadata
// succeeds or fails.
func TestMetadataWriter_DeliveryReporter_SkipsMetrics(t *testing.T) {
	t.Parallel()

	out := newMockMetadataDeliveryOutput("mw-dr")
	metrics := testhelper.NewMockMetrics()

	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(out, audit.WithRoute(&audit.EventRoute{})),
		audit.WithMetrics(metrics),
	)
	require.NoError(t, err)

	err = auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
	}))
	require.NoError(t, err)

	require.NoError(t, auditor.Close())

	// The event must have been delivered via WriteWithMetadata.
	assert.True(t, out.getWriteWithMetadataCalled(),
		"WriteWithMetadata must be called for an output that also implements DeliveryReporter")

	// The core auditor must not have called any metrics for this output.
	assert.Equal(t, 0, metrics.GetEventCount("mw-dr", audit.EventSuccess),
		"core auditor must not call RecordDelivery(success) for a MetadataWriter+DeliveryReporter output")
	assert.Equal(t, 0, metrics.GetEventCount("mw-dr", audit.EventError),
		"core auditor must not call RecordDelivery(error) for a MetadataWriter+DeliveryReporter output")
	assert.Equal(t, 0, metrics.GetOutputErrorCount("mw-dr"),
		"core auditor must not call RecordOutputError for a MetadataWriter+DeliveryReporter output")
}

// TestMetadataWriter_WithHMAC_ReceivesHMACData verifies that when HMAC is
// configured for an output, the data received by WriteWithMetadata already
// contains the _hmac field. HMAC is computed after all other transformations
// (field stripping, event_category) and must be visible to the metadata writer.
func TestMetadataWriter_WithHMAC_ReceivesHMACData(t *testing.T) {
	t.Parallel()

	out := newMockMetadataOutput("mw-hmac")

	tax := &audit.Taxonomy{
		Version:    1,
		Categories: map[string]*audit.CategoryDef{"write": {Events: []string{"ev1"}}},
		Events:     map[string]*audit.EventDef{"ev1": {Required: []string{"outcome"}}},
	}

	auditor, err := audit.New(
		audit.WithTaxonomy(tax),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(out, audit.WithHMAC(&audit.HMACConfig{
			Enabled: true,
			Salt: audit.HMACSalt{
				Version: "v1",
				Value:   []byte("hmac-test-salt-value!"),
			},
			Algorithm: "HMAC-SHA-256",
		})),
	)
	require.NoError(t, err)

	err = auditor.AuditEvent(audit.NewEvent("ev1", audit.Fields{"outcome": "success"}))
	require.NoError(t, err)

	require.NoError(t, auditor.Close())

	require.True(t, out.getWriteWithMetadataCalled())

	data := out.getLastData()
	require.NotEmpty(t, data, "WriteWithMetadata must receive non-empty data")

	// Parse the JSON payload and verify _hmac is present.
	var record map[string]interface{}
	require.NoError(t, json.Unmarshal(bytes.TrimRight(data, "\n"), &record),
		"data received by WriteWithMetadata must be valid JSON")
	hmacVal, ok := record["_hmac"]
	assert.True(t, ok, "data must contain the _hmac field when HMAC is configured")
	assert.NotEmpty(t, hmacVal, "_hmac field must not be empty")
}

// TestMetadataWriter_WithSensitivityExclusion_ReceivesStrippedData verifies
// that when an output is configured with sensitivity label exclusions, the data
// received by WriteWithMetadata has the excluded fields removed. The
// MetadataWriter sees the final, post-stripped payload.
func TestMetadataWriter_WithSensitivityExclusion_ReceivesStrippedData(t *testing.T) {
	t.Parallel()

	out := newMockMetadataOutput("mw-stripped")

	const taxYAML = `
version: 1
categories:
  write:
    events: [user_create]
sensitivity:
  labels:
    pii:
      description: "Personally identifiable information"
      fields: [email]
events:
  user_create:
    fields:
      outcome: {required: true}
      actor_id: {required: true}
      email:
        labels: [pii]
`
	tax, err := audit.ParseTaxonomyYAML([]byte(taxYAML))
	require.NoError(t, err)

	auditor, err := audit.New(
		audit.WithTaxonomy(tax),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		// Exclude PII — email must not appear in the data received by WriteWithMetadata.
		audit.WithNamedOutput(out, audit.WithExcludeLabels("pii")),
	)
	require.NoError(t, err)

	err = auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"email":    "alice@example.com",
	}))
	require.NoError(t, err)

	require.NoError(t, auditor.Close())

	require.True(t, out.getWriteWithMetadataCalled())

	data := out.getLastData()
	require.NotEmpty(t, data)

	var record map[string]interface{}
	require.NoError(t, json.Unmarshal(bytes.TrimRight(data, "\n"), &record),
		"data must be valid JSON")

	_, hasEmail := record["email"]
	assert.False(t, hasEmail,
		"the excluded PII field 'email' must not appear in data received by WriteWithMetadata")
	assert.Equal(t, "alice", record["actor_id"],
		"non-excluded fields must still be present in the data")
}

// TestMetadataWriter_WithEventCategory_DataAndMetaConsistent verifies that
// when SuppressEventCategory is false (zero value), the event_category field in the serialised
// data matches meta.Category. The library appends event_category to the
// payload before calling WriteWithMetadata, so both must agree.
func TestMetadataWriter_WithEventCategory_DataAndMetaConsistent(t *testing.T) {
	t.Parallel()

	out := newMockMetadataOutput("mw-cat")

	tax := &audit.Taxonomy{
		Version: 1,

		Categories: map[string]*audit.CategoryDef{
			"security": {Events: []string{"auth_failure"}},
		},
		Events: map[string]*audit.EventDef{
			"auth_failure": {Required: []string{"outcome"}},
		},
	}

	auditor, err := audit.New(
		audit.WithTaxonomy(tax),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)

	err = auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome": "failure",
	}))
	require.NoError(t, err)

	require.NoError(t, auditor.Close())

	require.True(t, out.getWriteWithMetadataCalled())

	data := out.getLastData()
	meta := out.getLastMeta()

	var record map[string]interface{}
	require.NoError(t, json.Unmarshal(bytes.TrimRight(data, "\n"), &record),
		"data must be valid JSON")

	eventCatInData, ok := record["event_category"]
	require.True(t, ok,
		"event_category must appear in serialised data when SuppressEventCategory=false")
	assert.Equal(t, meta.Category, eventCatInData,
		"event_category in data must equal meta.Category")
}

// TestMetadataWriter_MixedOutputs_IsolationOnError verifies output isolation:
// when the MetadataWriter output returns a write error, the standard output
// (which does not implement MetadataWriter) still receives the event. A
// failing output must not block delivery to other outputs.
func TestMetadataWriter_MixedOutputs_IsolationOnError(t *testing.T) {
	t.Parallel()

	// MetadataWriter output that always errors.
	failingMW := newMockMetadataOutput("mw-failing")
	failingMW.WriteErr = errors.New("metadata write failed")

	// Standard output that should always succeed regardless.
	successOut := testhelper.NewMockOutput("standard-out")

	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(failingMW),
		audit.WithNamedOutput(successOut),
	)
	require.NoError(t, err)

	err = auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
	}))
	require.NoError(t, err)

	require.NoError(t, auditor.Close())

	// The MetadataWriter output attempted delivery and failed.
	assert.True(t, failingMW.getWriteWithMetadataCalled(),
		"WriteWithMetadata must have been called on the failing output")

	// The standard output must have received the event despite the other output failing.
	assert.Equal(t, 1, successOut.EventCount(),
		"the standard output must receive the event even when the MetadataWriter output errors")
}

// TestMetadataWriter_CachedAssertion_Correct verifies the type assertion caching
// in prepareOutputEntries: an output implementing MetadataWriter must produce a
// non-nil metadataWriter field on the outputEntry, while a plain output must
// produce nil. This is an observable-behaviour test — the cache drives dispatch.
// We verify it by checking which Write path was taken, not by inspecting internals.
func TestMetadataWriter_CachedAssertion_Correct(t *testing.T) {
	t.Parallel()

	mwOut := newMockMetadataOutput("mw-cached")
	plainOut := testhelper.NewMockOutput("plain-cached")

	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(mwOut),
		audit.WithNamedOutput(plainOut),
	)
	require.NoError(t, err)

	err = auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
	}))
	require.NoError(t, err)

	require.NoError(t, auditor.Close())

	// The MetadataWriter output must have gone through WriteWithMetadata.
	assert.True(t, mwOut.getWriteWithMetadataCalled(),
		"cached metadataWriter assertion must route to WriteWithMetadata for implementing output")
	assert.False(t, mwOut.getWriteCalled(),
		"Write must not be called when metadataWriter cache is non-nil")

	// The plain output must have gone through Write.
	assert.Equal(t, 1, plainOut.EventCount(),
		"cached nil metadataWriter assertion must route to Write for non-implementing output")
}

func TestTimezoneAlwaysPopulated(t *testing.T) {
	t.Parallel()
	// Create an auditor with NO timezone config — it should auto-detect.
	tax := &audit.Taxonomy{
		Version: 1,
		Events:  map[string]*audit.EventDef{"test_event": {}},
		Categories: map[string]*audit.CategoryDef{
			"test": {Events: []string{"test_event"}},
		},
	}
	var buf bytes.Buffer
	out, err := audit.NewStdoutOutput(audit.StdoutConfig{Writer: &buf})
	require.NoError(t, err)

	auditor, err := audit.New(
		audit.WithTaxonomy(tax),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
		audit.WithAppName("test"),
		audit.WithHost("test"),
		// No WithTimezone — should auto-detect
	)
	require.NoError(t, err)

	require.NoError(t, auditor.AuditEvent(audit.NewEvent("test_event", audit.Fields{})))
	require.NoError(t, auditor.Close())

	assert.Contains(t, buf.String(), `"timezone":`,
		"timezone must always be present in output even when not explicitly configured")
}

func TestTimezoneAutoDetect(t *testing.T) {
	t.Parallel()
	tax := &audit.Taxonomy{
		Version: 1,
		Events:  map[string]*audit.EventDef{"test_event": {}},
		Categories: map[string]*audit.CategoryDef{
			"test": {Events: []string{"test_event"}},
		},
	}
	var buf bytes.Buffer
	out, err := audit.NewStdoutOutput(audit.StdoutConfig{Writer: &buf})
	require.NoError(t, err)

	auditor, err := audit.New(
		audit.WithTaxonomy(tax),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
		audit.WithAppName("test"),
		audit.WithHost("test"),
		// No WithTimezone
	)
	require.NoError(t, err)

	require.NoError(t, auditor.AuditEvent(audit.NewEvent("test_event", audit.Fields{})))
	require.NoError(t, auditor.Close())

	// Auto-detected timezone should match the system timezone.
	expected := time.Now().Location().String()
	assert.Contains(t, buf.String(), `"timezone":"`+expected+`"`,
		"auto-detected timezone should match system timezone")
}

func TestTimezoneOverride(t *testing.T) {
	t.Parallel()
	tax := &audit.Taxonomy{
		Version: 1,
		Events:  map[string]*audit.EventDef{"test_event": {}},
		Categories: map[string]*audit.CategoryDef{
			"test": {Events: []string{"test_event"}},
		},
	}
	var buf bytes.Buffer
	out, err := audit.NewStdoutOutput(audit.StdoutConfig{Writer: &buf})
	require.NoError(t, err)

	auditor, err := audit.New(
		audit.WithTaxonomy(tax),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
		audit.WithAppName("test"),
		audit.WithHost("test"),
		audit.WithTimezone("America/New_York"),
	)
	require.NoError(t, err)

	require.NoError(t, auditor.AuditEvent(audit.NewEvent("test_event", audit.Fields{})))
	require.NoError(t, auditor.Close())

	assert.Contains(t, buf.String(), `"timezone":"America/New_York"`,
		"timezone override should appear in output")
	assert.NotContains(t, buf.String(), `"timezone":"Local"`,
		"auto-detected timezone should not appear when overridden")
}
