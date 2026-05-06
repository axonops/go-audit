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
	"strings"
	"testing"
	"time"

	"github.com/axonops/audit"
	"github.com/axonops/audit/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Audit call validation tests
// ---------------------------------------------------------------------------

func TestLogger_Audit_ValidCall(t *testing.T) {
	t.Parallel()

	out := testhelper.NewMockOutput("test")
	auditor := newTestAuditor(t, out)

	err := auditor.AuditEvent(audit.NewEvent("schema_register", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "my-topic",
	}))
	require.NoError(t, err)

	require.True(t, out.WaitForEvents(1, 2*time.Second), "expected 1 event")
	ev := out.GetEvent(0)
	assert.Equal(t, "schema_register", ev["event_type"])
	assert.Equal(t, "success", ev["outcome"])
	assert.Equal(t, "alice", ev["actor_id"])
	assert.NotEmpty(t, ev["timestamp"])
}

func TestLogger_Audit_MissingRequiredField(t *testing.T) {
	t.Parallel()

	out := testhelper.NewMockOutput("test")
	auditor := newTestAuditor(t, out)

	err := auditor.AuditEvent(audit.NewEvent("schema_register", audit.Fields{
		"outcome": "success",
		// missing actor_id and subject
	}))
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrValidation)
	assert.ErrorIs(t, err, audit.ErrMissingRequiredField)
	assert.Contains(t, err.Error(), "missing required fields")
	assert.Contains(t, err.Error(), "actor_id")
	assert.Contains(t, err.Error(), "subject")
}

func TestLogger_Audit_MissingSingleRequiredField(t *testing.T) {
	t.Parallel()

	out := testhelper.NewMockOutput("test")
	auditor := newTestAuditor(t, out)

	err := auditor.AuditEvent(audit.NewEvent("schema_register", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		// missing subject
	}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "subject")
}

func TestLogger_Audit_UnknownEventType(t *testing.T) {
	t.Parallel()

	out := testhelper.NewMockOutput("test")
	auditor := newTestAuditor(t, out)

	err := auditor.AuditEvent(audit.NewEvent("schema_registr", audit.Fields{}))
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrValidation)
	assert.ErrorIs(t, err, audit.ErrUnknownEventType)
	assert.Contains(t, err.Error(), "unknown event type")
	assert.Contains(t, err.Error(), "schema_registr")
}

func TestLogger_Audit_UnknownFieldStrict(t *testing.T) {
	t.Parallel()

	out := testhelper.NewMockOutput("test")
	auditor := newTestAuditor(t, out)

	err := auditor.AuditEvent(audit.NewEvent("schema_register", audit.Fields{
		"outcome":     "success",
		"actor_id":    "alice",
		"subject":     "my-topic",
		"bogus_field": "value",
	}))
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrValidation)
	assert.ErrorIs(t, err, audit.ErrUnknownField)
	assert.Contains(t, err.Error(), "unknown fields")
	assert.Contains(t, err.Error(), "bogus_field")
}

func TestLogger_Audit_UnknownFieldWarn(t *testing.T) {
	t.Parallel()

	out := testhelper.NewMockOutput("test")
	auditor := newTestAuditor(t, out, audit.WithValidationMode(audit.ValidationWarn))

	err := auditor.AuditEvent(audit.NewEvent("schema_register", audit.Fields{
		"outcome":     "success",
		"actor_id":    "alice",
		"subject":     "my-topic",
		"bogus_field": "value",
	}))
	// Warn mode: no error, event accepted.
	assert.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))
}

func TestLogger_Audit_UnknownFieldPermissive(t *testing.T) {
	t.Parallel()

	out := testhelper.NewMockOutput("test")
	auditor := newTestAuditor(t, out, audit.WithValidationMode(audit.ValidationPermissive))

	err := auditor.AuditEvent(audit.NewEvent("schema_register", audit.Fields{
		"outcome":     "success",
		"actor_id":    "alice",
		"subject":     "my-topic",
		"bogus_field": "value",
	}))
	assert.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))
}

// ---------------------------------------------------------------------------
// Reserved standard fields (#237)
// ---------------------------------------------------------------------------

func TestLogger_Audit_ReservedStandardField_AcceptedInStrictMode(t *testing.T) {
	t.Parallel()
	tax := &audit.Taxonomy{
		Version:    1,
		Categories: map[string]*audit.CategoryDef{"write": {Events: []string{"ev1"}}},
		Events: map[string]*audit.EventDef{
			"ev1": {Required: []string{"marker"}},
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

	// source_ip is a reserved standard field — accepted without declaration.
	err = auditor.AuditEvent(audit.NewEvent("ev1", audit.Fields{
		"marker":    "test",
		"source_ip": "10.0.0.1",
		"reason":    "test_reason",
	}))
	assert.NoError(t, err)
}

func TestLogger_Audit_ReservedStandardField_StillRejectsUnknown(t *testing.T) {
	t.Parallel()
	tax := &audit.Taxonomy{
		Version:    1,
		Categories: map[string]*audit.CategoryDef{"write": {Events: []string{"ev1"}}},
		Events: map[string]*audit.EventDef{
			"ev1": {Required: []string{"marker"}},
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

	// "foobar" is NOT a reserved standard field — rejected in strict mode.
	err = auditor.AuditEvent(audit.NewEvent("ev1", audit.Fields{
		"marker":    "test",
		"source_ip": "10.0.0.1",
		"foobar":    "unknown",
	}))
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrValidation)
	assert.ErrorIs(t, err, audit.ErrUnknownField)
	assert.Contains(t, err.Error(), "unknown fields")
	assert.Contains(t, err.Error(), "foobar")
	assert.NotContains(t, err.Error(), "source_ip")
}

func TestWithAppName_Empty_ReturnsError(t *testing.T) {
	t.Parallel()
	_, err := audit.New(
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithAppName(""),
		audit.WithHost("test-host"),
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrConfigInvalid)
	assert.Contains(t, err.Error(), "app_name must not be empty")
}

func TestWithAppName_ExceedsMaxLength(t *testing.T) {
	t.Parallel()
	// 256 bytes — one byte over the 255-byte maximum.
	_, err := audit.New(
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithAppName(strings.Repeat("a", 256)),
		audit.WithHost("test-host"),
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrConfigInvalid)
	assert.Contains(t, err.Error(), "app_name exceeds maximum length of 255 bytes")
}

func TestWithAppName_AtMaxLength(t *testing.T) {
	t.Parallel()
	// 255 bytes — exactly at the limit, must be accepted.
	out := testhelper.NewMockOutput("test")
	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
		audit.WithAppName(strings.Repeat("a", 255)),
	)
	require.NoError(t, err, "255-byte app_name is at the limit and must be accepted")
	t.Cleanup(func() { require.NoError(t, auditor.Close()) })
}

func TestWithHost_Empty_ReturnsError(t *testing.T) {
	t.Parallel()
	_, err := audit.New(
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithHost(""),
		audit.WithAppName("test-app"),
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrConfigInvalid)
	assert.Contains(t, err.Error(), "host must not be empty")
}

func TestWithHost_ExceedsMaxLength(t *testing.T) {
	t.Parallel()
	// 256 bytes — one byte over the 255-byte maximum.
	_, err := audit.New(
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithHost(strings.Repeat("h", 256)),
		audit.WithAppName("test-app"),
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrConfigInvalid)
	assert.Contains(t, err.Error(), "host exceeds maximum length of 255 bytes")
}

func TestWithHost_AtMaxLength(t *testing.T) {
	t.Parallel()
	// 255 bytes — exactly at the limit, must be accepted.
	out := testhelper.NewMockOutput("test")
	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
		audit.WithHost(strings.Repeat("h", 255)),
	)
	require.NoError(t, err, "255-byte host is at the limit and must be accepted")
	t.Cleanup(func() { require.NoError(t, auditor.Close()) })
}

func TestWithTimezone_Empty_ReturnsError(t *testing.T) {
	t.Parallel()
	_, err := audit.New(
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithTimezone(""),
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrConfigInvalid)
	assert.Contains(t, err.Error(), "timezone must not be empty")
}

func TestWithTimezone_ExceedsMaxLength(t *testing.T) {
	t.Parallel()
	// 65 bytes — one byte over the 64-byte maximum.
	_, err := audit.New(
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithTimezone(strings.Repeat("Z", 65)),
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrConfigInvalid)
	assert.Contains(t, err.Error(), "timezone exceeds maximum length of 64 bytes")
}

func TestWithTimezone_AtMaxLength(t *testing.T) {
	t.Parallel()
	// 64 bytes — exactly at the limit, must be accepted.
	out := testhelper.NewMockOutput("test")
	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
		audit.WithTimezone(strings.Repeat("Z", 64)),
	)
	require.NoError(t, err, "64-byte timezone is at the limit and must be accepted")
	t.Cleanup(func() { require.NoError(t, auditor.Close()) })
}

func TestWithStandardFieldDefaults_InvalidKey(t *testing.T) {
	t.Parallel()
	// "bogus" is not a reserved standard field and must be rejected.
	_, err := audit.New(
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithStandardFieldDefaults(map[string]any{"bogus": "value"}),
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrConfigInvalid)
	assert.Contains(t, err.Error(), "bogus")
	assert.Contains(t, err.Error(), "not a reserved standard field")
}

func TestLogger_FrameworkFields_InOutput(t *testing.T) {
	t.Parallel()
	out := testhelper.NewMockOutput("test")
	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
		audit.WithAppName("testapp"),
		audit.WithHost("testhost"),
		audit.WithTimezone("America/New_York"),
	)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, auditor.Close()) })

	require.NoError(t, auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
	})))
	require.True(t, out.WaitForEvents(1, 2*time.Second))

	record := out.GetEvent(0)
	assert.Equal(t, "testapp", record["app_name"])
	assert.Equal(t, "testhost", record["host"])
	assert.Equal(t, "America/New_York", record["timezone"])
	assert.NotNil(t, record["pid"], "pid should always be present")
}

func TestLogger_Timezone_AutoDetected(t *testing.T) {
	t.Parallel()
	out := testhelper.NewMockOutput("test")
	// No WithTimezone — timezone should auto-detect from system.
	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, auditor.Close()) })

	require.NoError(t, auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
	})))
	require.True(t, out.WaitForEvents(1, 2*time.Second))

	record := out.GetEvent(0)
	tz, ok := record["timezone"]
	assert.True(t, ok, "timezone should be auto-detected when not configured")
	assert.NotEmpty(t, tz, "auto-detected timezone should be non-empty")
	assert.Equal(t, time.Now().Location().String(), tz, "should match system timezone")
}

// ---------------------------------------------------------------------------
// Standard field defaults (#237)
// ---------------------------------------------------------------------------

func TestWithStandardFieldDefaults_Applied(t *testing.T) {
	t.Parallel()
	out := testhelper.NewMockOutput("test")
	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
		audit.WithStandardFieldDefaults(map[string]any{"source_ip": "10.0.0.1"}),
	)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, auditor.Close()) })

	require.NoError(t, auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
	})))
	require.True(t, out.WaitForEvents(1, 2*time.Second))

	record := out.GetEvent(0)
	assert.Equal(t, "10.0.0.1", record["source_ip"], "default should be applied")
}

func TestWithStandardFieldDefaults_PerEventOverride(t *testing.T) {
	t.Parallel()
	out := testhelper.NewMockOutput("test")
	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
		audit.WithStandardFieldDefaults(map[string]any{"source_ip": "10.0.0.1"}),
	)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, auditor.Close()) })

	require.NoError(t, auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"outcome":   "success",
		"actor_id":  "alice",
		"source_ip": "192.168.1.1",
	})))
	require.True(t, out.WaitForEvents(1, 2*time.Second))

	record := out.GetEvent(0)
	assert.Equal(t, "192.168.1.1", record["source_ip"], "per-event value should override default")
}

func TestWithStandardFieldDefaults_EmptyStringOverride(t *testing.T) {
	t.Parallel()
	out := testhelper.NewMockOutput("test")
	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
		audit.WithStandardFieldDefaults(map[string]any{"source_ip": "10.0.0.1"}),
	)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, auditor.Close()) })

	require.NoError(t, auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"outcome":   "success",
		"actor_id":  "alice",
		"source_ip": "",
	})))
	require.True(t, out.WaitForEvents(1, 2*time.Second))

	record := out.GetEvent(0)
	assert.Equal(t, "", record["source_ip"], "empty string counts as set -- no default applied")
}

func TestWithStandardFieldDefaults_LastWins(t *testing.T) {
	t.Parallel()
	out := testhelper.NewMockOutput("test")
	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithStandardFieldDefaults(map[string]any{"source_ip": "a"}),
		audit.WithStandardFieldDefaults(map[string]any{"source_ip": "b"}),
		audit.WithValidationMode(audit.ValidationPermissive),
		audit.WithOutputs(out),
	)
	require.NoError(t, err, "multiple WithStandardFieldDefaults calls should not error (last wins)")

	err = auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{"outcome": "ok"}))
	require.NoError(t, err)
	require.NoError(t, auditor.Close())
	require.Equal(t, 1, out.EventCount())

	ev := out.GetEvent(0)
	assert.Equal(t, "b", ev["source_ip"], "second call should win (last wins)")
}

func TestWithStandardFieldDefaults_SatisfiesRequired(t *testing.T) {
	t.Parallel()
	// Taxonomy with source_ip as required.
	tax := &audit.Taxonomy{
		Version:    1,
		Categories: map[string]*audit.CategoryDef{"write": {Events: []string{"ev1"}}},
		Events: map[string]*audit.EventDef{
			"ev1": {Required: []string{"outcome", "source_ip"}},
		},
	}
	out := testhelper.NewMockOutput("test")
	auditor, err := audit.New(
		audit.WithTaxonomy(tax),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
		audit.WithStandardFieldDefaults(map[string]any{"source_ip": "10.0.0.1"}),
	)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, auditor.Close()) })

	// Event only provides outcome — source_ip should come from defaults.
	err = auditor.AuditEvent(audit.NewEvent("ev1", audit.Fields{"outcome": "success"}))
	assert.NoError(t, err, "default should satisfy required field")
}

func TestLogger_Audit_NilFields(t *testing.T) {
	t.Parallel()

	out := testhelper.NewMockOutput("test")
	auditor := newTestAuditor(t, out)

	// schema_register requires outcome, actor_id, subject — nil map
	// means all are missing.
	err := auditor.AuditEvent(audit.NewEvent("schema_register", nil))
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrValidation)
	assert.ErrorIs(t, err, audit.ErrMissingRequiredField)
	assert.Contains(t, err.Error(), "missing required fields")
}

func TestLogger_Audit_DisabledCategory(t *testing.T) {
	t.Parallel()

	out := testhelper.NewMockOutput("test")
	auditor := newTestAuditor(t, out)

	// Disable the "read" category at runtime.
	require.NoError(t, auditor.DisableCategory("read"))

	err := auditor.AuditEvent(audit.NewEvent("schema_read", audit.Fields{"outcome": "success"}))
	require.NoError(t, err)

	// Send an enabled event as sentinel to prove the drain loop processed
	// past the filtered event.
	err = auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{"outcome": "failure", "actor_id": "sentinel"}))
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))
	assert.Equal(t, 1, out.EventCount(), "disabled category event should not be delivered")
	assert.Equal(t, "auth_failure", out.GetEvent(0)["event_type"])
}

func TestLogger_Audit_OptionalFields(t *testing.T) {
	t.Parallel()

	out := testhelper.NewMockOutput("test")
	auditor := newTestAuditor(t, out)

	// Include an optional field.
	err := auditor.AuditEvent(audit.NewEvent("schema_register", audit.Fields{
		"outcome":     "success",
		"actor_id":    "alice",
		"subject":     "my-topic",
		"schema_type": "AVRO",
	}))
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))
	ev := out.GetEvent(0)
	assert.Equal(t, "AVRO", ev["schema_type"])
}

// ---------------------------------------------------------------------------
// Framework-provided fields tests
// ---------------------------------------------------------------------------

func TestLogger_Audit_TimestampAutoPopulated(t *testing.T) {
	t.Parallel()

	out := testhelper.NewMockOutput("test")
	auditor := newTestAuditor(t, out)

	before := time.Now()
	err := auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
	}))
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))

	ev := out.GetEvent(0)
	tsStr, ok := ev["timestamp"].(string)
	require.True(t, ok, "timestamp should be a string")
	ts, err := time.Parse(time.RFC3339Nano, tsStr)
	require.NoError(t, err)
	assert.False(t, ts.Before(before), "timestamp should be after test start")
}

func TestLogger_Audit_EventTypeAutoPopulated(t *testing.T) {
	t.Parallel()

	out := testhelper.NewMockOutput("test")
	auditor := newTestAuditor(t, out)

	err := auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
	}))
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))

	ev := out.GetEvent(0)
	assert.Equal(t, "auth_failure", ev["event_type"])
}

func TestLogger_Audit_ConsumerTimestampOverwritten(t *testing.T) {
	t.Parallel()

	out := testhelper.NewMockOutput("test")
	auditor := newTestAuditor(t, out, audit.WithValidationMode(audit.ValidationPermissive))

	err := auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":   "failure",
		"actor_id":  "bob",
		"timestamp": "consumer-set-value",
	}))
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))

	ev := out.GetEvent(0)
	// Framework should have overwritten the consumer value.
	assert.NotEqual(t, "consumer-set-value", ev["timestamp"])
}

// ---------------------------------------------------------------------------
// OmitEmpty tests
// ---------------------------------------------------------------------------

func TestLogger_Audit_OmitEmptyTrue(t *testing.T) {
	t.Parallel()

	out := testhelper.NewMockOutput("test")
	auditor := newTestAuditor(t, out, audit.WithOmitEmpty())

	err := auditor.AuditEvent(audit.NewEvent("schema_register", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "my-topic",
		// schema_type (optional) not provided
	}))
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))

	ev := out.GetEvent(0)
	_, hasSchemaType := ev["schema_type"]
	assert.False(t, hasSchemaType, "OmitEmpty should omit unset optional fields")
}

func TestLogger_Audit_OmitEmptyFalse(t *testing.T) {
	t.Parallel()

	out := testhelper.NewMockOutput("test")
	auditor := newTestAuditor(t, out)

	err := auditor.AuditEvent(audit.NewEvent("schema_register", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "my-topic",
		// schema_type (optional) not provided
	}))
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))

	ev := out.GetEvent(0)
	_, hasSchemaType := ev["schema_type"]
	assert.True(t, hasSchemaType, "OmitEmpty=false should include all registered fields")
}
