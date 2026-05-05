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
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/axonops/audit"
	"github.com/axonops/audit/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Event interface and NewEvent tests
// ---------------------------------------------------------------------------

func TestNewEvent_ImplementsInterface(t *testing.T) {
	t.Parallel()
	evt := audit.NewEvent("user_create", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
	})
	assert.Equal(t, "user_create", evt.EventType())
	assert.Equal(t, "success", evt.Fields()["outcome"])
	assert.Equal(t, "alice", evt.Fields()["actor_id"])
}

func TestAuditEvent_WithNewEvent(t *testing.T) {
	t.Parallel()
	out := testhelper.NewMockOutput("test")
	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)
	defer func() { _ = auditor.Close() }()

	evt := audit.NewEvent("schema_register", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "test-schema",
	})
	require.NoError(t, auditor.AuditEvent(evt))
	require.True(t, out.WaitForEvents(1, 2*time.Second))
	assert.Equal(t, "success", out.GetEvent(0)["outcome"])
}

func TestAuditEvent_UnknownEventType(t *testing.T) {
	t.Parallel()
	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
	)
	require.NoError(t, err)
	defer func() { _ = auditor.Close() }()

	err = auditor.AuditEvent(audit.NewEvent("nonexistent", audit.Fields{}))
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrValidation)
	assert.ErrorIs(t, err, audit.ErrUnknownEventType)
	assert.Contains(t, err.Error(), "unknown event type")
}

func TestAuditEvent_NilEvent(t *testing.T) {
	t.Parallel()
	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
	)
	require.NoError(t, err)
	defer func() { _ = auditor.Close() }()

	err = auditor.AuditEvent(nil)
	require.Error(t, err)
	// text-only: nil-event guard at audit.go:378 returns raw fmt.Errorf
	// without a sentinel wrap. The contract is the error message.
	assert.Contains(t, err.Error(), "event must not be nil")
}

// ---------------------------------------------------------------------------
// event_category (#227)
// ---------------------------------------------------------------------------

func TestAppendPostFields_JSON_SingleField(t *testing.T) {
	t.Parallel()
	data := []byte(`{"event_type":"test","outcome":"success"}` + "\n")
	fields := []audit.PostField{{JSONKey: "event_category", CEFKey: "cat", Value: "security"}}
	result := audit.AppendPostFields(data, &audit.JSONFormatter{}, fields)
	assert.Equal(t, `{"event_type":"test","outcome":"success","event_category":"security"}`+"\n", string(result))
}

func TestAppendPostFields_JSON_EmptyFields(t *testing.T) {
	t.Parallel()
	data := []byte(`{"event_type":"test"}` + "\n")
	result := audit.AppendPostFields(data, &audit.JSONFormatter{}, nil)
	assert.Equal(t, string(data), string(result), "empty fields should return unchanged data")
}

func TestAppendPostFields_CEF_SingleField(t *testing.T) {
	t.Parallel()
	data := []byte("CEF:0|V|P|1|test|desc|5|outcome=success\n")
	fields := []audit.PostField{{JSONKey: "event_category", CEFKey: "cat", Value: "write"}}
	result := audit.AppendPostFields(data, &audit.CEFFormatter{}, fields)
	assert.Equal(t, "CEF:0|V|P|1|test|desc|5|outcome=success cat=write\n", string(result))
}

func TestAppendPostFields_CEF_EmptyFields(t *testing.T) {
	t.Parallel()
	data := []byte("CEF:0|V|P|1|test|desc|5|outcome=success\n")
	result := audit.AppendPostFields(data, &audit.CEFFormatter{}, nil)
	assert.Equal(t, string(data), string(result))
}

func TestAppendPostFields_JSON_MultipleFields(t *testing.T) {
	t.Parallel()
	data := []byte(`{"event_type":"test","outcome":"success"}` + "\n")
	fields := []audit.PostField{
		{JSONKey: "event_category", CEFKey: "cat", Value: "security"},
		{JSONKey: "checksum", CEFKey: "checksum", Value: "abc123"},
	}
	result := audit.AppendPostFields(data, &audit.JSONFormatter{}, fields)
	assert.Contains(t, string(result), `"event_category":"security"`)
	assert.Contains(t, string(result), `"checksum":"abc123"`)
	assert.True(t, strings.HasSuffix(string(result), "}\n"))
}

func TestAppendPostFields_JSON_Escaping(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		field    audit.PostField
		contains string
	}{
		{
			name:     "value with double quotes",
			field:    audit.PostField{JSONKey: "msg", CEFKey: "msg", Value: `he said "hello"`},
			contains: `"msg":"he said \"hello\""`,
		},
		{
			name:     "value with backslash",
			field:    audit.PostField{JSONKey: "path", CEFKey: "path", Value: `C:\Users\admin`},
			contains: `"path":"C:\\Users\\admin"`,
		},
		{
			name:     "value with newline",
			field:    audit.PostField{JSONKey: "msg", CEFKey: "msg", Value: "line1\nline2"},
			contains: `"msg":"line1\nline2"`,
		},
		{
			name:  "value with control chars and null",
			field: audit.PostField{JSONKey: "msg", CEFKey: "msg", Value: "tab\there\x00null"},
		},
		{
			name:  "key with special chars",
			field: audit.PostField{JSONKey: "my\"key", CEFKey: "mykey", Value: "val"},
		},
	}
	data := []byte(`{"event_type":"test"}` + "\n")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := audit.AppendPostFields(data, &audit.JSONFormatter{}, []audit.PostField{tt.field})
			assert.True(t, json.Valid(result), "output must be valid JSON, got: %s", result)
			if tt.contains != "" {
				assert.Contains(t, string(result), tt.contains)
			}
		})
	}
}

func TestAppendPostFields_CEF_MultipleFields(t *testing.T) {
	t.Parallel()
	data := []byte("CEF:0|V|P|1|test|desc|5|outcome=success\n")
	fields := []audit.PostField{
		{JSONKey: "event_category", CEFKey: "cat", Value: "write"},
		{JSONKey: "checksum", CEFKey: "checksum", Value: "abc123"},
	}
	result := audit.AppendPostFields(data, &audit.CEFFormatter{}, fields)
	assert.Contains(t, string(result), "cat=write")
	assert.Contains(t, string(result), "checksum=abc123")
	assert.True(t, strings.HasSuffix(string(result), "\n"))
}

func TestAppendPostFields_UnknownFormatter(t *testing.T) {
	t.Parallel()
	data := []byte("some custom format\n")
	fields := []audit.PostField{{JSONKey: "k", CEFKey: "k", Value: "v"}}
	result := audit.AppendPostFields(data, nil, fields)
	assert.Equal(t, string(data), string(result), "unknown formatter should return unchanged")
}

func TestIsFrameworkField_EventCategory(t *testing.T) {
	t.Parallel()
	assert.True(t, audit.IsFrameworkField("event_category", nil))
}

func TestEventCategory_SingleCategory_JSON(t *testing.T) {
	t.Parallel()

	out := testhelper.NewMockOutput("test")
	tax := &audit.Taxonomy{
		Version: 1,

		Categories: map[string]*audit.CategoryDef{"security": {Events: []string{"auth_failure"}}},
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

	err = auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{"outcome": "failure"}))
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))
	require.NoError(t, auditor.Close())

	ev := out.GetEvent(0)
	assert.Equal(t, "security", ev["event_category"])
}

func TestEventCategory_MultiCategory_SeparateDeliveries(t *testing.T) {
	t.Parallel()

	out := testhelper.NewMockOutput("test")
	tax := &audit.Taxonomy{
		Version: 1,

		Categories: map[string]*audit.CategoryDef{
			"security": {Events: []string{"admin_update"}},
			"write":    {Events: []string{"admin_update"}},
		},
		Events: map[string]*audit.EventDef{
			"admin_update": {Required: []string{"outcome"}},
		},
	}

	auditor, err := audit.New(
		audit.WithTaxonomy(tax),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)

	err = auditor.AuditEvent(audit.NewEvent("admin_update", audit.Fields{"outcome": "success"}))
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(2, 2*time.Second))
	require.NoError(t, auditor.Close())

	cat0, ok0 := out.GetEvent(0)["event_category"].(string)
	require.True(t, ok0, "event_category should be a string")
	cat1, ok1 := out.GetEvent(1)["event_category"].(string)
	require.True(t, ok1, "event_category should be a string")
	categories := []string{cat0, cat1}
	assert.Contains(t, categories, "security")
	assert.Contains(t, categories, "write")
}

func TestEventCategory_Uncategorised_NoField(t *testing.T) {
	t.Parallel()

	out := testhelper.NewMockOutput("test")
	tax := &audit.Taxonomy{
		Version: 1,

		Categories: map[string]*audit.CategoryDef{"write": {Events: []string{"ev1"}}},
		Events: map[string]*audit.EventDef{
			"ev1":         {Required: []string{"outcome"}},
			"uncat_event": {Required: []string{"outcome"}},
		},
	}

	auditor, err := audit.New(
		audit.WithTaxonomy(tax),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)

	err = auditor.AuditEvent(audit.NewEvent("uncat_event", audit.Fields{"outcome": "success"}))
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))
	require.NoError(t, auditor.Close())

	ev := out.GetEvent(0)
	_, hasCategory := ev["event_category"]
	assert.False(t, hasCategory, "uncategorised event should not have event_category")
}

func TestEventCategory_EmitFalse_NoField(t *testing.T) {
	t.Parallel()

	out := testhelper.NewMockOutput("test")
	tax := &audit.Taxonomy{
		Version:               1,
		SuppressEventCategory: true,
		Categories:            map[string]*audit.CategoryDef{"security": {Events: []string{"auth_failure"}}},
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

	err = auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{"outcome": "failure"}))
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))
	require.NoError(t, auditor.Close())

	ev := out.GetEvent(0)
	_, hasCategory := ev["event_category"]
	assert.False(t, hasCategory, "emit_event_category:false should not add event_category")
}

func TestEventCategory_UserSupplied_Skipped(t *testing.T) {
	t.Parallel()

	out := testhelper.NewMockOutput("test")
	tax := &audit.Taxonomy{
		Version: 1,

		Categories: map[string]*audit.CategoryDef{"security": {Events: []string{"auth_failure"}}},
		Events: map[string]*audit.EventDef{
			"auth_failure": {Required: []string{"outcome"}},
		},
	}

	auditor, err := audit.New(
		audit.WithValidationMode(audit.ValidationPermissive),
		audit.WithTaxonomy(tax),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)

	// User tries to set event_category — framework value should win.
	err = auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":        "failure",
		"event_category": "user_custom",
	}))
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))
	require.NoError(t, auditor.Close())

	ev := out.GetEvent(0)
	assert.Equal(t, "security", ev["event_category"], "framework category should override user-supplied")
}

// ---------------------------------------------------------------------------
// event_category benchmarks (#227)
// ---------------------------------------------------------------------------

func BenchmarkAppendPostFields_JSON(b *testing.B) {
	data := []byte(`{"timestamp":"2026-01-01T00:00:00Z","event_type":"auth_failure","severity":8,"outcome":"failure","actor_id":"alice"}` + "\n")
	fields := []audit.PostField{{JSONKey: "event_category", CEFKey: "cat", Value: "security"}}
	formatter := &audit.JSONFormatter{}
	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		_ = audit.AppendPostFields(data, formatter, fields)
	}
}

func BenchmarkAppendPostFields_CEF(b *testing.B) {
	data := []byte("CEF:0|Test|App|1.0|auth_failure|desc|8|rt=1704067200000 act=auth_failure suser=alice outcome=failure\n")
	fields := []audit.PostField{{JSONKey: "event_category", CEFKey: "cat", Value: "security"}}
	formatter := &audit.CEFFormatter{}
	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		_ = audit.AppendPostFields(data, formatter, fields)
	}
}

func BenchmarkAppendPostFields_Disabled(b *testing.B) {
	data := []byte(`{"timestamp":"2026-01-01T00:00:00Z","event_type":"test","severity":5,"outcome":"success"}` + "\n")
	formatter := &audit.JSONFormatter{}
	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		_ = audit.AppendPostFields(data, formatter, nil)
	}
}
