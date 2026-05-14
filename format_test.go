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

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/quick"
	"time"

	"github.com/axonops/audit"
	"github.com/axonops/audit/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testTime = time.Date(2026, 3, 17, 12, 0, 0, 0, time.UTC)

var testDef = &audit.EventDef{
	Required: []string{"outcome", "actor_id", "subject"},
	Optional: []string{"schema_type", "version"},
}

// ---------------------------------------------------------------------------
// JSONFormatter tests
// ---------------------------------------------------------------------------

func TestJSONFormatter_ValidOutput(t *testing.T) {
	f := &audit.JSONFormatter{}
	data, err := f.Format(testTime, "schema_register", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "my-topic",
	}, testDef, nil)
	require.NoError(t, err)

	// Must end with newline.
	assert.True(t, data[len(data)-1] == '\n', "output must end with newline")

	// Must be valid JSON.
	var m map[string]any
	require.NoError(t, json.Unmarshal(data, &m))

	assert.Equal(t, "schema_register", m["event_type"])
	assert.Equal(t, "success", m["outcome"])
	assert.Equal(t, "alice", m["actor_id"])
	assert.NotEmpty(t, m["timestamp"])
}

func TestJSONFormatter_FieldOrdering(t *testing.T) {
	f := &audit.JSONFormatter{}
	data, err := f.Format(testTime, "schema_register", audit.Fields{
		"outcome":     "success",
		"actor_id":    "alice",
		"subject":     "my-topic",
		"schema_type": "AVRO",
		"version":     1,
	}, testDef, nil)
	require.NoError(t, err)

	raw := string(data)
	// Framework fields first.
	tsIdx := strings.Index(raw, `"timestamp"`)
	etIdx := strings.Index(raw, `"event_type"`)
	// Required fields sorted: actor_id, outcome, subject.
	aiIdx := strings.Index(raw, `"actor_id"`)
	oIdx := strings.Index(raw, `"outcome"`)
	sIdx := strings.Index(raw, `"subject"`)
	// Optional fields sorted: schema_type, version.
	stIdx := strings.Index(raw, `"schema_type"`)
	vIdx := strings.Index(raw, `"version"`)

	assert.Less(t, tsIdx, etIdx, "timestamp before event_type")
	assert.Less(t, etIdx, aiIdx, "event_type before required fields")
	assert.Less(t, aiIdx, oIdx, "actor_id before outcome (sorted)")
	assert.Less(t, oIdx, sIdx, "outcome before subject (sorted)")
	assert.Less(t, sIdx, stIdx, "required before optional")
	assert.Less(t, stIdx, vIdx, "schema_type before version (sorted)")
}

func TestJSONFormatter_DurationMarshalling(t *testing.T) {
	f := &audit.JSONFormatter{}
	data, err := f.Format(testTime, "schema_register", audit.Fields{
		"outcome":     "success",
		"actor_id":    "alice",
		"subject":     "my-topic",
		"duration_ms": 1500 * time.Millisecond,
	}, testDef, nil)
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(data, &m))

	// duration_ms should be int64 milliseconds, not Go duration string.
	assert.Equal(t, float64(1500), m["duration_ms"])
}

func TestJSONFormatter_DurationAsInt(t *testing.T) {
	// duration_ms as a plain int (not time.Duration) must not be dropped.
	f := &audit.JSONFormatter{}
	data, err := f.Format(testTime, "schema_register", audit.Fields{
		"outcome":     "success",
		"actor_id":    "alice",
		"subject":     "my-topic",
		"duration_ms": 250,
	}, testDef, nil)
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(data, &m))

	assert.Equal(t, float64(250), m["duration_ms"], "duration_ms as int must not be dropped")
}

func TestCEFFormatter_DurationAsInt(t *testing.T) {
	f := &audit.CEFFormatter{Vendor: "V", Product: "P", Version: "1"}
	data, err := f.Format(testTime, "ev", audit.Fields{
		"outcome":     "ok",
		"duration_ms": 500,
	}, &audit.EventDef{
		Required: []string{"outcome"},
		Optional: []string{"duration_ms"},
	}, nil)
	require.NoError(t, err)

	// Non-Duration duration_ms should appear as a regular field, not be dropped.
	line := string(data)
	assert.Contains(t, line, "duration_ms=500", "duration_ms as int must not be dropped in CEF")
}

func TestCEFFormatter_SeverityClamped(t *testing.T) {
	tests := []struct {
		name     string
		severity int
		want     int
	}{
		{"below zero", -5, 0},
		{"above ten", 42, 10},
		{"in range", 7, 7},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &audit.CEFFormatter{
				Vendor: "V", Product: "P", Version: "1",
				SeverityFunc: func(string) int { return tt.severity },
			}
			data, err := f.Format(testTime, "ev", audit.Fields{"outcome": "ok"}, &audit.EventDef{
				Required: []string{"outcome"},
			}, nil)
			require.NoError(t, err)
			assert.Contains(t, string(data), fmt.Sprintf("|%d|", tt.want))
		})
	}
}

func TestJSONFormatter_TimestampRFC3339Nano(t *testing.T) {
	f := &audit.JSONFormatter{Timestamp: audit.TimestampRFC3339Nano}
	data, err := f.Format(testTime, "ev", audit.Fields{"outcome": "ok"}, &audit.EventDef{
		Required: []string{"outcome"},
	}, nil)
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(data, &m))

	ts, ok := m["timestamp"].(string)
	require.True(t, ok, "timestamp should be a string for RFC3339Nano")
	parsed, err := time.Parse(time.RFC3339Nano, ts)
	require.NoError(t, err)
	assert.Equal(t, testTime, parsed)
}

func TestJSONFormatter_TimestampUnixMillis(t *testing.T) {
	f := &audit.JSONFormatter{Timestamp: audit.TimestampUnixMillis}
	data, err := f.Format(testTime, "ev", audit.Fields{"outcome": "ok"}, &audit.EventDef{
		Required: []string{"outcome"},
	}, nil)
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(data, &m))

	ts, ok := m["timestamp"].(float64)
	require.True(t, ok, "timestamp should be a number for unix_ms")
	assert.Equal(t, float64(testTime.UnixMilli()), ts)
}

func TestJSONFormatter_UnrecognisedTimestampFormat(t *testing.T) {
	f := &audit.JSONFormatter{Timestamp: audit.TimestampFormat("bogus")}
	data, err := f.Format(testTime, "ev", audit.Fields{"outcome": "ok"}, &audit.EventDef{
		Required: []string{"outcome"},
	}, nil)
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(data, &m), "output must be valid JSON")

	ts, ok := m["timestamp"].(string)
	require.True(t, ok, "timestamp should be a string (RFC3339Nano fallback)")
	parsed, err := time.Parse(time.RFC3339Nano, ts)
	require.NoError(t, err, "timestamp should parse as RFC3339Nano")
	assert.Equal(t, testTime, parsed)
}

func TestJSONFormatter_OmitEmptyTrue(t *testing.T) {
	f := &audit.JSONFormatter{OmitEmpty: true}
	data, err := f.Format(testTime, "schema_register", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "my-topic",
		// schema_type and version not provided
	}, testDef, nil)
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(data, &m))

	_, has := m["schema_type"]
	assert.False(t, has, "OmitEmpty should omit missing optional fields")
}

func TestJSONFormatter_OmitEmptyFalse(t *testing.T) {
	f := &audit.JSONFormatter{OmitEmpty: false}
	data, err := f.Format(testTime, "schema_register", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "my-topic",
	}, testDef, nil)
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(data, &m))

	_, has := m["schema_type"]
	assert.True(t, has, "OmitEmpty=false should include all registered fields")
	assert.Nil(t, m["schema_type"], "missing optional should be null")
}

func TestJSONFormatter_UnicodeValues(t *testing.T) {
	f := &audit.JSONFormatter{}
	data, err := f.Format(testTime, "ev", audit.Fields{
		"outcome": "success",
		"name":    "hello \u4e16\u754c",
	}, &audit.EventDef{
		Required: []string{"outcome"},
		Optional: []string{"name"},
	}, nil)
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(data, &m))
	assert.Contains(t, m["name"], "\u4e16\u754c")
}

func TestJSONFormatter_LongValues(t *testing.T) {
	f := &audit.JSONFormatter{}
	longVal := strings.Repeat("x", 64*1024) // 64KB
	data, err := f.Format(testTime, "ev", audit.Fields{
		"outcome": longVal,
	}, &audit.EventDef{
		Required: []string{"outcome"},
	}, nil)
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(data, &m))
	assert.Equal(t, longVal, m["outcome"])
}

func TestJSONFormatter_NilFields(t *testing.T) {
	f := &audit.JSONFormatter{}
	data, err := f.Format(testTime, "ev", nil, &audit.EventDef{}, nil)
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(data, &m))
	assert.Equal(t, "ev", m["event_type"])
}

func TestJSONFormatter_NewlineInjection(t *testing.T) {
	f := &audit.JSONFormatter{}
	data, err := f.Format(testTime, "ev", audit.Fields{
		"outcome": "success\n{\"injected\":true}",
	}, &audit.EventDef{
		Required: []string{"outcome"},
	}, nil)
	require.NoError(t, err)

	// The output must be a single line (one trailing newline only).
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	assert.Equal(t, 1, len(lines), "embedded newline must not produce a second line")
}

func TestJSONFormatter_ExtraFieldsSorted(t *testing.T) {
	f := &audit.JSONFormatter{OmitEmpty: false}
	data, err := f.Format(testTime, "ev", audit.Fields{
		"outcome": "ok",
		"zebra":   "z",
		"alpha":   "a",
	}, &audit.EventDef{
		Required: []string{"outcome"},
	}, nil)
	require.NoError(t, err)

	raw := string(data)
	aIdx := strings.Index(raw, `"alpha"`)
	zIdx := strings.Index(raw, `"zebra"`)
	assert.Less(t, aIdx, zIdx, "extra fields should be sorted")
}

// TestCEFFormatter_AllFieldKeysSortedSlow exercises the allFieldKeysSortedSlow
// path (knownFields == nil) with required, optional, and extra fields. This
// path triggers when EventDef is constructed manually without taxonomy
// registration. CEF formatter uses allFieldKeysSorted for extension field
// ordering — JSON formatter uses separate per-group sorting.
func TestCEFFormatter_AllFieldKeysSortedSlow(t *testing.T) {
	t.Parallel()
	// Use empty FieldMapping so fields are not remapped to CEF standard keys.
	f := &audit.CEFFormatter{Vendor: "T", Product: "T", Version: "1", FieldMapping: map[string]string{}}

	// Manually-constructed EventDef has no knownFields (nil) —
	// triggers allFieldKeysSortedSlow.
	def := &audit.EventDef{
		Required: []string{"field_c", "field_a"},
		Optional: []string{"field_d", "field_b"},
	}
	data, err := f.Format(testTime, "manual_event", audit.Fields{
		"field_c": "c",
		"field_a": "a",
		"field_d": "d",
		"field_b": "b",
		"zebra":   "z",
		"alpha":   "aa",
	}, def, nil)
	require.NoError(t, err)

	raw := string(data)
	// All fields should be present in CEF extensions.
	for _, key := range []string{"field_a", "field_b", "field_c", "field_d", "alpha", "zebra"} {
		assert.Contains(t, raw, key+"=", "extension key %q should be in output", key)
	}
	// CEF uses allFieldKeysSorted — all keys globally sorted alphabetically.
	alphaIdx := strings.Index(raw, "alpha=")
	fieldAIdx := strings.Index(raw, "field_a=")
	fieldDIdx := strings.Index(raw, "field_d=")
	zebraIdx := strings.Index(raw, "zebra=")
	assert.Less(t, alphaIdx, fieldAIdx, "alpha should appear before field_a")
	assert.Less(t, fieldDIdx, zebraIdx, "field_d should appear before zebra")
}

// TestCEFFormatter_ExtraFieldsWithKnownFields exercises the middle path
// in allFieldKeysSorted: knownFields exists (taxonomy-registered) but extra
// fields are present (permissive mode). This builds a combined sorted list
// from the pre-computed known keys and the extra keys.
func TestCEFFormatter_ExtraFieldsWithKnownFields(t *testing.T) {
	t.Parallel()

	const taxYAML = `
version: 1
categories:
  write:
    events: [user_create]
events:
  user_create:
    fields:
      outcome: {required: true}
      actor_id: {required: true}
      note: {}
`
	tax, err := audit.ParseTaxonomyYAML([]byte(taxYAML))
	require.NoError(t, err)

	def := tax.Events["user_create"]
	require.NotNil(t, def)

	f := &audit.CEFFormatter{Vendor: "T", Product: "T", Version: "1"}
	data, err := f.Format(testTime, "user_create", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"note":     "a note",
		"extra_b":  "b",
		"extra_a":  "a",
	}, def, nil)
	require.NoError(t, err)

	raw := string(data)
	// Extra fields should be present and sorted among known fields.
	for _, key := range []string{"extra_a", "extra_b"} {
		assert.Contains(t, raw, key+"=", "extra extension key %q should be in output", key)
	}
	// Extra fields should be alphabetically sorted relative to each other.
	extraAIdx := strings.Index(raw, "extra_a=")
	extraBIdx := strings.Index(raw, "extra_b=")
	assert.Less(t, extraAIdx, extraBIdx, "extra_a should appear before extra_b")
}

// ---------------------------------------------------------------------------
// CEFFormatter tests
// ---------------------------------------------------------------------------

func TestCEFFormatter_ValidHeader(t *testing.T) {
	f := &audit.CEFFormatter{
		Vendor:  "TestVendor",
		Product: "TestProduct",
		Version: "1.0",
	}
	data, err := f.Format(testTime, "schema_register", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "my-topic",
	}, testDef, nil)
	require.NoError(t, err)

	line := string(data)
	assert.True(t, strings.HasPrefix(line, "CEF:0|TestVendor|TestProduct|1.0|schema_register|"))
	assert.True(t, strings.HasSuffix(line, "\n"), "must end with newline")

	// Should be a single line.
	lines := strings.Split(strings.TrimSuffix(line, "\n"), "\n")
	assert.Equal(t, 1, len(lines))
}

func TestCEFFormatter_DefaultSeverity(t *testing.T) {
	f := &audit.CEFFormatter{Vendor: "V", Product: "P", Version: "1"}
	data, err := f.Format(testTime, "ev", audit.Fields{"outcome": "ok"}, &audit.EventDef{
		Required: []string{"outcome"},
	}, nil)
	require.NoError(t, err)

	// Default severity is 5.
	assert.Contains(t, string(data), "|ev|5|")
}

func TestCEFFormatter_CustomSeverity(t *testing.T) {
	f := &audit.CEFFormatter{
		Vendor:  "V",
		Product: "P",
		Version: "1",
		SeverityFunc: func(et string) int {
			if et == "auth_failure" {
				return 8
			}
			return 3
		},
	}
	data, err := f.Format(testTime, "auth_failure", audit.Fields{"outcome": "fail"}, &audit.EventDef{
		Required: []string{"outcome"},
	}, nil)
	require.NoError(t, err)
	assert.Contains(t, string(data), "|auth_failure|8|")
}

func TestCEFFormatter_DefaultDescription(t *testing.T) {
	f := &audit.CEFFormatter{Vendor: "V", Product: "P", Version: "1"}
	data, err := f.Format(testTime, "my_event", audit.Fields{"outcome": "ok"}, &audit.EventDef{
		Required: []string{"outcome"},
	}, nil)
	require.NoError(t, err)

	// Default description is the event type itself.
	assert.Contains(t, string(data), "|my_event|my_event|")
}

func TestCEFFormatter_CustomDescription(t *testing.T) {
	f := &audit.CEFFormatter{
		Vendor:  "V",
		Product: "P",
		Version: "1",
		DescriptionFunc: func(et string) string {
			return "Custom: " + et
		},
	}
	data, err := f.Format(testTime, "ev", audit.Fields{"outcome": "ok"}, &audit.EventDef{
		Required: []string{"outcome"},
	}, nil)
	require.NoError(t, err)
	assert.Contains(t, string(data), "|Custom: ev|")
}

func TestCEFFormatter_ExtensionFields(t *testing.T) {
	f := &audit.CEFFormatter{Vendor: "V", Product: "P", Version: "1"}
	data, err := f.Format(testTime, "ev", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
	}, &audit.EventDef{
		Required: []string{"outcome", "actor_id"},
	}, nil)
	require.NoError(t, err)

	line := string(data)
	// actor_id maps to suser via DefaultCEFFieldMapping.
	assert.Contains(t, line, "suser=alice")
	assert.Contains(t, line, "outcome=success")
}

func TestCEFFormatter_AllDefaultFieldMappings(t *testing.T) {
	t.Parallel()
	mapping := audit.DefaultCEFFieldMapping()
	f := &audit.CEFFormatter{Vendor: "V", Product: "P", Version: "1"}

	for auditField, cefKey := range mapping {
		t.Run(auditField+"→"+cefKey, func(t *testing.T) {
			t.Parallel()
			fields := audit.Fields{auditField: "test_value"}
			def := &audit.EventDef{Required: []string{auditField}}

			data, err := f.Format(testTime, "test_event", fields, def, nil)
			require.NoError(t, err)

			line := string(data)
			expected := cefKey + "=test_value"
			assert.Contains(t, line, expected,
				"field %q should map to CEF key %q", auditField, cefKey)
		})
	}
}

func TestCEFFormatter_EventDefDescription(t *testing.T) {
	t.Parallel()
	f := &audit.CEFFormatter{Vendor: "V", Product: "P", Version: "1"}
	def := &audit.EventDef{
		Required:    []string{"outcome"},
		Description: "A schema was registered",
	}
	data, err := f.Format(testTime, "schema_register", audit.Fields{"outcome": "success"}, def, nil)
	require.NoError(t, err)

	line := string(data)
	assert.Contains(t, line, "A schema was registered",
		"CEF header should contain EventDef.Description")
}

func TestCEFFormatter_CustomFieldMapping(t *testing.T) {
	f := &audit.CEFFormatter{
		Vendor:  "V",
		Product: "P",
		Version: "1",
		FieldMapping: map[string]string{
			"actor_id": "customActor",
			"outcome":  "result",
		},
	}
	data, err := f.Format(testTime, "ev", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
	}, &audit.EventDef{
		Required: []string{"outcome", "actor_id"},
	}, nil)
	require.NoError(t, err)

	line := string(data)
	assert.Contains(t, line, "customActor=alice")
	assert.Contains(t, line, "result=success")
	assert.NotContains(t, line, "suser=")
}

func TestCEFFormatter_CustomFieldMappingMergesDefaults(t *testing.T) {
	// Custom mapping overrides actor_id but source_ip should still
	// use the default mapping to "src".
	f := &audit.CEFFormatter{
		Vendor:  "V",
		Product: "P",
		Version: "1",
		FieldMapping: map[string]string{
			"actor_id": "customActor",
		},
	}
	data, err := f.Format(testTime, "ev", audit.Fields{
		"outcome":   "success",
		"actor_id":  "alice",
		"source_ip": "10.0.0.1",
	}, &audit.EventDef{
		Required: []string{"outcome", "actor_id"},
		Optional: []string{"source_ip"},
	}, nil)
	require.NoError(t, err)

	line := string(data)
	assert.Contains(t, line, "customActor=alice", "override should apply")
	assert.Contains(t, line, "src=10.0.0.1", "default mapping should still apply")
}

func TestCEFFormatter_OmitEmpty(t *testing.T) {
	f := &audit.CEFFormatter{Vendor: "V", Product: "P", Version: "1", OmitEmpty: true}
	data, err := f.Format(testTime, "ev", audit.Fields{
		"outcome": "ok",
		"empty":   "",
	}, &audit.EventDef{
		Required: []string{"outcome"},
		Optional: []string{"empty"},
	}, nil)
	require.NoError(t, err)
	assert.NotContains(t, string(data), "empty=")
}

func TestCEFFormatter_DurationInExtensions(t *testing.T) {
	f := &audit.CEFFormatter{Vendor: "V", Product: "P", Version: "1"}
	data, err := f.Format(testTime, "ev", audit.Fields{
		"outcome":     "ok",
		"duration_ms": 2500 * time.Millisecond,
	}, &audit.EventDef{
		Required: []string{"outcome"},
	}, nil)
	require.NoError(t, err)
	assert.Contains(t, string(data), "cn1=2500")
	assert.Contains(t, string(data), "cn1Label=durationMs")
}

// ---------------------------------------------------------------------------
// CEF escaping tests (exhaustive)
// ---------------------------------------------------------------------------

func TestCEFEscapeHeader(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"pipe", "hello|world", `hello\|world`},
		{"backslash", `hello\world`, `hello\\world`},
		{"both", `a\b|c`, `a\\b\|c`},
		{"newline stripped", "line1\nline2", "line1 line2"},
		{"cr stripped", "line1\rline2", "line1 line2"},
		{"null byte", "hello\x00world", "hello\x00world"}, // C0 controls pass through in headers
		{"tab", "hello\tworld", "hello\tworld"},           // tab passes through
		{"bell", "hello\x07world", "hello\x07world"},      // bell passes through
		{"clean", "hello", "hello"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := audit.CEFEscapeHeaderForTest(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCEFEscapeExtValue(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"equals", "a=b", `a\=b`},
		{"backslash", `a\b`, `a\\b`},
		{"newline", "a\nb", `a\nb`},
		{"cr", "a\rb", `a\rb`},
		{"all special", "a\\=b\nc\r", `a\\\=b\nc\r`},
		{"clean", "hello", "hello"},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := audit.CEFEscapeExtValueForTest(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestCEFFormatter_DoesNotPerformRuntimeKeyValidation locks in that
// the PER-EVENT CEF extension-key validation was removed as part of
// #477. Validation still happens — but exactly once per formatter,
// at construction time (see [audit.CEFFormatter.fieldMapping] →
// resolveOnce). The hot path is validation-free.
//
// This test drives Format repeatedly with a valid FieldMapping and
// asserts no error. The matching negative test
// [TestCEFFormatter_RejectsInvalidFieldMappingAtConstruction] proves
// the construction-time check catches unsafe keys, so the hot path
// never has to. Between these two tests, the contract is pinned.
func TestCEFFormatter_DoesNotPerformRuntimeKeyValidation(t *testing.T) {
	t.Parallel()
	f := &audit.CEFFormatter{
		Vendor:  "AxonOps",
		Product: "Test",
		Version: "1",
		FieldMapping: map[string]string{
			"outcome": "custom_outcome",
		},
	}
	def := &audit.EventDef{Required: []string{"outcome"}}
	for i := 0; i < 100; i++ {
		result, err := f.Format(time.Now(), "user_create",
			audit.Fields{"outcome": "success"}, def, nil)
		require.NoError(t, err,
			"valid FieldMapping must not produce per-event errors (iter %d)", i)
		assert.Contains(t, string(result), "custom_outcome=success")
	}
}

// TestCEFFormatter_RejectsInvalidFieldMappingAtConstruction verifies
// that a FieldMapping value containing characters outside the CEF
// extension-key character class fails at the first Format call via
// the construction-time (resolveOnce) validator. Catching this at
// construction prevents a log-injection class: CEF extension keys
// are written unescaped by writeExtField, so a key containing space,
// `=`, `|`, or newline would let a misconfigured mapping inject
// synthetic extension pairs or terminate the event early, which
// downstream SIEMs mis-parse as spoofed audit events (#477).
func TestCEFFormatter_RejectsInvalidFieldMappingAtConstruction(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		bad  string
	}{
		{"space", "has space"},
		{"equals", "has=equals"},
		{"pipe", "has|pipe"},
		{"newline", "has\nnewline"},
		{"dot", "has.dot"},
		// NOTE: empty string is intentionally not a rejection case —
		// it is the documented opt-out sentinel (see
		// TestCEFFormatter_FieldMapping_DropDefault_ViaDelete, #591).
	}
	def := &audit.EventDef{Required: []string{"outcome"}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := &audit.CEFFormatter{
				Vendor:       "V",
				Product:      "P",
				Version:      "1",
				FieldMapping: map[string]string{"outcome": tc.bad},
			}
			_, err := f.Format(time.Now(), "ev",
				audit.Fields{"outcome": "ok"}, def, nil)
			require.Error(t, err,
				"invalid extension key %q must be rejected at construction", tc.bad)
			// text-only: format_cef.go:463 returns raw fmt.Errorf without an audit sentinel wrap.
			assert.Contains(t, err.Error(), "invalid extension key")
			// A second call must return the SAME error (resolveErr is
			// captured once, not re-computed).
			_, err2 := f.Format(time.Now(), "ev",
				audit.Fields{"outcome": "ok"}, def, nil)
			require.Error(t, err2)
			assert.Equal(t, err.Error(), err2.Error(),
				"construction-time error must be stable across calls")
		})
	}
}

// TestCEFExtKeyValidation exercises the validateExtKey helper
// directly, giving concrete confidence in the character classes
// accepted and rejected by the construction-time mapping validator.
func TestCEFExtKeyValidation(t *testing.T) {
	tests := []struct {
		key   string
		valid bool
	}{
		{"suser", true},
		{"cn1Label", true},
		{"custom_field", true},
		{"field123", true},
		{"has space", false},
		{"has=equals", false},
		{"has|pipe", false},
		{"", false},
		{"has.dot", false},
	}
	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			err := audit.ValidateExtKeyForTest(tt.key)
			if tt.valid {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

// TestCEFFormatter_PoolSafety verifies that the sync.Pool buffer reuse
// does not corrupt cached Format() results.
func TestCEFFormatter_PoolSafety(t *testing.T) {
	f := &audit.CEFFormatter{Vendor: "V", Product: "P", Version: "1"}
	def := &audit.EventDef{Required: []string{"outcome"}}
	ts := time.Now()

	result1, err := f.Format(ts, "ev1", audit.Fields{"outcome": "first"}, def, nil)
	require.NoError(t, err)

	result2, err := f.Format(ts, "ev2", audit.Fields{"outcome": "second"}, def, nil)
	require.NoError(t, err)

	assert.Contains(t, string(result1), "outcome=first")
	assert.Contains(t, string(result2), "outcome=second")
	assert.NotEqual(t, result1, result2)
}

func TestCEFEscapeExtValue_QuickCheck(t *testing.T) {
	f := func(s string) bool {
		escaped := audit.CEFEscapeExtValueForTest(s)
		old := audit.CEFEscapeExtValueOldForTest(s)
		// Output must be byte-for-byte identical to the old implementation.
		if escaped != old {
			return false
		}
		// No raw newlines or carriage returns in escaped output.
		return !strings.Contains(escaped, "\n") && !strings.Contains(escaped, "\r")
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 10000}); err != nil {
		t.Error(err)
	}
}

func TestCEFEscapeHeader_QuickCheck(t *testing.T) {
	f := func(s string) bool {
		escaped := audit.CEFEscapeHeaderForTest(s)
		old := audit.CEFEscapeHeaderOldForTest(s)
		// Output must be byte-for-byte identical to the old implementation.
		if escaped != old {
			return false
		}
		// No raw newlines, carriage returns, or unescaped pipes.
		if strings.Contains(escaped, "\n") || strings.Contains(escaped, "\r") {
			return false
		}
		// Check no unescaped pipe: every | must be preceded by \.
		for i, ch := range escaped {
			if ch == '|' && (i == 0 || escaped[i-1] != '\\') {
				return false
			}
		}
		return true
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 10000}); err != nil {
		t.Error(err)
	}
}

// ---------------------------------------------------------------------------
// CEF log injection prevention
// ---------------------------------------------------------------------------

func TestCEFFormatter_NewlineInjection(t *testing.T) {
	f := &audit.CEFFormatter{Vendor: "V", Product: "P", Version: "1"}
	data, err := f.Format(testTime, "ev", audit.Fields{
		"outcome": "success\n{injected}",
	}, &audit.EventDef{
		Required: []string{"outcome"},
	}, nil)
	require.NoError(t, err)

	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	assert.Equal(t, 1, len(lines), "embedded newline must not produce a second CEF line")
}

func TestCEFFormatter_HeaderPipeInjection(t *testing.T) {
	f := &audit.CEFFormatter{Vendor: "Bad|Vendor", Product: "P", Version: "1"}
	data, err := f.Format(testTime, "ev|bad", audit.Fields{
		"outcome": "ok",
	}, &audit.EventDef{
		Required: []string{"outcome"},
	}, nil)
	require.NoError(t, err)

	line := string(data)
	// The vendor's pipe should be escaped in the header.
	assert.Contains(t, line, `Bad\|Vendor`)
	// The event type's pipe should be escaped in the header.
	assert.Contains(t, line, `ev\|bad`)
	// Single line.
	lines := strings.Split(strings.TrimSuffix(line, "\n"), "\n")
	assert.Equal(t, 1, len(lines))
}

// ---------------------------------------------------------------------------
// Auditor integration tests
// ---------------------------------------------------------------------------

func TestLogger_WithFormatter_Custom(t *testing.T) {
	out := testhelper.NewMockOutput("test")
	called := false
	custom := &stubFormatter{
		fn: func(ts time.Time, eventType string, fields audit.Fields, def *audit.EventDef) ([]byte, error) {
			called = true
			return []byte(`{"custom":true}` + "\n"), nil
		},
	}

	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
		audit.WithFormatter(custom),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditor.Close() })

	err = auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
	}))
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))
	assert.True(t, called, "custom formatter should have been called")
}

type stubFormatter struct {
	fn func(time.Time, string, audit.Fields, *audit.EventDef) ([]byte, error)
}

func (s *stubFormatter) Format(ts time.Time, eventType string, fields audit.Fields, def *audit.EventDef, _ *audit.FormatOptions) ([]byte, error) {
	return s.fn(ts, eventType, fields, def)
}

func (s *stubFormatter) ContentType() string { return "application/x-ndjson" }

func TestLogger_DefaultJSONFormatter(t *testing.T) {
	out := testhelper.NewMockOutput("test")
	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditor.Close() })

	err = auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
	}))
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))

	// Default formatter should produce valid JSON.
	var m map[string]any
	require.NoError(t, json.Unmarshal(out.GetEvents()[0], &m))
	assert.Equal(t, "auth_failure", m["event_type"])
}

func TestLogger_CEFViaWithFormatter(t *testing.T) {
	out := testhelper.NewMockOutput("test")
	cef := &audit.CEFFormatter{
		Vendor:  "TestCo",
		Product: "TestApp",
		Version: "2.0",
	}

	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
		audit.WithFormatter(cef),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditor.Close() })

	err = auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
	}))
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))

	line := string(out.GetEvents()[0])
	assert.True(t, strings.HasPrefix(line, "CEF:0|TestCo|TestApp|2.0|auth_failure|"))
}

func TestLogger_WithFormatter_Nil(t *testing.T) {
	_, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithFormatter(nil),
	)
	require.Error(t, err)
	// text-only: options.go:264 returns raw fmt.Errorf without an audit sentinel wrap.
	assert.Contains(t, err.Error(), "formatter must not be nil")
}

// ---------------------------------------------------------------------------
// CEF extension key validation
// ---------------------------------------------------------------------------

func TestCEFFormatter_FieldValueTypes(t *testing.T) {
	f := &audit.CEFFormatter{Vendor: "V", Product: "P", Version: "1"}
	data, err := f.Format(testTime, "ev", audit.Fields{
		"outcome":  "ok",
		"count":    42,
		"count64":  int64(100),
		"count32":  int32(99),
		"ratio":    3.14,
		"ratio32":  float32(2.5),
		"size":     uint(999),
		"bigcount": uint64(18446744073709551615),
		"active":   true,
		"inactive": false,
		"dur":      2 * time.Second,
		"when":     testTime,
		"nilfield": nil,
		"custom":   []string{"a", "b"},
	}, &audit.EventDef{
		Required: []string{"outcome"},
		Optional: []string{"count", "count64", "count32", "ratio", "ratio32", "size", "bigcount", "active", "inactive", "dur", "when", "nilfield", "custom"},
	}, nil)
	require.NoError(t, err)

	line := string(data)
	assert.Contains(t, line, "count=42")
	assert.Contains(t, line, "count64=100")
	assert.Contains(t, line, "count32=99")
	assert.Contains(t, line, "ratio=3.14")
	assert.Contains(t, line, "ratio32=2.5")
	assert.Contains(t, line, "size=999")
	assert.Contains(t, line, "bigcount=18446744073709551615")
	assert.Contains(t, line, "active=true")
	assert.Contains(t, line, "inactive=false")
	assert.Contains(t, line, "dur=2000")
	assert.Contains(t, line, "when=2026-03-17T12:00:00Z")
}

func TestJSONFormatter_WriteFieldError(t *testing.T) {
	// A channel value cannot be marshalled — the formatter should
	// return an error, not panic.
	f := &audit.JSONFormatter{}
	_, err := f.Format(testTime, "ev", audit.Fields{
		"outcome": "ok",
		"bad":     make(chan struct{}),
	}, &audit.EventDef{
		Required: []string{"outcome"},
		Optional: []string{"bad"},
	}, nil)
	require.Error(t, err)
	// text-only: format_json.go:169 returns raw fmt.Errorf without an audit sentinel wrap.
	assert.Contains(t, err.Error(), "json format")
}

func TestDefaultCEFFieldMapping(t *testing.T) {
	m := audit.DefaultCEFFieldMapping()
	assert.Equal(t, "suser", m["actor_id"])
	assert.Equal(t, "src", m["source_ip"])

	// Mutating the returned copy should not affect the default.
	m["actor_id"] = "modified"
	m2 := audit.DefaultCEFFieldMapping()
	assert.Equal(t, "suser", m2["actor_id"], "default mapping must not be mutated")
}

func TestDefaultCEFFieldMapping_IndependentCopies(t *testing.T) {
	// Each call must return a distinct map instance. Mutating one
	// must not affect the other.
	m1 := audit.DefaultCEFFieldMapping()
	m2 := audit.DefaultCEFFieldMapping()

	m1["actor_id"] = "corrupted"
	m1["new_key"] = "injected"

	assert.Equal(t, "suser", m2["actor_id"], "second call must not see first call's mutation")
	_, hasNew := m2["new_key"]
	assert.False(t, hasNew, "second call must not see first call's new key")
}

// ---------------------------------------------------------------------------
// Framework fields (#237)
// ---------------------------------------------------------------------------

func TestJSONFormatter_FrameworkFields(t *testing.T) {
	t.Parallel()
	jf := &audit.JSONFormatter{}
	jf.SetFrameworkFields("myapp", "prod-01", "UTC", 12345)

	data, err := jf.Format(testTime, "ev", audit.Fields{
		"outcome": "success",
	}, &audit.EventDef{
		Required: []string{"outcome"},
	}, nil)
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(data, &m))

	assert.Equal(t, "myapp", m["app_name"])
	assert.Equal(t, "prod-01", m["host"])
	assert.Equal(t, "UTC", m["timezone"])
	assert.Equal(t, float64(12345), m["pid"])
}

func TestJSONFormatter_FrameworkFields_OmittedWhenEmpty(t *testing.T) {
	t.Parallel()
	jf := &audit.JSONFormatter{}
	// No SetFrameworkFields call — fields should be absent.

	data, err := jf.Format(testTime, "ev", audit.Fields{
		"outcome": "success",
	}, &audit.EventDef{
		Required: []string{"outcome"},
	}, nil)
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(data, &m))

	_, hasApp := m["app_name"]
	_, hasHost := m["host"]
	_, hasTZ := m["timezone"]
	_, hasPID := m["pid"]
	assert.False(t, hasApp, "app_name should be absent")
	assert.False(t, hasHost, "host should be absent")
	assert.False(t, hasTZ, "timezone should be absent")
	assert.False(t, hasPID, "pid should be absent")
}

func TestCEFFormatter_FrameworkFields(t *testing.T) {
	t.Parallel()
	cf := &audit.CEFFormatter{Vendor: "V", Product: "P", Version: "1"}
	cf.SetFrameworkFields("myapp", "prod-01", "UTC", 12345)

	data, err := cf.Format(testTime, "ev", audit.Fields{
		"outcome": "success",
	}, &audit.EventDef{
		Required: []string{"outcome"},
	}, nil)
	require.NoError(t, err)

	line := string(data)
	assert.Contains(t, line, "deviceProcessName=myapp")
	assert.Contains(t, line, "dvchost=prod-01")
	assert.Contains(t, line, "dtz=UTC")
	assert.Contains(t, line, "dvcpid=12345")
}

func TestCEFFormatter_FrameworkFields_OmittedWhenEmpty(t *testing.T) {
	t.Parallel()
	cf := &audit.CEFFormatter{Vendor: "V", Product: "P", Version: "1"}
	// No SetFrameworkFields call.

	data, err := cf.Format(testTime, "ev", audit.Fields{
		"outcome": "success",
	}, &audit.EventDef{
		Required: []string{"outcome"},
	}, nil)
	require.NoError(t, err)

	line := string(data)
	assert.NotContains(t, line, "deviceProcessName")
	assert.NotContains(t, line, "dvchost")
	assert.NotContains(t, line, "dtz")
	assert.NotContains(t, line, "dvcpid")
}

func TestDefaultCEFFieldMapping_AllStandardEntries(t *testing.T) {
	t.Parallel()
	m := audit.DefaultCEFFieldMapping()

	expected := map[string]string{
		// Identity and access
		"actor_id":    "suser",
		"actor_uid":   "suid",
		"role":        "spriv",
		"target_id":   "duser",
		"target_uid":  "duid",
		"target_role": "dpriv",
		// Event context
		"outcome": "outcome",
		"reason":  "reason",
		"message": "msg",
		// Network
		"source_ip":   "src",
		"source_host": "shost",
		"source_port": "spt",
		"dest_ip":     "dst",
		"dest_host":   "dhost",
		"dest_port":   "dpt",
		"protocol":    "app",
		"transport":   "proto",
		// HTTP / request
		"request_id": "externalId",
		"user_agent": "requestClientApplication",
		"referrer":   "requestContext",
		"method":     "requestMethod",
		"path":       "request",
		// Temporal
		"start_time": "start",
		"end_time":   "end",
		// File
		"file_name": "fname",
		"file_path": "filePath",
		"file_hash": "fileHash",
		"file_size": "fsize",
	}

	assert.Len(t, m, len(expected), "mapping should have %d entries", len(expected))
	for auditField, cefKey := range expected {
		assert.Equal(t, cefKey, m[auditField], "audit field %q should map to %q", auditField, cefKey)
	}
}

func TestDefaultCEFFieldMapping_NoDuplicateCEFKeys(t *testing.T) {
	t.Parallel()
	m := audit.DefaultCEFFieldMapping()
	seen := make(map[string]string, len(m))
	for auditField, cefKey := range m {
		if prev, ok := seen[cefKey]; ok {
			t.Errorf("duplicate CEF key %q: used by both %q and %q", cefKey, prev, auditField)
		}
		seen[cefKey] = auditField
	}
}

func TestCEFFormatter_ConcurrentFormat_NoRace(t *testing.T) {
	cf := &audit.CEFFormatter{
		Vendor:  "V",
		Product: "P",
		Version: "1",
	}
	def := &audit.EventDef{
		Required: []string{"outcome"},
	}
	ts := time.Now()

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Each goroutine gets its own fields map to avoid relying
			// on Format never writing to the map.
			f := audit.Fields{"outcome": "ok"}
			data, err := cf.Format(ts, "ev", f, def, nil)
			if err != nil {
				t.Errorf("Format failed: %v", err)
				return
			}
			s := string(data)
			if !strings.HasPrefix(s, "CEF:0|V|P|1|") {
				t.Errorf("unexpected output prefix: %s", s[:40])
			}
			if !strings.HasSuffix(s, "\n") {
				t.Errorf("output missing newline terminator")
			}
		}()
	}
	wg.Wait()
}

func TestCEFFormatter_AllocCount(t *testing.T) {
	cf := &audit.CEFFormatter{
		Vendor:  "TestVendor",
		Product: "TestProduct",
		Version: "1.0",
	}
	def := &audit.EventDef{
		Required: []string{"outcome", "actor_id", "subject"},
		Optional: []string{"version"},
	}
	fields := audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "my-topic",
		"version":  1,
	}
	ts := testTime

	allocs := testing.AllocsPerRun(100, func() {
		_, _ = cf.Format(ts, "schema_register", fields, def, nil)
	})

	t.Logf("CEFFormatter.Format AllocsPerRun = %.0f", allocs)
	// Post-#496: 1 alloc on the drain path (the public Format's
	// defensive copy-out). Race detector adds a couple of
	// instrumentation allocs — threshold covers both. Tightened from
	// <= 10 (pre-#496 slack) as the per-field allocations are
	// eliminated (#496).
	const maxCEFAllocs = 5
	if allocs > maxCEFAllocs {
		t.Errorf("CEFFormatter.Format allocations = %.0f, want <= %d (#496 target: 1, +race slack)", allocs, maxCEFAllocs)
	}
}

// TestCEFFormatter_LargeEvent_AllocCount defends the #496 zero-per-
// field-alloc contract under a realistic 20-field event. Pre-#496 this
// was ~3 allocs/op (defensive copy + 2 amortised strconv+escape
// intermediates). Post-#496 it is 1 alloc/op — the defensive copy in
// the public Format path. Race detector adds a few instrumentation
// allocs; threshold covers that but is tight enough to catch a per-
// field regression.
func TestCEFFormatter_LargeEvent_AllocCount(t *testing.T) {
	cf := &audit.CEFFormatter{
		Vendor:  "TestVendor",
		Product: "TestProduct",
		Version: "1.0",
	}
	fields, def := largeEventFixture()
	ts := testTime

	// Warm the formatter buffer pool so the first-call growth
	// allocation doesn't skew AllocsPerRun's average.
	_, _ = cf.Format(ts, "api_request", fields, def, nil)

	allocs := testing.AllocsPerRun(500, func() {
		_, _ = cf.Format(ts, "api_request", fields, def, nil)
	})

	t.Logf("CEFFormatter.Format (20 fields) AllocsPerRun = %.2f", allocs)
	// Post-#496 baseline: 1 alloc (defensive copy). -race adds ~1-3
	// instrumentation allocs; 4 is a tight cap that catches a return
	// to per-field allocation while leaving race-detector headroom.
	const maxCEFLargeAllocs = 4
	if allocs > maxCEFLargeAllocs {
		t.Errorf("CEFFormatter.Format (20 fields) allocations = %.2f, want <= %d (#496 target: 1 + race slack)",
			allocs, maxCEFLargeAllocs)
	}
}

func TestJSONFormatter_AllocCount(t *testing.T) {
	jf := &audit.JSONFormatter{}
	def := &audit.EventDef{
		Required: []string{"outcome", "actor_id", "subject"},
		Optional: []string{"version"},
	}
	fields := audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "my-topic",
		"version":  1,
	}
	ts := testTime

	allocs := testing.AllocsPerRun(100, func() {
		_, _ = jf.Format(ts, "schema_register", fields, def, nil)
	})

	t.Logf("JSONFormatter.Format AllocsPerRun = %.0f", allocs)
	// Measured: 25 allocs normally, ~41 with -race. The race detector
	// instruments memory operations and adds significant allocations.
	// Threshold covers both modes.
	const maxJSONAllocs = 45
	if allocs > maxJSONAllocs {
		t.Errorf("JSONFormatter.Format allocations = %.0f, want <= %d", allocs, maxJSONAllocs)
	}
}

func TestCEFFormatter_NullByteStripped(t *testing.T) {
	f := &audit.CEFFormatter{Vendor: "V", Product: "P", Version: "1"}
	data, err := f.Format(testTime, "ev", audit.Fields{
		"outcome": "ok\x00injected",
	}, &audit.EventDef{
		Required: []string{"outcome"},
	}, nil)
	require.NoError(t, err)
	assert.NotContains(t, string(data), "\x00", "null bytes must be stripped")
}

func TestCEFFormatter_Format_DuplicateExtKey(t *testing.T) {
	baseDef := &audit.EventDef{
		Required: []string{"outcome"},
		Optional: []string{"source_ip", "actor_id"},
	}

	t.Run("rt_collision", func(t *testing.T) {
		f := &audit.CEFFormatter{
			Vendor:       "V",
			Product:      "P",
			Version:      "1",
			FieldMapping: map[string]string{"source_ip": "rt"},
		}
		data, err := f.Format(testTime, "ev", audit.Fields{
			"outcome":   "ok",
			"source_ip": "10.0.0.1",
		}, baseDef, nil)
		require.NoError(t, err)
		output := string(data)
		assert.Equal(t, 1, strings.Count(output, "rt="),
			"framework rt should appear once, user collision skipped")
		// Verify the framework value (epoch ms timestamp) survived, not the user value.
		assert.Contains(t, output,
			"rt="+strconv.FormatInt(testTime.UnixMilli(), 10))
		assert.NotContains(t, output, "rt=10.0.0.1")
	})

	t.Run("act_collision", func(t *testing.T) {
		f := &audit.CEFFormatter{
			Vendor:       "V",
			Product:      "P",
			Version:      "1",
			FieldMapping: map[string]string{"actor_id": "act"},
		}
		data, err := f.Format(testTime, "ev", audit.Fields{
			"outcome":  "ok",
			"actor_id": "alice",
		}, baseDef, nil)
		require.NoError(t, err)
		output := string(data)
		assert.Equal(t, 1, strings.Count(output, "act="),
			"framework act should appear once, user collision skipped")
		// Verify the framework value (event type) survived, not the user value.
		assert.Contains(t, output, "act=ev")
		assert.NotContains(t, output, "act=alice")
	})

	t.Run("cn1_with_duration", func(t *testing.T) {
		def := &audit.EventDef{
			Required: []string{"outcome"},
			Optional: []string{"actor_id", "duration_ms"},
		}
		f := &audit.CEFFormatter{
			Vendor:       "V",
			Product:      "P",
			Version:      "1",
			FieldMapping: map[string]string{"actor_id": "cn1"},
		}
		data, err := f.Format(testTime, "ev", audit.Fields{
			"outcome":     "ok",
			"actor_id":    "alice",
			"duration_ms": 500 * time.Millisecond,
		}, def, nil)
		require.NoError(t, err)
		output := string(data)
		assert.Equal(t, 1, strings.Count(output, "cn1="),
			"framework cn1 (duration) should appear once, user collision skipped")
	})

	t.Run("cn1_without_duration", func(t *testing.T) {
		f := &audit.CEFFormatter{
			Vendor:       "V",
			Product:      "P",
			Version:      "1",
			FieldMapping: map[string]string{"actor_id": "cn1"},
		}
		data, err := f.Format(testTime, "ev", audit.Fields{
			"outcome":  "ok",
			"actor_id": "alice",
		}, baseDef, nil)
		require.NoError(t, err)
		output := string(data)
		assert.Equal(t, 1, strings.Count(output, "cn1="),
			"cn1 not reserved when duration_ms absent, consumer mapping permitted")
		assert.Contains(t, output, "cn1=alice")
	})
}

func TestCEFFormatter_FrameworkField_Collision(t *testing.T) {
	t.Parallel()
	baseDef := &audit.EventDef{
		Required: []string{"outcome"},
		Optional: []string{"source_ip"},
	}

	for _, tc := range []struct {
		name    string
		cefKey  string
		value   string
		appName string
		host    string
		tz      string
		pid     int
	}{
		{"deviceProcessName", "deviceProcessName", "myapp", "myapp", "", "", 0},
		{"dvchost", "dvchost", "prod-01", "", "prod-01", "", 0},
		{"dtz", "dtz", "UTC", "", "", "UTC", 0},
		{"dvcpid", "dvcpid", "12345", "", "", "", 12345},
	} {
		t.Run(tc.name+"_collision", func(t *testing.T) {
			t.Parallel()
			f := &audit.CEFFormatter{
				Vendor:       "V",
				Product:      "P",
				Version:      "1",
				FieldMapping: map[string]string{"source_ip": tc.cefKey},
			}
			f.SetFrameworkFields(tc.appName, tc.host, tc.tz, tc.pid)
			data, err := f.Format(testTime, "ev", audit.Fields{
				"outcome":   "ok",
				"source_ip": "10.0.0.1",
			}, baseDef, nil)
			require.NoError(t, err)
			output := string(data)
			assert.Equal(t, 1, strings.Count(output, tc.cefKey+"="),
				"framework %s should appear once, user collision skipped", tc.cefKey)
			assert.Contains(t, output, tc.cefKey+"="+tc.value)
			assert.NotContains(t, output, tc.cefKey+"=10.0.0.1")
		})
	}
}

func TestJSONFormatter_FrameworkFields_Ordering(t *testing.T) {
	t.Parallel()
	jf := &audit.JSONFormatter{}
	jf.SetFrameworkFields("myapp", "prod-01", "UTC", 12345)

	data, err := jf.Format(testTime, "ev", audit.Fields{
		"outcome":     "success",
		"duration_ms": 250 * time.Millisecond,
	}, &audit.EventDef{
		Required: []string{"outcome"},
		Optional: []string{"duration_ms"},
	}, nil)
	require.NoError(t, err)

	raw := string(data)
	durIdx := strings.Index(raw, `"duration_ms"`)
	appIdx := strings.Index(raw, `"app_name"`)
	pidIdx := strings.Index(raw, `"pid"`)
	outcomeIdx := strings.Index(raw, `"outcome"`)

	assert.Less(t, durIdx, appIdx, "duration_ms before app_name")
	assert.Less(t, appIdx, pidIdx, "app_name before pid")
	assert.Less(t, pidIdx, outcomeIdx, "pid before user fields")
}

// ---------------------------------------------------------------------------
// WriteJSONString tests
// ---------------------------------------------------------------------------

func TestWriteJSONString(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{name: "empty", input: ""},
		{name: "plain_ascii", input: "hello world"},
		{name: "quotes", input: `say "hello"`},
		{name: "backslash", input: `back\slash`},
		{name: "newline", input: "line1\nline2"},
		{name: "tab", input: "col1\tcol2"},
		{name: "carriage_return", input: "line1\rline2"},
		{name: "null_byte", input: "null\x00byte"},
		{name: "all_control_chars", input: "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"},
		{name: "html_lt", input: "<script>"},
		{name: "html_gt", input: "value>other"},
		{name: "html_amp", input: "a&b"},
		{name: "html_mixed", input: `<a href="x&y">`},
		{name: "utf8_emoji", input: "hello 🎉 world"},
		{name: "utf8_cjk", input: "日本語テスト"},
		{name: "utf8_accented", input: "café résumé"},
		{name: "invalid_utf8", input: "bad\xfe\xffbyte"},
		{name: "line_separator_u2028", input: "before\u2028after"},
		{name: "paragraph_separator_u2029", input: "before\u2029after"},
		{name: "mixed_special", input: "line1\nline2\t\"quoted\"\\back<html>&amp;"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			audit.WriteJSONString(&buf, tt.input)
			got := buf.Bytes()

			want, err := json.Marshal(tt.input)
			require.NoError(t, err)

			assert.Equal(t, string(want), string(got),
				"WriteJSONString output must match json.Marshal")
		})
	}
}

// TestJSONFormatter_TimestampAppendFormat verifies that the
// ts.AppendFormat + AvailableBuffer pattern produces the same
// timestamp output as the old json.Marshal(ts.Format(...)) approach.
func TestJSONFormatter_TimestampAppendFormat(t *testing.T) {
	f := &audit.JSONFormatter{Timestamp: audit.TimestampRFC3339Nano}
	def := &audit.EventDef{Required: []string{"outcome"}}

	// Use a timestamp with nanosecond precision and a timezone offset
	// to exercise all format components.
	ts := time.Date(2026, 3, 28, 15, 4, 5, 123456789, time.FixedZone("EST", -5*60*60))

	data, err := f.Format(ts, "ev", audit.Fields{"outcome": "ok"}, def, nil)
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(data, &m))

	got, ok := m["timestamp"].(string)
	require.True(t, ok, "timestamp should be a string")
	want := ts.Format(time.RFC3339Nano)
	assert.Equal(t, want, got,
		"AppendFormat timestamp must match Format() string")
}

// TestJSONFormatter_PoolSafety verifies that the sync.Pool buffer
// reuse does not corrupt cached Format() results. This validates the
// copy-before-return pattern that prevents the pool-vs-cache race
// described in issue #101.
func TestJSONFormatter_PoolSafety(t *testing.T) {
	f := &audit.JSONFormatter{}
	def := &audit.EventDef{
		Required: []string{"outcome"},
	}
	ts := time.Now()

	// Call Format twice in succession. The second call should reuse
	// the pooled buffer but must not corrupt the first result.
	result1, err := f.Format(ts, "ev1", audit.Fields{"outcome": "first"}, def, nil)
	require.NoError(t, err)

	result2, err := f.Format(ts, "ev2", audit.Fields{"outcome": "second"}, def, nil)
	require.NoError(t, err)

	// Both results must be independent — the first must not have been
	// overwritten by the second.
	assert.Contains(t, string(result1), `"outcome":"first"`)
	assert.Contains(t, string(result2), `"outcome":"second"`)
	assert.NotEqual(t, result1, result2)
}

func TestJSONFormatter_HTMLSafeEscaping(t *testing.T) {
	t.Parallel()
	f := &audit.JSONFormatter{}
	def := &audit.EventDef{Required: []string{"payload"}}
	fields := audit.Fields{"payload": `<script>alert("xss")</script>`}

	data, err := f.Format(time.Now(), "test_event", fields, def, nil)
	require.NoError(t, err)

	// HTML-special chars must be escaped (matching json.Marshal behaviour).
	output := string(data)
	assert.NotContains(t, output, "<script>", "< must be escaped")
	assert.NotContains(t, output, "</script>", "> must be escaped")
	assert.Contains(t, output, `\u003c`, "< should be escaped as \\u003c")
	assert.Contains(t, output, `\u003e`, "> should be escaped as \\u003e")
}

func TestJSONFormatter_InvalidUTF8Replacement(t *testing.T) {
	t.Parallel()
	f := &audit.JSONFormatter{}
	def := &audit.EventDef{Required: []string{"data"}}
	// \x80\x81 are invalid UTF-8 continuation bytes.
	fields := audit.Fields{"data": "hello\x80\x81world"}

	data, err := f.Format(time.Now(), "test_event", fields, def, nil)
	require.NoError(t, err)

	output := string(data)
	assert.Contains(t, output, `\ufffd`, "invalid UTF-8 should be replaced with U+FFFD")
}

func TestWriteJSONString_QuickCheck(t *testing.T) {
	f := func(s string) bool {
		var buf bytes.Buffer
		audit.WriteJSONString(&buf, s)

		want, err := json.Marshal(s)
		if err != nil {
			return false
		}
		return bytes.Equal(buf.Bytes(), want)
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 10000}); err != nil {
		t.Errorf("WriteJSONString diverges from json.Marshal: %v", err)
	}
}

// TestWriteJSONBytes mirrors [TestWriteJSONString] for the []byte
// counterpart added in #494/#495. The two implementations MUST emit
// byte-identical output for any input — drift between them would make
// the loki output's `audit.WriteJSONBytes(buf, e.line)` call produce
// JSON that differs from the JSON formatter's serialised events.
func TestWriteJSONBytes(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{name: "empty", input: ""},
		{name: "plain_ascii", input: "hello world"},
		{name: "quotes", input: `say "hello"`},
		{name: "backslash", input: `back\slash`},
		{name: "newline", input: "line1\nline2"},
		{name: "tab", input: "col1\tcol2"},
		{name: "carriage_return", input: "line1\rline2"},
		{name: "null_byte", input: "null\x00byte"},
		{name: "all_control_chars", input: "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"},
		{name: "html_lt", input: "<script>"},
		{name: "html_gt", input: "value>other"},
		{name: "html_amp", input: "a&b"},
		{name: "html_mixed", input: `<a href="x&y">`},
		{name: "utf8_emoji", input: "hello 🎉 world"},
		{name: "utf8_cjk", input: "日本語テスト"},
		{name: "utf8_accented", input: "café résumé"},
		{name: "invalid_utf8", input: "bad\xfe\xffbyte"},
		{name: "line_separator_u2028", input: "before\u2028after"},
		{name: "paragraph_separator_u2029", input: "before\u2029after"},
		{name: "mixed_special", input: "line1\nline2\t\"quoted\"\\back<html>&amp;"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			audit.WriteJSONBytes(&buf, []byte(tt.input))
			got := buf.Bytes()

			want, err := json.Marshal(tt.input)
			require.NoError(t, err)

			assert.Equal(t, string(want), string(got),
				"WriteJSONBytes output must match json.Marshal")
		})
	}
}

// TestWriteJSONBytes_QuickCheck is the random-input parity test —
// across 10k random inputs, WriteJSONBytes must emit byte-identical
// output to encoding/json.Marshal. Catches drift between the
// hand-written byte path and the canonical Go encoder.
func TestWriteJSONBytes_QuickCheck(t *testing.T) {
	f := func(s string) bool {
		var buf bytes.Buffer
		audit.WriteJSONBytes(&buf, []byte(s))

		want, err := json.Marshal(s)
		if err != nil {
			return false
		}
		return bytes.Equal(buf.Bytes(), want)
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 10000}); err != nil {
		t.Errorf("WriteJSONBytes diverges from json.Marshal: %v", err)
	}
}

// TestWriteJSONBytes_MatchesWriteJSONString proves the two
// implementations cannot drift independently: any input that produces
// output X via WriteJSONString must produce the same X via
// WriteJSONBytes(string→[]byte). Random-input verification across
// 10k samples (#494/#495).
func TestWriteJSONBytes_MatchesWriteJSONString(t *testing.T) {
	f := func(s string) bool {
		var bufStr, bufBytes bytes.Buffer
		audit.WriteJSONString(&bufStr, s)
		audit.WriteJSONBytes(&bufBytes, []byte(s))
		return bytes.Equal(bufStr.Bytes(), bufBytes.Bytes())
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 10000}); err != nil {
		t.Errorf("WriteJSONBytes and WriteJSONString diverge: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Formatter benchmarks
// ---------------------------------------------------------------------------

func BenchmarkJSONFormatter_Format(b *testing.B) {
	f := &audit.JSONFormatter{}
	fields := audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "my-topic",
		"version":  1,
	}
	def := &audit.EventDef{
		Required: []string{"outcome", "actor_id", "subject"},
		Optional: []string{"version"},
	}
	audit.PrecomputeEventDefForTest(def)
	ts := time.Now()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = f.Format(ts, "schema_register", fields, def, nil)
	}
}

func BenchmarkCEFFormatter_Format(b *testing.B) {
	f := &audit.CEFFormatter{
		Vendor:  "TestVendor",
		Product: "TestProduct",
		Version: "1.0",
	}
	fields := audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "my-topic",
		"version":  1,
	}
	def := &audit.EventDef{
		Required: []string{"outcome", "actor_id", "subject"},
		Optional: []string{"version"},
	}
	audit.PrecomputeEventDefForTest(def)
	ts := time.Now()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = f.Format(ts, "schema_register", fields, def, nil)
	}
}

// largeEventFixture returns a 20-field event for benchmarking formatter
// scaling with production-realistic field counts.
func largeEventFixture() (audit.Fields, *audit.EventDef) {
	def := &audit.EventDef{
		Required: []string{"outcome", "actor_id", "method", "path", "source_ip"},
		Optional: []string{
			"request_id", "user_agent", "subject", "schema_type", "version",
			"cluster", "datacenter", "tenant_id", "session_id", "trace_id",
			"span_id", "response_code", "content_type", "payload_size", "tags",
		},
	}
	fields := audit.Fields{
		"outcome":       "success",
		"actor_id":      "alice",
		"method":        "POST",
		"path":          "/api/v1/schemas",
		"source_ip":     "10.0.0.1",
		"request_id":    "550e8400-e29b-41d4-a716-446655440000",
		"user_agent":    "audit-client/1.0",
		"subject":       "my-topic",
		"schema_type":   "avro",
		"version":       3,
		"cluster":       "prod-us-east-1",
		"datacenter":    "dc1",
		"tenant_id":     "tenant-42",
		"session_id":    "sess-abc123",
		"trace_id":      "4bf92f3577b34da6a3ce929d0e0e4736",
		"span_id":       "00f067aa0ba902b7",
		"response_code": 200,
		"content_type":  "application/json",
		"payload_size":  1024,
		"tags":          "production,critical",
	}
	audit.PrecomputeEventDefForTest(def)
	return fields, def
}

func BenchmarkJSONFormatter_Format_LargeEvent(b *testing.B) {
	f := &audit.JSONFormatter{}
	fields, def := largeEventFixture()
	ts := time.Now()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = f.Format(ts, "api_request", fields, def, nil)
	}
}

func BenchmarkCEFFormatter_Format_LargeEvent(b *testing.B) {
	f := &audit.CEFFormatter{
		Vendor:  "TestVendor",
		Product: "TestProduct",
		Version: "1.0",
	}
	fields, def := largeEventFixture()
	ts := time.Now()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = f.Format(ts, "api_request", fields, def, nil)
	}
}

// BenchmarkCEFFormatter_Format_LargeEvent_Escaping exercises the CEF
// escape hot path — 20 fields where every string value contains at
// least one metacharacter (backslash, equals, newline, CR). Confirms
// the in-place writeEscapedExtValueString path remains zero-alloc
// under adversarial content, not just escape-clean fixtures (#496).
func BenchmarkCEFFormatter_Format_LargeEvent_Escaping(b *testing.B) {
	f := &audit.CEFFormatter{
		Vendor:  "TestVendor",
		Product: "TestProduct",
		Version: "1.0",
	}
	def := &audit.EventDef{
		Required: []string{"outcome", "actor_id"},
		Optional: []string{
			"subject", "schema_type", "method", "path",
			"source_ip", "request_id", "user_agent",
			"reason", "message", "dest_host", "role",
			"file_name", "file_path", "target_id",
			"source_host", "transport", "protocol", "referrer",
		},
	}
	fields := audit.Fields{
		"outcome":     `success\n`,
		"actor_id":    "alice=admin",
		"subject":     "topic\\nested",
		"schema_type": "avro=1",
		"method":      "POST\rGET",
		"path":        "/api/v1/schemas\n",
		"source_ip":   "10.0.0.1=src",
		"request_id":  "550e8400\r",
		"user_agent":  "audit-client/1.0\\",
		"reason":      "consumer requested=true",
		"message":     "ok\nfine",
		"dest_host":   "host=x",
		"role":        "admin\\",
		"file_name":   "report=final.pdf",
		"file_path":   "/tmp/\nfoo",
		"target_id":   "bob=user",
		"source_host": "src=host",
		"transport":   "tcp\n",
		"protocol":    "https=1",
		"referrer":    "https://example.com/?a=b",
	}
	ts := time.Now()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = f.Format(ts, "api_request", fields, def, nil)
	}
}

// BenchmarkCEFFormatter_Format_Numeric isolates the numeric-
// conversion hot path: 10 integer + float fields, no strings beyond
// the required actor_id/outcome. Measures the win from switching
// from strconv.Itoa → string → escape → WriteString to direct
// strconv.AppendInt-into-buffer via stack scratch (#496).
func BenchmarkCEFFormatter_Format_Numeric(b *testing.B) {
	f := &audit.CEFFormatter{
		Vendor:  "TestVendor",
		Product: "TestProduct",
		Version: "1.0",
	}
	def := &audit.EventDef{
		Required: []string{"outcome", "actor_id"},
		Optional: []string{
			"dest_port", "source_port", "file_size",
			"latency_ms", "request_count", "retry_count",
			"error_count", "byte_count", "total", "elapsed",
		},
	}
	fields := audit.Fields{
		"outcome":       "success",
		"actor_id":      "alice",
		"dest_port":     443,
		"source_port":   54321,
		"file_size":     int64(1048576),
		"latency_ms":    int64(123),
		"request_count": 42,
		"retry_count":   3,
		"error_count":   0,
		"byte_count":    uint64(9999999),
		"total":         3.14159,
		"elapsed":       float32(2.718),
	}
	ts := time.Now()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = f.Format(ts, "api_request", fields, def, nil)
	}
}

// BenchmarkCEFFormatter_Format_Duration isolates the duration_ms /
// cn1 branch at format_cef.go so regressions to that code path
// surface as allocation growth. Fixture supplies duration_ms as a
// [time.Duration] (the type that triggers the cn1 emit — other
// types route through the generic extensions). #663 removed the
// last remaining intermediate-string allocation on this branch.
//
// Expectation: 1 alloc/op = the defensive copy in the public
// [CEFFormatter.Format] path. Zero allocs would require the
// bufferedFormatter drain-side path, which this test does not
// exercise.
func BenchmarkCEFFormatter_Format_Duration(b *testing.B) {
	f := &audit.CEFFormatter{
		Vendor:  "TestVendor",
		Product: "TestProduct",
		Version: "1.0",
	}
	def := &audit.EventDef{
		Required: []string{"outcome", "actor_id"},
		Optional: []string{"duration_ms"},
	}
	fields := audit.Fields{
		"outcome":     "success",
		"actor_id":    "alice",
		"duration_ms": 500 * time.Millisecond,
	}
	ts := time.Now()

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		_, _ = f.Format(ts, "api_request", fields, def, nil)
	}
}

// BenchmarkCEFFormatter_Format_Parallel runs the large-event path
// under concurrency via b.RunParallel. Confirms the pool contention
// and buf.Grow(768) preflight do not introduce lock hotspots; ns/op
// MUST NOT scale linearly with GOMAXPROCS (sub-linear is acceptable,
// super-linear indicates a shared-state regression).
func BenchmarkCEFFormatter_Format_Parallel(b *testing.B) {
	f := &audit.CEFFormatter{
		Vendor:  "TestVendor",
		Product: "TestProduct",
		Version: "1.0",
	}
	fields, def := largeEventFixture()
	ts := time.Now()

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = f.Format(ts, "api_request", fields, def, nil)
		}
	})
}

func BenchmarkFormatJSON_WithConfigFields(b *testing.B) {
	f := &audit.JSONFormatter{}
	f.SetFrameworkFields("myapp", "prod-01", "UTC", 12345)
	def := &audit.EventDef{Required: []string{"outcome", "actor_id"}}
	fields := audit.Fields{"outcome": "success", "actor_id": "alice"}
	ts := time.Now()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = f.Format(ts, "user_create", fields, def, nil)
	}
}

func BenchmarkFormatCEF_WithConfigFields(b *testing.B) {
	f := &audit.CEFFormatter{Vendor: "V", Product: "P", Version: "1"}
	f.SetFrameworkFields("myapp", "prod-01", "UTC", 12345)
	def := &audit.EventDef{Required: []string{"outcome", "actor_id"}}
	fields := audit.Fields{"outcome": "success", "actor_id": "alice"}
	ts := time.Now()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = f.Format(ts, "user_create", fields, def, nil)
	}
}

func BenchmarkFormatJSON_WithAllReservedFields(b *testing.B) {
	f := &audit.JSONFormatter{}
	f.SetFrameworkFields("myapp", "prod-01", "UTC", 12345)
	def := &audit.EventDef{Required: []string{"outcome", "actor_id"}}
	fields := audit.Fields{
		"outcome": "success", "actor_id": "alice",
		"source_ip": "10.0.0.1", "dest_ip": "192.168.1.1",
		"method": "POST", "path": "/api/users",
		"request_id": "req-12345", "user_agent": "test/1.0",
		"reason": "admin request", "target_id": "user-42",
		"protocol": "HTTPS", "role": "admin",
	}
	ts := time.Now()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = f.Format(ts, "user_create", fields, def, nil)
	}
}

func BenchmarkFormatCEF_WithAllReservedFields(b *testing.B) {
	f := &audit.CEFFormatter{Vendor: "V", Product: "P", Version: "1"}
	f.SetFrameworkFields("myapp", "prod-01", "UTC", 12345)
	def := &audit.EventDef{Required: []string{"outcome", "actor_id"}}
	fields := audit.Fields{
		"outcome": "success", "actor_id": "alice",
		"source_ip": "10.0.0.1", "dest_ip": "192.168.1.1",
		"method": "POST", "path": "/api/users",
		"request_id": "req-12345", "user_agent": "test/1.0",
		"reason": "admin request", "target_id": "user-42",
		"protocol": "HTTPS", "role": "admin",
	}
	ts := time.Now()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = f.Format(ts, "user_create", fields, def, nil)
	}
}

// ---------------------------------------------------------------------------
// FormatOptions.IsExcluded tests
// ---------------------------------------------------------------------------

func TestFormatOptions_IsExcluded(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		opts     *audit.FormatOptions
		field    string
		excluded bool
	}{
		{"nil opts", nil, "email", false},
		{"nil FieldLabels", &audit.FormatOptions{ExcludedLabels: map[string]struct{}{"pii": {}}}, "email", false},
		{"nil ExcludedLabels", &audit.FormatOptions{FieldLabels: map[string]map[string]struct{}{"email": {"pii": {}}}}, "email", false},
		{"field not in FieldLabels", &audit.FormatOptions{
			ExcludedLabels: map[string]struct{}{"pii": {}},
			FieldLabels:    map[string]map[string]struct{}{"phone": {"pii": {}}},
		}, "email", false},
		{"label not excluded", &audit.FormatOptions{
			ExcludedLabels: map[string]struct{}{"financial": {}},
			FieldLabels:    map[string]map[string]struct{}{"email": {"pii": {}}},
		}, "email", false},
		{"label excluded", &audit.FormatOptions{
			ExcludedLabels: map[string]struct{}{"pii": {}},
			FieldLabels:    map[string]map[string]struct{}{"email": {"pii": {}}},
		}, "email", true},
		{"multi label one excluded", &audit.FormatOptions{
			ExcludedLabels: map[string]struct{}{"financial": {}},
			FieldLabels:    map[string]map[string]struct{}{"card": {"pii": {}, "financial": {}}},
		}, "card", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.excluded, tt.opts.IsExcluded(tt.field))
		})
	}
}

func TestJSONFormatter_Format_WithExclusion(t *testing.T) {
	t.Parallel()
	f := &audit.JSONFormatter{}
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	def := &audit.EventDef{
		Required: []string{"outcome"},
		Optional: []string{"email", "name"},
	}
	fields := audit.Fields{
		"outcome": "success",
		"email":   "alice@example.com",
		"name":    "Alice",
	}
	opts := &audit.FormatOptions{
		ExcludedLabels: map[string]struct{}{"pii": {}},
		FieldLabels:    map[string]map[string]struct{}{"email": {"pii": {}}},
	}

	data, err := f.Format(ts, "user_create", fields, def, opts)
	require.NoError(t, err)
	s := string(data)

	assert.NotContains(t, s, "email")
	assert.NotContains(t, s, "alice@example.com")
	assert.Contains(t, s, `"name":"Alice"`)
	assert.Contains(t, s, `"outcome":"success"`)
	assert.Contains(t, s, `"event_type":"user_create"`)
}

func TestCEFFormatter_Format_WithExclusion(t *testing.T) {
	t.Parallel()
	f := &audit.CEFFormatter{Vendor: "Test", Product: "Test", Version: "1.0"}
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	def := &audit.EventDef{
		Required: []string{"outcome"},
		Optional: []string{"email"},
	}
	fields := audit.Fields{
		"outcome": "success",
		"email":   "alice@example.com",
	}
	opts := &audit.FormatOptions{
		ExcludedLabels: map[string]struct{}{"pii": {}},
		FieldLabels:    map[string]map[string]struct{}{"email": {"pii": {}}},
	}

	data, err := f.Format(ts, "user_create", fields, def, opts)
	require.NoError(t, err)
	s := string(data)

	assert.NotContains(t, s, "alice@example.com")
	assert.Contains(t, s, "outcome=success")
}

func TestCEFFormatter_RejectsLongVendor(t *testing.T) {
	t.Parallel()
	f := &audit.CEFFormatter{
		Vendor:  strings.Repeat("x", 256),
		Product: "P",
		Version: "1",
	}
	_, err := f.Format(testTime, "ev", audit.Fields{"outcome": "ok"}, &audit.EventDef{Required: []string{"outcome"}}, nil)
	assert.Error(t, err)
	// text-only: format_cef.go:280 returns raw fmt.Errorf without an audit sentinel wrap.
	assert.Contains(t, err.Error(), "vendor")
}

func TestCEFFormatter_RejectsLongProduct(t *testing.T) {
	t.Parallel()
	f := &audit.CEFFormatter{
		Vendor:  "V",
		Product: strings.Repeat("x", 256),
		Version: "1",
	}
	_, err := f.Format(testTime, "ev", audit.Fields{"outcome": "ok"}, &audit.EventDef{Required: []string{"outcome"}}, nil)
	assert.Error(t, err)
	// text-only: format_cef.go:283 returns raw fmt.Errorf without an audit sentinel wrap.
	assert.Contains(t, err.Error(), "product")
}

func TestCEFFormatter_RejectsLongVersion(t *testing.T) {
	t.Parallel()
	f := &audit.CEFFormatter{
		Vendor:  "V",
		Product: "P",
		Version: strings.Repeat("x", 256),
	}
	_, err := f.Format(testTime, "ev", audit.Fields{"outcome": "ok"}, &audit.EventDef{Required: []string{"outcome"}}, nil)
	assert.Error(t, err)
	// text-only: format_cef.go:286 returns raw fmt.Errorf without an audit sentinel wrap.
	assert.Contains(t, err.Error(), "version")
}

func TestCEFFormatter_AcceptsBoundaryVendor(t *testing.T) {
	t.Parallel()
	f := &audit.CEFFormatter{
		Vendor:  strings.Repeat("x", 255),
		Product: "P",
		Version: "1",
	}
	_, err := f.Format(testTime, "ev", audit.Fields{"outcome": "ok"}, &audit.EventDef{Required: []string{"outcome"}}, nil)
	assert.NoError(t, err)
}

// TestCEFFormatter_ConcurrentFormat is the named contract test from
// #589. It verifies the [audit.Formatter] interface's documented
// concurrency contract: a single formatter instance MAY be shared
// across goroutines and MUST be safe for concurrent use.
//
// The test runs Format from 64 goroutines against one *CEFFormatter
// instance. Combined with `go test -race`, it locks the contract at
// compile time — any future regression that introduces an unguarded
// write to shared formatter state (e.g. removing the sync.Once
// around fieldMapping) will fail here under the race detector.
func TestCEFFormatter_ConcurrentFormat(t *testing.T) {
	t.Parallel()
	f := &audit.CEFFormatter{
		Vendor:  "AxonOps",
		Product: "Audit",
		Version: "1.0",
		FieldMapping: map[string]string{
			"actor_id": "suser",
			"outcome":  "outcome",
		},
	}
	def := &audit.EventDef{
		Required: []string{"outcome", "actor_id"},
	}

	const goroutines = 64
	const iterations = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)
	errCh := make(chan error, goroutines*iterations)

	for g := range goroutines {
		go func(id int) {
			defer wg.Done()
			for i := range iterations {
				fields := audit.Fields{
					"outcome":  "success",
					"actor_id": fmt.Sprintf("goroutine-%d-iter-%d", id, i),
				}
				line, err := f.Format(testTime, "user_create", fields, def, nil)
				if err != nil {
					errCh <- err
					return
				}
				// Basic CEF header sanity — concurrent access must not
				// corrupt the output.
				if !bytes.HasPrefix(line, []byte("CEF:0|AxonOps|Audit|1.0|")) {
					errCh <- fmt.Errorf("goroutine %d iter %d: malformed CEF header: %s", id, i, line)
					return
				}
			}
		}(g)
	}
	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent Format failure: %v", err)
	}
}

// TestJSONFormatter_ConcurrentFormat mirrors
// TestCEFFormatter_ConcurrentFormat for [audit.JSONFormatter]. Though
// JSONFormatter holds only write-once configuration, the contract
// test locks the concurrent-safety guarantee in place regardless of
// future implementation drift.
func TestJSONFormatter_ConcurrentFormat(t *testing.T) {
	t.Parallel()
	f := &audit.JSONFormatter{}
	def := &audit.EventDef{Required: []string{"outcome", "actor_id"}}

	const goroutines = 64
	const iterations = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)
	errCh := make(chan error, goroutines*iterations)

	for g := range goroutines {
		go func(id int) {
			defer wg.Done()
			for i := range iterations {
				fields := audit.Fields{
					"outcome":  "success",
					"actor_id": fmt.Sprintf("g%d-i%d", id, i),
				}
				line, err := f.Format(testTime, "user_create", fields, def, nil)
				if err != nil {
					errCh <- err
					return
				}
				// Confirm the output is valid JSON; concurrent access
				// must not interleave bytes from different goroutines.
				var m map[string]any
				if jerr := json.Unmarshal(bytes.TrimSuffix(line, []byte{'\n'}), &m); jerr != nil {
					errCh <- fmt.Errorf("goroutine %d iter %d: invalid JSON: %w: %s", id, i, jerr, line)
					return
				}
			}
		}(g)
	}
	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent Format failure: %v", err)
	}
}

// TestCEFFormatter_FieldMapping_DropDefault_ViaDelete is the named
// contract test from issue #591 AC #1. It verifies the empty-string
// opt-out sentinel: passing `{"actor_id": ""}` drops the default
// actor_id → suser mapping so actor_id is emitted under its raw
// audit field name.
//
// Test name retained as "ViaDelete" per issue #591 acceptance
// criteria; the mechanism is the empty-string sentinel which
// performs the delete from the merged mapping internally.
func TestCEFFormatter_FieldMapping_DropDefault_ViaDelete(t *testing.T) {
	t.Parallel()
	f := &audit.CEFFormatter{
		Vendor:  "V",
		Product: "P",
		Version: "1",
		FieldMapping: map[string]string{
			"actor_id": "", // empty-string opt-out sentinel
		},
	}

	data, err := f.Format(testTime, "user_create", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
	}, &audit.EventDef{Required: []string{"outcome", "actor_id"}}, nil)
	require.NoError(t, err)

	line := string(data)
	assert.Contains(t, line, "actor_id=alice",
		"actor_id must emit as its raw audit field name after empty-string opt-out")
	assert.NotContains(t, line, "suser=",
		"default actor_id→suser mapping must be suppressed")
}

// TestCEFFormatter_FieldMapping_NoEscape_SelfMap is the named contract
// test from issue #591 AC #1. It verifies the second documented opt-out
// pattern: pass a self-mapping entry (field → its own name) to override
// the default mapping for that specific field without touching any
// other default.
func TestCEFFormatter_FieldMapping_NoEscape_SelfMap(t *testing.T) {
	t.Parallel()
	f := &audit.CEFFormatter{
		Vendor:  "V",
		Product: "P",
		Version: "1",
		FieldMapping: map[string]string{
			"actor_id": "actor_id",
		},
	}

	data, err := f.Format(testTime, "user_create", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
	}, &audit.EventDef{Required: []string{"outcome", "actor_id"}}, nil)
	require.NoError(t, err)

	line := string(data)
	assert.Contains(t, line, "actor_id=alice",
		"self-map must emit actor_id as the extension key, not the suser default")
	assert.NotContains(t, line, "suser=",
		"default actor_id→suser mapping must be overridden by the self-map entry")
}

// ---------------------------------------------------------------------------
// #565 group G2 — formatter edge-case tests
// ---------------------------------------------------------------------------

// TestJSONFormatter_NullByteInValue proves that a NUL byte
// embedded in a string field does not truncate the value or
// produce invalid JSON. The Go encoding/json contract escapes
// `\u0000`; the test pins this so a future formatter change
// that forgets to escape control bytes is caught immediately.
// (#565 G2).
func TestJSONFormatter_NullByteInValue(t *testing.T) {
	f := &audit.JSONFormatter{}
	data, err := f.Format(testTime, "schema_register", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "before\x00after",
	}, testDef, nil)
	require.NoError(t, err)

	// Output is valid JSON (round-trips through encoding/json).
	var m map[string]any
	require.NoError(t, json.Unmarshal(data, &m),
		"NUL byte in value must be escaped, producing valid JSON")
	assert.Equal(t, "before\x00after", m["subject"],
		"NUL byte must round-trip — no truncation")
}

// TestJSONFormatter_SurrogateHalfPair proves that an unpaired
// UTF-16 high-surrogate byte sequence in a string field does not
// produce raw invalid UTF-8 bytes in the JSON output. The Go
// encoding/json contract replaces invalid UTF-8 with the Unicode
// replacement character (U+FFFD); this test pins the contract so
// a future change that surfaces raw surrogate halves is caught —
// invalid UTF-8 in audit payloads breaks downstream JSON parsers.
// (#565 G2).
func TestJSONFormatter_SurrogateHalfPair(t *testing.T) {
	f := &audit.JSONFormatter{}
	// Bytes 0xED 0xA0 0xBD are the UTF-8 encoding of the unpaired
	// UTF-16 high surrogate U+D83D. The byte sequence is invalid
	// UTF-8 (RFC 3629 excludes the surrogate range). Go accepts
	// the raw bytes via hex escape but the formatter must not
	// pass them through unaltered.
	subjectVal := "lonely-\xed\xa0\xbd-surrogate"
	data, err := f.Format(testTime, "schema_register", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  subjectVal,
	}, testDef, nil)
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(data, &m),
		"output must be valid JSON despite invalid UTF-8 in input")
	subject, ok := m["subject"].(string)
	require.True(t, ok, "subject must be a string")
	assert.Contains(t, subject, "\uFFFD",
		"unpaired surrogate must be replaced with U+FFFD")
}

// TestCEFFormatter_EmptyEvent proves that a CEF event with zero
// custom fields still produces a syntactically valid CEF header
// with required positional fields populated. The trailing pipe
// must be present even when no extensions follow it.
// (#565 G2).
func TestCEFFormatter_EmptyEvent(t *testing.T) {
	f := &audit.CEFFormatter{Vendor: "Test", Product: "audit", Version: "1.0"}
	emptyDef := &audit.EventDef{}
	data, err := f.Format(testTime, "schema_register", audit.Fields{}, emptyDef, nil)
	require.NoError(t, err)

	raw := string(data)
	// CEF format: CEF:Version|Vendor|Product|Version|Signature|Name|Severity|Extensions
	// The first 7 pipe-separated header fields must all be present.
	assert.True(t, strings.HasPrefix(raw, "CEF:0|Test|audit|1.0|"),
		"empty event must emit the CEF header prefix; got: %s", raw)
	// Trailing newline.
	assert.True(t, len(data) > 0 && data[len(data)-1] == '\n',
		"output must end with newline")
}

// TestCEFFormatter_AllReservedStandardFieldMappings exercises
// every entry in DefaultCEFFieldMapping with a known value and
// asserts the audit-field name is replaced by the documented CEF
// extension key in the emitted line. This is a regression sentinel
// for the mapping table — a silent edit would break SIEM queries
// in production.
// (#565 G2).
func TestCEFFormatter_AllReservedStandardFieldMappings(t *testing.T) {
	f := &audit.CEFFormatter{Vendor: "Test", Product: "audit", Version: "1.0"}
	mapping := audit.DefaultCEFFieldMapping()
	require.NotEmpty(t, mapping, "DefaultCEFFieldMapping must be non-empty")

	// Build a sentinel value per audit field; assert each maps
	// to its documented CEF key.
	fields := audit.Fields{}
	expectedKeys := make(map[string]string, len(mapping))
	for auditName, cefKey := range mapping {
		val := "v_" + auditName
		fields[auditName] = val
		expectedKeys[cefKey] = val
	}

	// EventDef must declare the optional fields so the formatter
	// emits them. Use a permissive def listing every audit field.
	def := &audit.EventDef{}
	for auditName := range mapping {
		def.Optional = append(def.Optional, auditName)
	}

	data, err := f.Format(testTime, "schema_register", fields, def, nil)
	require.NoError(t, err)
	raw := string(data)

	for cefKey, val := range expectedKeys {
		assertion := fmt.Sprintf("%s=%s", cefKey, val)
		assert.Contains(t, raw, assertion,
			"CEF output must contain mapped field %q with value %q", cefKey, val)
	}
}

// TestJSONFormatter_TimestampUnixMillis_EdgeCases proves that
// Unix-millis timestamp encoding handles boundary inputs
// deterministically: zero, positive, and negative values produce
// the expected integer encoding without panic or precision loss.
// (#565 G2).
func TestJSONFormatter_TimestampUnixMillis_EdgeCases(t *testing.T) {
	cases := []struct {
		ts     time.Time
		name   string
		wantMs int64
	}{
		{
			name:   "epoch zero",
			ts:     time.Unix(0, 0).UTC(),
			wantMs: 0,
		},
		{
			name:   "year 2000",
			ts:     time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC),
			wantMs: 946684800000,
		},
		{
			name:   "millisecond precision",
			ts:     time.Date(2026, 1, 1, 0, 0, 0, 123_000_000, time.UTC),
			wantMs: 1767225600123,
		},
		{
			name:   "negative pre-epoch",
			ts:     time.Date(1969, 12, 31, 23, 59, 59, 0, time.UTC),
			wantMs: -1000,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &audit.JSONFormatter{Timestamp: audit.TimestampUnixMillis}
			data, err := f.Format(tc.ts, "schema_register", audit.Fields{
				"outcome":  "success",
				"actor_id": "a",
				"subject":  "s",
			}, testDef, nil)
			require.NoError(t, err)
			var m map[string]any
			require.NoError(t, json.Unmarshal(data, &m))
			gotMs, ok := m["timestamp"].(float64)
			require.True(t, ok, "timestamp must be a JSON number; got %T", m["timestamp"])
			assert.InDelta(t, float64(tc.wantMs), gotMs, 0,
				"unix-ms timestamp must encode exactly")
		})
	}
}
