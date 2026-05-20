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
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/audit"
)

// cimDef is the EventDef used across CIM formatter tests. The CIM
// formatter is largely def-agnostic — it remaps field names by key,
// not by required/optional categorisation.
var cimDef = &audit.EventDef{
	Required: []string{"actor_id", "outcome"},
	Optional: []string{"event_category"},
}

func decodeCIM(t *testing.T, data []byte) map[string]any {
	t.Helper()
	require.NotEmpty(t, data)
	require.Equal(t, byte('\n'), data[len(data)-1], "output must terminate with newline")
	var m map[string]any
	require.NoError(t, json.Unmarshal(data[:len(data)-1], &m),
		"output must be valid JSON: %s", string(data))
	return m
}

// TestCIM_FrameworkFieldsMappedToCIMNames verifies the full mapping
// table (audit → CIM Change) for the most common event shape.
func TestCIM_FrameworkFieldsMappedToCIMNames(t *testing.T) {
	f := &audit.CIMChangeFormatter{}
	f.SetFrameworkFields("AxonOps:Audit", "host-01", "UTC", 12345)
	data, err := f.Format(testTime, "user_create", audit.Fields{
		"event_category": "account",
		"actor": map[string]any{
			"id":   "alice",
			"name": "Alice Cooper",
		},
		"target": map[string]any{
			"id":   "bob",
			"type": "user",
			"path": "/users/bob",
			"attrs": map[string]any{
				"role": "admin",
			},
		},
		"outcome":   "success",
		"source_ip": "10.0.0.5",
	}, cimDef, nil)
	require.NoError(t, err)

	m := decodeCIM(t, data)

	// _time is epoch seconds with ms precision.
	assert.InDelta(t, float64(testTime.UnixMilli())/1000.0, m["_time"], 0.001)

	// action ↔ event_type.
	assert.Equal(t, "user_create", m["action"])

	// change_type ↔ event_category.
	assert.Equal(t, "account", m["change_type"])

	// user / user_id / user_name from actor.
	assert.Equal(t, "alice", m["user_id"])
	assert.Equal(t, "Alice Cooper", m["user_name"])
	assert.NotNil(t, m["user"], "user must be present (nested actor)")

	// object / object_id / object_category / object_path / object_attrs.
	assert.Equal(t, "bob", m["object_id"])
	assert.Equal(t, "user", m["object_category"])
	assert.Equal(t, "/users/bob", m["object_path"])
	// object_attrs is JSON-stringified — decode + compare.
	attrStr, ok := m["object_attrs"].(string)
	require.True(t, ok, "object_attrs must be JSON-stringified")
	var attrs map[string]any
	require.NoError(t, json.Unmarshal([]byte(attrStr), &attrs))
	assert.Equal(t, "admin", attrs["role"])

	// status from outcome.
	assert.Equal(t, "success", m["status"])

	// src from source_ip.
	assert.Equal(t, "10.0.0.5", m["src"])

	// vendor_product from appName fallback.
	assert.Equal(t, "AxonOps:Audit", m["vendor_product"])

	// dvc + host from framework host.
	assert.Equal(t, "host-01", m["dvc"])
	assert.Equal(t, "host-01", m["host"])
}

// TestCIM_OutcomeSuccessMapsToStatusSuccess pins the success-path of
// the binary status collapse.
func TestCIM_OutcomeSuccessMapsToStatusSuccess(t *testing.T) {
	f := &audit.CIMChangeFormatter{}
	data, err := f.Format(testTime, "x", audit.Fields{"outcome": "success"}, cimDef, nil)
	require.NoError(t, err)
	m := decodeCIM(t, data)
	assert.Equal(t, "success", m["status"])
}

// TestCIM_OutcomeFailureMapsToStatusFailure covers the lossy collapse:
// every non-success outcome value collapses to "failure". The
// formatter's godoc lists "failure", "denied", "error", "pending",
// "unknown" — table-driven here, including case variants and
// non-string types. Also anchors that the ORIGINAL outcome value is
// PRESERVED via the pass-through (the collapse is lossy on `status`
// but `outcome` is recoverable downstream).
func TestCIM_OutcomeFailureMapsToStatusFailure(t *testing.T) {
	tests := []struct {
		outcome any
		name    string
	}{
		{"failure", "failure"},
		{"denied", "denied"},
		{"error", "error"},
		{"pending", "pending"},
		{"unknown", "unknown"},
		{"", "empty string"},
		{"FAILURE", "uppercase FAILURE"},
		{0, "int 0"},
		{nil, "nil"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := &audit.CIMChangeFormatter{}
			data, err := f.Format(testTime, "x", audit.Fields{"outcome": tc.outcome}, cimDef, nil)
			require.NoError(t, err)
			m := decodeCIM(t, data)
			assert.Equal(t, "failure", m["status"],
				"non-success outcome %v must collapse to failure", tc.outcome)
			// The original outcome value MUST be preserved alongside
			// the collapsed status so consumers can recover the
			// granular value.
			if tc.outcome != nil {
				assert.Contains(t, m, "outcome",
					"original outcome %v must be preserved alongside status", tc.outcome)
			}
		})
	}
}

// TestCIM_OutcomeIsPreservedAlongsideStatus pins the recoverability
// of the lossy collapse: every event with an outcome emits BOTH
// the collapsed `status` AND the original `outcome` so consumers
// can disambiguate downstream.
func TestCIM_OutcomeIsPreservedAlongsideStatus(t *testing.T) {
	f := &audit.CIMChangeFormatter{}
	data, err := f.Format(testTime, "x", audit.Fields{"outcome": "denied"}, cimDef, nil)
	require.NoError(t, err)
	m := decodeCIM(t, data)
	assert.Equal(t, "failure", m["status"], "binary CIM status")
	assert.Equal(t, "denied", m["outcome"], "original outcome preserved")
}

// TestCIM_OutcomeCaseInsensitiveSuccess — "Success" / "SUCCESS"
// match success. The collapse uses strings.EqualFold.
func TestCIM_OutcomeCaseInsensitiveSuccess(t *testing.T) {
	for _, s := range []string{"Success", "SUCCESS", "sUcCeSs"} {
		t.Run(s, func(t *testing.T) {
			f := &audit.CIMChangeFormatter{}
			data, err := f.Format(testTime, "x", audit.Fields{"outcome": s}, cimDef, nil)
			require.NoError(t, err)
			m := decodeCIM(t, data)
			assert.Equal(t, "success", m["status"],
				"case-insensitive success match must hold for %q", s)
		})
	}
}

// TestCIM_PreservesUnmappedCustomFields verifies that fields not in
// the CIM mapping table pass through to the output verbatim AND
// that MAPPED fields are NOT duplicated in their original form
// (anti-tautology: a mutant impl that emits everything via the
// pass-through would fail this test).
func TestCIM_PreservesUnmappedCustomFields(t *testing.T) {
	f := &audit.CIMChangeFormatter{}
	data, err := f.Format(testTime, "x", audit.Fields{
		"actor_id":       "alice",        // mapped → user_id
		"event_category": "account",      // mapped → change_type
		"source_ip":      "10.0.0.1",     // mapped → src
		"custom_field":   "custom_value", // unmapped
		"trace_id":       "abc-123",      // unmapped
		"approval_step":  3,              // unmapped
	}, cimDef, nil)
	require.NoError(t, err)
	m := decodeCIM(t, data)
	// Unmapped fields pass through verbatim.
	assert.Equal(t, "custom_value", m["custom_field"])
	assert.Equal(t, "abc-123", m["trace_id"])
	assert.Contains(t, []any{3.0, int64(3), float64(3)}, m["approval_step"])
	// Mapped fields are NOT duplicated under their original audit
	// key — they appear only under the CIM-canonical key.
	_, hasEventCategory := m["event_category"]
	assert.False(t, hasEventCategory,
		"event_category must be remapped to change_type, not duplicated")
	_, hasSourceIP := m["source_ip"]
	assert.False(t, hasSourceIP,
		"source_ip must be remapped to src, not duplicated")
	_, hasActorID := m["actor_id"]
	assert.False(t, hasActorID,
		"actor_id must be remapped to user_id, not duplicated")
	// And the CIM-canonical names are present.
	assert.Equal(t, "account", m["change_type"])
	assert.Equal(t, "10.0.0.1", m["src"])
	assert.Equal(t, "alice", m["user_id"])
}

// TestCIM_TargetIDFlatMappedToObjectID anchors the flat `target_id`
// mapping (separate from the nested `target.id` extraction).
func TestCIM_TargetIDFlatMappedToObjectID(t *testing.T) {
	f := &audit.CIMChangeFormatter{}
	data, err := f.Format(testTime, "x", audit.Fields{"target_id": "topic-7"}, cimDef, nil)
	require.NoError(t, err)
	m := decodeCIM(t, data)
	assert.Equal(t, "topic-7", m["object_id"])
	// And the original audit key is NOT duplicated.
	_, has := m["target_id"]
	assert.False(t, has, "target_id must be remapped to object_id")
}

// TestCIM_TargetFlatVariantsMapToObjectFields covers target_type,
// target_path, target_attrs (the flat variants that some audit
// schemas use instead of the nested `target.type` etc.).
func TestCIM_TargetFlatVariantsMapToObjectFields(t *testing.T) {
	f := &audit.CIMChangeFormatter{}
	data, err := f.Format(testTime, "x", audit.Fields{
		"target_type":  "user",
		"target_path":  "/users/bob",
		"target_attrs": map[string]any{"role": "admin"},
	}, cimDef, nil)
	require.NoError(t, err)
	m := decodeCIM(t, data)
	assert.Equal(t, "user", m["object_category"])
	assert.Equal(t, "/users/bob", m["object_path"])
	// target_attrs is JSON-stringified.
	require.Contains(t, m, "object_attrs")
	attrStr, ok := m["object_attrs"].(string)
	require.True(t, ok)
	var attrs map[string]any
	require.NoError(t, json.Unmarshal([]byte(attrStr), &attrs))
	assert.Equal(t, "admin", attrs["role"])
}

// TestCIM_ActorAsStringMap verifies the formatter handles a
// `map[string]string` actor (some taxonomy-generated code uses
// concrete-typed maps rather than `map[string]any`).
func TestCIM_ActorAsStringMap(t *testing.T) {
	f := &audit.CIMChangeFormatter{}
	data, err := f.Format(testTime, "x", audit.Fields{
		"actor": map[string]string{"id": "alice", "name": "Alice"},
	}, cimDef, nil)
	require.NoError(t, err)
	m := decodeCIM(t, data)
	assert.Equal(t, "alice", m["user_id"],
		"actor as map[string]string must still populate user_id")
	assert.Equal(t, "Alice", m["user_name"])
}

// TestCIM_FlatTargetIDOverridesNested anchors the precedence rule:
// when both nested `target.id` AND flat `target_id` are present,
// the flat value wins (explicit > derived).
func TestCIM_FlatTargetIDOverridesNested(t *testing.T) {
	f := &audit.CIMChangeFormatter{}
	data, err := f.Format(testTime, "x", audit.Fields{
		"target":    map[string]any{"id": "nested-id"},
		"target_id": "flat-id",
	}, cimDef, nil)
	require.NoError(t, err)
	m := decodeCIM(t, data)
	assert.Equal(t, "flat-id", m["object_id"],
		"flat target_id must override nested target.id")
}

// TestCIM_SeverityEmittedAsSeverityID verifies the CIM-flavoured
// `severity_id` name (avoids collision with consumer-supplied string
// `severity` fields).
func TestCIM_SeverityEmittedAsSeverityID(t *testing.T) {
	f := &audit.CIMChangeFormatter{}
	data, err := f.Format(testTime, "x", audit.Fields{}, cimDef, nil)
	require.NoError(t, err)
	m := decodeCIM(t, data)
	// severity_id is present and is a number (JSON decodes to float64).
	_, has := m["severity_id"]
	assert.True(t, has, "severity_id must be emitted from def.ResolvedSeverity()")
	// The legacy `severity` key MUST NOT be emitted under the CIM name.
	_, hasLegacy := m["severity"]
	assert.False(t, hasLegacy, "legacy `severity` name must not be emitted (use severity_id)")
}

// TestCIM_NilEventDef — the def parameter is documented as never nil
// when called by the library, but defensive testing: nil def must
// not panic and severity_id must be omitted.
func TestCIM_NilEventDef(t *testing.T) {
	f := &audit.CIMChangeFormatter{}
	data, err := f.Format(testTime, "x", audit.Fields{"actor_id": "alice"}, nil, nil)
	require.NoError(t, err)
	m := decodeCIM(t, data)
	_, has := m["severity_id"]
	assert.False(t, has, "severity_id must be omitted when def is nil")
	// Rest of the mapping still works.
	assert.Equal(t, "alice", m["user_id"])
}

// TestCIM_FormatOptions_ExcludeMappedField verifies that
// opts.IsExcluded() is honoured for MAPPED fields, not just for
// pass-through fields. A consumer who excludes `outcome` from a
// per-output route must not see `status` either (the formatter
// derives status from outcome).
func TestCIM_FormatOptions_ExcludeMappedField(t *testing.T) {
	// Construct FormatOptions with a "pii" label that excludes the
	// outcome and severity fields.
	opts := &audit.FormatOptions{
		ExcludedLabels: map[string]struct{}{"pii": {}},
		FieldLabels: map[string]map[string]struct{}{
			"outcome":  {"pii": {}},
			"severity": {"pii": {}},
		},
	}
	f := &audit.CIMChangeFormatter{}
	data, err := f.Format(testTime, "x", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
	}, cimDef, opts)
	require.NoError(t, err)
	m := decodeCIM(t, data)
	// status MUST NOT be emitted when outcome is excluded.
	_, hasStatus := m["status"]
	assert.False(t, hasStatus, "status must be omitted when outcome is excluded")
	// outcome itself MUST NOT be emitted (excluded by label).
	_, hasOutcome := m["outcome"]
	assert.False(t, hasOutcome, "outcome must be omitted when excluded")
	// severity_id MUST NOT be emitted when severity is excluded.
	_, hasSev := m["severity_id"]
	assert.False(t, hasSev, "severity_id must be omitted when severity is excluded")
	// Non-excluded mapped fields still appear.
	assert.Equal(t, "alice", m["user_id"])
}

// TestCIM_NestedActorObjectPreserved verifies that the full nested
// actor / target objects survive in the output alongside the
// flattened CIM user_id / object_id top-level fields.
func TestCIM_NestedActorObjectPreserved(t *testing.T) {
	f := &audit.CIMChangeFormatter{}
	data, err := f.Format(testTime, "x", audit.Fields{
		"actor": map[string]any{
			"id":   "alice",
			"name": "Alice Cooper",
			"role": "admin",
		},
		"target": map[string]any{
			"id":   "topic-1",
			"type": "topic",
		},
	}, cimDef, nil)
	require.NoError(t, err)
	m := decodeCIM(t, data)

	// Flattened CIM top-level fields.
	assert.Equal(t, "alice", m["user_id"])
	assert.Equal(t, "topic-1", m["object_id"])

	// Nested objects survive — including custom fields like "role".
	actor, ok := m["user"].(map[string]any)
	require.True(t, ok, "user must be a nested object; got %T", m["user"])
	assert.Equal(t, "admin", actor["role"],
		"nested actor object must preserve all original fields")

	target, ok := m["object"].(map[string]any)
	require.True(t, ok, "object must be a nested object; got %T", m["object"])
	assert.Equal(t, "topic", target["type"])
}

// TestCIM_VendorProductFromConfig — explicit VendorProduct option
// overrides the framework appName.
func TestCIM_VendorProductFromConfig(t *testing.T) {
	f := &audit.CIMChangeFormatter{VendorProduct: "Acme:CustomTag"}
	f.SetFrameworkFields("default-app-name", "h", "UTC", 0)
	data, err := f.Format(testTime, "x", audit.Fields{}, cimDef, nil)
	require.NoError(t, err)
	m := decodeCIM(t, data)
	assert.Equal(t, "Acme:CustomTag", m["vendor_product"],
		"VendorProduct option must override SetFrameworkFields appName")
}

// TestCIM_VendorProductFromFrameworkContext — when VendorProduct is
// empty, fall back to the appName supplied via SetFrameworkFields.
func TestCIM_VendorProductFromFrameworkContext(t *testing.T) {
	f := &audit.CIMChangeFormatter{}
	f.SetFrameworkFields("AxonOps:Audit", "h", "UTC", 0)
	data, err := f.Format(testTime, "x", audit.Fields{}, cimDef, nil)
	require.NoError(t, err)
	m := decodeCIM(t, data)
	assert.Equal(t, "AxonOps:Audit", m["vendor_product"])
}

// TestCIM_VendorProductOmittedWhenBothEmpty — when neither override
// nor appName is set, vendor_product is omitted (zero-value).
func TestCIM_VendorProductOmittedWhenBothEmpty(t *testing.T) {
	f := &audit.CIMChangeFormatter{}
	data, err := f.Format(testTime, "x", audit.Fields{}, cimDef, nil)
	require.NoError(t, err)
	m := decodeCIM(t, data)
	_, ok := m["vendor_product"]
	assert.False(t, ok, "vendor_product must be omitted when both override and appName are empty")
}

// TestCIM_ContentType pins the wire format.
func TestCIM_ContentType(t *testing.T) {
	f := &audit.CIMChangeFormatter{}
	assert.Equal(t, "application/x-ndjson", f.ContentType())
}

// TestCIM_NewlineDelimited verifies that the output is exactly one
// JSON object terminated by exactly one newline — the NDJSON
// contract Splunk's HEC /raw and webhook consumers depend on.
func TestCIM_NewlineDelimited(t *testing.T) {
	f := &audit.CIMChangeFormatter{}
	data, err := f.Format(testTime, "x", audit.Fields{"outcome": "success"}, cimDef, nil)
	require.NoError(t, err)
	// Exactly one newline.
	assert.Equal(t, 1, strings.Count(string(data), "\n"))
	// No embedded \n inside the JSON object.
	body := string(data[:len(data)-1])
	assert.NotContains(t, body, "\n",
		"NDJSON body must not contain embedded newlines")
}
