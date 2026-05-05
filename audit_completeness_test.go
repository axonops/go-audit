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
// Field completeness tests
// ---------------------------------------------------------------------------

func TestLogger_Audit_FieldCompleteness_AllFieldsPresent(t *testing.T) {
	tax := &audit.Taxonomy{
		Version: 1,
		Categories: map[string]*audit.CategoryDef{
			"security": {Events: []string{"auth_check"}},
		},
		Events: map[string]*audit.EventDef{
			"auth_check": {
				Required: []string{"outcome", "actor_id", "actor_type"},
			},
		},
	}

	out := testhelper.NewMockOutput("field-test")
	auditor, err := audit.New(
		audit.WithTaxonomy(tax),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, auditor.Close()) })

	fields := audit.Fields{
		"outcome":     "success",
		"actor_id":    "alice",
		"actor_type":  "user",
		"target_type": "schema",
		"target_id":   "my-topic-value",
		"reason":      "valid_credentials",
		"source_ip":   "192.168.1.100",
		"user_agent":  "test-client/1.0",
		"request_id":  "req-12345",
	}
	require.NoError(t, auditor.AuditEvent(audit.NewEvent("auth_check", fields)))
	require.True(t, out.WaitForEvents(1, 2*time.Second))

	record := out.GetEvent(0)

	// Auto-populated fields.
	assert.Contains(t, record, "timestamp")
	assert.NotEmpty(t, record["timestamp"], "timestamp must not be empty")
	assert.Equal(t, "auth_check", record["event_type"])

	// All required fields present with correct values.
	for _, f := range tax.Events["auth_check"].Required {
		assert.Contains(t, record, f, "required field %q must be present", f)
	}

	// All optional fields we provided present with correct values.
	for _, f := range tax.Events["auth_check"].Optional {
		assert.Contains(t, record, f, "provided optional field %q must be present", f)
		assert.Equal(t, fields[f], record[f], "field %q value mismatch", f)
	}
}

func TestLogger_Audit_FieldCompleteness_OmittedOptionalFieldsAbsent(t *testing.T) {
	tax := &audit.Taxonomy{
		Version: 1,
		Categories: map[string]*audit.CategoryDef{
			"security": {Events: []string{"auth_check"}},
		},
		Events: map[string]*audit.EventDef{
			"auth_check": {
				Required: []string{"outcome", "actor_id"},
				Optional: []string{},
			},
		},
	}

	out := testhelper.NewMockOutput("field-test")
	auditor, err := audit.New(
		audit.WithOmitEmpty(),
		audit.WithTaxonomy(tax),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, auditor.Close()) })

	// Send event with only required fields — optional fields omitted.
	require.NoError(t, auditor.AuditEvent(audit.NewEvent("auth_check", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
	})))
	require.True(t, out.WaitForEvents(1, 2*time.Second))

	record := out.GetEvent(0)

	// Required fields must be present.
	assert.Equal(t, "success", record["outcome"])
	assert.Equal(t, "alice", record["actor_id"])

	// Optional fields not provided should be absent (OmitEmpty=true).
	for _, f := range tax.Events["auth_check"].Optional {
		assert.NotContains(t, record, f,
			"omitted optional field %q should not appear in output", f)
	}
}
