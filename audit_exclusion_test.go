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
// formatWithExclusion error path (#316)
// ---------------------------------------------------------------------------

// exclusionErrorFormatter returns an error only when FormatOptions is non-nil
// (i.e. when called through the formatWithExclusion path). This distinguishes
// it from the formatCached path where opts is nil.
type exclusionErrorFormatter struct{}

func (e *exclusionErrorFormatter) Format(_ time.Time, _ string, _ audit.Fields, _ *audit.EventDef, opts *audit.FormatOptions) ([]byte, error) {
	if opts != nil {
		return nil, errors.New("format error on exclusion path")
	}
	return []byte(`{"ok":true}` + "\n"), nil
}

func (e *exclusionErrorFormatter) ContentType() string { return "application/x-ndjson" }

// TestFormatWithExclusion_ErrorPath verifies that when Format returns an error
// through the formatWithExclusion path (sensitivity label stripping), the
// event is dropped and the serialization error is recorded in metrics.
func TestFormatWithExclusion_ErrorPath(t *testing.T) {
	t.Parallel()

	const taxYAML = `
version: 1
categories:
  write:
    events: [user_create]
sensitivity:
  labels:
    pii:
      description: "PII"
      fields: [email]
events:
  user_create:
    fields:
      outcome: {required: true}
      email:
        labels: [pii]
`
	tax, err := audit.ParseTaxonomyYAML([]byte(taxYAML))
	require.NoError(t, err)

	out := testhelper.NewMockOutput("excluded")
	metrics := testhelper.NewMockMetrics()

	auditor, err := audit.New(
		audit.WithTaxonomy(tax),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		// Excluding "pii" triggers formatWithExclusion (FormatOptions non-nil).
		audit.WithNamedOutput(out, audit.WithOutputFormatter(&exclusionErrorFormatter{}), audit.WithExcludeLabels("pii")),
		audit.WithMetrics(metrics),
	)
	require.NoError(t, err)

	err = auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"outcome": "success",
		"email":   "alice@example.com",
	}))
	require.NoError(t, err)
	require.NoError(t, auditor.Close())

	// The event should be dropped — formatter returned error on exclusion path.
	assert.Equal(t, 0, out.EventCount(),
		"output should receive nothing when formatter errors on exclusion path")

	// Serialization error metric should be recorded.
	assert.Greater(t, metrics.GetSerializationErrorCount("user_create"), 0,
		"serialization error metric must be recorded for format failure on exclusion path")
}
