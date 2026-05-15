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
// Filter tests
// ---------------------------------------------------------------------------

func TestLogger_EnableCategory(t *testing.T) {
	t.Parallel()

	out := testhelper.NewMockOutput("test")
	auditor := newTestAuditor(t, out)

	// Disable "read", then re-enable it.
	require.NoError(t, auditor.DisableCategory("read"))
	require.NoError(t, auditor.EnableCategory("read"))

	err := auditor.AuditEvent(audit.NewEvent("schema_read", audit.Fields{"outcome": "success"}))
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))
}

func TestLogger_DisableCategory(t *testing.T) {
	t.Parallel()

	out := testhelper.NewMockOutput("test")
	auditor := newTestAuditor(t, out)

	// Disable "write" at runtime.
	require.NoError(t, auditor.DisableCategory("write"))

	err := auditor.AuditEvent(audit.NewEvent("schema_register", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "test",
	}))
	require.NoError(t, err)

	// Send an enabled event as sentinel to prove processing.
	err = auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{"outcome": "failure", "actor_id": "sentinel"}))
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))
	assert.Equal(t, 1, out.EventCount(), "disabled category should not deliver events")
}

func TestLogger_EnableEvent_OverridesCategory(t *testing.T) {
	t.Parallel()

	out := testhelper.NewMockOutput("test")
	auditor := newTestAuditor(t, out)

	// Disable "read" category, then enable one specific event from it.
	require.NoError(t, auditor.DisableCategory("read"))
	require.NoError(t, auditor.EnableEvent("schema_read"))

	err := auditor.AuditEvent(audit.NewEvent("schema_read", audit.Fields{"outcome": "success"}))
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))

	// config_read (same category, no override) should still be filtered.
	err = auditor.AuditEvent(audit.NewEvent("config_read", audit.Fields{"outcome": "success"}))
	require.NoError(t, err)

	// Send an enabled event as sentinel, then verify only 2 events
	// (schema_read + sentinel), not 3.
	err = auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{"outcome": "failure", "actor_id": "sentinel"}))
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(2, 2*time.Second))
	assert.Equal(t, 2, out.EventCount(), "only overridden event + sentinel should be delivered")
}

func TestLogger_DisableEvent_OverridesCategory(t *testing.T) {
	t.Parallel()

	out := testhelper.NewMockOutput("test")
	auditor := newTestAuditor(t, out)

	// "write" category is enabled. Disable one specific event.
	require.NoError(t, auditor.DisableEvent("schema_register"))

	err := auditor.AuditEvent(audit.NewEvent("schema_register", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "test",
	}))
	require.NoError(t, err)

	// schema_delete (same category, no override) should still work.
	err = auditor.AuditEvent(audit.NewEvent("schema_delete", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "test",
	}))
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))
	assert.Equal(t, 1, out.EventCount(), "only non-overridden event should be delivered")
}

func TestLogger_Filter_InvalidCategory(t *testing.T) {
	t.Parallel()

	out := testhelper.NewMockOutput("test")
	auditor := newTestAuditor(t, out)

	err := auditor.EnableCategory("nonexistent")
	assert.Error(t, err)
	// text-only: EnableCategory/DisableCategory return raw fmt.Errorf
	// without a sentinel wrap (audit.go:793,809). The category-name
	// substring is the only stable contract.
	assert.Contains(t, err.Error(), "unknown category")

	err = auditor.DisableCategory("nonexistent")
	assert.Error(t, err)
}

func TestLogger_MultiCategory_DeliveredPerCategory(t *testing.T) {
	t.Parallel()
	out := testhelper.NewMockOutput("test")

	// Create a taxonomy where auth_failure is in both security and access.
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

	auditor, err := audit.New(
		audit.WithTaxonomy(tax),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditor.Close() })

	err = auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{"outcome": "failure"}))
	require.NoError(t, err)

	// Event in 2 categories → 2 deliveries to the unrouted output.
	require.True(t, out.WaitForEvents(2, 2*time.Second))
	assert.Equal(t, 2, out.EventCount(), "multi-category event should be delivered twice")
}

func TestLogger_MultiCategory_DisableOneCategory(t *testing.T) {
	t.Parallel()
	out := testhelper.NewMockOutput("test")

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

	auditor, err := audit.New(
		audit.WithTaxonomy(tax),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditor.Close() })

	// Disable one category.
	require.NoError(t, auditor.DisableCategory("security"))

	err = auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{"outcome": "failure"}))
	require.NoError(t, err)

	// Only the access pass should deliver.
	require.True(t, out.WaitForEvents(1, 2*time.Second))
	assert.Equal(t, 1, out.EventCount(), "should deliver once — only access category enabled")
}

func TestLogger_MultiCategory_DisableAllCategories(t *testing.T) {
	t.Parallel()
	out := testhelper.NewMockOutput("test")

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

	auditor, err := audit.New(
		audit.WithTaxonomy(tax),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditor.Close() })

	require.NoError(t, auditor.DisableCategory("security"))
	require.NoError(t, auditor.DisableCategory("access"))

	err = auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{"outcome": "failure"}))
	require.NoError(t, err)

	// Both categories disabled → event enters channel but no category
	// pass runs. Send a sentinel to prove processing completed.
	require.NoError(t, auditor.EnableCategory("security"))
	err = auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{"outcome": "sentinel"}))
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))
	assert.Equal(t, 1, out.EventCount(), "only sentinel should arrive — first event had all categories disabled")
}

func TestLogger_Uncategorised_DeliveredToUnroutedOutput(t *testing.T) {
	t.Parallel()
	out := testhelper.NewMockOutput("test")

	// data_export is not in any category.
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

	auditor, err := audit.New(
		audit.WithTaxonomy(tax),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditor.Close() })

	err = auditor.AuditEvent(audit.NewEvent("data_export", audit.Fields{"outcome": "success"}))
	require.NoError(t, err)

	require.True(t, out.WaitForEvents(1, 2*time.Second))
	assert.Equal(t, 1, out.EventCount(), "uncategorised event should be delivered to unrouted output")
}

func TestLogger_MultiCategory_EnableEventOverride(t *testing.T) {
	t.Parallel()
	out := testhelper.NewMockOutput("test")

	tax := &audit.Taxonomy{
		Version: 1,
		Categories: map[string]*audit.CategoryDef{
			"security":   {Events: []string{"auth_failure"}},
			"compliance": {Events: []string{"auth_failure"}},
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
	t.Cleanup(func() { _ = auditor.Close() })

	// Disable both categories, then force-enable the event.
	require.NoError(t, auditor.DisableCategory("security"))
	require.NoError(t, auditor.DisableCategory("compliance"))
	require.NoError(t, auditor.EnableEvent("auth_failure"))

	err = auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{"outcome": "failure"}))
	require.NoError(t, err)

	// EnableEvent should override disabled categories — event delivered
	// on ALL category passes (both security and compliance).
	require.True(t, out.WaitForEvents(2, 2*time.Second))
	assert.Equal(t, 2, out.EventCount(), "EnableEvent should deliver on all category passes")
}

func TestLogger_MultiCategory_IncludeRoute(t *testing.T) {
	t.Parallel()
	out := testhelper.NewMockOutput("test")

	tax := &audit.Taxonomy{
		Version: 1,
		Categories: map[string]*audit.CategoryDef{
			"security":   {Events: []string{"auth_failure"}},
			"compliance": {Events: []string{"auth_failure"}},
		},
		Events: map[string]*audit.EventDef{
			"auth_failure": {Required: []string{"outcome"}},
		},
	}

	auditor, err := audit.New(
		audit.WithTaxonomy(tax),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(out, audit.WithRoute(&audit.EventRoute{
			IncludeCategories: map[string]audit.SeverityRange{"security": {}},
		})),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditor.Close() })

	err = auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{"outcome": "failure"}))
	require.NoError(t, err)

	// Output includes only security — should get 1 delivery (security pass),
	// not 2 (compliance pass is filtered by the route).
	require.True(t, out.WaitForEvents(1, 2*time.Second))
	assert.Equal(t, 1, out.EventCount(), "include route should match only one category pass")
}

func TestLogger_MultiCategory_ExcludeRoute(t *testing.T) {
	t.Parallel()
	out := testhelper.NewMockOutput("test")

	tax := &audit.Taxonomy{
		Version: 1,
		Categories: map[string]*audit.CategoryDef{
			"security":   {Events: []string{"auth_failure"}},
			"compliance": {Events: []string{"auth_failure"}},
		},
		Events: map[string]*audit.EventDef{
			"auth_failure": {Required: []string{"outcome"}},
		},
	}

	auditor, err := audit.New(
		audit.WithTaxonomy(tax),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(out, audit.WithRoute(&audit.EventRoute{
			ExcludeCategories: []string{"security"},
		})),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditor.Close() })

	err = auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{"outcome": "failure"}))
	require.NoError(t, err)

	// Output excludes security — should get 1 delivery (compliance pass only).
	require.True(t, out.WaitForEvents(1, 2*time.Second))
	assert.Equal(t, 1, out.EventCount(), "exclude route should skip security, deliver compliance")
}

func TestLogger_Filter_InvalidEvent(t *testing.T) {
	t.Parallel()

	out := testhelper.NewMockOutput("test")
	auditor := newTestAuditor(t, out)

	err := auditor.EnableEvent("nonexistent")
	assert.Error(t, err)
	// text-only: EnableEvent/DisableEvent return raw fmt.Errorf without
	// a sentinel wrap (audit.go:825,842). The Auditor.AuditEvent path
	// uses ErrUnknownEventType, but the runtime-toggle methods don't.
	assert.Contains(t, err.Error(), "unknown event type")

	err = auditor.DisableEvent("nonexistent")
	assert.Error(t, err)
}
