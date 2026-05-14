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
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/axonops/audit"
	"github.com/axonops/audit/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFanout_DeliverToAll(t *testing.T) {
	out1 := testhelper.NewMockOutput("out1")
	out2 := testhelper.NewMockOutput("out2")
	out3 := testhelper.NewMockOutput("out3")
	auditor, err := audit.New(
		audit.WithValidationMode(audit.ValidationPermissive),
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out1, out2, out3),
	)
	require.NoError(t, err)

	require.NoError(t, auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{"outcome": "success"})))
	require.NoError(t, auditor.Close())

	for _, out := range []*testhelper.MockOutput{out1, out2, out3} {
		assert.Equal(t, 1, out.EventCount(),
			"output %s should receive 1 event", out.Name())
	}
}

func TestFanout_OutputFailureIsolation(t *testing.T) {
	failing := testhelper.NewMockOutput("failing")
	failing.SetWriteErr(assert.AnError)
	healthy := testhelper.NewMockOutput("healthy")
	auditor, err := audit.New(
		audit.WithValidationMode(audit.ValidationPermissive),
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(failing, healthy),
	)
	require.NoError(t, err)

	require.NoError(t, auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{"outcome": "success"})))
	require.NoError(t, auditor.Close())

	assert.Equal(t, 1, healthy.EventCount(),
		"healthy output should receive event despite failing output")
}

func TestFanout_RouteFiltering(t *testing.T) {
	tests := []struct {
		name      string
		route     audit.EventRoute
		events    []string // event types to emit
		wantCount int
	}{
		{
			name:      "include category matches",
			route:     audit.EventRoute{IncludeCategories: map[string]*audit.SeverityRange{"security": nil}},
			events:    []string{"user_create", "auth_failure"},
			wantCount: 1, // only auth_failure
		},
		{
			name:      "include category no match",
			route:     audit.EventRoute{IncludeCategories: map[string]*audit.SeverityRange{"security": nil}},
			events:    []string{"user_create", "user_get"},
			wantCount: 0,
		},
		{
			name:      "include event type matches",
			route:     audit.EventRoute{IncludeEventTypes: []string{"auth_failure"}},
			events:    []string{"auth_failure", "permission_denied"},
			wantCount: 1, // only auth_failure
		},
		{
			name: "include union matches category and event type",
			route: audit.EventRoute{
				IncludeCategories: map[string]*audit.SeverityRange{"write": nil},
				IncludeEventTypes: []string{"auth_failure"},
			},
			events:    []string{"user_create", "auth_failure", "user_get"},
			wantCount: 2, // user_create (write) + auth_failure
		},
		{
			name:      "exclude category skips",
			route:     audit.EventRoute{ExcludeCategories: []string{"read"}},
			events:    []string{"user_create", "user_get"},
			wantCount: 1, // only user_create
		},
		{
			name:      "exclude event type skips",
			route:     audit.EventRoute{ExcludeEventTypes: []string{"config_get"}},
			events:    []string{"config_get", "user_get"},
			wantCount: 1, // only user_get
		},
		{
			name: "exclude union skips both",
			route: audit.EventRoute{
				ExcludeCategories: []string{"read"},
				ExcludeEventTypes: []string{"user_delete"},
			},
			events:    []string{"user_create", "user_delete", "user_get"},
			wantCount: 1, // only user_create
		},
		{
			name:      "empty route receives all",
			route:     audit.EventRoute{},
			events:    []string{"user_create", "auth_failure", "user_get"},
			wantCount: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := testhelper.NewMockOutput("routed")
			auditor, err := audit.New(
				audit.WithValidationMode(audit.ValidationPermissive),
				audit.WithTaxonomy(testhelper.TestTaxonomy()),
				audit.WithAppName("test-app"),
				audit.WithHost("test-host"),
				audit.WithNamedOutput(out, audit.WithRoute(&tt.route)),
			)
			require.NoError(t, err)

			for _, evt := range tt.events {
				require.NoError(t, auditor.AuditEvent(audit.NewEvent(evt, audit.Fields{"outcome": "success"})))
			}
			require.NoError(t, auditor.Close())

			assert.Equal(t, tt.wantCount, out.EventCount())
		})
	}
}

func TestFanout_DuplicateOutputName_Error(t *testing.T) {
	out1 := testhelper.NewMockOutput("same-name")
	out2 := testhelper.NewMockOutput("same-name")
	_, err := audit.New(
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out1, out2),
	)
	require.Error(t, err)
	// text-only: options.go:295 returns raw fmt.Errorf without a sentinel
	// wrap. The duplicate-name guard is internal to WithOutputs.
	assert.Contains(t, err.Error(), "duplicate output name")
}

func TestFanout_WithOutputs_AfterWithNamedOutput_Error(t *testing.T) {
	out1 := testhelper.NewMockOutput("named")
	out2 := testhelper.NewMockOutput("plain")
	_, err := audit.New(
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(out1, audit.WithRoute(&audit.EventRoute{})),
		audit.WithOutputs(out2), // should error
	)
	require.Error(t, err)
	// text-only: options.go:284 returns raw fmt.Errorf without a sentinel
	// wrap (mutual-exclusion guard between WithOutputs / WithNamedOutput).
	assert.Contains(t, err.Error(), "cannot be used with WithNamedOutput")
}

func TestFanout_WithNamedOutput_AfterWithOutputs_Error(t *testing.T) {
	out1 := testhelper.NewMockOutput("plain")
	out2 := testhelper.NewMockOutput("named")
	_, err := audit.New(
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out1),
		audit.WithNamedOutput(out2, audit.WithRoute(&audit.EventRoute{})), // should error
	)
	require.Error(t, err)
	// text-only: options.go:383 returns raw fmt.Errorf without a sentinel
	// wrap (mutual-exclusion guard between WithOutputs / WithNamedOutput).
	assert.Contains(t, err.Error(), "cannot be used with WithOutputs")
}

func TestFanout_BootstrapValidation_UnknownCategory(t *testing.T) {
	out := testhelper.NewMockOutput("test")
	_, err := audit.New(
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(out, audit.WithRoute(&audit.EventRoute{
			IncludeCategories: map[string]*audit.SeverityRange{"nonexistent": nil},
		})),
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrConfigInvalid)
	assert.Contains(t, err.Error(), "unknown taxonomy entries")
}

func TestFanout_BootstrapValidation_MixedMode(t *testing.T) {
	out := testhelper.NewMockOutput("test")
	_, err := audit.New(
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(out, audit.WithRoute(&audit.EventRoute{
			IncludeCategories: map[string]*audit.SeverityRange{"write": nil},
			ExcludeCategories: []string{"read"},
		})),
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrConfigInvalid)
	assert.Contains(t, err.Error(), "either include or exclude")
}

func TestFanout_SetOutputRoute(t *testing.T) {
	out := testhelper.NewMockOutput("routed")
	auditor, err := audit.New(
		audit.WithValidationMode(audit.ValidationPermissive),
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(out, audit.WithRoute(&audit.EventRoute{})),
	)
	require.NoError(t, err)

	// Initially receives all events.
	require.NoError(t, auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{"outcome": "success"})))
	require.True(t, out.WaitForEvents(1, 2*time.Second))

	// Set route to security only.
	require.NoError(t, auditor.SetOutputRoute("routed", &audit.EventRoute{
		IncludeCategories: map[string]*audit.SeverityRange{"security": nil},
	}))

	require.NoError(t, auditor.AuditEvent(audit.NewEvent("user_delete", audit.Fields{"outcome": "success"})))
	require.NoError(t, auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{"outcome": "failure"})))
	require.NoError(t, auditor.Close())

	// Should have: 1 initial + 1 auth_failure = 2 (user_delete filtered).
	assert.Equal(t, 2, out.EventCount())
}

func TestFanout_SetOutputRoute_DoesNotAffectOtherOutputs(t *testing.T) {
	outA := testhelper.NewMockOutput("a")
	outB := testhelper.NewMockOutput("b")
	auditor, err := audit.New(
		audit.WithValidationMode(audit.ValidationPermissive),
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(outA, audit.WithRoute(&audit.EventRoute{})),
		audit.WithNamedOutput(outB, audit.WithRoute(&audit.EventRoute{})),
	)
	require.NoError(t, err)

	// Restrict A to security only.
	require.NoError(t, auditor.SetOutputRoute("a", &audit.EventRoute{
		IncludeCategories: map[string]*audit.SeverityRange{"security": nil},
	}))

	require.NoError(t, auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{"outcome": "success"})))
	require.NoError(t, auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{"outcome": "failure"})))
	require.NoError(t, auditor.Close())

	assert.Equal(t, 1, outA.EventCount(), "A should only get auth_failure")
	assert.Equal(t, 2, outB.EventCount(), "B should get both events")
}

func TestFanout_SetOutputRoute_UnknownOutput(t *testing.T) {
	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditor.Close() })

	err = auditor.SetOutputRoute("nonexistent", &audit.EventRoute{})
	require.Error(t, err)
	// text-only: audit.go:862,879,891 return raw fmt.Errorf without a
	// sentinel wrap. The output-name substring is the contract.
	assert.Contains(t, err.Error(), "unknown output")
}

func TestFanout_SetOutputRoute_InvalidRoute(t *testing.T) {
	out := testhelper.NewMockOutput("test")
	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(out, audit.WithRoute(&audit.EventRoute{})),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditor.Close() })

	err = auditor.SetOutputRoute("test", &audit.EventRoute{
		IncludeCategories: map[string]*audit.SeverityRange{"bogus": nil},
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrConfigInvalid)
	assert.Contains(t, err.Error(), "unknown taxonomy entries")
}

func TestFanout_ClearOutputRoute(t *testing.T) {
	out := testhelper.NewMockOutput("routed")
	auditor, err := audit.New(
		audit.WithValidationMode(audit.ValidationPermissive),
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(out, audit.WithRoute(&audit.EventRoute{
			IncludeCategories: map[string]*audit.SeverityRange{"security": nil},
		})),
	)
	require.NoError(t, err)

	// Clear route — now receives all events.
	require.NoError(t, auditor.ClearOutputRoute("routed"))
	require.NoError(t, auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{"outcome": "success"})))
	require.NoError(t, auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{"outcome": "failure"})))
	require.NoError(t, auditor.Close())

	assert.Equal(t, 2, out.EventCount(), "should receive all events after clearing route")
}

func TestFanout_ClearOutputRoute_UnknownOutput(t *testing.T) {
	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditor.Close() })

	err = auditor.ClearOutputRoute("nonexistent")
	require.Error(t, err)
	// text-only: audit.go:862,879,891 return raw fmt.Errorf without a
	// sentinel wrap. The output-name substring is the contract.
	assert.Contains(t, err.Error(), "unknown output")
}

func TestFanout_OutputRoute(t *testing.T) {
	out := testhelper.NewMockOutput("test")
	route := audit.EventRoute{IncludeCategories: map[string]*audit.SeverityRange{"security": nil}}
	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(out, audit.WithRoute(&route)),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditor.Close() })

	got, err := auditor.OutputRoute("test")
	require.NoError(t, err)
	assert.Equal(t, route.IncludeCategories, got.IncludeCategories)

	// Mutating the returned route must not affect the stored route.
	// Map form (#193): inserting a new key on the returned map must
	// not be observable on a subsequent OutputRoute() call.
	got.IncludeCategories["write"] = nil
	got2, err := auditor.OutputRoute("test")
	require.NoError(t, err)
	assert.Len(t, got2.IncludeCategories, 1, "stored route should not be mutated")
}

func TestFanout_OutputRoute_UnknownOutput(t *testing.T) {
	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditor.Close() })

	_, err = auditor.OutputRoute("nonexistent")
	require.Error(t, err)
	// text-only: audit.go:862,879,891 return raw fmt.Errorf without a
	// sentinel wrap. The output-name substring is the contract.
	assert.Contains(t, err.Error(), "unknown output")
}

func TestFanout_OutputRoute_ReflectsSetAndClear(t *testing.T) {
	out := testhelper.NewMockOutput("test")
	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(out, audit.WithRoute(&audit.EventRoute{})),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditor.Close() })

	// Set a route.
	newRoute := audit.EventRoute{IncludeCategories: map[string]*audit.SeverityRange{"write": nil}}
	require.NoError(t, auditor.SetOutputRoute("test", &newRoute))
	got, err := auditor.OutputRoute("test")
	require.NoError(t, err)
	assert.Equal(t, map[string]*audit.SeverityRange{"write": nil}, got.IncludeCategories)

	// Clear.
	require.NoError(t, auditor.ClearOutputRoute("test"))
	got, err = auditor.OutputRoute("test")
	require.NoError(t, err)
	assert.True(t, got.IsEmpty())
}

func TestFanout_ConcurrentSetRouteAndAudit(t *testing.T) {
	out := testhelper.NewMockOutput("concurrent")
	auditor, err := audit.New(
		audit.WithValidationMode(audit.ValidationPermissive),
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(out, audit.WithRoute(&audit.EventRoute{})),
	)
	require.NoError(t, err)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for range 100 {
			_ = auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{"outcome": "failure"}))
		}
	}()

	go func() {
		defer wg.Done()
		for range 50 {
			_ = auditor.SetOutputRoute("concurrent", &audit.EventRoute{
				IncludeCategories: map[string]*audit.SeverityRange{"security": nil},
			})
			_ = auditor.ClearOutputRoute("concurrent")
		}
	}()

	wg.Wait()
	require.NoError(t, auditor.Close())

	// All events are security category, so they should all arrive
	// regardless of route toggling (include security = match, empty = match).
	assert.Equal(t, 100, out.EventCount(),
		"all security events should arrive regardless of route toggling")
}

func TestFanout_GlobalFilterTakesPrecedence(t *testing.T) {
	out := testhelper.NewMockOutput("all")
	auditor, err := audit.New(
		audit.WithValidationMode(audit.ValidationPermissive),
		audit.WithTaxonomy(&audit.Taxonomy{
			Version: 1,
			Categories: map[string]*audit.CategoryDef{
				"write":    {Events: []string{"user_create"}},
				"security": {Events: []string{"auth_failure"}},
			},
			Events: map[string]*audit.EventDef{
				"user_create":  {Required: []string{"outcome"}},
				"auth_failure": {Required: []string{"outcome"}},
			},
		}),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(out, audit.WithRoute(&audit.EventRoute{
			IncludeCategories: map[string]*audit.SeverityRange{"security": nil},
		})),
	)
	require.NoError(t, err)

	// Disable security globally — should not reach output even though route includes it.
	require.NoError(t, auditor.DisableCategory("security"))
	require.NoError(t, auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{"outcome": "failure"})))
	require.NoError(t, auditor.Close())

	assert.Equal(t, 0, out.EventCount(),
		"globally disabled event should not reach any output")
}

func TestFanout_PerOutputFormatter(t *testing.T) {
	jsonOut := testhelper.NewMockOutput("json")
	cefOut := testhelper.NewMockOutput("cef")

	cefFmt := &audit.CEFFormatter{
		Vendor:  "Test",
		Product: "Audit",
		Version: "1.0",
	}

	auditor, err := audit.New(
		audit.WithValidationMode(audit.ValidationPermissive),
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(jsonOut, audit.WithRoute(&audit.EventRoute{})),
		audit.WithNamedOutput(cefOut, audit.WithRoute(&audit.EventRoute{}), audit.WithOutputFormatter(cefFmt)),
	)
	require.NoError(t, err)

	require.NoError(t, auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{"outcome": "success"})))
	require.NoError(t, auditor.Close())

	require.Equal(t, 1, jsonOut.EventCount())
	require.Equal(t, 1, cefOut.EventCount())

	jsonData := jsonOut.GetEvents()[0]
	assert.Equal(t, byte('{'), jsonData[0], "json output should be JSON")

	cefData := cefOut.GetEvents()[0]
	assert.Contains(t, string(cefData), "CEF:0|", "cef output should be CEF")
}

func TestFanout_PanicInFormatter_DrainLoopSurvives(t *testing.T) {
	out := testhelper.NewMockOutput("survivor")
	auditor, err := audit.New(
		audit.WithValidationMode(audit.ValidationPermissive),
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(out, audit.WithRoute(&audit.EventRoute{}), audit.WithOutputFormatter(&panicFormatter{})),
	)
	require.NoError(t, err)

	// The panic is recovered by processEntry — drain loop survives.
	require.NoError(t, auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{"outcome": "success"})))
	// Second event also processed (drain loop not dead).
	require.NoError(t, auditor.AuditEvent(audit.NewEvent("user_delete", audit.Fields{"outcome": "success"})))
	require.NoError(t, auditor.Close())

	// Events are lost due to panic, but the drain loop is alive.
	assert.Equal(t, 0, out.EventCount())
}

// panicFormatter is a Formatter that always panics.
type panicFormatter struct{}

func (p *panicFormatter) Format(_ time.Time, _ string, _ audit.Fields, _ *audit.EventDef, _ *audit.FormatOptions) ([]byte, error) {
	panic("formatter panic")
}

func (p *panicFormatter) ContentType() string { return "application/x-ndjson" }

func TestFanout_PanicInOutputWrite_OtherOutputsStillReceive(t *testing.T) {
	panicOut := &panicOnWriteOutput{MockOutput: *testhelper.NewMockOutput("panicker")}
	survivor := testhelper.NewMockOutput("survivor")

	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(panicOut, survivor),
	)
	require.NoError(t, err)

	// The panic in panicOut.Write is recovered per-output.
	// The survivor output must still receive the event.
	require.NoError(t, auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
	})))
	require.NoError(t, auditor.Close())

	assert.Equal(t, 0, panicOut.EventCount(), "panicking output should have 0 events (panic before recording)")
	assert.Equal(t, 1, survivor.EventCount(), "survivor output must receive the event despite earlier panic")
}

// panicOnWriteOutput is an output whose Write always panics.
type panicOnWriteOutput struct {
	testhelper.MockOutput
}

func (p *panicOnWriteOutput) Write(_ []byte) error {
	panic("output write panic")
}

func TestFanout_SharedFormatter_DeliversSameBytes(t *testing.T) {
	out1 := testhelper.NewMockOutput("a")
	out2 := testhelper.NewMockOutput("b")

	auditor, err := audit.New(
		audit.WithValidationMode(audit.ValidationPermissive),
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out1, out2), // same default formatter
	)
	require.NoError(t, err)

	require.NoError(t, auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{"outcome": "success"})))
	require.NoError(t, auditor.Close())

	require.Equal(t, 1, out1.EventCount())
	require.Equal(t, 1, out2.EventCount())

	// Same formatter → same bytes.
	assert.Equal(t, out1.GetEvents()[0], out2.GetEvents()[0],
		"outputs sharing a formatter should receive identical bytes")
}

func TestFanout_PerOutputRouteFilter_MetricsRecordFiltered(t *testing.T) {
	out := testhelper.NewMockOutput("filtered")
	metrics := testhelper.NewMockMetrics()

	auditor, err := audit.New(
		audit.WithValidationMode(audit.ValidationPermissive),
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithMetrics(metrics),
		audit.WithNamedOutput(out, audit.WithRoute(&audit.EventRoute{
			IncludeCategories: map[string]*audit.SeverityRange{"security": nil},
		})),
	)
	require.NoError(t, err)

	// This write event will be filtered by the per-output route.
	require.NoError(t, auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{"outcome": "success"})))
	require.NoError(t, auditor.Close())

	assert.Equal(t, 0, out.EventCount())
	assert.Greater(t, metrics.GetOutputFiltered("filtered"), 0,
		"RecordOutputFiltered should be called for route-filtered events")
}

func TestFanout_ExcludeEventType_EndToEnd(t *testing.T) {
	out := testhelper.NewMockOutput("no-config-get")
	auditor, err := audit.New(
		audit.WithValidationMode(audit.ValidationPermissive),
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(out, audit.WithRoute(&audit.EventRoute{
			ExcludeEventTypes: []string{"config_get"},
		})),
	)
	require.NoError(t, err)

	require.NoError(t, auditor.AuditEvent(audit.NewEvent("config_get", audit.Fields{"outcome": "success"})))
	require.NoError(t, auditor.AuditEvent(audit.NewEvent("user_get", audit.Fields{"outcome": "success"})))
	require.NoError(t, auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{"outcome": "success"})))
	require.NoError(t, auditor.Close())

	assert.Equal(t, 2, out.EventCount(), "config_get should be excluded")
}

// errorFormatter always returns an error (does not panic).
type errorFormatter struct{}

func (e *errorFormatter) Format(_ time.Time, _ string, _ audit.Fields, _ *audit.EventDef, _ *audit.FormatOptions) ([]byte, error) {
	return nil, fmt.Errorf("format failed")
}

func (e *errorFormatter) ContentType() string { return "application/x-ndjson" }

func TestFanout_ErrorFormatter_DoesNotBlockDefaultFormatter(t *testing.T) {
	goodOut := testhelper.NewMockOutput("good")
	badOut := testhelper.NewMockOutput("bad")

	auditor, err := audit.New(
		audit.WithValidationMode(audit.ValidationPermissive),
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(goodOut, audit.WithRoute(&audit.EventRoute{})),
		audit.WithNamedOutput(badOut, audit.WithRoute(&audit.EventRoute{}), audit.WithOutputFormatter(&errorFormatter{})),
	)
	require.NoError(t, err)

	require.NoError(t, auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{"outcome": "success"})))
	require.NoError(t, auditor.Close())

	assert.Equal(t, 1, goodOut.EventCount(),
		"good output should receive event despite error formatter on other output")
	assert.Equal(t, 0, badOut.EventCount(),
		"bad output should receive nothing due to formatter error")
}

// TestFanout_ConcurrentEventOverrideAndAudit exercises the eventOverrides
// syncmap under concurrent write+read. A writer goroutine toggles a
// per-event override while reader goroutines call Audit. The race
// detector verifies no data races on the syncmap.
func TestFanout_ConcurrentEventOverrideAndAudit(t *testing.T) {
	out := testhelper.NewMockOutput("test")
	auditor, err := audit.New(
		audit.WithValidationMode(audit.ValidationPermissive),
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)

	var wg sync.WaitGroup
	wg.Add(2)

	// Writer: toggle per-event override on auth_failure.
	go func() {
		defer wg.Done()
		for range 100 {
			_ = auditor.DisableEvent("auth_failure")
			_ = auditor.EnableEvent("auth_failure")
		}
	}()

	// Reader: audit auth_failure concurrently.
	go func() {
		defer wg.Done()
		for range 100 {
			_ = auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{"outcome": "failure"}))
		}
	}()

	wg.Wait()
	require.NoError(t, auditor.Close())
	// Count is non-deterministic due to concurrent enable/disable.
	// The test passes iff the race detector reports no data race.
}

// TestFanout_AllExcludeRoute_ZeroDeliveries proves that fan-out
// with all outputs configured to exclude every event category
// produces zero deliveries. The contract: a deliberately
// over-restrictive route does not silently leak events. (#565 G10).
func TestFanout_AllExcludeRoute_ZeroDeliveries(t *testing.T) {
	excludeAll := &audit.EventRoute{
		ExcludeCategories: []string{"write", "security", "read"},
	}
	out1 := testhelper.NewMockOutput("out1")
	out2 := testhelper.NewMockOutput("out2")
	auditor, err := audit.New(
		audit.WithValidationMode(audit.ValidationPermissive),
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(out1, audit.WithRoute(excludeAll)),
		audit.WithNamedOutput(out2, audit.WithRoute(excludeAll)),
	)
	require.NoError(t, err)
	require.NoError(t, auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{"outcome": "success"})))
	require.NoError(t, auditor.Close())

	assert.Zero(t, out1.EventCount(), "out1 must receive zero events when all categories excluded")
	assert.Zero(t, out2.EventCount(), "out2 must receive zero events when all categories excluded")
}

// TestFanout_IncludeExclude_MultipleOutputs_Independence proves
// that two outputs with disjoint include/exclude rules each route
// independently — no leakage from one output's filter into
// another's. (#565 G10).
func TestFanout_IncludeExclude_MultipleOutputs_Independence(t *testing.T) {
	writeOnly := &audit.EventRoute{IncludeCategories: map[string]*audit.SeverityRange{"write": nil}}
	securityOnly := &audit.EventRoute{IncludeCategories: map[string]*audit.SeverityRange{"security": nil}}
	out1 := testhelper.NewMockOutput("write-only")
	out2 := testhelper.NewMockOutput("security-only")
	auditor, err := audit.New(
		audit.WithValidationMode(audit.ValidationPermissive),
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(out1, audit.WithRoute(writeOnly)),
		audit.WithNamedOutput(out2, audit.WithRoute(securityOnly)),
	)
	require.NoError(t, err)
	// user_create is in the "write" category per testhelper.TestTaxonomy.
	require.NoError(t, auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{"outcome": "success"})))
	require.NoError(t, auditor.Close())

	assert.Equal(t, 1, out1.EventCount(),
		"write-only output must receive write-category events")
	assert.Zero(t, out2.EventCount(),
		"security-only output must NOT receive write-category events")
}
