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
	"testing"

	"github.com/axonops/audit"
	"github.com/axonops/audit/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Per-category severity tests for issue #193.
// These are black-box behavioural tests covering the three modes
// defined on EventRoute (Mode A: category-only, Mode B: per-category
// severity, Mode C: severity-only catch-all) and the severity
// precedence rule (per-category > route-level > catch-all).

// ---------------------------------------------------------------------------
// MatchesRoute — Mode A (category only, nil filter)
// ---------------------------------------------------------------------------

func TestPerCat_ModeA_AnySeverityPasses(t *testing.T) {
	t.Parallel()
	route := audit.EventRoute{
		IncludeCategories: map[string]audit.SeverityRange{
			"security": {},
		},
	}
	// Category match with nil filter passes regardless of severity.
	for sev := 0; sev <= 10; sev++ {
		assert.True(t,
			audit.MatchesRoute(&route, "auth_failure", "security", sev),
			"sev=%d: nil filter must pass all severities", sev)
	}
	// Different category → no match.
	assert.False(t,
		audit.MatchesRoute(&route, "user_create", "write", 5),
		"category not in map must not match")
}

// ---------------------------------------------------------------------------
// MatchesRoute — Mode B (per-category severity)
// ---------------------------------------------------------------------------

func TestPerCat_ModeB_MinOnly(t *testing.T) {
	t.Parallel()
	route := audit.EventRoute{
		IncludeCategories: map[string]audit.SeverityRange{
			"security": {MinSeverity: intPtr(7)},
		},
	}
	cases := []struct {
		sev  int
		want bool
	}{
		{0, false}, {6, false}, {7, true}, {8, true}, {10, true},
	}
	for _, c := range cases {
		assert.Equal(t, c.want,
			audit.MatchesRoute(&route, "auth_failure", "security", c.sev),
			"sev=%d", c.sev)
	}
}

func TestPerCat_ModeB_MaxOnly(t *testing.T) {
	t.Parallel()
	route := audit.EventRoute{
		IncludeCategories: map[string]audit.SeverityRange{
			"read": {MaxSeverity: intPtr(3)},
		},
	}
	cases := []struct {
		sev  int
		want bool
	}{
		{0, true}, {3, true}, {4, false}, {10, false},
	}
	for _, c := range cases {
		assert.Equal(t, c.want,
			audit.MatchesRoute(&route, "user_get", "read", c.sev),
			"sev=%d", c.sev)
	}
}

func TestPerCat_ModeB_MinAndMax(t *testing.T) {
	t.Parallel()
	route := audit.EventRoute{
		IncludeCategories: map[string]audit.SeverityRange{
			"security": {MinSeverity: intPtr(4), MaxSeverity: intPtr(7)},
		},
	}
	cases := []struct {
		sev  int
		want bool
	}{
		{3, false}, {4, true}, {5, true}, {7, true}, {8, false},
	}
	for _, c := range cases {
		assert.Equal(t, c.want,
			audit.MatchesRoute(&route, "auth_failure", "security", c.sev),
			"sev=%d", c.sev)
	}
}

func TestPerCat_ModeB_MixedFilters(t *testing.T) {
	t.Parallel()
	// security ≥ 7, read any severity.
	route := audit.EventRoute{
		IncludeCategories: map[string]audit.SeverityRange{
			"security": {MinSeverity: intPtr(7)},
			"read":     {},
		},
	}
	// Security: only ≥7 passes.
	assert.False(t, audit.MatchesRoute(&route, "auth_failure", "security", 3))
	assert.True(t, audit.MatchesRoute(&route, "auth_failure", "security", 8))
	// Read: all severities pass.
	for sev := 0; sev <= 10; sev++ {
		assert.True(t,
			audit.MatchesRoute(&route, "user_get", "read", sev),
			"read sev=%d", sev)
	}
}

// ---------------------------------------------------------------------------
// MatchesRoute — Severity precedence (per-cat overrides route-level)
// ---------------------------------------------------------------------------

func TestPerCat_RouteLevelDoesNotApplyToCategoryMatch(t *testing.T) {
	t.Parallel()
	// Route-level min=9, but the category has a nil filter → all
	// severities pass for category matches.
	route := audit.EventRoute{
		IncludeCategories: map[string]audit.SeverityRange{
			"security": {},
		},
		MinSeverity: intPtr(9),
	}
	assert.True(t,
		audit.MatchesRoute(&route, "auth_failure", "security", 3),
		"route-level min must not apply to category matches")
}

func TestPerCat_RouteLevelAppliesToEventTypeMatch(t *testing.T) {
	t.Parallel()
	// Mixed: per-category for "security", event-type list for the
	// admin_action event-type, route-level min=5 applies ONLY to the
	// event-type fallback path.
	route := audit.EventRoute{
		IncludeCategories: map[string]audit.SeverityRange{
			"security": {MinSeverity: intPtr(7)},
		},
		IncludeEventTypes: []string{"admin_action"},
		MinSeverity:       intPtr(5),
	}
	// Security category match with sev=8 → per-cat 7 passes.
	assert.True(t, audit.MatchesRoute(&route, "auth_failure", "security", 8))
	// Security category match with sev=6 → per-cat 7 fails.
	assert.False(t, audit.MatchesRoute(&route, "auth_failure", "security", 6))
	// admin_action event-type match in "write" cat with sev=6 → route-level 5 passes.
	assert.True(t, audit.MatchesRoute(&route, "admin_action", "write", 6))
	// admin_action event-type with sev=4 → route-level 5 fails.
	assert.False(t, audit.MatchesRoute(&route, "admin_action", "write", 4))
}

// ---------------------------------------------------------------------------
// MatchesRoute — Mode C (severity-only catch-all)
// ---------------------------------------------------------------------------

func TestPerCat_ModeC_SeverityOnly(t *testing.T) {
	t.Parallel()
	route := audit.EventRoute{
		MinSeverity: intPtr(9),
	}
	// No category / event-type filters: severity is the only gate.
	assert.False(t, audit.MatchesRoute(&route, "auth_failure", "security", 8))
	assert.True(t, audit.MatchesRoute(&route, "auth_failure", "security", 9))
	// Works for any category — pure severity gate.
	assert.True(t, audit.MatchesRoute(&route, "user_get", "read", 10))
}

// ---------------------------------------------------------------------------
// Presence vs absence — key-in-map is the include signal
// ---------------------------------------------------------------------------

func TestPerCat_AbsentKey_DoesNotMatch(t *testing.T) {
	t.Parallel()
	// Presence of a key in IncludeCategories is the include signal;
	// the zero-value SeverityRange{} means "no severity constraint".
	// An absent category key must NOT match the route; a present
	// zero-value key MUST match at every severity.
	route := audit.EventRoute{
		IncludeCategories: map[string]audit.SeverityRange{
			"security": {}, // present, zero value
		},
	}
	for sev := 0; sev <= 10; sev++ {
		// Present key — all severities pass.
		assert.True(t, audit.MatchesRoute(&route, "auth_failure", "security", sev),
			"present zero-value key must match every severity; sev=%d", sev)
		// Absent key — never matches regardless of severity.
		assert.False(t, audit.MatchesRoute(&route, "user_create", "write", sev),
			"absent key must not match; sev=%d", sev)
	}
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

func TestPerCat_Validation_OutOfRangeMin(t *testing.T) {
	t.Parallel()
	tax := testhelper.TestTaxonomy()
	route := audit.EventRoute{
		IncludeCategories: map[string]audit.SeverityRange{
			"security": {MinSeverity: intPtr(11)},
		},
	}
	err := audit.ValidateEventRoute(&route, tax)
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrConfigInvalid)
	assert.Contains(t, err.Error(), "security",
		"error should name the offending category")
	assert.Contains(t, err.Error(), "11",
		"error should report the offending value")
}

func TestPerCat_Validation_OutOfRangeMax(t *testing.T) {
	t.Parallel()
	tax := testhelper.TestTaxonomy()
	route := audit.EventRoute{
		IncludeCategories: map[string]audit.SeverityRange{
			"security": {MaxSeverity: intPtr(-1)},
		},
	}
	err := audit.ValidateEventRoute(&route, tax)
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrConfigInvalid)
	assert.Contains(t, err.Error(), "security")
}

func TestPerCat_Validation_MinGreaterThanMax(t *testing.T) {
	t.Parallel()
	tax := testhelper.TestTaxonomy()
	route := audit.EventRoute{
		IncludeCategories: map[string]audit.SeverityRange{
			"security": {MinSeverity: intPtr(8), MaxSeverity: intPtr(3)},
		},
	}
	err := audit.ValidateEventRoute(&route, tax)
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrConfigInvalid)
	assert.Contains(t, err.Error(), "security")
	assert.Contains(t, err.Error(), "exceeds max_severity")
}

func TestPerCat_Validation_UnknownCategory(t *testing.T) {
	t.Parallel()
	tax := testhelper.TestTaxonomy()
	route := audit.EventRoute{
		IncludeCategories: map[string]audit.SeverityRange{
			"nonexistent": {},
		},
	}
	err := audit.ValidateEventRoute(&route, tax)
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrConfigInvalid)
	assert.Contains(t, err.Error(), "nonexistent")
}

func TestPerCat_Validation_DeterministicErrorOrder(t *testing.T) {
	t.Parallel()
	// Two invalid per-category filters — error must name the
	// first-alphabetically offender for determinism. Validation
	// iterates sorted keys and returns on the first failure.
	tax := testhelper.TestTaxonomy()
	route := audit.EventRoute{
		IncludeCategories: map[string]audit.SeverityRange{
			"zzz_unknown": {MinSeverity: intPtr(11)},
			"security":    {MinSeverity: intPtr(11)},
		},
	}
	err := audit.ValidateEventRoute(&route, tax)
	require.Error(t, err)
	// "security" sorts before "zzz_unknown"; per-category validation
	// returns at "security" without reaching "zzz_unknown".
	assert.Contains(t, err.Error(), "security")
	assert.NotContains(t, err.Error(), "zzz_unknown",
		"validation should return at the first failure, not continue")
}

// ---------------------------------------------------------------------------
// Round-trip via SetOutputRoute / OutputRoute (deep clone)
// ---------------------------------------------------------------------------

func TestPerCat_RoundTrip_DeepClonePreservesSeverityRange(t *testing.T) {
	t.Parallel()
	tax := testhelper.TestTaxonomy()
	auditor, err := audit.New(
		audit.WithTaxonomy(tax),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(testhelper.NewMockOutput("test")),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditor.Close() })

	original := &audit.EventRoute{
		IncludeCategories: map[string]audit.SeverityRange{
			"security": {MinSeverity: intPtr(7), MaxSeverity: intPtr(9)},
			"read":     {},
		},
	}
	require.NoError(t, auditor.SetOutputRoute("test", original))

	got, err := auditor.OutputRoute("test")
	require.NoError(t, err)
	require.Len(t, got.IncludeCategories, 2,
		"both keys must round-trip; absent keys would also return a zero-value SeverityRange from the map")
	require.Contains(t, got.IncludeCategories, "security")
	require.NotNil(t, got.IncludeCategories["security"].MinSeverity)
	assert.Equal(t, 7, *got.IncludeCategories["security"].MinSeverity)
	require.NotNil(t, got.IncludeCategories["security"].MaxSeverity)
	assert.Equal(t, 9, *got.IncludeCategories["security"].MaxSeverity)
	// Zero-value SeverityRange for "read" survives the round-trip.
	require.Contains(t, got.IncludeCategories, "read")
	assert.Equal(t, audit.SeverityRange{}, got.IncludeCategories["read"])

	// Mutating the returned route's SeverityRange must not affect
	// the stored route. This is the core deep-clone invariant.
	*got.IncludeCategories["security"].MinSeverity = 99
	got2, err := auditor.OutputRoute("test")
	require.NoError(t, err)
	assert.Equal(t, 7, *got2.IncludeCategories["security"].MinSeverity,
		"stored route SeverityRange must not be mutable via the returned copy")
}

func TestPerCat_RoundTrip_CallerMutationOfInputCannotCorrupt(t *testing.T) {
	t.Parallel()
	tax := testhelper.TestTaxonomy()
	auditor, err := audit.New(
		audit.WithTaxonomy(tax),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(testhelper.NewMockOutput("test")),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditor.Close() })

	// Construct the route with a *int pointer the caller still owns.
	// This is the critical deep-clone test: mutating the SAME *int
	// after SetOutputRoute returns must NOT change the stored value.
	min7 := 7
	original := &audit.EventRoute{
		IncludeCategories: map[string]audit.SeverityRange{
			"security": {MinSeverity: &min7},
		},
	}
	require.NoError(t, auditor.SetOutputRoute("test", original))

	// Mutation #1: the SAME *int pointee.
	min7 = 99
	// Mutation #2: insert a new key into the caller's map.
	original.IncludeCategories["new_cat"] = audit.SeverityRange{}

	got, err := auditor.OutputRoute("test")
	require.NoError(t, err)
	require.NotContains(t, got.IncludeCategories, "new_cat",
		"caller adding a key to the input map must not affect the stored route")
	require.NotNil(t, got.IncludeCategories["security"].MinSeverity)
	assert.Equal(t, 7, *got.IncludeCategories["security"].MinSeverity,
		"stored MinSeverity must be a deep copy of the *int — mutating the "+
			"caller's pointee must not change the stored value")
}

// ---------------------------------------------------------------------------
// Benchmarks (#193 hot-path additions per performance-reviewer)
// ---------------------------------------------------------------------------

func BenchmarkMatchesRoute_PerCategorySeverity(b *testing.B) {
	// Mode B — Per-category severity gating, the new capability.
	route := audit.EventRoute{
		IncludeCategories: map[string]audit.SeverityRange{
			"security":   {MinSeverity: intPtr(7)},
			"compliance": {MinSeverity: intPtr(5)},
			"write":      {MinSeverity: intPtr(3)},
			"read":       {},
		},
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		audit.MatchesRoute(&route, "user_create", "write", 7)
	}
}

func BenchmarkMatchesRoute_MixedNilAndFilter(b *testing.B) {
	// Worst branch-predictor case: some categories with nil filter,
	// some with thresholds, calls alternate between the two paths.
	route := audit.EventRoute{
		IncludeCategories: map[string]audit.SeverityRange{
			"security": {MinSeverity: intPtr(7)},
			"read":     {},
			"write":    {MinSeverity: intPtr(3)},
			"admin":    {},
		},
	}
	categories := []string{"security", "read", "write", "admin"}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		audit.MatchesRoute(&route, "user_create", categories[i%len(categories)], 5)
	}
}
