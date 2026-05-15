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

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/axonops/audit"
	"github.com/axonops/audit/internal/testhelper"
)

// TestFilter_StateMachine_Determinism property-checks that any
// sequence of filter mutators (Enable/Disable Category/Event,
// SetOutputRoute, ClearOutputRoute) produces a deterministic final
// state. Determinism is checked by driving TWO fresh auditors with
// the same recorded operation sequence and comparing their final
// route maps. If the filter state machine had any hidden global
// mutable state, map-iteration nondeterminism, or order-sensitive
// merging, this property would surface it.
//
// Per-test 30s budget per AC #2 (#558). The default rapid example
// count (100) takes well under 1s in practice.
func TestFilter_StateMachine_Determinism(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(rt *rapid.T) {
		ops := genFilterOps(rt)
		stateA := applyFilterOps(t, ops)
		stateB := applyFilterOps(t, ops)
		if !equalRouteState(stateA, stateB) {
			rt.Fatalf("filter state non-deterministic across two fresh auditors:\n  A=%v\n  B=%v", stateA, stateB)
		}
	})
}

// filterOpKind enumerates the six filter mutators under test.
type filterOpKind int

const (
	opEnableCategory filterOpKind = iota
	opDisableCategory
	opEnableEvent
	opDisableEvent
	opSetOutputRoute
	opClearOutputRoute
)

// filterOp is a single recorded mutator call. Fields are ordered by
// pointer-then-string-then-int to satisfy fieldalignment without
// sacrificing the readable group order in the godoc above.
type filterOp struct {
	route    *audit.EventRoute
	category string // for Enable/DisableCategory
	event    string // for Enable/DisableEvent
	output   string // for Set/ClearOutputRoute
	kind     filterOpKind
}

// genFilterOps generates a sequence of 0..20 filter ops drawn from
// the fixture taxonomy's category and event names (sourced from
// internal/testhelper/taxonomy.go::TestTaxonomy so EnableEvent /
// DisableEvent calls actually mutate state instead of being no-ops).
func genFilterOps(rt *rapid.T) []filterOp {
	categories := []string{"write", "read", "security"}
	events := []string{
		"user_create", "user_delete", "user_get", "config_get",
		"auth_failure", "permission_denied",
	}
	outputs := []string{"primary", "secondary"}

	n := rapid.IntRange(0, 20).Draw(rt, "op_count")
	out := make([]filterOp, n)
	for i := 0; i < n; i++ {
		kind := filterOpKind(rapid.IntRange(0, 5).Draw(rt, "kind"))
		op := filterOp{kind: kind}
		switch kind {
		case opEnableCategory, opDisableCategory:
			op.category = rapid.SampledFrom(categories).Draw(rt, "category")
		case opEnableEvent, opDisableEvent:
			op.event = rapid.SampledFrom(events).Draw(rt, "event")
		case opSetOutputRoute:
			op.output = rapid.SampledFrom(outputs).Draw(rt, "output")
			op.route = &audit.EventRoute{}
			if rapid.Bool().Draw(rt, "include_categories") {
				cat := rapid.SampledFrom(categories).Draw(rt, "include_cat")
				op.route.IncludeCategories = map[string]audit.SeverityRange{cat: {}}
			}
		case opClearOutputRoute:
			op.output = rapid.SampledFrom(outputs).Draw(rt, "output")
		}
		out[i] = op
	}
	return out
}

// applyFilterOps constructs a fresh auditor with the fixture
// taxonomy + two named outputs, applies the recorded sequence, and
// returns a deterministic snapshot of the resulting per-output route
// state.
func applyFilterOps(t *testing.T, ops []filterOp) map[string]string {
	t.Helper()
	tax := testhelper.TestTaxonomy()
	primary := testhelper.NewMockOutput("primary")
	secondary := testhelper.NewMockOutput("secondary")
	auditor, err := audit.New(
		audit.WithTaxonomy(tax),
		audit.WithAppName("filter-property"),
		audit.WithHost("filter-property-host"),
		audit.WithNamedOutput(primary, audit.WithRoute(&audit.EventRoute{})),
		audit.WithNamedOutput(secondary, audit.WithRoute(&audit.EventRoute{})),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditor.Close() })

	for _, op := range ops {
		// Errors are normal here: e.g. EnableEvent on a disabled
		// auditor returns ErrDisabled; SetOutputRoute on an unknown
		// output returns an error. Both behaviours are themselves
		// deterministic — applying the same op to a fresh auditor
		// produces the same outcome — so we ignore the error and
		// rely on the route-state comparison to catch any divergence.
		switch op.kind {
		case opEnableCategory:
			_ = auditor.EnableCategory(op.category)
		case opDisableCategory:
			_ = auditor.DisableCategory(op.category)
		case opEnableEvent:
			_ = auditor.EnableEvent(op.event)
		case opDisableEvent:
			_ = auditor.DisableEvent(op.event)
		case opSetOutputRoute:
			_ = auditor.SetOutputRoute(op.output, op.route)
		case opClearOutputRoute:
			_ = auditor.ClearOutputRoute(op.output)
		}
	}

	return snapshotRoutes(t, auditor)
}

// snapshotRoutes returns a stable string snapshot of the route state
// for the two named outputs. We compare strings rather than
// EventRoute structs to avoid pointer-identity false-positives.
func snapshotRoutes(t *testing.T, auditor *audit.Auditor) map[string]string {
	t.Helper()
	out := make(map[string]string, 2)
	for _, name := range []string{"primary", "secondary"} {
		route, err := auditor.OutputRoute(name)
		if err != nil {
			out[name] = "<error: " + err.Error() + ">"
			continue
		}
		out[name] = formatRoute(&route)
	}
	return out
}

// formatRoute serialises an EventRoute to a deterministic string.
// Takes a pointer to avoid copying the 144-byte struct (the struct
// has slices + severity pointers; passing by value triggers
// gocritic's hugeParam linter).
func formatRoute(r *audit.EventRoute) string {
	return "include_cats=" + joinSortedMap(r.IncludeCategories) +
		" exclude_cats=" + joinSorted(r.ExcludeCategories) +
		" include_evts=" + joinSorted(r.IncludeEventTypes) +
		" exclude_evts=" + joinSorted(r.ExcludeEventTypes)
}

// joinSortedMap collapses a map[string]audit.SeverityRange to a
// deterministic "[a,b,c]" string of the keys. Per-category severity
// ranges are not part of the property-test domain today; if a future
// op introduces them, extend this to include the range too.
func joinSortedMap(m map[string]audit.SeverityRange) string {
	if len(m) == 0 {
		return "[]"
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return joinSorted(keys)
}

// joinSorted returns "[a,b,c]" for any input order.
func joinSorted(xs []string) string {
	if len(xs) == 0 {
		return "[]"
	}
	cp := append([]string(nil), xs...)
	// In-place insertion sort — small N, no extra deps.
	for i := 1; i < len(cp); i++ {
		for j := i; j > 0 && cp[j-1] > cp[j]; j-- {
			cp[j-1], cp[j] = cp[j], cp[j-1]
		}
	}
	out := "["
	for i, s := range cp {
		if i > 0 {
			out += ","
		}
		out += s
	}
	out += "]"
	return out
}

// equalRouteState compares two route snapshots for set-equality.
func equalRouteState(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// TestMatchesRoute_BuiltEquivalentToUnbuilt property-checks that
// MatchesRoute returns the same result regardless of whether the
// route has been built with Build() (which populates the inline
// fast path and routeMode discriminator) or is consumed as a raw
// struct literal (which routes through the field-by-field slow
// path). This is the regression guard for PR-2 (#867): the inline
// `[4]inlineCat` fast path and the routeMode switch must produce
// byte-identical match decisions to the legacy slow path across
// every combination of include/exclude/severity configuration.
//
// rapid draws route shapes spanning the inline-eligible (N≤4)
// and map-fallback (N>4) ranges so both code paths in the
// routeModeInclude case are exercised.
func TestMatchesRoute_BuiltEquivalentToUnbuilt(t *testing.T) {
	t.Parallel()

	categories := []string{"write", "read", "security", "admin", "audit", "debug", "trace", "info"}
	events := []string{"user_create", "user_read", "auth_failure", "auth_success", "schema_register", "data_export"}

	rapid.Check(t, func(rt *rapid.T) {
		built := genRoute(rt, categories, events)
		// Take a value copy then Build() the copy; never touch the
		// "unbuilt" reference. The two routes are otherwise identical.
		unbuilt := cloneRouteForProperty(built)
		audit.BuildRouteForTest(built)

		cat := rapid.SampledFrom(append(categories, "uncategorised")).Draw(rt, "category")
		evt := rapid.SampledFrom(append(events, "unknown_event")).Draw(rt, "event")
		sev := rapid.IntRange(0, 10).Draw(rt, "severity")

		got := audit.MatchesRoute(built, evt, cat, sev)
		want := audit.MatchesRoute(unbuilt, evt, cat, sev)
		require.Equal(rt, want, got,
			"built and unbuilt routes must agree on (event=%q, category=%q, severity=%d)",
			evt, cat, sev)
	})
}

// identityString is the keyFn for rapid.SliceOfNDistinct when the
// element type is already comparable (strings).
func identityString(s string) string { return s }

// genRoute draws a random EventRoute spanning include / exclude /
// severity-only / empty shapes, including inline-eligible (N≤4)
// and map-fallback (N>4) include-categories sizes.
func genRoute(rt *rapid.T, categories, events []string) *audit.EventRoute {
	shape := rapid.IntRange(0, 5).Draw(rt, "route_shape")
	switch shape {
	case 0:
		return &audit.EventRoute{}
	case 1:
		return genIncludeCategoriesRoute(rt, categories)
	case 2:
		return genIncludeEventTypesRoute(rt, events)
	case 3:
		return genIncludeUnionRoute(rt, categories, events)
	case 4:
		return genExcludeRoute(rt, categories, events)
	default:
		return genSeverityOnlyRoute(rt)
	}
}

// genSeverityOnlyRoute draws a severity-only catch-all route with
// either Min, Max, or both bounds. Adds Max coverage that the
// earlier "always MinSeverity" generator missed.
func genSeverityOnlyRoute(rt *rapid.T) *audit.EventRoute {
	shape := rapid.IntRange(0, 2).Draw(rt, "sev_shape")
	switch shape {
	case 0:
		v := rapid.IntRange(0, 10).Draw(rt, "min_sev")
		return &audit.EventRoute{MinSeverity: &v}
	case 1:
		v := rapid.IntRange(0, 10).Draw(rt, "max_sev")
		return &audit.EventRoute{MaxSeverity: &v}
	default:
		minSev := rapid.IntRange(0, 10).Draw(rt, "min_sev")
		maxSev := rapid.IntRange(minSev, 10).Draw(rt, "max_sev")
		return &audit.EventRoute{MinSeverity: &minSev, MaxSeverity: &maxSev}
	}
}

// genIncludeUnionRoute draws a route with BOTH IncludeCategories
// AND IncludeEventTypes populated — the union shape that the
// earlier generator never produced. Real-world routes commonly
// combine "all events in these categories OR these specific
// events outside those categories".
func genIncludeUnionRoute(rt *rapid.T, categories, events []string) *audit.EventRoute {
	r := genIncludeCategoriesRoute(rt, categories)
	ne := rapid.IntRange(1, 3).Draw(rt, "n_include_evts_union")
	r.IncludeEventTypes = rapid.SliceOfNDistinct(rapid.SampledFrom(events), ne, ne, identityString).Draw(rt, "pick_union_evts")
	return r
}

// genIncludeCategoriesRoute draws 1..6 categories with optional
// per-category severity bounds. The range spans the inline (N≤4)
// and map (N>4) paths so both code paths in routeModeInclude fire.
func genIncludeCategoriesRoute(rt *rapid.T, categories []string) *audit.EventRoute {
	n := rapid.IntRange(1, 6).Draw(rt, "n_include_cats")
	picks := rapid.SliceOfNDistinct(rapid.SampledFrom(categories), n, n, identityString).Draw(rt, "pick_cats")
	m := make(map[string]audit.SeverityRange, n)
	for _, c := range picks {
		if rapid.Bool().Draw(rt, "cat_has_min") {
			v := rapid.IntRange(0, 10).Draw(rt, "min_sev")
			m[c] = audit.SeverityRange{MinSeverity: &v}
		} else {
			m[c] = audit.SeverityRange{}
		}
	}
	return &audit.EventRoute{IncludeCategories: m}
}

// genIncludeEventTypesRoute draws 1..4 event types — the include-
// event-types-only path that exercises the routeModeInclude case
// with inlineCatCount==0 and len(IncludeCategories)==0.
func genIncludeEventTypesRoute(rt *rapid.T, events []string) *audit.EventRoute {
	n := rapid.IntRange(1, 4).Draw(rt, "n_include_evts")
	picks := rapid.SliceOfNDistinct(rapid.SampledFrom(events), n, n, identityString).Draw(rt, "pick_evts")
	return &audit.EventRoute{IncludeEventTypes: picks}
}

// genExcludeRoute draws an exclude route with either or both of
// ExcludeCategories and ExcludeEventTypes populated (at least one
// must be non-empty to make this an exclude-mode route).
func genExcludeRoute(rt *rapid.T, categories, events []string) *audit.EventRoute {
	nc := rapid.IntRange(0, 3).Draw(rt, "n_exclude_cats")
	ne := rapid.IntRange(0, 3).Draw(rt, "n_exclude_evts")
	if nc == 0 && ne == 0 {
		nc = 1
	}
	r := &audit.EventRoute{}
	if nc > 0 {
		r.ExcludeCategories = rapid.SliceOfNDistinct(rapid.SampledFrom(categories), nc, nc, identityString).Draw(rt, "pick_excat")
	}
	if ne > 0 {
		r.ExcludeEventTypes = rapid.SliceOfNDistinct(rapid.SampledFrom(events), ne, ne, identityString).Draw(rt, "pick_exevt")
	}
	return r
}

// cloneRouteForProperty makes a deep-enough copy of an EventRoute
// for the property test: the SeverityRange map and slices are
// independent, and Build() called on one route does not affect the
// other. Inner *int pointers are shared because the property only
// reads them.
func cloneRouteForProperty(r *audit.EventRoute) *audit.EventRoute {
	cp := &audit.EventRoute{
		MinSeverity: r.MinSeverity,
		MaxSeverity: r.MaxSeverity,
	}
	if r.IncludeCategories != nil {
		cp.IncludeCategories = make(map[string]audit.SeverityRange, len(r.IncludeCategories))
		for k, v := range r.IncludeCategories {
			cp.IncludeCategories[k] = v
		}
	}
	if r.IncludeEventTypes != nil {
		cp.IncludeEventTypes = append([]string(nil), r.IncludeEventTypes...)
	}
	if r.ExcludeCategories != nil {
		cp.ExcludeCategories = append([]string(nil), r.ExcludeCategories...)
	}
	if r.ExcludeEventTypes != nil {
		cp.ExcludeEventTypes = append([]string(nil), r.ExcludeEventTypes...)
	}
	return cp
}
