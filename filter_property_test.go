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
				op.route.IncludeCategories = map[string]*audit.SeverityRange{cat: nil}
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

// joinSortedMap collapses a map[string]*audit.SeverityRange to a
// deterministic "[a,b,c]" string of the keys. Per-category severity
// ranges are not part of the property-test domain today; if a future
// op introduces them, extend this to include the range too.
func joinSortedMap(m map[string]*audit.SeverityRange) string {
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
