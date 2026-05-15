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
	"testing"

	"github.com/axonops/audit"
	"github.com/stretchr/testify/assert"
)

// TestInlineCatBoundary asserts the inline-fast-path threshold (#867
// PR-2). populateInlineCats populates the inline array when 1 <=
// len(IncludeCategories) <= 4. For 0 categories the array stays
// empty (inlineCatCount == 0, kind != routeModeInclude). For
// 1..4 categories the array is fully populated and MatchesRoute
// uses the inline fast path. For >= 5 categories the inline array
// is empty and MatchesRoute falls through to the map.
//
// This test catches mutations to the boundary condition that
// functional tests would not surface, because the slow-path map
// lookup still produces a correct match for N == 4.
func TestInlineCatBoundary(t *testing.T) {
	t.Parallel()

	cases := []struct {
		n               int
		wantInlineCount int8
	}{
		{0, 0},
		{1, 1},
		{2, 2},
		{3, 3},
		{4, 4},
		{5, 0}, // map fallback — inline array is empty
		{16, 0},
		{32, 0},
	}

	for _, tc := range cases {
		t.Run(fmt.Sprintf("N=%d", tc.n), func(t *testing.T) {
			t.Parallel()
			cats := make(map[string]audit.SeverityRange, tc.n)
			for i := 0; i < tc.n; i++ {
				cats[fmt.Sprintf("cat_%02d", i)] = audit.SeverityRange{}
			}
			route := &audit.EventRoute{IncludeCategories: cats}
			audit.BuildRouteForTest(route)

			got := audit.InlineCatCountForTest(route)
			assert.Equal(t, tc.wantInlineCount, got,
				"inlineCatCount mismatch for N=%d: want %d, got %d",
				tc.n, tc.wantInlineCount, got)
		})
	}
}

// TestRouteKind asserts the routeMode classification (#867 PR-2).
// MatchesRoute switches on route.kind for O(1) dispatch; mis-
// classification would silently route an event through the wrong
// arm of the switch. Property tests cover behavioural equivalence
// but cannot directly observe the kind discriminator.
func TestRouteKind(t *testing.T) {
	t.Parallel()

	cases := []struct {
		route    *audit.EventRoute
		name     string
		wantKind uint8 // 0=empty, 1=include, 2=exclude, 3=severity-only
	}{
		{
			name:     "empty route",
			route:    &audit.EventRoute{},
			wantKind: 0,
		},
		{
			name: "include categories",
			route: &audit.EventRoute{
				IncludeCategories: map[string]audit.SeverityRange{"security": {}},
			},
			wantKind: 1,
		},
		{
			name: "include event types",
			route: &audit.EventRoute{
				IncludeEventTypes: []string{"auth_failure"},
			},
			wantKind: 1,
		},
		{
			name: "exclude categories",
			route: &audit.EventRoute{
				ExcludeCategories: []string{"read"},
			},
			wantKind: 2,
		},
		{
			name: "exclude event types",
			route: &audit.EventRoute{
				ExcludeEventTypes: []string{"config_get"},
			},
			wantKind: 2,
		},
		{
			name:     "severity-only",
			route:    &audit.EventRoute{MinSeverity: intPtrLocal(7)},
			wantKind: 3,
		},
		{
			name:     "severity-only with max",
			route:    &audit.EventRoute{MaxSeverity: intPtrLocal(5)},
			wantKind: 3,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			audit.BuildRouteForTest(tc.route)
			got := audit.KindForTest(tc.route)
			assert.Equal(t, tc.wantKind, got,
				"kind mismatch for %q: want %d, got %d",
				tc.name, tc.wantKind, got)
		})
	}
}

func intPtrLocal(v int) *int { return &v }
