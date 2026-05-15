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
	"github.com/axonops/audit/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEventRoute_IsEmpty(t *testing.T) {
	assert.True(t, (&audit.EventRoute{}).IsEmpty())
	assert.False(t, (&audit.EventRoute{IncludeCategories: map[string]audit.SeverityRange{"write": {}}}).IsEmpty())
	assert.False(t, (&audit.EventRoute{ExcludeEventTypes: []string{"auth_failure"}}).IsEmpty())
}

func TestValidateEventRoute(t *testing.T) {
	tax := testhelper.TestTaxonomy()

	tests := []struct { //nolint:govet // test struct field order matches readability
		name    string
		wantErr string
		route   audit.EventRoute
	}{
		{
			name:  "empty route",
			route: audit.EventRoute{},
		},
		{
			name:  "valid include categories",
			route: audit.EventRoute{IncludeCategories: map[string]audit.SeverityRange{"write": {}, "security": {}}},
		},
		{
			name:  "valid include event types",
			route: audit.EventRoute{IncludeEventTypes: []string{"auth_failure"}},
		},
		{
			name:  "valid exclude categories",
			route: audit.EventRoute{ExcludeCategories: []string{"read"}},
		},
		{
			name:  "valid exclude event types",
			route: audit.EventRoute{ExcludeEventTypes: []string{"config_get"}},
		},
		{
			name: "valid include categories and event types",
			route: audit.EventRoute{
				IncludeCategories: map[string]audit.SeverityRange{"write": {}},
				IncludeEventTypes: []string{"auth_failure"},
			},
		},
		{
			name: "valid exclude categories and event types",
			route: audit.EventRoute{
				ExcludeCategories: []string{"read"},
				ExcludeEventTypes: []string{"user_delete"},
			},
		},
		{
			name: "mixed include and exclude categories",
			route: audit.EventRoute{
				IncludeCategories: map[string]audit.SeverityRange{"write": {}},
				ExcludeCategories: []string{"read"},
			},
			wantErr: "either include or exclude, not both",
		},
		{
			name: "mixed include categories and exclude event types",
			route: audit.EventRoute{
				IncludeCategories: map[string]audit.SeverityRange{"write": {}},
				ExcludeEventTypes: []string{"auth_failure"},
			},
			wantErr: "either include or exclude, not both",
		},
		{
			name: "mixed include event types and exclude categories",
			route: audit.EventRoute{
				IncludeEventTypes: []string{"user_create"},
				ExcludeCategories: []string{"read"},
			},
			wantErr: "either include or exclude, not both",
		},
		{
			name:    "unknown include category",
			route:   audit.EventRoute{IncludeCategories: map[string]audit.SeverityRange{"nonexistent": {}}},
			wantErr: "unknown taxonomy entries",
		},
		{
			name:    "unknown exclude category",
			route:   audit.EventRoute{ExcludeCategories: []string{"bogus"}},
			wantErr: "unknown taxonomy entries",
		},
		{
			name:    "unknown include event type",
			route:   audit.EventRoute{IncludeEventTypes: []string{"fake_event"}},
			wantErr: "unknown taxonomy entries",
		},
		{
			name:    "unknown exclude event type",
			route:   audit.EventRoute{ExcludeEventTypes: []string{"fake_event"}},
			wantErr: "unknown taxonomy entries",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := audit.ValidateEventRoute(&tt.route, tax)
			if tt.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.ErrorIs(t, err, audit.ErrConfigInvalid)
				assert.Contains(t, err.Error(), tt.wantErr)
			}
		})
	}
}

func TestMatchesRoute(t *testing.T) {
	tests := []struct { //nolint:govet // test struct
		name      string
		eventType string
		category  string
		route     audit.EventRoute
		want      bool
	}{
		// Empty route — matches everything.
		{
			name:      "empty route matches all",
			route:     audit.EventRoute{},
			eventType: "user_create",
			category:  "write",
			want:      true,
		},
		// Include mode — categories.
		{
			name:      "include category match",
			route:     audit.EventRoute{IncludeCategories: map[string]audit.SeverityRange{"security": {}}},
			eventType: "auth_failure",
			category:  "security",
			want:      true,
		},
		{
			name:      "include category no match",
			route:     audit.EventRoute{IncludeCategories: map[string]audit.SeverityRange{"security": {}}},
			eventType: "user_create",
			category:  "write",
			want:      false,
		},
		// Include mode — event types.
		{
			name:      "include event type match",
			route:     audit.EventRoute{IncludeEventTypes: []string{"auth_failure"}},
			eventType: "auth_failure",
			category:  "security",
			want:      true,
		},
		{
			name:      "include event type no match",
			route:     audit.EventRoute{IncludeEventTypes: []string{"auth_failure"}},
			eventType: "permission_denied",
			category:  "security",
			want:      false,
		},
		// Include mode — union of categories + event types.
		{
			name: "include union category match",
			route: audit.EventRoute{
				IncludeCategories: map[string]audit.SeverityRange{"write": {}},
				IncludeEventTypes: []string{"auth_failure"},
			},
			eventType: "user_create",
			category:  "write",
			want:      true,
		},
		{
			name: "include union event type match",
			route: audit.EventRoute{
				IncludeCategories: map[string]audit.SeverityRange{"write": {}},
				IncludeEventTypes: []string{"auth_failure"},
			},
			eventType: "auth_failure",
			category:  "security",
			want:      true,
		},
		{
			name: "include union no match",
			route: audit.EventRoute{
				IncludeCategories: map[string]audit.SeverityRange{"write": {}},
				IncludeEventTypes: []string{"auth_failure"},
			},
			eventType: "config_get",
			category:  "read",
			want:      false,
		},
		// Exclude mode — categories.
		{
			name:      "exclude category match skips",
			route:     audit.EventRoute{ExcludeCategories: []string{"read"}},
			eventType: "user_get",
			category:  "read",
			want:      false,
		},
		{
			name:      "exclude category no match delivers",
			route:     audit.EventRoute{ExcludeCategories: []string{"read"}},
			eventType: "user_create",
			category:  "write",
			want:      true,
		},
		// Exclude mode — event types.
		{
			name:      "exclude event type match skips",
			route:     audit.EventRoute{ExcludeEventTypes: []string{"config_get"}},
			eventType: "config_get",
			category:  "read",
			want:      false,
		},
		{
			name:      "exclude event type no match delivers",
			route:     audit.EventRoute{ExcludeEventTypes: []string{"config_get"}},
			eventType: "user_get",
			category:  "read",
			want:      true,
		},
		// Exclude mode — union of categories + event types.
		{
			name: "exclude union category match skips",
			route: audit.EventRoute{
				ExcludeCategories: []string{"read"},
				ExcludeEventTypes: []string{"user_delete"},
			},
			eventType: "config_get",
			category:  "read",
			want:      false,
		},
		{
			name: "exclude union event type match skips",
			route: audit.EventRoute{
				ExcludeCategories: []string{"read"},
				ExcludeEventTypes: []string{"user_delete"},
			},
			eventType: "user_delete",
			category:  "write",
			want:      false,
		},
		{
			name: "exclude union no match delivers",
			route: audit.EventRoute{
				ExcludeCategories: []string{"read"},
				ExcludeEventTypes: []string{"user_delete"},
			},
			eventType: "user_create",
			category:  "write",
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := audit.MatchesRoute(&tt.route, tt.eventType, tt.category, 5)
			assert.Equal(t, tt.want, got)
		})
	}
}

// ---------------------------------------------------------------------------
// Route matching benchmarks
// ---------------------------------------------------------------------------

func BenchmarkMatchesRoute(b *testing.B) {
	b.Run("empty_route", func(b *testing.B) {
		route := audit.EventRoute{}
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			audit.MatchesRoute(&route, "user_create", "write", 5)
		}
	})

	b.Run("include_categories", func(b *testing.B) {
		route := audit.EventRoute{
			IncludeCategories: map[string]audit.SeverityRange{"write": {}, "security": {}, "admin": {}, "read": {}},
		}
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			audit.MatchesRoute(&route, "user_create", "write", 5)
		}
	})

	b.Run("exclude_categories", func(b *testing.B) {
		route := audit.EventRoute{
			ExcludeCategories: []string{"debug", "trace", "internal"},
		}
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			audit.MatchesRoute(&route, "user_create", "write", 5)
		}
	})

	b.Run("include_event_types", func(b *testing.B) {
		route := audit.EventRoute{
			IncludeEventTypes: []string{"user_create", "user_delete", "schema_register", "auth_failure"},
		}
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			audit.MatchesRoute(&route, "user_create", "write", 5)
		}
	})

	b.Run("include_20_categories", func(b *testing.B) {
		cats := make(map[string]audit.SeverityRange, 20)
		for i := 0; i < 20; i++ {
			cats[fmt.Sprintf("category_%02d", i)] = audit.SeverityRange{}
		}
		cats["write"] = audit.SeverityRange{} // ensure the match key is present
		route := audit.EventRoute{IncludeCategories: cats}
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			audit.MatchesRoute(&route, "user_create", "write", 5)
		}
	})

}

// BenchmarkMatchesRoute_Severity is defined in severity_routing_test.go.
