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
// DestinationKeyer dedup tests
// ---------------------------------------------------------------------------

// destKeyOutput is a mock output that implements DestinationKeyer.
type destKeyOutput struct {
	name string
	key  string
}

func (d *destKeyOutput) Write(_ []byte) error { return nil }
func (d *destKeyOutput) Close() error         { return nil }
func (d *destKeyOutput) Name() string         { return d.name }
func (d *destKeyOutput) DestinationKey() string {
	return d.key
}

func TestWithOutputs_DuplicateDestination_ReturnsError(t *testing.T) {
	t.Parallel()
	o1 := &destKeyOutput{name: "out1", key: "/var/log/audit.log"}
	o2 := &destKeyOutput{name: "out2", key: "/var/log/audit.log"}
	_, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(o1, o2),
	)
	require.ErrorIs(t, err, audit.ErrDuplicateDestination)
	assert.Contains(t, err.Error(), "out1")
	assert.Contains(t, err.Error(), "out2")
}

func TestWithNamedOutput_DuplicateDestination_ReturnsError(t *testing.T) {
	t.Parallel()
	o1 := &destKeyOutput{name: "out1", key: "localhost:514"}
	o2 := &destKeyOutput{name: "out2", key: "localhost:514"}
	_, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(o1),
		audit.WithNamedOutput(o2),
	)
	require.ErrorIs(t, err, audit.ErrDuplicateDestination)
	assert.Contains(t, err.Error(), "out1")
	assert.Contains(t, err.Error(), "out2")
}

func TestWithOutputs_EmptyDestinationKey_NoCollision(t *testing.T) {
	t.Parallel()
	// Outputs returning empty DestinationKey opt out of dedup.
	o1 := &destKeyOutput{name: "out1", key: ""}
	o2 := &destKeyOutput{name: "out2", key: ""}
	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(o1, o2),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditor.Close() })
}

func TestWithOutputs_MixedTypes_NoFalsePositive(t *testing.T) {
	t.Parallel()
	// destKeyOutput + MockOutput (no DestinationKeyer) should not collide.
	o1 := &destKeyOutput{name: "keyed", key: "/var/log/audit.log"}
	o2 := testhelper.NewMockOutput("unkeyed")
	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(o1, o2),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditor.Close() })
}

// ---------------------------------------------------------------------------
// formatCache tests
// ---------------------------------------------------------------------------

// cacheTestFmt is a minimal Formatter for testing the cache.
type cacheTestFmt struct{ id int }

func (f *cacheTestFmt) Format(_ time.Time, _ string, _ audit.Fields, _ *audit.EventDef, _ *audit.FormatOptions) ([]byte, error) {
	return []byte("data"), nil
}

func (f *cacheTestFmt) ContentType() string { return "application/x-ndjson" }

func TestFormatCache_PutGet(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		formatters int
	}{
		{name: "single_formatter", formatters: 1},
		{name: "at_array_capacity", formatters: audit.FormatCacheSizeForTest},
		{name: "overflow_to_map", formatters: audit.FormatCacheSizeForTest + 1},
		{name: "well_beyond_capacity", formatters: audit.FormatCacheSizeForTest * 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fc := &audit.FormatCacheForTest{}
			fmts := make([]*cacheTestFmt, tt.formatters)
			for i := range fmts {
				fmts[i] = &cacheTestFmt{id: i}
				fc.Put(fmts[i], []byte{byte(i)})
			}

			for i, f := range fmts {
				data, ok := fc.Get(f)
				assert.True(t, ok, "formatter %d should be found", i)
				assert.Equal(t, []byte{byte(i)}, data)
			}

			unknown := &cacheTestFmt{id: 999}
			_, ok := fc.Get(unknown)
			assert.False(t, ok, "unknown formatter should not be found")
		})
	}
}

func TestFormatCache_NilData(t *testing.T) {
	t.Parallel()
	fc := &audit.FormatCacheForTest{}
	f := &cacheTestFmt{id: 1}

	fc.Put(f, nil)

	data, ok := fc.Get(f)
	assert.True(t, ok, "nil-data entry should be found (cached failure)")
	assert.Nil(t, data, "data should be nil for cached failure")
}

// TestFormatCache_FillsArraySlots_ZeroMapAllocs is the authoritative
// regression guard for #499. It asserts that inserting exactly
// [audit.FormatCacheSizeForTest] distinct formatters into a fresh
// [formatCache] via Put does NOT trigger the overflow-map make() —
// operationally, AllocsPerRun must be 0. The test adapts
// automatically to the current constant, so a future bump or shrink
// is reflected in the assertion without a code edit. If a future
// refactor shrinks the constant (or the struct layout silently
// pushes fc to the heap), this test fails loudly in normal
// `go test` — benchmarks only fail via benchstat, which is not on
// the `make check` path.
func TestFormatCache_FillsArraySlots_ZeroMapAllocs(t *testing.T) {
	// Intentionally NOT t.Parallel(): testing.AllocsPerRun panics
	// when called from a parallel test.
	// Pre-allocate one distinct formatter instance per cache slot.
	// Pointer identity is what the cache keys on, so each &cacheTestFmt{}
	// produces a distinct key regardless of field values.
	fmts := make([]audit.Formatter, audit.FormatCacheSizeForTest)
	for i := range fmts {
		fmts[i] = &cacheTestFmt{id: i + 1}
	}
	payload := []byte("cached")

	allocs := testing.AllocsPerRun(1000, func() {
		fc := &audit.FormatCacheForTest{}
		for _, f := range fmts {
			fc.Put(f, payload)
		}
	})
	t.Logf("formatCache.Put × %d distinct formatters: AllocsPerRun = %.2f",
		audit.FormatCacheSizeForTest, allocs)
	assert.LessOrEqual(t, allocs, 0.0,
		"filling the array slots must not allocate the overflow map (#499); any >0 indicates formatCacheSize was shrunk or the struct escaped to the heap")
}
