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

package audit

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestFieldsPool_DropsOversizedMap_NotReused verifies the #579 B-26
// pool-hygiene guard: maps whose length exceeds [maxPooledFieldsLen]
// are dropped in [returnFieldsToPool] rather than pooled.
//
// Verification uses the [fieldsPoolDrops] counter which is
// deterministically incremented by the guard branch — a
// pointer-identity check via [sync.Pool.Get] would be non-deterministic
// (GC may evict + per-P sharding may hide the Put), and a
// post-return `len()` check would be tautological because
// `returnFieldsToPool` calls `clear()` before `Put()` on the non-drop
// path.
func TestFieldsPool_DropsOversizedMap_NotReused(t *testing.T) {
	// Intentionally NOT t.Parallel(): all three TestFieldsPool_* tests
	// read and assert exact deltas on the package-global
	// [fieldsPoolDrops] counter. Parallelisation would let one test's
	// drop bump leak into another test's before/after window, causing
	// flakes that the race detector cannot surface (atomic counters
	// are race-free; the race here is logical, not data).
	before := fieldsPoolDrops.Load()

	// Build a map beyond the threshold.
	oversized := make(Fields, maxPooledFieldsLen+16)
	for i := 0; i < maxPooledFieldsLen+16; i++ {
		oversized[poolTestKey(i)] = "v"
	}

	returnFieldsToPool(oversized)

	after := fieldsPoolDrops.Load()
	assert.Equal(t, before+1, after,
		"fieldsPoolDrops must increment once when an oversized map is returned — the B-26 guard is broken if this stays flat")
}

// TestFieldsPool_KeepsSmallMap verifies the guard does NOT drop maps
// at or under the threshold — protects against a regression that
// over-eagerly discards every map.
func TestFieldsPool_KeepsSmallMap(t *testing.T) {
	// Intentionally NOT t.Parallel(): see comment on
	// TestFieldsPool_DropsOversizedMap_NotReused.
	before := fieldsPoolDrops.Load()

	small := make(Fields, 4)
	small["a"] = 1
	small["b"] = 2
	returnFieldsToPool(small)

	after := fieldsPoolDrops.Load()
	assert.Equal(t, before, after,
		"small maps must be pooled, not dropped — the drop counter must stay flat")
}

// TestFieldsPool_NilIsNoop verifies the nil-safety contract.
func TestFieldsPool_NilIsNoop(t *testing.T) {
	// Intentionally NOT t.Parallel(): see comment on
	// TestFieldsPool_DropsOversizedMap_NotReused.
	before := fieldsPoolDrops.Load()
	returnFieldsToPool(nil)
	after := fieldsPoolDrops.Load()
	assert.Equal(t, before, after, "nil must be a silent no-op")
}

// poolTestKey converts an int into a unique field name — a tiny
// helper scoped to this test file to avoid a strconv import.
func poolTestKey(i int) string {
	if i == 0 {
		return "k0"
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return "k" + string(buf[pos:])
}
