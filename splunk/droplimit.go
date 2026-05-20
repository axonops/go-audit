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

package splunk

// SYNC: this file is a copy of droplimit.go from the loki and core
// audit packages. The type is unexported and cannot be shared across
// Go modules. Keep all copies in sync when making changes (#692).

import (
	"sync/atomic"
	"time"
)

// dropLimiter rate-limits diagnostic slog.Warn calls for drop-cause
// events such as buffer-full or oversized-event-rejected. Each drop
// cause owns its own dropLimiter (see [Output.dropsOversized] and
// [Output.dropsBufferFull]) so a burst of one cause does not silence
// the other in the same window. The zero value is ready to use — the
// first drop always triggers a warning.
//
// dropLimiter is safe for concurrent use.
type dropLimiter struct {
	interval time.Duration
	lastWarn atomic.Int64 // UnixNano of last emitted warning
	count    atomic.Int64 // drops since last emitted warning
}

// newDropLimiter returns a dropLimiter whose `allow` method emits at
// most one true result per interval. The first call to `allow` always
// returns true.
func newDropLimiter(interval time.Duration) *dropLimiter {
	return &dropLimiter{interval: interval}
}

// allow returns true if the caller should emit a warning now,
// otherwise false. Either way the drop is counted.
func (d *dropLimiter) allow() bool {
	d.count.Add(1)
	now := time.Now().UnixNano()
	last := d.lastWarn.Load()
	if now-last >= int64(d.interval) {
		if d.lastWarn.CompareAndSwap(last, now) {
			d.count.Store(0)
			return true
		}
	}
	return false
}
