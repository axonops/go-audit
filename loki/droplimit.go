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

package loki

// SYNC: this file is a copy of droplimit.go from the core audit
// package. The type is unexported and cannot be shared across Go
// modules. Keep both copies in sync when making changes.

import (
	"sync/atomic"
	"time"
)

// dropLimiter rate-limits diagnostic slog.Warn calls for drop-cause
// events such as buffer-full or oversized-event-rejected. Each drop
// cause owns its own dropLimiter (see [Output.dropsOversized] and
// [Output.dropsBufferFull]) so a burst of one cause does not silence
// the other in the same window (#692). The zero value is ready to
// use — the first drop always triggers a warning.
//
// dropLimiter is safe for concurrent use.
type dropLimiter struct {
	lastWarn atomic.Int64 // UnixNano of last emitted warning
	count    atomic.Int64 // drops since last emitted warning
}

// record records a drop event. If at least interval has elapsed since
// the last warning, warnFn is called with the number of drops
// accumulated since the previous warning.
func (d *dropLimiter) record(interval time.Duration, warnFn func(dropped int64)) {
	d.count.Add(1)

	// UnixNano uses wall clock; NTP adjustments may shift the interval
	// by the step size, which is acceptable for a 10s diagnostic window.
	now := time.Now().UnixNano()
	last := d.lastWarn.Load()
	if now-last >= int64(interval) {
		if d.lastWarn.CompareAndSwap(last, now) {
			dropped := d.count.Swap(0)
			warnFn(dropped)
		}
	}
}
