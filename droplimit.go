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

// SYNC: this file's dropLimiter type is also implemented in
//
//	file/droplimit.go, webhook/droplimit.go,
//	syslog/droplimit.go, loki/droplimit.go.
//
// The type is unexported and cannot be shared across Go modules
// (each output module is independently versioned and published).
// Keep all five copies in sync when making changes (#542).
//
// The core copy (this file) is the canonical reference; sub-module
// copies are byte-for-byte identical to the type definition and
// record method body, but strip the longer comment block on
// lock-free semantics (#492) to keep the per-module file minimal.

import (
	"sync/atomic"
	"time"
)

// dropLimiter rate-limits diagnostic slog.Warn calls for buffer-full
// drop events. The zero value is ready to use — the first drop always
// triggers a warning.
//
// dropLimiter is safe for concurrent use.
type dropLimiter struct {
	lastWarn atomic.Int64 // UnixNano of last emitted warning
	count    atomic.Int64 // drops since last emitted warning
}

// record records a drop event. If at least interval has elapsed since
// the last warning, warnFn is called with the number of drops
// accumulated since the previous warning.
//
// # Window-boundary counting semantics (#492)
//
// Counting uses two atomics (lastWarn + count) that are not updated
// under a shared lock. The call sequence is:
//
//  1. count.Add(1)        — producer bumps the pending-drops counter.
//  2. lastWarn.Load()     — producer reads the last-warn time.
//  3. CompareAndSwap      — producer races to claim the window boundary.
//  4. count.Swap(0)       — winner resets the counter and observes N.
//  5. warnFn(N)           — winner emits the diagnostic.
//
// A producer that performed its Add(1) AFTER another producer's
// Swap(0) (step 4) will have its drop counted in the NEXT window
// rather than the one whose boundary just closed. The total number
// of drops reported across all windows is conserved — no drop is
// ever uncounted — but individual per-window counts are slightly
// smeared across the boundary under high-concurrency bursts.
//
// This is deliberate. A lock-free design means the ordering between
// "my Add has landed" and "someone else's Swap has run" is not
// serialised, and adding a mutex just to serialise a diagnostic
// counter would cost more than the smear is worth. Every drop
// shifted forward is simply counted in the subsequent window, so
// the running total stays accurate — only the per-window boundary
// blurs. The interval is already a diagnostic sampling hint
// (default 10s), not an SLA, so exact window-aligned counts are not
// a contract the caller can rely on.
//
// Callers needing an SLA-grade monotonic drop total should use the
// [OutputMetrics.RecordDrop] counter, which is bumped via a pure
// atomic.Add on every drop with no windowing involved.
func (d *dropLimiter) record(interval time.Duration, warnFn func(dropped int64)) {
	d.count.Add(1)

	// Accepted trade-off (#509, master-tracker C-30): time.Now() is
	// a syscall on some kernels and adds a handful of nanoseconds per
	// call. record() runs only on the drop path — reaching this
	// function at all means the buffer is full and the producer is
	// outpacing the drain, i.e. the system is already in a degraded
	// state. Adding any optimisation here (cached clock, TSC rdtsc)
	// would introduce cross-platform portability risk without any
	// observable improvement on a path that runs orders of magnitude
	// less frequently than Audit() itself.

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
