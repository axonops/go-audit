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
	"slices"
	"time"
)

// QueueLen returns the number of events currently queued in the async
// intake queue. Returns 0 for disabled or synchronous auditors. Safe
// for concurrent use.
func (a *Auditor) QueueLen() int {
	if a.ch == nil {
		return 0
	}
	return len(a.ch)
}

// QueueCap returns the configured async intake queue capacity. Returns
// 0 for disabled or synchronous auditors. Safe for concurrent use.
func (a *Auditor) QueueCap() int {
	if a.ch == nil {
		return 0
	}
	return cap(a.ch)
}

// OutputNames returns a sorted list of all configured output names.
// Safe for concurrent use. Returns nil for disabled auditors with no
// outputs.
func (a *Auditor) OutputNames() []string {
	if len(a.entries) == 0 {
		return nil
	}
	names := make([]string, len(a.entries))
	for i, oe := range a.entries {
		names[i] = oe.output.Name()
	}
	slices.Sort(names)
	return names
}

// IsCategoryEnabled reports whether events in the named category
// would be delivered. This accounts for both category-level state
// and per-event overrides. Returns false for disabled auditors or
// unknown categories.
func (a *Auditor) IsCategoryEnabled(category string) bool {
	if a.disabled || a.taxonomy == nil || a.filter == nil {
		return false
	}
	if _, ok := a.taxonomy.Categories[category]; !ok {
		return false
	}
	// Check category state via the filter's atomic map.
	if enabled, ok := a.filter.enabledCategories.Load(category); ok {
		return enabled
	}
	return true // default-enabled
}

// IsEventEnabled reports whether the named event type would be
// delivered. This accounts for category state, per-event overrides,
// and the global filter. Returns false for disabled auditors or
// unknown event types.
func (a *Auditor) IsEventEnabled(eventType string) bool {
	if a.disabled || a.taxonomy == nil || a.filter == nil {
		return false
	}
	return a.filter.isEnabled(eventType, a.taxonomy)
}

// IsDisabled reports whether the auditor is a no-op (created with
// [WithDisabled]). Safe for concurrent use.
func (a *Auditor) IsDisabled() bool {
	return a.disabled
}

// LastDeliveryAge returns the duration since the named output last
// successfully delivered a batch. Zero is returned when:
//
//   - the auditor is disabled;
//   - outputName is not configured (caller can disambiguate via
//     [Auditor.OutputNames]);
//   - the output does not implement [LastDeliveryReporter] —
//     telemetry is unavailable;
//   - the output has not yet completed a successful delivery.
//
// All four cases collapse to the same return value (`0`) and are
// not distinguishable by the caller without a separate call to
// [Auditor.OutputNames] or [Auditor.IsDisabled]. Treat `0` as "no
// signal" for staleness purposes — a /healthz handler SHOULD
// consider an output healthy until it has produced at least one
// successful delivery, otherwise newly-started auditors fail their
// liveness probe before any traffic arrives.
//
// We chose zero-as-sentinel over a `(time.Duration, bool)` tuple
// because every realistic /healthz handler wants to treat
// "no-signal" identically to "fresh" — both pass the probe — so a
// tuple return would force every caller to write the same
// `if !ok || age <= threshold` boilerplate. Use [Auditor.OutputNames]
// or [Auditor.IsDisabled] when an operator dashboard genuinely
// needs to disambiguate the four cases.
//
// Negative durations: wall-clock time can step backwards on NTP
// correction, so [time.Since] applied to a stored timestamp may
// return a negative [time.Duration]. The canonical comparison
// `age > threshold` evaluates negative ages as "fresh" and passes
// the probe — accidentally correct, but documented for callers
// who maintain dashboards or alerts on the raw return value.
//
// Designed for /healthz handlers. Iterating [Auditor.OutputNames]
// and calling LastDeliveryAge against a staleness threshold flips
// the probe to unhealthy when an output silently stops delivering.
//
// The age is computed against [time.Now] at call time using
// wall-clock arithmetic. Wall-clock means the value can jump on
// system time changes; /healthz thresholds SHOULD be ≥ 10 s to
// absorb sub-second NTP slews. The reference example in
// [examples/16-health-endpoint] uses 30 s.
//
// Concurrency: safe to call from any goroutine. Reads are atomic;
// no mutex.
func (a *Auditor) LastDeliveryAge(outputName string) time.Duration {
	if a.disabled || a.outputsByName == nil {
		return 0
	}
	oe, ok := a.outputsByName[outputName]
	if !ok {
		return 0
	}
	reporter, ok := oe.output.(LastDeliveryReporter)
	if !ok {
		return 0
	}
	nanos := reporter.LastDeliveryNanos()
	if nanos == 0 {
		return 0
	}
	return time.Since(time.Unix(0, nanos))
}

// IsSynchronous reports whether the auditor delivers events inline
// within [Auditor.AuditEvent] (created with [WithSynchronousDelivery]).
// Safe for concurrent use.
func (a *Auditor) IsSynchronous() bool {
	return a.synchronous
}
