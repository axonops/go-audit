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
	"hash"
	"slices"
	"sync/atomic"
)

// Event flow through the fan-out engine:
//
//	Audit() → validate → global filter → enqueue
//	  → drainLoop → for each output:
//	    → per-output route filter (matchesRoute)
//	    → serialise once per unique formatter
//	    → deliver to output
//
// Events that pass the global category/event filter are delivered to
// each output whose EventRoute matches. Serialisation is cached per
// Formatter pointer: if three outputs share the same formatter, the
// event is serialised once and the same []byte is delivered to all
// three. Output failures are isolated — one output returning an error
// does not block delivery to others.

// outputEntry bundles an [Output] with its per-output [EventRoute] and
// optional [Formatter] override. The route may be changed at runtime
// via [Auditor.SetOutputRoute]; access is lock-free via atomic.Pointer.
type outputEntry struct {
	output         Output
	metadataWriter MetadataWriter      // cached at construction; nil if output doesn't implement
	formatter      Formatter           // nil = use auditor's default formatter
	excludedLabels map[string]struct{} // nil = no sensitivity exclusions
	formatOpts     *FormatOptions      // pre-allocated; nil when no exclusions
	hmacConfig     *HMACConfig         // nil = no HMAC for this output
	hmac           *hmacState          // pre-constructed hash for drain-loop reuse; nil when no HMAC
	route          atomic.Pointer[EventRoute]
	selfReports    bool // cached at construction; false if output doesn't implement DeliveryReporter
}

// hmacState holds a pre-constructed hash.Hash and reusable buffers for
// HMAC computation. Created once at auditor construction; used
// exclusively by the single drain goroutine — no synchronisation needed.
type hmacState struct {
	mac     hash.Hash // reset+reuse per event
	sumBuf  [64]byte  // large enough for SHA-512 / SHA3-512
	hexBuf  [128]byte // hex-encoded output (2x max hash size)
	hashLen int       // actual hash output size in bytes
}

// matchesEvent reports whether the event should be delivered to this
// output based on its current route. Lock-free — single atomic load.
func (oe *outputEntry) matchesEvent(eventType, category string, severity int) bool {
	route := oe.route.Load()
	if route == nil {
		return true // nil route = all events
	}
	return MatchesRoute(route, eventType, category, severity)
}

// effectiveFormatter returns the per-output formatter if set, or the
// provided default.
func (oe *outputEntry) effectiveFormatter(defaultFmt Formatter) Formatter {
	if oe.formatter != nil {
		return oe.formatter
	}
	return defaultFmt
}

// setRoute atomically replaces the output's event route. The route is
// deep-copied into a new EventRoute to prevent the caller from
// mutating backing arrays, the IncludeCategories map, or the inner
// *int pointers of any SeverityRange values after the call returns.
func (oe *outputEntry) setRoute(route *EventRoute) {
	cp := &EventRoute{
		IncludeCategories: cloneIncludeCategories(route.IncludeCategories),
		IncludeEventTypes: slices.Clone(route.IncludeEventTypes),
		ExcludeCategories: slices.Clone(route.ExcludeCategories),
		ExcludeEventTypes: slices.Clone(route.ExcludeEventTypes),
		MinSeverity:       copyIntPtr(route.MinSeverity),
		MaxSeverity:       copyIntPtr(route.MaxSeverity),
	}
	buildRouteSets(cp)
	oe.route.Store(cp)
}

// getRoute returns a deep copy of the output's current event route.
// The IncludeCategories map is freshly allocated and every
// SeverityRange value's inner *int pointers are deep-copied so the
// caller cannot mutate the stored route.
func (oe *outputEntry) getRoute() EventRoute {
	route := oe.route.Load()
	if route == nil {
		return EventRoute{}
	}
	return EventRoute{
		IncludeCategories: cloneIncludeCategories(route.IncludeCategories),
		IncludeEventTypes: slices.Clone(route.IncludeEventTypes),
		ExcludeCategories: slices.Clone(route.ExcludeCategories),
		ExcludeEventTypes: slices.Clone(route.ExcludeEventTypes),
		MinSeverity:       copyIntPtr(route.MinSeverity),
		MaxSeverity:       copyIntPtr(route.MaxSeverity),
	}
}

// cloneIncludeCategories returns a deep copy of an IncludeCategories
// map: the outer map is freshly allocated, and every value's inner
// *int pointers (MinSeverity, MaxSeverity) are deep-copied. A nil
// input returns nil.
func cloneIncludeCategories(in map[string]SeverityRange) map[string]SeverityRange {
	if in == nil {
		return nil
	}
	out := make(map[string]SeverityRange, len(in))
	for k, v := range in {
		out[k] = SeverityRange{
			MinSeverity: copyIntPtr(v.MinSeverity),
			MaxSeverity: copyIntPtr(v.MaxSeverity),
		}
	}
	return out
}
