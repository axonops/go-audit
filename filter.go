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
	"fmt"
	"slices"
	"strings"
	"sync/atomic"

	"github.com/axonops/syncmap"
)

// SeverityRange is an inclusive [Min, Max] severity bound on the CEF
// scale (0-10). Used as the value type of
// [EventRoute.IncludeCategories] to express per-category severity
// thresholds in a route. A nil pointer in either field disables that
// side of the bound; the zero value SeverityRange{} (both inner
// pointers nil) means "no severity constraint" for the associated
// category.
type SeverityRange struct {
	// MinSeverity is the inclusive lower bound on CEF severity
	// (0-10). Nil means no lower bound.
	MinSeverity *int

	// MaxSeverity is the inclusive upper bound on CEF severity
	// (0-10). Nil means no upper bound.
	MaxSeverity *int
}

// EventRoute restricts which events are delivered to a specific output.
// Routes operate in one of two mutually exclusive modes:
//
// Include mode (allow-list): events are delivered if their category
// is a key in [EventRoute.IncludeCategories] OR their event type is in
// [EventRoute.IncludeEventTypes].
//
// Exclude mode (deny-list): events are delivered unless their category
// is in [EventRoute.ExcludeCategories] OR their event type is in
// [EventRoute.ExcludeEventTypes].
//
// Setting both include and exclude fields on the same route is a
// bootstrap error. An empty route (all fields nil/empty) delivers all
// globally-enabled events.
//
// # Severity precedence
//
// Severity filters are applied based on which inclusion path matched
// the event:
//
//   - If the event's category is a key in [EventRoute.IncludeCategories],
//     the value's [SeverityRange] applies. The zero value
//     SeverityRange{} means "no severity constraint for this
//     category", and route-level [EventRoute.MinSeverity] /
//     [EventRoute.MaxSeverity] are NOT applied.
//   - Else if the event's type is in [EventRoute.IncludeEventTypes],
//     the route-level severity bounds apply.
//   - Else (no include categories or event types — the severity-only
//     catch-all), the route-level severity bounds apply.
//   - In exclude mode, the route-level severity bounds apply.
//
//nolint:govet // field order: exported fields first for API clarity, then pre-computed sets
type EventRoute struct {
	// IncludeCategories maps category names to per-category severity
	// filters. Presence of a key allows events in that category; the
	// value's [SeverityRange] optionally restricts by severity. The
	// zero value SeverityRange{} means "all severities allowed for
	// this category". Mutually exclusive with ExcludeCategories and
	// ExcludeEventTypes.
	IncludeCategories map[string]SeverityRange

	// IncludeEventTypes lists event type names to allow. Events whose
	// type is in this list are delivered using the route-level
	// MinSeverity/MaxSeverity bounds. Mutually exclusive with
	// ExcludeCategories and ExcludeEventTypes.
	IncludeEventTypes []string

	// ExcludeCategories lists category names to deny. Events whose
	// category is in this list are skipped. Mutually exclusive with
	// IncludeCategories and IncludeEventTypes.
	ExcludeCategories []string

	// ExcludeEventTypes lists event type names to deny. Events whose
	// type is in this list are skipped regardless of category.
	// Mutually exclusive with IncludeCategories and IncludeEventTypes.
	ExcludeEventTypes []string

	// MinSeverity sets a minimum severity threshold. Applied to
	// event-type matches and to the severity-only catch-all (when
	// IncludeCategories has no entries). Per-category filters in
	// IncludeCategories override this for category matches. Nil means
	// no minimum filter.
	MinSeverity *int

	// MaxSeverity sets a maximum severity threshold. Applied to
	// event-type matches and to the severity-only catch-all. Per-
	// category filters in IncludeCategories override this for
	// category matches. Nil means no maximum filter.
	MaxSeverity *int

	// kind + inlineCatCount are placed here (immediately after the
	// exported fields) so MatchesRoute's switch-on-kind dispatches
	// from the same cache line as the exported map/slice headers
	// it then reads. Putting kind at the end of the struct adds an
	// extra cache-line miss per call. See ADR 0007 (#867).
	kind           routeMode // populated by buildRouteSets; zero == unbuilt or empty
	inlineCatCount int8      // 0..4; >0 means use the inline fast path

	// Pre-computed sets for O(1) lookup, populated by buildRouteSets.
	// The sets back the IncludeEventTypes / ExcludeCategories /
	// ExcludeEventTypes slices. Nil when the route was constructed
	// without buildRouteSets (e.g. direct struct literal in tests);
	// MatchesRoute falls back to slices.Contains in that case.
	includeEvtSet map[string]struct{}
	excludeCatSet map[string]struct{}
	excludeEvtSet map[string]struct{}

	// Inline fast path for IncludeCategories when the route has 4 or
	// fewer included categories — the typical real-world case.
	// Populated by buildRouteSets; MatchesRoute scans
	// inlineCats[:inlineCatCount] with a direct string compare,
	// skipping the map hash / bucket lookup entirely. For
	// len(IncludeCategories) > 4 the inline fast path is bypassed
	// and the map is consulted instead.
	//
	// The 4-element threshold reflects measurement on AMD Ryzen
	// (Zen 4): linear scan over a [4]string is ~2 ns, the smallest
	// Go map lookup is ~3.5 ns. Beyond 4 entries the hash-based
	// lookup wins. See docs/adr/0007-matchesroute-perf.md (#867).
	//
	// Placed last in the struct so the cache lines it occupies
	// are only loaded when the inline fast path actually fires.
	inlineCats [4]inlineCat
}

// inlineCat is one entry of the EventRoute inline-fast-path array.
// Defined outside the EventRoute struct so it can be named for
// loops and tests. Field order kept as key-then-value for cache
// locality on the hot-path string compare; the pointer-byte
// rearrangement govet/fieldalignment suggests doesn't actually
// reduce GC scan work (3 pointer slots either way).
//
//nolint:govet // intentional field order for cache locality
type inlineCat struct {
	key string
	val SeverityRange
}

// routeMode classifies an EventRoute by which fields it uses, so
// MatchesRoute can dispatch on a single byte instead of re-scanning
// every len()-of-map / nil-of-pointer condition on every call.
type routeMode uint8

const (
	// routeModeEmpty is the zero value. Either every field is
	// empty/nil (route matches all events) OR the route was built
	// via direct struct literal without calling buildRouteSets —
	// MatchesRoute falls back to IsEmpty() + slow path in either case.
	routeModeEmpty routeMode = iota
	// routeModeInclude — at least one of IncludeCategories /
	// IncludeEventTypes is non-empty. Excludes are guaranteed empty
	// because mixing is a validation error.
	routeModeInclude
	// routeModeExclude — at least one of ExcludeCategories /
	// ExcludeEventTypes is non-empty. Includes are guaranteed empty.
	routeModeExclude
	// routeModeSeverityOnly — every include/exclude field is empty
	// but MinSeverity or MaxSeverity is non-nil. The route is a
	// pure severity-band filter.
	routeModeSeverityOnly
)

// IsEmpty reports whether all route fields are empty, meaning the
// output receives all globally-enabled events.
func (r *EventRoute) IsEmpty() bool {
	return len(r.IncludeCategories) == 0 &&
		len(r.IncludeEventTypes) == 0 &&
		len(r.ExcludeCategories) == 0 &&
		len(r.ExcludeEventTypes) == 0 &&
		r.MinSeverity == nil &&
		r.MaxSeverity == nil
}

func (r *EventRoute) isIncludeMode() bool {
	return len(r.IncludeCategories) > 0 || len(r.IncludeEventTypes) > 0
}

func (r *EventRoute) isExcludeMode() bool {
	return len(r.ExcludeCategories) > 0 || len(r.ExcludeEventTypes) > 0
}

// ValidateEventRoute checks that the route is well-formed: include and
// exclude fields are not mixed, severity fields are in range 0-10 and
// min does not exceed max (route-level and per-category), and all
// referenced categories and event types exist in the taxonomy.
func ValidateEventRoute(route *EventRoute, taxonomy *Taxonomy) error {
	if route.isIncludeMode() && route.isExcludeMode() {
		return fmt.Errorf("%w: EventRoute must use either include or exclude, not both", ErrConfigInvalid)
	}
	if err := validateSeverityRange(route.MinSeverity, route.MaxSeverity, "EventRoute"); err != nil {
		return err
	}
	// Iterate categories in sorted order so a per-category validation
	// error is deterministic.
	cats := make([]string, 0, len(route.IncludeCategories))
	for cat := range route.IncludeCategories {
		cats = append(cats, cat)
	}
	slices.Sort(cats)
	for _, cat := range cats {
		f := route.IncludeCategories[cat]
		// Zero-value SeverityRange{} (both inner pointers nil) means
		// "no severity constraint" — validateSeverityRange returns
		// nil for that input, so no special case is needed here.
		ctx := fmt.Sprintf("EventRoute category %q", cat)
		if err := validateSeverityRange(f.MinSeverity, f.MaxSeverity, ctx); err != nil {
			return err
		}
	}
	return validateRouteEntries(route, taxonomy)
}

// validateSeverityRange checks that a (Min, Max) severity pair is in
// range [audit.MinSeverity, audit.MaxSeverity] and that Min does not
// exceed Max. The contextLabel is included in any error message so
// per-category failures point at the category name.
func validateSeverityRange(minP, maxP *int, contextLabel string) error {
	if minP != nil && (*minP < MinSeverity || *minP > MaxSeverity) {
		return fmt.Errorf("%w: %s min_severity %d out of range %d-%d",
			ErrConfigInvalid, contextLabel, *minP, MinSeverity, MaxSeverity)
	}
	if maxP != nil && (*maxP < MinSeverity || *maxP > MaxSeverity) {
		return fmt.Errorf("%w: %s max_severity %d out of range %d-%d",
			ErrConfigInvalid, contextLabel, *maxP, MinSeverity, MaxSeverity)
	}
	if minP != nil && maxP != nil && *minP > *maxP {
		return fmt.Errorf("%w: %s min_severity %d exceeds max_severity %d",
			ErrConfigInvalid, contextLabel, *minP, *maxP)
	}
	return nil
}

// validateRouteEntries checks that all categories and event types
// referenced by the route exist in the taxonomy.
func validateRouteEntries(route *EventRoute, taxonomy *Taxonomy) error {
	var unknown []string
	unknown = checkCategoryMap(unknown, route.IncludeCategories, taxonomy)
	unknown = checkCategories(unknown, route.ExcludeCategories, taxonomy)
	unknown = checkEventTypes(unknown, route.IncludeEventTypes, taxonomy)
	unknown = checkEventTypes(unknown, route.ExcludeEventTypes, taxonomy)

	if len(unknown) > 0 {
		slices.Sort(unknown)
		return fmt.Errorf("%w: EventRoute references unknown taxonomy entries: [%s]",
			ErrConfigInvalid, strings.Join(unknown, ", "))
	}
	return nil
}

func checkCategories(unknown, cats []string, taxonomy *Taxonomy) []string {
	for _, cat := range cats {
		if _, ok := taxonomy.Categories[cat]; !ok {
			unknown = append(unknown, fmt.Sprintf("category %q", cat))
		}
	}
	return unknown
}

// checkCategoryMap validates keys of an IncludeCategories map. Map
// iteration is non-deterministic in Go — the caller (validateRouteEntries)
// sorts the resulting unknown slice before formatting the error so the
// error message is reproducible.
func checkCategoryMap(unknown []string, cats map[string]SeverityRange, taxonomy *Taxonomy) []string {
	for cat := range cats {
		if _, ok := taxonomy.Categories[cat]; !ok {
			unknown = append(unknown, fmt.Sprintf("category %q", cat))
		}
	}
	return unknown
}

func checkEventTypes(unknown, evts []string, taxonomy *Taxonomy) []string {
	for _, evt := range evts {
		if _, ok := taxonomy.Events[evt]; !ok {
			unknown = append(unknown, fmt.Sprintf("event type %q", evt))
		}
	}
	return unknown
}

// buildRouteSets populates the pre-computed lookup sets, inline fast
// path, and routeMode discriminator on the route. Called by setRoute
// in fanout.go. After this returns MatchesRoute can dispatch on
// r.kind in O(1) and, for the common "include with 1-4 categories"
// case, skip the map hash entirely via the inline fast path.
func buildRouteSets(r *EventRoute) {
	r.includeEvtSet = toSet(r.IncludeEventTypes)
	r.excludeCatSet = toSet(r.ExcludeCategories)
	r.excludeEvtSet = toSet(r.ExcludeEventTypes)
	populateInlineCats(r)
	r.kind = classifyRoute(r)
}

// populateInlineCats fills the inline fast path when the route has
// 1-4 included categories. For larger maps MatchesRoute consults
// the IncludeCategories map directly. The inline array is zeroed
// first so a Build()-then-rebuild on the same route instance does
// not leak stale entries.
func populateInlineCats(r *EventRoute) {
	r.inlineCats = [4]inlineCat{}
	r.inlineCatCount = 0
	if n := len(r.IncludeCategories); n > 0 && n <= len(r.inlineCats) {
		i := 0
		for k, v := range r.IncludeCategories {
			r.inlineCats[i].key = k
			r.inlineCats[i].val = v
			i++
		}
		r.inlineCatCount = int8(i) //nolint:gosec // bounded by len(r.inlineCats) = 4
	}
}

// classifyRoute returns the routeMode for a route. The
// classification is mutually exclusive because ValidateEventRoute
// rejects routes that mix include and exclude — see the
// isIncludeMode / isExcludeMode mutex check in ValidateEventRoute.
func classifyRoute(r *EventRoute) routeMode {
	switch {
	case len(r.IncludeCategories) > 0 || len(r.IncludeEventTypes) > 0:
		return routeModeInclude
	case len(r.ExcludeCategories) > 0 || len(r.ExcludeEventTypes) > 0:
		return routeModeExclude
	case r.MinSeverity != nil || r.MaxSeverity != nil:
		return routeModeSeverityOnly
	}
	return routeModeEmpty
}

// toSet converts a string slice to a set. Returns nil for empty slices.
//
// MUTATION-EQUIV(#571): the `len(ss) == 0` early-return mutant
// (NEGATION variant) is exempt because [inSet] always falls back to
// slices.Contains on the original slice when the pre-computed set is
// nil — the populated-map vs nil distinction is invisible to callers.
// See MUTATION_TESTING.md.
func toSet(ss []string) map[string]struct{} {
	if len(ss) == 0 {
		return nil
	}
	m := make(map[string]struct{}, len(ss))
	for _, s := range ss {
		m[s] = struct{}{}
	}
	return m
}

// MatchesRoute reports whether an event should be delivered to an
// output with the given route. eventType is the event name, category
// is its taxonomy category, severity is the event's resolved severity
// (0-10). An empty route matches all events.
//
// Matching applies the severity precedence documented on
// [EventRoute]:
//
//   - In include mode, category-key match wins: that category's
//     per-category [SeverityRange] applies (zero value = pass all
//     severities). Otherwise, an event-type match uses route-level
//     severity.
//   - In exclude mode, route-level severity applies.
//   - In the severity-only catch-all (no include or exclude lists),
//     route-level severity applies.
//
// Routes built via setRoute (the production path) dispatch on the
// pre-computed [routeMode] kind in O(1). The "include with 1-4
// categories" case skips the IncludeCategories map entirely via a
// linear scan over the inline fast-path array — the typical real-
// world workload. Routes built via direct struct literal (tests)
// fall through to the field-by-field slow path.
func MatchesRoute(route *EventRoute, eventType, category string, severity int) bool {
	switch route.kind {
	case routeModeInclude:
		return matchesInclude(route, eventType, category, severity)
	case routeModeExclude:
		return matchesExclude(route, eventType, category, severity)
	case routeModeSeverityOnly:
		return checkSeverity(route.MinSeverity, route.MaxSeverity, severity)
	case routeModeEmpty:
		// kind == routeModeEmpty covers two cases:
		//   (1) every field is genuinely empty — route matches all events
		//   (2) route was built via direct struct literal without
		//       buildRouteSets — fall back to the field-by-field path
		return matchesEmptyOrUnbuilt(route, eventType, category, severity)
	}
	return false
}

// matchesInclude is the include-mode branch of MatchesRoute. Extracted
// for clarity (and to satisfy gocognit) — the function-call cost is
// acceptable because the include path itself is sub-3ns on the
// inline fast path; the call adds ~1 cycle at most.
func matchesInclude(route *EventRoute, eventType, category string, severity int) bool {
	// Inline fast path: scan up to 4 categories with direct
	// string compare. The branch on inlineCatCount > 0 is stable
	// per route, so the predictor learns it.
	if route.inlineCatCount > 0 {
		for _, ic := range route.inlineCats[:route.inlineCatCount] {
			if ic.key == category {
				return checkSeverity(ic.val.MinSeverity, ic.val.MaxSeverity, severity)
			}
		}
	} else if len(route.IncludeCategories) > 0 {
		// N>4 — map fallback. Guarded by len() so include-event-
		// types-only routes skip the nil-map read entirely.
		// The zero-value SeverityRange{} flows through
		// checkSeverity(nil, nil, _) which returns true.
		if filter, ok := route.IncludeCategories[category]; ok {
			return checkSeverity(filter.MinSeverity, filter.MaxSeverity, severity)
		}
	}
	// Event-type fallback uses route-level severity.
	if inSet(route.includeEvtSet, route.IncludeEventTypes, eventType) {
		return checkSeverity(route.MinSeverity, route.MaxSeverity, severity)
	}
	return false
}

// matchesExclude is the exclude-mode branch of MatchesRoute. The
// route-level severity gate is checked first because exclude routes
// commonly carry a severity bound and rejecting on severity is
// cheaper than two set lookups.
func matchesExclude(route *EventRoute, eventType, category string, severity int) bool {
	if !checkSeverity(route.MinSeverity, route.MaxSeverity, severity) {
		return false
	}
	return !inSet(route.excludeCatSet, route.ExcludeCategories, category) &&
		!inSet(route.excludeEvtSet, route.ExcludeEventTypes, eventType)
}

// matchesEmptyOrUnbuilt handles the routeModeEmpty arm: either a
// genuinely empty route (matches all events) or a route built via
// direct struct literal that bypassed buildRouteSets (the
// field-by-field slow path). Both are folded into one helper so
// the routeModeEmpty case stays cheap when it can.
func matchesEmptyOrUnbuilt(route *EventRoute, eventType, category string, severity int) bool {
	if route.IsEmpty() {
		return true
	}
	if route.isExcludeMode() {
		return matchesExclude(route, eventType, category, severity)
	}
	if route.isIncludeMode() {
		// matchesInclude reads the inline fast path fields too,
		// but for an unbuilt route inlineCatCount == 0 and it
		// falls through to the map fallback — correct.
		return matchesInclude(route, eventType, category, severity)
	}
	return checkSeverity(route.MinSeverity, route.MaxSeverity, severity)
}

// checkSeverity returns true if the event's severity is within the
// inclusive range [*minP, *maxP]. A nil pointer disables that side
// of the bound. Returns true if both pointers are nil.
func checkSeverity(minP, maxP *int, severity int) bool {
	if minP != nil && severity < *minP {
		return false
	}
	if maxP != nil && severity > *maxP {
		return false
	}
	return true
}

// inSet checks membership using the pre-computed set if available,
// falling back to slices.Contains for routes without pre-computed sets.
func inSet(set map[string]struct{}, fallback []string, key string) bool {
	if set != nil {
		_, ok := set[key]
		return ok
	}
	return slices.Contains(fallback, key)
}

// filterState tracks which categories and individual event types are
// enabled. It is safe for concurrent use — reads are lock-free via
// [syncmap.SyncMap] (backed by [sync.Map] internally). The
// AxonOps-controlled fork of [github.com/rgooding/go-syncmap] is
// used so the dependency's supply chain (CI, CodeQL, SECURITY.md,
// signed releases) is under the same engineering controls as audit
// itself (#158).
type filterState struct {
	// enabledCategories tracks the enabled state of each category.
	// Reads are lock-free for stable keys after initial population.
	enabledCategories syncmap.SyncMap[string, bool]

	// eventOverrides tracks per-event-type overrides. A true value
	// forces the event to be enabled regardless of its category; a
	// false value forces it disabled. Events not in this map inherit
	// their category's state.
	eventOverrides syncmap.SyncMap[string, bool]

	// hasEventOverrides is set when EnableEvent or DisableEvent is
	// called. Guards the eventOverrides.Load on the hot path —
	// skipping the sync.Map lookup when no overrides exist reduces
	// BenchmarkAudit from ~1500 ns/op to ~590 ns/op.
	hasEventOverrides atomic.Bool
}

// newFilterState initialises a filterState with all taxonomy categories
// enabled by default.
func newFilterState(t *Taxonomy) *filterState {
	f := &filterState{}
	for cat := range t.Categories {
		f.enabledCategories.Store(cat, true)
	}
	return f
}

// isEnabled reports whether the given event type should be processed.
// It checks per-event overrides first, then falls back to the event's
// category state. An event is enabled if ANY of its categories is
// enabled. Uncategorised events (empty Categories) are always enabled
// at the global level. Lock-free on the read path.
func (f *filterState) isEnabled(eventType string, taxonomy *Taxonomy) bool {
	// Per-event override takes precedence. The atomic flag guards
	// the sync.Map lookup — without it, BenchmarkAudit regresses ~2.5x.
	if f.hasEventOverrides.Load() {
		if override, ok := f.eventOverrides.Load(eventType); ok {
			return override
		}
	}

	// Fall back to category state.
	def, ok := taxonomy.Events[eventType]
	if !ok {
		return false
	}

	// Uncategorised events are always globally enabled.
	if len(def.Categories) == 0 {
		return true
	}

	// Enabled if ANY category is enabled.
	//
	// Accepted trade-off (#509, master-tracker C-29): linear scan
	// over def.Categories. An event_type typically belongs to 1–3
	// categories; `BenchmarkFilterCheck` runs at ~16 ns/op and 0
	// allocs/op which includes this loop. A map-based early-exit
	// would regress the common single-category case by adding a
	// map allocation at registration time without reducing the
	// steady-state ns/op. Re-evaluate only if production taxonomies
	// emerge with >10 categories per event.
	for _, cat := range def.Categories {
		if enabled, _ := f.enabledCategories.Load(cat); enabled {
			return true
		}
	}
	return false
}

// isCategoryEnabled reports whether the given category is currently
// enabled. Used by the drain loop to skip disabled category passes.
func (f *filterState) isCategoryEnabled(category string) bool {
	enabled, _ := f.enabledCategories.Load(category)
	return enabled
}
