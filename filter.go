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
// side of the bound; a nil *SeverityRange (or a *SeverityRange with
// both fields nil) means "no severity constraint" for the associated
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
//     the value's [SeverityRange] applies. A nil value means "no
//     severity constraint for this category", and route-level
//     [EventRoute.MinSeverity]/[EventRoute.MaxSeverity] are NOT applied.
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
	// value (when non-nil) further restricts by severity. A nil value
	// means "all severities allowed for this category". Mutually
	// exclusive with ExcludeCategories and ExcludeEventTypes.
	IncludeCategories map[string]*SeverityRange

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

	// Pre-computed sets for O(1) lookup, populated by buildRouteSets.
	// IncludeCategories is itself a map and serves as its own lookup
	// (no parallel set needed). The remaining sets back the
	// IncludeEventTypes / ExcludeCategories / ExcludeEventTypes
	// slices. Nil when the route was constructed without
	// buildRouteSets (e.g. direct struct literal in tests);
	// MatchesRoute falls back to slices.Contains in that case.
	includeEvtSet map[string]struct{}
	excludeCatSet map[string]struct{}
	excludeEvtSet map[string]struct{}
}

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
		if f == nil {
			continue
		}
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
func checkCategoryMap(unknown []string, cats map[string]*SeverityRange, taxonomy *Taxonomy) []string {
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

// buildRouteSets populates the pre-computed lookup sets on the route
// for O(1) matching in MatchesRoute. Called by setRoute in fanout.go.
// IncludeCategories is itself a map and serves as its own lookup, so
// no parallel set is needed for that field.
func buildRouteSets(r *EventRoute) {
	r.includeEvtSet = toSet(r.IncludeEventTypes)
	r.excludeCatSet = toSet(r.ExcludeCategories)
	r.excludeEvtSet = toSet(r.ExcludeEventTypes)
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
//     per-category [SeverityRange] applies (nil = pass all severities).
//     Otherwise, an event-type match uses route-level severity.
//   - In exclude mode, route-level severity applies.
//   - In the severity-only catch-all (no include or exclude lists),
//     route-level severity applies.
//
// When pre-computed sets are available (route created via setRoute),
// event type / exclude lookups are O(1). Category include lookup is
// always O(1) since IncludeCategories is itself a map. Falls back to
// slices.Contains for routes constructed as direct struct literals.
func MatchesRoute(route *EventRoute, eventType, category string, severity int) bool {
	if route.IsEmpty() {
		return true
	}

	if route.isExcludeMode() {
		if !checkSeverity(route.MinSeverity, route.MaxSeverity, severity) {
			return false
		}
		return !inSet(route.excludeCatSet, route.ExcludeCategories, category) &&
			!inSet(route.excludeEvtSet, route.ExcludeEventTypes, eventType)
	}

	if route.isIncludeMode() {
		// Category-key match wins; the per-category filter (or nil)
		// determines severity entirely — route-level severity does
		// not apply to category matches.
		if filter, ok := route.IncludeCategories[category]; ok {
			if filter == nil {
				return true
			}
			return checkSeverity(filter.MinSeverity, filter.MaxSeverity, severity)
		}
		// Event-type fallback uses route-level severity.
		if inSet(route.includeEvtSet, route.IncludeEventTypes, eventType) {
			return checkSeverity(route.MinSeverity, route.MaxSeverity, severity)
		}
		return false
	}

	// Severity-only catch-all — route-level severity decides.
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
