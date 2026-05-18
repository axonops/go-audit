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
	"regexp"
)

// Fields is the map type for audit event fields. Consumers pass
// field values as Fields to [Auditor.AuditEvent] and generated event
// builders.
//
// Fields is a defined type (not an alias) so it can carry convenience
// methods. Callers constructing fields from a plain map must convert
// explicitly: audit.Fields(m).
//
// Comparable pattern: [net/url.Values], [net/http.Header].
//
// # Supported value types
//
// The library guarantees faithful rendering across both built-in
// formatters (JSON and CEF) for these value types only:
//
//   - string
//   - int, int32, int64
//   - float64
//   - bool
//   - [time.Time]
//   - [time.Duration]
//   - []string
//   - map[string]string
//   - nil (renders as null in JSON; absent in CEF)
//
// Behaviour for values outside this vocabulary depends on the
// auditor's ValidationMode (configured via [WithValidationMode]):
//
//   - [ValidationStrict]: [Auditor.AuditEvent] returns a
//     [ValidationError] wrapping [ErrUnknownFieldType] and the event
//     is dropped.
//   - [ValidationWarn]: the unsupported value is coerced via
//     fmt.Sprintf("%v", v) and a warning is logged through the
//     diagnostic logger ([WithDiagnosticLogger]).
//   - [ValidationPermissive]: the unsupported value is coerced
//     silently.
//
// Coercion is functional but produces formatter-hostile output for
// composite types (struct dumps, "{}" for empty maps). Consumers
// should pass values in the supported vocabulary; the validation
// mode is a backstop, not a feature.
//
// Reserved standard fields ([ReservedStandardFieldNames]) carry an
// additional declared Go type (queryable via
// [ReservedStandardFieldType]). [WithStandardFieldDefaults] enforces
// that declared type at construction time. Per-event values supplied
// via Fields are NOT type-checked against the reserved type — only
// the supported-vocabulary check above runs.
type Fields map[string]any

// Has reports whether the field map contains a value for key.
func (f Fields) Has(key string) bool {
	_, ok := f[key]
	return ok
}

// String returns the value for key as a string. If the key is missing
// or the value is not a string, it returns the empty string.
func (f Fields) String(key string) string {
	v, _ := f[key].(string)
	return v
}

// Int returns the value for key as an int. If the key is missing or
// the value is not an int, it returns 0. Float64 values (common from
// JSON unmarshalling) are truncated toward zero (e.g. 99.9 → 99).
func (f Fields) Int(key string) int {
	switch v := f[key].(type) {
	case int:
		return v
	case float64:
		return int(v)
	default:
		return 0
	}
}

// SensitivityConfig holds all sensitivity label definitions for a
// taxonomy. It is optional; a nil SensitivityConfig means no
// sensitivity labels are defined and the feature is fully disabled
// with zero overhead.
type SensitivityConfig struct {
	// Labels maps label names (e.g., "pii", "financial") to their
	// definitions. Label names MUST be non-empty and match the
	// pattern `^[a-z][a-z0-9_]*$` for code generation safety.
	// [ValidateTaxonomy] rejects any name that does not conform.
	Labels map[string]*SensitivityLabel
}

// SensitivityLabel defines a single sensitivity label with optional
// global field mappings and regex patterns. Labels are defined in the
// taxonomy's sensitivity section and can be associated with fields via
// three mechanisms: explicit per-event annotation, global field name
// mapping, and regex patterns.
type SensitivityLabel struct {
	// Description is an optional human-readable explanation of what
	// this label represents.
	Description string

	// Fields lists field names that are globally assigned this label
	// across all events. A field listed here receives this label in
	// every event where it appears, regardless of per-event annotation.
	Fields []string

	// Patterns lists regex patterns. Any field name matching a pattern
	// is assigned this label. Patterns are compiled once at parse time.
	Patterns []string

	// compiled holds the compiled regexes. Populated by
	// compileSensitivityPatterns at taxonomy parse time.
	compiled []*regexp.Regexp
}

// CategoryDef defines a taxonomy category with its member events and
// optional default severity.
type CategoryDef struct {
	// Severity is the default CEF severity (0-10) for all events in
	// this category. Nil means not set — events inherit the global
	// default (5). A non-nil pointer to 0 means explicitly severity 0.
	Severity *int

	// Events lists the event type names belonging to this category.
	Events []string
}

// EventDef defines a single audit event type in the taxonomy.
type EventDef struct {
	// Categories lists the taxonomy categories this event belongs to
	// (e.g. ["write"], ["security", "access"]). Derived from the
	// [Taxonomy.Categories] map during parsing — not set by consumers.
	// Sorted alphabetically. May be empty for uncategorised events.
	Categories []string

	// Description is an optional human-readable explanation of what
	// this event type represents. It is informational metadata only
	// — it has no effect on validation, routing, or serialisation.
	// When present, [audit-gen] emits it as a Go comment above the
	// generated constant. Also used as the default CEF description.
	Description string

	// Severity is the event-level CEF severity (0-10). Nil means
	// inherit from the category. A non-nil pointer to 0 means
	// explicitly severity 0. Resolution: event → category → 5.
	Severity *int

	// Required lists field names that must be present in every
	// [Auditor.AuditEvent] call for this event type. Missing required
	// fields always produce an error regardless of validation mode.
	Required []string

	// Optional lists field names that may be present. In strict
	// validation mode, any field not in Required or Optional
	// produces an error.
	Optional []string

	// FieldLabels maps field names to their resolved sensitivity labels,
	// represented as a set (map key = label name, value always struct{}).
	// Populated at taxonomy registration time from all three label
	// sources: explicit per-event annotation, global field name mapping,
	// and regex patterns. Nil when no sensitivity config is defined.
	// Read-only after construction — consumers MUST NOT modify this map.
	FieldLabels map[string]map[string]struct{}

	// FieldTypes maps custom (non-reserved) field names to their Go
	// type name as declared in the taxonomy YAML `type:` annotation
	// (e.g., "string", "int", "int64", "float64", "bool", "time.Time",
	// "time.Duration"). Empty or missing entry defaults to "string".
	// Reserved standard fields are NOT in this map — their Go type
	// is authoritative from [standardFieldGoType]. Consumed by
	// [cmd/audit-gen] to emit typed `Set<Field>(v Type)` setters.
	// Read-only after construction.
	FieldTypes map[string]string

	// Pre-computed fields populated by precomputeTaxonomy at
	// registration time. These are read-only after construction
	// and eliminate per-event allocations in validation and
	// formatting.
	fieldAnnotations map[string][]string // per-event label annotations from YAML
	knownFields      map[string]struct{} // union of Required + Optional
	sortedRequired   []string            // Required, sorted alphabetically
	sortedOptional   []string            // Optional, sorted alphabetically
	sortedAllKeys    []string            // Required + Optional, merged, deduped, sorted
	resolvedSeverity int                 // event → category → 5; precomputed
	severityResolved bool                // true once resolvedSeverity has been set
}

// ResolvedSeverity returns the effective severity for this event type.
// The value is precomputed during taxonomy registration and is always
// in the range 0-10. Resolution chain: event Severity (if non-nil) →
// first category Severity in alphabetical order (if non-nil) → 5.
// For events in multiple categories, set event-level Severity to
// avoid depending on alphabetical category ordering.
func (d *EventDef) ResolvedSeverity() int {
	if !d.severityResolved {
		return 5 // default for EventDefs not processed by precomputeTaxonomy
	}
	return d.resolvedSeverity
}

// Taxonomy defines the complete set of audit event types, their
// categories, required and optional fields, and which categories are
// enabled by default. Consumers register a taxonomy at bootstrap via
// [WithTaxonomy].
//
// The framework does not hardcode any event types, field names, or
// categories. The only events the framework injects are "startup" and
// "shutdown" lifecycle events, which are added automatically if not
// already present.
//
// # Construction
//
// Three ways to obtain a [Taxonomy]:
//
//   - [ParseTaxonomyYAML] — load a single YAML document from a
//     `[]byte` (typically `//go:embed`-ed). The returned Taxonomy
//     is already migrated, validated, and precomputed; pass it to
//     [WithTaxonomy] without further work. **Recommended for
//     production.**
//   - [DevTaxonomy] — returns a permissive in-code Taxonomy with
//     a single "all" category. Useful for prototyping and tests;
//     not appropriate for production (see the [DevTaxonomy] godoc
//     for the migration path).
//   - Struct literal — construct a `Taxonomy` value directly in
//     Go. Supported but skips the migration step that
//     [ParseTaxonomyYAML] runs. Pass the result through
//     [ValidateTaxonomy] before [WithTaxonomy] to catch errors at
//     startup rather than at first emission.
type Taxonomy struct {
	// Categories maps category names to their definitions. An event
	// type may appear in multiple categories or in none (uncategorised
	// events are always globally enabled).
	Categories map[string]*CategoryDef

	// Events maps event type names to their definitions. Every event
	// type listed in Categories MUST have a corresponding entry here.
	// Pointers are used to avoid per-event heap escapes when passing
	// definitions through the drain path.
	Events map[string]*EventDef

	// Sensitivity defines the sensitivity label configuration. Nil
	// means no sensitivity labels are defined; the feature is fully
	// disabled with zero overhead.
	Sensitivity *SensitivityConfig

	// Version is the taxonomy schema version. MUST be > 0. Currently
	// only version 1 is supported; higher values cause [WithTaxonomy]
	// to return an error wrapping [ErrTaxonomyInvalid].
	Version int

	// SuppressEventCategory controls whether the `event_category` field
	// is omitted from serialised output. The zero value (false) means
	// the category IS emitted — matching the YAML default when
	// `emit_event_category` is absent. Set to true to suppress.
	SuppressEventCategory bool

	// validated is set by [ParseTaxonomyYAML] after migration,
	// validation, and precomputation succeed. [WithTaxonomy] skips
	// redundant re-validation when this flag is true.
	validated bool

	// dev is set by [DevTaxonomy] to signal that this is a permissive
	// development taxonomy. [New] emits a slog.Warn when this
	// flag is true.
	dev bool
}

// DevTaxonomy creates a permissive development taxonomy where every
// listed event type accepts any fields with no required fields. All
// events are placed in a single "dev" category.
//
// DevTaxonomy is for prototyping and testing only. It accepts any
// event type with any fields and MUST NOT be used in production.
// [New] emits a [log/slog] warning when a DevTaxonomy is used.
//
// # Migrating to production
//
// When the prototype is ready, migrate to a strict taxonomy by:
//
//  1. Listing every event type the application emits (the dev-only
//     log warning will not flag stale call sites — `grep` for
//     `audit.NewEvent(`, `auditor.AuditEvent(`, and the generated
//     event-constructor names).
//  2. Authoring a YAML taxonomy or constructing
//     [Taxonomy] / [CategoryDef] / [EventDef] literals listing
//     required fields, categories, and severities for each event.
//  3. Replacing `audit.WithTaxonomy(audit.DevTaxonomy(...))` with
//     `audit.WithTaxonomy(parsedTaxonomy)` — `audit.New` will then
//     enforce the schema and reject unknown event types and
//     unknown fields at runtime.
//  4. Optionally generating typed event builders via `audit-gen`
//     so the schema is enforced at compile time.
//
// See `docs/taxonomy-validation.md` and `examples/02-code-generation`
// for a worked migration.
func DevTaxonomy(eventTypes ...string) *Taxonomy {
	events := make(map[string]*EventDef, len(eventTypes))
	for _, et := range eventTypes {
		events[et] = &EventDef{}
	}
	return &Taxonomy{
		Version: 1,
		Categories: map[string]*CategoryDef{
			"dev": {Events: eventTypes},
		},
		Events: events,
		dev:    true,
	}
}

const (
	// currentTaxonomyVersion is the latest taxonomy schema version
	// supported by this library.
	currentTaxonomyVersion = 1

	// minSupportedTaxonomyVersion is the oldest taxonomy schema
	// version the library can migrate from.
	minSupportedTaxonomyVersion = 1
)

// Severity bounds for event and route severity values. These follow
// the CEF range convention (0 = least severe, 10 = most severe). Both
// bounds are inclusive. See [EventDef.Severity], [CategoryDef.Severity],
// and [EventRoute.MinSeverity] / [EventRoute.MaxSeverity].
const (
	// MinSeverity is the minimum allowed severity (inclusive).
	MinSeverity = 0
	// MaxSeverity is the maximum allowed severity (inclusive).
	MaxSeverity = 10
)

// clampSeverity restricts a severity value to the valid CEF range
// [MinSeverity, MaxSeverity].
func clampSeverity(s int) int {
	if s < MinSeverity {
		return MinSeverity
	}
	if s > MaxSeverity {
		return MaxSeverity
	}
	return s
}
