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
	"bytes"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/goccy/go-yaml"
)

// yamlTaxonomy is the intermediate representation of a YAML taxonomy
// document. Field names use snake_case yaml tags matching the schema.
type yamlTaxonomy struct {
	Categories  yamlCategoriesResult    `yaml:"categories"`
	Events      map[string]yamlEventDef `yaml:"events"`
	Sensitivity *yamlSensitivity        `yaml:"sensitivity"`
	Version     int                     `yaml:"version"`
}

// yamlSensitivity is the intermediate representation of the sensitivity
// label configuration in YAML.
type yamlSensitivity struct {
	Labels map[string]*yamlSensitivityLabel `yaml:"labels"`
}

// yamlSensitivityLabel defines a single sensitivity label in YAML.
type yamlSensitivityLabel struct {
	Description string   `yaml:"description"`
	Fields      []string `yaml:"fields"`
	Patterns    []string `yaml:"patterns"`
}

// yamlCategoriesResult holds the parsed categories and the optional
// emit_event_category setting from the categories section.
type yamlCategoriesResult struct {
	categories        yamlCategories
	emitEventCategory *bool // nil = absent (default true)
}

// UnmarshalYAML parses the categories section, extracting both category
// definitions and the optional emit_event_category setting.
func (r *yamlCategoriesResult) UnmarshalYAML(data []byte) error {
	// First pass: unmarshal into a raw map to iterate keys.
	var raw yaml.MapSlice
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("taxonomy: categories must be a YAML mapping — declare like:\n  categories:\n    read:\n      events: [user_view]")
	}

	r.categories = make(yamlCategories, len(raw))

	for _, item := range raw {
		catName, ok := item.Key.(string)
		if !ok {
			return fmt.Errorf("categories: category key must be a string (got %T) — use bare strings like 'read:'", item.Key)
		}
		if catName == "emit_event_category" {
			v, vOK := item.Value.(bool)
			if !vOK {
				return fmt.Errorf("categories: emit_event_category: expected boolean (got %T) — use true or false", item.Value)
			}
			r.emitEventCategory = &v
			continue
		}
		def, err := parseCategoryValue(catName, item.Value)
		if err != nil {
			return err
		}
		r.categories[catName] = def
	}
	return nil
}

// yamlCategories handles polymorphic YAML category parsing. Categories
// can be either a simple list of event names or a struct with severity
// and events. Both formats are supported in the same document.
type yamlCategories map[string]*yamlCategoryDef

// yamlCategoryDef represents a single category in YAML.
type yamlCategoryDef struct {
	Severity *int     `yaml:"severity"`
	Events   []string `yaml:"events"`
}

// parseCategoryValue handles polymorphic category parsing: a category
// value can be a sequence (simple list of event names) or a mapping
// (struct with severity and events).
func parseCategoryValue(catName string, value any) (*yamlCategoryDef, error) {
	switch v := value.(type) {
	case []any:
		// Simple list format: category: [event1, event2]
		events := make([]string, 0, len(v))
		for _, item := range v {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("category %q: event name must be a string (got %T) — use bare strings like '- user_create'", catName, item)
			}
			events = append(events, s)
		}
		return &yamlCategoryDef{Events: events}, nil

	case map[string]any:
		// Struct format: category: {severity: N, events: [...]}
		return parseCategoryMap(catName, v)

	default:
		return nil, fmt.Errorf("category %q: expected a YAML sequence (e.g. '- user_create') or mapping (e.g. 'events: [...]'), got %T", catName, value)
	}
}

// parseCategoryMap decodes a struct-format category from a map and
// validates that only known fields (severity, events) are present.
func parseCategoryMap(catName string, m map[string]any) (*yamlCategoryDef, error) {
	allowed := map[string]struct{}{"severity": {}, "events": {}}
	for key := range m {
		if _, ok := allowed[key]; !ok {
			return nil, fmt.Errorf("category %q: unknown field %q (valid: events, severity)", catName, key)
		}
	}
	var def yamlCategoryDef
	if sv, ok := m["severity"]; ok {
		s, err := toInt(sv)
		if err != nil {
			return nil, fmt.Errorf("category %q: severity must be an integer 0-7 (got %T)", catName, sv)
		}
		def.Severity = &s
	}
	if ev, ok := m["events"]; ok {
		events, err := toStringSlice(ev)
		if err != nil {
			return nil, fmt.Errorf("category %q: %w", catName, err)
		}
		def.Events = events
	}
	return &def, nil
}

// toInt converts a YAML numeric value to int.
func toInt(v any) (int, error) {
	switch n := v.(type) {
	case int:
		return n, nil
	case uint64:
		return int(n), nil //nolint:gosec // severity range 0-10, no overflow risk
	case float64:
		return int(n), nil
	default:
		return 0, fmt.Errorf("expected integer, got %T", v)
	}
}

// toStringSlice converts a YAML sequence value to []string.
func toStringSlice(v any) ([]string, error) {
	list, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("expected a YAML sequence, got %T", v)
	}
	result := make([]string, 0, len(list))
	for _, item := range list {
		s, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("expected string, got %T", item)
		}
		result = append(result, s)
	}
	return result, nil
}

// yamlEventDef is the intermediate representation of a single event
// definition within the YAML taxonomy. Categories are derived from
// the categories map — there is no category field on events.
//
// Fields are declared in a unified fields: map. Each field entry
// specifies whether the field is required (default false = optional)
// and optionally carries sensitivity labels.
type yamlEventDef struct {
	Fields      map[string]*yamlFieldDef `yaml:"fields"`
	Severity    *int                     `yaml:"severity"`
	Description string                   `yaml:"description"`
}

// yamlFieldDef defines a single field within an event definition.
// A nil yamlFieldDef is treated as optional with no labels, default
// type string.
type yamlFieldDef struct {
	Type     string   `yaml:"type"`
	Labels   []string `yaml:"labels"`
	Required bool     `yaml:"required"`
}

// supportedCustomFieldTypes lists the YAML type-vocabulary values
// accepted on custom (non-reserved) fields. Matches [log/slog.Kind] —
// drops `uint64`/`group`/`any` (not applicable to leaf fields), adds
// both `int` and `int64` widths since wire representation matters
// for downstream consumers (SIEM parsers, CEF numeric constraints).
// The default (empty) value is treated as "string".
var supportedCustomFieldTypes = []string{
	"string",
	"int",
	"int64",
	"float64",
	"bool",
	"time",
	"duration",
}

// customFieldYAMLToGoType maps the YAML type-vocabulary value to the
// Go type name used by [cmd/audit-gen] in generated setters and
// stored in [EventDef.FieldTypes].
var customFieldYAMLToGoType = map[string]string{
	"":         "string", // default — no type declared
	"string":   "string",
	"int":      "int",
	"int64":    "int64",
	"float64":  "float64",
	"bool":     "bool",
	"time":     "time.Time",
	"duration": "time.Duration",
}

// validateCustomFieldType returns the Go type name for the supplied
// YAML type-vocabulary value, or an error wrapping [ErrValidation]
// listing the accepted set when the value is unknown. An empty
// string returns "string" (the documented default).
func validateCustomFieldType(eventName, fieldName, yamlType string) (string, error) {
	goType, ok := customFieldYAMLToGoType[yamlType]
	if !ok {
		return "", fmt.Errorf("%w: event %q field %q: unknown type %q (valid: %s)",
			ErrValidation, eventName, fieldName, yamlType,
			strings.Join(supportedCustomFieldTypes, ", "))
	}
	return goType, nil
}

// sanitizeParserErrorMsg replaces C0/C1 control bytes and DEL in the
// third-party YAML parser's error message with a Unicode replacement
// character so downstream log consumers cannot be log-injected by an
// adversarial consumer submitting YAML with embedded NUL / CR / LF.
// Surfaced by [FuzzParseTaxonomyYAML] (#481).
func sanitizeParserErrorMsg(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\n' || r == '\t':
			b.WriteRune(r) // preserve legitimate newlines/tabs in multi-line errors
		case r < 0x20 || r == 0x7f:
			b.WriteRune('\uFFFD')
		case r >= 0x80 && r <= 0x9f:
			b.WriteRune('\uFFFD')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// ParseTaxonomyYAML parses a YAML document into a [*Taxonomy].
// The input MUST be a single YAML document containing a valid taxonomy
// definition. Unknown keys are rejected.
//
// The returned Taxonomy is fully migrated, validated, and
// precomputed. Passing it to [WithTaxonomy] skips redundant
// re-validation.
//
// Input errors (empty, multi-document, invalid syntax) wrap
// [ErrInvalidInput]. Taxonomy validation errors wrap
// [ErrTaxonomyInvalid]. On error, nil is returned.
//
// ParseTaxonomyYAML accepts []byte only — no file paths, no readers.
// Use [embed] or [os.ReadFile] in the caller to load from disk.
// The canonical embed pattern:
//
//	import _ "embed"
//
//	//go:embed taxonomy.yaml
//	var taxonomyYAML []byte
//
//	tax, err := audit.ParseTaxonomyYAML(taxonomyYAML)
//	if err != nil {
//	    log.Fatalf("audit: load taxonomy: %v", err)
//	}
//
// An unknown-key error in the YAML produces a message like:
// `audit: invalid input: [line 3:1] unknown field "eventss" (valid: categories, events, sensitivity, version)`.
// The line:column reference, the offending key, and the closed set
// of valid keys all appear together so the failure is fixable from
// the error text alone.
//
// # Trust model
//
// The taxonomy is developer-owned input. Callers typically embed it
// at compile time via [embed.FS] or load it from a path the developer
// controls; the library treats the document as trusted. ParseTaxonomyYAML
// imposes no input-size cap because, at the developer-trust boundary,
// such a cap would be ceremony rather than defense — a YAML alias bomb
// amplifies regardless of input size, and `goccy/go-yaml` does not
// expose an alias-budget guard. Memory usage scales linearly with the
// number of event types, field definitions, and sensitivity patterns.
//
// Sensitivity precompute is O(events × fields × labels × patterns):
// taxonomies with many events AND many sensitivity patterns AND many
// fields per event will see noticeable parse-time cost. This is a
// per-load cost, not a per-event cost — the precomputed Taxonomy is
// then read in O(1) on the hot path.
func ParseTaxonomyYAML(data []byte) (*Taxonomy, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: input is empty", ErrInvalidInput)
	}

	dec := yaml.NewDecoder(bytes.NewReader(data), yaml.DisallowUnknownField())

	var yt yamlTaxonomy
	if err := dec.Decode(&yt); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidInput, sanitizeParserErrorMsg(WrapUnknownFieldError(err, yamlTaxonomy{})))
	}

	// Reject multi-document YAML and trailing content.
	var discard any
	if err := dec.Decode(&discard); err == nil {
		return nil, fmt.Errorf("%w: input contains multiple YAML documents", ErrInvalidInput)
	} else if !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: trailing content after YAML document: %s", ErrInvalidInput, sanitizeParserErrorMsg(err))
	}

	tax, err := convertYAMLTaxonomy(yt)
	if err != nil {
		return nil, err
	}

	if err := MigrateTaxonomy(&tax); err != nil {
		return nil, err
	}

	if err := ValidateTaxonomy(tax); err != nil {
		return nil, err
	}

	if err := precomputeTaxonomy(&tax); err != nil {
		return nil, err
	}
	return &tax, nil
}

// convertYAMLTaxonomy transforms the intermediate yamlTaxonomy into a
// [Taxonomy]. All maps and slices are defensively copied. EventDef.Categories
// is derived from the categories map — events may belong to multiple
// categories or none (uncategorised). Returns an error when an
// [EventDef] declares an unknown per-field type.
func convertYAMLTaxonomy(yt yamlTaxonomy) (Taxonomy, error) {
	categories := make(map[string]*CategoryDef, len(yt.Categories.categories))
	for name, yamlCat := range yt.Categories.categories {
		categories[name] = &CategoryDef{
			Severity: copyIntPtr(yamlCat.Severity),
			Events:   copyStrings(yamlCat.Events),
		}
	}

	events := make(map[string]*EventDef, len(yt.Events))
	for name, def := range yt.Events {
		ev, evErr := convertYAMLEventDef(name, def)
		if evErr != nil {
			return Taxonomy{}, evErr
		}
		events[name] = ev
	}

	// Derive EventDef.Categories from the categories map.
	for catName, catDef := range categories {
		for _, eventName := range catDef.Events {
			if def, ok := events[eventName]; ok {
				def.Categories = append(def.Categories, catName)
			}
		}
	}
	// Sort categories on each event for deterministic ordering.
	for _, def := range events {
		slices.Sort(def.Categories)
	}

	// Default emit_event_category to true when absent from YAML.
	// The Go struct uses SuppressEventCategory (inverted): zero value
	// (false) means "emit category", matching the YAML default.
	suppressEventCategory := false
	if yt.Categories.emitEventCategory != nil {
		suppressEventCategory = !*yt.Categories.emitEventCategory
	}

	tax := Taxonomy{
		Version:               yt.Version,
		Categories:            categories,
		Events:                events,
		SuppressEventCategory: suppressEventCategory,
	}

	if yt.Sensitivity != nil {
		tax.Sensitivity = convertYAMLSensitivity(yt.Sensitivity)
	}
	return tax, nil
}

// convertYAMLSensitivity converts the YAML sensitivity config to a
// [SensitivityConfig].
func convertYAMLSensitivity(ys *yamlSensitivity) *SensitivityConfig {
	if ys == nil || len(ys.Labels) == 0 {
		return nil
	}
	sc := &SensitivityConfig{
		Labels: make(map[string]*SensitivityLabel, len(ys.Labels)),
	}
	for name, yl := range ys.Labels {
		label := &SensitivityLabel{
			Description: yl.Description,
			Fields:      copyStrings(yl.Fields),
			Patterns:    copyStrings(yl.Patterns),
		}
		sc.Labels[name] = label
	}
	return sc
}

// convertYAMLEventDef converts a single yamlEventDef into an [EventDef].
// Required and Optional are derived from the unified fields map. Per-field
// label annotations are stored in fieldAnnotations for later resolution
// by [precomputeSensitivity]. Per-field type annotations (for custom
// fields only — reserved fields always use their standard Go type)
// populate [EventDef.FieldTypes] after validation against
// [supportedCustomFieldTypes].
func convertYAMLEventDef(eventName string, def yamlEventDef) (*EventDef, error) {
	ev := &EventDef{
		Description: def.Description,
		Severity:    copyIntPtr(def.Severity),
	}
	for fieldName, fieldDef := range def.Fields {
		if err := convertYAMLFieldInto(ev, eventName, fieldName, fieldDef); err != nil {
			return nil, err
		}
	}
	slices.Sort(ev.Required)
	slices.Sort(ev.Optional)
	return ev, nil
}

// convertYAMLFieldInto threads a single yamlFieldDef onto ev —
// Required/Optional list placement, label annotations, and the per-
// field type (custom fields only). Split from convertYAMLEventDef
// to keep cognitive complexity under the linter threshold.
func convertYAMLFieldInto(ev *EventDef, eventName, fieldName string, fieldDef *yamlFieldDef) error {
	if fieldDef == nil {
		ev.Optional = append(ev.Optional, fieldName)
		return nil
	}
	if fieldDef.Required {
		ev.Required = append(ev.Required, fieldName)
	} else {
		ev.Optional = append(ev.Optional, fieldName)
	}
	if len(fieldDef.Labels) > 0 {
		if ev.fieldAnnotations == nil {
			ev.fieldAnnotations = make(map[string][]string)
		}
		ev.fieldAnnotations[fieldName] = copyStrings(fieldDef.Labels)
	}
	// Reserved standard fields always use their library-declared Go
	// type — reject any consumer override via YAML `type:` so the
	// generator's reserved-field table stays authoritative.
	if IsReservedStandardField(fieldName) {
		if fieldDef.Type != "" {
			return fmt.Errorf("%w: event %q field %q: reserved standard field cannot declare a `type:` (library-defined)",
				ErrValidation, eventName, fieldName)
		}
		return nil
	}
	goType, err := validateCustomFieldType(eventName, fieldName, fieldDef.Type)
	if err != nil {
		return err
	}
	if ev.FieldTypes == nil {
		ev.FieldTypes = make(map[string]string)
	}
	ev.FieldTypes[fieldName] = goType
	return nil
}

// copyIntPtr returns a copy of p. A nil input returns nil.
func copyIntPtr(p *int) *int {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

// copyStrings returns a shallow copy of s. A nil input returns nil.
func copyStrings(s []string) []string {
	if s == nil {
		return nil
	}
	cp := make([]string, len(s))
	copy(cp, s)
	return cp
}
