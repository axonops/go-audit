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

// Internal helpers for [Taxonomy]: precomputation of derived fields
// (category derivation, severity resolution, sorted-key tables) and
// deep copying of all mutable substructure for defensive consumer-
// supplied taxonomies. Split out of taxonomy.go (#540) to keep the
// public type definitions readable; all symbols here are package-
// private.

import (
	"regexp"
	"slices"
)

// precomputeTaxonomy populates the pre-computed fields on every
// EventDef in the taxonomy. This includes deriving Categories from
// the categories map (for Go-level construction where categories
// are not set on EventDef directly) and building the field lookup
// structures. Must be called after validation succeeds.
func precomputeTaxonomy(t *Taxonomy) error {
	deriveEventCategories(t)

	for _, def := range t.Events {
		def.resolvedSeverity = resolveEventSeverity(def, t)
		def.severityResolved = true
	}
	for _, def := range t.Events {
		precomputeEventDef(def)
	}
	if err := precomputeSensitivity(t); err != nil {
		return err
	}
	t.validated = true
	return nil
}

// deriveEventCategories populates EventDef.Categories from the
// taxonomy's category map. This ensures Categories is populated for
// both YAML-parsed and Go-constructed taxonomies.
func deriveEventCategories(t *Taxonomy) {
	for catName, catDef := range t.Categories {
		if catDef == nil {
			continue
		}
		for _, eventName := range catDef.Events {
			if def, ok := t.Events[eventName]; ok {
				if !slices.Contains(def.Categories, catName) {
					def.Categories = append(def.Categories, catName)
				}
			}
		}
	}
	for _, def := range t.Events {
		slices.Sort(def.Categories)
	}
}

// resolveEventSeverity computes the effective severity for an event.
// Resolution: event Severity → first category Severity → 5.
func resolveEventSeverity(def *EventDef, t *Taxonomy) int {
	if def.Severity != nil {
		return clampSeverity(*def.Severity)
	}
	// Check categories in sorted order for determinism.
	for _, catName := range def.Categories {
		if catDef, ok := t.Categories[catName]; ok && catDef.Severity != nil {
			return clampSeverity(*catDef.Severity)
		}
	}
	return 5
}

// precomputeEventDef populates the pre-computed lookup structures
// on a single EventDef: knownFields set, sorted field lists, and
// merged sorted key list.
func precomputeEventDef(def *EventDef) {
	def.knownFields = make(map[string]struct{}, len(def.Required)+len(def.Optional))
	for _, f := range def.Required {
		def.knownFields[f] = struct{}{}
	}
	for _, f := range def.Optional {
		def.knownFields[f] = struct{}{}
	}

	def.sortedRequired = sortedCopy(def.Required)
	def.sortedOptional = sortedCopy(def.Optional)

	// Build sorted all-keys from the already-deduped knownFields set.
	all := make([]string, 0, len(def.knownFields))
	for k := range def.knownFields {
		all = append(all, k)
	}
	slices.Sort(all)
	def.sortedAllKeys = all
}

// sortedCopy returns a sorted copy of the input slice.
func sortedCopy(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	cp := make([]string, len(s))
	copy(cp, s)
	slices.Sort(cp)
	return cp
}

// deepCopyTaxonomy returns a deep copy of t. All mutable maps, slices,
// and pointer fields are copied so that mutations to the original after
// the copy do not affect the copy. Called by [WithTaxonomy] to prevent
// post-construction mutation by the consumer.
func deepCopyTaxonomy(t *Taxonomy) *Taxonomy {
	cp := &Taxonomy{
		Version:               t.Version,
		SuppressEventCategory: t.SuppressEventCategory,
		validated:             t.validated,
		dev:                   t.dev,
	}
	cp.Categories = deepCopyCategories(t.Categories)
	cp.Events = deepCopyEvents(t.Events)
	cp.Sensitivity = deepCopySensitivity(t.Sensitivity)
	return cp
}

func deepCopyCategories(cats map[string]*CategoryDef) map[string]*CategoryDef {
	if cats == nil {
		return nil
	}
	cp := make(map[string]*CategoryDef, len(cats))
	for name, cat := range cats {
		cp[name] = &CategoryDef{
			Severity: copyIntPtr(cat.Severity),
			Events:   copyStrings(cat.Events),
		}
	}
	return cp
}

func deepCopyEvents(events map[string]*EventDef) map[string]*EventDef {
	if events == nil {
		return nil
	}
	cp := make(map[string]*EventDef, len(events))
	for name, ev := range events {
		cp[name] = deepCopyEventDef(ev)
	}
	return cp
}

func deepCopyEventDef(ev *EventDef) *EventDef {
	cpEv := &EventDef{
		Categories:       copyStrings(ev.Categories),
		Description:      ev.Description,
		Severity:         copyIntPtr(ev.Severity),
		Required:         copyStrings(ev.Required),
		Optional:         copyStrings(ev.Optional),
		resolvedSeverity: ev.resolvedSeverity,
		severityResolved: ev.severityResolved,
		sortedRequired:   copyStrings(ev.sortedRequired),
		sortedOptional:   copyStrings(ev.sortedOptional),
		sortedAllKeys:    copyStrings(ev.sortedAllKeys),
	}
	if ev.knownFields != nil {
		cpEv.knownFields = make(map[string]struct{}, len(ev.knownFields))
		for k := range ev.knownFields {
			cpEv.knownFields[k] = struct{}{}
		}
	}
	if ev.FieldLabels != nil {
		cpEv.FieldLabels = make(map[string]map[string]struct{}, len(ev.FieldLabels))
		for field, labels := range ev.FieldLabels {
			cpLabels := make(map[string]struct{}, len(labels))
			for l := range labels {
				cpLabels[l] = struct{}{}
			}
			cpEv.FieldLabels[field] = cpLabels
		}
	}
	if ev.fieldAnnotations != nil {
		cpEv.fieldAnnotations = make(map[string][]string, len(ev.fieldAnnotations))
		for field, labels := range ev.fieldAnnotations {
			cpEv.fieldAnnotations[field] = copyStrings(labels)
		}
	}
	if ev.FieldTypes != nil {
		cpEv.FieldTypes = make(map[string]string, len(ev.FieldTypes))
		for k, v := range ev.FieldTypes {
			cpEv.FieldTypes[k] = v
		}
	}
	return cpEv
}

func deepCopySensitivity(sc *SensitivityConfig) *SensitivityConfig {
	if sc == nil {
		return nil
	}
	cp := &SensitivityConfig{
		Labels: make(map[string]*SensitivityLabel, len(sc.Labels)),
	}
	for name, label := range sc.Labels {
		cpLabel := &SensitivityLabel{
			Description: label.Description,
			Fields:      copyStrings(label.Fields),
			Patterns:    copyStrings(label.Patterns),
		}
		if label.compiled != nil {
			// regexp.Regexp is safe for concurrent use; shallow copy is intentional.
			cpLabel.compiled = make([]*regexp.Regexp, len(label.compiled))
			copy(cpLabel.compiled, label.compiled)
		}
		cp.Labels[name] = cpLabel
	}
	return cp
}
