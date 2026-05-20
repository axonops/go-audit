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
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// CIMChangeFormatter serialises audit events shaped for the Splunk
// Common Information Model "Change" data model (CIM 6.1). Wire format
// is newline-delimited JSON (NDJSON); ContentType is
// "application/x-ndjson".
//
// Field mapping (audit ↔ CIM Change):
//
//	timestamp        → _time (epoch seconds, ms precision)
//	event_type       → action
//	event_category   → change_type
//	actor / actor.id → user / user_id
//	actor.name       → user_name
//	target / target.id → object / object_id
//	target.type / target_type → object_category
//	target.path / target_path → object_path
//	target.attrs / target_attrs → object_attrs (JSON-stringified)
//	outcome          → status (collapsed) + outcome (preserved)
//	source_ip        → src
//	severity         → severity_id (numeric extension; not CIM-canonical)
//	app_name         → vendor_product (default; overridable)
//	host             → dvc + host
//
// Outcome → status collapse. The CIM Change `status` field is a
// binary enum (success | failure). Audit outcomes other than
// "success" — including "failure", "denied", "error", "pending",
// "unknown" — collapse to "failure" for `status`. The formatter
// ALSO preserves the original `outcome` field verbatim so the
// granular value is recoverable downstream — Splunk searches can
// pivot on `status` for CIM compliance AND on `outcome` for
// fine-grained reporting.
//
// Unmapped fields. Any field not in the mapping table above passes
// through to the JSON output with its original key, alphabetically
// ordered after the CIM fields. Snake_case is preserved.
//
// VendorProduct. Defaults to the application name set via
// [FrameworkFieldSetter.SetFrameworkFields]. Override per-output via
// [CIMChangeFormatter.VendorProduct] to set the Splunk `vendor_product`
// identifier explicitly (e.g., "AxonOps:Audit").
//
// # Concurrency
//
// Safe for concurrent use by multiple goroutines, per the
// [Formatter] contract.
//
// # Future CIM data models
//
// This formatter targets the Change data model only. Authentication,
// Network Traffic, etc. are scheduled to ship as separate formatter
// types (e.g. CIMAuthenticationFormatter / `type: cim_authentication`).
type CIMChangeFormatter struct {
	// VendorProduct sets the CIM `vendor_product` field. When empty,
	// falls back to the appName set via SetFrameworkFields.
	VendorProduct string

	// Framework fields set once via SetFrameworkFields.
	appName  string
	host     string
	timezone string
	pid      int
}

// ContentType implements [Formatter.ContentType].
func (f *CIMChangeFormatter) ContentType() string { return "application/x-ndjson" }

// SetFrameworkFields implements [FrameworkFieldSetter].
func (f *CIMChangeFormatter) SetFrameworkFields(appName, host, timezone string, pid int) {
	f.appName = appName
	f.host = host
	f.timezone = timezone
	f.pid = pid
}

// auditFieldsRemappedToCIM are the source-side field names handled by
// the explicit CIM mapping. They are excluded from the pass-through
// loop to prevent duplicate emission of (e.g.) both event_category
// and change_type. `outcome` is deliberately NOT in this set — the
// formatter preserves it alongside the collapsed `status` so the
// binary collapse remains recoverable.
var auditFieldsRemappedToCIM = map[string]struct{}{
	"timestamp":      {},
	"event_type":     {},
	"event_category": {},
	"actor":          {},
	"actor_id":       {},
	"target":         {},
	"target_id":      {},
	"target_type":    {},
	"target_path":    {},
	"target_attrs":   {},
	"source_ip":      {},
	"severity":       {}, // emitted as `severity_id` instead
}

// Format implements [Formatter.Format].
func (f *CIMChangeFormatter) Format(ts time.Time, eventType string, fields Fields, def *EventDef, opts *FormatOptions) ([]byte, error) { //nolint:gocyclo,cyclop // long-but-flat orchestrator; per-field mapping is in helpers
	out := make(map[string]any, len(fields)+8)

	// _time: epoch seconds with ms precision (CIM canonical form).
	out["_time"] = float64(ts.UnixMilli()) / 1000.0

	// action: closed-set CIM verb; we forward eventType verbatim and
	// rely on the consumer's TA mapping rules to normalise to the
	// CIM enum (PR 3 ships the TA generator with FIELDALIAS rules).
	out["action"] = eventType

	// change_type: from event_category if present.
	if v, ok := fields["event_category"]; ok && !opts.IsExcluded("event_category") {
		out["change_type"] = v
	}

	mapActor(out, fields, opts)
	if err := mapTarget(out, fields, opts); err != nil {
		return nil, fmt.Errorf("audit: cim_change format: %w", err)
	}

	// status: outcome collapsed to binary success/failure. The
	// original outcome is preserved by the pass-through loop below
	// because `outcome` is deliberately NOT in
	// auditFieldsRemappedToCIM — so consumers can recover the
	// granular value from `outcome` when `status` is "failure".
	if v, ok := fields["outcome"]; ok && !opts.IsExcluded("outcome") {
		out["status"] = collapseOutcomeToCIMStatus(v)
	}

	// src: from source_ip.
	if v, ok := fields["source_ip"]; ok && !opts.IsExcluded("source_ip") {
		out["src"] = v
	}

	// severity_id: numeric severity from def. Named with the `_id`
	// suffix per CIM convention for numeric tag-friendly enums; this
	// avoids collision with consumer-supplied string `severity` fields
	// and signals "this is a non-canonical extension to CIM Change".
	// Skipped if the consumer excluded `severity` via FormatOptions.
	if def != nil && !opts.IsExcluded("severity") {
		out["severity_id"] = int64(def.ResolvedSeverity())
	}

	// vendor_product: explicit override or fallback to appName.
	if vp := f.resolvedVendorProduct(); vp != "" {
		out["vendor_product"] = vp
	}

	// dvc + host: from framework host.
	if f.host != "" {
		out["dvc"] = f.host
		out["host"] = f.host
	}

	mapPassThrough(out, fields, opts)

	b, err := json.Marshal(out)
	if err != nil {
		return nil, fmt.Errorf("audit: cim_change format: %w", err)
	}
	// Append the NDJSON terminator in-place — reuses b's capacity
	// when there is headroom, avoiding a second allocation.
	return append(b, '\n'), nil
}

// mapActor flattens the `actor` and `actor_id` audit fields onto the
// CIM user / user_id / user_name keys. Accepts both `map[string]any`
// and `map[string]string` for the nested form. Precedence: a flat
// `actor_id` overrides any `actor.id` extracted from the nested
// form.
func mapActor(out map[string]any, fields Fields, opts *FormatOptions) { //nolint:gocognit,gocyclo,cyclop // per-type switch is the simplest correct form
	if v, ok := fields["actor"]; ok && !opts.IsExcluded("actor") {
		out["user"] = v
		switch m := v.(type) {
		case map[string]any:
			if id, ok := m["id"]; ok {
				out["user_id"] = id
			}
			if name, ok := m["name"]; ok {
				out["user_name"] = name
			}
		case map[string]string:
			if id, ok := m["id"]; ok {
				out["user_id"] = id
			}
			if name, ok := m["name"]; ok {
				out["user_name"] = name
			}
		}
	}
	if v, ok := fields["actor_id"]; ok && !opts.IsExcluded("actor_id") {
		out["user_id"] = v
	}
}

// mapTarget flattens the `target` audit field plus the optional
// `target_id` / `target_type` / `target_path` / `target_attrs` flat
// variants onto the CIM object / object_id / object_category /
// object_path / object_attrs keys.
func mapTarget(out map[string]any, fields Fields, opts *FormatOptions) error { //nolint:gocognit,gocyclo,cyclop // per-type switch + flat-overrides; refactoring further obscures the mapping
	if v, ok := fields["target"]; ok && !opts.IsExcluded("target") {
		out["object"] = v
		switch m := v.(type) {
		case map[string]any:
			if err := extractTargetSubfields(out, m); err != nil {
				return err
			}
		case map[string]string:
			extractTargetSubfieldsFromStringMap(out, m)
		}
	}
	// Flat overrides — these win over any subfield value extracted
	// from the nested map above (operator-supplied flat field is
	// the explicit choice).
	if v, ok := fields["target_id"]; ok && !opts.IsExcluded("target_id") {
		out["object_id"] = v
	}
	if v, ok := fields["target_type"]; ok && !opts.IsExcluded("target_type") {
		out["object_category"] = v
	}
	if v, ok := fields["target_path"]; ok && !opts.IsExcluded("target_path") {
		out["object_path"] = v
	}
	if v, ok := fields["target_attrs"]; ok && !opts.IsExcluded("target_attrs") {
		attrsJSON, err := json.Marshal(v)
		if err != nil {
			return fmt.Errorf("target_attrs marshal: %w", err)
		}
		out["object_attrs"] = string(attrsJSON)
	}
	return nil
}

func extractTargetSubfields(out, m map[string]any) error {
	if id, ok := m["id"]; ok {
		out["object_id"] = id
	}
	if typ, ok := m["type"]; ok {
		out["object_category"] = typ
	}
	if path, ok := m["path"]; ok {
		out["object_path"] = path
	}
	if attrs, ok := m["attrs"]; ok {
		attrsJSON, err := json.Marshal(attrs)
		if err != nil {
			return fmt.Errorf("target.attrs marshal: %w", err)
		}
		out["object_attrs"] = string(attrsJSON)
	}
	return nil
}

func extractTargetSubfieldsFromStringMap(out map[string]any, m map[string]string) {
	if id, ok := m["id"]; ok {
		out["object_id"] = id
	}
	if typ, ok := m["type"]; ok {
		out["object_category"] = typ
	}
	if path, ok := m["path"]; ok {
		out["object_path"] = path
	}
	// attrs in a string map is just a string — emit verbatim.
	if attrs, ok := m["attrs"]; ok {
		out["object_attrs"] = attrs
	}
}

// mapPassThrough copies every field NOT in auditFieldsRemappedToCIM
// to the output map. Output ordering is determined by json.Marshal
// (sorted) — sort the keys here for forward-compat with custom
// marshallers and so future code that iterates the output sees a
// stable order.
func mapPassThrough(out map[string]any, fields Fields, opts *FormatOptions) {
	extraKeys := make([]string, 0, len(fields))
	for k := range fields {
		if _, mapped := auditFieldsRemappedToCIM[k]; mapped {
			continue
		}
		if opts.IsExcluded(k) {
			continue
		}
		extraKeys = append(extraKeys, k)
	}
	sort.Strings(extraKeys)
	for _, k := range extraKeys {
		out[k] = fields[k]
	}
}

// resolvedVendorProduct returns the override if set, otherwise the
// framework AppName.
func (f *CIMChangeFormatter) resolvedVendorProduct() string {
	if f.VendorProduct != "" {
		return f.VendorProduct
	}
	return f.appName
}

// collapseOutcomeToCIMStatus implements the binary outcome → status
// collapse documented on [CIMChangeFormatter]. Returns "success" for
// the success outcome (case-insensitive), "failure" otherwise.
func collapseOutcomeToCIMStatus(v any) string {
	s, ok := v.(string)
	if !ok {
		return "failure"
	}
	if strings.EqualFold(s, "success") {
		return "success"
	}
	return "failure"
}

// Compile-time interface assertions.
var (
	_ Formatter            = (*CIMChangeFormatter)(nil)
	_ FrameworkFieldSetter = (*CIMChangeFormatter)(nil)
)
