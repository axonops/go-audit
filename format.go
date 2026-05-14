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
	"slices"
	"sync"
	"time"
)

// sortedKeysPool reuses []string backing arrays for the per-event
// key-sorting paths in sortedFieldKeys / extraFieldKeys /
// allFieldKeysSorted. Outliers (cap > maxPooledKeysCap) are dropped
// rather than re-pooled to avoid pinning oversized arrays.
//
// The initial capacity is sized to absorb the append-then-dedupe
// pattern used by [allFieldKeysSortedSlow], where Required +
// Optional + fields are appended before [slices.Compact] collapses
// duplicates. A 20-field audit event with a matching fields map
// (the representative
// [BenchmarkCEFFormatter_Format_LargeEvent_Escaping] fixture)
// feeds 40 pre-dedupe entries; sizing the initial cap at
// [maxPooledKeysCap] = 64 covers that worst case without a
// growslice allocation. Each pooled slice header carries 64 ×
// sizeof(string) = 1024 B on amd64 (vs 256 B at the pre-#664
// cap=16); absolute overhead across the pool is under 40 KB at
// steady state. See #664 for rationale and measurements.
const (
	initialPooledKeysCap = 64
	maxPooledKeysCap     = 64
)

var sortedKeysPool = sync.Pool{
	New: func() any {
		s := make([]string, 0, initialPooledKeysCap)
		return &s
	},
}

// getSortedKeysSlice returns a zero-length []string from the pool.
// The caller MUST return it via [putSortedKeysSlice] when done.
func getSortedKeysSlice() *[]string {
	ks, ok := sortedKeysPool.Get().(*[]string)
	if !ok {
		s := make([]string, 0, initialPooledKeysCap)
		return &s
	}
	return ks
}

// putSortedKeysSlice returns ks to the pool. Slices with cap exceeding
// [maxPooledKeysCap] are dropped to bound pool memory under outlier
// events.
func putSortedKeysSlice(ks *[]string) {
	if ks == nil || cap(*ks) > maxPooledKeysCap {
		return
	}
	*ks = (*ks)[:0]
	sortedKeysPool.Put(ks)
}

// FormatOptions carries optional per-output context to the formatter.
// A nil *FormatOptions means no special handling — all fields are
// emitted. When non-nil, the formatter skips fields whose sensitivity
// labels overlap with ExcludedLabels.
//
// The library sets FieldLabels per-event before calling [Formatter.Format].
// Implementations MUST NOT retain the opts pointer or modify its fields
// beyond the duration of the Format call.
type FormatOptions struct {
	// ExcludedLabels is the set of sensitivity labels to exclude.
	// Set once at construction time; immutable after that.
	ExcludedLabels map[string]struct{}
	// FieldLabels maps field names to their resolved sensitivity labels.
	// Set by the library per-event from [EventDef.FieldLabels] before
	// calling Format. Implementations MUST NOT retain this pointer.
	FieldLabels map[string]map[string]struct{}
}

// IsExcluded reports whether fieldName carries any label in the
// excluded set. Custom [Formatter] implementations should call this
// to honor sensitivity exclusions.
func (o *FormatOptions) IsExcluded(fieldName string) bool {
	if o == nil || o.FieldLabels == nil || o.ExcludedLabels == nil {
		return false
	}
	labels, ok := o.FieldLabels[fieldName]
	if !ok {
		return false
	}
	for label := range labels {
		if _, excluded := o.ExcludedLabels[label]; excluded {
			return true
		}
	}
	return false
}

// Formatter serialises an audit event into a wire-format byte slice.
// Implementations MUST append a newline terminator. The library
// provides [JSONFormatter] and [CEFFormatter].
//
// # Concurrency
//
// A single Auditor's drain loop calls Format from one goroutine at a
// time, but a formatter instance MAY be shared across multiple
// Auditors via [WithFormatter] (multi-tenant or multi-pipeline
// deployments) and MAY be called from caller goroutines in
// synchronous delivery mode. Implementations MUST be safe for
// concurrent use.
//
// Stateless formatters satisfy this trivially. Formatters that cache
// derived state (resolved field mappings, compiled templates, metric
// handles) SHOULD guard the state with [sync.Once] for one-shot
// initialisation or [sync.RWMutex] / [sync/atomic] for mutable
// caches. The package-level [sync.Pool] pattern used by the built-in
// [JSONFormatter] and [CEFFormatter] is the recommended shape for
// per-call buffer reuse.
//
// Precedent: [log/slog.Handler.Handle], [net/http.Handler.ServeHTTP],
// and [encoding/json.Marshaler] all require concurrent-safe
// implementations by the same reasoning.
type Formatter interface {
	// Format serialises a single audit event into a wire-format byte
	// slice. Implementations MUST append a newline terminator; the
	// library passes the result directly to [Output.Write].
	//
	// ts is the wall-clock time recorded at drain time (not
	// submission). eventType is the registered event type name.
	// fields contains the caller-supplied key-value pairs. def is the
	// [EventDef] for eventType; it is never nil when called by the
	// library. opts carries per-output sensitivity exclusion context;
	// nil means no field exclusion. Use [FormatOptions.IsExcluded] to
	// check whether a field should be skipped. Implementations MUST
	// NOT retain the opts pointer beyond the Format call.
	//
	// A non-nil error causes the event to be dropped and
	// [Metrics.RecordSerializationError] to be called.
	Format(ts time.Time, eventType string, fields Fields, def *EventDef, opts *FormatOptions) ([]byte, error)

	// ContentType returns the MIME type of the bytes emitted by
	// [Formatter.Format]. HTTP-based outputs use this value as the
	// request Content-Type header. Implementations MUST return a
	// stable, non-empty value (the library reads it once at
	// construction time and propagates it to outputs via
	// [ContentTypeSetter.SetContentType]).
	//
	// Examples: the built-in [JSONFormatter] returns
	// "application/x-ndjson"; [CEFFormatter] returns "text/plain"
	// (CEF has no IANA-registered media type — text/plain is the
	// convention accepted by ArcSight SmartConnector and Splunk
	// HEC).
	//
	// The value MUST satisfy the RFC 9110 §5.5 field-value grammar
	// — no CRLF, no NUL, no non-printable control characters.
	// [ContentTypeSetter.SetContentType] validates and rejects unsafe
	// values at auditor construction; the HTTP transport applies its
	// own validation downstream as defence in depth.
	ContentType() string
}

// bufferedFormatter is an internal optimisation interface: built-in
// formatters ([JSONFormatter], [CEFFormatter]) implement it to expose
// their pool-leased [bytes.Buffer] directly to the drain pipeline,
// avoiding the per-event defensive copy-out that the public
// [Formatter.Format] method must perform.
//
// The interface is intentionally unexported: only first-party
// formatters can opt in. Third-party formatters continue through the
// public [Formatter] path and are unaffected.
//
// The returned buffer is leased — the caller MUST return it via
// releaseFormatBuf when finished. The pipeline tracks leases via
// [formatCache] (which owns the formatter buffer and the per-event
// postBuf scratch) and releases them in [Auditor.processEntry]'s
// defer chain, after every [Output.Write] for the event has returned.
type bufferedFormatter interface {
	Formatter
	formatBuf(ts time.Time, eventType string, fields Fields, def *EventDef, opts *FormatOptions) (*bytes.Buffer, error)
	releaseFormatBuf(buf *bytes.Buffer)
}

// FrameworkFieldSetter is implemented by formatters that emit
// auditor-wide framework metadata (app_name, host, timezone, pid) in
// serialised output. The library calls SetFrameworkFields once at
// construction time, after all options are applied and before the
// first Format call.
//
// [JSONFormatter] and [CEFFormatter] implement this interface.
// Third-party formatters that do not implement it silently omit these
// fields.
type FrameworkFieldSetter interface {
	SetFrameworkFields(appName, host, timezone string, pid int)
}

// TimestampFormat controls how timestamps are rendered in serialised
// output. Unrecognised values default to [TimestampRFC3339Nano].
type TimestampFormat string

const (
	// TimestampRFC3339Nano renders timestamps as RFC 3339 with
	// nanosecond precision (e.g. "2006-01-02T15:04:05.999999999Z07:00").
	// This is the default.
	TimestampRFC3339Nano TimestampFormat = "rfc3339nano"

	// TimestampUnixMillis renders timestamps as Unix epoch
	// milliseconds (e.g. 1709222400000).
	TimestampUnixMillis TimestampFormat = "unix_ms"
)

// sortedFieldKeys returns field keys filtered by framework field
// exclusion and optionally by zero-value omission. When a pre-sorted
// slice is available (non-nil), it is used directly. Otherwise the
// fallback slice is sorted on the fly. When omitEmpty is false and no
// framework fields are present, the pre-sorted slice is returned
// directly (zero allocation).
//
// owned is non-nil when the returned slice came from [sortedKeysPool];
// the caller MUST release it via [putSortedKeysSlice]. owned is nil
// when the returned slice is borrowed from the EventDef and MUST NOT
// be released.
func sortedFieldKeys(sorted, fallback []string, fields Fields, omitEmpty bool) (keys []string, owned *[]string) {
	src := sorted
	if src == nil {
		src = sortedCopy(fallback)
	}
	if len(src) == 0 {
		return nil, nil
	}
	// Fast path: when omitEmpty is false and no framework fields
	// appear in the list, return it directly (zero allocation).
	if !omitEmpty && !containsFrameworkField(src, fields) {
		return src, nil
	}
	owned = getSortedKeysSlice()
	for _, k := range src {
		if isFrameworkField(k, fields) {
			continue
		}
		if omitEmpty && shouldOmit(k, fields) {
			continue
		}
		*owned = append(*owned, k)
	}
	return *owned, owned
}

// containsFrameworkField reports whether any key in sorted is a
// framework-managed field for the given fields map.
func containsFrameworkField(sorted []string, fields Fields) bool {
	for _, k := range sorted {
		if isFrameworkField(k, fields) {
			return true
		}
	}
	return false
}

// isFrameworkField reports whether k is a framework-managed field that
// should be skipped during user-field iteration.
func isFrameworkField(k string, fields Fields) bool {
	switch k {
	case "timestamp", "event_type", "severity", "event_category",
		"app_name", "host", "timezone", "pid":
		return true
	case "duration_ms":
		_, isDuration := fields[k].(time.Duration)
		return isDuration
	}
	return false
}

// shouldOmit reports whether a field should be omitted when OmitEmpty
// is true: the field either does not exist or has a zero value.
func shouldOmit(k string, fields Fields) bool {
	v, exists := fields[k]
	return !exists || isZeroValue(v)
}

// extraFieldKeys returns field keys that are not in the EventDef's
// Required or Optional lists (i.e. extra fields from permissive mode),
// sorted alphabetically. Uses the pre-computed knownFields set to
// avoid per-call map allocation.
//
// owned is non-nil when the returned slice came from [sortedKeysPool]
// and MUST be released by the caller via [putSortedKeysSlice]. When
// no extra fields exist, both keys and owned are nil.
func extraFieldKeys(def *EventDef, fields Fields, omitEmpty bool) (keys []string, owned *[]string) {
	known := effectiveKnownFields(def)
	if !hasExtraFields(known, fields, omitEmpty) {
		return nil, nil
	}
	owned = getSortedKeysSlice()
	for k, v := range fields {
		if _, ok := known[k]; ok {
			continue
		}
		if isFrameworkField(k, fields) {
			continue
		}
		if omitEmpty && isZeroValue(v) {
			continue
		}
		*owned = append(*owned, k)
	}
	if len(*owned) == 0 {
		putSortedKeysSlice(owned)
		return nil, nil
	}
	slices.Sort(*owned)
	return *owned, owned
}

// hasExtraFields reports whether fields contains any key that is not
// in known and not a framework field. When omitEmpty is true, zero-
// valued extras are not counted.
func hasExtraFields(known map[string]struct{}, fields Fields, omitEmpty bool) bool {
	for k, v := range fields {
		if _, ok := known[k]; ok {
			continue
		}
		if isFrameworkField(k, fields) {
			continue
		}
		if omitEmpty && isZeroValue(v) {
			continue
		}
		return true
	}
	return false
}

// effectiveKnownFields returns the pre-computed knownFields set or
// builds one from Required + Optional if pre-computed fields are nil.
func effectiveKnownFields(def *EventDef) map[string]struct{} {
	if def.knownFields != nil {
		return def.knownFields
	}
	known := make(map[string]struct{}, len(def.Required)+len(def.Optional))
	for _, k := range def.Required {
		known[k] = struct{}{}
	}
	for _, k := range def.Optional {
		known[k] = struct{}{}
	}
	return known
}

// allFieldKeysSorted returns all field keys from the EventDef
// (required + optional) plus any extra fields, sorted alphabetically.
// When pre-computed fields are available and no extra fields are
// present (the common case), sortedAllKeys is returned directly
// (zero allocation). Falls back to building the list from scratch
// when pre-computed fields are nil.
//
// owned is non-nil when the returned slice came from [sortedKeysPool]
// and MUST be released by the caller via [putSortedKeysSlice].
func allFieldKeysSorted(def *EventDef, fields Fields) (keys []string, owned *[]string) {
	if def.knownFields == nil {
		return allFieldKeysSortedSlow(def, fields)
	}

	hasExtra := false
	for k := range fields {
		if _, ok := def.knownFields[k]; !ok && !isFrameworkField(k, fields) {
			hasExtra = true
			break
		}
	}
	if !hasExtra {
		return def.sortedAllKeys, nil
	}

	owned = getSortedKeysSlice()
	*owned = append(*owned, def.sortedAllKeys...)
	for k := range fields {
		if _, ok := def.knownFields[k]; ok {
			continue
		}
		if isFrameworkField(k, fields) {
			continue
		}
		*owned = append(*owned, k)
	}
	slices.Sort(*owned)
	return *owned, owned
}

// allFieldKeysSortedSlow builds the sorted key list from scratch when
// pre-computed fields are not available. Reached only by third-party
// callers who invoke the public [Formatter.Format] with a
// hand-constructed [EventDef] (the production [Auditor] path takes
// the fast branch above because [Auditor.prepareOutputEntries]
// populates knownFields / sortedAllKeys at startup).
//
// Dedupe is done post-sort via [slices.Compact] rather than a
// map[string]bool tracked during append. The map costs one heap
// allocation per call — 7.7M objects / 72 % of all allocations in
// [BenchmarkCEFFormatter_Format_Numeric] and _Escaping, per
// memprofile (#664). Sort + Compact is O(n log n) either way and
// produces the identical output: sort(unique(Required ∪ Optional ∪
// fields)). The append-then-sort-then-compact path is zero-alloc
// after the per-event pool warm-up.
func allFieldKeysSortedSlow(def *EventDef, fields Fields) (keys []string, owned *[]string) {
	owned = getSortedKeysSlice()
	*owned = append(*owned, def.Required...)
	*owned = append(*owned, def.Optional...)
	for k := range fields {
		*owned = append(*owned, k)
	}
	slices.Sort(*owned)
	*owned = slices.Compact(*owned)
	return *owned, owned
}
