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
	"fmt"
	"slices"
	"strconv"
	"sync"
	"time"
)

// cefBufPool caches bytes.Buffer instances for CEFFormatter.Format.
// The New function pre-grows to 256 bytes as a starting hint; the
// buffer grows on first use and retains capacity, so after warm-up
// the pool holds buffers large enough for the typical ~400-byte output.
//
// Outlier buffers (cap > maxPooledBufCap) are dropped on Put rather
// than re-pooled. On Put the backing array is zeroed across [0:cap]
// to defend against future read-past-len bugs.
var cefBufPool = sync.Pool{
	New: func() any {
		b := new(bytes.Buffer)
		b.Grow(256)
		return b
	},
}

// putCEFBuf returns buf to [cefBufPool] with defensive zeroing and
// outlier rejection.
//
// MUTATION-EQUIV(#571): both the nil-check and cap-threshold mutations
// here are documented equivalent in MUTATION_TESTING.md — pool put is
// allocation-only behaviour, the produced output is already complete
// and unaffected.
func putCEFBuf(buf *bytes.Buffer) {
	if buf == nil || buf.Cap() > maxPooledBufCap {
		return
	}
	buf.Reset()
	b := buf.Bytes()
	clear(b[:cap(b)])
	cefBufPool.Put(buf)
}

// defaultCEFFieldMappingEntries returns a new map containing the
// built-in audit-field-to-CEF-extension-key mapping. Each call returns
// a distinct map instance; callers may mutate the result without
// affecting other callers. No package-level mutable state is held.
func defaultCEFFieldMappingEntries() map[string]string {
	return map[string]string{
		// Identity and access
		"actor_id":    "suser",
		"actor_uid":   "suid",
		"role":        "spriv",
		"target_id":   "duser",
		"target_uid":  "duid",
		"target_role": "dpriv",

		// Event context
		"outcome": "outcome",
		"reason":  "reason",
		"message": "msg",

		// Network
		"source_ip":   "src",
		"source_host": "shost",
		"source_port": "spt",
		"dest_ip":     "dst",
		"dest_host":   "dhost",
		"dest_port":   "dpt",
		"protocol":    "app",
		"transport":   "proto",

		// HTTP / request
		"request_id": "externalId",
		"user_agent": "requestClientApplication",
		"referrer":   "requestContext",
		"method":     "requestMethod",
		"path":       "request",

		// Temporal
		"start_time": "start",
		"end_time":   "end",

		// File
		"file_name": "fname",
		"file_path": "filePath",
		"file_hash": "fileHash",
		"file_size": "fsize",
	}
}

// DefaultCEFFieldMapping returns a new map containing the built-in
// field mapping from audit field names to standard CEF extension keys.
// Each call returns a distinct map instance; callers may freely mutate
// the result. Consumers can use this as a base, add or override
// entries, and pass the result to [CEFFormatter.FieldMapping].
func DefaultCEFFieldMapping() map[string]string {
	return defaultCEFFieldMappingEntries()
}

// CEFFormatter serialises audit events in Common Event Format (CEF).
//
// The output format is:
//
//	CEF:0|{Vendor}|{Product}|{Version}|{eventType}|{description}|{severity}|{extensions}
//
// Header fields use pipe (|) as a delimiter. Extension values use
// key=value pairs separated by spaces.
//
// # Escaping
//
// Header fields escape backslash and pipe: \ -> \\, | -> \|.
// Newlines and carriage returns in headers are replaced with spaces.
// Extension values escape backslash, equals, newline, and CR:
// \ -> \\, = -> \=, newline -> \n (literal), CR -> \r (literal).
// All remaining C0 control characters (0x00-0x1F) are stripped.
//
// # Severity
//
// Severity is determined by [CEFFormatter.SeverityFunc] if set. If nil,
// the taxonomy-defined severity is used via [EventDef.ResolvedSeverity]:
// event Severity (if non-nil) → first category Severity in alphabetical
// order (if non-nil) → 5. Values are clamped to the valid CEF range 0-10.
//
// # Concurrency
//
// Safe for concurrent use by multiple goroutines, per the
// [Formatter] contract. Lazy field-mapping resolution is guarded by
// [sync.Once], and per-call buffers are leased from a package-level
// [sync.Pool]. The noCopy marker prevents accidental copies that
// would duplicate the sync.Once state.
type CEFFormatter struct {
	// SeverityFunc maps event types to CEF severity. If nil,
	// taxonomy-defined severity is used via [EventDef.ResolvedSeverity]
	// (precomputed at taxonomy registration time and guaranteed to be
	// in the valid range 0-10 — no per-event clamp).
	//
	// When non-nil, return values are clamped to 0-10 on every event
	// to protect against out-of-range consumer returns. Set
	// SeverityFunc only to override the taxonomy.
	SeverityFunc func(eventType string) int

	// DescriptionFunc maps event types to human-readable CEF
	// descriptions. If nil, [EventDef.Description] is used when
	// non-empty, falling back to the event type name.
	DescriptionFunc func(eventType string) string

	// FieldMapping maps audit field names to CEF extension keys. If nil,
	// [DefaultCEFFieldMapping] is used. If non-nil, entries are merged
	// with [DefaultCEFFieldMapping]: consumer entries override matching
	// defaults, and defaults not present in FieldMapping remain active.
	// Unmapped fields use their original audit field name as the
	// extension key.
	//
	// To opt out of a default mapping for a specific field, use either
	// of these supported patterns (pick whichever reads better at the
	// call site):
	//
	//  1. Empty-string opt-out — pass the audit field name mapped to
	//     "" to explicitly drop the default. The field is then emitted
	//     with the raw audit field name as the CEF extension key:
	//
	//	f := &audit.CEFFormatter{FieldMapping: map[string]string{
	//	    "actor_id": "", // drop default actor_id → suser
	//	}}
	//
	//  2. Self-map — pass the audit field name mapped to itself. Same
	//     on-wire result (the raw audit field name becomes the
	//     extension key), but keeps the intent explicit at the call
	//     site:
	//
	//	f := &audit.CEFFormatter{FieldMapping: map[string]string{
	//	    "actor_id": "actor_id", // emit as actor_id=... not suser=...
	//	}}
	FieldMapping    map[string]string
	resolvedMapping map[string]string

	// resolveErr captures any error produced by [fieldMapping]'s
	// construction-time validation (e.g. an unsafe CEF extension key
	// in consumer-supplied FieldMapping). Surfaced from every call to
	// Format so the problem fails fast rather than silently emitting
	// corrupt CEF lines. See #477.
	resolveErr error

	// Vendor is the CEF header vendor field (e.g. "AxonOps"). If empty,
	// the vendor position in the header is blank but the pipe
	// delimiters are preserved. SHOULD be non-empty for
	// standard-compliant CEF output.
	Vendor string

	// Product is the CEF header product field (e.g. "SchemaRegistry").
	// If empty, the product position is blank. SHOULD be non-empty.
	Product string

	// Version is the CEF header product version field (e.g. "1.0").
	// If empty, the version position is blank. SHOULD be non-empty.
	Version string

	// Framework fields set once via SetFrameworkFields.
	appName  string
	host     string
	timezone string
	pidStr   string // pre-formatted PID; empty when pid == 0
	pid      int

	// noCopy prevents go vet from missing struct copies after first use.
	// CEFFormatter embeds sync.Once which must not be copied.
	noCopy      noCopy
	resolveOnce sync.Once

	// OmitEmpty controls whether zero-value fields are omitted from
	// extensions.
	OmitEmpty bool
}

// noCopy is a go vet guard that prevents copying of structs containing
// sync primitives. See https://pkg.go.dev/sync#Locker.
type noCopy struct{}

func (*noCopy) Lock()   {}
func (*noCopy) Unlock() {}

// maxCEFHeaderField is the maximum byte length for Vendor, Product,
// and Version header fields.
//
// The ArcSight CEF Implementation Standard does not define a per-
// field limit — only a ~1022-byte cap on total header length for
// syslog-compatible delivery. 255 is a conservative operational
// ceiling chosen because it: (a) matches the common ASCII C-string
// length assumption used by many SIEMs for header parsing; (b)
// leaves ample room under the ~1022-byte total-header cap when
// combined across Vendor + Product + Version + the variable
// signature / name / severity fields; (c) protects against
// pathological consumer configuration (e.g. an accidentally
// concatenated version string growing unbounded across releases).
//
// Consumers who need to emit header values longer than 255 bytes
// should raise an issue with the use case — the limit is not
// rooted in the spec and can be revisited.
const maxCEFHeaderField = 255

// cefSeverityStrings avoids per-event strconv.Itoa for severity (0-10).
var cefSeverityStrings = [11]string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10"}

// ContentType implements [Formatter.ContentType]. CEF has no
// IANA-registered media type; "text/plain" is the de-facto
// convention accepted by ArcSight SmartConnector and Splunk HEC
// raw endpoints. Operators sending CEF to a receiver that demands
// a specific value can override the Content-Type via the output's
// headers config.
func (cf *CEFFormatter) ContentType() string { return "text/plain" }

// Format serialises a single audit event as a CEF line. The returned
// slice is owned by the caller (defensive copy from the pooled buffer).
//
// Internal callers in the drain pipeline use [CEFFormatter.formatBuf]
// to obtain the leased buffer directly and skip the copy.
func (cf *CEFFormatter) Format(ts time.Time, eventType string, fields Fields, def *EventDef, opts *FormatOptions) ([]byte, error) {
	buf, err := cf.formatBuf(ts, eventType, fields, def, opts)
	if err != nil {
		return nil, err
	}
	out := make([]byte, buf.Len())
	copy(out, buf.Bytes())
	cf.releaseFormatBuf(buf)
	return out, nil
}

// releaseFormatBuf returns buf to [cefBufPool], applying the same
// outlier-rejection and zeroing rules as [putCEFBuf].
func (*CEFFormatter) releaseFormatBuf(buf *bytes.Buffer) { putCEFBuf(buf) }

// formatBuf serialises an event into a pool-leased *bytes.Buffer.
// See [JSONFormatter.formatBuf] for the contract.
func (cf *CEFFormatter) formatBuf(ts time.Time, eventType string, fields Fields, def *EventDef, opts *FormatOptions) (*bytes.Buffer, error) {
	if len(cf.Vendor) > maxCEFHeaderField {
		return nil, fmt.Errorf("audit: cef vendor exceeds %d bytes (%d)", maxCEFHeaderField, len(cf.Vendor))
	}
	if len(cf.Product) > maxCEFHeaderField {
		return nil, fmt.Errorf("audit: cef product exceeds %d bytes (%d)", maxCEFHeaderField, len(cf.Product))
	}
	if len(cf.Version) > maxCEFHeaderField {
		return nil, fmt.Errorf("audit: cef version exceeds %d bytes (%d)", maxCEFHeaderField, len(cf.Version))
	}
	severity := cf.severity(eventType, def)
	description := cf.description(eventType, def)
	mapping := cf.fieldMapping()
	// Construction-time validation failure (e.g. unsafe extension
	// key in FieldMapping) is surfaced here so every Format call
	// fails fast rather than emitting corrupt CEF that downstream
	// SIEMs mis-parse as spoofed events (#477).
	if cf.resolveErr != nil {
		return nil, cf.resolveErr
	}

	buf, ok := cefBufPool.Get().(*bytes.Buffer)
	if !ok {
		buf = new(bytes.Buffer)
	}
	buf.Reset()
	// Preflight: size the buffer for the common case (~150 B header +
	// 20 fields × ~25 B per key=value pair). Eliminates 1–2 doubling
	// reallocs on cold-pool events and backstops the AvailableBuffer
	// boundary hazard for primitive Append* callers on warm buffers
	// (#496). No-op when cap already suffices.
	buf.Grow(768)

	// Write header: CEF:0|vendor|product|version|eventType|description|severity|
	buf.WriteString("CEF:0|")
	buf.WriteString(cefEscapeHeader(cf.Vendor))
	buf.WriteByte('|')
	buf.WriteString(cefEscapeHeader(cf.Product))
	buf.WriteByte('|')
	buf.WriteString(cefEscapeHeader(cf.Version))
	buf.WriteByte('|')
	buf.WriteString(cefEscapeHeader(eventType))
	buf.WriteByte('|')
	buf.WriteString(cefEscapeHeader(description))
	buf.WriteByte('|')
	buf.WriteString(cefSeverityStrings[severity])
	buf.WriteByte('|')

	// Write extensions directly into the same buffer.
	extStart := buf.Len()

	// Timestamp as receipt time (epoch ms) — write directly to buffer
	// to avoid strconv.FormatInt string allocation.
	if extStart < buf.Len() {
		buf.WriteByte(' ')
	}
	buf.WriteString("rt=")
	buf.Write(strconv.AppendInt(buf.AvailableBuffer(), ts.UnixMilli(), 10))

	// Event type as device action.
	writeExtField(buf, extStart, "act", eventType)

	// Build reserved key set from framework-emitted extension keys.
	reserved := map[string]struct{}{
		"rt":  {},
		"act": {},
	}

	// Duration if present as time.Duration. writeExtFieldInt64 routes
	// the int64 via strconv.AppendInt into a stack-scratch slice and
	// writes that slice directly into the pool-leased buffer — no
	// intermediate string allocation and no any-box (#663, follow-up
	// to #496's per-field alloc removal).
	if v, ok := fields["duration_ms"]; ok {
		if d, ok := v.(time.Duration); ok {
			writeExtFieldInt64(buf, extStart, "cn1", d.Milliseconds())
			writeExtField(buf, extStart, "cn1Label", "durationMs")
			reserved["cn1"] = struct{}{}
			reserved["cn1Label"] = struct{}{}
		}
	}

	// Framework fields (app_name, host, timezone, pid).
	cf.writeFrameworkExtensions(buf, extStart, reserved)

	// All fields via mapping.
	if err := cf.writeFieldExtensions(buf, extStart, fields, def, mapping, reserved, opts); err != nil {
		putCEFBuf(buf)
		return nil, err
	}

	buf.WriteByte('\n')
	return buf, nil
}

// writeFieldExtensions writes all user-defined fields as CEF
// extensions into buf, starting at extStart. Fields whose mapped
// extension key collides with a reserved framework key are silently
// skipped.
func (cf *CEFFormatter) writeFieldExtensions(buf *bytes.Buffer, extStart int, fields Fields, def *EventDef, mapping map[string]string, reserved map[string]struct{}, opts *FormatOptions) error {
	// Per-event extension-key validation was removed as part of #477.
	// The taxonomy validator (ValidateTaxonomy) already rejects any
	// event-type key or field name that does not match the safe
	// identifier pattern at load time, so consumer-controlled names
	// reaching this point are known-safe. Custom FieldMapping entries
	// are consumer code and are trusted.
	allKeys, owned := allFieldKeysSorted(def, fields)
	for _, k := range allKeys {
		if isFrameworkField(k, fields) {
			continue
		}
		if opts.IsExcluded(k) {
			continue
		}
		v := fields[k]
		if cf.OmitEmpty && isZeroValue(v) {
			continue
		}
		extKey := mapFieldKey(k, mapping)
		// Skip fields whose mapped key collides with a framework-
		// emitted extension key. Collision is a consumer mapping
		// misconfiguration; it is silently skipped to avoid
		// per-event log flooding.
		if _, dup := reserved[extKey]; dup {
			continue
		}
		writeExtFieldValue(buf, extStart, extKey, v)
	}
	putSortedKeysSlice(owned)
	return nil
}

func (cf *CEFFormatter) severity(eventType string, def *EventDef) int {
	// SeverityFunc takes precedence (explicit consumer override).
	// Return value is clamped because the consumer-supplied function
	// can return any int; an out-of-range value must not reach the
	// wire (B-28).
	if cf.SeverityFunc != nil {
		return clampSeverity(cf.SeverityFunc(eventType))
	}
	// Common fast path: taxonomy-resolved severity is precomputed and
	// clamped during taxonomy registration (see precomputeTaxonomy in
	// taxonomy.go). No per-event clamp is required here.
	return def.ResolvedSeverity()
}

func (cf *CEFFormatter) description(eventType string, def *EventDef) string {
	// DescriptionFunc takes precedence (backwards compatibility).
	if cf.DescriptionFunc != nil {
		return cf.DescriptionFunc(eventType)
	}
	// Use taxonomy-defined description.
	if def.Description != "" {
		return def.Description
	}
	return eventType
}

// fieldMapping returns the resolved field mapping, merging consumer
// overrides with defaults. The result is computed once and cached.
//
// Every resolved extension key is validated once here (O(1) startup
// cost) against the CEF key character class `[a-zA-Z0-9_]+`. Keys
// containing space, `=`, `|`, newline, or other characters would be
// written verbatim into the CEF extension section by [writeExtField]
// and could be mis-parsed by downstream SIEMs as spoofed extension
// pairs, a new event delimiter, or a truncated event. Catching the
// misconfiguration at construction time keeps the per-event hot path
// validation-free while preventing the log-injection class (#477).
//
// The first validation failure is captured in [cf.resolveErr] and
// surfaced from every [Format] call.
func (cf *CEFFormatter) fieldMapping() map[string]string {
	cf.resolveOnce.Do(func() {
		merged := cf.mergedMapping()
		// Validate every resolved extension key. Sort the audit keys
		// so the first error reported is deterministic.
		auditKeys := make([]string, 0, len(merged))
		for k := range merged {
			auditKeys = append(auditKeys, k)
		}
		slices.Sort(auditKeys)
		for _, auditKey := range auditKeys {
			extKey := merged[auditKey]
			if err := validateExtKey(extKey); err != nil {
				cf.resolveErr = fmt.Errorf(
					"audit: cef: field %q maps to invalid extension key %q: %w",
					auditKey, extKey, err)
				return
			}
		}
		cf.resolvedMapping = merged
	})
	return cf.resolvedMapping
}

// mergedMapping combines [DefaultCEFFieldMapping] with
// [CEFFormatter.FieldMapping] following the documented overlay rules:
//
//   - nil FieldMapping: use defaults only.
//   - non-nil FieldMapping: start from defaults, then apply the
//     consumer map. An empty-string consumer value is the explicit
//     opt-out sentinel — the entry is removed from the merged map so
//     the audit field name is emitted verbatim (B-23).
func (cf *CEFFormatter) mergedMapping() map[string]string {
	defaults := defaultCEFFieldMappingEntries()
	if cf.FieldMapping == nil {
		return defaults
	}
	merged := make(map[string]string, len(defaults)+len(cf.FieldMapping))
	for k, v := range defaults {
		merged[k] = v
	}
	for k, v := range cf.FieldMapping {
		if v == "" {
			delete(merged, k)
			continue
		}
		merged[k] = v
	}
	return merged
}

// SetFrameworkFields stores auditor-wide framework metadata for
// emission in every CEF event. Called once at construction time.
func (cf *CEFFormatter) SetFrameworkFields(appName, host, timezone string, pid int) {
	cf.appName = appName
	cf.host = host
	cf.timezone = timezone
	cf.pid = pid
	if pid > 0 {
		cf.pidStr = strconv.Itoa(pid)
	}
}

// writeFrameworkExtensions writes app_name, host, timezone, and pid as
// standard CEF extension keys.
func (cf *CEFFormatter) writeFrameworkExtensions(buf *bytes.Buffer, extStart int, reserved map[string]struct{}) {
	if cf.appName != "" {
		writeExtField(buf, extStart, "deviceProcessName", cf.appName)
		reserved["deviceProcessName"] = struct{}{}
	}
	if cf.host != "" {
		writeExtField(buf, extStart, "dvchost", cf.host)
		reserved["dvchost"] = struct{}{}
	}
	if cf.timezone != "" {
		writeExtField(buf, extStart, "dtz", cf.timezone)
		reserved["dtz"] = struct{}{}
	}
	if cf.pidStr != "" {
		writeExtField(buf, extStart, "dvcpid", cf.pidStr)
		reserved["dvcpid"] = struct{}{}
	}
}

// CEF header / extension-value escape helpers (cefEscapeHeader,
// cefEscapeExtValue) and the extension-key validator (validateExtKey)
// are defined in format_cef_escape.go.

// writeExtField writes a key=value pair to the buffer. extStart is the
// buffer position where extensions begin (after the header); a space
// separator is added before each field except the first extension.
//
// Uses [writeEscapedExtValueString] for the value so pre-formatted
// string values from framework/header callers write in place without
// allocating an intermediate escaped string (#496).
//
// MUTATION-EQUIV(#571): the `b.Len() > extStart` boundary mutant
// (>= variant) is exempt because the unconditional `rt=` write at
// formatBuf line 334 makes b.Len() strictly greater than extStart at
// every call site. A future refactor that makes `rt=` optional must
// revisit MUTATION_TESTING.md.
func writeExtField(b *bytes.Buffer, extStart int, key, value string) {
	if b.Len() > extStart {
		b.WriteByte(' ')
	}
	b.WriteString(key)
	b.WriteByte('=')
	writeEscapedExtValueString(b, value)
}

// writeExtFieldInt64 writes a key=<decimal int64> pair directly into
// the buffer. Typed-parameter twin of [writeExtFieldValue] for the
// int64 hot-path case — calling writeExtFieldValue(b, k, x) with
// x int64 boxes x on the heap to satisfy the `any` parameter (one
// alloc per call); this helper skips the box entirely. The first
// consumer is the CEF `cn1`/duration branch in [CEFFormatter.formatBuf]
// (#663).
//
// Values are emitted via strconv.AppendInt into a 32-byte stack
// scratch (sized to hold any decimal int64 including sign). CEF
// decimal values require no escaping, so no escape pass is needed.
func writeExtFieldInt64(b *bytes.Buffer, extStart int, key string, v int64) {
	if b.Len() > extStart {
		b.WriteByte(' ')
	}
	b.WriteString(key)
	b.WriteByte('=')
	var scratch [32]byte
	b.Write(strconv.AppendInt(scratch[:0], v, 10))
}

// writeExtFieldValue writes a key=value pair to the buffer, converting
// v directly into the buffer via [appendFormatFieldValue] — no
// intermediate string, no per-field allocation for primitives (#496).
// Non-primitive fallback writes via [fmt.Fprintf] "%v", which still
// allocates but preserves today's CEF output byte-for-byte.
//
// Note: passing an int/int64/uint/float value here boxes the value
// on the heap to satisfy the `any` parameter. Use
// [writeExtFieldInt64] for the int64 hot path to avoid that alloc.
//
// MUTATION-EQUIV(#571): same exemption rationale as writeExtField —
// the unconditional `rt=` write at formatBuf line 334 makes
// b.Len() > extStart strictly true at every call site.
func writeExtFieldValue(b *bytes.Buffer, extStart int, key string, v any) {
	if b.Len() > extStart {
		b.WriteByte(' ')
	}
	b.WriteString(key)
	b.WriteByte('=')
	appendFormatFieldValue(b, v)
}

// writeEscapedExtValueString is the in-place analogue of
// [cefEscapeExtValue]: single-pass byte scanner that writes the
// escaped bytes directly into buf instead of building an intermediate
// string. Byte-for-byte equivalent to cefEscapeExtValue — any
// divergence would reopen the #477-class log-injection bug class.
//
// Escapes: '\\' -> "\\\\", '=' -> "\\=", '\n' -> "\\n" (two-char
// literal), '\r' -> "\\r" (two-char literal). Other C0 control bytes
// (0x00-0x1F) are stripped. All other bytes pass through unchanged.
// Operates on bytes, not runes — CEF is byte-oriented; invalid UTF-8
// passes through unchanged to match the legacy contract (#496).
func writeEscapedExtValueString(buf *bytes.Buffer, s string) {
	start := 0
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b >= 0x20 {
			switch b {
			case '\\':
				buf.WriteString(s[start:i])
				buf.WriteString(`\\`)
				start = i + 1
			case '=':
				buf.WriteString(s[start:i])
				buf.WriteString(`\=`)
				start = i + 1
			}
			continue
		}
		// C0 control character.
		buf.WriteString(s[start:i])
		switch b {
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		default:
			// Strip other control characters.
		}
		start = i + 1
	}
	if start == 0 {
		// Fast path: no escaping needed, single WriteString of the
		// entire input — matches cefEscapeExtValue's 0-alloc return.
		buf.WriteString(s)
		return
	}
	buf.WriteString(s[start:])
}

// appendFormatFieldValue writes the CEF extension-value representation
// of v directly into buf. Primitives take the zero-alloc path via
// strconv.Append* into a stack scratch (independent of buf's capacity
// — see loki/push.go:220 precedent). Strings route through the
// in-place escape writer. Non-primitives fall through to fmt.Fprintf
// which allocates but preserves today's byte-for-byte output (#496).
//
// nil writes nothing (matches legacy formatFieldValue's empty-string
// return, which yields "key=" with an empty value).
//
//nolint:gocyclo,cyclop // type switch; complexity is inherent
func appendFormatFieldValue(buf *bytes.Buffer, v any) {
	if v == nil {
		return
	}
	// Stack scratch for numeric conversions: sized for the largest
	// strconv.AppendX output (float64: up to 24 bytes for 'g' format;
	// int64/uint64: up to 20 bytes). 32 gives headroom for all cases.
	// Escape-analysis keeps this on the stack since the returned slice
	// is immediately written into buf and discarded.
	var scratch [32]byte
	switch val := v.(type) {
	case string:
		writeEscapedExtValueString(buf, val)
	case bool:
		buf.Write(strconv.AppendBool(scratch[:0], val))
	case int:
		buf.Write(strconv.AppendInt(scratch[:0], int64(val), 10))
	case int64:
		buf.Write(strconv.AppendInt(scratch[:0], val, 10))
	case int32:
		buf.Write(strconv.AppendInt(scratch[:0], int64(val), 10))
	case uint:
		buf.Write(strconv.AppendUint(scratch[:0], uint64(val), 10))
	case uint64:
		buf.Write(strconv.AppendUint(scratch[:0], val, 10))
	case float64:
		buf.Write(strconv.AppendFloat(scratch[:0], val, 'g', -1, 64))
	case float32:
		buf.Write(strconv.AppendFloat(scratch[:0], float64(val), 'g', -1, 32))
	case time.Duration:
		buf.Write(strconv.AppendInt(scratch[:0], val.Milliseconds(), 10))
	case time.Time:
		// Reuses the in-buffer append path. RFC3339 output is in the
		// escape-free character set, so no escape pass required.
		buf.Write(val.AppendFormat(scratch[:0], time.RFC3339))
	default:
		// Non-primitive fallback (#496). Only reachable when a consumer
		// bypasses generated builders and puts a slice/map/struct in
		// Fields (generated setters are typed — #575 tightens the
		// remaining "any" custom-field setters). MUST preserve the
		// legacy byte-for-byte semantics: fmt.Sprintf("%v", val) +
		// cefEscapeExtValue. Routing the %v output through the
		// in-place escape writer maintains the #477-class log-injection
		// defence for values containing "=", "\", "\n", or C0 bytes.
		// Costs one string allocation on this path (matches legacy),
		// which is acceptable because the path is rare and will
		// disappear entirely once #575 types custom-field setters.
		writeEscapedExtValueString(buf, fmt.Sprintf("%v", val))
	}
}

// mapFieldKey maps an audit field name to a CEF extension key using
// the provided mapping. If no mapping exists, the field name is used.
func mapFieldKey(fieldName string, mapping map[string]string) string {
	if ext, ok := mapping[fieldName]; ok {
		return ext
	}
	return fieldName
}
