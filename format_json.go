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
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"time"
	"unicode/utf8"
)

// jsonBufPool caches bytes.Buffer instances for JSONFormatter.Format
// to avoid per-call heap allocation of the output buffer. Buffers are
// Reset on retrieval from the pool (before each Format call) to ensure
// a clean slate. The pooled buffer's internal byte slice grows to the
// typical output size and is reused across calls, eliminating repeated
// growth allocations.
//
// Outlier buffers (cap > maxPooledBufCap) are dropped on Put rather
// than re-pooled, to bound pool memory under pathological event sizes.
// On Put, the buffer's backing array is zeroed across [0:cap] to
// defend against future read-past-len bugs that could leak prior-event
// content (see security review of #497).
var jsonBufPool = sync.Pool{
	New: func() any { return new(bytes.Buffer) },
}

// maxPooledBufCap caps the buffer capacity that the format buffer
// pools will accept on Put. Larger buffers are dropped (let GC
// reclaim) to prevent a single oversized event pinning megabytes of
// pool memory until the next GC cycle.
const maxPooledBufCap = 64 * 1024

// putJSONBuf returns buf to [jsonBufPool] with defensive zeroing and
// outlier rejection. Centralised so every Put site enforces the same
// invariants.
func putJSONBuf(buf *bytes.Buffer) {
	if buf == nil || buf.Cap() > maxPooledBufCap {
		return
	}
	// Reset first (off=0, len=0) then zero the full backing array via
	// b[:cap(b)] so future read-past-len bugs cannot leak prior-event
	// content. cost: ~40 ns for a 4 KiB buffer.
	buf.Reset()
	b := buf.Bytes()
	clear(b[:cap(b)])
	jsonBufPool.Put(buf)
}

// JSONFormatter serialises audit events as line-delimited JSON.
//
// Fields are emitted in deterministic order: framework fields first
// (timestamp, event_type, severity, duration_ms if present as
// [time.Duration]), then required fields (sorted), then optional fields
// (sorted), then any extra fields (sorted). Each event is terminated
// by a newline.
//
// [time.Duration] values are converted to int64 milliseconds.
// Timestamps are rendered according to [JSONFormatter.Timestamp]
// (default [TimestampRFC3339Nano]).
//
// # Concurrency
//
// Safe for concurrent use by multiple goroutines, per the
// [Formatter] contract. All per-call buffers are leased from a
// package-level [sync.Pool]; the struct itself holds only
// write-once configuration set at construction.
type JSONFormatter struct {
	// Timestamp controls the timestamp format. Empty defaults to
	// [TimestampRFC3339Nano].
	Timestamp TimestampFormat

	// Framework fields set once via SetFrameworkFields.
	appName  string
	host     string
	timezone string
	pid      int

	// OmitEmpty controls whether zero-value fields are omitted.
	OmitEmpty bool
}

// ContentType implements [Formatter.ContentType]. JSONFormatter emits
// newline-delimited JSON; the MIME type "application/x-ndjson" is
// the [NDJSON spec](https://github.com/ndjson/ndjson-spec) convention
// and is accepted by every webhook receiver that supports streaming
// JSON.
func (jf *JSONFormatter) ContentType() string { return "application/x-ndjson" }

// Format serialises a single audit event as a JSON line. The returned
// slice is owned by the caller (defensive copy from the pooled buffer).
//
// Internal callers in the drain pipeline use [JSONFormatter.formatBuf]
// to obtain the leased buffer directly and skip the copy.
func (jf *JSONFormatter) Format(ts time.Time, eventType string, fields Fields, def *EventDef, opts *FormatOptions) ([]byte, error) {
	buf, err := jf.formatBuf(ts, eventType, fields, def, opts)
	if err != nil {
		return nil, err
	}
	out := make([]byte, buf.Len())
	copy(out, buf.Bytes())
	jf.releaseFormatBuf(buf)
	return out, nil
}

// formatBuf serialises an event into a pool-leased *bytes.Buffer.
// Callers MUST return the buffer via [JSONFormatter.releaseFormatBuf].
func (jf *JSONFormatter) formatBuf(ts time.Time, eventType string, fields Fields, def *EventDef, opts *FormatOptions) (*bytes.Buffer, error) {
	buf, ok := jsonBufPool.Get().(*bytes.Buffer)
	if !ok {
		buf = new(bytes.Buffer)
	}
	buf.Reset()
	buf.WriteByte('{')

	enc := &jsonEncoder{buf: buf, omitEmpty: jf.OmitEmpty}

	// Framework fields first.
	enc.writeTimestamp(ts, jf.tsFormat())
	enc.writeStringField("event_type", eventType)
	enc.writeInt64Field("severity", int64(def.ResolvedSeverity()))
	jf.writeDuration(enc, fields)
	jf.writeFrameworkFields(enc)

	// Required fields (sorted). Uses pre-sorted slice when available;
	// pooled when filtering forces a copy.
	reqKeys, reqOwned := sortedFieldKeys(def.sortedRequired, def.Required, fields, jf.OmitEmpty)
	for _, k := range reqKeys {
		if opts.IsExcluded(k) {
			continue
		}
		enc.writeField(k, fields[k])
	}
	putSortedKeysSlice(reqOwned)

	// Optional fields (sorted).
	optKeys, optOwned := sortedFieldKeys(def.sortedOptional, def.Optional, fields, jf.OmitEmpty)
	for _, k := range optKeys {
		if opts.IsExcluded(k) {
			continue
		}
		enc.writeField(k, fields[k])
	}
	putSortedKeysSlice(optOwned)

	// Extra fields not in required or optional (sorted).
	exKeys, exOwned := extraFieldKeys(def, fields, jf.OmitEmpty)
	for _, k := range exKeys {
		if opts.IsExcluded(k) {
			continue
		}
		enc.writeField(k, fields[k])
	}
	putSortedKeysSlice(exOwned)

	buf.WriteByte('}')
	buf.WriteByte('\n')

	if enc.err != nil {
		putJSONBuf(buf)
		return nil, fmt.Errorf("audit: json format: %w", enc.err)
	}
	return buf, nil
}

// releaseFormatBuf returns buf to [jsonBufPool], applying the same
// outlier-rejection and zeroing rules as [putJSONBuf].
func (*JSONFormatter) releaseFormatBuf(buf *bytes.Buffer) { putJSONBuf(buf) }

func (jf *JSONFormatter) tsFormat() TimestampFormat {
	if jf.Timestamp == "" {
		return TimestampRFC3339Nano
	}
	return jf.Timestamp
}

// writeDuration writes duration_ms as an int64 if the value is a
// [time.Duration]. Non-Duration values for duration_ms are handled as
// regular fields through the normal field path.
func (jf *JSONFormatter) writeDuration(enc *jsonEncoder, fields Fields) {
	if v, ok := fields["duration_ms"]; ok {
		if d, ok := v.(time.Duration); ok {
			enc.writeInt64Field("duration_ms", d.Milliseconds())
		}
	}
}

// SetFrameworkFields stores auditor-wide framework metadata for
// emission in every JSON event. Called once at construction time.
func (jf *JSONFormatter) SetFrameworkFields(appName, host, timezone string, pid int) {
	jf.appName = appName
	jf.host = host
	jf.timezone = timezone
	jf.pid = pid
}

// writeFrameworkFields writes app_name, host, timezone, and pid if set.
func (jf *JSONFormatter) writeFrameworkFields(enc *jsonEncoder) {
	if jf.appName != "" {
		enc.writeStringField("app_name", jf.appName)
	}
	if jf.host != "" {
		enc.writeStringField("host", jf.host)
	}
	if jf.timezone != "" {
		enc.writeStringField("timezone", jf.timezone)
	}
	if jf.pid > 0 {
		enc.writeInt64Field("pid", int64(jf.pid))
	}
}

// jsonEncoder writes JSON key-value pairs to a buffer with comma
// separation. It tracks the first error encountered.
type jsonEncoder struct {
	buf       *bytes.Buffer
	err       error
	omitEmpty bool
	hasFields bool // true after the first field is written
}

func (e *jsonEncoder) writeComma() {
	if e.hasFields {
		e.buf.WriteByte(',')
	}
	e.hasFields = true
}

func (e *jsonEncoder) writeTimestamp(ts time.Time, format TimestampFormat) {
	e.writeComma()
	e.buf.WriteString(`"timestamp":`)
	//nolint:exhaustive // unrecognised TimestampFormat values fall back to RFC3339Nano
	switch format {
	case TimestampUnixMillis:
		e.buf.WriteString(strconv.FormatInt(ts.UnixMilli(), 10))
	default:
		// RFC3339Nano timestamps contain only ASCII characters safe in
		// JSON (digits, colons, dashes, T, Z, dot, plus). Write between
		// quotes without escaping, using AvailableBuffer to avoid a
		// string allocation from ts.Format().
		e.buf.WriteByte('"')
		b := ts.AppendFormat(e.buf.AvailableBuffer(), time.RFC3339Nano)
		_, _ = e.buf.Write(b)
		e.buf.WriteByte('"')
	}
}

func (e *jsonEncoder) writeStringField(key, value string) {
	e.writeComma()
	e.writeKey(key)
	WriteJSONString(e.buf, value)
}

func (e *jsonEncoder) writeInt64Field(key string, value int64) {
	e.writeComma()
	e.writeKey(key)
	b := strconv.AppendInt(e.buf.AvailableBuffer(), value, 10)
	_, _ = e.buf.Write(b)
}

func (e *jsonEncoder) writeKey(key string) {
	WriteJSONString(e.buf, key)
	e.buf.WriteByte(':')
}

//nolint:cyclop,gocyclo // flat type switch over common field types; linear, not true complexity
func (e *jsonEncoder) writeField(key string, value any) {
	if e.omitEmpty && isZeroValue(value) {
		return
	}

	// Convert time.Duration to int64 milliseconds.
	if d, ok := value.(time.Duration); ok {
		e.writeInt64Field(key, d.Milliseconds())
		return
	}

	e.writeComma()
	e.writeKey(key)
	switch v := value.(type) {
	case string:
		WriteJSONString(e.buf, v)
	case int:
		b := strconv.AppendInt(e.buf.AvailableBuffer(), int64(v), 10)
		_, _ = e.buf.Write(b)
	case int64:
		b := strconv.AppendInt(e.buf.AvailableBuffer(), v, 10)
		_, _ = e.buf.Write(b)
	case int32:
		b := strconv.AppendInt(e.buf.AvailableBuffer(), int64(v), 10)
		_, _ = e.buf.Write(b)
	case float64:
		// Fallback to json.Marshal for exact format matching.
		data, err := json.Marshal(v)
		if err != nil && e.err == nil {
			e.err = err
		}
		e.buf.Write(data)
	case bool:
		e.buf.WriteString(strconv.FormatBool(v))
	case nil:
		e.buf.WriteString("null")
	default:
		// Fallback: json.Marshal for unknown types.
		data, err := json.Marshal(v)
		if err != nil && e.err == nil {
			e.err = err
		}
		e.buf.Write(data)
	}
}

// WriteJSONString writes the JSON-encoded form of s directly to buf,
// producing byte-for-byte identical output to [encoding/json.Marshal]
// for string values. This includes HTML-safe escaping of <, >, and &,
// and JavaScript-safe escaping of U+2028/U+2029 line/paragraph
// separators. Invalid UTF-8 is replaced with \ufffd.
//
// Writing directly to the buffer eliminates the per-call allocation
// that json.Marshal incurs for its return value.
//
// WriteJSONString is exported for use by output modules (e.g. loki)
// that construct JSON payloads and need allocation-free string escaping.
//
//nolint:gocyclo,cyclop // single-pass byte scanner; complexity is inherent in JSON escaping rules
func WriteJSONString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	start := 0
	for i := 0; i < len(s); {
		b := s[i]
		if b >= utf8.RuneSelf {
			var size int
			start, size = writeJSONMultibyte(buf, s, i, start)
			i += size
			continue
		}
		if jsonSafeASCII[b] {
			i++
			continue
		}
		buf.WriteString(s[start:i])
		switch b {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			// Remaining control chars (0x00-0x1F) and HTML-special (<, >, &).
			buf.WriteString(`\u00`)
			buf.WriteByte(hexDigits[b>>4])
			buf.WriteByte(hexDigits[b&0xf])
		}
		i++
		start = i
	}
	buf.WriteString(s[start:])
	buf.WriteByte('"')
}

// WriteJSONBytes is the []byte-input counterpart to [WriteJSONString].
// Used by output backends (notably loki) that accumulate pre-serialised
// event lines as []byte and need to embed them as JSON string values
// on the wire. Avoiding the `string(b)` conversion at the call site
// eliminates one heap allocation per event on the drain hot path
// (#494/#495).
//
// Behaviour is identical to WriteJSONString — the input is treated as
// UTF-8 bytes, escaped per RFC 7159, and emitted surrounded by double
// quotes. Multibyte sequences are preserved; ASCII control bytes and
// the JSON metacharacters (`"`, `\`, `<`, `>`, `&`) are \uXXXX /
// backslash-escaped.
//
//nolint:gocyclo,cyclop // mirrors WriteJSONString — splitting would duplicate the jump table with no benefit
func WriteJSONBytes(buf *bytes.Buffer, b []byte) {
	buf.WriteByte('"')
	start := 0
	for i := 0; i < len(b); {
		c := b[i]
		if c >= utf8.RuneSelf {
			var size int
			start, size = writeJSONMultibyteBytes(buf, b, i, start)
			i += size
			continue
		}
		if jsonSafeASCII[c] {
			i++
			continue
		}
		buf.Write(b[start:i])
		switch c {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			buf.WriteString(`\u00`)
			buf.WriteByte(hexDigits[c>>4])
			buf.WriteByte(hexDigits[c&0xf])
		}
		i++
		start = i
	}
	buf.Write(b[start:])
	buf.WriteByte('"')
}

// writeJSONMultibyte handles multi-byte UTF-8 sequences in
// [WriteJSONString]. Returns the updated start position and the rune
// size in bytes (avoiding a redundant DecodeRuneInString in the caller).
func writeJSONMultibyte(buf *bytes.Buffer, s string, i, start int) (newStart, size int) {
	r, size := utf8.DecodeRuneInString(s[i:])
	switch {
	case r == utf8.RuneError && size == 1:
		buf.WriteString(s[start:i])
		buf.WriteString(`\ufffd`)
		return i + size, size
	case r == '\u2028':
		buf.WriteString(s[start:i])
		buf.WriteString(`\u2028`)
		return i + size, size
	case r == '\u2029':
		buf.WriteString(s[start:i])
		buf.WriteString(`\u2029`)
		return i + size, size
	default:
		return start, size // no escape needed; continue accumulating
	}
}

// writeJSONMultibyteBytes is the []byte-input counterpart to
// [writeJSONMultibyte] for [WriteJSONBytes].
func writeJSONMultibyteBytes(buf *bytes.Buffer, b []byte, i, start int) (newStart, size int) {
	r, size := utf8.DecodeRune(b[i:])
	switch {
	case r == utf8.RuneError && size == 1:
		buf.Write(b[start:i])
		buf.WriteString(`\ufffd`)
		return i + size, size
	case r == '\u2028':
		buf.Write(b[start:i])
		buf.WriteString(`\u2028`)
		return i + size, size
	case r == '\u2029':
		buf.Write(b[start:i])
		buf.WriteString(`\u2029`)
		return i + size, size
	default:
		return start, size
	}
}

const hexDigits = "0123456789abcdef"

// jsonSafeASCII marks ASCII bytes safe to pass through [WriteJSONString]
// without escaping. Bytes with false entries need escaping.
var jsonSafeASCII = func() [256]bool {
	var t [256]bool
	for i := 0x20; i < utf8.RuneSelf; i++ {
		t[i] = true
	}
	t['"'] = false
	t['\\'] = false
	t['<'] = false // HTML-safe escaping (matches json.Marshal)
	t['>'] = false
	t['&'] = false
	return t
}()
