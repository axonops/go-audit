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
	"strconv"
	"testing"
	"time"

	"pgregory.net/rapid"
)

// TestAppendPostFieldJSONInto_PropertyEqualsAppendPostFields is the
// rigorous byte-equality proof that the W2 in-place JSON post-field
// append produces output byte-identical to the legacy copy-out
// implementation. Per test-analyst prescription for #497.
//
// Rapid generates random JSON-formatted base events and random
// sequences of PostField values; the property asserts that applying
// appendPostFieldJSONInto N times to a buffer pre-loaded with base
// bytes produces byte-identical output to appendPostFieldsJSON.
//
// Failure mode if regressed: the in-place truncate/append/restore
// sequence subtly diverges from the copy-path's append-string ordering,
// causing JSON malformation that breaks every downstream verifier
// (HMAC, JSON parser).
func TestAppendPostFieldJSONInto_PropertyEqualsAppendPostFields(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		base := generateValidJSONBase(t)
		fields := generatePostFields(t)

		// Reference: legacy copy-path (allocates fresh).
		want := appendPostFieldsJSON(base, fields)

		// Subject: W2 in-place path applied sequentially.
		buf := new(bytes.Buffer)
		buf.Write(base)
		var got []byte
		for _, f := range fields {
			got = appendPostFieldJSONInto(buf, f)
		}
		if len(fields) == 0 {
			got = buf.Bytes()
		}

		if !bytes.Equal(want, got) {
			t.Fatalf("in-place output diverges from copy-path output\nbase  = %q\nfields= %#v\nwant  = %q\ngot   = %q",
				base, fields, want, got)
		}
	})
}

// TestAppendPostField_PublicAPI covers the exported single-field
// fast path so the public contract stays wired. The drain pipeline
// uses the unexported *Into variants; this test protects the
// published allocating path used by consumers who implement custom
// formatters.
func TestAppendPostField_PublicAPI(t *testing.T) {
	field := PostField{JSONKey: "event_category", CEFKey: "cat", Value: "write"}

	t.Run("json", func(t *testing.T) {
		base := []byte(`{"outcome":"success"}` + "\n")
		got := AppendPostField(base, &JSONFormatter{}, field)
		want := []byte(`{"outcome":"success","event_category":"write"}` + "\n")
		if !bytes.Equal(want, got) {
			t.Fatalf("AppendPostField JSON:\nwant=%q\ngot =%q", want, got)
		}
	})

	t.Run("cef", func(t *testing.T) {
		base := []byte("CEF:0|v|p|1|evt|name|0|\n")
		got := AppendPostField(base, &CEFFormatter{}, field)
		want := []byte("CEF:0|v|p|1|evt|name|0| cat=write\n")
		if !bytes.Equal(want, got) {
			t.Fatalf("AppendPostField CEF:\nwant=%q\ngot =%q", want, got)
		}
	})

	t.Run("unknown_formatter_returns_unchanged", func(t *testing.T) {
		base := []byte(`{"outcome":"success"}` + "\n")
		got := AppendPostField(base, noopFormatter{}, field)
		if !bytes.Equal(base, got) {
			t.Fatalf("unknown formatter must return data unchanged\nbase=%q\ngot =%q", base, got)
		}
	})

	t.Run("short_input_returns_unchanged", func(t *testing.T) {
		base := []byte("x")
		got := AppendPostField(base, &JSONFormatter{}, field)
		if !bytes.Equal(base, got) {
			t.Fatalf("short input must return data unchanged\nbase=%q\ngot =%q", base, got)
		}
	})
}

// noopFormatter is an Event formatter that is neither *JSONFormatter
// nor *CEFFormatter, used to exercise the AppendPostField default
// arm that returns input unchanged.
type noopFormatter struct{}

func (noopFormatter) Format(ts time.Time, eventType string, fields Fields, def *EventDef, opts *FormatOptions) ([]byte, error) {
	return nil, nil
}

func (noopFormatter) ContentType() string { return "application/x-ndjson" }

// TestAppendPostFieldsJSONInto_PropertyEqualsSequentialInPlace is
// the byte-equality proof for the #508 batch in-place JSON path.
// Rapid generates random JSON-formatted bases and random PostField
// sequences; the property asserts the batched single-call output
// matches the sequential N-call in-place output exactly.
//
// Failure mode if regressed: the batch truncate/append-N/restore
// sequence diverges from the N-call loop (e.g., wrong terminator
// position, field reordering, or missing separator), producing
// output that fails HMAC verification or JSON parsing.
func TestAppendPostFieldsJSONInto_PropertyEqualsSequentialInPlace(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		base := generateValidJSONBase(t)
		fields := generatePostFields(t)

		// Reference: N sequential appendPostFieldJSONInto calls.
		refBuf := new(bytes.Buffer)
		refBuf.Write(base)
		for _, f := range fields {
			appendPostFieldJSONInto(refBuf, f)
		}
		want := append([]byte(nil), refBuf.Bytes()...)

		// Subject: one appendPostFieldsJSONInto batch call.
		gotBuf := new(bytes.Buffer)
		gotBuf.Write(base)
		got := appendPostFieldsJSONInto(gotBuf, fields)

		if !bytes.Equal(want, got) {
			t.Fatalf("batch JSON in-place output diverges from sequential in-place output\nbase  = %q\nfields= %#v\nwant  = %q\ngot   = %q",
				base, fields, want, got)
		}
	})
}

// TestAppendPostFieldsCEFInto_PropertyEqualsSequentialInPlace is
// the CEF analogue of the JSON batch property. Guards against
// wire-format drift between the batch path and the existing
// sequential single-field path — #508.
func TestAppendPostFieldsCEFInto_PropertyEqualsSequentialInPlace(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		base := generateValidCEFBase(t)
		fields := generatePostFields(t)

		refBuf := new(bytes.Buffer)
		refBuf.Write(base)
		for _, f := range fields {
			appendPostFieldCEFInto(refBuf, f)
		}
		want := append([]byte(nil), refBuf.Bytes()...)

		gotBuf := new(bytes.Buffer)
		gotBuf.Write(base)
		got := appendPostFieldsCEFInto(gotBuf, fields)

		if !bytes.Equal(want, got) {
			t.Fatalf("batch CEF in-place output diverges from sequential in-place output\nbase  = %q\nfields= %#v\nwant  = %q\ngot   = %q",
				base, fields, want, got)
		}
	})
}

// TestAppendPostFieldsInto_MalformedBase pins the all-or-none
// guard behaviour: when the buffer lacks the expected terminator
// (}\n for JSON, \n for CEF), the function MUST return without
// appending any field. A partial append would produce malformed
// wire bytes that downstream HMAC verification or parsers would
// reject — #508 security-reviewer note on the all-or-none contract.
func TestAppendPostFieldsInto_MalformedBase(t *testing.T) {
	fields := []PostField{
		{JSONKey: "event_category", CEFKey: "cat", Value: "write"},
		{JSONKey: "_hmac_version", CEFKey: "_hmacVersion", Value: "v1"},
	}

	cases := []struct {
		name      string
		formatter Formatter
		base      string
	}{
		{"json_empty", &JSONFormatter{}, ""},
		{"json_one_byte", &JSONFormatter{}, "x"},
		{"json_missing_newline", &JSONFormatter{}, "{}"},
		{"json_missing_brace", &JSONFormatter{}, "]\n"},
		{"cef_empty", &CEFFormatter{}, ""},
		{"cef_missing_newline", &CEFFormatter{}, "CEF:0|v|p|1|e|n|0|"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			buf := new(bytes.Buffer)
			buf.WriteString(tc.base)
			before := append([]byte(nil), buf.Bytes()...)

			got := appendPostFieldsInto(buf, tc.formatter, fields)

			if !bytes.Equal(before, got) {
				t.Fatalf("malformed base must be returned unchanged\nbefore=%q\nafter =%q",
					before, got)
			}
			if !bytes.Equal(before, buf.Bytes()) {
				t.Fatalf("buffer must not be partially mutated on malformed base\nbefore=%q\nbuffer=%q",
					before, buf.Bytes())
			}
		})
	}
}

// TestAppendPostFieldsInto_EmptyFields pins the documented contract
// that an empty fields slice returns buf.Bytes() unchanged and does
// not touch the buffer. Defensive regression guard for #508.
func TestAppendPostFieldsInto_EmptyFields(t *testing.T) {
	base := []byte(`{"outcome":"success"}` + "\n")
	buf := new(bytes.Buffer)
	buf.Write(base)

	got := appendPostFieldsInto(buf, &JSONFormatter{}, nil)

	if !bytes.Equal(base, got) {
		t.Fatalf("empty fields must return base unchanged\nwant=%q\ngot =%q", base, got)
	}
	if !bytes.Equal(base, buf.Bytes()) {
		t.Fatalf("empty fields must not touch buffer\nwant=%q\nbuf =%q", base, buf.Bytes())
	}
}

// TestAppendPostFieldCEFInto_PropertyEqualsAppendPostFields is the
// CEF analogue of the JSON property. CEF terminates with \n only (no
// brace), so the truncate-and-restore semantics differ — both
// implementations must agree byte-for-byte on every base + field combo.
func TestAppendPostFieldCEFInto_PropertyEqualsAppendPostFields(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		base := generateValidCEFBase(t)
		fields := generatePostFields(t)

		want := appendPostFieldsCEF(base, fields)

		buf := new(bytes.Buffer)
		buf.Write(base)
		var got []byte
		for _, f := range fields {
			got = appendPostFieldCEFInto(buf, f)
		}
		if len(fields) == 0 {
			got = buf.Bytes()
		}

		if !bytes.Equal(want, got) {
			t.Fatalf("in-place CEF output diverges from copy-path output\nbase  = %q\nfields= %#v\nwant  = %q\ngot   = %q",
				base, fields, want, got)
		}
	})
}

// generateValidJSONBase produces a JSON-formatted event terminated
// with "}\n", matching the contract appendPostFieldJSONInto / Json
// expects. Generated via the actual JSONFormatter so the bytes are
// guaranteed valid.
func generateValidJSONBase(t *rapid.T) []byte {
	jf := &JSONFormatter{}
	def := &EventDef{
		Required: []string{"outcome"},
		Optional: []string{"actor_id", "marker"},
	}
	def.knownFields = make(map[string]struct{}, 3)
	for _, k := range def.Required {
		def.knownFields[k] = struct{}{}
	}
	for _, k := range def.Optional {
		def.knownFields[k] = struct{}{}
	}
	def.sortedRequired = append([]string{}, def.Required...)
	def.sortedOptional = append([]string{}, def.Optional...)
	def.sortedAllKeys = []string{"actor_id", "marker", "outcome"}

	fields := Fields{
		"outcome": rapid.SampledFrom([]string{"success", "failure", "error"}).Draw(t, "outcome"),
	}
	if rapid.Bool().Draw(t, "withActor") {
		fields["actor_id"] = rapid.StringMatching("[a-zA-Z][a-zA-Z0-9_]{0,15}").Draw(t, "actor_id")
	}
	if rapid.Bool().Draw(t, "withMarker") {
		fields["marker"] = rapid.StringN(1, 32, 32).Draw(t, "marker")
	}

	out, err := jf.Format(time.Unix(1700000000, 0).UTC(), "test_event", fields, def, nil)
	if err != nil {
		t.Fatalf("JSON base generation: %v", err)
	}
	return out
}

// generateValidCEFBase produces a CEF-formatted event terminated with
// "\n" via the actual CEFFormatter.
func generateValidCEFBase(t *rapid.T) []byte {
	cf := &CEFFormatter{
		Vendor:  "axonops",
		Product: "audit",
		Version: "1.0",
	}
	def := &EventDef{
		Required: []string{"outcome"},
		Optional: []string{"actor_id", "marker"},
	}
	def.knownFields = make(map[string]struct{}, 3)
	for _, k := range def.Required {
		def.knownFields[k] = struct{}{}
	}
	for _, k := range def.Optional {
		def.knownFields[k] = struct{}{}
	}
	def.sortedRequired = append([]string{}, def.Required...)
	def.sortedOptional = append([]string{}, def.Optional...)
	def.sortedAllKeys = []string{"actor_id", "marker", "outcome"}

	fields := Fields{
		"outcome": rapid.SampledFrom([]string{"success", "failure", "error"}).Draw(t, "outcome"),
	}
	if rapid.Bool().Draw(t, "withActor") {
		fields["actor_id"] = rapid.StringMatching("[a-zA-Z][a-zA-Z0-9_]{0,15}").Draw(t, "actor_id")
	}
	if rapid.Bool().Draw(t, "withMarker") {
		fields["marker"] = rapid.StringN(1, 32, 32).Draw(t, "marker")
	}

	out, err := cf.Format(time.Unix(1700000000, 0).UTC(), "test_event", fields, def, nil)
	if err != nil {
		t.Fatalf("CEF base generation: %v", err)
	}
	return out
}

// generatePostFields produces 0..5 PostField values with keys drawn
// from a safe charset (matching SaltVersion validation: alphanumeric
// + ._:-) and values that are valid UTF-8 strings.
func generatePostFields(t *rapid.T) []PostField {
	n := rapid.IntRange(0, 5).Draw(t, "fieldCount")
	fields := make([]PostField, n)
	keyGen := rapid.StringMatching(`[A-Za-z][A-Za-z0-9._:\-]{0,15}`)
	valGen := rapid.StringN(0, 64, 64)
	for i := range fields {
		fields[i] = PostField{
			JSONKey: keyGen.Draw(t, "jsonKey"),
			CEFKey:  keyGen.Draw(t, "cefKey"),
			Value:   valGen.Draw(t, "value"),
		}
	}
	return fields
}

// TestWriteEscapedExtValueString_PropertyEqualsCEFEscape proves byte-for-
// byte equivalence between the in-place writeEscapedExtValueString and
// the legacy cefEscapeExtValue across hostile byte inputs — NUL, CRLF,
// pipes, equals, invalid UTF-8, overlong encodings, combining bytes. A
// divergence here reopens the #477-class log-injection bug. Uses
// rapid.StringOf(rapid.Byte()) to generate raw byte strings (not valid-
// UTF-8 strings), mirroring the security-reviewer ask for #496.
func TestWriteEscapedExtValueString_PropertyEqualsCEFEscape(t *testing.T) {
	// Adversarial seeds: verify these specific inputs regardless of what
	// rapid's shrinker chooses. Each encodes a class of failure mode.
	seeds := []string{
		"",            // empty — must produce empty output
		"\x00",        // NUL
		"a=b",         // unescaped =
		`\=`,          // escape + equals
		"=\n",         // equals then newline
		"\r\n",        // CRLF
		`\` + "\n",    // backslash then newline
		"\xff\xfe",    // invalid UTF-8 (BOM bytes)
		"\xc0\x80",    // overlong-encoded NUL
		"a\x00\nb=c",  // mixed controls + escapes
		"hello world", // clean
		"\\\\",        // multiple escapes
	}
	for _, s := range seeds {
		want := cefEscapeExtValue(s)
		var buf bytes.Buffer
		writeEscapedExtValueString(&buf, s)
		if got := buf.String(); got != want {
			t.Fatalf("seed divergence for %q:\n  want=%q\n  got =%q", s, want, got)
		}
	}

	rapid.Check(t, func(t *rapid.T) {
		// Generate raw byte strings (not rapid.String() which is UTF-8 only)
		// so invalid UTF-8 is part of the corpus.
		bs := rapid.SliceOfN(rapid.Byte(), 0, 256).Draw(t, "rawBytes")
		s := string(bs)

		want := cefEscapeExtValue(s)

		var buf bytes.Buffer
		writeEscapedExtValueString(&buf, s)
		got := buf.String()

		if got != want {
			t.Fatalf("rapid divergence for %q (bytes=%v):\n  want=%q\n  got =%q",
				s, bs, want, got)
		}
	})
}

// TestAppendFormatFieldValue_ByteEquivalentToLegacy proves the new in-
// place appendFormatFieldValue produces byte-identical output to the
// legacy cefEscapeExtValue(formatFieldValue(v)) path across every
// supported primitive type plus nil. Defends AC 3 of #496 (output bytes
// unchanged).
//
//nolint:cyclop // table-driven type switch; complexity is inherent to the test fixture
func TestAppendFormatFieldValue_ByteEquivalentToLegacy(t *testing.T) {
	// Replicate the deleted formatFieldValue's logic locally so we can
	// compare against it. If this helper ever drifts from the shipped
	// appendFormatFieldValue semantics, the test fails loudly.
	legacyFormatFieldValue := func(v any) string {
		if v == nil {
			return ""
		}
		switch val := v.(type) {
		case string:
			return val
		case bool:
			if val {
				return "true"
			}
			return "false"
		case int:
			return fmtInt(int64(val))
		case int64:
			return fmtInt(val)
		case int32:
			return fmtInt(int64(val))
		case uint:
			return fmtUint(uint64(val))
		case uint64:
			return fmtUint(val)
		case float64:
			return fmtFloat(val, 64)
		case float32:
			return fmtFloat(float64(val), 32)
		case time.Duration:
			return fmtInt(val.Milliseconds())
		case time.Time:
			return val.Format(time.RFC3339)
		default:
			return fmt.Sprintf("%v", val)
		}
	}

	cases := []struct { //nolint:govet // fieldalignment: readability over packing for a test fixture
		name string
		v    any
	}{
		{"nil", nil},
		{"empty_string", ""},
		{"string_clean", "hello"},
		{"string_with_eq", "a=b"},
		{"string_with_backslash", `a\b`},
		{"string_with_newline", "a\nb"},
		{"string_with_control", "a\x01b"},
		{"bool_true", true},
		{"bool_false", false},
		{"int_zero", int(0)},
		{"int_neg", int(-42)},
		{"int64_max", int64(9223372036854775807)},
		{"int32_neg", int32(-1)},
		{"uint_zero", uint(0)},
		{"uint64_max", uint64(18446744073709551615)},
		{"float64_pi", float64(3.14159)},
		{"float64_neg", float64(-1.5)},
		{"float32_pi", float32(3.14)},
		{"duration_1s", time.Second},
		{"duration_zero", time.Duration(0)},
		{"time_zero", time.Time{}},
		{"time_unix", time.Unix(1700000000, 0).UTC()},
		// Non-primitive fallback — MUST route through the escape writer
		// so values containing CEF metacharacters cannot forge extension
		// fragments (#496 + #477-class log-injection defence).
		{"slice_clean", []string{"a", "b"}},
		{"slice_with_eq", []string{"a=b", "c"}},
		{"slice_with_newline", []string{"a\nb"}},
		{"slice_with_backslash", []string{`a\b`}},
		{"map_with_eq", map[string]string{"k": "v=x"}},
		{"map_with_injection", map[string]string{"k": "v\nCEF:0|x|x|1|x|x|1|"}},
		{"struct_with_backslash", struct{ X string }{X: `a\b`}},
		{"struct_with_newline", struct{ X string }{X: "a\nb"}},
		{"pointer_with_eq", &struct{ X string }{X: "a=b"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want := cefEscapeExtValue(legacyFormatFieldValue(tc.v))

			var buf bytes.Buffer
			appendFormatFieldValue(&buf, tc.v)
			got := buf.String()

			if got != want {
				t.Fatalf("v=%#v (%T):\n  want=%q\n  got =%q", tc.v, tc.v, want, got)
			}
		})
	}
}

// fmtInt / fmtUint / fmtFloat mirror strconv's formatters used by the
// legacy formatFieldValue. Kept local so this test remains immune to
// any future strconv changes.
func fmtInt(v int64) string                  { return strconv.FormatInt(v, 10) }
func fmtUint(v uint64) string                { return strconv.FormatUint(v, 10) }
func fmtFloat(v float64, bitSize int) string { return strconv.FormatFloat(v, 'g', -1, bitSize) }
