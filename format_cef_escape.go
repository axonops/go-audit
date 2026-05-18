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

// CEF escape helpers and extension-key validation. Split out of
// format_cef.go (#540). The string-returning escape functions
// (cefEscapeHeader, cefEscapeExtValue) are called from formatBuf;
// the in-place version writeEscapedExtValueString stays in
// format_cef.go because it is tightly coupled to
// appendFormatFieldValue.

import (
	"fmt"
	"strings"
)

// cefEscapeHeader escapes characters in CEF header fields using a
// single-pass byte scanner. Escapes: \ -> \\, | -> \|, \n -> space,
// \r -> space. Returns the original string unchanged when no escaping
// is needed, avoiding allocation on the common path.
func cefEscapeHeader(s string) string {
	var buf strings.Builder
	start := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			buf.WriteString(s[start:i])
			buf.WriteString(`\\`)
			start = i + 1
		case '|':
			buf.WriteString(s[start:i])
			buf.WriteString(`\|`)
			start = i + 1
		case '\n', '\r':
			buf.WriteString(s[start:i])
			buf.WriteByte(' ')
			start = i + 1
		}
	}
	if start == 0 {
		return s // no escaping needed; return original string (0 allocs)
	}
	buf.WriteString(s[start:])
	return buf.String()
}

// cefEscapeExtValue escapes characters in CEF extension values using a
// single-pass byte scanner. Escapes: \ -> \\, = -> \=, \n -> \n
// (literal backslash-n), \r -> \r (literal backslash-r). Remaining C0
// control characters (0x00-0x1F) are stripped.
func cefEscapeExtValue(s string) string {
	var buf strings.Builder
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
		return s // no escaping needed; return original string (0 allocs)
	}
	buf.WriteString(s[start:])
	return buf.String()
}

// validateExtKey returns an error if the key is not a valid CEF
// extension key name (must match `[a-zA-Z0-9_]+`). Called once per
// CEFFormatter from [fieldMapping]'s resolveOnce — never on the
// per-event hot path (#477).
func validateExtKey(key string) error {
	// Caller (fieldMapping.resolveOnce) prepends "audit: cef field
	// mapping key %q: " so the user sees the offending key in
	// context. Don't double-prefix here.
	if key == "" {
		return fmt.Errorf("must be non-empty and match [a-zA-Z0-9_]+")
	}
	for _, c := range key {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '_' {
			return fmt.Errorf("must match [a-zA-Z0-9_]+")
		}
	}
	return nil
}
