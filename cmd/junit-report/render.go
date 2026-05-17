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

// This file is BYTE-IDENTICAL with cmd/junit-report/render.go.
// `make check-report-parity` enforces this — change one, change both.
// The shared escape helpers are security-critical; any divergence
// risks a Markdown or HTML injection in one tool but not the other.

package main

import (
	"html"
	"strings"
)

// stepSummaryByteBudget approximates the GitHub Actions step summary
// hard cap. Anything beyond 1 MiB is silently truncated by GitHub.
// We reserve a small margin so the truncation footer always fits.
const stepSummaryByteBudget = 1024*1024 - 4096

// mdSpecial lists the GFM metacharacters escaped by escapeMarkdown.
// `~` is included for strikethrough; `=` for setext underline at line
// start (escaped unconditionally for simplicity).
const mdSpecial = "\\`*_{}[]()#+-.!|<>~="

// sanitiseLine replaces CR/LF and C0 control characters in s with a
// single space, collapsing consecutive control characters into one
// space. Intra-name runs of real spaces are preserved. Applied before
// either escaper so newline-based injection (mid-summary header
// insertion, premature </details>, list-item smuggling) is impossible.
func sanitiseLine(s string) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s))
	prevSpace := false
	for _, r := range s {
		switch {
		case r == '\t', r == '\n', r == '\r', r < 0x20, r == 0x7F:
			if !prevSpace {
				b.WriteByte(' ')
				prevSpace = true
			}
		default:
			b.WriteRune(r)
			prevSpace = false
		}
	}
	return strings.TrimSpace(b.String())
}

// escapeMarkdown escapes every GFM metacharacter in s with a leading
// backslash. Assumes s has already passed through sanitiseLine (no
// CR/LF, no C0 controls).
func escapeMarkdown(s string) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s) + len(s)/4)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x80 && strings.IndexByte(mdSpecial, c) >= 0 {
			b.WriteByte('\\')
		}
		b.WriteByte(c)
	}
	return b.String()
}

// escapeHTMLAttr escapes the five HTML metacharacters. Used for content
// inside <summary>...</summary> where GFM treats the body as HTML.
func escapeHTMLAttr(s string) string {
	return html.EscapeString(s)
}

// fenceForError returns a backtick fence longer than any run of
// backticks in s. Minimum length is 3 — CommonMark's shortest fence.
// Required so a fenced code block whose body itself contains backticks
// closes at the right place.
func fenceForError(s string) string {
	longest, cur := 0, 0
	for i := 0; i < len(s); i++ {
		if s[i] == '`' {
			cur++
			if cur > longest {
				longest = cur
			}
		} else {
			cur = 0
		}
	}
	n := longest + 1
	if n < 3 {
		n = 3
	}
	return strings.Repeat("`", n)
}
