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

package splunk

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestParseRetryAfter covers every documented format and edge case
// for the Retry-After header. Server-controlled DoS is the primary
// concern — a malicious or misbehaving HEC must not be able to
// stall the output for arbitrary durations via a crafted header.
func TestParseRetryAfter(t *testing.T) { //nolint:funlen // table-driven enumeration
	now := time.Now()
	tests := []struct {
		name   string
		input  string
		check  func(t *testing.T, got time.Duration)
		expect time.Duration // when 0, use check; when non-zero, exact equal (±1s tolerance for HTTP-date)
	}{
		{
			name:   "empty header — no delay",
			input:  "",
			expect: 0,
		},
		{
			name:   "integer seconds — honoured",
			input:  "10",
			expect: 10 * time.Second,
		},
		{
			name:   "zero — no delay",
			input:  "0",
			expect: 0,
		},
		{
			name:   "negative — no delay (fall back to backoff)",
			input:  "-5",
			expect: 0,
		},
		{
			name:   "non-numeric — fall back to backoff",
			input:  "banana",
			expect: 0,
		},
		{
			name:   "value exceeds maxRetryAfter — capped",
			input:  "999999", // 277h
			expect: maxRetryAfter,
		},
		{
			name:  "HTTP-date in the future — honoured",
			input: now.Add(30 * time.Second).UTC().Format(time.RFC1123),
			check: func(t *testing.T, got time.Duration) {
				// Allow 1s wiggle for the time.Until() call drift.
				assert.InDelta(t, 30*time.Second, got, float64(2*time.Second))
			},
		},
		{
			name:   "HTTP-date in the past — no delay",
			input:  now.Add(-1 * time.Hour).UTC().Format(time.RFC1123),
			expect: 0,
		},
		{
			name:  "HTTP-date very far in the future — capped at maxRetryAfter",
			input: now.Add(1 * time.Hour).UTC().Format(time.RFC1123),
			check: func(t *testing.T, got time.Duration) {
				assert.Equal(t, maxRetryAfter, got)
			},
		},
		{
			name:   "garbage HTTP-date format — fall back",
			input:  "not-a-date",
			expect: 0,
		},
		{
			name:   "float seconds — rejected (Splunk says integer only)",
			input:  "1.5",
			expect: 0,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseRetryAfter(tc.input)
			if tc.check != nil {
				tc.check(t, got)
				return
			}
			assert.Equal(t, tc.expect, got)
		})
	}
}

// TestSplunkBackoff_BoundedByMax verifies that the exponential
// backoff never exceeds backoffMax regardless of attempt count.
// This is the boundary defence — a `>` vs `>=` mutation would
// otherwise pass example-based tests.
func TestSplunkBackoff_BoundedByMax(t *testing.T) {
	for attempt := 0; attempt < 100; attempt++ {
		d := splunkBackoff(attempt)
		// Jitter is [0.5, 1.0) so the lower bound is backoffBase/2
		// for attempt=0; the upper bound for any attempt is
		// strictly < backoffMax (because jitter < 1.0).
		assert.LessOrEqual(t, d, backoffMax,
			"attempt %d produced %s > backoffMax %s", attempt, d, backoffMax)
		assert.Greater(t, d, time.Duration(0),
			"attempt %d produced non-positive backoff %s", attempt, d)
	}
}

// TestSplunkBackoff_ExponentialGrowth verifies that the backoff
// roughly doubles with each attempt until reaching backoffMax. Uses
// median-of-many to absorb the jitter randomness.
func TestSplunkBackoff_ExponentialGrowth(t *testing.T) {
	median := func(attempt int) time.Duration {
		var sum time.Duration
		const n = 50
		for i := 0; i < n; i++ {
			sum += splunkBackoff(attempt)
		}
		return sum / n
	}
	m0 := median(0)
	m1 := median(1)
	m2 := median(2)
	assert.Greater(t, m1, m0, "attempt 1 median (%s) should exceed attempt 0 median (%s)", m1, m0)
	assert.Greater(t, m2, m1, "attempt 2 median (%s) should exceed attempt 1 median (%s)", m2, m1)
}

// TestSanitizeText_StripsControlChars covers the defence against
// HEC response bodies that contain CR/LF/NUL that could break log
// formatting if echoed verbatim.
func TestSanitizeText_StripsControlChars(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"empty", "", ""},
		{"plain ASCII", "Hello world", "Hello world"},
		{"newline replaced", "line1\nline2", "line1?line2"},
		{"CRLF replaced", "line1\r\nline2", "line1??line2"},
		{"NUL replaced", "before\x00after", "before?after"},
		{"tab preserved", "before\tafter", "before\tafter"},
		{"non-ASCII multibyte replaced byte-by-byte", "café", "caf??"},
		{"long input truncated to 256 chars", string(make([]byte, 300)), string(make([]byte, 256))},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitizeText(tc.input)
			if tc.name == "non-ASCII multibyte replaced byte-by-byte" {
				// "café" = 5 bytes (c,a,f,0xc3,0xa9); the two non-ASCII
				// bytes become '?'.
				assert.Equal(t, "caf??", got)
				return
			}
			if tc.name == "long input truncated to 256 chars" {
				// Input was 300 NUL bytes; after truncation 256 NULs,
				// each replaced by '?'.
				assert.Len(t, got, 256)
				for _, b := range []byte(got) {
					assert.Equal(t, byte('?'), b)
				}
				return
			}
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestParseHECCode covers the response-body parser for the HEC error
// envelope. Bounded by io.LimitReader at the call site.
func TestParseHECCode(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  int
	}{
		{"empty body", []byte{}, 0},
		{"valid success", []byte(`{"text":"Success","code":0}`), 0},
		{"valid invalid-token", []byte(`{"text":"Invalid token","code":4}`), 4},
		{"valid capacity warning", []byte(`{"text":"Approaching capacity","code":24}`), 24},
		{"malformed JSON", []byte(`{"text":`), 0},
		{"HTML error page", []byte(`<html><body>503 Service Unavailable</body></html>`), 0},
		{"empty JSON object", []byte(`{}`), 0},
		{"code only", []byte(`{"code":7}`), 7},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := parseHECCode(tc.input)
			assert.Equal(t, tc.want, got)
		})
	}
}
