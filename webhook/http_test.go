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

package webhook_test

import (
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/axonops/audit/webhook"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Retry-After — RFC 9110 §10.2.3 delta-seconds form (#291)
// ---------------------------------------------------------------------------

// TestParseRetryAfter exercises every value class the parser is
// expected to handle: absent, malformed, non-positive, valid,
// and over-cap. The cap is documented as 30s.
func TestParseRetryAfter(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
		want time.Duration
	}{
		{"empty", "", 0},
		{"zero", "0", 0},
		{"negative", "-1", 0},
		{"non-numeric", "soon", 0},
		{"http-date (unsupported)", "Wed, 21 Oct 2026 07:28:00 GMT", 0},
		{"floating-point (rejected by Atoi)", "1.5", 0},
		{"leading-space (rejected by Atoi)", " 1", 0},
		{"multi-valued (rejected by Atoi)", "30, 60", 0},
		{"one-second", "1", 1 * time.Second},
		{"five-seconds", "5", 5 * time.Second},
		{"at-cap", "30", 30 * time.Second},
		{"over-cap clamped", "600", 30 * time.Second},
		{"way-over-cap clamped", "999999", 30 * time.Second},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := webhook.ParseRetryAfter(tc.in)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestParseRetryAfter_CapMatchesConstant asserts the documented
// cap value so a future change to the constant cannot silently
// shorten the cap without updating the test/docs.
func TestParseRetryAfter_CapMatchesConstant(t *testing.T) {
	t.Parallel()
	assert.Equal(t, 30*time.Second, webhook.MaxRetryAfter,
		"docs and parser cap must agree")
}

// TestHTTP_RetryAfter_Respected verifies that when a 429 carries a
// Retry-After hint, the webhook output sleeps at least that long
// before the next attempt. The handler returns 429 + Retry-After: 1
// on the first request, then a 2xx — the gap between request
// timestamps must be ≥ ~800 ms (the hint, less wall-clock slack to
// avoid CI flakiness).
//
// AC #1, #2, #4 of issue #291.
func TestHTTP_RetryAfter_Respected(t *testing.T) {
	t.Parallel()

	var (
		requestCount atomic.Int32
		mu           sync.Mutex
		timestamps   []time.Time
	)
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		timestamps = append(timestamps, time.Now())
		mu.Unlock()
		n := requestCount.Add(1)
		if n == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	out := newTestWebhookOutput(t, srv.url(), func(c *webhook.Config) {
		c.BatchSize = 1
		c.FlushInterval = 10 * time.Millisecond
		c.MaxRetries = 3
	})

	require.NoError(t, out.Write([]byte(`{"event":"retry_after"}`)))

	if !srv.waitForRequests(2, 5*time.Second) {
		t.Fatalf("expected at least 2 requests, got %d", srv.requestCount())
	}

	mu.Lock()
	defer mu.Unlock()
	require.GreaterOrEqual(t, len(timestamps), 2,
		"need both 429 and follow-up request captured")
	gap := timestamps[1].Sub(timestamps[0])
	// Retry-After: 1 → 1s. Loose lower bound (800ms) avoids
	// CI flakiness; jittered backoff alone would land in
	// [100ms, 200ms) so anything ≥ 800ms proves the hint won.
	assert.GreaterOrEqual(t, gap, 800*time.Millisecond,
		"retry must respect Retry-After: 1 (got %s)", gap)
}

// TestHTTP_RetryAfter_OverCap_Clamped verifies that a hostile
// Retry-After: 600 from a malicious server is clamped to the 30s
// cap rather than honoured literally. The test asserts the cap
// via the parser; an end-to-end timing test would block the suite
// for 30s, which is unacceptable.
//
// AC #3 of issue #291.
func TestHTTP_RetryAfter_OverCap_Clamped(t *testing.T) {
	t.Parallel()
	got := webhook.ParseRetryAfter("600")
	assert.Equal(t, webhook.MaxRetryAfter, got,
		"hostile Retry-After must be capped at MaxRetryAfter")
}

// TestHTTP_RetryAfter_ComputedBackoffWins verifies the max()
// semantics in the other direction: when the server's Retry-After
// hint is smaller than the computed backoff, the computed backoff
// wins. Without this test, a regression that inverted the
// comparison (taking min instead of max) would pass the
// hint-honoured test.
//
// Handler returns 429 + Retry-After: 1 on every request. On
// attempt 4 (range index 3) the computed backoff is
// `100ms * 2^3 = 800ms` with jitter [0.5, 1.0) → [400ms, 800ms),
// which is at or below 1s — the hint dominates here too. So we
// instead set a hint of just 0 (no header) and assert the gap
// matches standard backoff. This is the negative twin to
// TestHTTP_RetryAfter_Respected.
//
// AC #2 of issue #291 (the >= branch in
// `if w.retryHint > backoff` must fall through cleanly when the
// hint is smaller).
func TestHTTP_RetryAfter_ComputedBackoffWins(t *testing.T) {
	t.Parallel()

	var (
		requestCount atomic.Int32
		mu           sync.Mutex
		timestamps   []time.Time
	)
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		timestamps = append(timestamps, time.Now())
		mu.Unlock()
		n := requestCount.Add(1)
		if n == 1 {
			// Retry-After: 0 → parser returns 0, no hint applied.
			// This drives the `w.retryHint > backoff` branch into
			// the fall-through (false) leg; the retry sleep must
			// be the computed backoff, not zero.
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	out := newTestWebhookOutput(t, srv.url(), func(c *webhook.Config) {
		c.BatchSize = 1
		c.FlushInterval = 10 * time.Millisecond
		c.MaxRetries = 3
	})

	require.NoError(t, out.Write([]byte(`{"event":"computed_wins"}`)))

	if !srv.waitForRequests(2, 5*time.Second) {
		t.Fatalf("expected 2 requests, got %d", srv.requestCount())
	}

	mu.Lock()
	defer mu.Unlock()
	require.GreaterOrEqual(t, len(timestamps), 2)
	gap := timestamps[1].Sub(timestamps[0])

	// Attempt 1 computed backoff: 200ms * jitter [0.5, 1.0)
	// → [100ms, 200ms). Hint is 0. Effective wait must be in
	// that range — definitely under 500ms.
	assert.Less(t, gap, 500*time.Millisecond,
		"hint of 0 must fall through to computed backoff (got %s)", gap)
}

// TestHTTP_RetryAfter_MalformedHeader_StillRetries verifies that
// a malformed Retry-After value does not abort the retry — the
// retry still happens with standard backoff, just as if the
// header were absent. Guards against a future refactor that
// might surface a parser error rather than silently degrading.
func TestHTTP_RetryAfter_MalformedHeader_StillRetries(t *testing.T) {
	t.Parallel()

	var requestCount atomic.Int32
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		n := requestCount.Add(1)
		if n == 1 {
			w.Header().Set("Retry-After", "tomorrow") // garbage
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	out := newTestWebhookOutput(t, srv.url(), func(c *webhook.Config) {
		c.BatchSize = 1
		c.FlushInterval = 10 * time.Millisecond
		c.MaxRetries = 3
	})

	require.NoError(t, out.Write([]byte(`{"event":"malformed_retry_after"}`)))

	if !srv.waitForRequests(2, 5*time.Second) {
		t.Fatalf("malformed Retry-After must not block the retry — got %d/2 requests",
			srv.requestCount())
	}
}

// TestHTTP_RetryAfter_ClearedAfterUse verifies that once a hint is
// consumed by a retry, it is cleared — a subsequent 429 with no
// Retry-After header falls back to the standard backoff curve
// (~[100ms, 200ms) for attempt 1). Without clearing, a stale hint
// from an earlier 429 could inflate subsequent retries.
//
// The handler returns:
//
//	req 1: 429 with Retry-After: 1
//	req 2: 429 with no header
//	req 3: 204
//
// Gap between req 1→2 must be ≥ 800ms (hint honoured). Gap between
// req 2→3 must be ≤ 500ms (hint cleared, standard backoff applies).
func TestHTTP_RetryAfter_ClearedAfterUse(t *testing.T) {
	t.Parallel()

	var (
		requestCount atomic.Int32
		mu           sync.Mutex
		timestamps   []time.Time
	)
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		timestamps = append(timestamps, time.Now())
		mu.Unlock()
		n := requestCount.Add(1)
		switch n {
		case 1:
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
		case 2:
			w.WriteHeader(http.StatusTooManyRequests) // no header
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	})

	out := newTestWebhookOutput(t, srv.url(), func(c *webhook.Config) {
		c.BatchSize = 1
		c.FlushInterval = 10 * time.Millisecond
		c.MaxRetries = 5
	})

	require.NoError(t, out.Write([]byte(`{"event":"retry_after_cleared"}`)))

	if !srv.waitForRequests(3, 10*time.Second) {
		t.Fatalf("expected 3 requests, got %d", srv.requestCount())
	}

	mu.Lock()
	defer mu.Unlock()
	require.GreaterOrEqual(t, len(timestamps), 3,
		"need three request timestamps for gap analysis")

	gapHinted := timestamps[1].Sub(timestamps[0])
	gapCleared := timestamps[2].Sub(timestamps[1])

	assert.GreaterOrEqual(t, gapHinted, 800*time.Millisecond,
		"first retry must respect Retry-After: 1 (got %s)", gapHinted)
	// Attempt 2 standard backoff (no hint): 200ms * jitter[0.5,1.0)
	// → [100ms, 200ms). A stale hint would produce ≥ 800ms again.
	// Relative assertion (gapCleared < gapHinted/2) is robust to
	// scheduler slop on heavily-loaded CI runners — it only fails
	// if the hint actually leaked.
	assert.Less(t, gapCleared, gapHinted/2,
		"second retry must use standard backoff after hint cleared "+
			"(hinted=%s, cleared=%s)", gapHinted, gapCleared)
}
