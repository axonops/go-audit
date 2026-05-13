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
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/axonops/audit"
	"github.com/axonops/audit/audittest"
	"github.com/axonops/audit/webhook"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// ---------------------------------------------------------------------------
// Test helpers: TLS certificates
// ---------------------------------------------------------------------------

// TLS test certificates are produced by [audittest.GenerateTestCerts]
// — the audittest package is cross-module-importable; the core's
// internal/testhelper is not (#568).

// ---------------------------------------------------------------------------
// Test helpers: mock metrics
// ---------------------------------------------------------------------------

// mockMetrics satisfies both audit.Metrics and webhook.Metrics for testing.
//
// Synchronisation: a sync.Cond keyed off mu lets tests use waitFor*
// helpers instead of require.Eventually polling. Replaces the
// flake-prone polling pattern (#705 family). Pattern mirrors
// internal/testhelper/output.go MockOutput.
type mockMetrics struct {
	cond             *sync.Cond
	events           map[string]int // "output:status" -> count
	outputErrors     map[string]int
	filteredCount    map[string]int
	validationErrors map[string]int
	globalFiltered   map[string]int
	serializationErr map[string]int
	mu               sync.Mutex
	bufferDrops      int
}

func newMockMetrics() *mockMetrics {
	m := &mockMetrics{
		events:           make(map[string]int),
		outputErrors:     make(map[string]int),
		filteredCount:    make(map[string]int),
		validationErrors: make(map[string]int),
		globalFiltered:   make(map[string]int),
		serializationErr: make(map[string]int),
	}
	m.cond = sync.NewCond(&m.mu)
	return m
}

// --- audit.Metrics methods ---

func (m *mockMetrics) RecordDelivery(output string, status audit.EventStatus) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events[output+":"+string(status)]++
	m.cond.Broadcast()
}

func (m *mockMetrics) RecordOutputError(output string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.outputErrors[output]++
	m.cond.Broadcast()
}

func (m *mockMetrics) RecordOutputFiltered(output string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.filteredCount[output]++
	m.cond.Broadcast()
}

func (m *mockMetrics) RecordBufferDrop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bufferDrops++
	m.cond.Broadcast()
}

func (m *mockMetrics) RecordValidationError(eventType string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.validationErrors[eventType]++
	m.cond.Broadcast()
}

func (m *mockMetrics) RecordFiltered(eventType string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.globalFiltered[eventType]++
	m.cond.Broadcast()
}

func (m *mockMetrics) RecordSerializationError(eventType string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.serializationErr[eventType]++
	m.cond.Broadcast()
}

func (m *mockMetrics) RecordSubmitted() {}

func (m *mockMetrics) RecordQueueDepth(_, _ int) {}

// --- Accessors ---

func (m *mockMetrics) getEventCount(output string, status audit.EventStatus) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.events[output+":"+string(status)]
}

// waitForEventCount blocks until the (output, status) counter
// reaches at least n, or the timeout expires. Replaces
// require.Eventually with a deterministic sync.Cond barrier
// (#705 family fix). Pattern mirrors
// internal/testhelper/output.go MockOutput.WaitForEvents.
func (m *mockMetrics) waitForEventCount(t *testing.T, output string, status audit.EventStatus, n int, timeout time.Duration) {
	t.Helper()
	key := output + ":" + string(status)
	deadline := time.Now().Add(timeout)
	m.mu.Lock()
	defer m.mu.Unlock()
	timer := time.AfterFunc(timeout, func() {
		m.mu.Lock()
		m.cond.Broadcast()
		m.mu.Unlock()
	})
	defer timer.Stop()
	for m.events[key] < n {
		if time.Now().After(deadline) {
			t.Fatalf("waitForEventCount(%s, %s, %d): only %d recorded after %v",
				output, status, n, m.events[key], timeout)
			return
		}
		m.cond.Wait()
	}
}

var _ audit.Metrics = (*mockMetrics)(nil)

// mockOutputMetrics implements audit.OutputMetrics for testing.
//
// Synchronisation: a sync.Cond keyed off mu lets tests use
// waitFor* helpers instead of require.Eventually polling.
// Replaces flake-prone polling pattern (#705 family). Construct
// via newMockOutputMetrics to ensure the cond is initialised
// — there is no second construction path.
type mockOutputMetrics struct {
	cond    *sync.Cond
	mu      sync.Mutex
	drops   int
	flushes int
	errors  int
	retries int
}

func newMockOutputMetrics() *mockOutputMetrics {
	m := &mockOutputMetrics{}
	m.cond = sync.NewCond(&m.mu)
	return m
}

func (m *mockOutputMetrics) RecordDrop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.drops++
	m.cond.Broadcast()
}
func (m *mockOutputMetrics) RecordFlush(_ int, _ time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.flushes++
	m.cond.Broadcast()
}
func (m *mockOutputMetrics) RecordError() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.errors++
	m.cond.Broadcast()
}
func (m *mockOutputMetrics) RecordRetry(_ int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.retries++
	m.cond.Broadcast()
}
func (m *mockOutputMetrics) RecordQueueDepth(_, _ int) {}

func (m *mockOutputMetrics) getDrops() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.drops
}

func (m *mockOutputMetrics) getRetries() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.retries
}

func (m *mockOutputMetrics) getErrors() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.errors
}

// waitForDrops blocks until at least n drops have been recorded
// or timeout expires. Requires the cond to be initialised via
// newMockOutputMetrics. Replaces require.Eventually with a
// deterministic sync.Cond barrier (#705 family fix).
func (m *mockOutputMetrics) waitForDrops(t *testing.T, n int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	m.mu.Lock()
	defer m.mu.Unlock()
	timer := time.AfterFunc(timeout, func() {
		m.mu.Lock()
		m.cond.Broadcast()
		m.mu.Unlock()
	})
	defer timer.Stop()
	for m.drops < n {
		if time.Now().After(deadline) {
			t.Fatalf("waitForDrops(%d): only %d recorded after %v", n, m.drops, timeout)
			return
		}
		m.cond.Wait()
	}
}

var _ audit.OutputMetrics = (*mockOutputMetrics)(nil)

// ---------------------------------------------------------------------------
// Test helpers: taxonomy
// ---------------------------------------------------------------------------

// testTaxonomy returns a taxonomy with common event types for testing.
func testTaxonomy() *audit.Taxonomy {
	return &audit.Taxonomy{
		Version: 1,
		Categories: map[string]*audit.CategoryDef{
			"write":    {Events: []string{"user_create", "user_delete"}},
			"read":     {Events: []string{"user_get", "config_get"}},
			"security": {Events: []string{"auth_failure", "permission_denied"}},
		},
		Events: map[string]*audit.EventDef{
			"user_create":       {Required: []string{"outcome"}},
			"user_delete":       {Required: []string{"outcome"}},
			"user_get":          {Required: []string{"outcome"}},
			"config_get":        {Required: []string{"outcome"}},
			"auth_failure":      {Required: []string{"outcome"}},
			"permission_denied": {Required: []string{"outcome"}},
		},
	}
}

// ---------------------------------------------------------------------------
// Test helpers for webhook
// ---------------------------------------------------------------------------

// webhookTestServer wraps httptest.Server with request capture and
// a waitForRequests polling helper (no time.Sleep).
type webhookTestServer struct {
	server    *httptest.Server
	requestCh chan struct{}
	requests  []*webhookCapturedRequest
	mu        sync.Mutex
}

type webhookCapturedRequest struct {
	Method  string
	Path    string
	Headers http.Header
	Body    []byte
}

func newWebhookTestServer(t *testing.T, handler http.HandlerFunc) *webhookTestServer {
	t.Helper()
	s := &webhookTestServer{
		requestCh: make(chan struct{}, 1000),
	}
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		defer func() { _ = r.Body.Close() }()
		s.mu.Lock()
		s.requests = append(s.requests, &webhookCapturedRequest{
			Method:  r.Method,
			Path:    r.URL.Path,
			Headers: r.Header.Clone(),
			Body:    body,
		})
		s.mu.Unlock()
		select {
		case s.requestCh <- struct{}{}:
		default:
		}
		handler(w, r)
	}))
	t.Cleanup(func() { s.server.Close() })
	return s
}

func (s *webhookTestServer) url() string { return s.server.URL }

func (s *webhookTestServer) waitForRequests(n int, timeout time.Duration) bool {
	deadline := time.After(timeout)
	for {
		s.mu.Lock()
		count := len(s.requests)
		s.mu.Unlock()
		if count >= n {
			return true
		}
		select {
		case <-s.requestCh:
		case <-deadline:
			return false
		}
	}
}

func (s *webhookTestServer) getRequests() []*webhookCapturedRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make([]*webhookCapturedRequest, len(s.requests))
	copy(cp, s.requests)
	return cp
}

func (s *webhookTestServer) requestCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.requests)
}

// newTestWebhookOutput creates a webhook output for testing with
// AllowInsecureHTTP and AllowPrivateRanges (httptest uses http://127.0.0.1).
func newTestWebhookOutput(t *testing.T, rawURL string, opts ...func(*webhook.Config)) *webhook.Output {
	t.Helper()
	return newTestWebhookOutputWithOpts(t, rawURL, opts, nil)
}

// newTestWebhookOutputWithOpts is the extended form: in addition to
// the cfg-mutator hooks that newTestWebhookOutput accepts, it also
// takes a slice of [webhook.Option] for the new construction-time
// wiring (#696: WithDiagnosticLogger, WithOutputMetrics).
func newTestWebhookOutputWithOpts(t *testing.T, rawURL string, cfgOpts []func(*webhook.Config), wOpts []webhook.Option) *webhook.Output {
	t.Helper()
	cfg := &webhook.Config{
		URL:                rawURL,
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
		BatchSize:          10,
		FlushInterval:      50 * time.Millisecond,
		Timeout:            5 * time.Second,
		MaxRetries:         2,
		BufferSize:         100,
	}
	for _, opt := range cfgOpts {
		opt(cfg)
	}
	out, err := webhook.New(cfg, nil, wOpts...)
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })
	return out
}

// ---------------------------------------------------------------------------
// Commit 3 tests: Constructor, interface, Name
// ---------------------------------------------------------------------------

func TestNewWebhookOutput_Valid(t *testing.T) {
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	})
	out, err := webhook.New(&webhook.Config{
		URL:                srv.url(),
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
	}, nil)
	require.NoError(t, err)
	require.NoError(t, out.Close())
}

func TestNewWebhookOutput_InvalidConfig(t *testing.T) {
	_, err := webhook.New(&webhook.Config{}, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrConfigInvalid)
	assert.Contains(t, err.Error(), "must not be empty")
}

func TestWebhookOutput_ImplementsOutput(t *testing.T) {
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	})
	out := newTestWebhookOutput(t, srv.url())
	var _ audit.Output = out
}

func TestWebhookOutput_Name(t *testing.T) {
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	})
	out := newTestWebhookOutput(t, srv.url())
	name := out.Name()
	assert.True(t, strings.HasPrefix(name, "webhook:"), "Name should start with webhook:")
	assert.Contains(t, name, "127.0.0.1")
}

// ---------------------------------------------------------------------------
// Commit 4 tests: Write/Close lifecycle
// ---------------------------------------------------------------------------

func TestWebhookOutput_WriteAfterClose(t *testing.T) {
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	})
	out, err := webhook.New(&webhook.Config{
		URL:                srv.url(),
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
	}, nil)
	require.NoError(t, err)
	require.NoError(t, out.Close())

	err = out.Write([]byte(`{"event":"after_close"}`))
	assert.ErrorIs(t, err, audit.ErrOutputClosed)
}

func TestWebhookOutput_CloseIdempotent(t *testing.T) {
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	})
	out, err := webhook.New(&webhook.Config{
		URL:                srv.url(),
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
	}, nil)
	require.NoError(t, err)
	assert.NoError(t, out.Close())
	assert.NoError(t, out.Close())
}

func TestWebhookOutput_CloseShutdownTimeout_ExceedsHTTPTimeout(t *testing.T) {
	// Server delays 150ms — longer than the 100ms HTTP timeout but
	// shorter than the shutdown timeout (2*100ms+5s = 5.2s).
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(150 * time.Millisecond)
		w.WriteHeader(200)
	})
	out, err := webhook.New(&webhook.Config{
		URL:                srv.url(),
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
		BatchSize:          1,
		FlushInterval:      50 * time.Millisecond,
		Timeout:            100 * time.Millisecond,
		MaxRetries:         0,
	}, nil)
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte(`{"event":"test"}`)))

	start := time.Now()
	assert.NoError(t, out.Close())
	elapsed := time.Since(start)

	// Close should complete — the shutdown timeout (2*100ms+5s)
	// is much larger than the 150ms server delay.
	assert.Less(t, elapsed, 3*time.Second,
		"Close should not take excessively long")
}

func TestWebhookOutput_BufferOverflow_NonBlocking(t *testing.T) {
	// Slow server keeps the batch goroutine busy.
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(1 * time.Second)
		w.WriteHeader(200)
	})
	metrics := newMockMetrics()
	om := newMockOutputMetrics()
	out, err := webhook.New(&webhook.Config{
		URL:                srv.url(),
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
		BatchSize:          1, // flush immediately
		FlushInterval:      50 * time.Millisecond,
		Timeout:            5 * time.Second,
		MaxRetries:         1,
		BufferSize:         3, // tiny buffer
	}, metrics, webhook.WithOutputMetrics(om))
	require.NoError(t, err)

	// First event triggers flush (blocks on slow server).
	// Subsequent writes fill buffer and overflow.
	start := time.Now()
	for range 15 {
		_ = out.Write([]byte(`{"event":"overflow"}`))
	}
	elapsed := time.Since(start)

	assert.Less(t, elapsed, 500*time.Millisecond,
		"Write should not block on full buffer")

	require.NoError(t, out.Close())

	assert.Greater(t, om.getDrops(), 0,
		"OutputMetrics.RecordDrop should be called for buffer overflow")
}

// ---------------------------------------------------------------------------
// Commit 5 tests: HTTP POST, NDJSON, retry
// ---------------------------------------------------------------------------

func TestWebhookOutput_Delivery(t *testing.T) {
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	})
	out := newTestWebhookOutput(t, srv.url(), func(cfg *webhook.Config) {
		cfg.BatchSize = 3
	})

	for range 3 {
		require.NoError(t, out.Write([]byte(`{"event":"delivery_test"}`+"\n")))
	}
	require.True(t, srv.waitForRequests(1, 2*time.Second))
	require.NoError(t, out.Close())

	reqs := srv.getRequests()
	require.GreaterOrEqual(t, len(reqs), 1)

	// Verify NDJSON: 3 lines, each valid JSON.
	lines := strings.Split(strings.TrimSpace(string(reqs[0].Body)), "\n")
	assert.Len(t, lines, 3)
	for _, line := range lines {
		assert.True(t, json.Valid([]byte(line)), "each line should be valid JSON: %s", line)
	}
}

func TestWebhookOutput_ContentType_NDJSON(t *testing.T) {
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	})
	out := newTestWebhookOutput(t, srv.url(), func(cfg *webhook.Config) {
		cfg.BatchSize = 1
	})

	require.NoError(t, out.Write([]byte(`{"event":"ct"}`+"\n")))
	require.True(t, srv.waitForRequests(1, 2*time.Second))
	require.NoError(t, out.Close())

	reqs := srv.getRequests()
	assert.Equal(t, "application/x-ndjson", reqs[0].Headers.Get("Content-Type"))
}

func TestWebhookOutput_FlushInterval(t *testing.T) {
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	})
	out := newTestWebhookOutput(t, srv.url(), func(cfg *webhook.Config) {
		cfg.BatchSize = 1000 // large, so only timer triggers
		cfg.FlushInterval = 50 * time.Millisecond
	})

	require.NoError(t, out.Write([]byte(`{"event":"timer"}`+"\n")))
	require.True(t, srv.waitForRequests(1, 2*time.Second))
	require.NoError(t, out.Close())

	reqs := srv.getRequests()
	require.GreaterOrEqual(t, len(reqs), 1)
	assert.Contains(t, string(reqs[0].Body), "timer")
}

// TestWebhookOutput_FlushesOnByteThreshold verifies that accumulated
// event bytes crossing MaxBatchBytes triggers a flush before the count
// threshold would (#687 AC #2).
func TestWebhookOutput_FlushesOnByteThreshold(t *testing.T) {
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	})
	// BatchSize deliberately high so only byte threshold can trigger
	// the flush. FlushInterval long enough that the timer does not
	// fire before the assertion.
	out := newTestWebhookOutput(t, srv.url(), func(cfg *webhook.Config) {
		cfg.BatchSize = 1000
		cfg.FlushInterval = 10 * time.Second
		cfg.MaxBatchBytes = 4096 // 4 KiB
	})

	// Each event is ~1 KiB; 5 events = 5 KiB, crossing 4 KiB threshold.
	event := []byte(strings.Repeat("a", 1024))
	for i := 0; i < 5; i++ {
		require.NoError(t, out.Write(event))
	}

	// At least one HTTP POST should arrive before the FlushInterval
	// could otherwise fire.
	require.True(t, srv.waitForRequests(1, 2*time.Second),
		"byte threshold must trigger flush before count or timer")
	require.NoError(t, out.Close())
}

// TestWebhookOutput_OversizedEventFlushesAlone verifies that a single
// event exceeding MaxBatchBytes is flushed on its own rather than
// dropped (#687 AC #3).
func TestWebhookOutput_OversizedEventFlushesAlone(t *testing.T) {
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	})
	out := newTestWebhookOutput(t, srv.url(), func(cfg *webhook.Config) {
		cfg.BatchSize = 100
		cfg.FlushInterval = 10 * time.Second
		cfg.MaxBatchBytes = 1 << 10 // 1 KiB
	})

	// Single event exceeding MaxBatchBytes (4 KiB > 1 KiB).
	oversized := []byte(strings.Repeat("x", 4<<10))
	require.NoError(t, out.Write(oversized))

	require.True(t, srv.waitForRequests(1, 2*time.Second),
		"oversized single event must trigger immediate flush, not drop")
	require.NoError(t, out.Close())

	reqs := srv.getRequests()
	require.GreaterOrEqual(t, len(reqs), 1)
	// Event body should contain the oversized payload marker.
	assert.Contains(t, string(reqs[0].Body), "xxxx",
		"oversized event body must reach the server intact")
}

func TestWebhookOutput_CloseFlushesRemaining(t *testing.T) {
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	})
	out, err := webhook.New(&webhook.Config{
		URL:                srv.url(),
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
		BatchSize:          1000,             // won't trigger on size
		FlushInterval:      10 * time.Second, // won't trigger on timer
		Timeout:            5 * time.Second,
		BufferSize:         100,
	}, nil)
	require.NoError(t, err)

	for range 3 {
		require.NoError(t, out.Write([]byte(`{"event":"close_flush"}`+"\n")))
	}

	// Close triggers final flush.
	require.NoError(t, out.Close())

	reqs := srv.getRequests()
	require.GreaterOrEqual(t, len(reqs), 1)
	assert.Contains(t, string(reqs[len(reqs)-1].Body), "close_flush")
}

func TestWebhookOutput_EmptyBatch_NoRequest(t *testing.T) {
	var requestCount int32
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.WriteHeader(200)
	})
	_ = newTestWebhookOutput(t, srv.url(), func(cfg *webhook.Config) {
		cfg.FlushInterval = 20 * time.Millisecond
	})

	// Wait for 2+ flush intervals with no events.
	time.Sleep(60 * time.Millisecond) // intentional: testing absence of action

	assert.Equal(t, int32(0), atomic.LoadInt32(&requestCount),
		"empty batch should not trigger HTTP request")
}

func TestWebhookOutput_TimerResets_AfterBatchFlush(t *testing.T) {
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	})
	out := newTestWebhookOutput(t, srv.url(), func(cfg *webhook.Config) {
		cfg.BatchSize = 2
		cfg.FlushInterval = 200 * time.Millisecond
	})

	// 2 events -> batch-size flush.
	require.NoError(t, out.Write([]byte(`{"n":1}`+"\n")))
	require.NoError(t, out.Write([]byte(`{"n":2}`+"\n")))
	require.True(t, srv.waitForRequests(1, 2*time.Second))

	// 1 more event immediately after flush.
	require.NoError(t, out.Write([]byte(`{"n":3}`+"\n")))

	// Timer should reset — partial batch flushes at ~200ms from now.
	require.True(t, srv.waitForRequests(2, 1*time.Second),
		"partial batch should flush after reset FlushInterval")
	require.NoError(t, out.Close())
}

func TestWebhookOutput_CustomHeaders(t *testing.T) {
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	})
	out := newTestWebhookOutput(t, srv.url(), func(cfg *webhook.Config) {
		cfg.BatchSize = 1
		cfg.Headers = map[string]string{
			"Authorization": "Bearer test-token-123",
			"X-Custom":      "custom-value",
		}
	})

	require.NoError(t, out.Write([]byte(`{"event":"headers"}`+"\n")))
	require.True(t, srv.waitForRequests(1, 2*time.Second))
	require.NoError(t, out.Close())

	reqs := srv.getRequests()
	assert.Equal(t, "Bearer test-token-123", reqs[0].Headers.Get("Authorization"))
	assert.Equal(t, "custom-value", reqs[0].Headers.Get("X-Custom"))
}

func TestWebhookOutput_Retry_503ThenSuccess(t *testing.T) {
	var attempts atomic.Int32
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		n := attempts.Add(1)
		if n <= 2 {
			w.WriteHeader(503)
			return
		}
		w.WriteHeader(200)
	})
	out := newTestWebhookOutput(t, srv.url(), func(cfg *webhook.Config) {
		cfg.BatchSize = 1
		cfg.MaxRetries = 5
	})

	require.NoError(t, out.Write([]byte(`{"event":"retry"}`+"\n")))
	require.True(t, srv.waitForRequests(3, 10*time.Second))
	require.NoError(t, out.Close())

	assert.Equal(t, int32(3), attempts.Load())
}

func TestWebhookOutput_NoRetry_4xx(t *testing.T) {
	for _, code := range []int{400, 401, 403, 404, 422} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			var attempts atomic.Int32
			srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
				attempts.Add(1)
				w.WriteHeader(code)
			})
			out := newTestWebhookOutput(t, srv.url(), func(cfg *webhook.Config) {
				cfg.BatchSize = 1
				cfg.MaxRetries = 3
			})

			require.NoError(t, out.Write([]byte(`{"event":"no_retry"}`+"\n")))
			require.True(t, srv.waitForRequests(1, 2*time.Second))
			require.NoError(t, out.Close())

			assert.Equal(t, int32(1), attempts.Load(), "%d should not trigger retry", code)
		})
	}
}

func TestWebhookOutput_Retry_429(t *testing.T) {
	var attempts atomic.Int32
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		n := attempts.Add(1)
		if n == 1 {
			w.WriteHeader(429)
			return
		}
		w.WriteHeader(200)
	})
	out := newTestWebhookOutput(t, srv.url(), func(cfg *webhook.Config) {
		cfg.BatchSize = 1
	})

	require.NoError(t, out.Write([]byte(`{"event":"429"}`+"\n")))
	require.True(t, srv.waitForRequests(2, 10*time.Second))
	require.NoError(t, out.Close())

	assert.Equal(t, int32(2), attempts.Load())
}

func TestWebhookOutput_Redirect_Rejected(t *testing.T) {
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/other")
		w.WriteHeader(301)
	})
	out := newTestWebhookOutput(t, srv.url(), func(cfg *webhook.Config) {
		cfg.BatchSize = 1
	})

	require.NoError(t, out.Write([]byte(`{"event":"redirect"}`+"\n")))
	require.NoError(t, out.Close())

	// Redirect is non-retryable — at most 1 request.
	assert.LessOrEqual(t, srv.requestCount(), 1)
}

func TestWebhookOutput_RetryExhausted_Metrics(t *testing.T) {
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(503)
	})
	metrics := newMockMetrics()
	om := newMockOutputMetrics()
	out, err := webhook.New(&webhook.Config{
		URL:                srv.url(),
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
		BatchSize:          1,
		FlushInterval:      50 * time.Millisecond,
		MaxRetries:         2,
		Timeout:            5 * time.Second,
		BufferSize:         100,
	}, metrics, webhook.WithOutputMetrics(om))
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte(`{"event":"exhaust"}`+"\n")))
	// Close blocks until batch goroutine exits (retries complete or cancelled).
	require.NoError(t, out.Close())

	assert.Greater(t, om.getDrops(), 0,
		"OutputMetrics.RecordDrop should be called on retry exhaustion")
	assert.Greater(t, om.getRetries(), 0,
		"OutputMetrics.RecordRetry should be called during retry attempts")
}

// ---------------------------------------------------------------------------
// Concurrent writes (Commit 4, moved here for organization)
// ---------------------------------------------------------------------------

func TestWebhookOutput_ConcurrentWrites(t *testing.T) {
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	})
	out := newTestWebhookOutput(t, srv.url(), func(cfg *webhook.Config) {
		cfg.BufferSize = 1000
	})

	var wg sync.WaitGroup
	const goroutines = 50
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			_ = out.Write([]byte(`{"event":"concurrent"}` + "\n"))
		}()
	}
	wg.Wait()
	// Close is handled by t.Cleanup in newTestWebhookOutput.
}

// ---------------------------------------------------------------------------
// Commit 7 tests: Edge cases, SSRF enforcement, backoff, NDJSON
// ---------------------------------------------------------------------------

func TestWebhookOutput_WriteNil(t *testing.T) {
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	})
	out := newTestWebhookOutput(t, srv.url())
	assert.NoError(t, out.Write(nil), "Write(nil) should not panic or error")
}

func TestWebhookOutput_WriteEmpty(t *testing.T) {
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	})
	out := newTestWebhookOutput(t, srv.url())
	assert.NoError(t, out.Write([]byte{}), "Write([]byte{}) should not panic or error")
}

func TestWebhookOutput_SSRFBlocked(t *testing.T) {
	// httptest server at 127.0.0.1. With AllowPrivateRanges=false,
	// SSRF check blocks loopback. Events should be dropped.
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	})

	metrics := newMockMetrics()
	out, err := webhook.New(&webhook.Config{
		URL:                srv.url(),
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: false, // SSRF blocks 127.0.0.1
		BatchSize:          1,
		FlushInterval:      50 * time.Millisecond,
		Timeout:            1 * time.Second,
		MaxRetries:         1,
		BufferSize:         10,
		// Disable startup probe so the test exercises write-path SSRF
		// behaviour, not probe-path SSRF (which has its own coverage).
		DisableStartupVerification: true,
	}, metrics)
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte(`{"event":"ssrf"}`+"\n")))
	// Close blocks until batch goroutine exits (SSRF failure completes).
	require.NoError(t, out.Close())

	// No requests should reach the server — SSRF blocked the dial.
	assert.Equal(t, 0, srv.requestCount(), "SSRF should block connection to loopback")
}

func TestWebhookOutput_RequestTimeout(t *testing.T) {
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(5 * time.Second) // slow server
		w.WriteHeader(200)
	})
	metrics := newMockMetrics()
	om := newMockOutputMetrics()
	out, err := webhook.New(&webhook.Config{
		URL:                srv.url(),
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
		BatchSize:          1,
		FlushInterval:      50 * time.Millisecond,
		Timeout:            100 * time.Millisecond, // very short
		MaxRetries:         1,
		BufferSize:         100,
	}, metrics, webhook.WithOutputMetrics(om))
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte(`{"event":"timeout"}`+"\n")))
	// Close blocks until batch goroutine exits (timeout + retries complete).
	require.NoError(t, out.Close())

	assert.Greater(t, om.getDrops(), 0,
		"timed out request should result in dropped batch")
}

func TestWebhookBackoff(t *testing.T) {
	d0 := webhook.WebhookBackoff(0)
	assert.GreaterOrEqual(t, d0, 50*time.Millisecond) // 100ms * 0.5
	assert.Less(t, d0, 100*time.Millisecond)          // 100ms * 1.0

	d1 := webhook.WebhookBackoff(1)
	assert.GreaterOrEqual(t, d1, 100*time.Millisecond)
	assert.Less(t, d1, 200*time.Millisecond)

	// Should be capped at 5s.
	d20 := webhook.WebhookBackoff(20)
	assert.LessOrEqual(t, d20, 5*time.Second)
}

func TestBuildNDJSON(t *testing.T) {
	events := [][]byte{
		[]byte(`{"a":1}` + "\n"),
		[]byte(`{"b":2}`), // missing newline — should be added
		[]byte(`{"c":3}` + "\n"),
	}
	result := webhook.BuildNDJSON(events)
	lines := strings.Split(strings.TrimSpace(string(result)), "\n")
	assert.Len(t, lines, 3)
	for _, line := range lines {
		assert.True(t, json.Valid([]byte(line)), "each line should be valid JSON: %s", line)
	}
}

func TestBuildNDJSON_Empty(t *testing.T) {
	result := webhook.BuildNDJSON(nil)
	assert.Empty(t, result)
}

func TestNewWebhookOutput_EmbeddedCredentials_Rejected(t *testing.T) {
	_, err := webhook.New(&webhook.Config{
		URL: "https://user:pass@example.com/webhook",
	}, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrConfigInvalid)
	assert.Contains(t, err.Error(), "must not contain credentials")
}

func TestNewWebhookOutput_HeaderValueCRLF_Rejected(t *testing.T) {
	_, err := webhook.New(&webhook.Config{
		URL:     "https://example.com/webhook",
		Headers: map[string]string{"X-Custom": "val\r\nEvil: injected"},
	}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid characters")
}

func TestNewWebhookOutput_TLSCA_NonexistentFile(t *testing.T) {
	_, err := webhook.New(&webhook.Config{
		URL:   "https://example.com/webhook",
		TLSCA: "/nonexistent/ca.pem",
	}, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrConfigInvalid)
	assert.Contains(t, err.Error(), "tls file")
}

func TestNewWebhookOutput_TLSCA_InvalidPEM(t *testing.T) {
	dir := t.TempDir()
	badCA := dir + "/bad-ca.pem"
	require.NoError(t, os.WriteFile(badCA, []byte("not a pem"), 0o600))

	_, err := webhook.New(&webhook.Config{
		URL:   "https://example.com/webhook",
		TLSCA: badCA,
	}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse ca certificate")
}

func TestNewWebhookOutput_TLSCert_NonexistentFile(t *testing.T) {
	_, err := webhook.New(&webhook.Config{
		URL:     "https://example.com/webhook",
		TLSCert: "/nonexistent/cert.pem",
		TLSKey:  "/nonexistent/key.pem",
	}, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrConfigInvalid)
	assert.Contains(t, err.Error(), "tls file")
}

func TestWebhookOutput_ConcurrentWriteAndClose(t *testing.T) {
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	})
	out, err := webhook.New(&webhook.Config{
		URL:                srv.url(),
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
		BatchSize:          10,
		FlushInterval:      50 * time.Millisecond,
		Timeout:            5 * time.Second,
		BufferSize:         100,
	}, nil)
	require.NoError(t, err)

	// Start writers and close concurrently — exercise the race detector.
	var wg sync.WaitGroup
	wg.Add(21) // 20 writers + 1 closer
	for range 20 {
		go func() {
			defer wg.Done()
			_ = out.Write([]byte(`{"event":"race"}` + "\n"))
		}()
	}
	go func() {
		defer wg.Done()
		_ = out.Close()
	}()
	wg.Wait()
}

// ---------------------------------------------------------------------------
// TLSPolicy integration
// ---------------------------------------------------------------------------

func TestWebhookOutput_TLSPolicy_NilPreservesBehaviour(t *testing.T) {
	// Nil TLSPolicy should behave identically to the previous hardcoded
	// TLS 1.3 default.
	certs := audittest.GenerateTestCerts(t)

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	srv.TLS = certs.TLSCfg
	srv.StartTLS()
	t.Cleanup(func() { srv.Close() })

	out, err := webhook.New(&webhook.Config{
		URL:                srv.URL,
		TLSCA:              certs.CAPath,
		TLSPolicy:          nil, // explicitly nil
		AllowPrivateRanges: true,
		BatchSize:          1,
		FlushInterval:      50 * time.Millisecond,
		Timeout:            5 * time.Second,
		BufferSize:         100,
	}, nil)
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte(`{"event":"nil_policy"}`+"\n")))
	require.NoError(t, out.Close())
}

func TestWebhookOutput_TLSPolicy_AllowTLS12(t *testing.T) {
	certs := audittest.GenerateTestCerts(t)
	// Server accepts TLS 1.2.
	certs.TLSCfg.MinVersion = tls.VersionTLS12

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	srv.TLS = certs.TLSCfg
	srv.StartTLS()
	t.Cleanup(func() { srv.Close() })

	out, err := webhook.New(&webhook.Config{
		URL:   srv.URL,
		TLSCA: certs.CAPath,
		TLSPolicy: &audit.TLSPolicy{
			AllowTLS12: true,
		},
		AllowPrivateRanges: true,
		BatchSize:          1,
		FlushInterval:      50 * time.Millisecond,
		Timeout:            5 * time.Second,
		BufferSize:         100,
	}, nil)
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte(`{"event":"tls12_policy"}`+"\n")))
	require.NoError(t, out.Close())
}

// ---------------------------------------------------------------------------
// TLS tests
// ---------------------------------------------------------------------------

func TestWebhookOutput_TLS_WithCustomCA(t *testing.T) {
	certs := audittest.GenerateTestCerts(t)

	// Start an HTTPS server with the test CA's cert.
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	srv.TLS = certs.TLSCfg
	srv.StartTLS()
	t.Cleanup(func() { srv.Close() })

	out, err := webhook.New(&webhook.Config{
		URL:                srv.URL,
		TLSCA:              certs.CAPath,
		AllowPrivateRanges: true,
		BatchSize:          1,
		FlushInterval:      50 * time.Millisecond,
		Timeout:            5 * time.Second,
		BufferSize:         100,
	}, nil)
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte(`{"event":"tls_test"}`+"\n")))
	// Close flushes the final batch.
	require.NoError(t, out.Close())
}

func TestWebhookOutput_TLS_MTLS(t *testing.T) {
	certs := audittest.GenerateTestCerts(t)
	// Require client cert.
	certs.TLSCfg.ClientAuth = tls.RequireAndVerifyClientCert

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	srv.TLS = certs.TLSCfg
	srv.StartTLS()
	t.Cleanup(func() { srv.Close() })

	out, err := webhook.New(&webhook.Config{
		URL:                srv.URL,
		TLSCA:              certs.CAPath,
		TLSCert:            certs.ClientCert,
		TLSKey:             certs.ClientKey,
		AllowPrivateRanges: true,
		BatchSize:          1,
		FlushInterval:      50 * time.Millisecond,
		Timeout:            5 * time.Second,
		BufferSize:         100,
	}, nil)
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte(`{"event":"mtls_test"}`+"\n")))
	require.NoError(t, out.Close())
}

func TestWebhookOutput_TLS_WrongCA_Rejected(t *testing.T) {
	certs := audittest.GenerateTestCerts(t)

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	srv.TLS = certs.TLSCfg
	srv.StartTLS()
	t.Cleanup(func() { srv.Close() })

	// Generate a DIFFERENT CA — the server cert won't be trusted.
	wrongCerts := audittest.GenerateTestCerts(t)

	metrics := newMockMetrics()
	om := newMockOutputMetrics()
	out, err := webhook.New(&webhook.Config{
		URL:                srv.URL,
		TLSCA:              wrongCerts.CAPath, // wrong CA
		AllowPrivateRanges: true,
		BatchSize:          1,
		FlushInterval:      50 * time.Millisecond,
		Timeout:            2 * time.Second,
		MaxRetries:         1,
		BufferSize:         100,
		// Disable startup probe so the test exercises write-path TLS
		// rejection (probe-path TLS rejection has its own coverage).
		DisableStartupVerification: true,
	}, metrics, webhook.WithOutputMetrics(om))
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte(`{"event":"wrong_ca"}`+"\n")))

	// Wait deterministically for the TLS failure to be recorded
	// as an output drop. Replaces require.Eventually polling
	// (#705 family fix).
	om.waitForDrops(t, 1, 5*time.Second)

	require.NoError(t, out.Close())
}

// ---------------------------------------------------------------------------
// Delivery metrics tests (#53)
// ---------------------------------------------------------------------------

func TestWebhookOutput_DeliveryMetrics_SuccessOnHTTP200(t *testing.T) {
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	})
	metrics := newMockMetrics()
	out, err := webhook.New(&webhook.Config{
		URL:                srv.url(),
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
		BatchSize:          3,
		FlushInterval:      50 * time.Millisecond,
		Timeout:            5 * time.Second,
		BufferSize:         100,
	}, metrics)
	require.NoError(t, err)

	for range 3 {
		require.NoError(t, out.Write([]byte(`{"event":"metric_test"}`+"\n")))
	}
	// Wait deterministically for the batch goroutine to finish
	// delivery and record the success metric before we close.
	// Replaces require.Eventually polling (#705 family fix).
	name := out.Name()
	metrics.waitForEventCount(t, name, audit.EventSuccess, 3, 5*time.Second)

	require.NoError(t, out.Close())

	assert.Equal(t, 0, metrics.getEventCount(name, audit.EventError),
		"RecordDelivery(error) should not be called on success")
}

func TestWebhookOutput_DeliveryMetrics_ErrorOnRetryExhausted(t *testing.T) {
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(503)
	})
	metrics := newMockMetrics()
	out, err := webhook.New(&webhook.Config{
		URL:                srv.url(),
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
		BatchSize:          2,
		FlushInterval:      50 * time.Millisecond,
		Timeout:            5 * time.Second,
		MaxRetries:         2,
		BufferSize:         100,
	}, metrics)
	require.NoError(t, err)

	for range 2 {
		require.NoError(t, out.Write([]byte(`{"event":"drop_test"}`+"\n")))
	}
	require.NoError(t, out.Close())

	name := out.Name()
	assert.Equal(t, 2, metrics.getEventCount(name, audit.EventError),
		"RecordDelivery(error) should be called once per dropped event")
	assert.Equal(t, 0, metrics.getEventCount(name, audit.EventSuccess),
		"RecordDelivery(success) should not be called when retries exhausted")
}

func TestWebhookOutput_DeliveryMetrics_ErrorOnBufferOverflow(t *testing.T) {
	// Slow server to keep batch goroutine busy.
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(1 * time.Second)
		w.WriteHeader(200)
	})
	metrics := newMockMetrics()
	out, err := webhook.New(&webhook.Config{
		URL:                srv.url(),
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
		BatchSize:          1,
		FlushInterval:      50 * time.Millisecond,
		Timeout:            5 * time.Second,
		MaxRetries:         1,
		BufferSize:         3,
	}, metrics)
	require.NoError(t, err)

	// Fill buffer — overflow events are no longer recorded via
	// core Metrics.RecordDelivery (B-25 consistency with file + syslog).
	// They surface only via OutputMetrics.RecordDrop — asserted in
	// the separate per-output metrics test suite.
	for range 15 {
		_ = out.Write([]byte(`{"event":"overflow"}` + "\n"))
	}
	require.NoError(t, out.Close())

	name := out.Name()
	assert.Equal(t, 0, metrics.getEventCount(name, audit.EventError),
		"buffer overflow drops must not be recorded via core Metrics.RecordDelivery (B-25); use OutputMetrics.RecordDrop")
}

func TestWebhookOutput_CoreMetrics_SkippedForDeliveryReporter(t *testing.T) {
	// Verify that the core recordWrite does NOT call RecordDelivery
	// for webhook outputs (they report their own delivery).
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	})
	metrics := newMockMetrics()

	webhookOut, err := webhook.New(&webhook.Config{
		URL:                srv.url(),
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
		BatchSize:          1,
		FlushInterval:      50 * time.Millisecond,
		Timeout:            5 * time.Second,
		BufferSize:         100,
	}, metrics)
	require.NoError(t, err)

	// Create an auditor with the webhook output and metrics.
	auditor, err := audit.New(
		audit.WithValidationMode(audit.ValidationPermissive),
		audit.WithTaxonomy(testTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(webhookOut, audit.WithRoute(&audit.EventRoute{})),
		audit.WithMetrics(metrics),
	)
	require.NoError(t, err)

	require.NoError(t, auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{"outcome": "success"})))

	// Wait deterministically for the batch goroutine to finish
	// delivery and record the success metric. Polling the metric
	// is the correct synchronisation signal — waitForRequests
	// only proves the HTTP handler fired, not that the client
	// has read the response and recorded metrics. Replaces
	// require.Eventually polling (#705 family fix).
	name := webhookOut.Name()
	metrics.waitForEventCount(t, name, audit.EventSuccess, 1, 5*time.Second)

	require.NoError(t, auditor.Close())
}

// ---------------------------------------------------------------------------
// Nil WebhookMetrics (#54)
// ---------------------------------------------------------------------------

// coreOnlyMetrics implements audit.Metrics but not webhook.Metrics.
type coreOnlyMetrics struct {
	events map[string]int
	mu     sync.Mutex
}

func (m *coreOnlyMetrics) RecordDelivery(output string, status audit.EventStatus) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events[output+":"+string(status)]++
}

func (m *coreOnlyMetrics) RecordOutputError(_ string)        {}
func (m *coreOnlyMetrics) RecordOutputFiltered(_ string)     {}
func (m *coreOnlyMetrics) RecordValidationError(_ string)    {}
func (m *coreOnlyMetrics) RecordFiltered(_ string)           {}
func (m *coreOnlyMetrics) RecordSerializationError(_ string) {}
func (m *coreOnlyMetrics) RecordBufferDrop()                 {}
func (m *coreOnlyMetrics) RecordSubmitted()                  {}
func (m *coreOnlyMetrics) RecordQueueDepth(_, _ int)         {}

var _ audit.Metrics = (*coreOnlyMetrics)(nil)

func TestWebhookOutput_NilWebhookMetrics(t *testing.T) {
	// Slow server to fill the buffer.
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(1 * time.Second)
		w.WriteHeader(200)
	})
	m := &coreOnlyMetrics{events: make(map[string]int)}
	out, err := webhook.New(&webhook.Config{
		URL:                srv.url(),
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
		BatchSize:          1,
		FlushInterval:      50 * time.Millisecond,
		Timeout:            5 * time.Second,
		MaxRetries:         1,
		BufferSize:         3,
	}, m) // core Metrics only, no OutputMetrics (injected separately)
	require.NoError(t, err)

	// Overflow the buffer — should not panic despite missing
	// OutputMetrics. Buffer-overflow drops are no longer recorded via
	// core Metrics.RecordDelivery (B-25); the per-output RecordDrop path
	// is exercised in the OutputMetrics-specific tests. Here we only
	// assert that the code does not panic.
	for range 15 {
		_ = out.Write([]byte(`{"event":"overflow"}` + "\n"))
	}
	require.NoError(t, out.Close())

	// Core Metrics should NOT have recorded the overflow drops as
	// RecordDelivery(EventError) — B-25 alignment with file + syslog.
	m.mu.Lock()
	errorCount := m.events[out.Name()+":error"]
	m.mu.Unlock()
	assert.Equal(t, 0, errorCount, "buffer overflow drops must not be recorded via Metrics.RecordDelivery (B-25)")
}

// ---------------------------------------------------------------------------
// Close lifecycle tests (#325 — missing test for closeCh pattern)
// ---------------------------------------------------------------------------

// TestWebhookOutput_Close_InFlightRequestCompletes verifies that an HTTP
// POST in progress when Close() is called completes successfully instead
// of being cancelled. This tests the closeCh pattern: Close signals via
// channel, context stays live until batch loop exits.
func TestWebhookOutput_Close_InFlightRequestCompletes(t *testing.T) {
	var received atomic.Int32
	requestStarted := make(chan struct{})
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		close(requestStarted) // signal: request is in-flight
		time.Sleep(200 * time.Millisecond)
		received.Add(1)
		w.WriteHeader(200)
	})

	out, err := webhook.New(&webhook.Config{
		URL:                srv.url(),
		BatchSize:          1, // immediate flush on first event
		FlushInterval:      10 * time.Second,
		Timeout:            2 * time.Second, // plenty of time for 200ms delay
		MaxRetries:         1,
		BufferSize:         10,
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
	}, nil)
	require.NoError(t, err)

	// Write one event — BatchSize=1 triggers immediate flush (HTTP in-flight).
	require.NoError(t, out.Write([]byte(`{"event":"inflight"}`+"\n")))

	// Wait for the server handler to confirm the request arrived
	// (deterministic, no time.Sleep). The request is now in-flight.
	select {
	case <-requestStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for HTTP request to start")
	}

	// Close while HTTP is in-flight. With the closeCh pattern, the context
	// stays live so the 200ms-delayed request completes. With the old
	// cancel() pattern, the request would be aborted.
	require.NoError(t, out.Close())

	// The server must have received the complete request.
	assert.Equal(t, int32(1), received.Load(),
		"in-flight HTTP request must complete during Close, not be cancelled")
}

// ---------------------------------------------------------------------------
// TLS file validation tests (#325 — directory rejection)
// ---------------------------------------------------------------------------

func TestNewWebhookOutput_TLSCert_IsDirectory(t *testing.T) {
	dir := t.TempDir()
	_, err := webhook.New(&webhook.Config{
		URL:     "https://example.com/webhook",
		TLSCert: dir,
		TLSKey:  dir,
	}, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrConfigInvalid)
	assert.Contains(t, err.Error(), "directory")
}

func TestNewWebhookOutput_TLSCA_IsDirectory(t *testing.T) {
	dir := t.TempDir()
	_, err := webhook.New(&webhook.Config{
		URL:   "https://example.com/webhook",
		TLSCA: dir,
	}, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrConfigInvalid)
	assert.Contains(t, err.Error(), "directory")
}

// ---------------------------------------------------------------------------
// Config.String() credential redaction tests (#325, #475)
// ---------------------------------------------------------------------------

func TestWebhookConfig_String_RedactsHeaders(t *testing.T) {
	cfg := webhook.Config{
		URL:       "https://example.com/hook",
		Headers:   map[string]string{"Authorization": "Bearer super-secret-token"},
		BatchSize: 10,
		Timeout:   5 * time.Second,
	}
	s := cfg.String()
	assert.Contains(t, s, "WebhookConfig{")
	// URL is sanitised to scheme+host — path is dropped to keep
	// common token placements (Slack /services/.../<TOKEN>) out of
	// log output.
	assert.Contains(t, s, "https://example.com")
	assert.NotContains(t, s, "/hook", "path must be stripped from sanitised URL")
	// Header names are preserved so operators can see what's configured;
	// sensitive values are replaced with [REDACTED].
	assert.Contains(t, s, "Authorization")
	assert.Contains(t, s, "[REDACTED]")
	assert.NotContains(t, s, "super-secret-token")
	assert.NotContains(t, s, "Bearer")
}

func TestWebhookConfig_String_NoHeaders(t *testing.T) {
	cfg := webhook.Config{URL: "https://example.com/hook"}
	s := cfg.String()
	assert.Contains(t, s, "headers=map[]",
		"empty headers should appear as map[] (deterministic sorted form)")
}

func TestWebhookConfig_GoString_RedactsHeaders(t *testing.T) {
	cfg := webhook.Config{
		URL:     "https://example.com/hook",
		Headers: map[string]string{"Authorization": "Bearer secret-token-12345"},
	}
	out := fmt.Sprintf("%#v", cfg)
	assert.NotContains(t, out, "secret-token-12345", "GoString must not leak header values")
	assert.Contains(t, out, "WebhookConfig{")
}

func TestWebhookConfig_Format_RedactsHeaders(t *testing.T) {
	cfg := webhook.Config{
		URL:     "https://example.com/hook?api_key=leak-me",
		Headers: map[string]string{"Authorization": "Splunk my-hec-token"},
	}
	out := fmt.Sprintf("%+v", cfg)
	assert.NotContains(t, out, "my-hec-token", "Format must not leak header values via %%+v")
	assert.NotContains(t, out, "leak-me", "Format must not leak URL query values via %%+v")
	assert.NotContains(t, out, "api_key", "Format must not leak URL query keys via %%+v")
}

// TestWebhookConfig_String_RedactsURLQueryAndFragment verifies that
// common token placements in URL path, query, and fragment are dropped
// by Config.String(). Closes #475 AC #1.
func TestWebhookConfig_String_RedactsURLQueryAndFragment(t *testing.T) {
	tests := []struct {
		name       string
		url        string
		mustAppear string   // the sanitised URL that should appear
		mustNot    []string // substrings that must NOT appear
	}{
		{
			name:       "Slack path token",
			url:        "https://hooks.slack.com/services/T0A1B2/B0C1D2/XYZ-slack-secret",
			mustNot:    []string{"XYZ-slack-secret", "T0A1B2", "B0C1D2", "/services"},
			mustAppear: "https://hooks.slack.com",
		},
		{
			name:       "Datadog query API key",
			url:        "https://http-intake.logs.datadoghq.com/v1/input?dd-api-key=DD_APIKEY_123",
			mustNot:    []string{"DD_APIKEY_123", "dd-api-key", "/v1/input"},
			mustAppear: "https://http-intake.logs.datadoghq.com",
		},
		{
			name:       "Splunk HEC path token",
			url:        "https://splunk.example.com/services/collector/raw/TOKEN-SECRET",
			mustNot:    []string{"TOKEN-SECRET", "collector", "/services"},
			mustAppear: "https://splunk.example.com",
		},
		{
			name:       "Fragment with session",
			url:        "https://x.example.com/hook#session=sec-frag-leak",
			mustNot:    []string{"sec-frag-leak", "session=", "#"},
			mustAppear: "https://x.example.com",
		},
		{
			name:       "Invalid URL falls back to placeholder",
			url:        "::://not-a-url",
			mustNot:    []string{"not-a-url"},
			mustAppear: "<invalid-url>",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := webhook.Config{URL: tt.url}
			s := cfg.String()
			for _, forbidden := range tt.mustNot {
				assert.NotContains(t, s, forbidden,
					"String() leaked %q from URL %q", forbidden, tt.url)
			}
			assert.Contains(t, s, tt.mustAppear,
				"String() must include the sanitised form")
		})
	}
}

// TestWebhookConfig_String_RedactsCredentialHeaders verifies that
// header values are [REDACTED] when the header NAME matches the
// credential-pattern set (case-insensitive substring: auth, key,
// secret, token, cookie, password, credential, signature, hmac,
// session). Closes #475 AC #3 and AC #4.
func TestWebhookConfig_String_RedactsCredentialHeaders(t *testing.T) {
	cfg := webhook.Config{
		URL: "https://example.com",
		Headers: map[string]string{
			"Authorization":   "Bearer ABC-AUTH-LEAK",
			"X-API-Key":       "XYZ-KEY-LEAK",
			"X-Auth-Token":    "ATK-TRIPLE-LEAK",
			"Secret-Value":    "SEC-LEAK",
			"AUTHORIZATION":   "UPPERCASE-LEAK",
			"authorization":   "LOWERCASE-LEAK",
			"Cookie":          "SESSION=COOKIE-LEAK",
			"X-Hub-Signature": "sha256=SIG-LEAK",
			"X-Hmac":          "HMAC-LEAK",
			"X-Password":      "PASS-LEAK",
			"X-Credential":    "CRED-LEAK",
			"X-Session-Id":    "SESS-LEAK",
		},
	}
	s := cfg.String()
	for _, leak := range []string{
		"ABC-AUTH-LEAK",
		"XYZ-KEY-LEAK",
		"ATK-TRIPLE-LEAK",
		"SEC-LEAK",
		"UPPERCASE-LEAK",
		"LOWERCASE-LEAK",
		"COOKIE-LEAK",
		"SIG-LEAK",
		"HMAC-LEAK",
		"PASS-LEAK",
		"CRED-LEAK",
		"SESS-LEAK",
	} {
		assert.NotContains(t, s, leak,
			"sensitive header value leaked in String(): %q", leak)
	}
	// Every matching header should produce exactly one [REDACTED] marker,
	// and the header name is preserved.
	assert.Contains(t, s, "[REDACTED]")
	assert.Contains(t, s, "Authorization")
	assert.Contains(t, s, "Cookie")
	assert.Contains(t, s, "X-Hub-Signature")
}

// TestSanitiseClientError_RedactsURLInUrlError verifies that an
// *url.Error from http.Client.Do has its URL stripped to scheme+host
// before being logged. Closes #475 H1.
func TestSanitiseClientError_RedactsURLInUrlError(t *testing.T) {
	tests := []struct {
		name       string
		inputURL   string
		wantKept   string
		wantLeaked []string
	}{
		{
			name:       "Slack path token",
			inputURL:   "https://hooks.slack.com/services/T0A1B2/B0C1D2/XYZ-slack-secret",
			wantKept:   "https://hooks.slack.com",
			wantLeaked: []string{"XYZ-slack-secret", "T0A1B2", "/services"},
		},
		{
			name:       "Datadog query key",
			inputURL:   "https://http-intake.logs.datadoghq.com/v1/input?dd-api-key=DD_LEAK",
			wantKept:   "https://http-intake.logs.datadoghq.com",
			wantLeaked: []string{"DD_LEAK", "dd-api-key", "/v1/input"},
		},
		{
			name:       "Splunk HEC path token",
			inputURL:   "https://splunk.example.com/services/collector/raw/HEC-LEAK",
			wantKept:   "https://splunk.example.com",
			wantLeaked: []string{"HEC-LEAK", "collector"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inner := fmt.Errorf("connection refused")
			in := &url.Error{Op: "Post", URL: tt.inputURL, Err: inner}
			out := webhook.SanitiseClientError(in)

			msg := out.Error()
			assert.Contains(t, msg, "Post", "Op must survive")
			assert.Contains(t, msg, "connection refused", "inner err must survive")
			assert.Contains(t, msg, tt.wantKept)
			for _, leak := range tt.wantLeaked {
				assert.NotContains(t, msg, leak,
					"sanitiseClientError leaked %q", leak)
			}
		})
	}
}

// TestSanitiseClientError_PassesThroughNonUrlErrors verifies that
// plain errors not wrapping *url.Error are returned unchanged, and
// wrapped *url.Error is still reached via errors.As and redacted.
func TestSanitiseClientError_PassesThroughNonUrlErrors(t *testing.T) {
	plain := fmt.Errorf("plain error, no URL")
	got := webhook.SanitiseClientError(plain)
	assert.Equal(t, plain, got, "non-url errors must pass through unchanged")

	wrapped := fmt.Errorf("outer: %w", &url.Error{
		Op:  "Post",
		URL: "https://hooks.slack.com/services/T/B/LEAKED",
		Err: fmt.Errorf("timeout"),
	})
	gotWrapped := webhook.SanitiseClientError(wrapped)
	assert.NotContains(t, gotWrapped.Error(), "LEAKED",
		"wrapped url.Error must still be sanitised")
}

// TestWebhookConfig_String_PreservesNonSensitiveHeaders verifies that
// non-credential header values appear verbatim in String() so operators
// can see configured trace/content headers. Closes #475 AC Tests.
func TestWebhookConfig_String_PreservesNonSensitiveHeaders(t *testing.T) {
	cfg := webhook.Config{
		URL: "https://example.com",
		Headers: map[string]string{
			"X-Request-Id":    "trace-42",
			"Content-Type":    "application/json",
			"User-Agent":      "audit/v1",
			"Accept-Encoding": "gzip",
		},
	}
	s := cfg.String()
	for _, wanted := range []string{
		"trace-42",
		"application/json",
		"audit/v1",
		"gzip",
	} {
		assert.Contains(t, s, wanted,
			"non-sensitive header value unexpectedly dropped from String(): %q", wanted)
	}
	assert.NotContains(t, s, "[REDACTED]",
		"no [REDACTED] marker expected when all header names are non-sensitive")
}

// TestWebhook_ConstructionWarningsRoutedToInjectedLogger verifies that
// TLS-policy warnings emitted during New() route through the
// WithDiagnosticLogger-supplied logger rather than slog.Default().
// Closes #490.
//
// AllowTLS12 + AllowWeakCiphers triggers the "weak ciphers permitted"
// warning inside audit.TLSPolicy.Apply — the only code path in the
// TLS policy that emits a warning. Matches the syslog, loki, and
// file peer tests for consistent assertion phrasing.
func TestWebhook_ConstructionWarningsRoutedToInjectedLogger(t *testing.T) {
	var buf strings.Builder
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})
	injected := slog.New(handler)

	out, err := webhook.New(&webhook.Config{
		URL:                "https://example.com/events",
		TLSPolicy:          &audit.TLSPolicy{AllowTLS12: true, AllowWeakCiphers: true},
		AllowPrivateRanges: true,
		BatchSize:          1,
		FlushInterval:      10 * time.Millisecond,
		Timeout:            1 * time.Second,
		BufferSize:         10,
	}, nil, webhook.WithDiagnosticLogger(injected))
	require.NoError(t, err)
	require.NoError(t, out.Close())

	logged := buf.String()
	assert.Contains(t, logged, "weak ciphers",
		"expected weak-ciphers warning on injected logger, got: %q", logged)
	assert.Contains(t, logged, "output=webhook",
		"warning should carry output=webhook attribute: %q", logged)
}

// TestWebhook_SetDiagnosticLoggerUnderEventLoad was removed in #696
// along with the post-construction SetDiagnosticLogger API. The
// diagnostic logger is now fixed at construction via
// [webhook.WithDiagnosticLogger].

// TestWebhook_NilDiagnosticLoggerFallsBackToDefault verifies that
// WithDiagnosticLogger(nil) does not nil-deref and falls back to
// slog.Default for warning emission.
func TestWebhook_NilDiagnosticLoggerFallsBackToDefault(t *testing.T) {
	// Capture slog.Default temporarily.
	var buf strings.Builder
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	out, err := webhook.New(&webhook.Config{
		URL:                "https://example.com/events",
		TLSPolicy:          &audit.TLSPolicy{AllowTLS12: true, AllowWeakCiphers: true},
		AllowPrivateRanges: true,
		BatchSize:          1,
		FlushInterval:      10 * time.Millisecond,
		Timeout:            1 * time.Second,
		BufferSize:         10,
	}, nil, webhook.WithDiagnosticLogger(nil))
	require.NoError(t, err)
	require.NoError(t, out.Close())

	assert.Contains(t, buf.String(), "TLS",
		"WithDiagnosticLogger(nil) should fall back to slog.Default")
}

// TestWebhookClient_ResponseHeaderTimeoutHasFloor verifies that the
// transport's ResponseHeaderTimeout is never less than 1 second even
// when cfg.Timeout is absurdly small. Exercises the floor added for
// #485 — without it a misconfigured 1 ms Timeout would produce a
// 500 μs per-stage timeout that could not complete a real TLS
// handshake + server response.
func TestWebhookClient_ResponseHeaderTimeoutHasFloor(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		timeout time.Duration
		want    time.Duration
	}{
		{"tiny_1ms_floors_to_1s", 1 * time.Millisecond, 1 * time.Second},
		{"sub_floor_1500ms_floors_to_1s", 1500 * time.Millisecond, 1 * time.Second},
		{"exactly_2s_at_floor", 2 * time.Second, 1 * time.Second},
		{"20s_uses_half_10s", 20 * time.Second, 10 * time.Second},
		{"5min_uses_half_2m30s", 5 * time.Minute, 2*time.Minute + 30*time.Second},
		{"zero_floors_to_1s", 0, 1 * time.Second},
		{"negative_floors_to_1s", -5 * time.Second, 1 * time.Second},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := webhook.ResponseHeaderTimeout(tc.timeout)
			assert.Equal(t, tc.want, got,
				"ResponseHeaderTimeout(%v) = %v; want %v", tc.timeout, got, tc.want)
		})
	}

	assert.Equal(t, 1*time.Second, webhook.MinResponseHeaderTimeout,
		"floor constant must be 1 second for #485 contract")
}

// TestClient_RedirectBodyDrainCapped_Webhook verifies that a non-redirect
// 3xx response (HTTP 300 Multiple Choices) with a 10 MiB body has its
// client-side body drain capped at 4 KiB. Our CheckRedirect blocks
// 301/302/303/307/308 inside the stdlib (which already slurps ≤ 2 KiB),
// but any other 3xx status reaches our doPost defer-drain unmodified —
// without the cap the client would read up to maxResponseDrain (1 MiB)
// per retry from an attacker-controlled endpoint. See #484.
func TestClient_RedirectBodyDrainCapped_Webhook(t *testing.T) {
	const (
		bodySize = 10 << 20 // 10 MiB
		// Kernel TCP send buffers on Linux can grow to ~2 MiB via autotuning,
		// plus whatever the server flushed before the client closed the
		// connection. 4 MiB is comfortably below the 10 MiB body and proves
		// the cap prevented a full drain.
		maxExpected = 4 << 20
	)

	var bytesWritten atomic.Int64
	chunk := bytes.Repeat([]byte("X"), 4096)

	handlerDone := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		defer close(handlerDone)
		// Chunked transfer (no Content-Length) avoids "superfluous
		// WriteHeader" log noise when the client closes after the cap.
		w.WriteHeader(http.StatusMultipleChoices) // 300 — no redirect-follow
		flusher, _ := w.(http.Flusher)
		remaining := bodySize
		for remaining > 0 {
			toWrite := len(chunk)
			if toWrite > remaining {
				toWrite = remaining
			}
			n, err := w.Write(chunk[:toWrite])
			bytesWritten.Add(int64(n))
			if err != nil {
				return // client closed
			}
			if flusher != nil {
				flusher.Flush()
			}
			remaining -= n
		}
	}))
	t.Cleanup(srv.Close)

	out := newTestWebhookOutput(t, srv.URL, func(cfg *webhook.Config) {
		cfg.BatchSize = 1
		cfg.MaxRetries = 1 // 3xx is treated as client error (non-retryable)
	})

	require.NoError(t, out.Write([]byte(`{"event":"drain_cap"}`+"\n")))
	require.NoError(t, out.Close())

	// Wait for the server handler to return (so bytesWritten has settled)
	// — it exits quickly once the client closes the connection after
	// reading its capped 4 KiB.
	select {
	case <-handlerDone:
	case <-time.After(10 * time.Second):
		t.Fatal("server handler did not terminate within 10s")
	}

	written := bytesWritten.Load()
	assert.Less(t, written, int64(maxExpected),
		"server wrote %d bytes; client should have capped drain at 4 KiB", written)
}

// TestNew_NilConfig_ReturnsError verifies that [New] returns a
// non-nil error when passed a nil *Config. Nil-guard added for
// consistency with file.New / loki.New (#580 follow-up).
func TestNew_NilConfig_ReturnsError(t *testing.T) {
	t.Parallel()
	_, err := webhook.New(nil, nil)
	require.Error(t, err)
	// text-only: webhook.go:169 returns raw fmt.Errorf without a sentinel wrap.
	assert.Contains(t, err.Error(), "config must not be nil")
}

// TestWebhookOutput_Delivery_ExactEventCount pins the contract
// that every enqueued event reaches the receiver — the
// observable count is "events on the wire" (sum of NDJSON lines
// across all requests), not "requests" (which depends on
// batching policy). After N writes and Close, the server must
// observe exactly N event lines. Off-by-one errors in the batch
// flush logic surface here. (#565 G5).
func TestWebhookOutput_Delivery_ExactEventCount(t *testing.T) {
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	const n = 10
	out := newTestWebhookOutput(t, srv.url(), func(c *webhook.Config) {
		c.BatchSize = 1 // request per event
		c.FlushInterval = 50 * time.Millisecond
		c.MaxRetries = 1
	})
	for i := 0; i < n; i++ {
		require.NoError(t, out.Write([]byte(fmt.Sprintf(`{"event":"e%d"}`+"\n", i))))
	}
	require.NoError(t, out.Close())

	// Count event-marker substrings across all received bodies.
	// Whether the webhook batches into fewer NDJSON-bundled
	// requests or sends one per event, exactly N markers must
	// appear on the wire.
	srv.mu.Lock()
	defer srv.mu.Unlock()
	totalEvents := 0
	for _, req := range srv.requests {
		totalEvents += strings.Count(string(req.Body), `"event":"e`)
	}
	assert.Equal(t, n, totalEvents,
		"every enqueued event must reach the wire — got %d event markers across %d requests, want %d",
		totalEvents, len(srv.requests), n)
}

// TestWebhookOutput_NDJSON_MultiLinePayloadRejected pins the
// contract that an event payload containing a newline survives
// the wire round-trip without splitting the receiver's
// per-line parser. The audit-side serialiser produces
// newline-terminated JSON; an embedded literal newline within a
// JSON field value must be escaped as \n in the JSON output (Go
// encoding/json contract), so the receiver sees a single JSON
// document on the line and parses it cleanly. (#565 G5).
func TestWebhookOutput_NDJSON_MultiLinePayloadRejected(t *testing.T) {
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	out := newTestWebhookOutput(t, srv.url(), func(c *webhook.Config) {
		c.BatchSize = 1
		c.FlushInterval = 50 * time.Millisecond
		c.MaxRetries = 1
	})

	// Send a payload that already contains an escaped newline
	// in its JSON encoding. The audit caller is responsible for
	// producing valid JSON with embedded \n escapes — the
	// webhook output forwards bytes verbatim. The wire test
	// asserts that the bytes reach the server intact (single
	// request, body containing the escaped newline).
	payload := []byte(`{"event":"multi","msg":"line1\nline2"}` + "\n")
	require.NoError(t, out.Write(payload))
	require.NoError(t, out.Close())

	require.True(t, srv.waitForRequests(1, 3*time.Second))
	srv.mu.Lock()
	require.Len(t, srv.requests, 1, "exactly one request must reach the server")
	body := srv.requests[0].Body
	srv.mu.Unlock()

	// Parse the body as JSON — the escaped \n must NOT split
	// the parser. A parse failure indicates the multi-line
	// content was incorrectly forwarded as a literal newline.
	var decoded map[string]any
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(body), &decoded),
		"body must parse as a single JSON document; embedded \\n must remain escaped")
	assert.Equal(t, "line1\nline2", decoded["msg"],
		"the embedded newline must round-trip as a single string value")
}

// ---------------------------------------------------------------------------
// Issue #696 acceptance criteria — factory FrameworkContext plumbing
// ---------------------------------------------------------------------------

// TestOutputFactory_ZeroContext_NoPanic verifies the webhook factory
// tolerates a zero-value [audit.FrameworkContext]. Construct via
// factory pointing at a test server; write once; no panic.
func TestOutputFactory_ZeroContext_NoPanic(t *testing.T) {
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	yaml := []byte("url: " + srv.url() + "\nallow_insecure_http: true\nallow_private_ranges: true\nbatch_size: 1\nflush_interval: 50ms\ntimeout: 5s\n")

	factory := audit.LookupOutputFactory("webhook")
	require.NotNil(t, factory)

	out, err := factory("zero", yaml, audit.FrameworkContext{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	require.NoError(t, out.Write([]byte(`{"event":"zero"}`)))
}

// webhookCaptureHandler records every slog Record passed through
// Handle for assertion in factory plumbing tests.
type webhookCaptureHandler struct {
	records []slog.Record
	mu      sync.Mutex
}

func (h *webhookCaptureHandler) Enabled(_ context.Context, _ slog.Level) bool { return true }
func (h *webhookCaptureHandler) Handle(_ context.Context, r slog.Record) error { //nolint:gocritic // hugeParam: slog.Handler interface contract
	h.mu.Lock()
	h.records = append(h.records, r)
	h.mu.Unlock()
	return nil
}
func (h *webhookCaptureHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }
func (h *webhookCaptureHandler) WithGroup(_ string) slog.Handler      { return h }

func (h *webhookCaptureHandler) anyContains(s string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for i := range h.records {
		if strings.Contains(h.records[i].Message, s) {
			return true
		}
	}
	return false
}

// TestOutputFactory_LoggerReachesOutput verifies the webhook output
// uses the diagnostic logger from FrameworkContext. Provoke a TLS
// policy warning at construction (allow_tls12 + allow_weak_ciphers
// against an HTTPS URL) and assert the captured handler observed it.
func TestOutputFactory_LoggerReachesOutput(t *testing.T) {
	t.Parallel()
	h := &webhookCaptureHandler{}
	logger := slog.New(h)

	yaml := []byte(
		"url: https://example.com/events\n" +
			"tls_policy:\n" +
			"  allow_tls12: true\n" +
			"  allow_weak_ciphers: true\n" +
			"batch_size: 1\nflush_interval: 1s\ntimeout: 5s\n",
	)

	factory := audit.LookupOutputFactory("webhook")
	require.NotNil(t, factory)

	out, err := factory("logger", yaml, audit.FrameworkContext{DiagnosticLogger: logger})
	if err == nil {
		t.Cleanup(func() { _ = out.Close() })
	}

	assert.True(t, h.anyContains("weak"),
		"injected logger must capture the weak-cipher TLS warning emitted in New")
}

// TestOutputFactory_OutputMetricsReachesOutput verifies that the
// per-output metrics value supplied via
// [audit.FrameworkContext.OutputMetrics] reaches the webhook output.
func TestOutputFactory_OutputMetricsReachesOutput(t *testing.T) {
	t.Parallel()
	om := newMockOutputMetrics()

	// Server that 500s every request so the retry/error path runs.
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	yaml := []byte("url: " + srv.url() +
		"\nallow_insecure_http: true\nallow_private_ranges: true" +
		"\nbatch_size: 1\nflush_interval: 5ms\ntimeout: 1s\nmax_retries: 1\n")

	factory := audit.LookupOutputFactory("webhook")
	require.NotNil(t, factory)

	out, err := factory("metrics", yaml, audit.FrameworkContext{OutputMetrics: om})
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte(`{"event":"err"}`)))
	require.NoError(t, out.Close())

	// Either errors (delivery failure) or drops (buffer full) must
	// have been recorded — the contract is "the metrics value
	// reached the output".
	total := om.getDrops() + om.getErrors()
	assert.Positive(t, total,
		"per-output metrics value supplied via FrameworkContext must record drops or errors")
}
