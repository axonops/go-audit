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

package loki_test

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/axonops/audit"
	"github.com/axonops/audit/loki"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// lokiTestServer creates an httptest.Server that returns 204 on every
// request. The server URL is returned for use in Config.URL.
func lokiTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// validConfig returns a minimal Config suitable for testing, pointing
// at the provided test server URL.
func validConfig() *loki.Config {
	return validConfigWithURL("http://localhost:3100/loki/api/v1/push")
}

// validConfigWithURL returns a Config pointing at the given URL.
// DisableStartupVerification is set so existing tests that point at
// arbitrary (sometimes unreachable) URLs continue to exercise the
// constructor without contacting the destination — the probe-time
// behaviour has its own dedicated coverage in TestNew_StartupProbe_*.
func validConfigWithURL(url string) *loki.Config {
	return &loki.Config{
		URL:                        url,
		AllowInsecureHTTP:          true,
		AllowPrivateRanges:         true,
		BatchSize:                  100,
		FlushInterval:              1 * time.Second,
		Timeout:                    5 * time.Second,
		MaxRetries:                 1,
		BufferSize:                 1000,
		Gzip:                       true,
		DisableStartupVerification: true,
	}
}

// ---------------------------------------------------------------------------
// New() — constructor tests
// ---------------------------------------------------------------------------

func TestNew_ValidConfig(t *testing.T) {
	t.Parallel()

	out, err := loki.New(validConfig(), nil)
	require.NoError(t, err)
	require.NotNil(t, out)
	require.NoError(t, out.Close())
}

func TestNew_InvalidConfig(t *testing.T) {
	t.Parallel()

	cfg := &loki.Config{} // empty URL
	_, err := loki.New(cfg, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrConfigInvalid)
}

func TestNew_ConfigCopied(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	originalURL := cfg.URL
	out, err := loki.New(cfg, nil)
	require.NoError(t, err)

	// Mutating the original config must not affect the output.
	cfg.URL = "http://mutated:9999/bad"
	assert.Equal(t, "loki:localhost:3100", out.Name(),
		"Output name should use the original URL, not the mutated one")
	_ = originalURL
	require.NoError(t, out.Close())
}

// ---------------------------------------------------------------------------
// Name() and DestinationKey()
// ---------------------------------------------------------------------------

func TestOutput_Name(t *testing.T) {
	t.Parallel()

	out, err := loki.New(validConfig(), nil)
	require.NoError(t, err)
	assert.Equal(t, "loki:localhost:3100", out.Name())
	require.NoError(t, out.Close())
}

func TestOutput_DestinationKey(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	cfg.URL = "http://loki.example.com:3100/loki/api/v1/push?token=secret#frag"
	out, err := loki.New(cfg, nil)
	require.NoError(t, err)
	assert.Equal(t, "http://loki.example.com:3100/loki/api/v1/push",
		out.DestinationKey(),
		"DestinationKey must strip query params and fragment")
	require.NoError(t, out.Close())
}

// ---------------------------------------------------------------------------
// ReportsDelivery()
// ---------------------------------------------------------------------------

func TestOutput_ReportsDelivery(t *testing.T) {
	t.Parallel()

	out, err := loki.New(validConfig(), nil)
	require.NoError(t, err)
	assert.True(t, out.ReportsDelivery(),
		"Loki output must report its own delivery metrics")
	require.NoError(t, out.Close())
}

// ---------------------------------------------------------------------------
// Interface assertions
// ---------------------------------------------------------------------------

func TestOutput_ImplementsInterfaces(t *testing.T) {
	t.Parallel()

	out, err := loki.New(validConfig(), nil)
	require.NoError(t, err)
	defer func() { require.NoError(t, out.Close()) }()

	// These are compile-time checks too (var _ blocks in loki.go),
	// but runtime verification confirms the factory returns the right type.
	assert.Implements(t, (*audit.Output)(nil), out)
	assert.Implements(t, (*audit.MetadataWriter)(nil), out)
	assert.Implements(t, (*audit.DeliveryReporter)(nil), out)
	assert.Implements(t, (*audit.DestinationKeyer)(nil), out)
}

// TestOutput_SetFrameworkFields was removed in #696 along with the
// SetFrameworkFields API. Framework fields are now baked into the
// Output at construction via [loki.WithFrameworkContext].

// TestOutput_FrameworkContextOption verifies that WithFrameworkContext
// is honoured at construction without panicking — replaces the prior
// SetFrameworkFields no-panic smoke test.
func TestOutput_FrameworkContextOption(t *testing.T) {
	t.Parallel()

	out, err := loki.New(validConfig(), nil, loki.WithFrameworkContext(audit.FrameworkContext{
		AppName:  "myapp",
		Host:     "prod-01",
		Timezone: "UTC",
		PID:      12345,
	}))
	require.NoError(t, err)
	require.NoError(t, out.Close())
}

// ---------------------------------------------------------------------------
// Write() and WriteWithMetadata()
// ---------------------------------------------------------------------------

func TestOutput_Write(t *testing.T) {
	t.Parallel()

	out, err := loki.New(validConfig(), nil)
	require.NoError(t, err)

	err = out.Write([]byte(`{"event":"test"}`))
	assert.NoError(t, err, "Write should succeed on a valid output")
	require.NoError(t, out.Close())
}

func TestOutput_WriteWithMetadata(t *testing.T) {
	t.Parallel()

	out, err := loki.New(validConfig(), nil)
	require.NoError(t, err)

	meta := audit.EventMetadata{
		EventType: "user_login",
		Severity:  6,
		Category:  "authentication",
		Timestamp: time.Now(),
	}
	err = out.WriteWithMetadata([]byte(`{"actor_id":"alice"}`), meta)
	assert.NoError(t, err, "WriteWithMetadata should succeed on a valid output")
	require.NoError(t, out.Close())
}

func TestOutput_WriteAfterClose(t *testing.T) {
	t.Parallel()

	out, err := loki.New(validConfig(), nil)
	require.NoError(t, err)
	require.NoError(t, out.Close())

	err = out.Write([]byte(`{"event":"test"}`))
	assert.ErrorIs(t, err, audit.ErrOutputClosed,
		"Write after Close must return ErrOutputClosed")

	err = out.WriteWithMetadata([]byte(`{"event":"test"}`), audit.EventMetadata{})
	assert.ErrorIs(t, err, audit.ErrOutputClosed,
		"WriteWithMetadata after Close must return ErrOutputClosed")
}

func TestOutput_ConcurrentWriteAndClose(t *testing.T) {
	t.Parallel()

	srv := lokiTestServer(t)
	cfg := validConfigWithURL(srv.URL)
	cfg.BufferSize = 10000

	out, err := loki.New(cfg, nil)
	require.NoError(t, err)

	// Launch 50 goroutines writing concurrently.
	var wg sync.WaitGroup
	for g := 0; g < 50; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				_ = out.Write([]byte(`{"event":"concurrent"}`))
			}
		}()
	}

	// Close while writers are still running.
	require.NoError(t, out.Close())

	// Wait for all writers to finish.
	wg.Wait()

	// Post-close writes must return ErrOutputClosed (no panic).
	err = out.Write([]byte(`{"event":"after_close"}`))
	assert.ErrorIs(t, err, audit.ErrOutputClosed)
}

// ---------------------------------------------------------------------------
// Close() — idempotent
// ---------------------------------------------------------------------------

func TestOutput_CloseIdempotent(t *testing.T) {
	t.Parallel()

	out, err := loki.New(validConfig(), nil)
	require.NoError(t, err)

	require.NoError(t, out.Close(), "first Close")
	require.NoError(t, out.Close(), "second Close must be idempotent")
	require.NoError(t, out.Close(), "third Close must be idempotent")
}

// ---------------------------------------------------------------------------
// Buffer full — drop behaviour
// ---------------------------------------------------------------------------

func TestOutput_BufferFull_DropsEvent(t *testing.T) {
	t.Parallel()

	srv := lokiTestServer(t)
	metrics := &testOutputMetrics{}
	cfg := validConfigWithURL(srv.URL)
	cfg.BufferSize = loki.MinBufferSize  // smallest allowed buffer (100)
	cfg.BatchSize = loki.MaxBatchSize    // prevent size-based flush
	cfg.FlushInterval = 10 * time.Second // prevent timer-based flush

	out, err := loki.New(cfg, nil, loki.WithOutputMetrics(metrics))
	require.NoError(t, err)

	// Write from multiple goroutines to overwhelm the buffer faster
	// than the batch goroutine can drain it.
	data := []byte(`{"event":"fill"}`)
	var wg sync.WaitGroup
	for g := 0; g < 10; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				_ = out.Write(data)
			}
		}()
	}
	wg.Wait()

	require.True(t, metrics.waitForDrops(1, 2*time.Second),
		"at least some events should be dropped when buffer is full")

	require.NoError(t, out.Close())
}

// TestOutput_BufferFull_DoesNotRecordCoreEventError verifies the B-25
// contract: buffer-full drops surface only via OutputMetrics.RecordDrop
// and MUST NOT call core Metrics.RecordDelivery(EventError). Delivery
// errors (retry exhausted) still use RecordDelivery(EventError) — this
// test guards the buffer-drop path only.
func TestOutput_BufferFull_DoesNotRecordCoreEventError(t *testing.T) {
	t.Parallel()

	srv := lokiTestServer(t)
	coreMetrics := &mockCoreMetrics{}
	outMetrics := &testOutputMetrics{}
	cfg := validConfigWithURL(srv.URL)
	cfg.BufferSize = loki.MinBufferSize  // smallest allowed buffer (100)
	cfg.BatchSize = loki.MaxBatchSize    // prevent size-based flush
	cfg.FlushInterval = 10 * time.Second // prevent timer-based flush

	out, err := loki.New(cfg, coreMetrics, loki.WithOutputMetrics(outMetrics))
	require.NoError(t, err)

	data := []byte(`{"event":"fill"}`)
	var wg sync.WaitGroup
	for g := 0; g < 10; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				_ = out.Write(data)
			}
		}()
	}
	wg.Wait()

	require.True(t, outMetrics.waitForDrops(1, 2*time.Second),
		"at least some events must drop when buffer is full")

	require.NoError(t, out.Close())

	assert.Equal(t, 0, coreMetrics.errorCount(),
		"buffer-full drops must not call core Metrics.RecordDelivery(EventError) (B-25); use OutputMetrics.RecordDrop")
}

// ---------------------------------------------------------------------------
// Flush metrics — batch goroutine records flushes
// ---------------------------------------------------------------------------

func TestOutput_FlushOnClose(t *testing.T) {
	t.Parallel()

	srv := lokiTestServer(t)
	metrics := &testOutputMetrics{}
	cfg := validConfigWithURL(srv.URL)
	cfg.FlushInterval = 10 * time.Second // prevent timer flush

	out, err := loki.New(cfg, nil, loki.WithOutputMetrics(metrics))
	require.NoError(t, err)

	// Write a few events, then close.
	for i := 0; i < 5; i++ {
		require.NoError(t, out.Write([]byte(`{"event":"flush_test"}`)))
	}

	require.NoError(t, out.Close())

	assert.Greater(t, metrics.flushCount(), 0,
		"Close must flush remaining events")
}

func TestOutput_FlushOnBatchSize(t *testing.T) {
	t.Parallel()

	srv := lokiTestServer(t)
	metrics := &testOutputMetrics{}
	cfg := validConfigWithURL(srv.URL)
	cfg.BatchSize = 5
	cfg.FlushInterval = 10 * time.Second // prevent timer flush

	out, err := loki.New(cfg, nil, loki.WithOutputMetrics(metrics))
	require.NoError(t, err)

	// Write exactly BatchSize events to trigger a flush.
	for i := 0; i < cfg.BatchSize; i++ {
		require.NoError(t, out.Write([]byte(`{"event":"batch_size_test"}`)))
	}

	require.True(t, metrics.waitForFlush(1, 2*time.Second),
		"batch goroutine must flush when BatchSize is reached")

	require.NoError(t, out.Close())
}

func TestOutput_FlushOnTimer(t *testing.T) {
	t.Parallel()

	srv := lokiTestServer(t)
	metrics := &testOutputMetrics{}
	cfg := validConfigWithURL(srv.URL)
	cfg.BatchSize = 10000                      // large, prevent size-based flush
	cfg.FlushInterval = 200 * time.Millisecond // short timer

	out, err := loki.New(cfg, nil, loki.WithOutputMetrics(metrics))
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte(`{"event":"timer_test"}`)))

	require.True(t, metrics.waitForFlush(1, 2*time.Second),
		"batch goroutine must flush when FlushInterval elapses")

	require.NoError(t, out.Close())
}

func TestOutput_FlushOnMaxBatchBytes(t *testing.T) {
	t.Parallel()

	srv := lokiTestServer(t)
	metrics := &testOutputMetrics{}
	cfg := validConfigWithURL(srv.URL)
	cfg.BatchSize = 10000                     // large, prevent count-based flush
	cfg.MaxBatchBytes = loki.MinMaxBatchBytes // smallest allowed byte threshold (1024)
	cfg.FlushInterval = 10 * time.Second      // prevent timer flush

	out, err := loki.New(cfg, nil, loki.WithOutputMetrics(metrics))
	require.NoError(t, err)

	// Each event is ~22 bytes; 1024 / 22 ≈ 46 events to trigger.
	// Write enough to trigger at least one mid-batch flush.
	for i := 0; i < 100; i++ {
		require.NoError(t, out.Write([]byte(`{"event":"bytes_test"}`)))
	}

	require.True(t, metrics.waitForFlush(1, 2*time.Second),
		"MaxBatchBytes threshold should trigger a flush")

	require.NoError(t, out.Close())

	assert.Greater(t, metrics.flushCount(), 1,
		"MaxBatchBytes should trigger flush before final Close flush")
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// testOutputMetrics implements audit.OutputMetrics for loki tests.
type testOutputMetrics struct {
	mu        sync.Mutex
	dropCount int
	flushN    int
}

func (m *testOutputMetrics) RecordDrop() {
	m.mu.Lock()
	m.dropCount++
	m.mu.Unlock()
}

func (m *testOutputMetrics) RecordFlush(_ int, _ time.Duration) {
	m.mu.Lock()
	m.flushN++
	m.mu.Unlock()
}

func (m *testOutputMetrics) RecordError()              {}
func (m *testOutputMetrics) RecordRetry(_ int)         {}
func (m *testOutputMetrics) RecordQueueDepth(_, _ int) {}

func (m *testOutputMetrics) drops() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.dropCount
}

func (m *testOutputMetrics) flushCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.flushN
}

func (m *testOutputMetrics) waitForFlush(n int, timeout time.Duration) bool {
	deadline := time.After(timeout)
	for {
		if m.flushCount() >= n {
			return true
		}
		select {
		case <-deadline:
			return false
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func (m *testOutputMetrics) waitForDrops(n int, timeout time.Duration) bool {
	deadline := time.After(timeout)
	for {
		if m.drops() >= n {
			return true
		}
		select {
		case <-deadline:
			return false
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// ---------------------------------------------------------------------------
// Issue #696 acceptance criteria — factory FrameworkContext plumbing
// ---------------------------------------------------------------------------

// TestOutputFactory_ZeroContext_NoPanic verifies the loki factory
// tolerates a zero-value [audit.FrameworkContext]. Construct via
// factory pointing at the test server; write once; no panic.
func TestOutputFactory_ZeroContext_NoPanic(t *testing.T) {
	srv := lokiTestServer(t)
	yaml := []byte("url: " + srv.URL + "/loki/api/v1/push" +
		"\nallow_insecure_http: true\nallow_private_ranges: true" +
		"\nbatch_size: 1\nflush_interval: 100ms\ntimeout: 5s\n")

	factory := audit.LookupOutputFactory("loki")
	require.NotNil(t, factory)

	out, err := factory("zero", yaml, audit.FrameworkContext{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	require.NoError(t, out.Write([]byte(`{"event":"zero"}`)))
}

// lokiCaptureHandler records every slog Record passed through Handle
// for assertion in factory plumbing tests.
type lokiCaptureHandler struct {
	records []slog.Record
	mu      sync.Mutex
}

func (h *lokiCaptureHandler) Enabled(_ context.Context, _ slog.Level) bool { return true }
func (h *lokiCaptureHandler) Handle(_ context.Context, r slog.Record) error { //nolint:gocritic // hugeParam: slog.Handler interface contract
	h.mu.Lock()
	h.records = append(h.records, r)
	h.mu.Unlock()
	return nil
}
func (h *lokiCaptureHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }
func (h *lokiCaptureHandler) WithGroup(_ string) slog.Handler      { return h }

func (h *lokiCaptureHandler) anyContains(s string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for i := range h.records {
		if strings.Contains(h.records[i].Message, s) {
			return true
		}
	}
	return false
}

// TestOutputFactory_LoggerReachesOutput verifies the loki output
// uses the diagnostic logger from FrameworkContext. Provoke a TLS
// policy warning by combining allow_tls12 + allow_weak_ciphers
// against an HTTPS URL; the warning is emitted by buildLokiTLSConfig
// during construction.
func TestOutputFactory_LoggerReachesOutput(t *testing.T) {
	t.Parallel()
	h := &lokiCaptureHandler{}
	logger := slog.New(h)

	yaml := []byte(
		"url: https://loki.example.com/loki/api/v1/push\n" +
			"verify_on_startup: false\n" +
			"tls_policy:\n" +
			"  allow_tls12: true\n" +
			"  allow_weak_ciphers: true\n" +
			"batch_size: 1\nflush_interval: 1s\ntimeout: 5s\n",
	)

	factory := audit.LookupOutputFactory("loki")
	require.NotNil(t, factory)

	out, err := factory("logger", yaml, audit.FrameworkContext{DiagnosticLogger: logger})
	if err == nil {
		t.Cleanup(func() { _ = out.Close() })
	}

	assert.True(t, h.anyContains("weak"),
		"injected logger must capture the weak-cipher TLS warning")
}

// TestOutputFactory_OutputMetricsReachesOutput verifies that the
// per-output metrics value supplied via
// [audit.FrameworkContext.OutputMetrics] reaches the loki output.
func TestOutputFactory_OutputMetricsReachesOutput(t *testing.T) {
	t.Parallel()
	om := newOutputMetricsCollector()

	// Server that 500s every request so the retry/error path runs.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	yaml := []byte("url: " + srv.URL + "/loki/api/v1/push" +
		"\nallow_insecure_http: true\nallow_private_ranges: true" +
		"\nbatch_size: 1\nflush_interval: 100ms\ntimeout: 1s\nmax_retries: 1\n")

	factory := audit.LookupOutputFactory("loki")
	require.NotNil(t, factory)

	out, err := factory("metrics", yaml, audit.FrameworkContext{OutputMetrics: om})
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte(`{"event":"err"}`)))
	require.NoError(t, out.Close())

	total := om.drops() + om.errors()
	assert.Positive(t, total,
		"per-output metrics value supplied via FrameworkContext must record drops or errors")
}

// outputMetricsCollector implements audit.OutputMetrics for the AC
// tests. Distinct from the existing http_test.go mocks; standalone so
// the AC tests are self-contained.
type outputMetricsCollector struct {
	audit.NoOpOutputMetrics
	mu        sync.Mutex
	dropCount int
	errCount  int
}

func newOutputMetricsCollector() *outputMetricsCollector {
	return &outputMetricsCollector{}
}

func (m *outputMetricsCollector) RecordDrop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dropCount++
}
func (m *outputMetricsCollector) RecordError() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.errCount++
}
func (m *outputMetricsCollector) drops() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.dropCount
}
func (m *outputMetricsCollector) errors() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.errCount
}
