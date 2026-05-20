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

package splunk_test

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/audit/splunk"
)

// TestOutput_ResponseContentLengthOverCap_Rejected (AC 70) — a
// server that advertises a Content-Length larger than the per-
// endpoint cap is rejected without the client allocating the
// claimed buffer. The TCP connection is closed, not returned to
// the idle pool.
func TestOutput_ResponseContentLengthOverCap_Rejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/services/collector/health" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"text":"HEC is healthy","code":17}`))
			return
		}
		// Advertise a huge Content-Length but only write the small
		// body. The cap is 64 KiB; we claim 1 MiB.
		w.Header().Set("Content-Length", "1048576")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"text":"Success","code":0}`))
	}))
	defer srv.Close()

	rec := &recordingMetrics{}
	cfg := validCfg(srv.URL)
	cfg.MaxRetries = 0
	out, err := splunk.New(cfg, nil, splunk.WithOutputMetrics(rec))
	require.NoError(t, err)
	defer func() { _ = out.Close() }()

	require.NoError(t, out.Write([]byte(`{"event_type":"x"}`)))
	// Wait for the batch loop to process — assert.Eventually
	// because the drop is recorded by the goroutine, not the Write
	// caller.
	assert.Eventually(t, func() bool {
		return rec.drops.Load() >= 1
	}, 2*time.Second, 50*time.Millisecond,
		"expected the over-cap response to record a drop metric")
}

// TestOutput_ResponseContentLengthUnknown_StillBounded (AC 70) —
// a server that uses chunked transfer encoding (no Content-Length,
// resp.ContentLength == -1) is NOT rejected by the header check;
// the io.LimitReader at the body-read site is the load-bearing
// cap. Verifies the fast-fail does not over-reach.
func TestOutput_ResponseContentLengthUnknown_StillBounded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/services/collector/health" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"text":"HEC is healthy","code":17}`))
			return
		}
		// Force chunked by writing in stages; Go's net/http sets
		// Transfer-Encoding: chunked when no Content-Length is set
		// and the handler writes before its response is finalized.
		flusher, ok := w.(http.Flusher)
		require.True(t, ok)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"text":"Suc`))
		flusher.Flush()
		_, _ = w.Write([]byte(`cess","code":0}`))
	}))
	defer srv.Close()

	rec := &recordingMetrics{}
	out, err := splunk.New(validCfg(srv.URL), nil, splunk.WithOutputMetrics(rec))
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte(`{"event_type":"x"}`)))
	require.NoError(t, out.Close())
	// No drop — the chunked response decoded fine via the
	// LimitReader; the fast-fail short-circuit correctly passed
	// through Content-Length == -1.
	assert.Zero(t, rec.drops.Load(),
		"chunked response should not be over-cap rejected")
	assert.GreaterOrEqual(t, int(rec.flushes.Load()), 1,
		"chunked response should be treated as success")
}

// TestOutput_NetworkFailures_ConnectionRefused — server isn't
// listening. The output retries per the policy then drops.
func TestOutput_NetworkFailures_ConnectionRefused(t *testing.T) {
	// Pick a port, immediately release it. Subsequent dials get
	// ECONNREFUSED synchronously.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	require.NoError(t, l.Close())

	rec := &recordingMetrics{}
	cfg := validCfg("http://" + addr)
	cfg.MaxRetries = 1
	cfg.RetryBaseDelay = 5 * time.Millisecond
	cfg.RetryMaxDelay = 10 * time.Millisecond
	cfg.DisableStartupVerification = true
	out, err := splunk.New(cfg, nil, splunk.WithOutputMetrics(rec))
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte(`{"event_type":"x"}`)))
	require.NoError(t, out.Close())

	assert.GreaterOrEqual(t, rec.drops.Load(), int64(1),
		"connection-refused should record a drop after retries exhausted")
}

// TestOutput_NetworkFailures_DNSResolutionFailure — RFC 6761
// reserves the `.test` TLD for testing; `nonexistent.test` will
// never resolve in any DNS-conformant environment.
func TestOutput_NetworkFailures_DNSResolutionFailure(t *testing.T) {
	rec := &recordingMetrics{}
	cfg := validCfg("https://nonexistent.example.test:9999")
	cfg.MaxRetries = 1
	cfg.RetryBaseDelay = 5 * time.Millisecond
	cfg.RetryMaxDelay = 10 * time.Millisecond
	cfg.Timeout = 1 * time.Second
	cfg.DisableStartupVerification = true
	out, err := splunk.New(cfg, nil, splunk.WithOutputMetrics(rec))
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte(`{"event_type":"x"}`)))
	require.NoError(t, out.Close())

	// DNS failure produces a transient error in net/http; the retry
	// path drops after MaxRetries.
	assert.GreaterOrEqual(t, rec.drops.Load(), int64(1),
		"DNS failure should record a drop after retries exhausted")
}

// TestOutput_NetworkFailures_TLSHandshakeFailure — server's TLS
// cert is self-signed and the client trusts no CA. The handshake
// fails with x509.UnknownAuthorityError; the output classifies as
// non-retryable per the AC 54 fix.
func TestOutput_NetworkFailures_TLSHandshakeFailure(t *testing.T) {
	// httptest.NewTLSServer returns a TLS server with a self-signed
	// cert that no client trusts by default.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"text":"Success","code":0}`))
	}))
	defer srv.Close()

	rec := &recordingMetrics{}
	cfg := validCfg(srv.URL) // https://...
	cfg.AllowInsecureHTTP = false
	cfg.MaxRetries = 3
	cfg.RetryBaseDelay = 5 * time.Millisecond
	cfg.DisableStartupVerification = true
	out, err := splunk.New(cfg, nil, splunk.WithOutputMetrics(rec))
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte(`{"event_type":"x"}`)))
	// Allow the batch loop to process the TLS handshake failure.
	assert.Eventually(t, func() bool {
		return rec.drops.Load() >= 1
	}, 3*time.Second, 50*time.Millisecond,
		"TLS handshake failure should record a drop (non-retryable)")
	require.NoError(t, out.Close())
}

// TestOutput_TokenRedaction_TLSHandshakeError — folds onto the
// TLS-handshake fixture: capture the diagnostic logger output and
// assert the token never appears in the TLS error message.
func TestOutput_TokenRedaction_TLSHandshakeError(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"text":"Success","code":0}`))
	}))
	defer srv.Close()

	const secretToken = "super-secret-token-xyz-12345"
	logBuf := &splunkTestLogBuf{}
	cfg := validCfg(srv.URL)
	cfg.Token = secretToken
	cfg.AllowInsecureHTTP = false
	cfg.MaxRetries = 1
	cfg.RetryBaseDelay = 5 * time.Millisecond
	cfg.DisableStartupVerification = true
	out, err := splunk.New(cfg, nil, splunk.WithDiagnosticLogger(testLogger(logBuf)))
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte(`{"event_type":"x"}`)))
	// Wait for the batch loop to log the TLS error. Match strictly
	// on "TLS" or "x509" — the generic "splunk" prefix would also
	// hit the unrelated startup log line and let the test pass even
	// when the TLS error path was never reached.
	assert.Eventually(t, func() bool {
		s := logBuf.String()
		return strings.Contains(s, "TLS") || strings.Contains(s, "x509")
	}, 3*time.Second, 50*time.Millisecond,
		"diagnostic log should contain TLS or x509 error text")
	require.NoError(t, out.Close())

	assert.NotContains(t, logBuf.String(), secretToken,
		"TLS handshake error path must not leak the token")
}

// TestOutput_MalformedJSONResponseBody_TreatedAsRetryable5xx —
// AC 47. A 5xx response with a malformed JSON body must still
// retry (we never decoded the body to learn a HEC code that would
// short-circuit retry).
func TestOutput_MalformedJSONResponseBody_TreatedAsRetryable5xx(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/services/collector/health" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"text":"HEC is healthy","code":17}`))
			return
		}
		n := attempts.Add(1)
		if n < 2 {
			// 5xx + malformed JSON — the code parser returns 0, and
			// classify(5xx, 0) returns actionRetry.
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{not-valid-json`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"text":"Success","code":0}`))
	}))
	defer srv.Close()

	cfg := validCfg(srv.URL)
	cfg.MaxRetries = 3
	cfg.RetryBaseDelay = 5 * time.Millisecond
	cfg.RetryMaxDelay = 50 * time.Millisecond
	out, err := splunk.New(cfg, nil)
	require.NoError(t, err)
	require.NoError(t, out.Write([]byte(`{"event_type":"x"}`)))
	require.NoError(t, out.Close())

	assert.GreaterOrEqual(t, int(attempts.Load()), 2,
		"5xx with malformed body should retry")
}

// TestOutput_CloseRacingInFlightWrite_NoPanic — 100 goroutines
// writing concurrently with one goroutine closing. No panic.
func TestOutput_CloseRacingInFlightWrite_NoPanic(t *testing.T) {
	srv, _ := newStub(t)
	cfg := validCfg(srv.URL)
	cfg.BufferSize = 10_000
	out, err := splunk.New(cfg, nil)
	require.NoError(t, err)

	const writers = 100
	done := make(chan struct{}, writers)
	stop := make(chan struct{})
	var writeCount atomic.Int64
	for i := 0; i < writers; i++ {
		go func() {
			for {
				select {
				case <-stop:
					done <- struct{}{}
					return
				default:
					_ = out.Write([]byte(`{"event_type":"x"}`))
					writeCount.Add(1)
				}
			}
		}()
	}
	// Synchronise on observable progress: wait until every writer
	// has landed at least one Write before calling Close. Avoids
	// the time.Sleep flake — Close races real in-flight work.
	require.Eventually(t, func() bool {
		return writeCount.Load() >= int64(writers)
	}, 2*time.Second, 1*time.Millisecond,
		"every writer should have completed at least one Write before Close")

	closeErr := out.Close()
	close(stop)
	for i := 0; i < writers; i++ {
		<-done
	}
	assert.NoError(t, closeErr)
}

// TestOutput_KeepAlive_ConnectionReused — wraps the stub server's
// listener with a counting net.Listener and asserts two successive
// /event requests share one TCP connection (health uses a separate
// short-lived connection; the second /event reuses the first).
func TestOutput_KeepAlive_ConnectionReused(t *testing.T) {
	var eventReqs atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/services/collector/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"text":"HEC is healthy","code":17}`))
	})
	mux.HandleFunc("/services/collector/event", func(w http.ResponseWriter, _ *http.Request) {
		eventReqs.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"text":"Success","code":0}`))
	})
	srv := httptest.NewUnstartedServer(mux)
	counting := &countingListener{Listener: srv.Listener}
	srv.Listener = counting
	srv.Start()
	defer srv.Close()

	cfg := validCfg(srv.URL)
	cfg.BatchSize = 1
	cfg.FlushInterval = 100 * time.Millisecond // minimum allowed
	out, err := splunk.New(cfg, nil)
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte(`{"event_type":"a"}`)))
	// Wait for the first /event to land before issuing the second —
	// only then can keep-alive reuse occur on the same conn.
	require.Eventually(t, func() bool {
		return eventReqs.Load() >= 1
	}, 3*time.Second, 5*time.Millisecond,
		"first /event request should reach the server")

	require.NoError(t, out.Write([]byte(`{"event_type":"b"}`)))
	require.NoError(t, out.Close())

	require.Eventually(t, func() bool {
		return eventReqs.Load() >= 2
	}, 3*time.Second, 5*time.Millisecond,
		"second /event request should reach the server")

	// Three HTTP requests are made (1 health + 2 /event). With
	// keep-alive working, accepts <= 2 (health + first event;
	// second event reuses) — or even <= 1 if the transport reuses
	// the health probe's connection for the /event posts.
	// Anything > 2 means keep-alive is broken.
	accepts := counting.accepts.Load()
	assert.LessOrEqual(t, accepts, int64(2),
		"expected keep-alive reuse: at most 2 Accept calls for 3 requests; got %d", accepts)
	assert.GreaterOrEqual(t, accepts, int64(1),
		"expected at least 1 Accept call (the server was actually reached); got %d", accepts)
}

// TestOutput_SingleEventOverMaxBatchBytes_Drops — a single event
// whose assembled payload (post-envelope) exceeds MaxBatchBytes is
// dropped client-side rather than sent for HEC to reject with 413.
// Saves the network round-trip on a batch the server cannot accept
// anyway (Splunk's hard cap applies to uncompressed payload).
func TestOutput_SingleEventOverMaxBatchBytes_Drops(t *testing.T) {
	srv, stub := newStub(t)
	rec := &recordingMetrics{}
	cfg := validCfg(srv.URL)
	cfg.MaxBatchBytes = 1024
	cfg.MaxEventBytes = 2048
	cfg.DisableStartupVerification = true
	out, err := splunk.New(cfg, nil, splunk.WithOutputMetrics(rec))
	require.NoError(t, err)

	// 1400-byte payload — accepted by MaxEventBytes (2048) at Write
	// time, but the assembled envelope exceeds MaxBatchBytes (1024).
	// The pre-flush size check drops the batch.
	big := []byte(fmt.Sprintf(`{"event_type":"x","payload":%q}`,
		strings.Repeat("a", 1400)))
	require.NoError(t, out.Write(big))
	require.NoError(t, out.Close())

	assert.Equal(t, int64(1), rec.drops.Load(),
		"oversize batch must be dropped (pre-flush size check)")
	assert.Zero(t, stub.reqCount(),
		"oversize batch must not reach the server (no /event POST, no health probe — startup verification disabled)")
}

// TestOutput_RedirectBlocked — server returns 302 with Location;
// the output's CheckRedirect returns errRedirectBlocked, the batch
// drops.
func TestOutput_RedirectBlocked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/services/collector/health" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"text":"HEC is healthy","code":17}`))
			return
		}
		w.Header().Set("Location", "http://evil.example.invalid/exfil")
		w.WriteHeader(http.StatusFound) // 302
	}))
	defer srv.Close()

	rec := &recordingMetrics{}
	cfg := validCfg(srv.URL)
	cfg.MaxRetries = 0
	out, err := splunk.New(cfg, nil, splunk.WithOutputMetrics(rec))
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte(`{"event_type":"x"}`)))
	assert.Eventually(t, func() bool {
		return rec.drops.Load() >= 1
	}, 2*time.Second, 50*time.Millisecond,
		"302 redirect should drop the batch (non-retryable)")
	require.NoError(t, out.Close())
}

// TestOutput_RawEndpoint_NewlineFormat — /raw NDJSON appends a
// trailing newline to each event.
func TestOutput_RawEndpoint_NewlineFormat(t *testing.T) {
	srv, stub := newStub(t)
	cfg := validCfg(srv.URL)
	cfg.Endpoint = splunk.EndpointRaw
	cfg.BatchSize = 2
	cfg.FlushInterval = 10 * time.Second
	out, err := splunk.New(cfg, nil)
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte(`{"event":1}`)))
	require.NoError(t, out.Write([]byte(`{"event":2}`)))
	require.NoError(t, out.Close())

	require.GreaterOrEqual(t, stub.reqCount(), 1)
	body := string(stub.lastBody())
	assert.Equal(t, "{\"event\":1}\n{\"event\":2}\n", body)
}

// TestOutput_GzipDisabled_NoContentEncodingHeader — explicit
// Gzip=false produces no Content-Encoding header.
func TestOutput_GzipDisabled_NoContentEncodingHeader(t *testing.T) {
	srv, stub := newStub(t)
	cfg := validCfg(srv.URL)
	gz := false
	cfg.Gzip = &gz
	out, err := splunk.New(cfg, nil)
	require.NoError(t, err)
	require.NoError(t, out.Write([]byte(`{"event_type":"x"}`)))
	require.NoError(t, out.Close())

	r := stub.lastReq()
	assert.Empty(t, r.contentEnc, "Gzip=false should produce no Content-Encoding header")
}

// TestOutput_LibraryHeadersAlwaysSet — consumer Headers map sets
// arbitrary extra headers; the library still sets its own managed
// headers (Content-Type, User-Agent, Authorization). The reserved-
// header rejection at config-validation time is covered by
// TestConfig_ReservedHeadersRejected; this test verifies the
// runtime applyRequestHeaders path adds the library's headers on
// every request alongside the consumer's extras.
func TestOutput_LibraryHeadersAlwaysSet(t *testing.T) {
	srv, stub := newStub(t)
	cfg := validCfg(srv.URL)
	cfg.Headers = map[string]string{"X-Tenant": "alpha"}
	out, err := splunk.New(cfg, nil)
	require.NoError(t, err)
	require.NoError(t, out.Write([]byte(`{"event_type":"x"}`)))
	require.NoError(t, out.Close())

	r := stub.lastReq()
	assert.Equal(t, "application/json", r.contentType,
		"library must set Content-Type even when consumer adds extra headers")
	assert.True(t, strings.HasPrefix(r.auth, "Splunk "),
		"library must set Authorization with Splunk auth scheme")
}

// TestConfig_ReservedHeadersRejected — the config validator rejects
// consumer attempts to override Content-Type, Authorization,
// Content-Encoding, User-Agent, or the ACK channel header. This is
// the up-front guard; the runtime override in applyRequestHeaders
// is defence-in-depth (tested by TestOutput_LibraryHeadersAlwaysSet).
func TestConfig_ReservedHeadersRejected(t *testing.T) {
	reserved := []string{
		"Authorization",
		"Content-Type",
		"Content-Encoding",
		"User-Agent",
		"X-Splunk-Request-Channel",
		// Case-insensitive: validation lowercases before comparing.
		"authorization",
		"CONTENT-TYPE",
	}
	for _, h := range reserved {
		t.Run(h, func(t *testing.T) {
			srv, _ := newStub(t)
			cfg := validCfg(srv.URL)
			cfg.Headers = map[string]string{h: "evil-value"}
			_, err := splunk.New(cfg, nil)
			require.Error(t, err, "reserved header %q must be rejected", h)
			assert.ErrorIs(t, err, splunk.ErrConfigInvalid)
		})
	}
}

// TestOutput_Name_ReturnsCachedValue — basic coverage for the
// host-suffix cache.
func TestOutput_Name_ReturnsCachedValue(t *testing.T) {
	srv, _ := newStub(t)
	out, err := splunk.New(validCfg(srv.URL), nil)
	require.NoError(t, err)
	defer func() { _ = out.Close() }()

	n1 := out.Name()
	n2 := out.Name()
	assert.Equal(t, n1, n2, "Name should return a stable cached value")
	assert.True(t, strings.HasPrefix(n1, "splunk:"))
}

// TestOutput_ReportsDelivery_True — Output implements
// audit.DeliveryReporter and reports true so the core pipeline
// does not double-record metrics.
func TestOutput_ReportsDelivery_True(t *testing.T) {
	srv, _ := newStub(t)
	out, err := splunk.New(validCfg(srv.URL), nil)
	require.NoError(t, err)
	defer func() { _ = out.Close() }()
	assert.True(t, out.ReportsDelivery())
}

// TestOutput_LastDeliveryAge_ZeroBeforeFirstSuccess — the
// DeliveryReporter.LastDeliveryAge starts at 0 until the first
// successful delivery; thereafter it is monotonically increasing.
func TestOutput_LastDeliveryAge_Lifecycle(t *testing.T) {
	srv, _ := newStub(t)
	out, err := splunk.New(validCfg(srv.URL), nil)
	require.NoError(t, err)
	defer func() { _ = out.Close() }()

	// Before any send.
	assert.Zero(t, out.LastDeliveryAge())

	require.NoError(t, out.Write([]byte(`{"event_type":"x"}`)))
	// Wait for the flush.
	assert.Eventually(t, func() bool {
		return out.LastDeliveryAge() > 0
	}, 3*time.Second, 50*time.Millisecond)

	// Age should keep increasing (no further sends).
	a1 := out.LastDeliveryAge()
	time.Sleep(50 * time.Millisecond)
	assert.Greater(t, out.LastDeliveryAge(), a1)
}

// countingListener wraps a net.Listener and counts Accept calls
// (one Accept == one new TCP connection — keep-alive reuse does
// NOT count again).
type countingListener struct {
	net.Listener
	accepts atomic.Int64
}

func (c *countingListener) Accept() (net.Conn, error) {
	conn, err := c.Listener.Accept()
	if err == nil {
		c.accepts.Add(1)
	}
	return conn, err
}

// splunkTestLogBuf is a thread-safe writer for capturing the
// diagnostic logger output in redaction tests.
type splunkTestLogBuf struct {
	buf strings.Builder
	mu  sync.Mutex
}

func (b *splunkTestLogBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *splunkTestLogBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// testLogger returns a slog.Logger that writes to the buffer with
// a text handler at debug level (captures everything).
func testLogger(buf *splunkTestLogBuf) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}
