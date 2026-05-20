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
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/axonops/audit"
	"github.com/axonops/audit/splunk"
)

// TestMain enforces goleak across the package — every test that
// constructs an Output must clean up its goroutines.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m,
		goleak.IgnoreTopFunction("internal/poll.runtime_pollWait"),
	)
}

// newStub returns a Splunk HEC stub that records every request and
// responds with HTTP 200 + the documented Success body.
func newStub(t *testing.T) (*httptest.Server, *hecStub) {
	t.Helper()
	stub := &hecStub{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stub.handle(t, w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, stub
}

// hecStub records the requests the test received and provides
// helpers to assert on them.
type hecStub struct {
	mu        sync.Mutex
	requests  []recordedRequest
	respCode  int
	respBody  []byte
	respDelay time.Duration
}

type recordedRequest struct {
	method      string
	path        string
	rawQuery    string
	auth        string
	contentEnc  string
	userAgent   string
	contentType string
	body        []byte
}

func (s *hecStub) handle(t *testing.T, w http.ResponseWriter, r *http.Request) {
	t.Helper()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Errorf("stub: read body: %v", err)
		http.Error(w, "read", http.StatusInternalServerError)
		return
	}
	// Decompress if the request was gzipped — keep the original bytes
	// so a separate assertion can check that gzip was used.
	finalBody := body
	if r.Header.Get("Content-Encoding") == "gzip" {
		gz, err := gzip.NewReader(strings.NewReader(string(body)))
		if err == nil {
			defer func() { _ = gz.Close() }()
			finalBody, _ = io.ReadAll(gz)
		}
	}
	s.mu.Lock()
	s.requests = append(s.requests, recordedRequest{
		method:      r.Method,
		path:        r.URL.Path,
		rawQuery:    r.URL.RawQuery,
		auth:        r.Header.Get("Authorization"),
		contentEnc:  r.Header.Get("Content-Encoding"),
		userAgent:   r.Header.Get("User-Agent"),
		contentType: r.Header.Get("Content-Type"),
		body:        finalBody,
	})
	respCode := s.respCode
	respBody := s.respBody
	delay := s.respDelay
	s.mu.Unlock()

	if delay > 0 {
		time.Sleep(delay)
	}

	// Health endpoint always returns the documented healthy body.
	if r.URL.Path == "/services/collector/health" {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"text":"HEC is healthy","code":17}`))
		return
	}

	if respCode == 0 {
		respCode = http.StatusOK
	}
	if respBody == nil {
		respBody = []byte(`{"text":"Success","code":0}`)
	}
	w.WriteHeader(respCode)
	_, _ = w.Write(respBody)
}

func (s *hecStub) lastBody() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.requests) == 0 {
		return nil
	}
	return s.requests[len(s.requests)-1].body
}

func (s *hecStub) reqCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.requests)
}

func (s *hecStub) lastReq() recordedRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.requests) == 0 {
		return recordedRequest{}
	}
	return s.requests[len(s.requests)-1]
}

func (s *hecStub) setResponse(code int, body []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.respCode = code
	s.respBody = body
}

// validCfg returns a known-good config for the given stub server URL.
// AllowInsecureHTTP is set so httptest.NewServer's http:// URL is
// accepted; AllowPrivateRanges so the SSRF dial control doesn't block
// 127.0.0.1.
func validCfg(serverURL string) *splunk.Config {
	gzip := false // disable gzip in tests so we can assert raw envelope bytes
	return &splunk.Config{
		URL:                        serverURL,
		Token:                      "test-token-abc",
		BufferSize:                 100,
		BatchSize:                  10,
		MaxBatchBytes:              1024,
		MaxEventBytes:              1024,
		FlushInterval:              100 * time.Millisecond,
		Timeout:                    1 * time.Second,
		Gzip:                       &gzip,
		AllowInsecureHTTP:          true,
		AllowPrivateRanges:         true,
		DisableStartupVerification: false,
	}
}

func TestNew_ValidConfig(t *testing.T) {
	srv, _ := newStub(t)
	out, err := splunk.New(validCfg(srv.URL), nil)
	require.NoError(t, err)
	require.NotNil(t, out)
	require.NoError(t, out.Close())
}

func TestNew_MissingURL(t *testing.T) {
	_, err := splunk.New(&splunk.Config{Token: "x"}, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, splunk.ErrConfigInvalid)
}

func TestNew_MissingToken(t *testing.T) {
	_, err := splunk.New(&splunk.Config{URL: "https://x"}, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, splunk.ErrConfigInvalid)
}

func TestNew_TokenStartingWithSplunkPrefix_Rejected(t *testing.T) {
	cfg := validCfg("https://x.test")
	cfg.Token = "Splunk abc-def"
	cfg.DisableStartupVerification = true
	_, err := splunk.New(cfg, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, splunk.ErrConfigInvalid)
}

func TestNew_TokenStartingWithBearerPrefix_Rejected(t *testing.T) {
	cfg := validCfg("https://x.test")
	cfg.Token = "Bearer abc-def"
	cfg.DisableStartupVerification = true
	_, err := splunk.New(cfg, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, splunk.ErrConfigInvalid)
}

func TestNew_TokenWithControlChars_Rejected(t *testing.T) {
	cfg := validCfg("https://x.test")
	cfg.Token = "abc\r\nfake"
	cfg.DisableStartupVerification = true
	_, err := splunk.New(cfg, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, splunk.ErrConfigInvalid)
}

func TestNew_URLWithCredentials_Rejected(t *testing.T) {
	cfg := validCfg("https://user:pass@x.test")
	cfg.DisableStartupVerification = true
	_, err := splunk.New(cfg, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, splunk.ErrConfigInvalid)
}

func TestNew_HTTPRejected(t *testing.T) {
	cfg := validCfg("http://x.test")
	cfg.AllowInsecureHTTP = false
	cfg.DisableStartupVerification = true
	_, err := splunk.New(cfg, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, splunk.ErrConfigInvalid)
}

// TestNew_SplunkCloudScheme_ExpandsAndConstructs verifies that
// `splunkcloud://<stack>` is expanded to the canonical HTTPS URL
// during construction. The stub server is unreachable (no real
// Splunk Cloud DNS in tests), so we DisableStartupVerification and
// assert the URL rewrite + successful construction.
func TestNew_SplunkCloudScheme_ExpandsAndConstructs(t *testing.T) {
	cfg := validCfg("splunkcloud://acme-prod")
	cfg.DisableStartupVerification = true
	out, err := splunk.New(cfg, nil)
	require.NoError(t, err)
	require.NoError(t, out.Close())
	// The URL must be rewritten to the canonical form (visible via
	// the stored config — sanity check via Name() which derives from
	// the URL host).
	assert.Contains(t, out.Name(), "http-inputs-acme-prod.splunkcloud.com",
		"Name() must reflect the expanded splunkcloud URL host")
}

func TestNew_AckModeRequired_RejectedInPR1(t *testing.T) {
	cfg := validCfg("https://x.test")
	cfg.AckMode = splunk.AckModeRequired
	cfg.DisableStartupVerification = true
	_, err := splunk.New(cfg, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, splunk.ErrPR1NotImplemented)
}

func TestNew_HealthCheckFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	cfg := validCfg(srv.URL)
	_, err := splunk.New(cfg, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, splunk.ErrHealthCheckFailed)
}

func TestNew_HealthCheckSkipped(t *testing.T) {
	cfg := validCfg("https://nonexistent.invalid")
	cfg.DisableStartupVerification = true
	out, err := splunk.New(cfg, nil)
	require.NoError(t, err)
	require.NoError(t, out.Close())
}

func TestOutput_Name_FormatHostSuffix(t *testing.T) {
	srv, _ := newStub(t)
	out, err := splunk.New(validCfg(srv.URL), nil)
	require.NoError(t, err)
	defer func() { _ = out.Close() }()
	assert.True(t, strings.HasPrefix(out.Name(), "splunk:"))
	assert.NotEqual(t, "splunk:", out.Name())
}

func TestOutput_EventEnvelope_Format(t *testing.T) {
	srv, stub := newStub(t)
	out, err := splunk.New(validCfg(srv.URL), nil)
	require.NoError(t, err)

	evt := []byte(`{"timestamp":"2026-05-20T10:00:00.123Z","event_type":"user_login","actor_id":"alice"}`)
	require.NoError(t, out.Write(evt))
	require.NoError(t, out.Close())

	require.GreaterOrEqual(t, stub.reqCount(), 1)
	body := stub.lastBody()
	require.NotEmpty(t, body)

	// Decode the envelope and assert structure.
	var env struct {
		Event      json.RawMessage `json:"event"`
		Time       float64         `json:"time"`
		Host       string          `json:"host"`
		Source     string          `json:"source"`
		Sourcetype string          `json:"sourcetype"`
		Index      string          `json:"index"`
	}
	dec := json.NewDecoder(strings.NewReader(string(body)))
	require.NoError(t, dec.Decode(&env))
	assert.JSONEq(t, string(evt), string(env.Event))
	assert.Equal(t, "audit:event", env.Sourcetype)
	assert.Equal(t, "audit", env.Source)
	// 2026-05-20T10:00:00.123Z = epoch milliseconds 1779616800123,
	// expressed as seconds with millisecond precision = 1779616800.123.
	// Assert within 1ms to detect any regression that returns time.Now()
	// or drops sub-second precision (test-analyst: tautology fix).
	expected := time.Date(2026, 5, 20, 10, 0, 0, 123_000_000, time.UTC)
	expectedFloat := float64(expected.UnixMilli()) / 1000.0
	assert.InDelta(t, expectedFloat, env.Time, 0.001)
}

func TestOutput_EventEnvelope_ConcatenatedBatch(t *testing.T) {
	srv, stub := newStub(t)
	cfg := validCfg(srv.URL)
	cfg.BatchSize = 3
	cfg.FlushInterval = 10 * time.Second // ensure flush is size-triggered
	out, err := splunk.New(cfg, nil)
	require.NoError(t, err)
	for i := 0; i < 3; i++ {
		require.NoError(t, out.Write([]byte(`{"event_type":"x","actor_id":"a"}`)))
	}
	require.NoError(t, out.Close())

	require.GreaterOrEqual(t, stub.reqCount(), 1)
	body := stub.lastBody()
	// Stream-decode the concatenated JSON — must yield exactly 3 objects.
	dec := json.NewDecoder(strings.NewReader(string(body)))
	count := 0
	for {
		var obj map[string]any
		if err := dec.Decode(&obj); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			t.Fatalf("decode: %v", err)
		}
		count++
	}
	assert.Equal(t, 3, count)
}

func TestOutput_AuthHeader_ExactSplunkPrefix(t *testing.T) {
	srv, stub := newStub(t)
	cfg := validCfg(srv.URL)
	cfg.Token = "abc-123-def"
	out, err := splunk.New(cfg, nil)
	require.NoError(t, err)
	require.NoError(t, out.Write([]byte(`{"event_type":"x"}`)))
	require.NoError(t, out.Close())

	require.GreaterOrEqual(t, stub.reqCount(), 1)
	r := stub.lastReq()
	assert.Equal(t, "Splunk abc-123-def", r.auth)
}

func TestOutput_UserAgentHeader(t *testing.T) {
	srv, stub := newStub(t)
	out, err := splunk.New(validCfg(srv.URL), nil)
	require.NoError(t, err)
	require.NoError(t, out.Write([]byte(`{"event_type":"x"}`)))
	require.NoError(t, out.Close())

	r := stub.lastReq()
	assert.True(t, strings.HasPrefix(r.userAgent, "audit-splunk/"),
		"User-Agent should start with audit-splunk/; got %q", r.userAgent)
}

func TestOutput_GzipCompression_DefaultOn(t *testing.T) {
	srv, stub := newStub(t)
	cfg := validCfg(srv.URL)
	cfg.Gzip = nil // unset — defaults to true
	out, err := splunk.New(cfg, nil)
	require.NoError(t, err)
	require.NoError(t, out.Write([]byte(`{"event_type":"x"}`)))
	require.NoError(t, out.Close())

	r := stub.lastReq()
	assert.Equal(t, "gzip", r.contentEnc)
}

func TestOutput_HECErrorCode_4_Stops(t *testing.T) {
	srv, stub := newStub(t)
	stub.setResponse(403, []byte(`{"text":"Invalid token","code":4}`))
	cfg := validCfg(srv.URL)
	cfg.MaxRetries = 0
	out, err := splunk.New(cfg, nil)
	require.NoError(t, err)
	require.NoError(t, out.Write([]byte(`{"event_type":"x"}`)))
	// Subsequent Writes return ErrOutputClosed once the batch loop has
	// processed the stop signal — poll deterministically (no time.Sleep
	// as synchronisation, per test-analyst).
	assert.Eventually(t, func() bool {
		return errors.Is(out.Write([]byte(`{"event_type":"y"}`)), audit.ErrOutputClosed)
	}, 2*time.Second, 10*time.Millisecond)
	require.NoError(t, out.Close())
}

func TestOutput_HECCode24_NotError_RequestSucceeds(t *testing.T) {
	srv, stub := newStub(t)
	stub.setResponse(200, []byte(`{"text":"Approaching capacity","code":24}`))
	rec := &recordingMetrics{}
	out, err := splunk.New(validCfg(srv.URL), nil, splunk.WithOutputMetrics(rec))
	require.NoError(t, err)
	require.NoError(t, out.Write([]byte(`{"event_type":"x"}`)))
	require.NoError(t, out.Close())
	assert.GreaterOrEqual(t, stub.reqCount(), 1)
	// Code 24 is HTTP 200 + capacity warning — it MUST be treated as
	// success (RecordFlush), NOT as a drop. A regression that
	// mis-classified code 24 as actionDrop would call RecordDrop here.
	assert.Equal(t, int64(0), rec.drops.Load(),
		"HEC code 24 must not record a drop (it is a capacity warning, not an error)")
	assert.GreaterOrEqual(t, int(rec.flushes.Load()), 1,
		"HEC code 24 must record a flush (the request succeeded)")
}

// recordingMetrics is a minimal audit.OutputMetrics that counts each
// kind of event so tests can assert on classification semantics. The
// NoOpOutputMetrics embed picks up any future OutputMetrics method
// additions automatically.
type recordingMetrics struct {
	audit.NoOpOutputMetrics
	flushes atomic.Int64
	drops   atomic.Int64
	errors  atomic.Int64
	retries atomic.Int64
}

func (r *recordingMetrics) RecordFlush(_ int, _ time.Duration) { r.flushes.Add(1) }
func (r *recordingMetrics) RecordDrop()                        { r.drops.Add(1) }
func (r *recordingMetrics) RecordError()                       { r.errors.Add(1) }
func (r *recordingMetrics) RecordRetry(_ int)                  { r.retries.Add(1) }

func TestOutput_HTTP503_Retries(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/services/collector/health" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"text":"HEC is healthy","code":17}`))
			return
		}
		n := attempts.Add(1)
		if n < 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"text":"Server is busy","code":9}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"text":"Success","code":0}`))
	}))
	defer srv.Close()
	cfg := validCfg(srv.URL)
	cfg.MaxRetries = 3
	cfg.RetryBaseDelay = 10 * time.Millisecond
	cfg.RetryMaxDelay = 50 * time.Millisecond
	out, err := splunk.New(cfg, nil)
	require.NoError(t, err)
	start := time.Now()
	require.NoError(t, out.Write([]byte(`{"event_type":"x"}`)))
	require.NoError(t, out.Close())
	elapsed := time.Since(start)
	// Two attempts means at least one backoff window was respected.
	// At RetryBaseDelay=10ms with jitter [0.5,1.0), backoff is in
	// [5ms,10ms) on first retry — assert the elapsed total includes
	// at least the floor to detect a busy-loop regression.
	assert.GreaterOrEqual(t, int(attempts.Load()), 2)
	assert.Greater(t, elapsed, 5*time.Millisecond,
		"retry path should sleep at least once; busy-loop regression?")
}

func TestOutput_CloseIdempotent(t *testing.T) {
	srv, _ := newStub(t)
	out, err := splunk.New(validCfg(srv.URL), nil)
	require.NoError(t, err)
	require.NoError(t, out.Close())
	require.NoError(t, out.Close())
	require.NoError(t, out.Close())
}

func TestOutput_WriteAfterClose_ReturnsErrOutputClosed(t *testing.T) {
	srv, _ := newStub(t)
	out, err := splunk.New(validCfg(srv.URL), nil)
	require.NoError(t, err)
	require.NoError(t, out.Close())
	err = out.Write([]byte(`{"event_type":"x"}`))
	assert.ErrorIs(t, err, audit.ErrOutputClosed)
}

func TestOutput_SingleEventOverMaxEventBytes_Drops(t *testing.T) {
	srv, stub := newStub(t)
	cfg := validCfg(srv.URL)
	cfg.MaxEventBytes = 1024 // minimum allowed; oversize threshold
	cfg.DisableStartupVerification = true
	out, err := splunk.New(cfg, nil)
	require.NoError(t, err)
	big := make([]byte, 2048)
	for i := range big {
		big[i] = 'a'
	}
	err = out.Write(big)
	assert.ErrorIs(t, err, audit.ErrEventTooLarge)
	require.NoError(t, out.Close())
	// No /event request should have been made (only the health check
	// is allowed; we disabled it above).
	assert.Equal(t, 0, stub.reqCount())
}

func TestOutput_ConfigString_RedactsToken(t *testing.T) {
	cfg := &splunk.Config{
		URL:   "https://user:pass@splunk.example.com:8088",
		Token: "super-secret-token",
	}
	for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
		out := formatWith(t, format, *cfg)
		assert.NotContains(t, out, "super-secret-token", "format %s leaked token", format)
		assert.NotContains(t, out, "user:pass", "format %s leaked URL credentials", format)
	}
}

// formatWith returns fmt.Sprintf(format, v) — wrapped only to capture
// a panic in the formatter chain (defensive against a regression in
// Config.Format that recursively re-enters fmt).
func formatWith(t *testing.T, format string, v any) string {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("format %s panicked: %v", format, r)
		}
	}()
	return fmt.Sprintf(format, v)
}
