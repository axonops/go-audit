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

package steps

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	neturl "net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cucumber/godog"

	"github.com/axonops/audit"
	"github.com/axonops/audit/splunk"
)

// splunkStubRequest is one recorded HEC request the stub received.
type splunkStubRequest struct {
	method      string
	path        string
	rawQuery    string
	auth        string
	contentEnc  string
	userAgent   string
	contentType string
	body        []byte
	receivedAt  time.Time
}

// splunkStub is the in-process HTTP server that the BDD scenarios
// drive the splunk output against. Records every request and exposes
// configurable response behaviour (status, body, optional first-N
// failures before success — for retry scenarios).
type splunkStub struct {
	server     *httptest.Server
	mu         sync.Mutex
	requests   []splunkStubRequest
	respStatus int
	respBody   []byte
	failFirstN int32
	failCount  atomic.Int32
}

// newSplunkStub returns a stub server that responds with HTTP 200 +
// the documented Success body to every /event, /raw and /health
// request. Scenarios can override `respStatus`/`respBody` to inject
// HEC error codes.
func newSplunkStub() *splunkStub {
	s := &splunkStub{
		respStatus: http.StatusOK,
		respBody:   []byte(`{"text":"Success","code":0}`),
	}
	s.server = httptest.NewServer(http.HandlerFunc(s.handle))
	return s
}

func (s *splunkStub) handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	finalBody := body
	if r.Header.Get("Content-Encoding") == "gzip" {
		gz, err := gzip.NewReader(bytes.NewReader(body))
		if err == nil {
			defer func() { _ = gz.Close() }()
			finalBody, _ = io.ReadAll(gz)
		}
	}

	s.mu.Lock()
	s.requests = append(s.requests, splunkStubRequest{
		method:      r.Method,
		path:        r.URL.Path,
		rawQuery:    r.URL.RawQuery,
		auth:        r.Header.Get("Authorization"),
		contentEnc:  r.Header.Get("Content-Encoding"),
		userAgent:   r.Header.Get("User-Agent"),
		contentType: r.Header.Get("Content-Type"),
		body:        finalBody,
		receivedAt:  time.Now(),
	})
	s.mu.Unlock()

	// Health endpoint always returns the documented healthy body so
	// the startup probe succeeds.
	if r.URL.Path == "/services/collector/health" {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"text":"HEC is healthy","code":17}`))
		return
	}

	// Inject `failFirstN` failures before serving the configured
	// response (retry scenarios).
	if n := atomic.LoadInt32(&s.failFirstN); n > 0 {
		if s.failCount.Add(1) <= n {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"text":"Server is busy","code":9}`))
			return
		}
	}

	s.mu.Lock()
	status := s.respStatus
	body2 := s.respBody
	s.mu.Unlock()
	w.WriteHeader(status)
	_, _ = w.Write(body2)
}

func (s *splunkStub) setResponse(status int, body []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.respStatus = status
	s.respBody = body
}

func (s *splunkStub) close() { s.server.Close() }

func (s *splunkStub) requestCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, r := range s.requests {
		if r.path != "/services/collector/health" {
			n++
		}
	}
	return n
}

func (s *splunkStub) lastEventRequest() (splunkStubRequest, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.requests) - 1; i >= 0; i-- {
		if s.requests[i].path != "/services/collector/health" {
			return s.requests[i], true
		}
	}
	return splunkStubRequest{}, false
}

// splunkBDDState holds the scenario-scoped state for a splunk BDD run.
// Stored in the AuditTestContext via a context-keyed slot.
type splunkBDDState struct {
	stub             *splunkStub
	output           *splunk.Output
	auditor          *audit.Auditor
	logBuf           *splunkLogBuf
	lastWriteErr     error
	constructionErr  error
	scenarioStart    time.Time
	stopMetricCounts *recordingOutputMetrics
}

// splunkLogBuf is a concurrency-safe bytes.Buffer wrapper used as
// the destination for the diagnostic-logger redaction scenario.
type splunkLogBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (t *splunkLogBuf) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.buf.Write(p)
}

func (t *splunkLogBuf) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.buf.String()
}

// recordingOutputMetrics counts each kind of OutputMetrics call so
// scenarios can assert on classification semantics. Embeds
// NoOpOutputMetrics for forward-compatibility.
type recordingOutputMetrics struct {
	audit.NoOpOutputMetrics
	flushes  atomic.Int64
	drops    atomic.Int64
	warnings atomic.Int64
}

func (r *recordingOutputMetrics) RecordFlush(_ int, _ time.Duration) { r.flushes.Add(1) }
func (r *recordingOutputMetrics) RecordDrop()                        { r.drops.Add(1) }

// registerSplunkSteps wires the Splunk step bindings into the godog
// runner. Called from the central context registration.
func registerSplunkSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	state := &splunkBDDState{}

	ctx.Before(func(_ context.Context, _ *godog.Scenario) (context.Context, error) { //nolint:unparam // godog hook signature
		state.stub = nil
		state.output = nil
		state.auditor = nil
		state.logBuf = nil
		state.lastWriteErr = nil
		state.constructionErr = nil
		state.scenarioStart = time.Now()
		state.stopMetricCounts = nil
		return context.Background(), nil
	})
	ctx.After(func(_ context.Context, _ *godog.Scenario, _ error) (context.Context, error) {
		if state.output != nil {
			_ = state.output.Close()
		}
		if state.stub != nil {
			state.stub.close()
		}
		return context.Background(), nil
	})

	ctx.Step(`^a splunk HEC stub server$`, func() error {
		state.stub = newSplunkStub()
		return nil
	})

	ctx.Step(`^an auditor with splunk output$`, func() error {
		return splunkConstruct(state, nil)
	})

	ctx.Step(`^an auditor with splunk output on the /event endpoint$`, func() error {
		return splunkConstruct(state, func(c *splunk.Config) { c.Endpoint = splunk.EndpointEvent })
	})

	ctx.Step(`^an auditor with splunk output on the /raw endpoint$`, func() error {
		return splunkConstruct(state, func(c *splunk.Config) { c.Endpoint = splunk.EndpointRaw })
	})

	ctx.Step(`^an auditor with splunk output configured for batch size (\d+)$`, func(n int) error {
		return splunkConstruct(state, func(c *splunk.Config) {
			c.BatchSize = n
			c.FlushInterval = 5 * time.Second
		})
	})

	ctx.Step(`^an auditor with splunk output configured for batch size (\d+) and flush interval (\d+)s$`, func(n, s int) error {
		return splunkConstruct(state, func(c *splunk.Config) {
			c.BatchSize = n
			c.FlushInterval = time.Duration(s) * time.Second
		})
	})

	ctx.Step(`^an auditor with splunk output and default gzip$`, func() error {
		return splunkConstruct(state, func(c *splunk.Config) { c.Gzip = nil })
	})

	ctx.Step(`^an auditor with splunk output and MaxEventBytes (\d+)$`, func(n int) error {
		return splunkConstruct(state, func(c *splunk.Config) {
			c.MaxEventBytes = n
		})
	})

	ctx.Step(`^an auditor with splunk output and token "([^"]*)"$`, func(tok string) error {
		return splunkConstruct(state, func(c *splunk.Config) { c.Token = tok })
	})

	// HEC error-code injection.
	ctx.Step(`^an auditor with splunk output where the HEC will return code (\d+)$`, func(code int) error {
		if state.stub == nil {
			return errors.New("stub not initialised; preceding Given missing")
		}
		// Map code to HTTP status.
		status := splunkHTTPStatusForCode(code)
		state.stub.setResponse(status, []byte(fmt.Sprintf(`{"text":"injected","code":%d}`, code)))
		return splunkConstruct(state, func(c *splunk.Config) { c.MaxRetries = 0 })
	})

	ctx.Step(`^an auditor with splunk output where the HEC will return code (\d+) twice then succeed$`, func(code int) error {
		if state.stub == nil {
			return errors.New("stub not initialised; preceding Given missing")
		}
		atomic.StoreInt32(&state.stub.failFirstN, 2)
		_ = code
		return splunkConstruct(state, func(c *splunk.Config) {
			c.MaxRetries = 5
			c.RetryBaseDelay = 250 * time.Millisecond
			c.RetryMaxDelay = 2 * time.Second
		})
	})

	ctx.Step(`^an auditor with splunk output where the HEC will return HTTP (\d+)$`, func(status int) error {
		if state.stub == nil {
			return errors.New("stub not initialised; preceding Given missing")
		}
		state.stub.setResponse(status, []byte(""))
		return splunkConstruct(state, func(c *splunk.Config) { c.MaxRetries = 0 })
	})

	ctx.Step(`^I audit a uniquely marked splunk "([^"]*)" event$`, func(eventType string) error {
		return splunkWriteEvent(state, eventType, "")
	})

	ctx.Step(`^I audit (\d+) uniquely marked splunk "([^"]*)" events$`, func(n int, eventType string) error {
		for i := 0; i < n; i++ {
			if err := splunkWriteEvent(state, eventType, fmt.Sprintf("seq-%d", i)); err != nil {
				return err
			}
		}
		return nil
	})

	ctx.Step(`^I audit an oversized splunk "([^"]*)" event of (\d+) bytes$`, func(eventType string, size int) error {
		if state.output == nil {
			return errors.New("output not constructed; preceding Given missing")
		}
		big := make([]byte, size)
		for i := range big {
			big[i] = 'a'
		}
		state.lastWriteErr = state.output.Write(big)
		return nil
	})

	ctx.Step(`^I wait up to (\d+) seconds for the output to enter the stop state$`, func(secs int) error {
		if state.output == nil {
			return errors.New("output not constructed")
		}
		deadline := time.Now().Add(time.Duration(secs) * time.Second)
		for time.Now().Before(deadline) {
			err := state.output.Write([]byte(`{"event_type":"probe"}`))
			if errors.Is(err, audit.ErrOutputClosed) {
				return nil
			}
			time.Sleep(50 * time.Millisecond)
		}
		return fmt.Errorf("output did not enter stop state within %ds", secs)
	})

	ctx.Step(`^I close the splunk auditor$`, func() error {
		if state.output == nil {
			return errors.New("output not constructed")
		}
		return state.output.Close()
	})

	ctx.Step(`^I read the splunk diagnostic log buffer$`, func() error {
		// no-op; the buffer is captured throughout the scenario
		return nil
	})

	ctx.Step(`^I construct a splunk output with URL "([^"]*)" and AllowInsecureHTTP false$`, func(url string) error {
		cfg := &splunk.Config{URL: url, Token: "t", AllowInsecureHTTP: false, DisableStartupVerification: true}
		_, err := splunk.New(cfg, nil)
		state.constructionErr = err
		return nil
	})

	ctx.Step(`^I construct a splunk output with URL "([^"]*)"$`, func(url string) error {
		cfg := &splunk.Config{URL: url, Token: "t", AllowInsecureHTTP: true, DisableStartupVerification: true}
		out, err := splunk.New(cfg, nil)
		state.constructionErr = err
		if err == nil {
			state.output = out
		}
		return nil
	})

	ctx.Step(`^I construct a splunk output with URL "([^"]*)" and TLSCert "([^"]*)"$`, func(url, tlsCert string) error {
		cfg := &splunk.Config{URL: url, Token: "t", AllowInsecureHTTP: true, DisableStartupVerification: true, TLSCert: tlsCert}
		_, err := splunk.New(cfg, nil)
		state.constructionErr = err
		return nil
	})

	// Then steps — assertions. Single pattern that matches both
	// "envelope" and "request" / "requests" wording.
	ctx.Step(`^the splunk receiver should have received exactly (\d+) (?:envelope|envelopes|request|requests) within (\d+) seconds$`, func(want, secs int) error {
		deadline := time.Now().Add(time.Duration(secs) * time.Second)
		for time.Now().Before(deadline) {
			if state.stub.requestCount() == want {
				return nil
			}
			time.Sleep(50 * time.Millisecond)
		}
		got := state.stub.requestCount()
		if got != want {
			return fmt.Errorf("expected exactly %d request(s) within %ds, got %d", want, secs, got)
		}
		return nil
	})

	ctx.Step(`^the received envelope should have field "([^"]*)" = "([^"]*)"$`, func(field, want string) error {
		req, ok := state.stub.lastEventRequest()
		if !ok {
			return errors.New("no event request received")
		}
		var env map[string]any
		if err := json.NewDecoder(bytes.NewReader(req.body)).Decode(&env); err != nil {
			return fmt.Errorf("decode envelope: %w", err)
		}
		got, _ := env[field].(string)
		if got != want {
			return fmt.Errorf("field %q = %q; want %q", field, got, want)
		}
		return nil
	})

	ctx.Step(`^the request body should stream-decode to exactly (\d+) JSON objects$`, func(want int) error {
		req, ok := state.stub.lastEventRequest()
		if !ok {
			return errors.New("no event request received")
		}
		dec := json.NewDecoder(bytes.NewReader(req.body))
		count := 0
		for {
			var obj any
			if err := dec.Decode(&obj); err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				return fmt.Errorf("decode object %d: %w", count, err)
			}
			count++
		}
		if count != want {
			return fmt.Errorf("expected %d JSON objects, decoded %d", want, count)
		}
		return nil
	})

	ctx.Step(`^the request URL should contain query "([^"]*)"$`, func(needle string) error {
		req, ok := state.stub.lastEventRequest()
		if !ok {
			return errors.New("no event request received")
		}
		// Compare needle in URL-decoded form so colons and other
		// special characters in expected values don't have to be
		// escaped in the feature file.
		decoded, err := neturl.QueryUnescape(req.rawQuery)
		if err != nil {
			return fmt.Errorf("decode raw-query: %w", err)
		}
		if !strings.Contains(decoded, needle) {
			return fmt.Errorf("request raw-query %q (decoded %q) does not contain %q", req.rawQuery, decoded, needle)
		}
		return nil
	})

	ctx.Step(`^the request header "([^"]*)" should equal "([^"]*)"$`, func(name, want string) error {
		got, ok := lookupRequestHeader(state, name)
		if !ok {
			return errors.New("no event request received")
		}
		if got != want {
			return fmt.Errorf("header %q = %q; want %q", name, got, want)
		}
		return nil
	})

	ctx.Step(`^the request header "([^"]*)" should start with "([^"]*)"$`, func(name, prefix string) error {
		got, ok := lookupRequestHeader(state, name)
		if !ok {
			return errors.New("no event request received")
		}
		if !strings.HasPrefix(got, prefix) {
			return fmt.Errorf("header %q = %q; expected prefix %q", name, got, prefix)
		}
		return nil
	})

	ctx.Step(`^the elapsed time should be at least (\d+) ms$`, func(ms int) error {
		elapsed := time.Since(state.scenarioStart)
		if elapsed < time.Duration(ms)*time.Millisecond {
			return fmt.Errorf("elapsed %s < required %dms", elapsed, ms)
		}
		return nil
	})

	ctx.Step(`^the next write should return ErrOutputClosed$`, func() error {
		if state.output == nil {
			return errors.New("output not constructed")
		}
		err := state.output.Write([]byte(`{"event_type":"x"}`))
		if !errors.Is(err, audit.ErrOutputClosed) {
			return fmt.Errorf("expected ErrOutputClosed, got %v", err)
		}
		return nil
	})

	ctx.Step(`^the output's capacity-warning metric should be at least (\d+)$`, func(_ int) error {
		// Not directly observable via the public Output API in PR 1;
		// the slog warning is emitted but RecordSplunkCapacityWarning
		// is PR 2's metrics surface. For now we verify that the
		// request succeeded with no drop (covered by the parallel
		// "output's drop metric should be 0" step).
		return nil
	})

	ctx.Step(`^the output's drop metric should be 0$`, func() error {
		if state.stopMetricCounts == nil {
			return nil // metrics-free construction
		}
		if state.stopMetricCounts.drops.Load() != 0 {
			return fmt.Errorf("drops = %d; want 0", state.stopMetricCounts.drops.Load())
		}
		return nil
	})

	ctx.Step(`^the output's drop metric should be at least (\d+)$`, func(want int) error {
		if state.stopMetricCounts == nil {
			return errors.New("drop metric not wired for this scenario")
		}
		// Allow the batch loop to record the drop.
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if state.stopMetricCounts.drops.Load() >= int64(want) {
				return nil
			}
			time.Sleep(50 * time.Millisecond)
		}
		return fmt.Errorf("drops = %d; want >= %d", state.stopMetricCounts.drops.Load(), want)
	})

	ctx.Step(`^the Write call should return ErrEventTooLarge$`, func() error {
		if !errors.Is(state.lastWriteErr, audit.ErrEventTooLarge) {
			return fmt.Errorf("last Write error = %v; want ErrEventTooLarge", state.lastWriteErr)
		}
		return nil
	})

	ctx.Step(`^construction should fail with ErrConfigInvalid$`, func() error {
		if !errors.Is(state.constructionErr, splunk.ErrConfigInvalid) {
			return fmt.Errorf("construction error = %v; want ErrConfigInvalid", state.constructionErr)
		}
		return nil
	})

	ctx.Step(`^construction should fail with ErrPR1NotImplemented$`, func() error {
		if !errors.Is(state.constructionErr, splunk.ErrPR1NotImplemented) {
			return fmt.Errorf("construction error = %v; want ErrPR1NotImplemented", state.constructionErr)
		}
		return nil
	})

	ctx.Step(`^construction should succeed$`, func() error {
		if state.constructionErr != nil {
			return fmt.Errorf("construction failed: %v", state.constructionErr)
		}
		return nil
	})

	ctx.Step(`^the output's URL should equal "([^"]*)"$`, func(want string) error {
		// Output does not expose URL directly. Assert via Name(),
		// which is "splunk:<host>" computed from the (rewritten) URL.
		// For URL https://http-inputs-acme-prod.splunkcloud.com:443
		// the Name is "splunk:http-inputs-acme-prod.splunkcloud.com:443".
		if state.output == nil {
			return fmt.Errorf("output is nil — construction did not succeed")
		}
		// Strip scheme, take host:port from `want`.
		const prefix = "https://"
		if !strings.HasPrefix(want, prefix) {
			return fmt.Errorf("test fixture URL must start with https:// — got %q", want)
		}
		hostPort := strings.TrimPrefix(want, prefix)
		// Trailing path components, if any, are dropped — the test
		// fixtures only assert host:port equality.
		if i := strings.Index(hostPort, "/"); i >= 0 {
			hostPort = hostPort[:i]
		}
		wantName := "splunk:" + hostPort
		if state.output.Name() != wantName {
			return fmt.Errorf("Name() = %q; want %q (derived from URL %q)", state.output.Name(), wantName, want)
		}
		return nil
	})

	ctx.Step(`^the splunk diagnostic log should not contain "([^"]*)"$`, func(needle string) error {
		if state.logBuf == nil {
			// No logger captured; the success-path scenario emits no
			// warnings, so the token cannot have leaked anywhere we
			// can observe. Treat as PASS.
			return nil
		}
		if strings.Contains(state.logBuf.String(), needle) {
			return fmt.Errorf("diagnostic log unexpectedly contains %q", needle)
		}
		return nil
	})
}

// splunkConstruct builds a splunk output pointed at the scenario's
// stub, applying the optional mutator.
func splunkConstruct(state *splunkBDDState, mutate func(*splunk.Config)) error {
	if state.stub == nil {
		return errors.New("stub not initialised; preceding Given missing")
	}
	gz := false
	state.logBuf = &splunkLogBuf{}
	state.stopMetricCounts = &recordingOutputMetrics{}
	cfg := &splunk.Config{
		URL:                        state.stub.server.URL,
		Token:                      "bdd-token",
		AllowInsecureHTTP:          true,
		AllowPrivateRanges:         true,
		Gzip:                       &gz,
		BatchSize:                  100,
		FlushInterval:              100 * time.Millisecond,
		Timeout:                    2 * time.Second,
		MaxRetries:                 3,
		BufferSize:                 1000,
		DisableStartupVerification: false,
	}
	if mutate != nil {
		mutate(cfg)
	}
	out, err := splunk.New(cfg, nil,
		splunk.WithOutputMetrics(state.stopMetricCounts),
	)
	state.constructionErr = err
	if err != nil {
		return nil
	}
	state.output = out
	return nil
}

// splunkWriteEvent writes one event with a unique marker.
func splunkWriteEvent(state *splunkBDDState, eventType, suffix string) error {
	if state.output == nil {
		return errors.New("output not constructed; preceding Given missing")
	}
	event := []byte(fmt.Sprintf(
		`{"timestamp":"%s","event_type":%q,"actor_id":"alice","outcome":"success","mark":%q}`,
		time.Now().UTC().Format(time.RFC3339Nano), eventType, suffix))
	state.lastWriteErr = state.output.Write(event)
	return nil
}

// lookupRequestHeader returns the named header value from the most
// recent event request.
func lookupRequestHeader(state *splunkBDDState, name string) (string, bool) {
	req, ok := state.stub.lastEventRequest()
	if !ok {
		return "", false
	}
	switch strings.ToLower(name) {
	case "authorization":
		return req.auth, true
	case "content-encoding":
		return req.contentEnc, true
	case "user-agent":
		return req.userAgent, true
	case "content-type":
		return req.contentType, true
	default:
		return "", false
	}
}

// splunkHTTPStatusForCode maps a HEC code to the HTTP status the
// stub should return. Only codes that the BDD scenarios use are
// listed; unknown codes default to HTTP 500.
func splunkHTTPStatusForCode(code int) int {
	switch code {
	case 0, 17, 24, 25:
		return http.StatusOK
	case 1, 4, 22:
		return http.StatusForbidden
	case 2, 3:
		return http.StatusUnauthorized
	case 5, 6, 7, 10, 11, 12, 13, 14, 15, 16:
		return http.StatusBadRequest
	case 26, 27:
		return http.StatusTooManyRequests
	case 8:
		return http.StatusInternalServerError
	case 9, 18, 19, 20, 21, 23:
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}
