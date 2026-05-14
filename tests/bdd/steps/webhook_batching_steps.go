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

// Step definitions for #463 — wire-level batched payload validation
// (JSON NDJSON + CEF text). Uses a purpose-built local httptest
// receiver that preserves the raw request body and headers per
// request, which the docker webhook-receiver does not (it
// JSON-decodes a single value per request — fine for single-event
// assertions, useless for body-structure assertions).

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"

	"github.com/cucumber/godog"

	"github.com/axonops/audit"
	"github.com/axonops/audit/webhook"
)

// capturedRequest snapshots the body and headers of one POST.
type capturedRequest struct {
	When        time.Time
	ContentType string
	Body        []byte
}

// bodyCaptureReceiver is a local HTTP server that captures the raw
// body and Content-Type of every POST it receives, in order. Unlike
// the docker webhook-receiver (which decodes one JSON value per
// request), this server preserves the wire bytes verbatim so tests
// can assert NDJSON line structure, CEF line structure, and the
// exact Content-Type header value.
type bodyCaptureReceiver struct {
	server   *httptest.Server
	requestC chan struct{}
	requests []capturedRequest
	mu       sync.Mutex
}

func newBodyCaptureReceiver() *bodyCaptureReceiver {
	r := &bodyCaptureReceiver{requestC: make(chan struct{}, 1024)}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /events", func(w http.ResponseWriter, req *http.Request) {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			http.Error(w, "read body: "+err.Error(), http.StatusInternalServerError)
			return
		}
		r.mu.Lock()
		r.requests = append(r.requests, capturedRequest{
			Body:        body,
			ContentType: req.Header.Get("Content-Type"),
			When:        time.Now(),
		})
		r.mu.Unlock()
		select {
		case r.requestC <- struct{}{}:
		default:
		}
		w.WriteHeader(http.StatusNoContent)
	})
	r.server = httptest.NewServer(mux)
	return r
}

func (r *bodyCaptureReceiver) url() string { return r.server.URL + "/events" }

func (r *bodyCaptureReceiver) close() { r.server.Close() }

// waitForRequests blocks until at least n requests are captured or
// timeout elapses. Returns true on success.
func (r *bodyCaptureReceiver) waitForRequests(n int, timeout time.Duration) bool {
	deadline := time.After(timeout)
	for {
		r.mu.Lock()
		count := len(r.requests)
		r.mu.Unlock()
		if count >= n {
			return true
		}
		select {
		case <-r.requestC:
		case <-deadline:
			return false
		}
	}
}

// snapshot returns a copy of the captured requests in order.
func (r *bodyCaptureReceiver) snapshot() []capturedRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]capturedRequest, len(r.requests))
	copy(out, r.requests)
	return out
}

// registerWebhookBatchingSteps registers steps for #463. Wires
// the bodyCaptureReceiver lifecycle to the test context via
// tc.LocalReceiver so cleanup runs at the end of every scenario.
//
//nolint:gocognit,gocyclo,cyclop // BDD step registration — many small step closures, low per-step complexity.
func registerWebhookBatchingSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^a local body-capturing webhook receiver$`, func() error {
		rcv := newBodyCaptureReceiver()
		tc.LocalReceiver = rcv
		tc.AddCleanup(rcv.close)
		return nil
	})

	ctx.Step(`^an auditor with webhook output to the body-capture receiver, batch size (\d+)$`, func(batchSize int) error {
		return setupBatchingAuditor(tc, batchSize, nil)
	})

	ctx.Step(`^an auditor with webhook output to the body-capture receiver using CEF formatter, batch size (\d+)$`, func(batchSize int) error {
		cefFmt := &audit.CEFFormatter{Vendor: "Test", Product: "BDD", Version: "1.0"}
		return setupBatchingAuditor(tc, batchSize, cefFmt)
	})

	ctx.Step(`^I audit (\d+) uniquely marked batching events$`, func(n int) error {
		for i := 1; i <= n; i++ {
			err := tc.Auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
				"outcome":   "success",
				"actor_id":  fmt.Sprintf("actor-%d", i),
				"marker":    fmt.Sprintf("m%d", i),
				"target_id": fmt.Sprintf("user-%d", i),
			}))
			if err != nil {
				return fmt.Errorf("audit event %d: %w", i, err)
			}
		}
		return nil
	})

	ctx.Step(`^I close the batching auditor$`, func() error {
		if tc.Auditor == nil {
			return nil
		}
		return tc.Auditor.Close()
	})

	ctx.Step(`^the body-capture receiver should have at least (\d+) request within (\d+) seconds$`, func(n, secs int) error {
		rcv, ok := tc.LocalReceiver.(*bodyCaptureReceiver)
		if !ok || rcv == nil {
			return fmt.Errorf("no body-capture receiver in scope")
		}
		if !rcv.waitForRequests(n, time.Duration(secs)*time.Second) {
			return fmt.Errorf("expected at least %d requests, got %d after %d seconds", n, len(rcv.snapshot()), secs)
		}
		return nil
	})

	ctx.Step(`^the most recent body-capture request body should have exactly (\d+) NDJSON lines$`, func(n int) error {
		body, err := latestBody(tc)
		if err != nil {
			return err
		}
		lines := splitNDJSON(body)
		if len(lines) != n {
			return fmt.Errorf("expected %d NDJSON lines, got %d (body=%q)", n, len(lines), body)
		}
		for i, line := range lines {
			var v map[string]any
			if err := json.Unmarshal(line, &v); err != nil {
				return fmt.Errorf("line %d not valid JSON (line=%q): %w", i+1, line, err)
			}
		}
		return nil
	})

	ctx.Step(`^the most recent body-capture request body should have exactly (\d+) CEF lines$`, func(n int) error {
		body, err := latestBody(tc)
		if err != nil {
			return err
		}
		// Independent CEF line splitter — do NOT call the formatter to
		// parse, otherwise we'd be re-asserting what we built.
		lines := splitNonEmptyLines(body)
		if len(lines) != n {
			return fmt.Errorf("expected %d CEF lines, got %d (body=%q)", n, len(lines), body)
		}
		for i, line := range lines {
			if !bytes.HasPrefix(line, []byte("CEF:0|")) {
				return fmt.Errorf("line %d does not start with \"CEF:0|\" (line=%q)", i+1, line)
			}
		}
		return nil
	})

	ctx.Step(`^the most recent body-capture request body should end with a newline$`, func() error {
		body, err := latestBody(tc)
		if err != nil {
			return err
		}
		if len(body) == 0 || body[len(body)-1] != '\n' {
			return fmt.Errorf("body does not end with newline (body=%q)", body)
		}
		return nil
	})

	ctx.Step(`^line (\d+) of the body-capture body should contain marker "([^"]*)"$`, func(lineN int, marker string) error {
		body, err := latestBody(tc)
		if err != nil {
			return err
		}
		lines := splitNDJSON(body)
		if lineN < 1 || lineN > len(lines) {
			return fmt.Errorf("line %d out of range (have %d lines)", lineN, len(lines))
		}
		if !bytes.Contains(lines[lineN-1], []byte(`"marker":"`+marker+`"`)) {
			return fmt.Errorf("line %d does not contain marker %q (line=%q)", lineN, marker, lines[lineN-1])
		}
		return nil
	})

	ctx.Step(`^the most recent body-capture request Content-Type should be "([^"]*)"$`, func(want string) error {
		req, err := latestRequest(tc)
		if err != nil {
			return err
		}
		if req.ContentType != want {
			return fmt.Errorf("Content-Type: got %q, want %q", req.ContentType, want)
		}
		return nil
	})

	ctx.Step(`^the most recent body-capture request Content-Type should not be "([^"]*)"$`, func(notWant string) error {
		req, err := latestRequest(tc)
		if err != nil {
			return err
		}
		if req.ContentType == notWant {
			return fmt.Errorf("Content-Type should not be %q but it is", notWant)
		}
		return nil
	})

	ctx.Step(`^the body-capture receiver should have exactly (\d+) requests$`, func(n int) error {
		rcv, ok := tc.LocalReceiver.(*bodyCaptureReceiver)
		if !ok || rcv == nil {
			return fmt.Errorf("no body-capture receiver in scope")
		}
		// Empty-close: give the goroutine a brief window to confirm
		// it did NOT make a request. 500 ms is generous given the
		// 50 ms flush interval below.
		time.Sleep(500 * time.Millisecond)
		got := len(rcv.snapshot())
		if got != n {
			return fmt.Errorf("expected exactly %d requests, got %d", n, got)
		}
		return nil
	})

	// Multi-output (#463) — Content-Type isolation between two webhook
	// outputs on the same auditor, one JSON one CEF.
	ctx.Step(`^two local body-capturing webhook receivers$`, func() error {
		a := newBodyCaptureReceiver()
		b := newBodyCaptureReceiver()
		tc.LocalReceiver = a
		tc.LocalReceiverB = b
		tc.AddCleanup(a.close)
		tc.AddCleanup(b.close)
		return nil
	})

	ctx.Step(`^an auditor with two webhook outputs: receiver A using JSON, receiver B using CEF, batch size (\d+)$`, func(batchSize int) error {
		return setupDualBatchingAuditor(tc, batchSize)
	})

	ctx.Step(`^receiver A should have at least (\d+) request within (\d+) seconds$`, func(n, secs int) error {
		rcv, ok := tc.LocalReceiver.(*bodyCaptureReceiver)
		if !ok || rcv == nil {
			return fmt.Errorf("no receiver A in scope")
		}
		if !rcv.waitForRequests(n, time.Duration(secs)*time.Second) {
			return fmt.Errorf("receiver A: expected at least %d requests, got %d", n, len(rcv.snapshot()))
		}
		return nil
	})

	ctx.Step(`^receiver B should have at least (\d+) request within (\d+) seconds$`, func(n, secs int) error {
		rcv, ok := tc.LocalReceiverB.(*bodyCaptureReceiver)
		if !ok || rcv == nil {
			return fmt.Errorf("no receiver B in scope")
		}
		if !rcv.waitForRequests(n, time.Duration(secs)*time.Second) {
			return fmt.Errorf("receiver B: expected at least %d requests, got %d", n, len(rcv.snapshot()))
		}
		return nil
	})

	ctx.Step(`^the most recent receiver A request Content-Type should be "([^"]*)"$`, func(want string) error {
		return assertReceiverContentType(tc.LocalReceiver, "A", want)
	})

	ctx.Step(`^the most recent receiver B request Content-Type should be "([^"]*)"$`, func(want string) error {
		return assertReceiverContentType(tc.LocalReceiverB, "B", want)
	})
}

func assertReceiverContentType(holder any, label, want string) error {
	rcv, ok := holder.(*bodyCaptureReceiver)
	if !ok || rcv == nil {
		return fmt.Errorf("no receiver %s in scope", label)
	}
	reqs := rcv.snapshot()
	if len(reqs) == 0 {
		return fmt.Errorf("receiver %s captured no requests", label)
	}
	got := reqs[len(reqs)-1].ContentType
	if got != want {
		return fmt.Errorf("receiver %s Content-Type: got %q, want %q", label, got, want)
	}
	return nil
}

// setupDualBatchingAuditor wires one auditor with two webhook
// outputs — one using the default JSON formatter pointed at
// receiver A, one using CEFFormatter pointed at receiver B.
// Validates the per-output Content-Type isolation invariant.
func setupDualBatchingAuditor(tc *AuditTestContext, batchSize int) error {
	rcvA, ok := tc.LocalReceiver.(*bodyCaptureReceiver)
	if !ok || rcvA == nil {
		return fmt.Errorf("receiver A not configured")
	}
	rcvB, ok := tc.LocalReceiverB.(*bodyCaptureReceiver)
	if !ok || rcvB == nil {
		return fmt.Errorf("receiver B not configured")
	}
	if tc.Taxonomy == nil {
		tax, err := audit.ParseTaxonomyYAML([]byte(routingTaxonomyYAML))
		if err != nil {
			return fmt.Errorf("parse taxonomy: %w", err)
		}
		tc.Taxonomy = tax
	}

	mkOut := func(url string) (*webhook.Output, error) {
		return webhook.New(&webhook.Config{
			URL:                url,
			AllowInsecureHTTP:  true,
			AllowPrivateRanges: true,
			BatchSize:          batchSize,
			FlushInterval:      50 * time.Millisecond,
			Timeout:            5 * time.Second,
			MaxRetries:         1,
			BufferSize:         1000,
		}, nil)
	}

	outA, err := mkOut(rcvA.url())
	if err != nil {
		return fmt.Errorf("create webhook A: %w", err)
	}
	tc.AddCleanup(func() { _ = outA.Close() })

	outB, err := mkOut(rcvB.url())
	if err != nil {
		return fmt.Errorf("create webhook B: %w", err)
	}
	tc.AddCleanup(func() { _ = outB.Close() })

	cefFmt := &audit.CEFFormatter{Vendor: "Test", Product: "BDD", Version: "1.0"}
	auditor, err := audit.New(
		audit.WithTaxonomy(tc.Taxonomy),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(outA),
		audit.WithNamedOutput(outB, audit.WithOutputFormatter(cefFmt)),
	)
	if err != nil {
		return fmt.Errorf("create auditor: %w", err)
	}
	tc.Auditor = auditor
	tc.AddCleanup(func() { _ = auditor.Close() })
	return nil
}

// setupBatchingAuditor builds an auditor with a single webhook
// output pointing at the body-capture receiver. The webhook output
// is constructed with a tight flush_interval so close() drains
// promptly.
func setupBatchingAuditor(tc *AuditTestContext, batchSize int, formatter audit.Formatter) error {
	rcv, ok := tc.LocalReceiver.(*bodyCaptureReceiver)
	if !ok || rcv == nil {
		return fmt.Errorf("no body-capture receiver in scope; add the Given step first")
	}
	if tc.Taxonomy == nil {
		tax, err := audit.ParseTaxonomyYAML([]byte(routingTaxonomyYAML))
		if err != nil {
			return fmt.Errorf("parse taxonomy: %w", err)
		}
		tc.Taxonomy = tax
	}

	out, err := webhook.New(&webhook.Config{
		URL:                rcv.url(),
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
		BatchSize:          batchSize,
		FlushInterval:      50 * time.Millisecond,
		Timeout:            5 * time.Second,
		MaxRetries:         1,
		BufferSize:         1000,
	}, nil)
	if err != nil {
		return fmt.Errorf("create webhook: %w", err)
	}
	tc.AddCleanup(func() { _ = out.Close() })

	var outputOpts []audit.OutputOption
	if formatter != nil {
		outputOpts = append(outputOpts, audit.WithOutputFormatter(formatter))
	}
	opts := []audit.Option{
		audit.WithTaxonomy(tc.Taxonomy),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(out, outputOpts...),
	}
	auditor, err := audit.New(opts...)
	if err != nil {
		return fmt.Errorf("create auditor: %w", err)
	}
	tc.Auditor = auditor
	tc.AddCleanup(func() { _ = auditor.Close() })
	return nil
}

// latestBody returns the most recent request body from the body-
// capture receiver, or an error if none has been captured.
func latestBody(tc *AuditTestContext) ([]byte, error) {
	req, err := latestRequest(tc)
	if err != nil {
		return nil, err
	}
	return req.Body, nil
}

func latestRequest(tc *AuditTestContext) (capturedRequest, error) {
	rcv, ok := tc.LocalReceiver.(*bodyCaptureReceiver)
	if !ok || rcv == nil {
		return capturedRequest{}, fmt.Errorf("no body-capture receiver in scope")
	}
	reqs := rcv.snapshot()
	if len(reqs) == 0 {
		return capturedRequest{}, fmt.Errorf("no requests captured yet")
	}
	return reqs[len(reqs)-1], nil
}

// splitNDJSON splits an NDJSON body into non-empty lines stripped of
// their trailing \n.
func splitNDJSON(body []byte) [][]byte {
	return splitNonEmptyLines(body)
}

func splitNonEmptyLines(body []byte) [][]byte {
	if len(body) == 0 {
		return nil
	}
	parts := bytes.Split(body, []byte("\n"))
	out := make([][]byte, 0, len(parts))
	for _, p := range parts {
		if len(bytes.TrimSpace(p)) == 0 {
			continue
		}
		out = append(out, p)
	}
	return out
}
