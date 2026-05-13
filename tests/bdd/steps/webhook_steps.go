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
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cucumber/godog"

	"github.com/axonops/audit"
	"github.com/axonops/audit/webhook"
)

// reserveUnboundPort binds a TCP port then immediately releases it,
// returning the host:port string of the now-unbound address. A TCP
// dial to this address returns ECONNREFUSED synchronously, giving
// the startup probe a deterministic unreachable target without
// relying on flaky "pick an unused port" guesses.
func reserveUnboundPort() (string, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("reserve port: %w", err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		return "", fmt.Errorf("release port: %w", err)
	}
	return addr, nil
}

func registerWebhookSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	registerWebhookGivenSteps(ctx, tc)
	registerWebhookWhenSteps(ctx, tc)
	registerWebhookThenSteps(ctx, tc)
}

// tlsWebhookReceiver is a local HTTPS server that captures events.
type tlsWebhookReceiver struct {
	server *httptest.Server
	events []json.RawMessage
	mu     sync.Mutex
}

func newTLSWebhookReceiver() *tlsWebhookReceiver {
	r := &tlsWebhookReceiver{}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /events", func(w http.ResponseWriter, req *http.Request) {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			http.Error(w, "read body: "+err.Error(), http.StatusInternalServerError)
			return
		}
		r.mu.Lock()
		// Split NDJSON lines.
		for _, line := range strings.Split(string(body), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				r.events = append(r.events, json.RawMessage(line))
			}
		}
		r.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})
	// httptest exemption (#559): the production webhook-receiver
	// container is HTTP-only; this fixture exercises the webhook
	// output's TLS path (CA pinning, server-cert handshake) which
	// the container cannot serve without a TLS rebuild.
	r.server = httptest.NewTLSServer(mux)
	return r
}

func (r *tlsWebhookReceiver) eventCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.events)
}

func (r *tlsWebhookReceiver) close() {
	r.server.Close()
}

// caFile writes the TLS server's CA certificate to a temp file and returns the path.
func (r *tlsWebhookReceiver) caFile() (string, error) {
	cert := r.server.Certificate()
	if cert == nil {
		return "", fmt.Errorf("no server certificate")
	}
	f, err := os.CreateTemp("", "bdd-ca-*.pem")
	if err != nil {
		return "", fmt.Errorf("create temp file: %w", err)
	}
	if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
		_ = f.Close()
		return "", fmt.Errorf("encode PEM: %w", err)
	}
	_ = f.Close()
	return f.Name(), nil
}

// localWebhookReceiver is a plain HTTP server that captures events,
// used for SSRF and redirect tests that don't need Docker.
type localWebhookReceiver struct { //nolint:govet // fieldalignment: readability preferred
	server   *httptest.Server
	events   []json.RawMessage
	redirect bool
	// large3xxBodySize, when >0, makes the receiver reply to POST /events
	// with HTTP 300 and a body of that size (streamed in 4 KiB chunks).
	// Used to exercise the client-side 3xx drain cap (#484).
	large3xxBodySize int64
	bytesSent        atomic.Int64
	handlerDone      chan struct{}
	doneOnce         sync.Once
	mu               sync.Mutex
}

func newLocalWebhookReceiver(redirect bool) *localWebhookReceiver {
	r := &localWebhookReceiver{redirect: redirect}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /events", func(w http.ResponseWriter, req *http.Request) {
		if r.redirect {
			http.Redirect(w, req, "/other", http.StatusMovedPermanently)
			return
		}
		if r.large3xxBodySize > 0 {
			r.handleLarge3xx(w)
			return
		}
		body, err := io.ReadAll(req.Body)
		if err != nil {
			http.Error(w, "read body: "+err.Error(), http.StatusInternalServerError)
			return
		}
		r.mu.Lock()
		for _, line := range strings.Split(string(body), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				r.events = append(r.events, json.RawMessage(line))
			}
		}
		r.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})
	// httptest exemption (#559): tests redirect (301) handling and
	// large-3xx-body delivery cap (#484). Adversarial responses no
	// real receiver would emit; precise control of redirect target
	// and chunked 3xx body is the contract under test.
	r.server = httptest.NewServer(mux)
	return r
}

// handleLarge3xx writes an HTTP 300 Multiple Choices response with a
// body of r.large3xxBodySize bytes, flushing every 4 KiB so TCP
// backpressure is observable as soon as the client stops reading.
// Total bytes successfully written are recorded in r.bytesSent so the
// BDD scenario can assert the client capped the drain. Uses chunked
// transfer (no Content-Length) so a client that closes after reading
// its cap does not produce "superfluous WriteHeader" log noise.
// sync.Once guarantees handlerDone is closed exactly once even if a
// future scenario permits the client to retry the request.
func (r *localWebhookReceiver) handleLarge3xx(w http.ResponseWriter) {
	defer func() {
		if r.handlerDone != nil {
			r.doneOnce.Do(func() { close(r.handlerDone) })
		}
	}()
	chunk := make([]byte, 4096)
	for i := range chunk {
		chunk[i] = 'X'
	}
	w.WriteHeader(http.StatusMultipleChoices) // 300 — no stdlib redirect-follow
	flusher, _ := w.(http.Flusher)
	remaining := r.large3xxBodySize
	for remaining > 0 {
		toWrite := int64(len(chunk))
		if toWrite > remaining {
			toWrite = remaining
		}
		n, err := w.Write(chunk[:toWrite])
		r.bytesSent.Add(int64(n))
		if err != nil {
			return
		}
		if flusher != nil {
			flusher.Flush()
		}
		remaining -= int64(n)
	}
}

func (r *localWebhookReceiver) eventCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.events)
}

func (r *localWebhookReceiver) close() {
	r.server.Close()
}

func registerWebhookGivenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^an auditor with webhook output configured for batch size (\d+)$`, func(batchSize int) error {
		return createWebhookAuditor(tc, &webhook.Config{
			BatchSize:     batchSize,
			FlushInterval: 100 * time.Millisecond,
		})
	})

	ctx.Step(`^an auditor with webhook output configured for batch size (\d+) and flush interval (\d+)ms$`, func(batchSize, flushMS int) error {
		return createWebhookAuditor(tc, &webhook.Config{
			BatchSize:     batchSize,
			FlushInterval: time.Duration(flushMS) * time.Millisecond,
		})
	})

	ctx.Step(`^an auditor with webhook output configured for batch size (\d+) and flush interval (\d+)s$`, func(batchSize, flushS int) error {
		return createWebhookAuditor(tc, &webhook.Config{
			BatchSize:     batchSize,
			FlushInterval: time.Duration(flushS) * time.Second,
		})
	})

	// Max event size (#688).
	ctx.Step(`^an auditor with webhook output configured for max event bytes (\d+)$`,
		func(maxEventBytes int) error {
			return createWebhookAuditor(tc, &webhook.Config{
				BatchSize:     1,
				FlushInterval: 50 * time.Millisecond,
				MaxEventBytes: maxEventBytes,
			})
		})

	// Byte-threshold batching (#687). Three-knob Given — mirrors the
	// pattern used by Loki and syslog BDD scenarios.
	ctx.Step(`^an auditor with webhook output configured for batch size (\d+) and flush interval (\d+)s and max batch bytes (\d+)$`,
		func(batchSize, flushS, maxBatchBytes int) error {
			return createWebhookAuditor(tc, &webhook.Config{
				BatchSize:     batchSize,
				FlushInterval: time.Duration(flushS) * time.Second,
				MaxBatchBytes: maxBatchBytes,
			})
		})

	ctx.Step(`^an auditor with webhook output configured for batch size (\d+) and max retries (\d+)$`, func(batchSize, maxRetries int) error {
		return createWebhookAuditor(tc, &webhook.Config{
			BatchSize:     batchSize,
			FlushInterval: 100 * time.Millisecond,
			MaxRetries:    maxRetries,
		})
	})

	ctx.Step(`^an auditor with webhook output with custom header "([^"]*)" = "([^"]*)"$`, func(name, value string) error {
		return createWebhookAuditor(tc, &webhook.Config{
			BatchSize:     1,
			FlushInterval: 100 * time.Millisecond,
			Headers:       map[string]string{name: value},
		})
	})

	ctx.Step(`^an auditor with webhook output to "([^"]*)" with AllowInsecureHTTP$`, func(url string) error {
		return createWebhookAuditorWithURL(tc, url, &webhook.Config{
			BatchSize:     1,
			FlushInterval: 100 * time.Millisecond,
		})
	})

	ctx.Step(`^mock webhook metrics are configured$`, func() error {
		tc.WebhookMetrics = &MockOutputMetrics{}
		return nil
	})

	ctx.Step(`^an auditor with webhook output and webhook metrics configured for batch size (\d+)$`, func(batchSize int) error {
		return createWebhookAuditorWithWebhookMetrics(tc, batchSize)
	})

	ctx.Step(`^the webhook receiver is configured to return status (\d+)$`, func(status int) error {
		return configureWebhook(tc.WebhookURL, status, 0)
	})

	ctx.Step(`^the webhook receiver is reconfigured to return status (\d+)$`, func(status int) error {
		return configureWebhook(tc.WebhookURL, status, 0)
	})

	ctx.Step(`^a local HTTPS webhook receiver$`, func() error {
		r := newTLSWebhookReceiver()
		tc.TLSReceiver = r
		tc.AddCleanup(func() { r.close() })
		return nil
	})

	ctx.Step(`^an auditor with webhook output to the HTTPS receiver with custom CA$`, func() error {
		r, ok := tc.TLSReceiver.(*tlsWebhookReceiver)
		if !ok || r == nil {
			return fmt.Errorf("no TLS webhook receiver configured")
		}
		caPath, err := r.caFile()
		if err != nil {
			return fmt.Errorf("get CA file: %w", err)
		}
		tc.AddCleanup(func() { _ = os.Remove(caPath) })

		cfg := &webhook.Config{
			URL:                r.server.URL + "/events",
			TLSCA:              caPath,
			AllowPrivateRanges: true,
			BatchSize:          1,
			FlushInterval:      100 * time.Millisecond,
			Timeout:            5 * time.Second,
		}
		out, err := webhook.New(cfg, nil)
		if err != nil {
			tc.LastErr = err
			return nil //nolint:nilerr // scenario may assert on tc.LastErr
		}
		tc.AddCleanup(func() { _ = out.Close() })
		opts := []audit.Option{
			audit.WithTaxonomy(tc.Taxonomy),
			audit.WithAppName("test-app"),
			audit.WithHost("test-host"),
			audit.WithOutputs(out),
		}
		auditor, err := audit.New(opts...)
		if err != nil {
			return fmt.Errorf("create auditor: %w", err)
		}
		tc.Auditor = auditor
		tc.AddCleanup(func() { _ = auditor.Close() })
		return nil
	})

	registerWebhookGivenSSRFSteps(ctx, tc)
}

func registerWebhookGivenSSRFSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) { //nolint:gocognit,gocyclo,cyclop // BDD step registration
	ctx.Step(`^a local HTTP webhook receiver$`, func() error {
		r := newLocalWebhookReceiver(false)
		tc.LocalReceiver = r
		tc.AddCleanup(func() { r.close() })
		return nil
	})

	ctx.Step(`^a local HTTP webhook receiver configured to redirect$`, func() error {
		r := newLocalWebhookReceiver(true)
		tc.LocalReceiver = r
		tc.AddCleanup(func() { r.close() })
		return nil
	})

	ctx.Step(`^a local HTTP webhook receiver returning 3xx with a (\d+) MiB body$`, func(bodyMiB int) error {
		r := newLocalWebhookReceiver(false)
		r.large3xxBodySize = int64(bodyMiB) << 20
		r.handlerDone = make(chan struct{})
		tc.LocalReceiver = r
		tc.AddCleanup(func() { r.close() })
		return nil
	})

	ctx.Step(`^an auditor with webhook output to the 3xx receiver$`, func() error {
		r, ok := tc.LocalReceiver.(*localWebhookReceiver)
		if !ok || r == nil {
			return fmt.Errorf("no local webhook receiver configured")
		}
		cfg := &webhook.Config{
			URL:                r.server.URL + "/events",
			AllowInsecureHTTP:  true,
			AllowPrivateRanges: true,
			BatchSize:          1,
			FlushInterval:      100 * time.Millisecond,
			Timeout:            5 * time.Second,
			MaxRetries:         1,
		}
		out, err := webhook.New(cfg, nil)
		if err != nil {
			return fmt.Errorf("create webhook output: %w", err)
		}
		tc.AddCleanup(func() { _ = out.Close() })
		opts := []audit.Option{
			audit.WithTaxonomy(tc.Taxonomy),
			audit.WithAppName("test-app"),
			audit.WithHost("test-host"),
			audit.WithOutputs(out),
		}
		auditor, err := audit.New(opts...)
		if err != nil {
			return fmt.Errorf("create auditor: %w", err)
		}
		tc.Auditor = auditor
		tc.AddCleanup(func() { _ = auditor.Close() })
		return nil
	})

	ctx.Step(`^the webhook receiver should have transmitted less than (\d+) MiB of body$`, func(limitMiB int) error {
		r, ok := tc.LocalReceiver.(*localWebhookReceiver)
		if !ok || r == nil {
			return fmt.Errorf("no local webhook receiver configured")
		}
		// Wait for the handler goroutine to return (client closed
		// connection, subsequent Write returned an error, loop exited).
		select {
		case <-r.handlerDone:
		case <-time.After(10 * time.Second):
			return fmt.Errorf("handler did not terminate within 10s")
		}
		sent := r.bytesSent.Load()
		limit := int64(limitMiB) << 20
		if sent >= limit {
			return fmt.Errorf("server transmitted %d bytes; expected < %d (cap ineffective)", sent, limit)
		}
		return nil
	})

	ctx.Step(`^an auditor with webhook output to the local receiver without AllowPrivateRanges$`, func() error {
		r, ok := tc.LocalReceiver.(*localWebhookReceiver)
		if !ok || r == nil {
			return fmt.Errorf("no local webhook receiver configured")
		}
		return createWebhookAuditorSSRF(tc, r.server.URL+"/events", false)
	})

	ctx.Step(`^an auditor with webhook output to the local receiver with AllowPrivateRanges$`, func() error {
		r, ok := tc.LocalReceiver.(*localWebhookReceiver)
		if !ok || r == nil {
			return fmt.Errorf("no local webhook receiver configured")
		}
		return createWebhookAuditorSSRF(tc, r.server.URL+"/events", true)
	})

	ctx.Step(`^an auditor with webhook output to the redirecting receiver with metrics$`, func() error {
		r, ok := tc.LocalReceiver.(*localWebhookReceiver)
		if !ok || r == nil {
			return fmt.Errorf("no local webhook receiver configured")
		}
		cfg := &webhook.Config{
			URL:                r.server.URL + "/events",
			AllowInsecureHTTP:  true,
			AllowPrivateRanges: true,
			BatchSize:          1,
			FlushInterval:      100 * time.Millisecond,
			Timeout:            2 * time.Second,
			MaxRetries:         1,
		}
		var oOpts []webhook.Option

		if tc.WebhookMetrics != nil {

			oOpts = append(oOpts, webhook.WithOutputMetrics(tc.WebhookMetrics))

		}

		out, err := webhook.New(cfg, nil, oOpts...)
		if err != nil {
			return fmt.Errorf("create webhook output: %w", err)
		}
		tc.AddCleanup(func() { _ = out.Close() })
		opts := []audit.Option{
			audit.WithTaxonomy(tc.Taxonomy),
			audit.WithAppName("test-app"),
			audit.WithHost("test-host"),
			audit.WithOutputs(out),
		}
		auditor, err := audit.New(opts...)
		if err != nil {
			return fmt.Errorf("create auditor: %w", err)
		}
		tc.Auditor = auditor
		tc.AddCleanup(func() { _ = auditor.Close() })
		return nil
	})

	ctx.Step(`^an auditor with webhook to local receiver with buffer size (\d+) and metrics$`, func(bufSize int) error {
		r, ok := tc.LocalReceiver.(*localWebhookReceiver)
		if !ok || r == nil {
			return fmt.Errorf("no local webhook receiver configured")
		}
		cfg := &webhook.Config{
			URL:                r.server.URL + "/events",
			AllowInsecureHTTP:  true,
			AllowPrivateRanges: true,
			BatchSize:          1,
			FlushInterval:      100 * time.Millisecond,
			Timeout:            5 * time.Second,
			BufferSize:         bufSize,
		}
		var oOpts []webhook.Option

		if tc.WebhookMetrics != nil {

			oOpts = append(oOpts, webhook.WithOutputMetrics(tc.WebhookMetrics))

		}

		out, err := webhook.New(cfg, nil, oOpts...)
		if err != nil {
			return fmt.Errorf("create webhook output: %w", err)
		}
		tc.AddCleanup(func() { _ = out.Close() })
		opts := []audit.Option{
			audit.WithTaxonomy(tc.Taxonomy),
			audit.WithAppName("test-app"),
			audit.WithHost("test-host"),
			audit.WithOutputs(out),
		}
		auditor, err := audit.New(opts...)
		if err != nil {
			return fmt.Errorf("create auditor: %w", err)
		}
		tc.Auditor = auditor
		tc.AddCleanup(func() { _ = auditor.Close() })
		return nil
	})
}

func registerWebhookWhenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	registerWebhookWhenAuditSteps(ctx, tc)
	registerWebhookWhenConstructionSteps(ctx, tc)
}

func registerWebhookWhenAuditSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^I audit a uniquely marked webhook "([^"]*)" event$`, func(eventType string) error {
		return auditMarkedWebhookEvent(tc, eventType, "default")
	})

	ctx.Step(`^I audit a uniquely marked webhook "([^"]*)" event "([^"]*)"$`, func(eventType, name string) error {
		return auditMarkedWebhookEvent(tc, eventType, name)
	})

	ctx.Step(`^I audit (\d+) uniquely marked webhook events$`, func(count int) error {
		for i := range count {
			name := fmt.Sprintf("webhook_%d", i)
			if err := auditMarkedWebhookEvent(tc, "user_create", name); err != nil {
				return fmt.Errorf("webhook event %d: %w", i, err)
			}
		}
		return nil
	})

	// Sized payloads for byte-threshold batching (#687) — handlers
	// extracted to keep registerWebhookWhenAuditSteps below the
	// cognitive-complexity threshold.
	ctx.Step(`^I audit (\d+) uniquely marked webhook events with (\d+) KiB payloads$`,
		auditWebhookSizedEventsStep(tc))

	ctx.Step(`^I audit a uniquely marked webhook "([^"]*)" event with a (\d+)-byte payload$`,
		auditWebhookOversizedEventStep(tc))

	ctx.Step(`^I wait (\d+) seconds for retries to exhaust$`, func(secs int) error {
		// scenario-control delay (#559): the step IS the wait. There is
		// no observable predicate to poll on — the contract is "wait N
		// seconds, then evaluate the post-conditions."
		time.Sleep(time.Duration(secs) * time.Second)
		return nil
	})

	ctx.Step(`^I rapidly audit (\d+) webhook events measuring time$`, func(count int) error {
		start := time.Now()
		for i := range count {
			_ = tc.Auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
				"outcome":  "success",
				"actor_id": fmt.Sprintf("rapid_%d", i),
			}))
		}
		tc.AuditDuration = time.Since(start)
		return nil
	})

	ctx.Step(`^all (\d+) audit calls should complete within (\d+) seconds$`, func(count, secs int) error {
		if tc.AuditDuration == 0 {
			return fmt.Errorf("no audit duration recorded")
		}
		maxDuration := time.Duration(secs) * time.Second
		if tc.AuditDuration > maxDuration {
			return fmt.Errorf("%d audit calls took %v (max %v) — suggests blocking", count, tc.AuditDuration, maxDuration)
		}
		return nil
	})
}

func registerWebhookWhenConstructionSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) { //nolint:gocognit,gocyclo,cyclop // BDD step registration
	ctx.Step(`^I try to create a webhook output to "([^"]*)" without AllowInsecureHTTP$`, func(url string) error {
		out, err := webhook.New(&webhook.Config{
			URL:                url,
			AllowInsecureHTTP:  false,
			AllowPrivateRanges: true,
			BatchSize:          1,
		}, nil)
		if out != nil {
			tc.AddCleanup(func() { _ = out.Close() })
		}
		tc.LastErr = err
		return nil
	})

	ctx.Step(`^I try to create a webhook output to "([^"]*)"$`, func(url string) error {
		out, err := webhook.New(&webhook.Config{
			URL:                url,
			AllowInsecureHTTP:  true,
			AllowPrivateRanges: true,
			BatchSize:          1,
			// Skip the startup probe so this step only exercises
			// config validation. Probe-time behaviour has its own
			// scenarios (#286).
			DisableStartupVerification: true,
		}, nil)
		if out != nil {
			tc.AddCleanup(func() { _ = out.Close() })
		}
		tc.LastErr = err
		return nil
	})

	ctx.Step(`^I try to create a webhook output to an unreachable URL$`, func() error {
		// Bind and immediately release a port so it's known-unbound;
		// the probe must reject the configuration at construction.
		addr, err := reserveUnboundPort()
		if err != nil {
			return err
		}
		out, err := webhook.New(&webhook.Config{
			URL:                "http://" + addr,
			AllowInsecureHTTP:  true,
			AllowPrivateRanges: true,
			BatchSize:          1,
		}, nil)
		if out != nil {
			tc.AddCleanup(func() { _ = out.Close() })
		}
		tc.LastErr = err
		return nil
	})

	ctx.Step(`^I try to create a webhook output to an unreachable URL with verify_on_startup false$`, func() error {
		addr, err := reserveUnboundPort()
		if err != nil {
			return err
		}
		out, err := webhook.New(&webhook.Config{
			URL:                        "http://" + addr,
			AllowInsecureHTTP:          true,
			AllowPrivateRanges:         true,
			BatchSize:                  1,
			DisableStartupVerification: true,
		}, nil)
		if out != nil {
			tc.AddCleanup(func() { _ = out.Close() })
		}
		tc.LastErr = err
		return nil
	})

	ctx.Step(`^I try to create a webhook output with header containing CRLF$`, func() error {
		out, err := webhook.New(&webhook.Config{
			URL:                "https://example.com/events",
			AllowPrivateRanges: true,
			BatchSize:          1,
			Headers:            map[string]string{"X-Bad": "value\r\nInjected: true"},
		}, nil)
		if out != nil {
			tc.AddCleanup(func() { _ = out.Close() })
		}
		tc.LastErr = err
		return nil
	})

	ctx.Step(`^I try to create a webhook output with batch size (\d+)$`, func(batchSize int) error {
		out, err := webhook.New(&webhook.Config{
			URL:                "https://example.com/events",
			AllowPrivateRanges: true,
			BatchSize:          batchSize,
		}, nil)
		if out != nil {
			tc.AddCleanup(func() { _ = out.Close() })
		}
		tc.LastErr = err
		return nil
	})

	ctx.Step(`^I try to create a webhook output with buffer size (\d+)$`, func(bufSize int) error {
		out, err := webhook.New(&webhook.Config{
			URL:                "https://example.com/events",
			AllowPrivateRanges: true,
			BatchSize:          1,
			BufferSize:         bufSize,
		}, nil)
		if out != nil {
			tc.AddCleanup(func() { _ = out.Close() })
		}
		tc.LastErr = err
		return nil
	})

	ctx.Step(`^I try to create a webhook output with max retries (\d+)$`, func(maxRetries int) error {
		out, err := webhook.New(&webhook.Config{
			URL:                "https://example.com/events",
			AllowPrivateRanges: true,
			BatchSize:          1,
			MaxRetries:         maxRetries,
		}, nil)
		if out != nil {
			tc.AddCleanup(func() { _ = out.Close() })
		}
		tc.LastErr = err
		return nil
	})

	ctx.Step(`^an auditor with webhook output to the HTTPS receiver with wrong CA and metrics$`, func() error {
		r, ok := tc.TLSReceiver.(*tlsWebhookReceiver)
		if !ok || r == nil {
			return fmt.Errorf("no TLS webhook receiver configured")
		}
		// Use invalid.crt — a valid PEM but different CA than the server's.
		wrongCA := filepath.Join(certDir(), "invalid.crt")
		cfg := &webhook.Config{
			URL:                r.server.URL + "/events",
			TLSCA:              wrongCA,
			AllowPrivateRanges: true,
			BatchSize:          1,
			FlushInterval:      100 * time.Millisecond,
			Timeout:            2 * time.Second,
			MaxRetries:         1,
			// Wrong-CA failure at runtime (write path) is the
			// property under test; the probe would short-circuit
			// at construction.
			DisableStartupVerification: true,
		}
		var oOpts []webhook.Option

		if tc.WebhookMetrics != nil {

			oOpts = append(oOpts, webhook.WithOutputMetrics(tc.WebhookMetrics))

		}

		out, err := webhook.New(cfg, nil, oOpts...)
		if err != nil {
			return fmt.Errorf("create webhook output: %w", err)
		}
		tc.AddCleanup(func() { _ = out.Close() })
		opts := []audit.Option{
			audit.WithTaxonomy(tc.Taxonomy),
			audit.WithAppName("test-app"),
			audit.WithHost("test-host"),
			audit.WithOutputs(out),
		}
		auditor, err := audit.New(opts...)
		if err != nil {
			return fmt.Errorf("create auditor: %w", err)
		}
		tc.Auditor = auditor
		tc.AddCleanup(func() { _ = auditor.Close() })
		return nil
	})
}

func registerWebhookThenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	registerWebhookThenCountSteps(ctx, tc)
	registerWebhookThenAssertSteps(ctx, tc)
}

func registerWebhookThenCountSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^the webhook receiver should have at least (\d+) events? within (\d+) seconds$`, func(n, timeout int) error {
		return assertWebhookEventCount(tc, n, time.Duration(timeout)*time.Second)
	})

	ctx.Step(`^the webhook receiver should have received all (\d+) events within (\d+) seconds$`, func(n, timeout int) error {
		return assertWebhookEventCount(tc, n, time.Duration(timeout)*time.Second)
	})

	ctx.Step(`^the webhook receiver should have at least (\d+) requests? within (\d+) seconds$`, func(n, timeout int) error {
		return assertWebhookEventCount(tc, n, time.Duration(timeout)*time.Second)
	})

	// #554 exact-count for non-retry happy paths. `events?|requests?`
	// covers both event and request semantics — receiver counts are
	// the same underlying counter.
	ctx.Step(`^the webhook receiver should have exactly (\d+) (?:events?|requests?) within (\d+) seconds$`, func(n, timeout int) error {
		return assertWebhookExactCount(tc, n, time.Duration(timeout)*time.Second)
	})

}

func registerWebhookThenAssertSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	registerWebhookThenBodySteps(ctx, tc)
	registerWebhookThenLocalReceiverSteps(ctx, tc)
	registerWebhookThenMetricsAndErrorSteps(ctx, tc)
}

func registerWebhookThenBodySteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^the received webhook event should have header "([^"]*)" with value "([^"]*)"$`, func(n, v string) error { return assertWebhookHeader(tc, n, v) })
	ctx.Step(`^the webhook event body should contain field "([^"]*)" with value "([^"]*)"$`, func(f, v string) error { return assertWebhookBodyField(tc, f, v) })
	ctx.Step(`^the webhook event body should contain field "([^"]*)"$`, func(f string) error { return assertWebhookBodyFieldPresent(tc, f) })
	ctx.Step(`^the webhook should not contain event_type "([^"]*)"$`, func(eventType string) error { return assertWebhookNoEventType(tc, eventType) })
}

//nolint:gocognit,gocyclo,cyclop // BDD step registration: many closures inline; splitting hurts readability
func registerWebhookThenLocalReceiverSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^the HTTPS webhook receiver should have at least (\d+) events? within (\d+) seconds$`, func(n, timeout int) error {
		r, ok := tc.TLSReceiver.(*tlsWebhookReceiver)
		if !ok || r == nil {
			return fmt.Errorf("no TLS webhook receiver configured")
		}
		return pollReceiverCount("HTTPS", r.eventCount, n, timeout)
	})

	ctx.Step(`^the local webhook receiver should have at least (\d+) events? within (\d+) seconds$`, func(n, timeout int) error {
		r, ok := tc.LocalReceiver.(*localWebhookReceiver)
		if !ok || r == nil {
			return fmt.Errorf("no local webhook receiver configured")
		}
		return pollReceiverCount("local", r.eventCount, n, timeout)
	})

	// #554 exact-count variants
	ctx.Step(`^the HTTPS webhook receiver should have exactly (\d+) events? within (\d+) seconds$`, func(n, timeout int) error {
		r, ok := tc.TLSReceiver.(*tlsWebhookReceiver)
		if !ok || r == nil {
			return fmt.Errorf("no TLS webhook receiver configured")
		}
		return pollReceiverExactCount("HTTPS", r.eventCount, n, timeout)
	})

	ctx.Step(`^the local webhook receiver should have exactly (\d+) events? within (\d+) seconds$`, func(n, timeout int) error {
		r, ok := tc.LocalReceiver.(*localWebhookReceiver)
		if !ok || r == nil {
			return fmt.Errorf("no local webhook receiver configured")
		}
		return pollReceiverExactCount("local", r.eventCount, n, timeout)
	})

	ctx.Step(`^the HTTPS webhook receiver should have received (\d+) events$`, func(expected int) error {
		r, ok := tc.TLSReceiver.(*tlsWebhookReceiver)
		if !ok || r == nil {
			return fmt.Errorf("no TLS webhook receiver configured")
		}
		got := r.eventCount()
		if got != expected {
			return fmt.Errorf("wanted exactly %d HTTPS webhook events, got %d", expected, got)
		}
		return nil
	})
}

func registerWebhookThenMetricsAndErrorSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^the webhook metrics should have recorded at least (\d+) flush$`, func(n int) error { return assertWebhookFlushCount(tc, n) })
	ctx.Step(`^the webhook construction should fail with exact error:$`, func(doc *godog.DocString) error { return assertWebhookExactError(tc, strings.TrimSpace(doc.Content)) })
	ctx.Step(`^the webhook construction should fail with an error$`, func() error { return assertWebhookAnyError(tc) })

	ctx.Step(`^the webhook metrics should have recorded at least (\d+) drops? within (\d+) seconds$`, func(minDrops, timeout int) error {
		if tc.WebhookMetrics == nil {
			return fmt.Errorf("no webhook metrics configured")
		}
		ok := pollUntil(time.Duration(timeout)*time.Second, 200*time.Millisecond, func() bool {
			return tc.WebhookMetrics.DropCount() >= minDrops
		})
		if !ok {
			return fmt.Errorf("wanted >= %d webhook drops, got %d after %ds", minDrops, tc.WebhookMetrics.DropCount(), timeout)
		}
		return nil
	})

	ctx.Step(`^the webhook construction should fail with an error containing "([^"]*)"$`, func(substr string) error {
		if tc.LastErr == nil {
			return fmt.Errorf("expected error containing %q, got nil", substr)
		}
		if !strings.Contains(tc.LastErr.Error(), substr) {
			return fmt.Errorf("expected error containing %q, got: %w", substr, tc.LastErr)
		}
		return nil
	})

	ctx.Step(`^the webhook construction should succeed$`, func() error {
		if tc.LastErr != nil {
			return fmt.Errorf("expected webhook construction to succeed, got: %w", tc.LastErr)
		}
		return nil
	})
}

// --- Internal helpers ---

func createWebhookAuditor(tc *AuditTestContext, cfg *webhook.Config) error {
	cfg.URL = tc.WebhookURL + "/events"
	cfg.AllowInsecureHTTP = true
	cfg.AllowPrivateRanges = true
	cfg.Timeout = 5 * time.Second
	return createWebhookAuditorFromConfig(tc, cfg)
}

func createWebhookAuditorWithWebhookMetrics(tc *AuditTestContext, batchSize int) error {
	cfg := &webhook.Config{
		URL:                tc.WebhookURL + "/events",
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
		BatchSize:          batchSize,
		FlushInterval:      100 * time.Millisecond,
		Timeout:            5 * time.Second,
	}

	var wOpts []webhook.Option
	if tc.WebhookMetrics != nil {
		wOpts = append(wOpts, webhook.WithOutputMetrics(tc.WebhookMetrics))
	}
	out, err := webhook.New(cfg, nil, wOpts...)
	if err != nil {
		tc.LastErr = err
		return nil //nolint:nilerr // scenario may assert on tc.LastErr
	}
	tc.AddCleanup(func() { _ = out.Close() })

	opts := []audit.Option{
		audit.WithTaxonomy(tc.Taxonomy),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	}
	auditor, err := audit.New(opts...)
	if err != nil {
		return fmt.Errorf("create auditor: %w", err)
	}
	tc.Auditor = auditor
	tc.AddCleanup(func() { _ = auditor.Close() })
	return nil
}

func createWebhookAuditorWithURL(tc *AuditTestContext, url string, cfg *webhook.Config) error {
	cfg.URL = url
	cfg.AllowInsecureHTTP = true
	cfg.AllowPrivateRanges = true
	cfg.Timeout = 5 * time.Second
	return createWebhookAuditorFromConfig(tc, cfg)
}

func createWebhookAuditorFromConfig(tc *AuditTestContext, cfg *webhook.Config) error {
	out, err := webhook.New(cfg, nil)
	if err != nil {
		tc.LastErr = err
		return nil //nolint:nilerr // scenario may assert on tc.LastErr
	}
	tc.AddCleanup(func() { _ = out.Close() })

	opts := []audit.Option{
		audit.WithTaxonomy(tc.Taxonomy),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	}
	auditor, err := audit.New(opts...)
	if err != nil {
		return fmt.Errorf("create auditor: %w", err)
	}
	tc.Auditor = auditor
	tc.AddCleanup(func() { _ = auditor.Close() })
	return nil
}

// auditWebhookSizedEventsStep returns the handler for the
// "I audit N uniquely marked webhook events with K KiB payloads"
// step (#687). Padding is concatenated into the declared `marker`
// field — the standard test taxonomy only allows known fields.
func auditWebhookSizedEventsStep(tc *AuditTestContext) func(int, int) error {
	return func(count, kib int) error {
		if tc.Auditor == nil {
			return fmt.Errorf("auditor is nil (construction may have failed: %w)", tc.LastErr)
		}
		padding := strings.Repeat("x", kib*1024)
		for i := range count {
			name := fmt.Sprintf("wh_sized_%d", i)
			m := marker("WHSZ")
			tc.Markers[name] = m
			fields := defaultRequiredFields(tc.Taxonomy, "user_create")
			fields["marker"] = m + "|" + padding
			if err := tc.Auditor.AuditEvent(audit.NewEvent("user_create", fields)); err != nil {
				return fmt.Errorf("webhook sized event %d: %w", i, err)
			}
		}
		return nil
	}
}

// auditWebhookOversizedEventStep returns the handler for the
// "I audit a uniquely marked webhook EVENT event with an N-byte
// payload" step (#687 oversized-event scenario).
func auditWebhookOversizedEventStep(tc *AuditTestContext) func(string, int) error {
	return func(eventType string, size int) error {
		if tc.Auditor == nil {
			return fmt.Errorf("auditor is nil (construction may have failed: %w)", tc.LastErr)
		}
		m := marker("WHOS")
		tc.Markers["default"] = m
		fields := defaultRequiredFields(tc.Taxonomy, eventType)
		fields["marker"] = m + "|" + strings.Repeat("x", size)
		return tc.Auditor.AuditEvent(audit.NewEvent(eventType, fields))
	}
}

func auditMarkedWebhookEvent(tc *AuditTestContext, eventType, name string) error {
	if tc.Auditor == nil {
		return fmt.Errorf("auditor is nil (construction may have failed: %w)", tc.LastErr)
	}
	m := marker("WH")
	tc.Markers[name] = m
	fields := defaultRequiredFields(tc.Taxonomy, eventType)
	fields["marker"] = m
	tc.LastErr = tc.Auditor.AuditEvent(audit.NewEvent(eventType, fields))
	return nil
}

func configureWebhook(baseURL string, statusCode, delayMS int) error {
	body := fmt.Sprintf(`{"status_code":%d,"delay_ms":%d}`, statusCode, delayMS)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		baseURL+"/configure", strings.NewReader(body))
	if err != nil {
		return fmt.Errorf("configure request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := testHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("configure webhook: %w", err)
	}
	if err := resp.Body.Close(); err != nil {
		return fmt.Errorf("configure webhook close body: %w", err)
	}
	return nil
}

func getWebhookEvents(baseURL string) ([]webhookEvent, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		baseURL+"/events", http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("get events request: %w", err)
	}
	resp, err := testHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get events: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read events: %w", err)
	}
	var events []webhookEvent
	if err := json.Unmarshal(data, &events); err != nil {
		return nil, fmt.Errorf("parse events: %w", err)
	}
	return events, nil
}

// webhookEvent represents an event stored by the webhook receiver.
type webhookEvent struct { //nolint:govet // fieldalignment: JSON field order matches receiver API
	Body    json.RawMessage   `json:"body"`
	Headers map[string]string `json:"headers"`
	Time    time.Time         `json:"time"`
}

func assertWebhookFlushCount(tc *AuditTestContext, minFlush int) error {
	if tc.WebhookMetrics == nil {
		return fmt.Errorf("no webhook metrics configured")
	}
	if tc.Auditor != nil {
		_ = tc.Auditor.Close()
	}
	if tc.WebhookMetrics.FlushCount() < minFlush {
		return fmt.Errorf("expected >= %d webhook flushes, got %d", minFlush, tc.WebhookMetrics.FlushCount())
	}
	return nil
}

func assertWebhookExactError(tc *AuditTestContext, expected string) error {
	if tc.LastErr == nil {
		return fmt.Errorf("expected error:\n  %q\ngot: nil", expected)
	}
	if tc.LastErr.Error() != expected {
		return fmt.Errorf("expected error:\n  %q\ngot:\n  %q", expected, tc.LastErr.Error())
	}
	return nil
}

func assertWebhookAnyError(tc *AuditTestContext) error {
	if tc.LastErr == nil {
		return fmt.Errorf("expected webhook construction error, got nil")
	}
	return nil
}

func assertWebhookEventCount(tc *AuditTestContext, minCount int, timeout time.Duration) error {
	ok := pollUntil(timeout, 200*time.Millisecond, func() bool {
		events, err := getWebhookEvents(tc.WebhookURL)
		return err == nil && len(events) >= minCount
	})
	if ok {
		return nil
	}
	events, _ := getWebhookEvents(tc.WebhookURL)
	return fmt.Errorf("wanted >= %d webhook events, got %d after %v", minCount, len(events), timeout)
}

func assertWebhookExactCount(tc *AuditTestContext, exactCount int, timeout time.Duration) error {
	// Wait for events to arrive, then verify exact count.
	var reached int
	ok := pollUntil(timeout, 200*time.Millisecond, func() bool {
		events, err := getWebhookEvents(tc.WebhookURL)
		if err != nil || len(events) < exactCount {
			return false
		}
		reached = len(events)
		return true
	})
	if ok {
		if reached == exactCount {
			return nil
		}
		return fmt.Errorf("wanted exactly %d webhook events, got %d", exactCount, reached)
	}
	events, _ := getWebhookEvents(tc.WebhookURL)
	return fmt.Errorf("wanted exactly %d webhook events, got %d after %v", exactCount, len(events), timeout)
}

func assertWebhookHeader(tc *AuditTestContext, name, value string) error {
	events, err := getWebhookEvents(tc.WebhookURL)
	if err != nil {
		return err
	}
	if len(events) == 0 {
		return fmt.Errorf("no webhook events to check headers")
	}
	got, ok := events[0].Headers[name]
	if !ok {
		return fmt.Errorf("header %q not found in webhook event (headers: %v)", name, events[0].Headers)
	}
	if got != value {
		return fmt.Errorf("header %q: want %q, got %q", name, value, got)
	}
	return nil
}

func assertWebhookBodyField(tc *AuditTestContext, field, value string) error {
	body, err := getFirstWebhookBody(tc)
	if err != nil {
		return err
	}
	got, ok := body[field]
	if !ok {
		return fmt.Errorf("field %q not found in webhook body", field)
	}
	if fmt.Sprintf("%v", got) != value {
		return fmt.Errorf("field %q: want %q, got %q", field, value, got)
	}
	return nil
}

func assertWebhookBodyFieldPresent(tc *AuditTestContext, field string) error {
	body, err := getFirstWebhookBody(tc)
	if err != nil {
		return err
	}
	if _, ok := body[field]; !ok {
		return fmt.Errorf("field %q not found in webhook body (keys: %v)", field, mapKeys(body))
	}
	return nil
}

// assertWebhookNoEventType verifies that NO webhook event has the given
// event_type. Used for routing exclusion tests.
func assertWebhookNoEventType(tc *AuditTestContext, eventType string) error {
	events, err := getWebhookEvents(tc.WebhookURL)
	if err != nil {
		return err
	}
	for _, event := range events {
		var body map[string]any
		if jErr := json.Unmarshal(event.Body, &body); jErr != nil {
			continue
		}
		if et, ok := body["event_type"]; ok && fmt.Sprintf("%v", et) == eventType {
			return fmt.Errorf("webhook unexpectedly contains event_type %q", eventType)
		}
	}
	return nil
}

func getFirstWebhookBody(tc *AuditTestContext) (map[string]any, error) {
	events, err := getWebhookEvents(tc.WebhookURL)
	if err != nil {
		return nil, err
	}
	if len(events) == 0 {
		return nil, fmt.Errorf("no webhook events")
	}
	var body map[string]any
	if err := json.Unmarshal(events[0].Body, &body); err != nil {
		return nil, fmt.Errorf("parse webhook body: %w", err)
	}
	return body, nil
}

func mapKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func pollReceiverCount(label string, countFn func() int, minCount, timeoutSecs int) error {
	ok := pollUntil(time.Duration(timeoutSecs)*time.Second, 200*time.Millisecond, func() bool {
		return countFn() >= minCount
	})
	if !ok {
		return fmt.Errorf("wanted >= %d %s webhook events, got %d after %ds", minCount, label, countFn(), timeoutSecs)
	}
	return nil
}

// pollReceiverExactCount waits up to timeoutSecs for the count to
// reach exactCount, then verifies no more events have arrived. Used
// by #554 non-retry happy-path scenarios where duplicate delivery
// is a regression.
func pollReceiverExactCount(label string, countFn func() int, exactCount, timeoutSecs int) error {
	var reached int
	ok := pollUntil(time.Duration(timeoutSecs)*time.Second, 200*time.Millisecond, func() bool {
		got := countFn()
		if got < exactCount {
			return false
		}
		reached = got
		return true
	})
	if ok {
		if reached == exactCount {
			return nil
		}
		return fmt.Errorf("wanted exactly %d %s webhook events, got %d", exactCount, label, reached)
	}
	return fmt.Errorf("wanted exactly %d %s webhook events, got %d after %ds", exactCount, label, countFn(), timeoutSecs)
}

func createWebhookAuditorSSRF(tc *AuditTestContext, url string, allowPrivate bool) error {
	cfg := &webhook.Config{
		URL:                url,
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: allowPrivate,
		BatchSize:          1,
		FlushInterval:      100 * time.Millisecond,
		Timeout:            2 * time.Second,
		MaxRetries:         1,
		// SSRF behaviour at runtime is the property under test;
		// the probe (which also enforces SSRF) would short-circuit
		// the write-path before any event flush.
		DisableStartupVerification: true,
	}
	var oOpts []webhook.Option

	if tc.WebhookMetrics != nil {

		oOpts = append(oOpts, webhook.WithOutputMetrics(tc.WebhookMetrics))

	}

	out, err := webhook.New(cfg, nil, oOpts...)
	if err != nil {
		return fmt.Errorf("create webhook output: %w", err)
	}
	tc.AddCleanup(func() { _ = out.Close() })
	opts := []audit.Option{
		audit.WithTaxonomy(tc.Taxonomy),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	}
	auditor, err := audit.New(opts...)
	if err != nil {
		return fmt.Errorf("create auditor: %w", err)
	}
	tc.Auditor = auditor
	tc.AddCleanup(func() { _ = auditor.Close() })
	return nil
}
