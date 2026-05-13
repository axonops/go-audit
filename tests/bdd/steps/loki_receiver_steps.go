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
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cucumber/godog"

	"github.com/axonops/audit"
	"github.com/axonops/audit/loki"
)

// localLokiReceiver is an httptest.Server that simulates Loki for
// retry, SSRF, and metrics BDD scenarios.
type localLokiReceiver struct { //nolint:govet // fieldalignment: readability preferred
	server    *httptest.Server
	status    atomic.Int32
	pushCount atomic.Int32
	redirect  bool
	// large3xxBodySize, when >0, makes the receiver reply with HTTP 300
	// and a body of that many bytes (streamed in 4 KiB chunks). Used to
	// exercise the client-side 3xx drain cap (#484).
	large3xxBodySize int64
	bytesSent        atomic.Int64
	handlerDone      chan struct{}
	doneOnce         sync.Once
}

func newLocalLokiReceiver(status int) *localLokiReceiver {
	r := &localLokiReceiver{}
	r.status.Store(int32(status)) //nolint:gosec // G115: test code, HTTP status codes fit int32
	// httptest exemption (#559): tests SSRF block, retry semantics, and
	// drainCap (#484) — the receiver streams arbitrary 3xx bodies in 4 KiB
	// chunks under precise test control. The real loki container cannot
	// produce these adversarial responses; precise byte-level streaming
	// behaviour is the contract under test.
	r.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if r.redirect {
			http.Redirect(w, req, "http://evil.example.com/", http.StatusFound)
			return
		}
		if r.large3xxBodySize > 0 {
			r.handleLarge3xx(w, req)
			return
		}
		// Drain body to prevent connection leak.
		_, _ = io.Copy(io.Discard, req.Body)
		_ = req.Body.Close()
		r.pushCount.Add(1)
		w.WriteHeader(int(r.status.Load()))
	}))
	return r
}

// handleLarge3xx writes an HTTP 300 Multiple Choices response with a
// body of r.large3xxBodySize bytes, flushing every 4 KiB. Bytes
// successfully written are tracked so the BDD scenario can assert the
// client-side drain cap took effect. Uses chunked transfer (no
// Content-Length) so a client that closes after reading its cap does
// not produce "superfluous WriteHeader" log noise. sync.Once
// guarantees handlerDone is closed exactly once even if a future
// scenario permits the client to retry the request.
func (r *localLokiReceiver) handleLarge3xx(w http.ResponseWriter, req *http.Request) {
	defer func() {
		if r.handlerDone != nil {
			r.doneOnce.Do(func() { close(r.handlerDone) })
		}
	}()
	_, _ = io.Copy(io.Discard, req.Body)
	_ = req.Body.Close()
	r.pushCount.Add(1)
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

func newRedirectLokiReceiver() *localLokiReceiver {
	r := &localLokiReceiver{redirect: true}
	// httptest exemption (#559): tests SSRF protection by emitting a
	// 302 to an off-host target — no real Loki container would emit
	// this redirect; the SSRF guard is the contract under test.
	r.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, "http://evil.example.com/", http.StatusFound)
	}))
	return r
}

// registerLokiReceiverSteps registers steps for local Loki receiver scenarios.
func registerLokiReceiverSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	registerLokiReceiverGivenSteps(ctx, tc)
	registerLokiReceiverThenSteps(ctx, tc)
}

func registerLokiReceiverGivenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	registerLokiReceiverSetupSteps(ctx, tc)
	registerLokiReceiverLoggerSteps(ctx, tc)
}

func registerLokiReceiverSetupSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^a local Loki receiver returning status (\d+)$`, func(status int) error {
		r := newLocalLokiReceiver(status)
		tc.LocalReceiver = r
		tc.AddCleanup(func() { r.server.Close() })
		return nil
	})

	ctx.Step(`^a local Loki receiver accepting pushes$`, func() error {
		r := newLocalLokiReceiver(http.StatusNoContent)
		tc.LocalReceiver = r
		tc.AddCleanup(func() { r.server.Close() })
		return nil
	})

	ctx.Step(`^a local Loki receiver configured to redirect$`, func() error {
		r := newRedirectLokiReceiver()
		tc.LocalReceiver = r
		tc.AddCleanup(func() { r.server.Close() })
		return nil
	})

	ctx.Step(`^a local Loki receiver returning 3xx with a (\d+) MiB body$`, func(bodyMiB int) error {
		r := newLocalLokiReceiver(http.StatusMultipleChoices)
		r.large3xxBodySize = int64(bodyMiB) << 20
		r.handlerDone = make(chan struct{})
		tc.LocalReceiver = r
		tc.AddCleanup(func() { r.server.Close() })
		return nil
	})

	ctx.Step(`^an auditor with loki output to the 3xx Loki receiver$`, func() error {
		r, ok := tc.LocalReceiver.(*localLokiReceiver)
		if !ok || r == nil {
			return fmt.Errorf("no local Loki receiver configured")
		}
		return createLokiAuditorWithReceiver(tc, r, &loki.Config{
			BatchSize:  1,
			MaxRetries: 1,
			Gzip:       true,
		})
	})

	ctx.Step(`^the loki receiver should have transmitted less than (\d+) MiB of body$`, func(limitMiB int) error {
		r, ok := tc.LocalReceiver.(*localLokiReceiver)
		if !ok || r == nil {
			return fmt.Errorf("no local Loki receiver configured")
		}
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

	ctx.Step(`^the local Loki receiver is reconfigured to return status (\d+)$`, func(status int) error {
		r, ok := tc.LocalReceiver.(*localLokiReceiver)
		if !ok || r == nil {
			return fmt.Errorf("no local Loki receiver configured")
		}
		r.status.Store(int32(status)) //nolint:gosec // G115: test code, HTTP status codes fit int32
		return nil
	})

	ctx.Step(`^mock loki metrics are configured$`, func() error {
		tc.LokiMetrics = &MockOutputMetrics{}
		return nil
	})
}

func registerLokiReceiverLoggerSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	registerLokiReceiverLoggerRetrySteps(ctx, tc)
	registerLokiReceiverLoggerSSRFSteps(ctx, tc)
}

func registerLokiReceiverLoggerRetrySteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^an auditor with loki output to the local receiver with max retries (\d+)$`, func(retries int) error {
		r, ok := tc.LocalReceiver.(*localLokiReceiver)
		if !ok || r == nil {
			return fmt.Errorf("no local Loki receiver configured")
		}
		return createLokiAuditorWithReceiver(tc, r, &loki.Config{
			MaxRetries: retries,
			BatchSize:  1,
			Gzip:       true,
		})
	})

	ctx.Step(`^an auditor with loki output to the local Loki receiver with metrics and max retries (\d+)$`, func(retries int) error {
		r, ok := tc.LocalReceiver.(*localLokiReceiver)
		if !ok || r == nil {
			return fmt.Errorf("no local Loki receiver configured")
		}
		cfg := &loki.Config{
			MaxRetries: retries,
			BatchSize:  1,
			Gzip:       true,
		}
		cfg.URL = r.server.URL + "/loki/api/v1/push"
		cfg.AllowInsecureHTTP = true
		cfg.AllowPrivateRanges = true

		var oOpts []loki.Option
		if tc.LokiMetrics != nil {
			oOpts = append(oOpts, loki.WithOutputMetrics(tc.LokiMetrics))
		}
		out, err := loki.New(cfg, nil, oOpts...)
		if err != nil {
			return fmt.Errorf("create loki output: %w", err)
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
		tc.LokiOutputName = out.Name()
		tc.AddCleanup(func() { _ = auditor.Close() })
		return nil
	})

	ctx.Step(`^an auditor with loki output to unreachable server with metrics$`, func() error {
		cfg := &loki.Config{
			URL:                "http://127.0.0.1:19999/loki/api/v1/push", // nothing listening
			AllowInsecureHTTP:  true,
			AllowPrivateRanges: true,
			BatchSize:          1,
			MaxRetries:         1,
			Gzip:               true,
			// The runtime unreachable-drop behaviour is the property
			// under test; the construction-time probe would block
			// this scenario at New().
			DisableStartupVerification: true,
		}
		return createLokiAuditorFromConfig(tc, cfg)
	})
}

func registerLokiReceiverLoggerSSRFSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^an auditor with loki output to the local Loki receiver without AllowPrivateRanges$`, func() error {
		r, ok := tc.LocalReceiver.(*localLokiReceiver)
		if !ok || r == nil {
			return fmt.Errorf("no local Loki receiver configured")
		}
		cfg := &loki.Config{
			URL:                r.server.URL + "/loki/api/v1/push",
			AllowInsecureHTTP:  true,
			AllowPrivateRanges: false, // SSRF blocks localhost
			BatchSize:          1,
			MaxRetries:         1,
			FlushInterval:      200 * time.Millisecond,
			Timeout:            5 * time.Second,
			BufferSize:         100,
			Gzip:               true,
			// Runtime SSRF-block-at-write is the property under test;
			// the probe enforces the same SSRF policy and would reject
			// at construction.
			DisableStartupVerification: true,
		}
		return createLokiAuditorFromConfig(tc, cfg)
	})

	ctx.Step(`^an auditor with loki output to the local Loki receiver with AllowPrivateRanges$`, func() error {
		r, ok := tc.LocalReceiver.(*localLokiReceiver)
		if !ok || r == nil {
			return fmt.Errorf("no local Loki receiver configured")
		}
		return createLokiAuditorWithReceiver(tc, r, &loki.Config{
			BatchSize: 1,
			Gzip:      true,
		})
	})

	ctx.Step(`^an auditor with loki output to the local Loki receiver with metrics$`, func() error {
		r, ok := tc.LocalReceiver.(*localLokiReceiver)
		if !ok || r == nil {
			return fmt.Errorf("no local Loki receiver configured")
		}
		return createLokiAuditorWithReceiver(tc, r, &loki.Config{
			BatchSize: 1,
			Gzip:      true,
		})
	})

	ctx.Step(`^an auditor with loki output to the redirecting Loki receiver with metrics$`, func() error {
		r, ok := tc.LocalReceiver.(*localLokiReceiver)
		if !ok || r == nil {
			return fmt.Errorf("no local Loki receiver configured")
		}
		return createLokiAuditorWithReceiver(tc, r, &loki.Config{
			BatchSize:  1,
			MaxRetries: 1,
			Gzip:       true,
		})
	})
}

func registerLokiReceiverThenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	registerLokiReceiverCountSteps(ctx, tc)
	registerLokiReceiverMetricSteps(ctx, tc)
}

func registerLokiReceiverCountSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^the local Loki receiver should have at least (\d+) push(?:es)? within (\d+) seconds$`,
		func(n, secs int) error {
			return waitForLocalPushes(tc, n, time.Duration(secs)*time.Second)
		})

	ctx.Step(`^the local Loki receiver should have received at most (\d+) push(?:es)?$`,
		func(n int) error {
			return assertMaxPushes(tc, n)
		})
}

func registerLokiReceiverMetricSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^the loki metrics should have recorded at least (\d+) flush(?:es)?$`,
		func(n int) error {
			return assertMinFlushes(tc, n)
		})

	ctx.Step(`^the loki metrics should have recorded at least (\d+) drops? within (\d+) seconds$`,
		func(n, secs int) error {
			return waitForDrops(tc, n, time.Duration(secs)*time.Second)
		})

	ctx.Step(`^the loki metrics should have recorded 0 drops$`, func() error {
		return assertZeroDrops(tc)
	})

	ctx.Step(`^the loki metrics should have recorded at least (\d+) errors? within (\d+) seconds$`,
		func(n, secs int) error {
			return waitForErrors(tc, n, time.Duration(secs)*time.Second)
		})
}

func waitForLocalPushes(tc *AuditTestContext, n int, timeout time.Duration) error {
	r, ok := tc.LocalReceiver.(*localLokiReceiver)
	if !ok || r == nil {
		return fmt.Errorf("no local Loki receiver configured")
	}
	deadline := time.After(timeout)
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		if int(r.pushCount.Load()) >= n {
			return nil
		}
		select {
		case <-deadline:
			return fmt.Errorf("timed out: wanted %d pushes, got %d", n, r.pushCount.Load())
		case <-tick.C:
		}
	}
}

func assertMaxPushes(tc *AuditTestContext, n int) error {
	r, ok := tc.LocalReceiver.(*localLokiReceiver)
	if !ok || r == nil {
		return fmt.Errorf("no local Loki receiver configured")
	}
	got := int(r.pushCount.Load())
	if got > n {
		return fmt.Errorf("expected at most %d pushes, got %d", n, got)
	}
	return nil
}

func assertMinFlushes(tc *AuditTestContext, n int) error {
	m := tc.LokiMetrics
	if m == nil {
		return fmt.Errorf("no mock loki metrics configured")
	}
	if m.FlushCount() < n {
		return fmt.Errorf("expected at least %d flushes, got %d", n, m.FlushCount())
	}
	return nil
}

func waitForDrops(tc *AuditTestContext, n int, timeout time.Duration) error {
	m := tc.LokiMetrics
	if m == nil {
		return fmt.Errorf("no mock loki metrics configured")
	}
	deadline := time.After(timeout)
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		if m.DropCount() >= n {
			return nil
		}
		select {
		case <-deadline:
			return fmt.Errorf("timed out: wanted %d drops, got %d", n, m.DropCount())
		case <-tick.C:
		}
	}
}

func waitForErrors(tc *AuditTestContext, n int, timeout time.Duration) error {
	m := tc.LokiMetrics
	if m == nil {
		return fmt.Errorf("no mock loki metrics configured")
	}
	deadline := time.After(timeout)
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		if m.ErrorCount() >= n {
			return nil
		}
		select {
		case <-deadline:
			return fmt.Errorf("timed out: wanted %d errors, got %d", n, m.ErrorCount())
		case <-tick.C:
		}
	}
}

func assertZeroDrops(tc *AuditTestContext) error {
	m := tc.LokiMetrics
	if m == nil {
		return fmt.Errorf("no mock loki metrics configured")
	}
	if m.DropCount() > 0 {
		return fmt.Errorf("expected 0 drops, got %d", m.DropCount())
	}
	return nil
}

// createLokiAuditorWithReceiver creates a Loki output pointing at the local receiver.
func createLokiAuditorWithReceiver(tc *AuditTestContext, r *localLokiReceiver, cfg *loki.Config) error {
	cfg.URL = r.server.URL + "/loki/api/v1/push"
	cfg.AllowInsecureHTTP = true
	cfg.AllowPrivateRanges = true
	return createLokiAuditorFromConfig(tc, cfg)
}

// createLokiAuditorFromConfig creates a Loki output from the exact config.
func createLokiAuditorFromConfig(tc *AuditTestContext, cfg *loki.Config) error {
	if cfg.FlushInterval == 0 {
		cfg.FlushInterval = 200 * time.Millisecond
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.BufferSize == 0 {
		cfg.BufferSize = 100
	}

	var lOpts []loki.Option
	if tc.LokiMetrics != nil {
		lOpts = append(lOpts, loki.WithOutputMetrics(tc.LokiMetrics))
	}
	out, err := loki.New(cfg, nil, lOpts...)
	if err != nil {
		return fmt.Errorf("create loki output: %w", err)
	}
	tc.AddCleanup(func() { _ = out.Close() })

	auditor, err := audit.New(
		audit.WithTaxonomy(tc.Taxonomy),
		audit.WithAppName("bdd-audit"),
		audit.WithHost("bdd-host"),
		audit.WithOutputs(out),
	)
	if err != nil {
		return fmt.Errorf("create auditor: %w", err)
	}
	tc.Auditor = auditor
	tc.AddCleanup(func() { _ = auditor.Close() })
	return nil
}
