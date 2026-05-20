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
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"runtime/debug"
	"sync/atomic"
	"time"

	"github.com/axonops/audit"
)

// libraryVersion returns the splunk module's version string parsed
// from BuildInfo. Falls back to "0.x" for `go run`-from-source
// builds where the module is not yet versioned. Used as the
// default UserAgent for HEC requests (AC 34).
func libraryVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, m := range info.Deps {
			if m.Path == "github.com/axonops/audit/splunk" && m.Version != "" {
				return m.Version
			}
		}
		if info.Main.Version != "" && info.Main.Version != "(devel)" {
			return info.Main.Version
		}
	}
	return "0.x"
}

// Compile-time interface assertions.
var (
	_ audit.Output           = (*Output)(nil)
	_ audit.DeliveryReporter = (*Output)(nil)
)

// ReportsDelivery implements [audit.DeliveryReporter] — splunk reports
// its own per-event delivery via [audit.Metrics.RecordDelivery] so the
// core pipeline must NOT double-record. Mirrors loki/webhook.
func (o *Output) ReportsDelivery() bool { return true }

// dropWarnInterval is the minimum interval between slog.Warn calls
// for buffer-full drop events. Mirrors loki/loki.go:39.
const dropWarnInterval = 10 * time.Second

// minResponseHeaderTimeout floors the derived
// [http.Transport.ResponseHeaderTimeout]. Mirrors loki precedent.
const minResponseHeaderTimeout = 1 * time.Second

// responseHeaderTimeout returns half of the overall client timeout,
// never below [minResponseHeaderTimeout].
func responseHeaderTimeout(t time.Duration) time.Duration {
	half := t / 2
	if half < minResponseHeaderTimeout {
		return minResponseHeaderTimeout
	}
	return half
}

// splunkEntry carries a copied event through the internal buffer
// channel to the batch goroutine.
type splunkEntry struct {
	data []byte
}

// Output pushes audit events to a Splunk HEC endpoint. Implements
// [audit.Output] and [audit.DeliveryReporter].
type Output struct { //nolint:govet // fieldalignment: readability preferred
	cfg           *Config
	metrics       audit.Metrics
	outputMetrics audit.OutputMetrics
	logger        *slog.Logger
	client        *http.Client
	endpointURL   string // pre-computed full endpoint URL (event or raw)
	name          string // "splunk:<host>", cached at construction
	ch            chan splunkEntry
	done          chan struct{}
	closeCh       chan struct{}
	cancel        context.CancelFunc
	closed        atomic.Bool
	stopped       atomic.Bool // permanent STOP state (token disabled etc.)

	// Flush-path state — owned exclusively by the batch goroutine.
	envelopeBuf bytes.Buffer
	rawBuf      bytes.Buffer
	compressBuf bytes.Buffer
	gzWriter    *gzip.Writer
	retryHint   time.Duration

	// Drop limiters and metrics.
	dropsOversized  *dropLimiter
	dropsBufferFull *dropLimiter
	maxEventBytes   int

	// Most recent successful delivery wall-clock time (powers
	// [audit.DeliveryReporter.LastDeliveryAge]).
	lastDeliveryNanos atomic.Int64
}

// New constructs a Splunk HEC [Output]. Returns an error if the
// config fails validation, if TLS material cannot be loaded, or if
// the startup health check fails (unless
// [Config.DisableStartupVerification] is true).
//
// `metrics` may be nil — the output records via a no-op
// [audit.NoOpOutputMetrics] when omitted. Use [WithOutputMetrics] to
// pass a real [audit.OutputMetrics] sink.
func New(cfg *Config, metrics audit.Metrics, opts ...Option) (*Output, error) {
	if cfg == nil {
		return nil, fmt.Errorf("%w: nil config", ErrConfigInvalid)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	o := resolveOptions(opts)

	// Build the HTTP transport. SSRF + TLS wiring matches the loki
	// precedent (loki/loki.go:190-209).
	tlsCfg, warnings, err := buildTLSConfig(cfg)
	if err != nil {
		return nil, err
	}
	for _, w := range warnings {
		o.logger.Warn("audit/splunk: TLS policy warning", "warning", w)
	}

	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: 30 * time.Second,
			Control: audit.NewSSRFDialControl(ssrfOptsFromConfig(cfg)...),
		}).DialContext,
		TLSClientConfig:       tlsCfg,
		DisableKeepAlives:     false,
		MaxIdleConns:          o.maxIdleConns,
		MaxIdleConnsPerHost:   o.maxIdleConns,
		IdleConnTimeout:       defaultIdleConnTimeout,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: responseHeaderTimeout(cfg.Timeout),
		// HEC is HTTP/1.1 only — defeat HTTP/2 auto-enable on some
		// Go versions (security review M5/13).
		ForceAttemptHTTP2: false,
		TLSNextProto:      map[string]func(string, *tls.Conn) http.RoundTripper{},
	}

	client := &http.Client{
		Timeout:   cfg.Timeout,
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errRedirectBlocked
		},
	}

	// Determine endpoint URL based on config.
	var endpointURL string
	switch cfg.Endpoint {
	case EndpointRaw:
		endpointURL, err = joinRawURL(cfg.URL, cfg)
	default:
		endpointURL, err = joinEventURL(cfg.URL)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: build endpoint URL: %v", ErrConfigInvalid, err)
	}

	// Compute Name from URL host.
	name := "splunk"
	if u, perr := url.Parse(cfg.URL); perr == nil && u.Host != "" {
		name = "splunk:" + u.Host
	}

	ctx, cancel := context.WithCancel(context.Background())
	out := &Output{
		cfg:             cfg,
		metrics:         metrics,
		outputMetrics:   o.outputMetrics,
		logger:          o.logger,
		client:          client,
		endpointURL:     endpointURL,
		name:            name,
		ch:              make(chan splunkEntry, cfg.BufferSize),
		done:            make(chan struct{}),
		closeCh:         make(chan struct{}),
		cancel:          cancel,
		dropsOversized:  newDropLimiter(dropWarnInterval),
		dropsBufferFull: newDropLimiter(dropWarnInterval),
		maxEventBytes:   cfg.MaxEventBytes,
	}
	out.gzWriter = gzip.NewWriter(&out.compressBuf)

	// Startup verification: probe /health before launching the batch
	// goroutine. Errors abort construction (no goroutine leak — the
	// goroutine has not been started yet).
	if !cfg.DisableStartupVerification {
		probeCtx, probeCancel := context.WithTimeout(ctx, cfg.StartupVerificationTimeout)
		err := out.probeEndpoint(probeCtx)
		probeCancel()
		if err != nil {
			cancel()
			return nil, err
		}
	}

	go out.batchLoop(ctx)
	return out, nil
}

// Name returns "splunk:<host>" or "splunk" when the URL host is empty.
func (o *Output) Name() string { return o.name }

// Write enqueues a serialised event for asynchronous delivery to HEC.
// Returns [audit.ErrOutputClosed] after [Close] has been called.
// Returns [audit.ErrEventTooLarge] if the event exceeds
// [Config.MaxEventBytes]. Returns nil on a successful enqueue OR on
// a buffer-full drop (the drop is recorded via metrics, not via the
// return value, matching the loki precedent).
func (o *Output) Write(data []byte) error {
	if o.closed.Load() {
		return audit.ErrOutputClosed
	}
	if o.stopped.Load() {
		return audit.ErrOutputClosed
	}
	if len(data) > o.maxEventBytes {
		o.recordOversized()
		return audit.ErrEventTooLarge
	}
	// Defensive copy so the caller can reuse its buffer.
	buf := make([]byte, len(data))
	copy(buf, data)
	select {
	case o.ch <- splunkEntry{data: buf}:
		return nil
	default:
		o.recordBufferFull()
		return nil
	}
}

// Close shuts down the output, draining any buffered events up to
// [Config.Timeout] * 2 + 5s. Idempotent.
func (o *Output) Close() error {
	if !o.closed.CompareAndSwap(false, true) {
		return nil
	}
	close(o.closeCh)
	// Wait for the batch goroutine to drain.
	deadline := time.After(2*o.cfg.Timeout + 5*time.Second)
	select {
	case <-o.done:
	case <-deadline:
		o.cancel()
		<-o.done
	}
	o.cancel()
	return nil
}

// LastDeliveryAge implements [audit.DeliveryReporter].
func (o *Output) LastDeliveryAge() time.Duration {
	ns := o.lastDeliveryNanos.Load()
	if ns == 0 {
		return 0
	}
	return time.Since(time.Unix(0, ns))
}

// recordOversized records a per-event oversize drop (rate-limited
// warning).
func (o *Output) recordOversized() {
	o.outputMetrics.RecordDrop()
	if o.dropsOversized.allow() {
		o.logger.Warn("audit/splunk: event exceeds MaxEventBytes — dropping",
			"output", o.name,
			"max_event_bytes", o.maxEventBytes,
		)
	}
}

// recordBufferFull records a buffer-overflow drop (rate-limited
// warning).
func (o *Output) recordBufferFull() {
	o.outputMetrics.RecordDrop()
	if o.dropsBufferFull.allow() {
		o.logger.Warn("audit/splunk: buffer full — dropping event",
			"output", o.name,
			"buffer_size", o.cfg.BufferSize,
		)
	}
}

// batchLoop is the producer goroutine. It accumulates events from the
// channel into a buffer, then flushes when any of (1) BatchSize
// events reached, (2) MaxBatchBytes accumulated, (3) FlushInterval
// elapsed, or (4) Close was signalled.
func (o *Output) batchLoop(ctx context.Context) {
	defer close(o.done)

	ticker := time.NewTicker(o.cfg.FlushInterval)
	defer ticker.Stop()

	var (
		batch      []splunkEntry
		batchBytes int
	)
	reset := func() {
		batch = batch[:0]
		batchBytes = 0
	}

	flushIfNonEmpty := func() {
		if len(batch) > 0 {
			o.flushBatch(ctx, batch)
			reset()
		}
	}

	for {
		select {
		case <-o.closeCh:
			// Drain remaining channel entries into one or more final
			// batches before exiting.
			for {
				select {
				case e := <-o.ch:
					batch = append(batch, e)
					batchBytes += len(e.data)
					if len(batch) >= o.cfg.BatchSize || batchBytes >= o.cfg.MaxBatchBytes {
						o.flushBatch(ctx, batch)
						reset()
					}
				default:
					flushIfNonEmpty()
					return
				}
			}
		case <-ctx.Done():
			return
		case e := <-o.ch:
			batch = append(batch, e)
			batchBytes += len(e.data)
			if len(batch) >= o.cfg.BatchSize || batchBytes >= o.cfg.MaxBatchBytes {
				flushIfNonEmpty()
			}
		case <-ticker.C:
			flushIfNonEmpty()
		}
	}
}

// flushBatch serialises and sends a batch of events. Drives the
// retry loop with backoff and Retry-After. The function is called
// only by [batchLoop]; the flush-path buffers are not concurrent-
// safe.
func (o *Output) flushBatch(ctx context.Context, batch []splunkEntry) { //nolint:gocyclo,cyclop,gocognit // long-but-flat; control flow follows the action returned by classify()
	if len(batch) == 0 {
		return
	}

	// Build the payload.
	var (
		payload    []byte
		compressed bool
	)
	if o.cfg.Endpoint == EndpointRaw {
		o.rawBuf.Reset()
		for _, e := range batch {
			rawEventLine(&o.rawBuf, e.data)
		}
		payload = o.rawBuf.Bytes()
	} else {
		o.envelopeBuf.Reset()
		now := time.Now()
		for _, e := range batch {
			if err := wrapEvent(&o.envelopeBuf, o.cfg, e.data, now); err != nil {
				o.logger.Warn("audit/splunk: envelope wrap failed — dropping event",
					"output", o.name, "error", err)
				o.outputMetrics.RecordDrop()
				continue
			}
		}
		payload = o.envelopeBuf.Bytes()
	}
	if len(payload) == 0 {
		return
	}

	// Pre-flush payload-size cap. A batch whose assembled payload
	// (post-envelope, pre-gzip) exceeds MaxBatchBytes is dropped
	// client-side rather than sent for the server to reject with
	// HTTP 413 — the network round-trip is wasted, and Splunk's
	// 1 MiB cap applies to uncompressed payload anyway.
	if len(payload) > o.cfg.MaxBatchBytes {
		o.logger.Warn("audit/splunk: batch payload exceeds MaxBatchBytes — dropping",
			"output", o.name, "batch_size", len(batch),
			"payload_bytes", len(payload), "limit", o.cfg.MaxBatchBytes)
		o.recordDrop(len(batch))
		return
	}

	if o.cfg.Gzip != nil && *o.cfg.Gzip {
		o.compressBuf.Reset()
		o.gzWriter.Reset(&o.compressBuf)
		if _, err := o.gzWriter.Write(payload); err != nil {
			o.logger.Warn("audit/splunk: gzip write failed — dropping batch",
				"output", o.name, "error", err)
			o.outputMetrics.RecordDrop()
			return
		}
		if err := o.gzWriter.Close(); err != nil {
			o.logger.Warn("audit/splunk: gzip close failed — dropping batch",
				"output", o.name, "error", err)
			o.outputMetrics.RecordDrop()
			return
		}
		payload = o.compressBuf.Bytes()
		compressed = true
	}

	// Retry loop. Every exit path must zero `retryHint` so a previous
	// batch's Retry-After does not leak across batches (code-reviewer B2).
	start := time.Now()
	maxRetries := o.cfg.MaxRetries
	for attempt := 0; attempt <= maxRetries; attempt++ {
		action, _, hecCode, err := o.doPost(ctx, payload, compressed)

		switch action {
		case actionSuccess, actionCapacityWarn:
			o.retryHint = 0
			o.recordSuccess(len(batch), time.Since(start))
			if action == actionCapacityWarn {
				o.logger.Warn("audit/splunk: HEC at capacity (code 24/25)",
					"output", o.name, "hec_code", hecCode)
			}
			return
		case actionRetry:
			if attempt == maxRetries {
				o.logger.Warn("audit/splunk: retries exhausted — dropping batch",
					"output", o.name, "batch_size", len(batch), "error", redact(err))
				o.retryHint = 0
				o.recordDrop(len(batch))
				return
			}
			delay := o.retryHint
			if delay <= 0 {
				delay = splunkBackoff(attempt)
			}
			// Cap server-supplied Retry-After at the configured
			// RetryMaxDelay (AC 53) — even if HEC says "wait 5
			// minutes", we never wait more than the operator-
			// configured maximum between attempts.
			if delay > o.cfg.RetryMaxDelay {
				delay = o.cfg.RetryMaxDelay
			}
			o.retryHint = 0
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
			}
			continue
		case actionStop:
			o.logger.Error("audit/splunk: HEC permanent failure — stopping output",
				"output", o.name, "hec_code", hecCode, "error", redact(err))
			o.retryHint = 0
			o.stopped.Store(true)
			o.recordDrop(len(batch))
			return
		case actionAckDisabled:
			// PR 1 never sets AckMode != Off, so this path is unreachable.
			o.logger.Error("audit/splunk: HEC reports ack disabled but client sent channel header (ack support ships in PR 2)",
				"output", o.name)
			o.retryHint = 0
			o.recordDrop(len(batch))
			return
		default: // actionDrop
			o.logger.Warn("audit/splunk: HEC rejected batch — dropping",
				"output", o.name, "hec_code", hecCode, "error", redact(err))
			o.retryHint = 0
			o.recordDrop(len(batch))
			return
		}
	}
}

// recordSuccess records successful delivery metrics for a batch.
func (o *Output) recordSuccess(batchSize int, dur time.Duration) {
	o.lastDeliveryNanos.Store(time.Now().UnixNano())
	o.outputMetrics.RecordFlush(batchSize, dur)
	if o.metrics != nil {
		for range batchSize {
			o.metrics.RecordDelivery(o.name, audit.EventSuccess)
		}
	}
}

// recordDrop records dropped events in metrics.
func (o *Output) recordDrop(count int) {
	for range count {
		o.outputMetrics.RecordDrop()
		if o.metrics != nil {
			o.metrics.RecordDelivery(o.name, audit.EventError)
		}
	}
}

// redact returns the error message with the token redacted. Defensive
// against any future code path that wraps the URL/token into an error.
// Currently the existing error sites use `sanitizeURLForLog` and
// never include the token; this is belt-and-braces.
func redact(err error) string {
	if err == nil {
		return ""
	}
	// Suppress potentially-sensitive wrapped error chains by formatting
	// only the top-level error message.
	var herr *hecError
	if errors.As(err, &herr) {
		return herr.Error()
	}
	return err.Error()
}
