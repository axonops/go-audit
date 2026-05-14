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

package webhook

// The webhook output uses a two-buffer architecture:
//
//	Auditor drain goroutine
//	  → Output.Write(data) — non-blocking copy+enqueue
//	    → batch goroutine reads from channel
//	      → accumulates events, flushes on size/timer/close
//	      → HTTP POST as NDJSON with retry
//
// The internal channel decouples the Auditor's drain loop from HTTP
// latency. If the channel is full, events are dropped (non-blocking)
// and [audit.OutputMetrics.RecordDrop] is recorded.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/axonops/audit"
)

// dropWarnInterval is the minimum interval between slog.Warn calls
// for buffer-full drop events.
const dropWarnInterval = 10 * time.Second

// Compile-time assertions.
var (
	_ audit.Output            = (*Output)(nil)
	_ audit.DeliveryReporter  = (*Output)(nil)
	_ audit.DestinationKeyer  = (*Output)(nil)
	_ audit.ContentTypeSetter = (*Output)(nil)
)

// defaultContentType is the request Content-Type used by [Output]
// when no [audit.ContentTypeSetter.SetContentType] call has fired
// (i.e., the webhook was constructed outside an auditor for unit
// tests). Matches the body shape produced by the default
// [audit.JSONFormatter].
const defaultContentType = "application/x-ndjson"

// maxContentTypeLen caps the Content-Type header value to defend
// against an adversarial formatter returning an absurd string.
// HTTP header values have no formal upper bound, but 256 covers
// every realistic media-type + parameter combination.
const maxContentTypeLen = 256

// errRedirectBlocked is returned by the http.Client's CheckRedirect
// function. It is checked in doPost to classify redirect errors as
// non-retryable.
var errRedirectBlocked = errors.New("audit/webhook: redirects are not followed")

// minResponseHeaderTimeout is the floor applied to the derived
// [http.Transport.ResponseHeaderTimeout]. Half of [Config.Timeout] is
// normally used to detect slow-to-respond servers early, but a
// misconfigured tiny [Config.Timeout] (for example 1 ms) would
// otherwise produce a per-stage timeout too short to complete a real
// TLS handshake + server processing burst (#485).
const minResponseHeaderTimeout = 1 * time.Second

// responseHeaderTimeout returns the per-stage response-header timeout
// for the HTTP transport: half of the overall client timeout, but
// never below [minResponseHeaderTimeout]. The overall
// [http.Client.Timeout] still enforces the caller-configured deadline.
func responseHeaderTimeout(t time.Duration) time.Duration {
	half := t / 2
	if half < minResponseHeaderTimeout {
		return minResponseHeaderTimeout
	}
	return half
}

// Output sends batched audit events to an HTTP endpoint with
// retry, SSRF prevention, and graceful shutdown.
//
// See the package-level architecture comment for the two-buffer design.
// Events are formatted as line-delimited JSON (application/x-ndjson).
//
// # Retry
//
// On HTTP 5xx or 429, the batch is retried with exponential backoff
// and jitter (100ms to 5s). On 4xx (other than 429), the batch is
// dropped immediately. On retry exhaustion, the batch is dropped and
// [audit.OutputMetrics.RecordDrop] is called for each event.
//
// # SSRF Prevention
//
// The HTTP client uses [audit.NewSSRFDialControl] to block
// connections to private, loopback, link-local, and cloud metadata
// addresses. Redirects are rejected entirely. Keep-alives are disabled
// to force fresh DNS resolution per request, preventing DNS rebinding.
//
// # Redirects Not Supported
//
// Redirects (301/302/303/307/308 with a Location header) are always
// rejected by [net/http.Client.CheckRedirect] — following a redirect
// would reopen the SSRF surface. For any other 3xx response reaching
// the response-drain path, the body is drained at most 4 KiB so an
// attacker-controlled endpoint cannot force up to maxResponseDrain
// (1 MiB) of traffic per retry. See issue #484.
//
// # At-Least-Once Semantics
//
// Retries may cause duplicate delivery if the server processes a batch
// but returns 5xx due to a timeout. Receivers SHOULD be idempotent.
//
// Output is safe for concurrent use.
//
//nolint:govet // fieldalignment: readability preferred — fields grouped by lifecycle (#463)
type Output struct {
	metrics         audit.Metrics
	outputMetrics   audit.OutputMetrics // immutable after New (#696)
	logger          *slog.Logger        // immutable after New (#696)
	client          *http.Client
	cancel          context.CancelFunc
	done            chan struct{}
	closeCh         chan struct{} // signals batchLoop to drain and exit
	headers         map[string]string
	ch              chan []byte
	url             string
	name            string      // cached from url.Parse at construction
	dropsOversized  dropLimiter // rate-limits oversized-event-rejected warnings (#688)
	dropsBufferFull dropLimiter // rate-limits buffer-full warnings
	flushIvl        time.Duration
	timeout         time.Duration
	// retryHint is the Retry-After delay parsed from the last 429
	// response. Consumed and cleared on the next retry attempt in
	// doPostWithRetry. Read/written only by doPostWithRetry in the
	// batchLoop goroutine; no synchronisation needed.
	retryHint time.Duration
	// contentType holds the request Content-Type as decided by the
	// formatter via [audit.ContentTypeSetter]. The auditor's
	// construction goroutine writes it once; the batchLoop reads it
	// on every doPost. The two goroutines have no synchronisation
	// edge between them at startup (batchLoop is started in New
	// BEFORE audit.New calls SetContentType), so atomic storage is
	// mandatory. A nil pointer means "use [defaultContentType]".
	contentType atomic.Pointer[string]
	// lastDeliveryNanos is the wall-clock UnixNano of the most recent
	// HTTP 2xx response (post-retry). Webhook is async — Write only
	// enqueues — so the timestamp updates from the batch goroutine
	// after the server confirms receipt. Powers
	// [audit.Auditor.LastDeliveryAge] (#753).
	lastDeliveryNanos atomic.Int64
	mu                sync.Mutex
	batchSize         int
	maxBatchBytes     int
	maxEventBytes     int
	maxRetries        int
	closed            atomic.Bool
}

// New creates a new [Output] from the given config.
// It validates the config, builds an SSRF-safe HTTP client, and starts
// the background batch goroutine. The metrics parameter is optional
// (may be nil). Per-output metrics may be supplied at construction
// via [WithOutputMetrics].
//
// Optional [Option] arguments tune construction-time behaviour. Pass
// [WithDiagnosticLogger] to route TLS-policy warnings to a custom
// logger.
func New(cfg *Config, metrics audit.Metrics, opts ...Option) (*Output, error) {
	if cfg == nil {
		return nil, fmt.Errorf("audit/webhook: config must not be nil")
	}
	// Copy config so validation/defaults don't mutate the caller's struct.
	cfgCopy := *cfg
	cfg = &cfgCopy

	o := resolveOptions(opts)

	if err := validateWebhookConfig(cfg); err != nil {
		return nil, err
	}

	tlsCfg, err := buildWebhookTLSConfig(cfg, o.logger)
	if err != nil {
		return nil, fmt.Errorf("audit/webhook: tls: %w", err)
	}

	ssrfOpts := ssrfOptsFromConfig(cfg)

	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: 30 * time.Second,
			Control: audit.NewSSRFDialControl(ssrfOpts...),
		}).DialContext,
		TLSClientConfig:       tlsCfg,
		DisableKeepAlives:     true, // force fresh dial per request (DNS rebinding)
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: responseHeaderTimeout(cfg.Timeout),
	}

	client := &http.Client{
		Timeout:   cfg.Timeout,
		Transport: transport,
		// Zero redirects — redirects reopen the SSRF surface.
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errRedirectBlocked
		},
	}

	// Construction-time connectivity probe (#286). Runs BEFORE the
	// batch goroutine is started so a failed probe never leaks a
	// goroutine. SSRF and TLS verification share their config with
	// the runtime transport — any divergence would be a regression.
	if !cfg.DisableStartupVerification {
		if err := probeEndpoint(cfg.URL, tlsCfg, cfg); err != nil {
			return nil, err
		}
	}

	// Copy headers to prevent caller mutation.
	headers := make(map[string]string, len(cfg.Headers))
	for k, v := range cfg.Headers {
		headers[k] = v
	}

	ctx, cancel := context.WithCancel(context.Background())

	w := &Output{
		client:        client,
		url:           cfg.URL,
		name:          webhookName(cfg.URL),
		headers:       headers,
		metrics:       metrics,
		ch:            make(chan []byte, cfg.BufferSize),
		closeCh:       make(chan struct{}),
		cancel:        cancel,
		done:          make(chan struct{}),
		batchSize:     cfg.BatchSize,
		maxBatchBytes: cfg.MaxBatchBytes,
		maxEventBytes: cfg.MaxEventBytes,
		maxRetries:    cfg.MaxRetries,
		flushIvl:      cfg.FlushInterval,
		timeout:       cfg.Timeout,
		logger:        o.logger,
		outputMetrics: o.outputMetrics,
	}

	go w.batchLoop(ctx)
	return w, nil
}

// Write enqueues a serialised audit event for batched delivery.
// Events exceeding MaxEventBytes are rejected with
// audit.ErrEventTooLarge before the defensive copy (#688). The data
// is copied before enqueuing. If the internal buffer is full, the
// event is dropped and [audit.OutputMetrics.RecordDrop] is called.
// Write never blocks the caller.
func (w *Output) Write(data []byte) error {
	if w.closed.Load() {
		return audit.ErrOutputClosed
	}

	if len(data) > w.maxEventBytes {
		w.dropsOversized.record(dropWarnInterval, func(dropped int64) {
			w.logger.Warn("audit: output webhook: event rejected (exceeds max_event_bytes)",
				"event_bytes", len(data),
				"max_event_bytes", w.maxEventBytes,
				"dropped", dropped)
		})
		// Drops are counted once via per-output OutputMetrics.RecordDrop
		// only — not via pipeline-level Metrics.RecordDelivery. This
		// matches file + syslog behaviour for consistency across all
		// self-reporting outputs (B-25).
		w.outputMetrics.RecordDrop()
		return fmt.Errorf("%w: %w: event size %d exceeds max_event_bytes %d",
			audit.ErrValidation, audit.ErrEventTooLarge, len(data), w.maxEventBytes)
	}

	cp := make([]byte, len(data))
	copy(cp, data)

	select {
	case w.ch <- cp:
		return nil
	default:
		w.dropsBufferFull.record(dropWarnInterval, func(dropped int64) {
			w.logger.Warn("audit: output webhook: event dropped (buffer full)",
				"dropped", dropped,
				"buffer_size", cap(w.ch))
		})
		// Drops are counted via per-output OutputMetrics.RecordDrop
		// only — see B-25 note above.
		w.outputMetrics.RecordDrop()
		return nil // non-blocking — do not return error to drain goroutine
	}
}

// Close signals the batch goroutine to drain and flush, then waits
// for completion. In-flight HTTP requests complete using the live
// context before the context is cancelled. Close is idempotent.
func (w *Output) Close() error {
	// Dual mechanism: mutex serialises the full Close sequence (signal,
	// wait, cancel, cleanup). Atomic provides fast-path rejection in
	// Write() without acquiring the mutex on every call.
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.closed.CompareAndSwap(false, true) {
		return nil
	}

	// Signal the batch loop to drain and exit. The batch loop will
	// flush any pending events using the LIVE context (not cancelled),
	// ensuring in-flight HTTP POSTs complete successfully.
	close(w.closeCh)

	// Shutdown timeout: 2x HTTP timeout (worst-case in-flight +
	// final flush) plus 5s buffer for backoff and channel drain.
	shutdownTimeout := 2*w.timeout + 5*time.Second
	timer := time.NewTimer(shutdownTimeout)
	defer timer.Stop()

	select {
	case <-w.done:
	case <-timer.C:
		w.logger.Error("audit/webhook: batch goroutine did not exit",
			"timeout", shutdownTimeout)
	}

	// Cancel the context AFTER the batch loop exits to clean up any
	// resources tied to it, then close idle HTTP connections.
	w.cancel()
	w.client.CloseIdleConnections()
	return nil
}

// ReportsDelivery returns true, indicating that Output reports
// its own delivery metrics from the batch goroutine after actual HTTP
// delivery, not from the Write enqueue path.
func (w *Output) ReportsDelivery() bool { return true }

// LastDeliveryNanos returns the wall-clock UnixNano of the most recent
// HTTP 2xx response, or 0 if no batch has yet been delivered. Updated
// from the batch goroutine after the server confirms receipt — failed
// batches (network errors, 4xx, retries-exhausted) leave the timestamp
// frozen. Implements [audit.LastDeliveryReporter] (#753).
func (w *Output) LastDeliveryNanos() int64 {
	return w.lastDeliveryNanos.Load()
}

// SetContentType implements [audit.ContentTypeSetter]. The auditor
// calls this once at construction time with the result of
// [audit.Formatter.ContentType] from the effective per-output
// formatter, before any event is dispatched.
//
// Validation rejects (silently — auditor construction continues):
//   - empty strings
//   - values exceeding [maxContentTypeLen]
//   - any string failing [net/http/internal/ascii.IsPrint] equivalent
//     validation against the [RFC 9110] field-value grammar
//     (i.e., contains CR, LF, NUL, or non-printable bytes).
//
// A rejected value leaves the previous Content-Type in place (or
// [defaultContentType] if SetContentType has never been called).
// This protects against a hostile or misbehaving formatter — the
// HTTP transport would reject the malformed value at request-send
// time anyway, but failing early at construction surfaces the bug
// in a single log line rather than per-request errors.
//
// Operator override: a `Content-Type` entry in the output's
// `headers` config (passed via [Config.Headers]) takes precedence
// over the value installed here. The request pipeline sets
// Content-Type from this field first, then applies operator
// headers — so an operator who must send (e.g.) `application/json`
// to a strict CEF receiver can still do so.
func (w *Output) SetContentType(ct string) {
	if ct == "" || len(ct) > maxContentTypeLen || !isValidContentType(ct) {
		w.logger.Warn("audit: output webhook: rejected invalid Content-Type from formatter",
			"value_length", len(ct))
		return
	}
	w.contentType.Store(&ct)
}

// effectiveContentType returns the Content-Type to use on the
// outbound POST: the value set via [Output.SetContentType], or
// [defaultContentType] when the webhook was constructed outside
// an auditor (e.g. unit tests).
func (w *Output) effectiveContentType() string {
	if p := w.contentType.Load(); p != nil {
		return *p
	}
	return defaultContentType
}

// isValidContentType is a conservative byte-level check matching the
// RFC 9110 §5.5 field-value grammar: visible ASCII plus space and
// horizontal tab, no control characters (excluding HTAB), no
// CR/LF/NUL. Sufficient for header-value safety; a stricter
// media-type-grammar check would be over-engineering — the HTTP
// transport applies its own validation downstream.
func isValidContentType(ct string) bool {
	// Iterate raw bytes via index — ranging over the string would yield
	// runes after UTF-8 decoding. Header values are byte-grammars per
	// RFC 9110 §5.5.
	for i := range len(ct) {
		b := ct[i]
		// HTAB (0x09) and visible ASCII (0x20..0x7E) only. Reject
		// every other byte including DEL, CR, LF, NUL.
		if b == 0x09 {
			continue
		}
		if b < 0x20 || b > 0x7E {
			return false
		}
	}
	return true
}

// Name returns the human-readable identifier for this output.
// The name is cached at construction time to avoid per-call url.Parse.
func (w *Output) Name() string {
	return w.name
}

// DestinationKey returns the webhook URL with query parameters and
// fragment stripped, enabling duplicate destination detection via
// [audit.DestinationKeyer]. Query parameters are stripped to avoid
// leaking auth tokens in error messages if two outputs collide.
func (w *Output) DestinationKey() string {
	u, err := url.Parse(w.url)
	if err != nil {
		return w.url
	}
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

// webhookName parses the URL and returns "webhook:<host>" or "webhook"
// if parsing fails.
func webhookName(rawURL string) string {
	if u, err := url.Parse(rawURL); err == nil {
		return "webhook:" + u.Host
	}
	return "webhook"
}

// batchLoop is the background goroutine that accumulates events and
// flushes batches on count threshold, byte threshold, timer timeout,
// or shutdown (#687). A single event whose data length alone exceeds
// MaxBatchBytes is flushed alone — never dropped.
func (w *Output) batchLoop(ctx context.Context) {
	defer close(w.done)

	batch := make([][]byte, 0, w.batchSize)
	batchBytes := 0
	timer := time.NewTimer(w.flushIvl)
	defer timer.Stop()

	for {
		select {
		case data := <-w.ch:
			batch = append(batch, data)
			batchBytes += len(data)
			if len(batch) >= w.batchSize || batchBytes >= w.maxBatchBytes {
				w.flush(ctx, batch)
				batch = batch[:0]
				batchBytes = 0
				resetWebhookTimer(timer, w.flushIvl)
			}

		case <-timer.C:
			if len(batch) > 0 {
				w.flush(ctx, batch)
				batch = batch[:0]
				batchBytes = 0
			}
			resetWebhookTimer(timer, w.flushIvl)

		case <-w.closeCh:
			// Go's select picks randomly among ready cases. If both
			// closeCh and w.ch are ready, data may be read first —
			// drainAndFlush handles any remaining channel items.
			w.drainAndFlush(ctx, batch)
			return
		}
	}
}

// drainAndFlush reads remaining events from the channel and does a
// final flush using the live (not-yet-cancelled) context. This ensures
// in-flight HTTP requests complete successfully during shutdown.
func (w *Output) drainAndFlush(ctx context.Context, batch [][]byte) {
	for {
		select {
		case data := <-w.ch:
			batch = append(batch, data)
		default:
			if len(batch) > 0 {
				w.flush(ctx, batch)
			}
			return
		}
	}
}

// flush sends a batch via HTTP POST with retry.
func (w *Output) flush(ctx context.Context, batch [][]byte) {
	w.doPostWithRetry(ctx, batch)
}

// resetWebhookTimer safely resets a timer, draining the channel first
// if the timer has already fired.
func resetWebhookTimer(t *time.Timer, d time.Duration) {
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
	t.Reset(d)
}
