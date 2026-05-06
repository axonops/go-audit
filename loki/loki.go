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

package loki

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/axonops/audit"
)

// dropWarnInterval is the minimum interval between slog.Warn calls
// for buffer-full drop events. Drops are always counted in metrics;
// only the diagnostic log message is rate-limited.
const dropWarnInterval = 10 * time.Second

// Compile-time interface assertions.
var (
	_ audit.Output           = (*Output)(nil)
	_ audit.MetadataWriter   = (*Output)(nil)
	_ audit.DeliveryReporter = (*Output)(nil)
	_ audit.DestinationKeyer = (*Output)(nil)
)

// errRedirectBlocked is returned by the HTTP client's CheckRedirect
// to reject all redirects, preventing SSRF via open redirects.
var errRedirectBlocked = errors.New("audit/loki: redirects are not followed")

// minResponseHeaderTimeout is the floor applied to the derived
// [http.Transport.ResponseHeaderTimeout]. Half of [Config.Timeout] is
// normally used to detect slow-to-respond servers early, but an
// unusually small [Config.Timeout] would otherwise produce a
// per-stage timeout too short to complete a real TLS handshake +
// server processing burst (#485).
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

// lokiEntry carries a copied event and its metadata through the
// internal buffer channel to the batch goroutine.
type lokiEntry struct { //nolint:govet // fieldalignment: readability preferred
	data     []byte              // defensive copy of serialised event
	metadata audit.EventMetadata // per-event fields for stream labels
}

// frameworkFields holds auditor-wide constant metadata used for Loki
// stream labels. Populated once at construction from the
// [audit.FrameworkContext] supplied via [WithFrameworkContext]. Held
// in an atomic.Pointer so the batchLoop goroutine reads a fully-
// published snapshot without a fresh atomic load per stream-label
// path.
type frameworkFields struct { //nolint:govet // fieldalignment: readability preferred
	appName  string
	host     string
	timezone string
	pid      int
	// pidStr is strconv.Itoa(pid) pre-computed at construction so the
	// per-event resolveDynamicFields path does not allocate a fresh
	// string on every call (#494). Empty when pid==0.
	pidStr string
}

// Output pushes audit events to a Grafana Loki instance via the HTTP
// Push API. It implements [audit.Output], [audit.MetadataWriter],
// [audit.DeliveryReporter], and [audit.DestinationKeyer].
//
// Events are buffered and flushed in batches based on count, byte
// size, or time interval — whichever threshold is reached first.
//
// # Redirects Not Supported
//
// Redirects (301/302/303/307/308 with a Location header) are always
// rejected by [net/http.Client.CheckRedirect] — following a redirect
// would reopen the SSRF surface. For any other 3xx response reaching
// the response-drain path, the body is drained at most 4 KiB so an
// attacker-controlled endpoint cannot force up to maxResponseBody
// (64 KiB) of traffic per retry. See issue #484.
type Output struct { //nolint:govet // fieldalignment: readability preferred
	cfg           *Config
	metrics       audit.Metrics       // core pipeline metrics (optional)
	outputMetrics audit.OutputMetrics // immutable after New (#696)
	ch            chan lokiEntry      // buffered input channel
	done          chan struct{}       // signals batch goroutine exit
	closeCh       chan struct{}       // signals batchLoop to drain and exit
	cancel        context.CancelFunc
	client        *http.Client
	name          string // "loki:<host>", cached at construction
	mu            sync.Mutex
	closed        atomic.Bool
	// fw caches the framework-field snapshot used as Loki stream
	// labels. Populated once in New (#696); the atomic.Pointer
	// indirection is kept because push.go reads on every event and
	// benefits from a single load over a multi-string copy.
	fw              atomic.Pointer[frameworkFields]
	logger          *slog.Logger // immutable after New (#696)
	dropsOversized  dropLimiter  // rate-limits oversized-event-rejected warnings (#688)
	dropsBufferFull dropLimiter  // rate-limits buffer-full warnings
	maxEventBytes   int          // snapshot of cfg.MaxEventBytes — immutable post-construction (#688)
	// lastDeliveryNanos is the wall-clock UnixNano of the most recent
	// HTTP 2xx push response. Loki is async — Write only enqueues —
	// so the timestamp updates from the batch goroutine after the
	// push API confirms receipt. Powers
	// [audit.Auditor.LastDeliveryAge] (#753).
	lastDeliveryNanos atomic.Int64

	// Flush-path state — owned exclusively by batchLoop goroutine.
	streams        map[string]*lokiStream // reused across flushes
	dynFields      []dynamicField         // reused dynamic field slice
	keyBuf         bytes.Buffer           // reused stream key builder
	payloadBuf     bytes.Buffer           // reused JSON payload buffer
	compressBuf    bytes.Buffer           // reused gzip output buffer
	compressDest   io.Writer              // target for gzip; defaults to &compressBuf
	gzWriter       *gzip.Writer           // reused gzip writer
	retryHint      time.Duration          // Retry-After hint from last 429
	sortKeysBuf    []string               // reused scratch for sortedStreams keys (#494)
	sortStreamsBuf []*lokiStream          // reused scratch for sortedStreams result (#494)
	labelKeysBuf   []string               // reused scratch for writeLabelsJSON keys (#494)
	intScratch     [20]byte               // scratch for strconv.AppendInt (int64 ≤ 19 digits + sign) (#494)
}

// New creates a new Loki [Output] from the given config. It validates
// the config, builds an SSRF-safe HTTP client, and starts the
// background batch goroutine. The metrics parameter is optional
// (may be nil). Per-output metrics may be supplied at construction
// via [WithOutputMetrics].
//
// Optional [Option] arguments tune construction-time behaviour. Pass
// [WithDiagnosticLogger] to route TLS-policy warnings to a custom
// logger; [WithFrameworkContext] to seed the auditor-wide framework
// metadata used as Loki stream labels.
func New(cfg *Config, metrics audit.Metrics, opts ...Option) (*Output, error) {
	if cfg == nil {
		return nil, fmt.Errorf("audit/loki: config must not be nil")
	}
	// Copy config so validation/defaults don't mutate the caller's struct.
	cfgCopy := *cfg
	cfg = &cfgCopy

	resolved := resolveOptions(opts)

	if err := validateLokiConfig(cfg); err != nil {
		return nil, err
	}

	tlsCfg, warnings, err := buildLokiTLSConfig(cfg)
	if err != nil {
		return nil, err
	}
	// Log TLS policy warnings via the injected logger (falls back to
	// slog.Default when no option supplied). Sanitised URL mirrors
	// Config.String — path/query/fragment dropped.
	for _, w := range warnings {
		resolved.logger.Warn(w, "output", "loki", "url", sanitizeURLForLog(cfg.URL))
	}

	var ssrfOpts []audit.SSRFOption
	if cfg.AllowPrivateRanges {
		ssrfOpts = append(ssrfOpts, audit.AllowPrivateRanges())
	}

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
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errRedirectBlocked
		},
	}

	// Copy headers to prevent caller mutation.
	headers := make(map[string]string, len(cfg.Headers))
	for k, v := range cfg.Headers {
		headers[k] = v
	}
	cfg.Headers = headers

	ctx, cancel := context.WithCancel(context.Background())

	o := &Output{
		cfg:           cfg,
		metrics:       metrics,
		ch:            make(chan lokiEntry, cfg.BufferSize),
		closeCh:       make(chan struct{}),
		cancel:        cancel,
		done:          make(chan struct{}),
		client:        client,
		name:          lokiName(cfg.URL),
		streams:       make(map[string]*lokiStream),
		maxEventBytes: cfg.MaxEventBytes,
		logger:        resolved.logger,
		outputMetrics: resolved.outputMetrics,
	}
	// Pre-compute the framework-field cache from the supplied
	// FrameworkContext (#696). Always store a non-nil pointer so
	// push.go's atomic load is a single, branchless dereference.
	var pidStr string
	if resolved.fctx.PID != 0 {
		pidStr = strconv.Itoa(resolved.fctx.PID)
	}
	o.fw.Store(&frameworkFields{
		appName:  resolved.fctx.AppName,
		host:     resolved.fctx.Host,
		timezone: resolved.fctx.Timezone,
		pid:      resolved.fctx.PID,
		pidStr:   pidStr,
	})
	o.compressDest = &o.compressBuf // default; overridden in tests

	go o.batchLoop(ctx)
	return o, nil
}

// WriteWithMetadata enqueues a serialised audit event with per-event
// metadata for batched delivery. The data is copied before enqueuing.
// Events exceeding MaxEventBytes are rejected with
// audit.ErrEventTooLarge before the defensive copy (#688). If the
// internal buffer is full, the event is dropped and
// [audit.OutputMetrics.RecordDrop] is called. WriteWithMetadata never blocks.
func (o *Output) WriteWithMetadata(data []byte, meta audit.EventMetadata) error {
	if o.closed.Load() {
		return audit.ErrOutputClosed
	}

	if len(data) > o.maxEventBytes {
		o.dropsOversized.record(dropWarnInterval, func(dropped int64) {
			o.logger.Warn("audit: output loki: event rejected (exceeds max_event_bytes)",
				"event_bytes", len(data),
				"max_event_bytes", o.maxEventBytes,
				"dropped", dropped)
		})
		// Buffer drops (event never attempted) are counted via per-
		// output OutputMetrics.RecordDrop only — not via pipeline-
		// level Metrics.RecordDelivery. Matches file + syslog for
		// consistency across all self-reporting outputs (B-25).
		// RecordDelivery(EventError) remains for retries-exhausted
		// failures in http.go where delivery WAS attempted.
		o.outputMetrics.RecordDrop()
		return fmt.Errorf("%w: %w: event size %d exceeds max_event_bytes %d",
			audit.ErrValidation, audit.ErrEventTooLarge, len(data), o.maxEventBytes)
	}

	cp := make([]byte, len(data))
	copy(cp, data)

	select {
	case o.ch <- lokiEntry{data: cp, metadata: meta}:
		return nil
	default:
		o.dropsBufferFull.record(dropWarnInterval, func(dropped int64) {
			o.logger.Warn("audit: output loki: event dropped (buffer full)",
				"dropped", dropped,
				"buffer_size", cap(o.ch))
		})
		// Buffer drops counted via OutputMetrics.RecordDrop only — see
		// B-25 note above.
		o.outputMetrics.RecordDrop()
		return nil // non-blocking — do not return error to drain goroutine
	}
}

// Write enqueues a serialised audit event without metadata. When
// called directly (outside the core library's MetadataWriter
// dispatch), events are delivered with framework-only stream labels
// and no per-event dynamic labels. Prefer WriteWithMetadata.
func (o *Output) Write(data []byte) error {
	return o.WriteWithMetadata(data, audit.EventMetadata{})
}

// Close signals the batch goroutine to drain and flush, then waits
// for completion. In-flight HTTP retries are cancelled via context.
// Close is idempotent.
func (o *Output) Close() error {
	o.mu.Lock()
	defer o.mu.Unlock()

	if !o.closed.CompareAndSwap(false, true) {
		return nil
	}

	// Signal the batch loop to drain and exit. The batch loop will
	// flush any pending events using the LIVE context (not cancelled),
	// ensuring in-flight HTTP POSTs complete successfully.
	close(o.closeCh)

	// Shutdown timeout: 2x HTTP timeout (worst-case in-flight +
	// final flush) plus 5s buffer for backoff and channel drain.
	shutdownTimeout := 2*o.cfg.Timeout + 5*time.Second
	timer := time.NewTimer(shutdownTimeout)
	defer timer.Stop()

	select {
	case <-o.done:
	case <-timer.C:
		o.logger.Error("audit/loki: batch goroutine did not exit",
			"timeout", shutdownTimeout)
	}

	// Cancel the context AFTER the batch loop exits to clean up any
	// resources tied to it, then close idle HTTP connections.
	o.cancel()
	o.client.CloseIdleConnections()
	return nil
}

// ReportsDelivery returns true, indicating that Output reports
// its own delivery metrics from the batch goroutine after actual HTTP
// delivery, not from the Write enqueue path.
func (o *Output) ReportsDelivery() bool { return true }

// LastDeliveryNanos returns the wall-clock UnixNano of the most recent
// HTTP 2xx push response, or 0 if no batch has yet been delivered.
// Updated from the batch goroutine after the push API confirms
// receipt — failed pushes (network errors, 4xx, retries-exhausted)
// leave the timestamp frozen. Implements
// [audit.LastDeliveryReporter] (#753).
func (o *Output) LastDeliveryNanos() int64 {
	return o.lastDeliveryNanos.Load()
}

// Name returns the human-readable identifier for this output.
func (o *Output) Name() string { return o.name }

// DestinationKey returns the Loki URL with query parameters and
// fragment stripped, enabling duplicate destination detection via
// [audit.DestinationKeyer].
func (o *Output) DestinationKey() string {
	u, err := url.Parse(o.cfg.URL)
	if err != nil {
		return o.cfg.URL
	}
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

// lokiName parses the URL and returns "loki:<host>" or "loki" if
// parsing fails.
func lokiName(rawURL string) string {
	if u, err := url.Parse(rawURL); err == nil {
		return "loki:" + u.Host
	}
	return "loki"
}

// batchLoop is the background goroutine that accumulates events and
// flushes batches on count, bytes, timer, or shutdown.
func (o *Output) batchLoop(ctx context.Context) {
	defer close(o.done)

	batch := make([]lokiEntry, 0, o.cfg.BatchSize)
	batchBytes := 0
	timer := time.NewTimer(o.cfg.FlushInterval)
	defer timer.Stop()

	for {
		select {
		case entry := <-o.ch:
			batch = append(batch, entry)
			batchBytes += len(entry.data)
			if len(batch) >= o.cfg.BatchSize || batchBytes >= o.cfg.MaxBatchBytes {
				o.flush(ctx, batch)
				batch = batch[:0]
				batchBytes = 0
				resetLokiTimer(timer, o.cfg.FlushInterval)
			}

		case <-timer.C:
			if len(batch) > 0 {
				o.flush(ctx, batch)
				batch = batch[:0]
				batchBytes = 0
			}
			resetLokiTimer(timer, o.cfg.FlushInterval)

		case <-o.closeCh:
			// Drain remaining events from the channel and flush
			// with the live context so HTTP POSTs complete.
			o.drainAndFlush(ctx, batch)
			return
		}
	}
}

// drainAndFlush reads remaining events from the channel and does a
// final flush using the provided context. The context is still live
// (not cancelled) so HTTP POSTs complete successfully.
func (o *Output) drainAndFlush(ctx context.Context, batch []lokiEntry) {
	for {
		select {
		case entry := <-o.ch:
			batch = append(batch, entry)
		default:
			if len(batch) > 0 {
				o.flush(ctx, batch)
			}
			return
		}
	}
}

// flush groups events into streams, builds the push payload, compresses
// it, and delivers to Loki via HTTP POST with retry. Metrics are
// recorded in doPostWithRetry after actual delivery outcome.
// flush() is synchronous — it blocks until delivery or drop. The body
// []byte from maybeCompress() points into Output buffers, which is
// safe because the next flush cannot start until this one completes
// (single batchLoop goroutine).
func (o *Output) flush(ctx context.Context, batch []lokiEntry) {
	o.groupByStream(batch)
	o.buildPayload()

	body, compressed, err := o.maybeCompress()
	if err != nil {
		o.logger.Warn("audit/loki: compression failed, sending uncompressed",
			"error", err, "batch_size", len(batch))
		body = o.payloadBuf.Bytes()
		compressed = false
	}

	o.doPostWithRetry(ctx, body, len(batch), compressed)
}

// resetLokiTimer safely resets a timer, draining the channel first
// if the timer has already fired.
func resetLokiTimer(t *time.Timer, d time.Duration) {
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
	t.Reset(d)
}
