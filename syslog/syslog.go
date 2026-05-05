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

package syslog

// srslog (github.com/axonops/srslog) is the AxonOps fork of the srslog
// library, providing RFC 5424 formatting, TCP/UDP/TLS transport, and
// thread-safe writes. Forked from github.com/gravwell/srslog for tagged
// release support and supply chain control (see #147).

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/axonops/audit"
	"github.com/axonops/srslog"
)

// Compile-time assertions.
var (
	_ audit.Output           = (*Output)(nil)
	_ audit.DestinationKeyer = (*Output)(nil)
	_ audit.MetadataWriter   = (*Output)(nil)
	_ audit.DeliveryReporter = (*Output)(nil)
)

// dropWarnInterval is the minimum interval between slog.Warn calls
// for buffer-full drop events.
const dropWarnInterval = 10 * time.Second

// syslogSeverities maps audit severity (0-10) to srslog severity.
// Indexed by audit severity. The mapping follows RFC 5424 severity
// semantics where lower syslog values are more critical:
//
//   - Audit 10 → LOG_CRIT (2): critical security events
//   - Audit 8-9 → LOG_ERR (3): high-severity events
//   - Audit 6-7 → LOG_WARNING (4): medium-severity events
//   - Audit 4-5 → LOG_NOTICE (5): normal operational events
//   - Audit 1-3 → LOG_INFO (6): low-severity informational events
//   - Audit 0 → LOG_DEBUG (7): debug/trace events
//
// LOG_EMERG (0) and LOG_ALERT (1) are intentionally excluded — they
// are reserved for system-level emergencies (kernel panics, imminent
// hardware failure) and can trigger console broadcasts and pager
// alerts on many syslog receivers. An audit library should never emit
// these severities.
var syslogSeverities = [11]srslog.Priority{
	srslog.LOG_DEBUG,   // audit 0
	srslog.LOG_INFO,    // audit 1
	srslog.LOG_INFO,    // audit 2
	srslog.LOG_INFO,    // audit 3
	srslog.LOG_NOTICE,  // audit 4
	srslog.LOG_NOTICE,  // audit 5
	srslog.LOG_WARNING, // audit 6
	srslog.LOG_WARNING, // audit 7
	srslog.LOG_ERR,     // audit 8
	srslog.LOG_ERR,     // audit 9
	srslog.LOG_CRIT,    // audit 10
}

// mapSeverity converts an audit event severity (in the range
// [audit.MinSeverity, audit.MaxSeverity]) to an srslog priority
// constant using the mapping in syslogSeverities. Values outside
// that range silently fall back to LOG_INFO (syslog severity 6).
// The taxonomy enforces the range at registration time, so
// out-of-range values indicate a programming error in a custom
// [Output] that bypasses the auditor and calls this function directly.
func mapSeverity(auditSeverity int) srslog.Priority {
	if auditSeverity < audit.MinSeverity || auditSeverity > audit.MaxSeverity {
		return srslog.LOG_INFO
	}
	return syslogSeverities[auditSeverity]
}

// ReconnectRecorder is an OPTIONAL extension interface for syslog
// reconnection telemetry. A consumer's [audit.OutputMetrics]
// implementation MAY also implement ReconnectRecorder. When the
// syslog output receives per-output metrics via [WithOutputMetrics]
// (or factory wiring via outputconfig.WithOutputMetricsFactory), it
// type-asserts for ReconnectRecorder and invokes RecordReconnect on
// every connect attempt. Precedent: [net/http.Flusher] as an optional
// extension on [http.ResponseWriter].
//
// Consumers who do not care about reconnection telemetry need not
// implement this interface — the base [audit.OutputMetrics] contract
// is sufficient.
type ReconnectRecorder interface {
	// RecordReconnect records a syslog reconnection attempt. success
	// indicates whether the reconnection succeeded. address is the
	// configured host:port. Implementations SHOULD NOT use address
	// as an unbounded metric label.
	RecordReconnect(address string, success bool)
}

// syslogEntry carries a copied event and its priority through the
// internal buffer channel to the writeLoop goroutine.
type syslogEntry struct {
	data     []byte
	priority srslog.Priority
}

// Output writes serialised audit events to a syslog server over
// TCP, UDP, or TCP+TLS (including mTLS). Events are formatted as
// RFC 5424 structured syslog messages with the pre-serialised audit
// payload (JSON or CEF) as the message body.
//
// Write enqueues events into an internal buffered channel and returns
// immediately. A background goroutine reads from the channel and
// performs the actual syslog write with reconnection handling.
//
// # Reconnection
//
// On connection failure, the background goroutine attempts bounded
// exponential backoff reconnection (100ms to 30s with jitter, up to
// [Config.MaxRetries] attempts). If all retries are exhausted, the
// event is dropped and an error metric is recorded. The goroutine
// continues processing subsequent events.
//
// # UDP limitations
//
// UDP syslog is fire-and-forget. Write over UDP rarely returns an
// error even if no server is listening. RFC 5424 recommends receivers
// support messages up to 2048 bytes on UDP; larger payloads may be
// silently truncated or dropped by the OS. Consumers with large audit
// events SHOULD use TCP or TCP+TLS.
//
// # TLS certificates
//
// TLS certificate files are loaded once at construction time and are
// NOT hot-reloaded. If a certificate expires and is rotated on disk,
// the output continues using the old certificate until the process is
// restarted.
//
// Output is safe for concurrent use.
type Output struct {
	// writer is the active srslog.Writer wrapped in atomic.Pointer
	// so the test seam SimulateDisconnect (in export_test.go) can
	// race-free clear it from the test goroutine while writeLoop
	// reads it in writeEntry. The single-writer invariant for
	// production paths is preserved (writeLoop is the only producer
	// outside the test seams). Loads are uncontended on the hot
	// path — one MOV on amd64, one LDAR on arm64 (#765).
	writer            atomic.Pointer[srslog.Writer]
	tlsCfg            *tls.Config         // cached for reconnection; nil for non-TLS
	reconnectRecorder ReconnectRecorder   // optional: nil when outputMetrics does not implement it
	outputMetrics     audit.OutputMetrics // immutable after New (#696)
	logger            *slog.Logger        // immutable after New (#696)
	// testOnFlush, if non-nil, is invoked after every successful
	// batch flush from writeLoop. The callback receives the flushed
	// batch size and a string identifying the trigger reason
	// ("count_threshold", "byte_threshold", "timer", "close",
	// "channel_closed"). Test-only seam — production code MUST NOT
	// set this. Wired via SetTestOnFlush in export_test.go. Replaces
	// the polling test pattern that flaked under CI runner load
	// (#705, #763). See internal/testhelper/output.go for the
	// canonical "wait on observable signal" pattern.
	testOnFlush atomic.Pointer[func(int, string)]
	// testOnReconnect, if non-nil, is invoked from
	// handleWriteFailure immediately after a successful reconnect
	// (after RecordReconnect(addr, true) fires) and before the
	// retry write is attempted on the new writer. The callback
	// receives the freshly-connected writer; tests typically close
	// it to deterministically force the retry-write-failed branch
	// of handleWriteFailure. Test-only seam — production code MUST
	// NOT set this. Wired via SetTestOnReconnect in export_test.go
	// (#765).
	testOnReconnect atomic.Pointer[func(*srslog.Writer)]
	ch              chan syslogEntry // async buffer
	closeCh         chan struct{}    // signals writeLoop to drain and exit
	done            chan struct{}    // closed when writeLoop exits
	name            string           // cached Name() result
	address         string
	network         string
	appName         string
	hostname        string
	writeCount      uint64      // drain-side event counter for RecordQueueDepth sampling
	drops           dropLimiter // rate-limits buffer-full drop warnings
	mu              sync.Mutex  // protects Close sequence
	failures        int         // consecutive failure count (writeLoop-only)
	maxRetry        int
	// Batching knobs — resolved from Config at construction time
	// (#599). See syslog.Config.BatchSize / .FlushInterval /
	// .MaxBatchBytes for the user-facing contract.
	batchSize     int
	flushInterval time.Duration
	maxBatchBytes int
	// maxEventBytes is the per-event size cap enforced at Write()
	// entry to bound consumer-controlled memory pressure (#688).
	maxEventBytes int
	// tlsHandshakeTimeout bounds the total dial+handshake budget on
	// every TLS connect (initial and reconnect, #746). Zero on
	// non-TLS networks; the resolved value is captured from the
	// validated Config and is therefore always within
	// [MinTLSHandshakeTimeout, MaxTLSHandshakeTimeout] when set.
	tlsHandshakeTimeout time.Duration
	// lastDeliveryNanos is the wall-clock UnixNano of the most recent
	// successful syslog write (#753). Async output: Write just
	// enqueues; this timestamp tracks actual remote delivery so
	// [audit.Auditor.LastDeliveryAge] surfaces silently-failing
	// outputs whose retry/drop loop drains the channel without
	// reaching the server.
	lastDeliveryNanos atomic.Int64
	facility          srslog.Priority // facility bits only (no severity)
	closed            atomic.Bool
}

// New creates a new [Output] from the given config. It validates the
// config, establishes the initial connection, and starts the
// background writeLoop goroutine.
//
// Per-output metrics may be supplied at construction via
// [WithOutputMetrics]. When omitted, telemetry calls become no-ops.
//
// Optional [Option] arguments tune construction-time behaviour. Pass
// [WithDiagnosticLogger] to route TLS-policy warnings to a custom
// logger.
func New(cfg *Config, opts ...Option) (*Output, error) {
	o := resolveOptions(opts)

	if err := validateSyslogConfig(cfg); err != nil {
		return nil, err
	}

	priority, err := parseFacility(cfg.Facility)
	if err != nil {
		return nil, fmt.Errorf("audit/syslog: facility %q: %w", cfg.Facility, err)
	}

	// Use explicit hostname from config if provided; otherwise fall
	// back to os.Hostname(). Failure is non-fatal; an empty hostname
	// is acceptable in the RFC 5424 header (NILVALUE "-" per §6.2.4).
	hostname := cfg.Hostname
	if hostname == "" {
		hostname, _ = os.Hostname()
	}

	var tlsCfg *tls.Config
	if cfg.Network == "tcp+tls" {
		tlsCfg, err = buildSyslogTLSConfig(cfg, o.logger)
		if err != nil {
			return nil, fmt.Errorf("audit/syslog: tls config: %w", err)
		}
	}

	maxRetry := cfg.MaxRetries
	if maxRetry <= 0 {
		maxRetry = DefaultMaxRetries
	}

	bufSize := cfg.BufferSize
	if bufSize <= 0 {
		bufSize = DefaultBufferSize
	}

	s := &Output{
		tlsCfg:              tlsCfg,
		ch:                  make(chan syslogEntry, bufSize),
		closeCh:             make(chan struct{}),
		done:                make(chan struct{}),
		name:                "syslog:" + cfg.Address,
		address:             cfg.Address,
		network:             cfg.Network,
		appName:             cfg.AppName,
		hostname:            hostname,
		facility:            priority, // parseFacility returns facility bits only
		maxRetry:            maxRetry,
		batchSize:           cfg.BatchSize,           // resolved to default by validateSyslogBatchingConfig
		flushInterval:       cfg.FlushInterval,       // resolved to default by validateSyslogBatchingConfig
		maxBatchBytes:       cfg.MaxBatchBytes,       // resolved to default by validateSyslogBatchingConfig
		maxEventBytes:       cfg.MaxEventBytes,       // resolved to default by validateMaxEventBytes (#688)
		tlsHandshakeTimeout: cfg.TLSHandshakeTimeout, // resolved to default by validateTLSHandshakeTimeout (#746); zero on non-TLS
		logger:              o.logger,
		outputMetrics:       o.outputMetrics,
	}
	// Detect optional ReconnectRecorder via structural typing.
	if rr, ok := o.outputMetrics.(ReconnectRecorder); ok {
		s.reconnectRecorder = rr
	}

	if err := s.connect(); err != nil {
		return nil, fmt.Errorf("audit/syslog: dial %s://%s: %w",
			cfg.Network, cfg.Address, err)
	}

	go s.writeLoop()
	return s, nil
}

// Write enqueues a serialised audit event for async delivery to the
// syslog server with the default severity (LOG_INFO). The data is
// copied before enqueuing. If the internal buffer is full, the event
// is dropped. Write never blocks the caller.
func (s *Output) Write(data []byte) error {
	return s.enqueue(data, s.facility|srslog.LOG_INFO)
}

// WriteWithMetadata enqueues a serialised audit event for async
// delivery with the syslog severity derived from the audit event's
// severity field.
func (s *Output) WriteWithMetadata(data []byte, meta audit.EventMetadata) error {
	return s.enqueue(data, s.facility|mapSeverity(meta.Severity))
}

// enqueue copies data and sends it to the writeLoop via the buffered
// channel. Events exceeding MaxEventBytes are rejected with
// audit.ErrEventTooLarge before the defensive copy (#688). If the
// channel is full, the event is dropped with metrics.
func (s *Output) enqueue(data []byte, priority srslog.Priority) error {
	if s.closed.Load() {
		return audit.ErrOutputClosed
	}

	if len(data) > s.maxEventBytes {
		s.drops.record(dropWarnInterval, func(dropped int64) {
			s.logger.Warn("audit: output syslog: event rejected (exceeds max_event_bytes)",
				"event_bytes", len(data),
				"max_event_bytes", s.maxEventBytes,
				"dropped", dropped)
		})
		s.outputMetrics.RecordDrop()
		return fmt.Errorf("%w: %w: event size %d exceeds max_event_bytes %d",
			audit.ErrValidation, audit.ErrEventTooLarge, len(data), s.maxEventBytes)
	}

	cp := make([]byte, len(data))
	copy(cp, data)

	select {
	case s.ch <- syslogEntry{data: cp, priority: priority}:
		return nil
	default:
		s.drops.record(dropWarnInterval, func(dropped int64) {
			s.logger.Warn("audit: output syslog: event dropped (buffer full)",
				"dropped", dropped,
				"buffer_size", cap(s.ch))
		})
		s.outputMetrics.RecordDrop()
		return nil // non-blocking — do not return error to drain goroutine
	}
}

// Close signals the background goroutine to drain and flush, then
// waits for completion and closes the syslog connection. Close is
// idempotent and safe for concurrent use.
func (s *Output) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}

	// Signal writeLoop to drain remaining events and exit.
	close(s.closeCh)

	// Wait for writeLoop to finish draining.
	shutdownTimeout := 10 * time.Second
	timer := time.NewTimer(shutdownTimeout)
	defer timer.Stop()

	select {
	case <-s.done:
	case <-timer.C:
		remaining := len(s.ch)
		s.logger.Error("audit: output syslog: shutdown timeout, events lost",
			"timeout", shutdownTimeout,
			"events_lost", remaining)
	}

	// Close the srslog.Writer AFTER the writeLoop exits. Store nil
	// before Close so a concurrent reader (none expected post-
	// shutdown, but defence in depth) cannot observe a half-closed
	// writer.
	if w := s.writer.Load(); w != nil {
		s.writer.Store(nil)
		if err := w.Close(); err != nil {
			return fmt.Errorf("audit/syslog: close: %w", err)
		}
	}
	return nil
}

// ReportsDelivery returns true, indicating that Output reports its
// own delivery metrics from the background writeLoop after actual
// syslog delivery, not from the Write enqueue path.
func (s *Output) ReportsDelivery() bool { return true }

// Name returns the human-readable identifier for this output.
func (s *Output) Name() string {
	return s.name
}

// DestinationKey returns the syslog server address, enabling
// duplicate destination detection via [audit.DestinationKeyer].
func (s *Output) DestinationKey() string {
	return s.address
}

// connect establishes a connection to the syslog server.
//
// For TLS connections, the dial + handshake is wrapped in a single
// context-bounded operation (#746). srslog.DialWithTLSConfig has no
// handshake timeout, so a server that completes the TCP three-way
// handshake but never sends ServerHello would wedge connect()
// indefinitely. We replace it with srslog.DialWithCustomDialer,
// passing a custom dialer that pre-dials the TCP layer with
// net.Dialer.DialContext, wraps with tls.Client, and bounds the
// handshake via tls.Conn.HandshakeContext.
//
// Note: srslog routes to its built-in TLS dialer based on the
// `network` argument string. We MUST pass "custom" here for srslog
// to invoke our custom dialer; the actual TLS layering happens
// inside the custom dialer (it captures s.tlsCfg). The output's
// own s.network field stays "tcp+tls" — that drives our framer
// selection and only-once-per-Output bookkeeping.
func (s *Output) connect() error {
	var w *srslog.Writer
	var err error

	defaultPriority := s.facility | srslog.LOG_INFO
	if s.tlsCfg != nil {
		w, err = srslog.DialWithCustomDialer(
			"custom", s.address, defaultPriority, s.appName,
			s.boundedTLSDialer(s.tlsHandshakeTimeout))
	} else {
		w, err = srslog.Dial(s.network, s.address, defaultPriority, s.appName)
	}
	if err != nil {
		return fmt.Errorf("audit/syslog: connect %s://%s: %w", s.network, s.address, err)
	}

	w.SetFormatter(srslog.RFC5424Formatter)
	// RFC 5425 octet-counting framing is TCP-only; UDP (RFC 5426)
	// uses one-message-per-datagram with no framing prefix.
	if s.network != "udp" {
		w.SetFramer(srslog.RFC5425MessageLengthFramer)
	}
	w.SetHostname(s.hostname)
	s.writer.Store(w)
	return nil
}

// boundedTLSDialer returns a srslog.DialFunc that bounds the total
// TCP-dial-plus-TLS-handshake time to handshakeTimeout (#746). The
// returned closure captures s.tlsCfg by pointer; tls.Client treats
// the *tls.Config as read-only after first use, so reuse across
// reconnects is safe.
//
// On handshake timeout the closure returns an error containing the
// substring "tls handshake timeout" so operators can recognise the
// failure mode in diagnostic logs. The error is wrapped through
// connect()'s "audit/syslog: connect ..." prefix and surfaces as a
// transient (non-ErrConfigInvalid) error so the existing reconnect
// loop in writeLoop retries.
func (s *Output) boundedTLSDialer(handshakeTimeout time.Duration) srslog.DialFunc {
	return func(network, raddr string) (net.Conn, error) {
		ctx, cancel := context.WithTimeout(context.Background(), handshakeTimeout)
		defer cancel()

		// One context governs the whole budget. DialContext (rather
		// than DialTimeout) ensures a slow TCP dial does not get its
		// own timeout — it eats into the same budget as the handshake.
		var dialer net.Dialer
		rawConn, err := dialer.DialContext(ctx, "tcp", raddr)
		if err != nil {
			return nil, fmt.Errorf("audit/syslog: tcp dial: %w", err)
		}
		// Defensive: if anything below this returns an error, close
		// the raw conn before returning so a wedged peer cannot
		// keep the FD open via a lingering goroutine.
		closeOnErr := true
		defer func() {
			if closeOnErr {
				_ = rawConn.Close()
			}
		}()

		// tls.Client requires either ServerName or InsecureSkipVerify
		// in the config (unlike tls.Dial, which infers ServerName from
		// the address). Clone the cached config and populate
		// ServerName from the dialled address when not already set,
		// mirroring tls.Dial's behaviour. The cached config remains
		// untouched and shareable across reconnects.
		tlsCfg := s.tlsCfg
		if tlsCfg.ServerName == "" {
			host, _, splitErr := net.SplitHostPort(raddr)
			if splitErr != nil {
				host = raddr
			}
			tlsCfg = tlsCfg.Clone()
			tlsCfg.ServerName = host
		}

		tlsConn := tls.Client(rawConn, tlsCfg)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return nil, fmt.Errorf("audit/syslog: tls handshake timeout: %w", err)
		}
		// Clear any deadline that may have been inherited; subsequent
		// reads/writes must not be deadline-bounded.
		_ = tlsConn.SetDeadline(time.Time{})
		closeOnErr = false
		return tlsConn, nil
	}
}

// writeLoop is the background goroutine that reads events from the
// channel, accumulates them into batches, and flushes to the syslog
// server (#599). Three triggers cause a flush:
//
//   - Count: len(batch) >= Config.BatchSize.
//   - Byte size: batchBytes >= Config.MaxBatchBytes (inclusive).
//   - Time: Config.FlushInterval has elapsed since the last flush.
//
// A single event exceeding MaxBatchBytes flushes alone — it is never
// dropped. Empty timer ticks are no-ops (no spurious network traffic).
//
// RFC 5425 octet-counting framing is preserved per message: flushBatch
// calls srslog.Writer.WriteWithPriority once per entry, so each event
// remains an independently framed syslog message even within a batch.
//
// On Close, writeLoop drains any remaining channel events into the
// pending batch and flushes once before returning.
func (s *Output) writeLoop() {
	defer close(s.done)

	st := newBatchState(s.batchSize)
	timer := time.NewTimer(s.flushInterval)
	defer timer.Stop()

	for {
		select {
		case entry, ok := <-s.ch:
			if !ok {
				s.flushAndReset(st, "channel_closed")
				return
			}
			st.append(entry)
			if reached, reason := st.thresholdReached(s.batchSize, s.maxBatchBytes); reached {
				s.flushAndReset(st, reason)
				resetSyslogTimer(timer, s.flushInterval)
			}
		case <-timer.C:
			s.flushAndReset(st, "timer")
			resetSyslogTimer(timer, s.flushInterval)
		case <-s.closeCh:
			s.handleShutdownDrain(st.batch)
			return
		}
	}
}

// batchState wraps the writeLoop's mutable batch slice plus the
// accumulated byte count. Encapsulated so writeLoop's top-level body
// stays below gocognit's cyclomatic threshold.
type batchState struct {
	batch      []syslogEntry
	batchBytes int
}

func newBatchState(batchSize int) *batchState {
	return &batchState{
		batch: make([]syslogEntry, 0, batchSize),
	}
}

func (st *batchState) append(entry syslogEntry) {
	st.batch = append(st.batch, entry)
	st.batchBytes += len(entry.data)
}

// thresholdReached returns whether the current batch state has hit a
// flush threshold and, if so, which one. The reason is one of
// "count_threshold" or "byte_threshold"; the empty string is returned
// when no threshold is reached.
func (st *batchState) thresholdReached(batchSize, maxBytes int) (reached bool, reason string) {
	if len(st.batch) >= batchSize {
		return true, "count_threshold"
	}
	if st.batchBytes >= maxBytes {
		return true, "byte_threshold"
	}
	return false, ""
}

// flushAndReset flushes any pending entries and returns the batch
// slice to a fresh zero-length, refreshed-capacity state. Clears
// per-slot pointers so stale event data does not pin memory until
// the next flush overwrites the slot.
func (s *Output) flushAndReset(st *batchState, reason string) {
	if len(st.batch) == 0 {
		return
	}
	flushed := len(st.batch)
	s.flushBatch(st.batch)
	for i := range st.batch {
		st.batch[i].data = nil
	}
	st.batch = st.batch[:0]
	st.batchBytes = 0
	// Prevent unbounded capacity growth from one-time oversized-event
	// outliers (performance-reviewer).
	if cap(st.batch) > 2*s.batchSize {
		st.batch = make([]syslogEntry, 0, s.batchSize)
	}
	// Test-only observability hook (#705/#763). Production-mode
	// callers leave testOnFlush as nil; the predictable nil-branch
	// is amortised over the per-batch flush path. See struct field
	// documentation.
	if hp := s.testOnFlush.Load(); hp != nil {
		(*hp)(flushed, reason)
	}
}

// handleShutdownDrain flushes any pending batch plus events still in
// the channel using the no-reconnect fast path. The normal
// writeEntry retry path can stall for up to maxRetry ×
// syslogMaxBackoff which would exceed the Close shutdown deadline;
// on shutdown we accept that a broken connection means remaining
// events are dropped rather than holding Close hostage. Contract
// documented on [Output.Close].
func (s *Output) handleShutdownDrain(batch []syslogEntry) {
	s.drainBatchNoRetry(batch)
	remaining := s.drainRemainingNoRetry()
	total := len(batch) + remaining
	// Test-only observability hook (#705/#763). Fires once at the
	// end of the Close-path drain regardless of whether the
	// pending batch or the channel held the events. Tests waiting
	// on Close-time flush behaviour (TestWriteLoop_FlushesPartialOnClose)
	// observe a single signal rather than poll. Skip the call when
	// nothing was drained — empty Close should not produce a
	// spurious signal.
	if total == 0 {
		return
	}
	if hp := s.testOnFlush.Load(); hp != nil {
		(*hp)(total, "close")
	}
}

// flushBatch writes every entry in batch to the syslog server via
// srslog.Writer.WriteWithPriority, preserving per-message RFC 5425
// octet-counting framing. Per-entry failures are handled by the
// existing handleWriteFailure reconnect+retry path; remaining batch
// entries continue processing after a failed entry succeeds on retry
// or is dropped after maxRetry exhaustion.
func (s *Output) flushBatch(batch []syslogEntry) {
	for i := range batch {
		s.writeEntry(batch[i])
	}
}

// resetSyslogTimer drains any pending timer event and resets it to
// the given duration. Mirrors the pattern in loki/loki.go to avoid
// timer-leak and double-fire hazards. Safe to call on a stopped or
// running timer.
func resetSyslogTimer(t *time.Timer, d time.Duration) {
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
	t.Reset(d)
}

// errSyslogNotConnected is returned when the syslog writer is nil
// (previous reconnect failed). Pre-allocated to avoid per-event alloc.
var errSyslogNotConnected = errors.New("audit/syslog: writer not connected")

// writeEntry writes a single event to the syslog server with panic
// recovery and reconnection handling.
func (s *Output) writeEntry(entry syslogEntry) {
	om := s.outputMetrics

	defer func() {
		if r := recover(); r != nil {
			buf := make([]byte, 4096)
			n := runtime.Stack(buf, false)
			s.logger.Error("audit: output syslog: panic recovered",
				"panic", r,
				"stack", string(buf[:n]))
			om.RecordError()
		}
	}()

	// Sample queue depth every 64 events.
	s.writeCount++
	if s.writeCount&63 == 0 {
		om.RecordQueueDepth(len(s.ch), cap(s.ch))
	}

	start := time.Now()

	// Attempt write. If the writer is nil (previous reconnect failed),
	// treat as a write failure.
	//
	// Accepted trade-off (#509, master-tracker C-28): srslog.Writer
	// takes an internal mutex on every WriteWithPriority call. That
	// mutex is uncontended in our topology — only writeLoop (one
	// goroutine per syslog Output) ever invokes it — so acquisition
	// adds minimal CAS overhead per event. Benchmarks
	// (BenchmarkSyslogOutput_Write in bench-baseline.txt) report the
	// end-to-end enqueue cost at ~75–78 ns/op dominated by channel
	// send, not the mutex. Forking srslog to strip the mutex would
	// gain single-digit nanoseconds per event on a single hot path,
	// at the cost of maintaining a divergent fork. Accepted as-is.
	var writeErr error
	w := s.writer.Load()
	if w == nil {
		writeErr = errSyslogNotConnected
	} else if _, err := w.WriteWithPriority(entry.priority, entry.data); err != nil {
		writeErr = err
	}

	if writeErr == nil {
		s.failures = 0
		// Three-site invariant: successful arms call
		// recordSuccess so the LastDeliveryReporter
		// timestamp (#753) and OutputMetrics.RecordFlush stay
		// in lockstep. Stays frozen on the failure arm.
		s.recordSuccess(om, 1, time.Since(start))
		return
	}

	// Write failed — attempt reconnection with backoff.
	s.handleWriteFailure(entry, writeErr, om)
}

// LastDeliveryNanos returns the wall-clock UnixNano of the most
// recent successful syslog write, or 0 if no write has yet
// succeeded. Implements [audit.LastDeliveryReporter] (#753).
func (s *Output) LastDeliveryNanos() int64 {
	return s.lastDeliveryNanos.Load()
}

// recordSuccess is the single point where successful
// syslog writes record their telemetry: the [LastDeliveryReporter]
// timestamp (#753) and the per-output [audit.OutputMetrics] flush
// counter. Three success arms call this — writeEntry, the
// retry-after-reconnect path, and drainOne — so the timestamp and
// the flush-count metric can never drift apart.
func (s *Output) recordSuccess(om audit.OutputMetrics, batch int, dur time.Duration) {
	s.lastDeliveryNanos.Store(time.Now().UnixNano())
	om.RecordFlush(batch, dur)
}

// handleWriteFailure attempts reconnection with bounded exponential
// backoff. Called from writeLoop (single goroutine — no mutex needed).
// On success, retries the original write. On exhaustion, drops the
// event.
func (s *Output) handleWriteFailure(entry syslogEntry, writeErr error, om audit.OutputMetrics) {
	s.failures++

	if s.failures > s.maxRetry {
		s.logger.Error("audit: output syslog: retries exhausted, dropping event",
			"address", s.address,
			"failures", s.failures,
			"last_error", writeErr)
		om.RecordError()
		return
	}

	// Close the old writer before reconnecting. Capture into a
	// local before Store(nil) so the method-value resolution
	// (w.Close) cannot race with the field reset.
	if w := s.writer.Load(); w != nil {
		s.writer.Store(nil)
		closeWriterForReconnect(w.Close, s.logger, s.address)
	}

	backoff := backoffDuration(s.failures)
	s.logger.Warn("audit: output syslog: reconnecting",
		"address", s.address,
		"attempt", s.failures,
		"backoff", backoff)

	om.RecordRetry(s.failures)

	// Sleep with closeCh interrupt — no mutex to release since the
	// writeLoop goroutine owns the connection exclusively.
	timer := time.NewTimer(backoff)
	select {
	case <-timer.C:
	case <-s.closeCh:
		timer.Stop()
		// Shutting down — don't reconnect, just drop.
		return
	}
	timer.Stop()

	rr := s.reconnectRecorder

	if err := s.connect(); err != nil {
		s.logger.Error("audit: output syslog: reconnect failed",
			"address", s.address,
			"attempt", s.failures,
			"error", err)
		if rr != nil {
			rr.RecordReconnect(s.address, false)
		}
		return
	}

	s.logger.Info("audit/syslog: reconnected", "address", s.address)
	if rr != nil {
		rr.RecordReconnect(s.address, true)
	}

	// Test-only observability hook (#765). Production-mode callers
	// leave testOnReconnect as nil; the predictable nil-branch is
	// amortised over the failure-recovery path, which is already
	// off the hot path. See struct field documentation.
	if hp := s.testOnReconnect.Load(); hp != nil {
		(*hp)(s.writer.Load())
	}

	if !s.retryAfterReconnect(entry, om) {
		return
	}

	s.failures = 0
	// Successful retry-after-reconnect — duration is not
	// meaningful here because the reconnect dwarfs the write.
	s.recordSuccess(om, 1, 0)
}

// retryAfterReconnect performs the post-reconnect retry write on
// the freshly-connected writer. Returns true on success, false on
// failure (caller should return without resetting s.failures).
//
// connect() just stored a non-nil writer and writeLoop is the sole
// mutator outside test seams; Load is expected to return non-nil.
// Defence in depth: if a future refactor or a test seam (e.g.,
// SimulateDisconnect via SetTestOnReconnect, #765) breaks the
// invariant, log loudly and record the failure rather than panic.
func (s *Output) retryAfterReconnect(entry syslogEntry, om audit.OutputMetrics) bool {
	w := s.writer.Load()
	if w == nil {
		s.logger.Error("audit: output syslog: writer nil after successful reconnect",
			"address", s.address)
		om.RecordError()
		return false
	}
	if _, err := w.WriteWithPriority(entry.priority, entry.data); err != nil {
		s.logger.Error("audit: output syslog: delivery failed after reconnect",
			"error", err)
		om.RecordError()
		return false
	}
	return true
}

// drainBatchNoRetry flushes pending batch entries to the syslog
// server during shutdown without retrying on failure. Used by the
// writeLoop's closeCh branch so that Close does not stall on a
// broken connection.
func (s *Output) drainBatchNoRetry(batch []syslogEntry) {
	for i := range batch {
		s.drainOne(batch[i])
	}
}

// drainRemainingNoRetry reads all remaining events from the channel
// after closeCh fires and writes them without retry. Non-blocking;
// returns the number drained once the channel is empty.
func (s *Output) drainRemainingNoRetry() int {
	drained := 0
	for {
		select {
		case entry := <-s.ch:
			s.drainOne(entry)
			drained++
		default:
			return drained
		}
	}
}

// drainOne writes a single event during drain with panic recovery
// and metrics recording. No reconnection is attempted — if the write
// fails, the event is dropped.
func (s *Output) drainOne(entry syslogEntry) {
	om := s.outputMetrics

	defer func() {
		if r := recover(); r != nil {
			buf := make([]byte, 4096)
			n := runtime.Stack(buf, false)
			s.logger.Error("audit: output syslog: panic recovered during drain",
				"panic", r,
				"stack", string(buf[:n]))
			om.RecordError()
		}
	}()

	w := s.writer.Load()
	if w == nil {
		return
	}

	start := time.Now()
	if _, err := w.WriteWithPriority(entry.priority, entry.data); err != nil {
		s.logger.Error("audit: output syslog: delivery failed during drain",
			"error", err)
		om.RecordError()
		return
	}
	s.recordSuccess(om, 1, time.Since(start))
}
