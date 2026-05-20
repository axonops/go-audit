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
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// randReader is the entropy source for [newChannelGUID]. Production
// uses crypto/rand.Reader; tests inject a failing reader to exercise
// the ErrCryptoRandFailed code path.
var randReader io.Reader = rand.Reader //nolint:revive,gochecknoglobals // package-level swap point for test entropy injection

// channelGUID is a 128-bit identifier in UUID v4 textual form
// (8-4-4-4-12 hex with version 4 and variant 10). One per [Output]
// instance.
type channelGUID string

// newChannelGUID returns a crypto/rand-sourced UUID v4. On any
// failure of the entropy source it returns ErrCryptoRandFailed —
// callers MUST propagate (never substitute a zero or pseudo-random
// GUID; a deterministic channel value would let an attacker observe
// or replay ack states).
func newChannelGUID(r io.Reader) (channelGUID, error) {
	var b [16]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return "", fmt.Errorf("%w: %w", ErrCryptoRandFailed, err)
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return channelGUID(fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])), nil
}

// AckMetricsRecorder is an optional extension implemented by
// [audit.OutputMetrics] instances that care about ACK telemetry.
// The library detects support via a runtime type assertion (same
// pattern as [file.RotationRecorder]). Implementations that do not
// implement this interface silently skip the ACK metric calls.
type AckMetricsRecorder interface {
	// RecordAckPending reports the current count of batches awaiting
	// acknowledgement. Called once per poll tick.
	RecordAckPending(gauge int)
	// RecordAckConfirmed records that `count` batches received a
	// positive ack in the last poll. Called once per poll tick when
	// count > 0.
	RecordAckConfirmed(count int)
	// RecordAckTimedOut records that `count` batches exceeded the
	// configured AckResendWindow. Called once per poll tick when
	// count > 0. Only fires for AckModeRequired.
	RecordAckTimedOut(count int)
	// RecordAckBufferFullDrop records that `count` events were
	// dropped because the in-flight buffer was full (AckModeRequired
	// only). Called from the batchLoop side, not from the poller.
	RecordAckBufferFullDrop(count int)
}

// AckSnapshot is a point-in-time view of the tracker's counters.
// Returned by [Output.AckMetricsSnapshot] for consumers who prefer
// pull-based reads over the push-based [AckMetricsRecorder] path.
type AckSnapshot struct {
	// Pending is len(inFlight) — batches with ackIDs we haven't yet
	// confirmed or timed out.
	Pending int
	// Confirmed is the cumulative count of batches with a positive ack.
	Confirmed int64
	// TimedOut is the cumulative count of batches whose AckResendWindow
	// elapsed without a positive ack (AckModeRequired only).
	TimedOut int64
	// BufferFullDrops is the cumulative count of events dropped because
	// the in-flight buffer was full (AckModeRequired only).
	BufferFullDrops int64
}

// flushBufs bundles the per-flush scratch buffers so the batchLoop
// and the resend path (poller goroutine, AckModeRequired) each own a
// separate set — `flushBatchAux` is called from both goroutines, and
// these buffers are not concurrent-safe.
type flushBufs struct {
	envelope  bytes.Buffer
	raw       bytes.Buffer
	compress  bytes.Buffer
	gz        *gzip.Writer // initialised once at construction
	retryHint time.Duration
}

// newFlushBufs constructs a flushBufs with its gzip writer pre-allocated.
func newFlushBufs() *flushBufs {
	b := &flushBufs{}
	b.gz = gzip.NewWriter(&b.compress)
	return b
}

// inFlightBatch holds one outstanding batch whose ackID is being
// polled. Owned exclusively by ackTracker; never escapes the package.
type inFlightBatch struct {
	ackID   int64
	entries []splunkEntry // retained for resend in AckModeRequired
	sentAt  time.Time
	resends int
}

// ackTracker is the per-output ACK state machine. One instance per
// [Output] when AckMode != AckModeOff (nil otherwise). The tracker
// runs exactly one goroutine — [ackTracker.pollLoop] — which polls
// /services/collector/ack at the configured AckPollInterval and
// applies confirmations / resends in a single tick.
//
// # Concurrency invariants
//
//   - `channel` and `pollURL` are immutable after newAckTracker;
//     safe lock-free read.
//   - `inFlight` is guarded by `mu`. Mutated by tracker.register
//     (batchLoop goroutine), tracker.applyConfirmations and
//     tracker.checkResendWindow (pollLoop goroutine), and
//     tracker.flushOnClose (Close caller).
//   - `confirmed` / `timedOut` / `bufferFullDrops` are atomic.Int64;
//     updated outside mu, read lock-free by [Output.AckMetricsSnapshot].
//   - `closed` is guarded by mu; transitions false→true once.
//   - `ctx` / `cancel` / `done` set in newAckTracker; cancel is
//     idempotent.
type ackTracker struct { //nolint:govet // fieldalignment: readability preferred (grouped by concern)
	cfg     *Config
	out     *Output
	channel channelGUID
	pollURL string

	// In-flight state.
	mu       sync.Mutex
	inFlight map[int64]*inFlightBatch
	closed   bool

	// Resend buffers — owned exclusively by pollLoop. Decoupled from
	// the batchLoop's flush buffers so resends don't race against
	// in-flight flushes.
	resendBufs *flushBufs

	// Lock-free counters.
	confirmed       atomic.Int64
	timedOut        atomic.Int64
	bufferFullDrops atomic.Int64

	// Rate-limited warns.
	warnPollFailure *dropLimiter

	// Goroutine lifecycle.
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
}

// newAckTracker constructs and returns a tracker for the given
// Output. Does NOT start the poll goroutine — caller is responsible
// for `go tr.pollLoop(ctx)` after the feature-detection probe has
// succeeded.
func newAckTracker(ctx context.Context, out *Output, channel channelGUID) (*ackTracker, error) {
	pollURL, err := joinAckURL(out.cfg.URL, string(channel))
	if err != nil {
		return nil, fmt.Errorf("audit/splunk: build ack URL: %w", err)
	}
	tCtx, cancel := context.WithCancel(ctx)
	return &ackTracker{
		cfg:             out.cfg,
		out:             out,
		channel:         channel,
		pollURL:         pollURL,
		inFlight:        make(map[int64]*inFlightBatch, out.cfg.BufferSize/out.cfg.BatchSize+1),
		resendBufs:      newFlushBufs(),
		warnPollFailure: newDropLimiter(dropWarnInterval),
		ctx:             tCtx,
		cancel:          cancel,
		done:            make(chan struct{}),
	}, nil
}

// register adds a freshly-sent batch to the in-flight set. Called by
// the batchLoop goroutine after a successful doPost that returned an
// ackID. The `entries` slice is retained for resend in
// AckModeRequired; AckModeBestEffort callers pass `nil` to save
// memory because resends are never attempted in best-effort mode.
func (t *ackTracker) register(ackID int64, entries []splunkEntry) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return
	}
	t.inFlight[ackID] = &inFlightBatch{
		ackID:   ackID,
		entries: entries,
		sentAt:  time.Now(),
	}
}

// inFlightCount returns the current in-flight buffer occupancy.
// Called by the batchLoop side before a flush in AckModeRequired to
// enforce the BufferSize cap (AC 59).
func (t *ackTracker) inFlightCount() int {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.inFlight)
}

// recordBufferFullDrop is the batchLoop-side hook for AC 59. Called
// when an oversize batch would push in-flight past BufferSize.
func (t *ackTracker) recordBufferFullDrop(count int) {
	if t == nil {
		return
	}
	t.bufferFullDrops.Add(int64(count))
	if rec, ok := t.out.outputMetrics.(AckMetricsRecorder); ok {
		rec.RecordAckBufferFullDrop(count)
	}
}

// pollLoop is the tracker's sole goroutine. Ticks at AckPollInterval
// and on each tick: (1) snapshots outstanding ackIDs, (2) polls
// /services/collector/ack, (3) applies confirmations, (4) checks the
// resend window (AckModeRequired only). Exits when t.ctx is
// cancelled (via [ackTracker.stop]).
//
// The `ctx` parameter is unused — pollLoop selects on t.ctx so
// tracker.stop() reliably cancels regardless of the caller's ctx.
// Kept for symmetry with batchLoop and to allow future per-tick
// context derivation.
func (t *ackTracker) pollLoop(_ context.Context) {
	defer close(t.done)
	ticker := time.NewTicker(t.cfg.AckPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-t.ctx.Done():
			return
		case <-ticker.C:
			t.tick(t.ctx)
		}
	}
}

// tick is the per-iteration body of pollLoop, extracted for testability.
func (t *ackTracker) tick(ctx context.Context) {
	ids := t.snapshotIDs()
	if len(ids) == 0 {
		t.publishPending()
		return
	}
	confirmed, err := t.pollAcks(ctx, ids)
	if err != nil {
		if t.warnPollFailure.allow() {
			t.out.logger.Warn("audit/splunk: ack poll failed",
				"output", t.out.name, "error", t.out.redact(err))
		}
		// Don't apply confirmations; let the resend-window logic
		// handle it on the next tick.
	} else {
		t.applyConfirmations(confirmed)
	}
	if t.cfg.AckMode == AckModeRequired {
		t.checkResendWindow(ctx)
	}
	t.publishPending()
}

// snapshotIDs returns the current in-flight ackID list. Safe to call
// from any goroutine.
func (t *ackTracker) snapshotIDs() []int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.inFlight) == 0 {
		return nil
	}
	ids := make([]int64, 0, len(t.inFlight))
	for id := range t.inFlight {
		ids = append(ids, id)
	}
	return ids
}

// applyConfirmations removes confirmed ackIDs from the in-flight map
// and increments the confirmed counter. Drops the retained entries
// slice for confirmed batches so resend storage is bounded.
func (t *ackTracker) applyConfirmations(confirmed map[int64]bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	var n int64
	for id, ok := range confirmed {
		if !ok {
			continue
		}
		if _, present := t.inFlight[id]; present {
			delete(t.inFlight, id)
			n++
		}
	}
	if n > 0 {
		t.confirmed.Add(n)
		if rec, ok := t.out.outputMetrics.(AckMetricsRecorder); ok {
			rec.RecordAckConfirmed(int(n))
		}
	}
}

// checkResendWindow scans in-flight batches whose sentAt is older
// than AckResendWindow. Each such batch is removed from in-flight,
// counted as timed out, and re-enqueued via flushBatchAux on the
// tracker's own resendBufs (decoupled from the batchLoop). Only
// called for AckModeRequired.
func (t *ackTracker) checkResendWindow(ctx context.Context) {
	now := time.Now()
	var toResend []*inFlightBatch
	t.mu.Lock()
	for id, batch := range t.inFlight {
		if now.Sub(batch.sentAt) > t.cfg.AckResendWindow {
			toResend = append(toResend, batch)
			delete(t.inFlight, id)
		}
	}
	t.mu.Unlock()
	if len(toResend) == 0 {
		return
	}
	t.timedOut.Add(int64(len(toResend)))
	if rec, ok := t.out.outputMetrics.(AckMetricsRecorder); ok {
		rec.RecordAckTimedOut(len(toResend))
	}
	for _, batch := range toResend {
		t.out.logger.Warn("audit/splunk: ack resend window elapsed — resending",
			"output", t.out.name,
			"batch_size", len(batch.entries),
			"prior_resends", batch.resends)
		if len(batch.entries) == 0 {
			continue
		}
		t.out.flushBatchAux(ctx, batch.entries, t.resendBufs)
	}
}

// publishPending fires the pending-count gauge to the
// AckMetricsRecorder if the metrics sink implements it.
func (t *ackTracker) publishPending() {
	if rec, ok := t.out.outputMetrics.(AckMetricsRecorder); ok {
		t.mu.Lock()
		n := len(t.inFlight)
		t.mu.Unlock()
		rec.RecordAckPending(n)
	}
}

// pollAcks issues `POST /services/collector/ack?channel=<GUID>` with
// body `{"acks":[id,...]}` and parses the response
// `{"acks":{"<id>":true|false,...}}`. Returns a map keyed by ackID
// with the confirmation status. Response body is bounded by
// `io.LimitReader(maxResponseDrainAck)` (1 MiB; documented at
// http.go).
func (t *ackTracker) pollAcks(ctx context.Context, ids []int64) (map[int64]bool, error) {
	body, err := json.Marshal(struct {
		Acks []int64 `json:"acks"`
	}{Acks: ids})
	if err != nil {
		return nil, fmt.Errorf("encode ack body: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.pollURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build ack request: %w", err)
	}
	t.out.applyRequestHeaders(req, false)
	resp, err := t.out.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ack request: %w", err)
	}
	defer drainAndClose(resp, maxResponseDrainAck)

	if !checkResponseSize(resp, maxResponseDrainAck) {
		// Force connection close — peer lied about Content-Length.
		resp.Close = true
		_ = resp.Body.Close()
		return nil, fmt.Errorf("ack response Content-Length %d exceeds %d", resp.ContentLength, int64(maxResponseDrainAck))
	}

	respBytes, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseDrainAck))

	if resp.StatusCode != http.StatusOK {
		// Detect ack-disabled via HEC code 14. classify() returns
		// actionAckDisabled for this combo; we parse the code here
		// to give a precise error for the operator log.
		hecCode, _ := parseHECCode(respBytes)
		if hecCode == 14 {
			return nil, fmt.Errorf("%w: HEC returned code 14 from /ack", ErrAckDisabled)
		}
		return nil, fmt.Errorf("ack HTTP %d (hec=%d)", resp.StatusCode, hecCode)
	}

	var parsed struct {
		Acks map[string]bool `json:"acks"`
	}
	if err := json.Unmarshal(respBytes, &parsed); err != nil {
		return nil, fmt.Errorf("decode ack response: %w", err)
	}
	out := make(map[int64]bool, len(parsed.Acks))
	for k, v := range parsed.Acks {
		var id int64
		if _, err := fmt.Sscanf(k, "%d", &id); err == nil {
			out[id] = v
		}
	}
	return out, nil
}

// flushOnClose observes the in-flight set draining naturally via
// the still-running pollLoop. Called from [Output.Close] BEFORE
// tracker.stop() cancels the loop. Best-effort: if the budget
// elapses with in-flight remaining, those batches are abandoned
// (resend on next process start is not the library's job —
// operators integrate with a journaling layer for strong durability).
//
// flushOnClose MUST NOT call tick() directly — the pollLoop owns the
// resendBufs and any concurrent flushBatchAux invocation from this
// goroutine would race against an in-flight tick.
func (t *ackTracker) flushOnClose(_ context.Context) {
	if t == nil {
		return
	}
	budget := 2 * t.cfg.Timeout
	deadline := time.Now().Add(budget)
	pollEvery := t.cfg.AckPollInterval
	for time.Now().Before(deadline) {
		t.mu.Lock()
		n := len(t.inFlight)
		t.mu.Unlock()
		if n == 0 {
			return
		}
		time.Sleep(pollEvery)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.inFlight) > 0 {
		t.out.logger.Warn("audit/splunk: Close timed out with batches still in-flight",
			"output", t.out.name, "remaining", len(t.inFlight))
	}
}

// stop cancels the poll goroutine and waits for it to exit. Called
// after flushOnClose from [Output.Close].
func (t *ackTracker) stop() {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.closed = true
	t.mu.Unlock()
	t.cancel()
	<-t.done
}

// snapshot returns a point-in-time view of the tracker's counters.
// Lock-free per the concurrency annotations above; the only locked
// read is `len(inFlight)`.
func (t *ackTracker) snapshot() AckSnapshot {
	if t == nil {
		return AckSnapshot{}
	}
	t.mu.Lock()
	n := len(t.inFlight)
	t.mu.Unlock()
	return AckSnapshot{
		Pending:         n,
		Confirmed:       t.confirmed.Load(),
		TimedOut:        t.timedOut.Load(),
		BufferFullDrops: t.bufferFullDrops.Load(),
	}
}
