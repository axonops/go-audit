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

// The drain-side of the syslog Output: the writeLoop goroutine, batch
// state, per-event writeEntry, and the no-retry shutdown drain helpers.
// Reconnect machinery (connect, boundedTLSDialer, handleWriteFailure,
// retryAfterReconnect) and the public API live in syslog.go (#540).

import (
	"errors"
	"runtime"
	"time"
)

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
