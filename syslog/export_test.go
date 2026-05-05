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

import (
	"crypto/tls"
	"net"
	"time"

	"github.com/axonops/srslog"
)

// BackoffDuration is exported for testing only.
var BackoffDuration = backoffDuration

// ValidateConfig is exported for testing only — exposes the package-
// internal validateSyslogConfig so tests can verify validator
// behaviour (defaulting, range checks) without dialling. Mutates cfg
// in place to fill defaulted values.
var ValidateConfig = validateSyslogConfig

// NewOutputForTesting constructs a minimal Output suitable for
// driving boundedTLSDialer directly without going through New —
// avoids the connect() round-trip on construction (#746). The
// returned Output is NOT safe to use for Write/Close.
func NewOutputForTesting(tlsCfg *tls.Config) *Output {
	return &Output{tlsCfg: tlsCfg}
}

// BoundedTLSDialer exposes the package-internal Output.boundedTLSDialer
// for tests that need to verify each invocation independently
// honours the configured handshake timeout (#746 AC #10).
func (s *Output) BoundedTLSDialer(handshakeTimeout time.Duration) func(network, raddr string) (net.Conn, error) {
	return s.boundedTLSDialer(handshakeTimeout)
}

// CloseWriterForReconnect is exported for testing only — lets tests
// drive the Close-error logging path without needing an interface
// seam on Output.writer (which is a concrete *srslog.Writer) (#489).
var CloseWriterForReconnect = closeWriterForReconnect

// MapSeverity is exported for testing only.
var MapSeverity = mapSeverity

// SimulateWriteFailure exercises the error path in writeEntry by
// temporarily setting the writer to nil. This causes
// errSyslogNotConnected to be returned, triggering handleWriteFailure
// which records RecordRetry/RecordError. Called synchronously from
// the test goroutine while writeLoop is blocked on an empty channel.
//
// The atomic.Pointer wrap (#765) makes the save/restore race-free
// under -race even when the writeLoop is technically still in flight
// from a prior batch (load-store on the same field is well-defined).
func (s *Output) SimulateWriteFailure() {
	saved := s.writer.Load()
	s.writer.Store(nil)
	s.writeEntry(syslogEntry{data: []byte("trigger-error"), priority: 0})
	s.writer.Store(saved)
}

// SimulateDisconnect atomically clears Output.writer without first
// closing the prior writer (the caller's hostile-server harness has
// already RST'd the underlying TCP connection). The next call to
// writeEntry triggered by an enqueued event sees errSyslogNotConnected
// at the nil check, enters handleWriteFailure, and (if the listener
// is still up) calls connect() → RecordReconnect(addr, true)
// deterministically. Used by hostile-server tests to bypass the TCP
// send-buffer cache that otherwise allows the first post-RST write
// to silently succeed at the syscall level (#765).
//
// Callers SHOULD wait for an initial flush barrier (via
// SetTestOnFlush) before invoking, so the next event the writeLoop
// processes is the one that observes nil. The Store itself is always
// race-clean (atomic.Pointer guarantees that); the wait is for test
// determinism, not memory safety.
func (s *Output) SimulateDisconnect() {
	s.writer.Store(nil)
}

// SetTestOnFlush registers a test-only callback fired after every
// successful batch flush from writeLoop. The callback receives the
// flushed batch size and a string identifying the trigger reason:
//
//   - "count_threshold" — len(batch) >= Config.BatchSize
//   - "byte_threshold"  — sum of entry sizes >= Config.MaxBatchBytes
//   - "timer"           — Config.FlushInterval elapsed
//   - "close"           — Output.Close drained the batch
//   - "channel_closed"  — Audit channel closed (Close path)
//
// Pass nil to clear the hook. Tests typically pair this with t.Cleanup
// to ensure the hook is cleared even if the test fails mid-flow.
//
// Replaces the polling test pattern (require.Eventually) that flaked
// under CI runner load (#705, #763). The canonical usage is:
//
//	flushed := make(chan struct {
//	    n      int
//	    reason string
//	}, 64)
//	out.SetTestOnFlush(func(n int, reason string) {
//	    select {
//	    case flushed <- struct {
//	        n      int
//	        reason string
//	    }{n, reason}:
//	    default: // never block production
//	    }
//	})
//	t.Cleanup(func() { out.SetTestOnFlush(nil) })
//
// Concurrency: the hook is invoked from the writeLoop goroutine.
// Callbacks MUST return promptly and MUST NOT block on a full
// channel. Use a buffered channel and non-blocking send.
func (s *Output) SetTestOnFlush(fn func(int, string)) {
	if fn == nil {
		s.testOnFlush.Store(nil)
		return
	}
	s.testOnFlush.Store(&fn)
}

// SetTestOnReconnect registers a test-only callback fired from
// handleWriteFailure immediately after a successful reconnect — i.e.
// after RecordReconnect(addr, true) but before the post-reconnect
// retry path runs. The callback receives the freshly-connected
// writer.
//
// Canonical use: call SimulateDisconnect() from inside the hook.
// This atomically clears Output.writer; handleWriteFailure's
// retryAfterReconnect helper re-loads s.writer immediately after
// the hook returns, sees nil, and trips the
// "writer nil after successful reconnect" guard which fires
// RecordError. This is the deterministic way to assert that the
// post-reconnect retry leg of handleWriteFailure was reached.
//
// Calling w.Close() directly does NOT work — srslog.Writer
// transparently re-dials internally on a closed conn (see
// writeAndRetryWithPriority in github.com/axonops/srslog), so the
// subsequent WriteWithPriority succeeds and the retry-write-error
// branch is masked.
//
// Mutations to s.writer from inside the hook are observed by the
// immediately-following s.writer.Load() in retryAfterReconnect.
//
// Pass nil to clear the hook. Tests typically pair this with
// t.Cleanup to ensure the hook is cleared even if the test fails
// mid-flow.
//
// Concurrency: invoked synchronously from the writeLoop goroutine.
// Callbacks MUST return promptly (#765 AC3).
func (s *Output) SetTestOnReconnect(fn func(*srslog.Writer)) {
	if fn == nil {
		s.testOnReconnect.Store(nil)
		return
	}
	s.testOnReconnect.Store(&fn)
}
