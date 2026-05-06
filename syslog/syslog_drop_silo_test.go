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

// Tests for the per-cause dropLimiter split (#692). The syslog Output
// formerly shared a single `drops` rate-limiter between the
// oversized-event-rejected path (#688) and the buffer-full path. A
// burst of one cause silenced the other in the same dropWarnInterval
// window. After #692 each cause has its own limiter; this test
// verifies the silos are independent **in both directions** —
// neither the oversized burst nor the buffer-full burst should
// silence the other, regardless of which arrives first.

package syslog_test

import (
	"bytes"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/audit/syslog"
)

// syslogSyncBuf wraps bytes.Buffer with a mutex so slog.JSONHandler
// can safely write concurrently with the test reader.
type syslogSyncBuf struct {
	buf bytes.Buffer
	mu  sync.Mutex
}

func (s *syslogSyncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syslogSyncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// TestDropLimiter_OversizedAndBufferFullSilosAreIndependent_Syslog
// asserts that an oversized-reject burst does NOT silence a
// subsequent buffer-full warn within the same dropWarnInterval, and
// vice-versa. Each cause has its own dropLimiter as of #692.
//
// Pre-#692 either ordering would observe exactly one warn — the
// first cause saturates the shared limiter; the second cause's warn
// is silenced. After #692 both warns appear regardless of order.
//
// The reverse-order subtest also defends against an asymmetric
// regression where only one of the two record() call sites is
// rewired to its dedicated limiter.
func TestDropLimiter_OversizedAndBufferFullSilosAreIndependent_Syslog(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		first string // "oversized" or "buffer_full"
	}{
		{name: "oversized_first_then_buffer_full", first: "oversized"},
		{name: "buffer_full_first_then_oversized", first: "buffer_full"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Stall the destination so the writeLoop cannot drain
			// the channel. stallingTCPListener (defined in
			// syslog_tls_handshake_timeout_test.go) accepts the
			// connection but never reads, so srslog's send blocks
			// on the kernel TCP buffer. Subsequent writes fill the
			// 1-slot internal channel and hit the default branch.
			addr, stopListener := stallingTCPListener(t)
			t.Cleanup(stopListener)

			buf := &syslogSyncBuf{}
			logger := slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

			const maxBytes = syslog.MinMaxEventBytes // 1 KiB
			out, err := syslog.New(&syslog.Config{
				Network:       "tcp",
				Address:       addr,
				BufferSize:    1,
				FlushInterval: 1 * time.Millisecond,
				MaxEventBytes: maxBytes,
			}, syslog.WithDiagnosticLogger(logger))
			require.NoError(t, err)
			t.Cleanup(func() { _ = out.Close() })

			oversized := bytes.Repeat([]byte("X"), maxBytes+1)
			triggerOversized := func() {
				for range 5 {
					_ = out.Write(oversized)
				}
			}
			triggerBufferFull := func() {
				// Flood with enough small writes that, with the
				// destination stalled and BufferSize=1, the channel
				// fills and at least one write hits the default
				// branch.
				for range 200 {
					_ = out.Write([]byte(`{"n":1}`))
				}
			}

			if tt.first == "oversized" {
				triggerOversized()
				triggerBufferFull()
			} else {
				triggerBufferFull()
				triggerOversized()
			}

			logs := buf.String()
			oversizedWarns := strings.Count(logs, "exceeds max_event_bytes")
			bufferFullWarns := strings.Count(logs, "buffer full")

			assert.Equal(t, 1, oversizedWarns,
				"expected exactly one oversized-cause warn; got %d. logs=%s", oversizedWarns, logs)
			assert.Equal(t, 1, bufferFullWarns,
				"expected exactly one buffer-full-cause warn — pre-#692 this would be 0 because the shared limiter was already saturated by the other-cause burst. logs=%s",
				logs)
		})
	}
}
