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

// Tests for the per-cause dropLimiter split (#692). The loki Output
// formerly shared a single `drops` rate-limiter between the
// oversized-event-rejected path (#688) and the buffer-full path. A
// burst of one cause silenced the other in the same dropWarnInterval
// window. After #692 each cause has its own limiter; this test
// verifies the silos are independent **in both directions** —
// neither the oversized burst nor the buffer-full burst should
// silence the other, regardless of which arrives first.

package loki_test

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/audit/loki"
)

// TestDropLimiter_OversizedAndBufferFullSilosAreIndependent_Loki
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
func TestDropLimiter_OversizedAndBufferFullSilosAreIndependent_Loki(t *testing.T) {
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

			// Stall the server so the batch goroutine cannot empty
			// the internal channel. Once the goroutine takes events
			// and blocks on POST, subsequent writes accumulate in
			// the buffer; further writes hit the default branch
			// and the buffer-full path fires.
			serverHold := make(chan struct{})
			srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
				<-serverHold
			}))
			t.Cleanup(srv.Close)

			buf := &lokiSyncBuf{}
			logger := slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

			const maxBytes = loki.MinMaxEventBytes // 1 KiB
			const bufferSize = loki.MinBufferSize  // 100 (loki minimum)
			out, err := loki.New(&loki.Config{
				URL:                srv.URL + "/loki/api/v1/push",
				MaxEventBytes:      maxBytes,
				BufferSize:         bufferSize,
				BatchSize:          1,
				FlushInterval:      100 * time.Millisecond,
				AllowInsecureHTTP:  true,
				AllowPrivateRanges: true,
			}, nil, loki.WithDiagnosticLogger(logger))
			require.NoError(t, err)
			t.Cleanup(func() { _ = out.Close() })
			// Registered AFTER the constructor so it runs BEFORE
			// out.Close (t.Cleanup is LIFO). Closing serverHold
			// unblocks the stalled HTTP handler so out.Close can
			// drain in finite time.
			t.Cleanup(func() { close(serverHold) })

			oversized := bytes.Repeat([]byte("X"), maxBytes+1)
			triggerOversized := func() {
				for range 5 {
					_ = out.Write(oversized)
				}
			}
			triggerBufferFull := func() {
				// 4× the buffer size guarantees at least one write
				// hits the default branch with the server stalled.
				for range bufferSize * 4 {
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
