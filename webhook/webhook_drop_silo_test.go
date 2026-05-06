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

// Tests for the per-cause dropLimiter split (#692). The webhook Output
// formerly shared a single `drops` rate-limiter between the
// oversized-event-rejected path (#688) and the buffer-full path. A
// burst of one cause silenced the other in the same dropWarnInterval
// window. After #692 each cause has its own limiter; this test
// verifies the silos are independent **in both directions** — neither
// the oversized burst nor the buffer-full burst should silence the
// other, regardless of which arrives first.

package webhook_test

import (
	"bytes"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/axonops/audit/webhook"
)

// TestDropLimiter_OversizedAndBufferFullSilosAreIndependent_Webhook
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
func TestDropLimiter_OversizedAndBufferFullSilosAreIndependent_Webhook(t *testing.T) {
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

			// Stall the server so the drain goroutine cannot empty
			// the internal channel. Once the goroutine takes the
			// first event and blocks on POST, subsequent writes
			// accumulate in the 1-slot buffer; further writes hit
			// the default branch and the buffer-full path fires.
			serverHold := make(chan struct{})
			srv := newWebhookTestServer(t, func(_ http.ResponseWriter, _ *http.Request) {
				<-serverHold
			})

			buf := &webhookSyncBuf{}
			logger := slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

			const maxBytes = webhook.MinMaxEventBytes // 1 KiB
			out := newTestWebhookOutputWithOpts(t, srv.url(),
				[]func(*webhook.Config){func(cfg *webhook.Config) {
					cfg.MaxEventBytes = maxBytes
					cfg.BufferSize = 1
					cfg.BatchSize = 1
					cfg.FlushInterval = 5 * time.Millisecond
					cfg.MaxRetries = 0
				}},
				[]webhook.Option{webhook.WithDiagnosticLogger(logger)},
			)
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
				for range 50 {
					_ = out.Write([]byte("ok"))
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
