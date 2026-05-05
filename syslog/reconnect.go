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
	"crypto/rand"
	"log/slog"
	"math"
	"time"
)

// closeWriterForReconnect closes the previous syslog writer before a
// reconnect attempt. A Close error here is informational only —
// handleWriteFailure immediately establishes a fresh transport via
// connect(), so there is no recoverable action the caller can take
// if Close fails (for example, the remote closed the TCP
// half-connection or a TLS teardown errored). The error is logged at
// debug level so operators can still observe the cause when a
// subsequent connect keeps failing; it is deliberately not promoted
// to warn/error and does not abort the reconnect path (#489).
//
// Kept as a package-level function (not a method on [*Output]) and
// taking the Close closure explicitly so unit tests can drive the
// error path without needing an interface seam on Output.writer —
// which is a concrete *srslog.Writer.
func closeWriterForReconnect(closeFn func() error, logger *slog.Logger, address string) {
	closeErr := closeFn()
	if closeErr == nil {
		return
	}
	if logger == nil {
		logger = slog.Default()
	}
	logger.Debug("audit: output syslog: close before reconnect failed",
		"address", address,
		"error", closeErr)
}

// backoffDuration returns the backoff duration for the given attempt
// number using bounded exponential backoff with jitter
// (100ms * 2^(attempt-1) * [0.5, 1.0], capped at 30s). Jitter prevents
// thundering herd when multiple clients reconnect simultaneously.
//
// The exponent uses attempt-1 because s.failures is pre-incremented
// before this call, so attempt=1 yields the initial 100ms base delay.
//
// SYNC: similar implementations in webhook/http.go (webhookBackoff)
// and loki/http.go (lokiBackoff). Syslog uses a 30s cap (persistent
// TCP reconnection) vs 5s for HTTP outputs. The helper is unexported
// and cannot be shared across Go modules. Keep the three copies in
// sync when making changes (#542).
func backoffDuration(attempt int) time.Duration {
	exp := math.Min(float64(attempt-1), 20) // clamp exponent to avoid overflow
	d := syslogBaseBackoff * time.Duration(math.Pow(2, exp))
	if d > syslogMaxBackoff {
		d = syslogMaxBackoff
	}
	// Add jitter: multiply by [0.5, 1.0) using crypto/rand.
	var b [1]byte
	if _, err := rand.Read(b[:]); err == nil {
		jitter := 0.5 + float64(b[0])/512.0 // [0.5, 1.0)
		d = time.Duration(float64(d) * jitter)
	}
	return d
}
