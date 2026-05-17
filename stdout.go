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

package audit

import (
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// StdoutFactory returns an [OutputFactory] that creates a
// [StdoutOutput] writing to [os.Stdout]. Register it with
// [RegisterOutputFactory] to enable the YAML `type: stdout` form:
//
//	audit.RegisterOutputFactory("stdout", audit.StdoutFactory())
//
// Blank-importing the [github.com/axonops/audit/outputs] convenience
// package registers this factory for you alongside file/syslog/
// webhook/loki. Prior to #578 the registration happened automatically
// via an init() in this package; that was dropped to eliminate hidden
// global mutation at import time.
func StdoutFactory() OutputFactory {
	return func(name string, rawConfig []byte, _ FrameworkContext) (Output, error) {
		if len(rawConfig) > 0 {
			return nil, fmt.Errorf("audit: stdout output %q: stdout does not accept configuration: %w", name, ErrConfigInvalid)
		}
		out, err := NewStdoutOutput(StdoutConfig{})
		if err != nil {
			return nil, err
		}
		return WrapOutput(out, name), nil
	}
}

// StdoutConfig holds configuration for [StdoutOutput].
type StdoutConfig struct {
	// Writer is the destination for audit events. When nil, [os.Stdout]
	// is used. The writer does not need to be safe for concurrent use;
	// StdoutOutput serialises writes internally.
	Writer io.Writer
}

// StdoutOutput writes serialised audit events to an [io.Writer],
// defaulting to [os.Stdout]. It is intended for development and
// debugging; production deployments SHOULD use [FileOutput] or
// another persistent output. The underlying writer can be
// [os.Stdout], [os.Stderr], or any [io.Writer] supplied via
// [StdoutConfig] or the convenience constructors [NewStdout],
// [NewStderr], [NewWriter].
//
// StdoutOutput does NOT close the underlying writer on [Close]
// because the writer is typically [os.Stdout], which must not be
// closed.
//
// StdoutOutput is safe for concurrent use.
type StdoutOutput struct {
	writer io.Writer
	// lastDeliveryNanos is the wall-clock UnixNano of the most recent
	// successful Write. Stdout is synchronous — Write success equals
	// delivery success — so the timestamp updates inside Write before
	// returning nil. Powers [Auditor.LastDeliveryAge] (#753).
	lastDeliveryNanos atomic.Int64
	mu                sync.Mutex
	closed            bool
}

// NewStdout returns a [StdoutOutput] that writes to [os.Stdout].
// Shorthand for NewStdoutOutput(StdoutConfig{}). Non-panicking
// replacement for the pre-#578 Stdout() helper.
func NewStdout() (*StdoutOutput, error) {
	return NewStdoutOutput(StdoutConfig{})
}

// NewStderr returns a [StdoutOutput] that writes to [os.Stderr].
// Useful when audit events must be visible on stderr (e.g., when
// stdout is reserved for primary application output).
func NewStderr() (*StdoutOutput, error) {
	return NewStdoutOutput(StdoutConfig{Writer: os.Stderr})
}

// NewWriter returns a [StdoutOutput] that writes to the given
// [io.Writer]. Useful for capturing audit events in a
// [bytes.Buffer] for tests, or for routing to any other
// destination that satisfies [io.Writer]. Passing nil causes the
// output to write to [os.Stdout].
func NewWriter(w io.Writer) (*StdoutOutput, error) {
	return NewStdoutOutput(StdoutConfig{Writer: w})
}

// NewStdoutOutput creates a new [StdoutOutput] from the given config.
// If [StdoutConfig.Writer] is nil, [os.Stdout] is used. Prefer the
// convenience constructors [NewStdout], [NewStderr], [NewWriter]
// unless you need the [StdoutConfig] struct for some reason.
func NewStdoutOutput(cfg StdoutConfig) (*StdoutOutput, error) {
	w := cfg.Writer
	if w == nil {
		w = os.Stdout
	}
	return &StdoutOutput{writer: w}, nil
}

// Write sends a serialised audit event to the underlying writer.
// Write returns [ErrOutputClosed] if the output has been closed.
// Write is safe for concurrent use.
func (s *StdoutOutput) Write(data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrOutputClosed
	}
	if _, err := s.writer.Write(data); err != nil {
		return fmt.Errorf("audit: stdout output write: %w", err)
	}
	// Synchronous output: Write success == delivery success (#753).
	s.lastDeliveryNanos.Store(time.Now().UnixNano())
	return nil
}

// LastDeliveryNanos returns the wall-clock UnixNano of the most
// recent successful [StdoutOutput.Write], or 0 if no write has yet
// succeeded. Implements [LastDeliveryReporter] (#753).
//
// The Load is intentionally lock-free even though [StdoutOutput.Write]
// stores while holding s.mu — atomic.Int64 provides the
// happens-before relationship; the mutex on the Write side is for
// the closed-flag check and the underlying writer call, not for
// the timestamp.
func (s *StdoutOutput) LastDeliveryNanos() int64 {
	return s.lastDeliveryNanos.Load()
}

// Close marks the output as closed. Subsequent calls to [Write] return
// [ErrOutputClosed]. Close does NOT close the underlying writer. Close
// is idempotent and safe for concurrent use with [StdoutOutput.Write].
func (s *StdoutOutput) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

// Name returns the human-readable identifier for this output.
func (s *StdoutOutput) Name() string {
	return "stdout"
}
