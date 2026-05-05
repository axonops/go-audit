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

package audit_test

// Split out of audit_test.go (#540).

import (
	"errors"
	"testing"
	"time"

	"github.com/axonops/audit"
	"github.com/axonops/audit/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Buffer and shutdown tests
// ---------------------------------------------------------------------------

func TestLogger_Audit_EventDelivered(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	auditor := newTestAuditor(t, out)

	err := auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
	}))
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))
	assert.Equal(t, 1, out.EventCount())
}

func TestLogger_Audit_BufferFull(t *testing.T) {

	metrics := testhelper.NewMockMetrics()

	// Tiny buffer + blocking output to force buffer full.
	out := &blockingOutput{name: "blocking", blockCh: make(chan struct{})}
	t.Cleanup(func() { close(out.blockCh) })

	auditor, err := audit.New(
		audit.WithQueueSize(1),
		audit.WithShutdownTimeout(50*time.Millisecond),
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
		audit.WithMetrics(metrics),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditor.Close() })

	// Fill the buffer (1 slot) + drain goroutine may take one.
	// Send enough to guarantee overflow.
	var bufferFullSeen bool
	for i := 0; i < 100; i++ {
		err = auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
			"outcome":  "failure",
			"actor_id": "bob",
		}))
		if errors.Is(err, audit.ErrQueueFull) {
			bufferFullSeen = true
		}
	}

	assert.True(t, bufferFullSeen, "should have seen ErrQueueFull")
	assert.Greater(t, metrics.GetBufferDrops(), 0, "should have recorded buffer drops")
}

// blockingOutput blocks on Write until blockCh is closed.
// enteredCh is signalled (once) when Write is first entered, allowing
// tests to synchronise on the drain goroutine reaching the blocking point.
type blockingOutput struct {
	blockCh   chan struct{}
	enteredCh chan struct{}
	name      string
}

func (b *blockingOutput) Write(_ []byte) error {
	if b.enteredCh != nil {
		select {
		case b.enteredCh <- struct{}{}:
		default:
		}
	}
	<-b.blockCh
	return nil
}
func (b *blockingOutput) Close() error { return nil }
func (b *blockingOutput) Name() string { return b.name }

func TestLogger_Close_DrainsEvents(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)

	// Send several events.
	for i := 0; i < 10; i++ {
		err := auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
			"outcome":  "failure",
			"actor_id": "bob",
		}))
		require.NoError(t, err)
	}

	// Close should drain all.
	require.NoError(t, auditor.Close())
	assert.Equal(t, 10, out.EventCount(), "Close should drain all pending events")
}

func TestLogger_Close_Idempotent(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)

	require.NoError(t, auditor.Close())
	require.NoError(t, auditor.Close()) // second call: no error.
}

func TestLogger_Audit_AfterClose(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)
	require.NoError(t, auditor.Close())

	err = auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
	}))
	assert.ErrorIs(t, err, audit.ErrClosed)
}

func TestLogger_Close_ShutdownTimeout(t *testing.T) {

	// Use a blocking output that never unblocks combined with a very
	// short drain timeout. Close should return within a bounded time
	// rather than hanging.
	out := &blockingOutput{name: "stuck", blockCh: make(chan struct{})}
	t.Cleanup(func() { close(out.blockCh) })

	auditor, err := audit.New(
		audit.WithQueueSize(10),
		audit.WithShutdownTimeout(10*time.Millisecond),
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)

	// Enqueue an event so the drain goroutine has work to do.
	_ = auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
	}))

	start := time.Now()
	_ = auditor.Close()
	elapsed := time.Since(start)

	// Close should complete quickly (within 1s), not hang for the
	// default 5s drain timeout.
	assert.Less(t, elapsed, 1*time.Second, "Close should respect short ShutdownTimeout")
}

func TestLogger_Close_OutputError(t *testing.T) {

	out := &errorOutput{name: "bad", closeErr: errors.New("close failed")}
	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)

	err = auditor.Close()
	require.Error(t, err)
	// text-only: the underlying error is errorOutput.closeErr (a test-
	// injected errors.New), so there is no library sentinel to assert
	// against here. The contract is that Close surfaces the wrapped
	// underlying error verbatim and prefixes it with the output name.
	assert.Contains(t, err.Error(), "close failed")
	assert.Contains(t, err.Error(), "bad", "error should include output name")
}

type errorOutput struct {
	closeErr error
	name     string
}

func (e *errorOutput) Write(_ []byte) error { return nil }
func (e *errorOutput) Close() error         { return e.closeErr }
func (e *errorOutput) Name() string         { return e.name }

func TestLogger_Close_MultipleOutputErrors(t *testing.T) {
	errAlpha := errors.New("alpha broke")
	errBeta := errors.New("beta broke")

	outA := &errorOutput{name: "alpha", closeErr: errAlpha}
	outB := &errorOutput{name: "beta", closeErr: errBeta}
	outC := &errorOutput{name: "gamma"} // succeeds

	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(outA, outB, outC),
	)
	require.NoError(t, err)

	err = auditor.Close()
	require.Error(t, err)

	// Both failures are reported via errors.Join.
	assert.ErrorIs(t, err, errAlpha)
	assert.ErrorIs(t, err, errBeta)
	assert.Contains(t, err.Error(), "alpha")
	assert.Contains(t, err.Error(), "beta")
	// Successful output does not appear in the error.
	assert.NotContains(t, err.Error(), "gamma")
}

func TestLogger_Close_AllOutputsCloseCalledOnError(t *testing.T) {
	// Verify output B's Close() is called even when output A's Close() fails.
	outA := &errorOutput{name: "fail-first", closeErr: errors.New("first fail")}
	outB := testhelper.NewMockOutput("second")

	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(outA, outB),
	)
	require.NoError(t, err)

	_ = auditor.Close()
	assert.True(t, outB.IsClosed(), "output B's Close() must be called even when A fails")
}
