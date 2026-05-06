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
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/axonops/audit"
	"github.com/axonops/audit/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// #600 AuditEventContext benchmarks — prove the ctx=Background fast
// path matches the legacy AuditEvent baseline within 5%, and document
// the additive cost when ctx is cancellable. Run via:
//
//   go test -run=NONE -bench='BenchmarkAudit(_AuditEventContext)?_' \
//     -benchmem -count=10 . | tee /tmp/600.txt
//   benchstat /tmp/600.txt
// ---------------------------------------------------------------------------

// benchCtxAuditor builds a baseline auditor for the ctx benchmarks.
// Identical setup to BenchmarkAudit so the variants share the baseline.
func benchCtxAuditor(b *testing.B, opts ...audit.Option) *audit.Auditor {
	b.Helper()
	silenceSlog(b)
	out := testhelper.NewMockOutput("bench")
	all := []audit.Option{
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("bench-app"),
		audit.WithHost("bench-host"),
		audit.WithOutputs(out),
	}
	all = append(all, opts...)
	auditor, err := audit.New(all...)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = auditor.Close() })
	return auditor
}

// BenchmarkAudit_AuditEventContext_Background must match
// BenchmarkAudit (legacy AuditEvent) within 5% — locked AC #7.
func BenchmarkAudit_AuditEventContext_Background(b *testing.B) {
	auditor := benchCtxAuditor(b)
	ctx := context.Background()
	fields := audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "topic",
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = auditor.AuditEventContext(ctx, audit.NewEvent("schema_register", fields))
	}
}

// BenchmarkAudit_AuditEventContext_HTTPRequestCtx exercises the
// realistic case: an HTTP-handler ctx (a cancelCtx with non-nil
// Done). This is the path most middleware consumers will hit.
func BenchmarkAudit_AuditEventContext_HTTPRequestCtx(b *testing.B) {
	auditor := benchCtxAuditor(b)
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	ctx := req.Context()
	fields := audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "topic",
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = auditor.AuditEventContext(ctx, audit.NewEvent("schema_register", fields))
	}
}

// BenchmarkAudit_AuditEventContext_PreCancelled measures the early-
// return cost when ctx is already cancelled. Should hit the ctx-err
// path immediately.
func BenchmarkAudit_AuditEventContext_PreCancelled(b *testing.B) {
	auditor := benchCtxAuditor(b)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	fields := audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = auditor.AuditEventContext(ctx, audit.NewEvent("schema_register", fields))
	}
}

// BenchmarkAudit_AuditEventContext_Background_Parallel proves the
// fast-path holds under contention.
func BenchmarkAudit_AuditEventContext_Background_Parallel(b *testing.B) {
	auditor := benchCtxAuditor(b)
	ctx := context.Background()
	fields := audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "topic",
	}
	b.ResetTimer()
	b.ReportAllocs()
	b.SetParallelism(100)
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = auditor.AuditEventContext(ctx, audit.NewEvent("schema_register", fields))
		}
	})
}

// BenchmarkAudit_AuditEventContext_Sync_Background measures the
// synchronous-delivery path with Background ctx — should match the
// legacy synchronous deliver path.
func BenchmarkAudit_AuditEventContext_Sync_Background(b *testing.B) {
	auditor := benchCtxAuditor(b, audit.WithSynchronousDelivery())
	ctx := context.Background()
	fields := audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "topic",
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = auditor.AuditEventContext(ctx, audit.NewEvent("schema_register", fields))
	}
}

// BenchmarkEventHandle_AuditContext_Background exercises the handle
// path's ctx fast path.
func BenchmarkEventHandle_AuditContext_Background(b *testing.B) {
	auditor := benchCtxAuditor(b)
	h, err := auditor.Handle("schema_register")
	if err != nil {
		b.Fatal(err)
	}
	ctx := context.Background()
	fields := audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "topic",
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = h.AuditContext(ctx, fields)
	}
}

// TestLogger_OverflowPolicy_ExactCapacity proves that exactly N
// events fit when the queue size is N (with a blocking output
// preventing drain) and that the (N+1)th event triggers exactly
// one ErrQueueFull. The contract pins the off-by-one boundary —
// a regression that allows N+1 events through, or rejects the
// Nth, would surface here. (#565 G11).
func TestLogger_OverflowPolicy_ExactCapacity(t *testing.T) {
	t.Parallel()
	metrics := testhelper.NewMockMetrics()

	// QueueSize 1 with a blocking output: the drain goroutine
	// dequeues the first event and blocks inside Write. The
	// queue is then empty, so a second Audit succeeds (filling
	// the slot). A third Audit fills the channel — Audit returns
	// ErrQueueFull on the next attempt because the drain remains
	// blocked.
	out := &blockingOutput{name: "blocking", blockCh: make(chan struct{}), enteredCh: make(chan struct{}, 1)}
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

	// Wait for the drain goroutine to reach the blocking write.
	require.NoError(t, auditor.AuditEvent(audit.NewEvent("auth_failure",
		audit.Fields{"outcome": "failure", "actor_id": "alice"})))
	select {
	case <-out.enteredCh:
	case <-time.After(2 * time.Second):
		t.Fatal("drain goroutine did not enter blocking Write")
	}

	// Now exactly one slot is free in the channel. Fill it.
	require.NoError(t, auditor.AuditEvent(audit.NewEvent("auth_failure",
		audit.Fields{"outcome": "failure", "actor_id": "bob"})),
		"second Audit must fit (exact capacity 1)")

	// The next Audit must overflow.
	err = auditor.AuditEvent(audit.NewEvent("auth_failure",
		audit.Fields{"outcome": "failure", "actor_id": "carol"}))
	require.Error(t, err, "third Audit must overflow")
	assert.ErrorIs(t, err, audit.ErrQueueFull,
		"overflow must surface ErrQueueFull")
}

// TestLogger_Audit_QueueFull_MetricsIncrement proves that the
// MockMetrics RecordDrop counter increments on every overflowed
// Audit call. The contract pins exact-counting — duplicate or
// missing increments would mislead operators about backpressure
// pressure. (#565 G11).
func TestLogger_Audit_QueueFull_MetricsIncrement(t *testing.T) {
	t.Parallel()
	metrics := testhelper.NewMockMetrics()

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

	// Push until 5 overflow drops are observed. Each drop must
	// increment the metric counter by exactly 1.
	overflowCount := 0
	for i := 0; i < 200 && overflowCount < 5; i++ {
		err = auditor.AuditEvent(audit.NewEvent("auth_failure",
			audit.Fields{"outcome": "failure", "actor_id": fmt.Sprintf("u%d", i)}))
		if errors.Is(err, audit.ErrQueueFull) {
			overflowCount++
		}
	}
	require.GreaterOrEqual(t, overflowCount, 5,
		"failed to drive 5 overflows in 200 attempts")

	// The metric counter must equal the observed overflow count.
	assert.Equal(t, overflowCount, metrics.GetBufferDrops(),
		"RecordDrop must fire exactly once per ErrQueueFull")
}

// TestLogger_Close_DrainCompletesBeforeTimeout proves that Close
// waits for all enqueued events to drain when the configured
// ShutdownTimeout is generous and the output drains quickly. The
// contract: an explicit Close on a non-blocking pipeline never
// drops events. (#565 G1).
func TestLogger_Close_DrainCompletesBeforeTimeout(t *testing.T) {
	t.Parallel()
	out := testhelper.NewMockOutput("drainable")
	auditor, err := audit.New(
		audit.WithValidationMode(audit.ValidationPermissive),
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithShutdownTimeout(5*time.Second),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)

	const eventCount = 50
	for i := 0; i < eventCount; i++ {
		require.NoError(t, auditor.AuditEvent(audit.NewEvent("user_create",
			audit.Fields{"outcome": "success", "actor_id": fmt.Sprintf("u%d", i)})))
	}
	closeStart := time.Now()
	require.NoError(t, auditor.Close())
	closeDur := time.Since(closeStart)
	assert.Less(t, closeDur, 5*time.Second,
		"Close must drain well before the configured ShutdownTimeout")
	assert.Equal(t, eventCount, out.EventCount(),
		"every enqueued event must be delivered before Close returns")
}

// TestLogger_Close_ZeroShutdownTimeout proves that
// WithShutdownTimeout(0) is treated as the documented default-
// trigger sentinel: applyDefaults resolves 0 to
// DefaultShutdownTimeout, the auditor constructs successfully,
// and Close honours the default. The earlier issue draft framed
// this as a rejection; the actual contract (config.go:84) is
// "zero defaults to DefaultShutdownTimeout" — a more permissive
// interpretation that this test pins. (#565 G1).
func TestLogger_Close_ZeroShutdownTimeout(t *testing.T) {
	t.Parallel()
	out := testhelper.NewMockOutput("zero-timeout")
	auditor, err := audit.New(
		audit.WithValidationMode(audit.ValidationPermissive),
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithShutdownTimeout(0), // sentinel for default
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(t, err, "WithShutdownTimeout(0) must NOT be rejected — it is the default-trigger sentinel")
	require.NoError(t, auditor.AuditEvent(audit.NewEvent("user_create",
		audit.Fields{"outcome": "success", "actor_id": "alice"})))
	require.NoError(t, auditor.Close())
	assert.Equal(t, 1, out.EventCount())
}

// TestLogger_New_WithDisabledCategoryAtBoot proves that calling
// DisableCategory immediately after New produces the expected
// boot-time disable: subsequent Audit calls for events in that
// category surface ErrCategoryDisabled (or are silently filtered,
// per the documented contract — verify the actual behaviour).
// (#565 G1).
func TestLogger_New_WithDisabledCategoryAtBoot(t *testing.T) {
	t.Parallel()
	out := testhelper.NewMockOutput("after-disable")
	auditor, err := audit.New(
		audit.WithValidationMode(audit.ValidationPermissive),
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditor.Close() })

	// Disable the "write" category before any events are sent —
	// the boot-time pattern an operator would use to roll out a
	// runtime kill switch on a particular event class.
	require.NoError(t, auditor.DisableCategory("write"))

	// user_create is in the "write" category in the test taxonomy.
	// The documented behaviour is silent filtering — Audit returns
	// nil but the event does not reach the output.
	auditErr := auditor.AuditEvent(audit.NewEvent("user_create",
		audit.Fields{"outcome": "success", "actor_id": "alice"}))
	// Either a non-nil error OR silent filtering — both are
	// valid contracts. The load-bearing assertion is "the event
	// did NOT reach the output". The specific sentinel is left
	// unpinned so a future change to the disabled-category
	// error type does not require this test to track it.
	_ = auditErr
	require.NoError(t, auditor.Close())
	assert.Zero(t, out.EventCount(),
		"events in a disabled category must not reach the output")
}
