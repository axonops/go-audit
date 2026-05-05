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
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/axonops/audit"
	"github.com/axonops/audit/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

// silenceSlog suppresses slog output during benchmarks so that
// auditor creation messages do not pollute benchmark output. The
// previous handler is restored via b.Cleanup.
func silenceSlog(b *testing.B) {
	b.Helper()
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	b.Cleanup(func() { slog.SetDefault(prev) })
}

func BenchmarkAudit(b *testing.B) {
	silenceSlog(b)
	out := testhelper.NewMockOutput("bench")
	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = auditor.Close() })

	fields := audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "my-topic",
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = auditor.AuditEvent(audit.NewEvent("schema_register", fields))
	}
}

func BenchmarkAuditDisabledCategory(b *testing.B) {
	silenceSlog(b)
	out := testhelper.NewMockOutput("bench")
	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = auditor.Close() })

	fields := audit.Fields{"outcome": "success"}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = auditor.AuditEvent(audit.NewEvent("schema_read", fields))
	}
}

func BenchmarkAuditDisabledAuditor(b *testing.B) {
	silenceSlog(b)
	auditor, err := audit.New(
		audit.WithDisabled(),
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
	)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = auditor.Close() })

	fields := audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = auditor.AuditEvent(audit.NewEvent("auth_failure", fields))
	}
}

// BenchmarkAudit_ViaHandle_vs_NewEvent quantifies the caller-side
// cost of EventHandle.Audit vs Auditor.AuditEvent(NewEvent(...)) on
// the same auditor, taxonomy, and fields. Both sub-benchmarks hit
// the drain slow path (defensive Fields copy; neither implements
// FieldsDonor); the only difference is that NewEvent allocates a
// *basicEvent that escapes through the Event interface return,
// whereas EventHandle.Audit calls auditInternalCtx directly without
// wrapping. The delta is one allocation per event. NoopOutput is
// used to exclude output-side defensive-copy noise and isolate the
// emission-path cost — see [internal/testhelper.NoopOutput]. #498.
func BenchmarkAudit_ViaHandle_vs_NewEvent(b *testing.B) {
	silenceSlog(b)
	out := testhelper.NewNoopOutput("bench")
	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(b, err)
	b.Cleanup(func() { _ = auditor.Close() })

	fields := audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "my-topic",
	}

	b.Run("NewEvent", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_ = auditor.AuditEvent(audit.NewEvent("schema_register", fields))
		}
	})

	b.Run("EventHandle", func(b *testing.B) {
		h := auditor.MustHandle("schema_register")
		b.ReportAllocs()
		for b.Loop() {
			_ = h.Audit(fields)
		}
	})
}

// ---------------------------------------------------------------------------
// Additional benchmarks — caller path
// ---------------------------------------------------------------------------

func BenchmarkAudit_RealisticFields(b *testing.B) {
	silenceSlog(b)
	taxonomy := &audit.Taxonomy{
		Version: 1,
		Categories: map[string]*audit.CategoryDef{
			"write": {Events: []string{"api_request"}},
		},
		Events: map[string]*audit.EventDef{
			"api_request": {
				Required: []string{"outcome", "actor_id", "method", "path"},
				Optional: []string{"subject", "schema_type", "version"},
			},
		},
	}
	out := testhelper.NewMockOutput("bench")
	auditor, err := audit.New(
		audit.WithTaxonomy(taxonomy),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = auditor.Close() })

	fields := audit.Fields{
		"outcome":     "success",
		"actor_id":    "alice",
		"method":      "POST",
		"path":        "/api/v1/schemas",
		"source_ip":   "10.0.0.1",
		"request_id":  "550e8400-e29b-41d4-a716-446655440000",
		"user_agent":  "audit-client/1.0",
		"subject":     "my-topic",
		"schema_type": "avro",
		"version":     1,
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = auditor.AuditEvent(audit.NewEvent("api_request", fields))
	}
}

func BenchmarkAudit_Parallel(b *testing.B) {
	silenceSlog(b)
	out := testhelper.NewMockOutput("bench")
	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = auditor.Close() })

	fields := audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "my-topic",
	}

	b.SetParallelism(100)
	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = auditor.AuditEvent(audit.NewEvent("schema_register", fields))
		}
	})
}

// BenchmarkAudit_PoolAmortised measures the Audit path under sustained
// load where the auditEntry pool is warm. Uses a large buffer and
// extended benchtime to demonstrate amortised pool benefit. The pool
// reduces GC pressure by reusing auditEntry structs rather than
// allocating and discarding them on every call.
func BenchmarkAudit_PoolAmortised(b *testing.B) {
	silenceSlog(b)
	out := testhelper.NewMockOutput("bench")
	auditor, err := audit.New(
		audit.WithQueueSize(100_000),
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = auditor.Close() })

	fields := audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "my-topic",
	}

	// Warm the pool with a few iterations before measuring.
	for range 1000 {
		_ = auditor.AuditEvent(audit.NewEvent("schema_register", fields))
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = auditor.AuditEvent(audit.NewEvent("schema_register", fields))
	}
}

// ---------------------------------------------------------------------------
// Fan-out benchmarks — multi-output scenarios
// ---------------------------------------------------------------------------

// BenchmarkAudit_FanOut_SharedFormatter measures fan-out to 3 outputs
// sharing the same default formatter. The formatCache should serialise
// once and deliver the same []byte to all three outputs.
func BenchmarkAudit_FanOut_SharedFormatter(b *testing.B) {
	silenceSlog(b)
	out1 := testhelper.NewMockOutput("out1")
	out2 := testhelper.NewMockOutput("out2")
	out3 := testhelper.NewMockOutput("out3")
	auditor, err := audit.New(
		audit.WithQueueSize(100_000),
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out1, out2, out3),
	)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = auditor.Close() })

	fields := audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "my-topic",
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = auditor.AuditEvent(audit.NewEvent("schema_register", fields))
	}
}

// BenchmarkAudit_FanOut_MixedFormatters measures fan-out to 3 outputs
// with 2 different formatters (JSON + CEF + JSON). The formatCache
// should serialise once per unique formatter (2 serialisations, not 3).
func BenchmarkAudit_FanOut_MixedFormatters(b *testing.B) {
	silenceSlog(b)
	out1 := testhelper.NewMockOutput("json1")
	out2 := testhelper.NewMockOutput("cef")
	out3 := testhelper.NewMockOutput("json2")
	cefFmt := &audit.CEFFormatter{Vendor: "V", Product: "P", Version: "1"}
	auditor, err := audit.New(
		audit.WithQueueSize(100_000),
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(out1),                                    // default JSON
		audit.WithNamedOutput(out2, audit.WithOutputFormatter(cefFmt)), // CEF
		audit.WithNamedOutput(out3),                                    // default JSON (shared)
	)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = auditor.Close() })

	fields := audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "my-topic",
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = auditor.AuditEvent(audit.NewEvent("schema_register", fields))
	}
}

// BenchmarkAudit_FanOut_FilteredOutputs measures fan-out to 3 outputs
// where one output filters the event via an include-category route.
// This exercises the per-output route matching + filtered-output
// metrics path.
func BenchmarkAudit_FanOut_FilteredOutputs(b *testing.B) {
	silenceSlog(b)
	out1 := testhelper.NewMockOutput("all")
	out2 := testhelper.NewMockOutput("write-only")
	out3 := testhelper.NewMockOutput("security-only")
	auditor, err := audit.New(
		audit.WithQueueSize(100_000),
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(out1), // receives all events
		audit.WithNamedOutput(out2, audit.WithRoute(&audit.EventRoute{
			IncludeCategories: []string{"write"},
		})), // receives only write events
		audit.WithNamedOutput(out3, audit.WithRoute(&audit.EventRoute{
			IncludeCategories: []string{"security"},
		})), // receives only security events — filters schema_register
	)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = auditor.Close() })

	fields := audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "my-topic",
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		// schema_register is "write" category — out1 and out2 receive it,
		// out3 filters it.
		_ = auditor.AuditEvent(audit.NewEvent("schema_register", fields))
	}
}

// BenchmarkAudit_FanOut_5Outputs measures fan-out to 5 outputs with
// the same formatter — tests scaling beyond the typical 1-3 output case.
func BenchmarkAudit_FanOut_5Outputs(b *testing.B) {
	silenceSlog(b)
	outputs := make([]audit.Output, 5)
	for i := range outputs {
		outputs[i] = testhelper.NewMockOutput("out" + string(rune('0'+i)))
	}
	auditor, err := audit.New(
		audit.WithQueueSize(100_000),
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(outputs...),
	)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = auditor.Close() })

	fields := audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "my-topic",
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = auditor.AuditEvent(audit.NewEvent("schema_register", fields))
	}
}

func TestDropLimiter_FirstDropAlwaysTriggers(t *testing.T) {
	t.Parallel()
	dl := &audit.DropLimiterForTest{}
	var triggered int
	dl.Record(10*time.Second, func(dropped int64) {
		triggered++
		assert.Equal(t, int64(1), dropped)
	})
	assert.Equal(t, 1, triggered, "first drop must trigger warning")
}

func TestDropLimiter_SubsequentDropsSuppressed(t *testing.T) {
	t.Parallel()
	dl := &audit.DropLimiterForTest{}
	var triggered int
	dl.Record(10*time.Second, func(_ int64) { triggered++ })
	// Second drop within interval should NOT trigger.
	dl.Record(10*time.Second, func(_ int64) { triggered++ })
	dl.Record(10*time.Second, func(_ int64) { triggered++ })
	assert.Equal(t, 1, triggered, "drops within interval must not trigger")
}

// TestDropLimiter_TotalConservedAcrossWindows guards the conservation
// invariant documented on dropLimiter.record: every Record call must
// be accounted for either in a warnFn callback or in the pending
// counter — no drop is ever uncounted, even under concurrent bursts
// that straddle a window boundary (#492).
//
// The test launches G goroutines each calling Record N times with a
// very short interval so multiple windows fire. It captures the
// sum of all warnFn-reported counts and adds the residual pending
// count; that total must equal G*N exactly.
func TestDropLimiter_TotalConservedAcrossWindows(t *testing.T) {
	t.Parallel()

	const (
		goroutines     = 64
		recordsPerG    = 2000
		windowInterval = 1 * time.Microsecond // fire many windows across the run
	)

	dl := &audit.DropLimiterForTest{}
	var reported atomic.Int64 // sum of all warnFn(dropped) values
	warn := func(dropped int64) { reported.Add(dropped) }

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			for range recordsPerG {
				dl.Record(windowInterval, warn)
			}
		}()
	}
	wg.Wait()

	pending := dl.PendingCount()
	total := reported.Load() + pending
	want := int64(goroutines * recordsPerG)
	assert.Equalf(t, want, total,
		"conservation violated: %d reported + %d pending != %d total records",
		reported.Load(), pending, want)
}

func TestLogger_DisableEvent_UncategorisedEvent(t *testing.T) {
	tax := &audit.Taxonomy{
		Version: 1,
		Categories: map[string]*audit.CategoryDef{
			"write": {Events: []string{"user_create"}},
		},
		Events: map[string]*audit.EventDef{
			"user_create":  {Required: []string{"outcome"}},
			"health_check": {Required: []string{"outcome"}}, // uncategorised
		},
	}

	out := testhelper.NewMockOutput("test")
	auditor, err := audit.New(
		audit.WithTaxonomy(tax),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)

	// health_check is uncategorised — always delivered by default.
	require.NoError(t, auditor.AuditEvent(audit.NewEvent("health_check", audit.Fields{"outcome": "ok"})))
	require.True(t, out.WaitForEvents(1, 2*time.Second))
	assert.Equal(t, 1, out.EventCount())

	// Disable it explicitly.
	require.NoError(t, auditor.DisableEvent("health_check"))
	require.NoError(t, auditor.AuditEvent(audit.NewEvent("health_check", audit.Fields{"outcome": "ok"})))

	// Close drains all pending events, guaranteeing processing is complete.
	require.NoError(t, auditor.Close())
	assert.Equal(t, 1, out.EventCount(), "disabled uncategorised event must not be delivered")
}

// BenchmarkAudit_EndToEnd measures the full Audit() path including
// enqueue with a large buffer. Events that overflow are silently
// dropped — the benchmark measures the amortised caller-side cost
// under sustained load. Drain-path (format + write) cost is measured
// separately by the formatter benchmarks.
func BenchmarkAudit_EndToEnd(b *testing.B) {
	silenceSlog(b)
	out := testhelper.NewMockOutput("bench")
	auditor, err := audit.New(
		audit.WithQueueSize(100_000),
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	if err != nil {
		b.Fatal(err)
	}

	fields := audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "my-topic",
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = auditor.AuditEvent(audit.NewEvent("schema_register", fields))
	}
	b.StopTimer()

	_ = auditor.Close()
}

func BenchmarkAudit_WithHMAC(b *testing.B) {
	silenceSlog(b)
	out := testhelper.NewMockOutput("bench")
	auditor, err := audit.New(
		audit.WithQueueSize(100_000),
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(out, audit.WithHMAC(&audit.HMACConfig{
			Enabled: true,
			Salt: audit.HMACSalt{
				Version: "v1",
				Value:   []byte("benchmark-salt-value-32-bytes!!!"),
			},
			Algorithm: "HMAC-SHA-256",
		})),
	)
	if err != nil {
		b.Fatal(err)
	}

	fields := audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "my-topic",
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = auditor.AuditEvent(audit.NewEvent("schema_register", fields))
	}
	b.StopTimer()

	_ = auditor.Close()
}

func BenchmarkStandardFieldDefaults_Applied(b *testing.B) {
	silenceSlog(b)
	out := testhelper.NewMockOutput("bench")
	auditor, err := audit.New(
		audit.WithQueueSize(100_000),
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(out),
		audit.WithStandardFieldDefaults(map[string]any{
			"source_ip":  "10.0.0.1",
			"actor_id":   "system",
			"request_id": "default-req",
		}),
	)
	if err != nil {
		b.Fatal(err)
	}

	fields := audit.Fields{
		"outcome": "success",
		"subject": "my-topic",
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = auditor.AuditEvent(audit.NewEvent("schema_register", fields))
	}
	b.StopTimer()

	_ = auditor.Close()
}

func BenchmarkDeliverToOutputs_WithMetadataWriter(b *testing.B) {
	silenceSlog(b)
	mock := &mockMetadataOutput{name: "bench-mw"}
	auditor, err := audit.New(
		audit.WithQueueSize(100_000),
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(mock),
	)
	if err != nil {
		b.Fatal(err)
	}

	fields := audit.Fields{"outcome": "success", "actor_id": "alice", "subject": "topic"}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = auditor.AuditEvent(audit.NewEvent("schema_register", fields))
	}
	b.StopTimer()
	_ = auditor.Close()
}

func BenchmarkDeliverToOutputs_MixedOutputs(b *testing.B) {
	silenceSlog(b)
	mwOut := &mockMetadataOutput{name: "bench-mw"}
	plainOut := testhelper.NewMockOutput("bench-plain")
	auditor, err := audit.New(
		audit.WithQueueSize(100_000),
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(mwOut),
		audit.WithNamedOutput(plainOut),
	)
	if err != nil {
		b.Fatal(err)
	}

	fields := audit.Fields{"outcome": "success", "actor_id": "alice", "subject": "topic"}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = auditor.AuditEvent(audit.NewEvent("schema_register", fields))
	}
	b.StopTimer()
	_ = auditor.Close()
}

// ---------------------------------------------------------------------------
// Async output simulation benchmarks (#455)
// ---------------------------------------------------------------------------

// mockAsyncOutput simulates the async Write pattern used by file and syslog
// outputs: data is copied, sent to a buffered channel, and discarded by a
// background goroutine. This faithfully reproduces the per-event cost of
// async outputs without requiring separate module dependencies or real I/O.
type mockAsyncOutput struct {
	ch     chan []byte
	done   chan struct{}
	name   string
	closed atomic.Bool
}

func newMockAsyncOutput(name string, bufSize int) *mockAsyncOutput {
	m := &mockAsyncOutput{
		ch:   make(chan []byte, bufSize),
		done: make(chan struct{}),
		name: name,
	}
	go m.drainLoop()
	return m
}

func (m *mockAsyncOutput) Write(data []byte) error {
	if m.closed.Load() {
		return audit.ErrOutputClosed
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	select {
	case m.ch <- cp:
	default:
		// drop
	}
	return nil
}

func (m *mockAsyncOutput) Close() error {
	if !m.closed.CompareAndSwap(false, true) {
		return nil
	}
	close(m.ch)
	<-m.done
	return nil
}

func (m *mockAsyncOutput) Name() string { return m.name }

func (m *mockAsyncOutput) drainLoop() {
	defer close(m.done)
	for data := range m.ch {
		_ = data // discard
	}
}

// BenchmarkProcessEntry_AsyncOutputs measures the full processEntry path
// (taxonomy lookup, JSON format, format cache, fan-out to 2 async outputs)
// using WithSynchronousDelivery to run processEntry inline. The async
// outputs simulate the copy+enqueue pattern of file and syslog outputs.
// This isolates drain-loop cost from caller-side validation.
func BenchmarkProcessEntry_AsyncOutputs(b *testing.B) {
	silenceSlog(b)
	fileOut := newMockAsyncOutput("async-file", 100_000)
	syslogOut := newMockAsyncOutput("async-syslog", 100_000)

	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(fileOut),
		audit.WithNamedOutput(syslogOut),
		audit.WithSynchronousDelivery(),
	)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = auditor.Close() })

	fields := audit.Fields{
		"outcome":    "success",
		"actor_id":   "alice",
		"subject":    "my-topic",
		"source_ip":  "10.0.0.1",
		"request_id": "550e8400-e29b-41d4-a716-446655440000",
	}

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		_ = auditor.AuditEvent(audit.NewEvent("schema_register", fields))
	}
}

// BenchmarkOutputClose_Drain measures how long Close() takes to drain
// N pending events from the async buffer through processEntry to outputs.
// This is a throughput benchmark for the drain goroutine under backlog.
func BenchmarkOutputClose_Drain(b *testing.B) {
	silenceSlog(b)

	for _, n := range []int{100, 1000, 10_000} {
		b.Run(fmt.Sprintf("events=%d", n), func(b *testing.B) {
			fields := audit.Fields{
				"outcome":  "success",
				"actor_id": "alice",
				"subject":  "my-topic",
			}

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				b.StopTimer()
				out := testhelper.NewMockOutput("bench-drain")
				auditor, err := audit.New(
					audit.WithQueueSize(n+1000), // room for all events
					audit.WithTaxonomy(testhelper.ValidTaxonomy()),
					audit.WithAppName("test-app"),
					audit.WithHost("test-host"),
					audit.WithOutputs(out),
				)
				if err != nil {
					b.Fatal(err)
				}

				// Enqueue N events. Some may be processed before Close,
				// but the benchmark measures the Close() drain path cost.
				for range n {
					_ = auditor.AuditEvent(audit.NewEvent("schema_register", fields))
				}

				b.StartTimer()
				_ = auditor.Close()
			}
		})
	}
}

func BenchmarkFilterCheck(b *testing.B) {
	silenceSlog(b)
	out := testhelper.NewMockOutput("bench")
	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = auditor.Close() })

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = audit.IsEnabledForTest(auditor, "schema_register")
	}
}

// BenchmarkFilterCheck_Parallel measures filter check throughput under
// heavy read contention. This is the scenario where sync.Map outperforms
// RWMutex — hundreds of concurrent readers avoid cache-line bouncing on
// the RWMutex reader counter.
func BenchmarkFilterCheck_Parallel(b *testing.B) {
	silenceSlog(b)
	out := testhelper.NewMockOutput("bench")
	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = auditor.Close() })

	b.SetParallelism(100)
	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = audit.IsEnabledForTest(auditor, "schema_register")
		}
	})
}

// BenchmarkFilterCheck_ReadWriteContention measures filter check
// throughput while a writer goroutine continuously toggles a category.
// This simulates the production scenario of runtime filter changes
// during sustained audit traffic.
func BenchmarkFilterCheck_ReadWriteContention(b *testing.B) {
	silenceSlog(b)
	out := testhelper.NewMockOutput("bench")
	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = auditor.Close() })

	// Background writer toggling a category throughout the benchmark.
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-done:
				return
			default:
				_ = auditor.DisableCategory("read")
				_ = auditor.EnableCategory("read")
			}
		}
	}()
	b.Cleanup(func() { close(done) })

	b.SetParallelism(100)
	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = audit.IsEnabledForTest(auditor, "schema_register")
		}
	})
}
