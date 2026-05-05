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
	"testing"

	"github.com/axonops/audit"
	"github.com/axonops/audit/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Fast-path / slow-path contract tests and benchmarks (#497)
// ---------------------------------------------------------------------------

// TestAudit_NewEvent_StillDefensiveCopies pins the slow-path contract:
// a caller that mutates the audit.Fields map AFTER AuditEvent returns
// MUST NOT see those mutations in the delivered payload. This is the
// core reason the slow path exists; the donor fast path (see
// FieldsDonor) explicitly opts out of this guarantee.
//
// Regression test for #497 AC 6. Breakage of this contract would be
// silent in production — a consumer reusing a Fields literal across
// calls would get their stale values delivered.
func TestAudit_NewEvent_StillDefensiveCopies(t *testing.T) {
	t.Parallel()

	tax := &audit.Taxonomy{
		Version: 1,
		Categories: map[string]*audit.CategoryDef{
			"write": {Events: []string{"user_create"}},
		},
		Events: map[string]*audit.EventDef{
			"user_create": {
				Required: []string{"outcome", "actor_id"},
				Optional: []string{"marker"},
			},
		},
	}
	out := testhelper.NewMockOutput("copy")
	auditor, err := audit.New(
		audit.WithTaxonomy(tax),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
		audit.WithSynchronousDelivery(),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditor.Close() })

	caller := audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"marker":   "before",
	}
	require.NoError(t, auditor.AuditEvent(audit.NewEvent("user_create", caller)))

	// Mutate the caller's map AFTER AuditEvent returns. The pipeline
	// must have copied — its delivered event must still carry the
	// pre-mutation values.
	caller["marker"] = "after"
	caller["actor_id"] = "bob"
	caller["outcome"] = "failure"

	require.Equal(t, 1, out.EventCount())
	ev := out.GetEvent(0)
	assert.Equal(t, "before", ev["marker"],
		"NewEvent slow path must defensively copy — caller mutation must not leak")
	assert.Equal(t, "alice", ev["actor_id"],
		"NewEvent slow path must defensively copy — caller mutation must not leak")
	assert.Equal(t, "success", ev["outcome"],
		"NewEvent slow path must defensively copy — caller mutation must not leak")
}

// newFastPathBenchAuditor builds an auditor wired to a NoopOutput so
// pipeline benchmarks measure ONLY the audit path — no MockOutput
// copy, no mutex contention, just AuditEvent → drain → format →
// Write(noop). Shared by the BenchmarkAudit_FastPath_* family (#497).
func newFastPathBenchAuditor(tb testing.TB, opts ...audit.Option) (*audit.Auditor, *testhelper.NoopOutput) {
	tb.Helper()
	tax := &audit.Taxonomy{
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
	out := testhelper.NewNoopOutput("noop")
	base := []audit.Option{
		audit.WithQueueSize(100_000),
		audit.WithTaxonomy(tax),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	}
	auditor, err := audit.New(append(base, opts...)...)
	if err != nil {
		tb.Fatal(err)
	}
	return auditor, out
}

// BenchmarkAudit_FastPath_PipelineOnly measures the pure pipeline
// cost: the event is constructed once outside the loop and re-used,
// isolating the drain → format → in-place post-field → Write(noop)
// path from caller-side allocation. Target: 0 allocs/op post-W2.
//
// Production callers MUST NOT re-use a builder — generated builders
// are single-use per AuditEvent. This benchmark deliberately violates
// that to isolate pipeline cost. See docs/performance.md.
func BenchmarkAudit_FastPath_PipelineOnly(b *testing.B) {
	silenceSlog(b)
	auditor, _ := newFastPathBenchAuditor(b)
	b.Cleanup(func() { _ = auditor.Close() })

	// FieldsDonor donor (test shim; mirrors cmd/audit-gen output) to
	// exercise the true zero-alloc fast path.
	evt := audit.NewFieldsDonorForTest("api_request", audit.Fields{
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
	})

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = auditor.AuditEvent(evt)
	}
}

// BenchmarkAudit_FastPath_EndToEnd measures the realistic per-call
// cost: event constructed inside the loop (the production pattern).
// Allocs include the caller-side Fields literal + value-boxing, which
// is the cost #660 (v1.1) addresses via typed-field builders. This
// pins the state where W2 has reached its limit without breaking
// format-neutrality.
func BenchmarkAudit_FastPath_EndToEnd(b *testing.B) {
	silenceSlog(b)
	auditor, _ := newFastPathBenchAuditor(b)
	b.Cleanup(func() { _ = auditor.Close() })

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = auditor.AuditEvent(audit.NewEvent("api_request", audit.Fields{
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
		}))
	}
}

// BenchmarkAudit_FastPath_Parallel exercises the pipeline under
// concurrency. Catches lock-contention regressions that single-
// goroutine benchmarks cannot see. ns/op MUST NOT scale linearly with
// GOMAXPROCS — sub-linear is acceptable, super-linear indicates
// shared-state contention that needs investigation.
func BenchmarkAudit_FastPath_Parallel(b *testing.B) {
	silenceSlog(b)
	auditor, _ := newFastPathBenchAuditor(b)
	b.Cleanup(func() { _ = auditor.Close() })

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = auditor.AuditEvent(audit.NewEvent("api_request", audit.Fields{
				"outcome":  "success",
				"actor_id": "alice",
				"method":   "POST",
				"path":     "/api/v1/schemas",
			}))
		}
	})
}

// BenchmarkAudit_FastPath_FanOut4_NoopOutputs measures the cost of
// fanning out one event to 4 NoopOutputs sharing the same formatter.
// The format cache should hit for outputs 2-4, so the per-output
// marginal cost is the post-field assembly + write(noop) only.
// Post-W2 target: 0 allocs/op.
func BenchmarkAudit_FastPath_FanOut4_NoopOutputs(b *testing.B) {
	silenceSlog(b)
	tax := &audit.Taxonomy{
		Version: 1,
		Categories: map[string]*audit.CategoryDef{
			"write": {Events: []string{"api_request"}},
		},
		Events: map[string]*audit.EventDef{
			"api_request": {Required: []string{"outcome", "actor_id", "method", "path"}},
		},
	}
	out1 := testhelper.NewNoopOutput("noop1")
	out2 := testhelper.NewNoopOutput("noop2")
	out3 := testhelper.NewNoopOutput("noop3")
	out4 := testhelper.NewNoopOutput("noop4")
	auditor, err := audit.New(
		audit.WithQueueSize(100_000),
		audit.WithTaxonomy(tax),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out1, out2, out3, out4),
	)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = auditor.Close() })

	evt := audit.NewEvent("api_request", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"method":   "POST",
		"path":     "/api/v1/schemas",
	})

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = auditor.AuditEvent(evt)
	}
}

// BenchmarkAudit_FastPath_WithHMAC_Noop measures the in-place HMAC
// post-field append cost. Pre-W2 this allocated 2 byte slices per
// output (_hmac_version + _hmac); post-W2 these are appended in place into
// the per-event scratch buffer. Target: 0 allocs/op on the pipeline
// side (HMAC compute contributes a small constant B/op from
// hex.EncodeToString — pre-existing, not introduced by W2).
func BenchmarkAudit_FastPath_WithHMAC_Noop(b *testing.B) {
	silenceSlog(b)
	tax := &audit.Taxonomy{
		Version: 1,
		Categories: map[string]*audit.CategoryDef{
			"write": {Events: []string{"api_request"}},
		},
		Events: map[string]*audit.EventDef{
			"api_request": {Required: []string{"outcome", "actor_id", "method", "path"}},
		},
	}
	out := testhelper.NewNoopOutput("noop")
	hmacCfg := &audit.HMACConfig{
		Enabled: true,
		Salt: audit.HMACSalt{
			Version: "v1",
			Value:   []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
		},
		Algorithm: "HMAC-SHA-256",
	}
	auditor, err := audit.New(
		audit.WithQueueSize(100_000),
		audit.WithTaxonomy(tax),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(out, audit.WithHMAC(hmacCfg)),
	)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = auditor.Close() })

	evt := audit.NewFieldsDonorForTest("api_request", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"method":   "POST",
		"path":     "/api/v1/schemas",
	})

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = auditor.AuditEvent(evt)
	}
}

// newMultiFormatterAuditor builds an auditor with a NoopOutput per
// formatter so the fan-out benchmark measures ONLY the formatCache /
// drain path — no output-side defensive copy or mutex contention.
// Each formatter instance is a distinct pointer so the cache treats
// them as distinct keys (cache keys on pointer identity, not field
// values). Used by BenchmarkAudit_FanOut_{5,8}DistinctFormatters for
// #499.
func newMultiFormatterAuditor(tb testing.TB, formatters []audit.Formatter) *audit.Auditor {
	tb.Helper()
	tax := &audit.Taxonomy{
		Version: 1,
		Categories: map[string]*audit.CategoryDef{
			"write": {Events: []string{"api_request"}},
		},
		Events: map[string]*audit.EventDef{
			"api_request": {
				Required: []string{"outcome", "actor_id", "method", "path"},
			},
		},
	}
	opts := []audit.Option{
		audit.WithQueueSize(100_000),
		audit.WithTaxonomy(tax),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
	}
	for i, f := range formatters {
		out := testhelper.NewNoopOutput(fmt.Sprintf("noop-%d", i))
		opts = append(opts, audit.WithNamedOutput(out, audit.WithOutputFormatter(f)))
	}
	auditor, err := audit.New(opts...)
	if err != nil {
		tb.Fatal(err)
	}
	return auditor
}

// BenchmarkAudit_FanOut_5DistinctFormatters documents the transition
// case for #499. Pre-bump (formatCacheSize=4) this path allocated a
// `make(map[Formatter]formatCacheEntry)` on first use because the 5th
// formatter spilled into the overflow map. Post-bump the overflow
// map is never touched and the benchmark reports 0 allocs/op on the
// drain side — evidence that the bump delivers its headline win on
// realistic multi-formatter fan-out shapes (#499 AC #2).
func BenchmarkAudit_FanOut_5DistinctFormatters(b *testing.B) {
	silenceSlog(b)
	fmts := []audit.Formatter{
		&audit.JSONFormatter{},
		&audit.JSONFormatter{OmitEmpty: true},
		&audit.CEFFormatter{Vendor: "V1", Product: "P", Version: "1"},
		&audit.CEFFormatter{Vendor: "V2", Product: "P", Version: "1"},
		&audit.JSONFormatter{Timestamp: audit.TimestampUnixMillis},
	}
	auditor := newMultiFormatterAuditor(b, fmts)
	b.Cleanup(func() { _ = auditor.Close() })

	evt := audit.NewFieldsDonorForTest("api_request", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"method":   "POST",
		"path":     "/api/v1/schemas",
	})

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = auditor.AuditEvent(evt)
	}
}

// BenchmarkAudit_FanOut_8DistinctFormatters validates that a full-
// capacity fan-out — one distinct formatter per cache slot — stays
// zero-alloc on the drain path (#499 AC #2). 4 × JSONFormatter + 4 ×
// CEFFormatter with different configs gives 8 distinct pointers
// exercising both formatter types' bufferedFormatter fast paths.
// 0 allocs/op is operational proof that the overflow map was never
// initialised — a single map header alloc would bump this to ≥ 1.
func BenchmarkAudit_FanOut_8DistinctFormatters(b *testing.B) {
	silenceSlog(b)
	fmts := []audit.Formatter{
		&audit.JSONFormatter{},
		&audit.JSONFormatter{OmitEmpty: true},
		&audit.JSONFormatter{Timestamp: audit.TimestampUnixMillis},
		&audit.JSONFormatter{OmitEmpty: true, Timestamp: audit.TimestampUnixMillis},
		&audit.CEFFormatter{Vendor: "V1", Product: "P", Version: "1"},
		&audit.CEFFormatter{Vendor: "V2", Product: "P", Version: "1"},
		&audit.CEFFormatter{Vendor: "V3", Product: "P", Version: "1"},
		&audit.CEFFormatter{Vendor: "V4", Product: "P", Version: "1"},
	}
	auditor := newMultiFormatterAuditor(b, fmts)
	b.Cleanup(func() { _ = auditor.Close() })

	evt := audit.NewFieldsDonorForTest("api_request", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"method":   "POST",
		"path":     "/api/v1/schemas",
	})

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = auditor.AuditEvent(evt)
	}
}

// BenchmarkProcessEntry_Drain measures the inline drain path
// (synchronous delivery) with a single mock output.
// Complements BenchmarkProcessEntry_AsyncOutputs which uses two
// async outputs — this one isolates the serialisation and
// single-output dispatch cost (#502).
func BenchmarkProcessEntry_Drain(b *testing.B) {
	silenceSlog(b)
	out := testhelper.NewMockOutput("bench-drain")
	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
		audit.WithSynchronousDelivery(),
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

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = auditor.AuditEvent(audit.NewEvent("schema_register", fields))
	}
}

// BenchmarkAudit_Parallelism measures the Audit hot path under
// varying parallelism (#503). Characterises contention on the
// filter state sync.Map across producer counts. Expected curve:
// near-linear up to the number of physical cores, then some
// degradation beyond as sync.Map's amortised-lock-free reads
// start to contend with atomic writes in adjacent cache lines.
func BenchmarkAudit_Parallelism(b *testing.B) {
	silenceSlog(b)
	out := testhelper.NewMockOutput("bench")
	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
		audit.WithQueueSize(100_000),
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

	for _, n := range []int{1, 10, 50, 100, 200} {
		b.Run(fmt.Sprintf("N=%d", n), func(b *testing.B) {
			b.SetParallelism(n)
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					_ = auditor.AuditEvent(audit.NewEvent("schema_register", fields))
				}
			})
		})
	}
}
