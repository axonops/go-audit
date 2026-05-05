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
	"testing"

	"github.com/axonops/audit"
	"github.com/axonops/audit/internal/testhelper"
)

// ---------------------------------------------------------------------------
// #598 Sanitizer benchmarks — prove zero-overhead-when-unset and document
// the additive cost when set. Run side-by-side via benchstat to show the
// no-sanitizer baseline ≈ nil-sanitizer fast path.
// ---------------------------------------------------------------------------

// benchSanitizerAuditor builds an auditor wired with optional sanitizer.
func benchSanitizerAuditor(b *testing.B, opts ...audit.Option) *audit.Auditor {
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

// noopBenchSanitizer is a Sanitizer that returns the input unchanged
// — measures the per-event interface dispatch + per-field branch
// cost.
type noopBenchSanitizer struct{ audit.NoopSanitizer }

// transformBenchSanitizer rewrites every value as the fixed string
// "[scrubbed]" — measures the upper bound (every field re-boxed and
// written back into the map).
type transformBenchSanitizer struct{ audit.NoopSanitizer }

func (transformBenchSanitizer) SanitizeField(_ string, _ any) any { return "[scrubbed]" }

// selectiveBenchSanitizer rewrites only one specific field — the
// realistic consumer pattern (drop passwords, mask credit cards).
type selectiveBenchSanitizer struct{ audit.NoopSanitizer }

func (selectiveBenchSanitizer) SanitizeField(key string, value any) any {
	if key == "actor_id" {
		return "[redacted]"
	}
	return value
}

// BenchmarkAudit_NoSanitizer is the baseline for the four
// sanitizer-related benchmarks below.
func BenchmarkAudit_NoSanitizer(b *testing.B) {
	auditor := benchSanitizerAuditor(b)
	fields := audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "topic",
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = auditor.AuditEvent(audit.NewEvent("schema_register", fields))
	}
}

// BenchmarkAudit_NilSanitizer registers nil via WithSanitizer and
// proves the nil-check fast path matches the unset baseline. If
// benchstat shows a delta vs BenchmarkAudit_NoSanitizer, the locked
// "zero overhead when unset" contract regressed.
func BenchmarkAudit_NilSanitizer(b *testing.B) {
	auditor := benchSanitizerAuditor(b, audit.WithSanitizer(nil))
	fields := audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "topic",
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = auditor.AuditEvent(audit.NewEvent("schema_register", fields))
	}
}

// BenchmarkAudit_NoopSanitizer isolates the per-field interface
// dispatch cost — the value-unchanged branch is hit on every field.
func BenchmarkAudit_NoopSanitizer(b *testing.B) {
	auditor := benchSanitizerAuditor(b, audit.WithSanitizer(noopBenchSanitizer{}))
	fields := audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "topic",
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = auditor.AuditEvent(audit.NewEvent("schema_register", fields))
	}
}

// BenchmarkAudit_TransformSanitizer is the upper bound: every field
// is rewritten and re-boxed.
func BenchmarkAudit_TransformSanitizer(b *testing.B) {
	auditor := benchSanitizerAuditor(b, audit.WithSanitizer(transformBenchSanitizer{}))
	fields := audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "topic",
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = auditor.AuditEvent(audit.NewEvent("schema_register", fields))
	}
}

// BenchmarkAudit_SelectiveSanitizer measures the realistic consumer
// pattern — one of N fields rewritten.
func BenchmarkAudit_SelectiveSanitizer(b *testing.B) {
	auditor := benchSanitizerAuditor(b, audit.WithSanitizer(selectiveBenchSanitizer{}))
	fields := audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "topic",
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = auditor.AuditEvent(audit.NewEvent("schema_register", fields))
	}
}
