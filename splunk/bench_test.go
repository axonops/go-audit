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

package splunk

import (
	"bytes"
	"compress/gzip"
	"testing"
	"time"
)

// Audit-shaped JSON event used as the benchmark input. Captures the
// realistic 5-field shape (timestamp + event_type + actor_id +
// outcome + target_id) — matches the README quickstart example.
var benchEvent = []byte(`{"timestamp":"2026-05-20T10:00:00.123Z","event_type":"user_login","actor_id":"alice","outcome":"success","target_id":"user-42"}`)

// BenchmarkWrapEvent measures the per-event cost of envelope wrapping
// on the /event endpoint hot path. No indexed fields — the common
// case. Should be allocation-light after the json.Encoder→json.Marshal
// optimisation (perf-reviewer HIGH-2).
func BenchmarkWrapEvent(b *testing.B) {
	cfg := &Config{
		Host:       "inventory-01",
		Source:     "audit",
		Sourcetype: "axonops:audit",
		Index:      "audit_logs",
	}
	var buf bytes.Buffer
	now := time.Now()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		_ = wrapEvent(&buf, cfg, benchEvent, now)
	}
}

// BenchmarkWrapEvent_IndexedFields measures the per-event cost when
// the operator has configured indexed-field extraction. Half of the
// requested fields exist in the event; half are missing. Exercises
// the JSON unmarshal + map lookup cost (perf-reviewer HIGH-4).
func BenchmarkWrapEvent_IndexedFields(b *testing.B) {
	cfg := &Config{
		Host:          "inventory-01",
		Source:        "audit",
		Sourcetype:    "axonops:audit",
		IndexedFields: []string{"actor_id", "event_type", "outcome", "missing1", "missing2", "missing3"},
	}
	var buf bytes.Buffer
	now := time.Now()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		_ = wrapEvent(&buf, cfg, benchEvent, now)
	}
}

// BenchmarkExtractTime exercises the timestamp-extraction hot path
// in isolation. Per-event cost: one json.Unmarshal of the event body
// into a narrow `{Timestamp any}` struct (perf-reviewer HIGH-3).
func BenchmarkExtractTime(b *testing.B) {
	now := time.Now()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = extractTime(benchEvent, now)
	}
}

// BenchmarkBatchConcatenation_N100 measures the cost of building a
// 100-event concatenated envelope batch. Approximates a typical
// flush at BatchSize=100. Should be allocation-bounded — the
// envelopeBuf is reused across events; per-event work is one
// wrapEvent call + buffer append.
func BenchmarkBatchConcatenation_N100(b *testing.B) {
	cfg := &Config{
		Host:       "inventory-01",
		Source:     "audit",
		Sourcetype: "axonops:audit",
	}
	var buf bytes.Buffer
	now := time.Now()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		for j := 0; j < 100; j++ {
			_ = wrapEvent(&buf, cfg, benchEvent, now)
		}
	}
}

// BenchmarkBatchConcatenation_N500 same as N100 but at the default
// BatchSize ceiling.
func BenchmarkBatchConcatenation_N500(b *testing.B) {
	cfg := &Config{
		Host:       "inventory-01",
		Source:     "audit",
		Sourcetype: "axonops:audit",
	}
	var buf bytes.Buffer
	now := time.Now()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		for j := 0; j < 500; j++ {
			_ = wrapEvent(&buf, cfg, benchEvent, now)
		}
	}
}

// BenchmarkGzipCompression_Small measures the gzip cost on a single
// envelope's worth of bytes (~300 bytes). Lower bound for the
// compression overhead.
func BenchmarkGzipCompression_Small(b *testing.B) {
	cfg := &Config{Sourcetype: "axonops:audit"}
	var raw bytes.Buffer
	_ = wrapEvent(&raw, cfg, benchEvent, time.Now())
	payload := raw.Bytes()

	var dst bytes.Buffer
	gz := gzip.NewWriter(&dst)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dst.Reset()
		gz.Reset(&dst)
		_, _ = gz.Write(payload)
		_ = gz.Close()
	}
}

// BenchmarkGzipCompression_Large measures the gzip cost on a 100-event
// batch (~30 KB) — the realistic flush size.
func BenchmarkGzipCompression_Large(b *testing.B) {
	cfg := &Config{Sourcetype: "axonops:audit"}
	var raw bytes.Buffer
	for j := 0; j < 100; j++ {
		_ = wrapEvent(&raw, cfg, benchEvent, time.Now())
	}
	payload := raw.Bytes()

	var dst bytes.Buffer
	gz := gzip.NewWriter(&dst)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dst.Reset()
		gz.Reset(&dst)
		_, _ = gz.Write(payload)
		_ = gz.Close()
	}
}

// BenchmarkRawEventLine_N100 measures the cost of building a
// 100-event NDJSON batch for the /raw endpoint. Should be the
// cheapest of the batch builders — no envelope wrapping.
func BenchmarkRawEventLine_N100(b *testing.B) {
	var buf bytes.Buffer
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		for j := 0; j < 100; j++ {
			rawEventLine(&buf, benchEvent)
		}
	}
}

// BenchmarkClassify_FullTable exercises the HEC error code dispatch
// table at every documented entry. Per-batch cost; not on the
// per-event hot path. Included to detect any future regression to
// a map-based dispatch (slower than the switch).
func BenchmarkClassify_FullTable(b *testing.B) {
	statuses := []int{200, 401, 403, 400, 429, 500, 503, 413}
	codes := []int{0, 1, 4, 7, 9, 14, 24, 27}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, s := range statuses {
			for _, c := range codes {
				_ = classify(s, c)
			}
		}
	}
}
