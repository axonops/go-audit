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

package loki

import (
	"errors"
	"testing"
	"time"

	"github.com/axonops/audit"
)

// FailingWriter is an io.Writer that always returns an error.
// Used to test the gzip error fallback path in maybeCompress.
type FailingWriter struct{}

func (fw *FailingWriter) Write(_ []byte) (int, error) {
	return 0, errors.New("injected compression failure")
}

// Exported aliases for internal functions needed by black-box tests.
var (
	ValidateLokiConfig    = validateLokiConfig
	BuildLokiTLSConfig    = buildLokiTLSConfig
	LokiBackoff           = lokiBackoff
	ParseRetryAfter       = parseRetryAfter
	SanitiseClientError   = sanitiseClientError   // #475 — error-URL redaction
	ResponseHeaderTimeout = responseHeaderTimeout // #485 — ResponseHeaderTimeout floor
)

// MinResponseHeaderTimeout is exported for testing only — lets tests
// assert that the floor constant matches the documented value (#485).
const MinResponseHeaderTimeout = minResponseHeaderTimeout

// TestEvent is a test-only event for building payloads.
type TestEvent struct { //nolint:govet // fieldalignment: readability preferred
	Data []byte
	Meta audit.EventMetadata
}

// TestPayloadInput configures a test payload build.
type TestPayloadInput struct { //nolint:govet // fieldalignment: readability preferred
	Events           []TestEvent
	StaticLabels     map[string]string
	AppName          string
	Host             string
	PID              int
	Gzip             bool
	ExcludeEventType bool
	ExcludeSeverity  bool
}

// buildTestConfig creates a Config from test input parameters.
// DisableStartupVerification is set so the build-payload helpers can
// be invoked without requiring a live Loki receiver — these tests
// exercise serialisation logic, not connectivity.
func buildTestConfig(input TestPayloadInput) *Config { //nolint:gocritic // hugeParam: test helper
	cfg := &Config{
		URL:                        "http://localhost:3100/loki/api/v1/push",
		AllowInsecureHTTP:          true,
		AllowPrivateRanges:         true,
		BatchSize:                  1000,
		FlushInterval:              10 * time.Second, // 10s in nanoseconds
		Timeout:                    5 * time.Second,
		MaxRetries:                 1,
		BufferSize:                 1000,
		Gzip:                       input.Gzip,
		DisableStartupVerification: true,
	}
	if input.StaticLabels != nil {
		cfg.Labels.Static = input.StaticLabels
	}
	if input.ExcludeEventType {
		cfg.Labels.Dynamic.ExcludeEventType = true
	}
	if input.ExcludeSeverity {
		cfg.Labels.Dynamic.ExcludeSeverity = true
	}
	return cfg
}

// buildTestOutput creates an Output from test input and returns it
// along with a batch of lokiEntry values.
func buildTestOutput(tb testing.TB, input TestPayloadInput) (*Output, []lokiEntry) { //nolint:gocritic // hugeParam: test helper
	tb.Helper()

	cfg := buildTestConfig(input)
	o, err := New(cfg, nil, WithFrameworkContext(audit.FrameworkContext{
		AppName:  input.AppName,
		Host:     input.Host,
		Timezone: "UTC",
		PID:      input.PID,
	}))
	if err != nil {
		tb.Fatalf("New() failed: %v", err)
	}

	batch := make([]lokiEntry, len(input.Events))
	for i, e := range input.Events {
		batch[i] = lokiEntry{data: e.Data, metadata: e.Meta}
	}
	return o, batch
}

// BuildTestPayload constructs a Loki push payload from test inputs.
// It creates a temporary Output with the supplied framework context,
// groups events, builds the payload, and returns the raw (uncompressed)
// JSON bytes. Framework fields are now construction-time only (#696).
func BuildTestPayload(tb testing.TB, input TestPayloadInput) []byte { //nolint:gocritic // hugeParam: test helper, readability preferred
	tb.Helper()

	o, batch := buildTestOutput(tb, input)
	defer func() { _ = o.Close() }()

	o.groupByStream(batch)
	o.buildPayload()
	return append([]byte(nil), o.payloadBuf.Bytes()...)
}

// BenchBatch wraps a batch for use in benchmarks, hiding the internal
// lokiEntry shape from the bench-test caller.
type BenchBatch struct {
	entries []lokiEntry
}

// SetupBatchBuildForBench creates an Output and pre-built batch
// suitable for reusing across b.Loop() iterations. Callers invoke
// [Output.RunBatchBuildForBench] inside the loop to measure the
// allocation behaviour of the batch-build hot path without re-paying
// the Output construction cost every iteration (#494).
func SetupBatchBuildForBench(tb testing.TB, input TestPayloadInput) (*Output, BenchBatch) { //nolint:gocritic // hugeParam: test helper, readability preferred
	tb.Helper()
	o, entries := buildTestOutput(tb, input)
	return o, BenchBatch{entries: entries}
}

// RunBatchBuildForBench runs the batch-build hot path (group → payload)
// once against a pre-constructed Output. Invoke inside b.Loop() for
// steady-state allocation measurement (#494).
func (o *Output) RunBatchBuildForBench(batch BenchBatch) {
	o.groupByStream(batch.entries)
	o.buildPayload()
}

// BuildTestCompressedPayload is like BuildTestPayload but returns
// gzip-compressed bytes.
func BuildTestCompressedPayload(tb testing.TB, input TestPayloadInput) []byte { //nolint:gocritic // hugeParam: test helper, readability preferred
	tb.Helper()

	o, batch := buildTestOutput(tb, input)
	defer func() { _ = o.Close() }()

	o.groupByStream(batch)
	o.buildPayload()
	body, _, _ := o.maybeCompress()
	return append([]byte(nil), body...)
}

// MaybeCompressForTest exposes maybeCompress for testing.
func (o *Output) MaybeCompressForTest() (body []byte, compressed bool, err error) {
	return o.maybeCompress()
}

// ForceCompressError replaces compressDest with a FailingWriter,
// causing the gzip.Writer to fail on Write. This exercises the
// gzip error fallback path in flush/maybeCompress.
func (o *Output) ForceCompressError() {
	o.compressDest = &FailingWriter{}
	o.gzWriter = nil // force re-creation with failing dest
}

// PreparePayloadForTest creates an Output from test input, groups events
// into streams, and builds the payload. Returns the Output ready for
// compression testing via MaybeCompressForTest.
func PreparePayloadForTest(tb testing.TB, input TestPayloadInput) *Output { //nolint:gocritic // hugeParam: test helper
	tb.Helper()
	o, batch := buildTestOutput(tb, input)
	o.groupByStream(batch)
	o.buildPayload()
	return o
}

// RebuildPayloadForTest re-groups and rebuilds the payload. Used after
// injecting a failing writer to re-prepare data for compression testing.
func (o *Output) RebuildPayloadForTest(tb testing.TB, input TestPayloadInput) { //nolint:gocritic // hugeParam: test helper
	tb.Helper()
	batch := make([]lokiEntry, len(input.Events))
	for i, e := range input.Events {
		batch[i] = lokiEntry{data: e.Data, metadata: e.Meta}
	}
	o.groupByStream(batch)
	o.buildPayload()
}
