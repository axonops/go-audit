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

import "time"

// EventStatus is the outcome label for a delivery attempt recorded
// via [Metrics.RecordDelivery]. It is a typed string so consumers can
// pass it straight to Prometheus / OpenTelemetry label vectors with
// a zero-cost `string(status)` conversion on the hot path.
//
// The underlying string values are a library contract: they are
// emitted as-is to downstream metric collectors. Existing
// consumer-side Prometheus queries and alert rules that match on
// `"success"` / `"error"` continue to work verbatim.
//
// Adding a new EventStatus value is a minor-version compatible
// change. Removing or renaming an existing value is breaking.
type EventStatus string

// Defined EventStatus values. Production code emits only these two;
// the set is deliberately minimal because other outcome categories
// (filtered, dropped, validation failure) have dedicated [Metrics]
// methods ([Metrics.RecordOutputFiltered], [Metrics.RecordBufferDrop],
// [Metrics.RecordValidationError]).
const (
	// EventSuccess records a successful delivery to an output.
	EventSuccess EventStatus = "success"

	// EventError records a non-retryable delivery failure.
	EventError EventStatus = "error"
)

// Metrics is an optional instrumentation interface that consumers implement
// to collect audit pipeline telemetry. Pass an implementation via
// [WithMetrics]; pass nil to disable metrics collection.
//
// The library never imports a concrete metrics library (Prometheus,
// OpenTelemetry, etc.). Consumers wire their own. The
// [examples/20-capstone] Prometheus adapter shows a complete
// implementation in under 50 lines using a table-driven registration
// pattern; copy it as a starting point.
//
// Consumers SHOULD embed [NoOpMetrics] in their implementation to
// absorb new methods added in future versions without breaking builds.
//
// # Ownership: Metrics vs OutputMetrics
//
// [Metrics] records pipeline-level counters that span the entire auditor:
//
//   - RecordSubmitted — total events entering the pipeline
//   - RecordDelivery — per-output delivery outcome (for non-self-reporting outputs)
//   - RecordBufferDrop — core intake queue overflow
//   - RecordQueueDepth — core intake queue pressure gauge
//
// [OutputMetrics] records per-output buffer operations inside each
// async output:
//
//   - RecordDrop — per-output buffer overflow
//   - RecordFlush — per-output batch delivery
//   - RecordError — per-output non-retryable delivery failure
//   - RecordRetry — per-output retry attempt
//   - RecordQueueDepth — per-output buffer pressure gauge
//
// For outputs that implement [DeliveryReporter] (webhook, loki, file,
// syslog), the output itself calls RecordDelivery after actual delivery.
// The core auditor skips RecordDelivery for these outputs to avoid
// phantom success counting.
//
// # Cardinality guidance
//
// Each method notes the Prometheus / OpenTelemetry label-vector
// dimensionality implied by its arguments. "High cardinality" flags
// methods whose label space scales with caller-supplied identifiers
// (event types, output names) — consumers with many event types
// should budget accordingly when wiring label vectors.
//
// # Forward compatibility
//
// Adding a method to [Metrics] in a v1.x release is a breaking
// interface change. The library adds new metrics via separate
// optional interfaces detected by type assertion on the passed
// [Metrics] value, mirroring the pattern used by [DeliveryReporter]
// on outputs and by [file.RotationRecorder] / [syslog.ReconnectRecorder]
// on [OutputMetrics]. Consumers who embed [NoOpMetrics] retain
// no-op implementations for every base-interface method; extensions
// are additive. See ADR 0005 (docs/adr/0005-metrics-interface-shape.md)
// for the full policy.
type Metrics interface {
	// RecordSubmitted records that an event was submitted to the
	// pipeline via [Auditor.AuditEvent]. Called once per AuditEvent
	// call, before any filtering or buffering. This is the "total
	// events in" counter.
	//
	// Cardinality: single counter (no labels).
	RecordSubmitted()

	// RecordDelivery records an event delivery attempt to the named
	// output. status is a typed enum — see [EventStatus] for the
	// defined values.
	//
	// Cardinality: 2-dimensional vector (output × status).
	// The output label set is bounded by the number of configured
	// outputs. status has two values ([EventSuccess], [EventError]).
	RecordDelivery(output string, status EventStatus)

	// RecordOutputError records a write error on the named output.
	//
	// Cardinality: 1-dimensional vector (output). Bounded by the
	// number of configured outputs.
	RecordOutputError(output string)

	// RecordOutputFiltered records that a per-output event route filter
	// prevented an event from being delivered to the named output.
	// This is distinct from [Metrics.RecordFiltered], which records
	// global category/event filter drops before any output is reached.
	//
	// Cardinality: 1-dimensional vector (output).
	RecordOutputFiltered(output string)

	// RecordValidationError records that [Auditor.AuditEvent] rejected an
	// event due to a validation failure: unknown event type, missing
	// required fields, or unknown fields in strict mode. The
	// eventType parameter is the event type string that was passed to
	// AuditEvent.
	//
	// Cardinality: 1-dimensional vector (event_type). HIGH cardinality
	// if the taxonomy grows large or if unknown event types are
	// common. Consumers may aggregate into a single counter without
	// the event_type label to cap the vector size.
	RecordValidationError(eventType string)

	// RecordFiltered records that an event was silently discarded by
	// the global category/event filter. This is distinct from
	// [Metrics.RecordOutputFiltered] which tracks per-output route
	// filtering.
	//
	// Cardinality: 1-dimensional vector (event_type). HIGH cardinality
	// — see [Metrics.RecordValidationError].
	RecordFiltered(eventType string)

	// RecordSerializationError records that the configured [Formatter]
	// returned an error (or panicked) when serialising an event. The
	// event is dropped when this occurs.
	//
	// Cardinality: 1-dimensional vector (event_type). HIGH cardinality
	// — see [Metrics.RecordValidationError].
	RecordSerializationError(eventType string)

	// RecordBufferDrop records that an event was dropped because the
	// main async queue was full.
	//
	// Cardinality: single counter (no labels).
	RecordBufferDrop()

	// RecordQueueDepth records the current depth and capacity of the
	// core intake queue. Called from the drain loop, sampled every 64
	// events processed. depth is len(channel), capacity is
	// cap(channel).
	//
	// Cardinality: gauge (depth) and an associated gauge or constant
	// (capacity). No per-call labels. Consumers may record the
	// capacity once at startup and emit depth per call.
	RecordQueueDepth(depth, capacity int)
}

// NoOpMetrics is a [Metrics] implementation where every method is a
// no-op. Embed it in your own struct to override only the methods you
// care about:
//
//	type MyMetrics struct {
//	    audit.NoOpMetrics
//	    drops atomic.Int64
//	}
//	func (m *MyMetrics) RecordBufferDrop() { m.drops.Add(1) }
type NoOpMetrics struct{}

// Compile-time interface check.
var _ Metrics = NoOpMetrics{}

// RecordSubmitted is a no-op.
func (NoOpMetrics) RecordSubmitted() {}

// RecordDelivery is a no-op.
func (NoOpMetrics) RecordDelivery(string, EventStatus) {}

// RecordOutputError is a no-op.
func (NoOpMetrics) RecordOutputError(string) {}

// RecordOutputFiltered is a no-op.
func (NoOpMetrics) RecordOutputFiltered(string) {}

// RecordValidationError is a no-op.
func (NoOpMetrics) RecordValidationError(string) {}

// RecordFiltered is a no-op.
func (NoOpMetrics) RecordFiltered(string) {}

// RecordSerializationError is a no-op.
func (NoOpMetrics) RecordSerializationError(string) {}

// RecordBufferDrop is a no-op.
func (NoOpMetrics) RecordBufferDrop() {}

// RecordQueueDepth is a no-op.
func (NoOpMetrics) RecordQueueDepth(int, int) {}

// OutputMetrics is an optional per-output instrumentation interface
// for async buffer telemetry. Each output receives its own instance
// at construction via [FrameworkContext.OutputMetrics] (typically
// produced per-output by an [OutputMetricsFactory] supplied to
// outputconfig.WithOutputMetricsFactory), scoped to that output's
// identity.
//
// Unlike [Metrics] (which tracks pipeline-level events), OutputMetrics
// tracks per-output buffer operations: drops, flushes, retries, errors,
// and queue depth. See the [Metrics] godoc for the ownership table.
//
// Output-specific extensions (e.g. file rotation, syslog reconnection)
// are detected via type assertion on the OutputMetrics value. The
// returned OutputMetrics MAY optionally implement output-specific
// extension interfaces (e.g. [file.RotationRecorder],
// [syslog.ReconnectRecorder]). If detected, the output uses the
// extended methods automatically.
//
// Consumers SHOULD embed [NoOpOutputMetrics] for forward compatibility.
type OutputMetrics interface {
	// RecordDrop records that an event was dropped because the
	// output's internal async buffer was full.
	RecordDrop()

	// RecordFlush records a successful batch flush to the output
	// destination. batchSize is the number of events in the batch.
	// dur is the wall-clock time of the flush operation.
	RecordFlush(batchSize int, dur time.Duration)

	// RecordError records a non-retryable delivery error.
	RecordError()

	// RecordRetry records a retry attempt. attempt is 1-indexed:
	// 1 means first retry (second delivery attempt), 2 means second
	// retry, etc.
	RecordRetry(attempt int)

	// RecordQueueDepth records the current depth and capacity of the
	// output's internal async buffer. depth is the number of events
	// waiting to be flushed, capacity is the buffer size.
	RecordQueueDepth(depth, capacity int)
}

// OutputMetricsFactory creates a scoped [OutputMetrics] for a named
// output. outputType is the output type name (e.g. "file", "syslog",
// "webhook", "loki"). outputName is the consumer-chosen YAML key name
// (e.g. "compliance_archive", "security_feed"). The factory is called
// once per output at construction time.
//
// Example Prometheus implementation:
//
//	func(outputType, outputName string) audit.OutputMetrics {
//	    return &outputMetrics{
//	        drops: dropsVec.WithLabelValues(outputType, outputName),
//	    }
//	}
type OutputMetricsFactory func(outputType, outputName string) OutputMetrics

// NoOpOutputMetrics is an [OutputMetrics] implementation where every
// method is a no-op. Embed it in your own struct to override only
// the methods you care about.
type NoOpOutputMetrics struct{}

// Compile-time interface check.
var _ OutputMetrics = NoOpOutputMetrics{}

// RecordDrop is a no-op.
func (NoOpOutputMetrics) RecordDrop() {}

// RecordFlush is a no-op.
func (NoOpOutputMetrics) RecordFlush(int, time.Duration) {}

// RecordError is a no-op.
func (NoOpOutputMetrics) RecordError() {}

// RecordRetry is a no-op.
func (NoOpOutputMetrics) RecordRetry(int) {}

// RecordQueueDepth is a no-op.
func (NoOpOutputMetrics) RecordQueueDepth(int, int) {}
