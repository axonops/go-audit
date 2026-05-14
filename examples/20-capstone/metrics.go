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

package main

import (
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/axonops/audit"
)

// auditMetrics is a Prometheus adapter for audit.Metrics.
//
// The struct embeds audit.NoOpMetrics so that adding a method to
// audit.Metrics in a future library version is a no-op drop-in (ADR
// 0005 forward-compatibility policy). Consumers override only the
// methods they want instrumented.
//
// The vec() helper reduces Prometheus vector construction to a single
// line per metric. Same struct also implements file.RotationRecorder
// via RecordRotation.
type auditMetrics struct {
	audit.NoOpMetrics

	delivery, outputErr, outputFilt *prometheus.CounterVec
	valErr, filt, serErr, rot       *prometheus.CounterVec
	bufferDrops                     prometheus.Counter
}

// Compile-time check: auditMetrics satisfies audit.Metrics. If a
// future library version adds a method and we forget to embed the
// refreshed NoOpMetrics, this assertion fails at build time.
var _ audit.Metrics = (*auditMetrics)(nil)

func vec(name, help string, labels ...string) *prometheus.CounterVec {
	return promauto.NewCounterVec(prometheus.CounterOpts{Name: name, Help: help}, labels)
}

func newMetrics() *auditMetrics {
	return &auditMetrics{
		delivery:    vec("audit_events_total", "Audit deliveries by output and status.", "output", "status"),
		outputErr:   vec("audit_output_errors_total", "Output write errors by output name.", "output"),
		outputFilt:  vec("audit_output_filtered_total", "Events filtered per output.", "output"),
		valErr:      vec("audit_validation_errors_total", "Validation errors by event type.", "event_type"),
		filt:        vec("audit_filtered_total", "Events filtered globally by event type.", "event_type"),
		serErr:      vec("audit_serialization_errors_total", "Serialization errors by event type.", "event_type"),
		rot:         vec("audit_file_rotations_total", "File rotations by path.", "path"),
		bufferDrops: promauto.NewCounter(prometheus.CounterOpts{Name: "audit_buffer_drops_total", Help: "Events dropped due to full buffer."}),
	}
}

// audit.Metrics methods — the five that carry labels plus BufferDrop.
// RecordSubmitted and RecordQueueDepth stay inherited no-ops from the
// embedded audit.NoOpMetrics (unsampled in this capstone).
func (m *auditMetrics) RecordDelivery(output string, status audit.EventStatus) {
	m.delivery.WithLabelValues(output, string(status)).Inc()
}
func (m *auditMetrics) RecordOutputError(output string) { m.outputErr.WithLabelValues(output).Inc() }
func (m *auditMetrics) RecordOutputFiltered(output string) {
	m.outputFilt.WithLabelValues(output).Inc()
}
func (m *auditMetrics) RecordValidationError(ev string)    { m.valErr.WithLabelValues(ev).Inc() }
func (m *auditMetrics) RecordFiltered(ev string)           { m.filt.WithLabelValues(ev).Inc() }
func (m *auditMetrics) RecordSerializationError(ev string) { m.serErr.WithLabelValues(ev).Inc() }
func (m *auditMetrics) RecordBufferDrop()                  { m.bufferDrops.Inc() }

// file.RotationRecorder — optional extension detected via type assertion.
func (m *auditMetrics) RecordRotation(path string) { m.rot.WithLabelValues(path).Inc() }

// --- audit.OutputMetrics via OutputMetricsFactory ---
//
// The factory creates a scoped perOutputMetrics instance for each
// output, labelled by output type and name. This gives per-output
// Prometheus metrics without a global shared counter. Kept as a
// separate type because OutputMetrics is a distinct contract from
// Metrics (per-output buffer telemetry, not pipeline-wide).

type perOutputMetrics struct {
	audit.NoOpOutputMetrics
	drops      prometheus.Counter
	flushBatch prometheus.Observer
	flushDur   prometheus.Observer
	retries    *prometheus.CounterVec
	errors     prometheus.Counter
}

func (p *perOutputMetrics) RecordDrop() { p.drops.Inc() }
func (p *perOutputMetrics) RecordFlush(batchSize int, dur time.Duration) {
	p.flushBatch.Observe(float64(batchSize))
	p.flushDur.Observe(dur.Seconds())
}
func (p *perOutputMetrics) RecordRetry(attempt int) {
	p.retries.WithLabelValues(strconv.Itoa(attempt)).Inc()
}
func (p *perOutputMetrics) RecordError() { p.errors.Inc() }

// newOutputMetricsFactory returns an OutputMetricsFactory producing
// per-output metrics scoped by output type and name. Histograms and
// counters are pre-registered once here; WithLabelValues lookups
// scope them per output.
func (m *auditMetrics) newOutputMetricsFactory() audit.OutputMetricsFactory {
	drops := promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "audit_output_drops_total", Help: "Per-output events dropped.",
	}, []string{"output_type", "output_name"})
	flushBatch := promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name: "audit_output_flush_batch_size", Help: "Events per per-output batch flush.",
		Buckets: []float64{1, 5, 10, 25, 50, 100, 250},
	}, []string{"output_type", "output_name"})
	flushDur := promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name: "audit_output_flush_duration_seconds", Help: "Per-output batch flush duration.",
		Buckets: prometheus.DefBuckets,
	}, []string{"output_type", "output_name"})
	retries := promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "audit_output_retries_total", Help: "Per-output retry attempts.",
	}, []string{"output_type", "output_name", "attempt"})
	errs := promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "audit_output_errors_by_output_total", Help: "Per-output non-retryable errors.",
	}, []string{"output_type", "output_name"})

	return func(outputType, outputName string) audit.OutputMetrics {
		lv := []string{outputType, outputName}
		return &perOutputMetrics{
			drops:      drops.WithLabelValues(lv...),
			flushBatch: flushBatch.WithLabelValues(lv...),
			flushDur:   flushDur.WithLabelValues(lv...),
			retries:    retries.MustCurryWith(prometheus.Labels{"output_type": outputType, "output_name": outputName}),
			errors:     errs.WithLabelValues(lv...),
		}
	}
}
