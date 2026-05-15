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

// Drop-in Prometheus adapter for the audit library. Copy this file
// (and the imports) into your own project to wire Prometheus metrics
// into the audit pipeline. The adapter satisfies both audit.Metrics
// (pipeline-wide counters) and provides an audit.OutputMetricsFactory
// that produces per-output buffer/flush/retry/error telemetry.
//
// Forward-compatibility: auditMetrics embeds audit.NoOpMetrics and
// perOutputMetrics embeds audit.NoOpOutputMetrics so future Metrics
// or OutputMetrics methods default to no-ops without breaking your
// build (see ADR 0005 in the project root).

import (
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/axonops/audit"
)

// auditMetrics implements audit.Metrics against a Prometheus
// registry. Compose with promauto so registration is automatic on
// the default (or user-supplied) registry.
type auditMetrics struct {
	audit.NoOpMetrics

	delivery, outputErr, outputFilt *prometheus.CounterVec
	valErr, filt, serErr            *prometheus.CounterVec
	bufferDrops                     prometheus.Counter
}

// Compile-time check: auditMetrics MUST satisfy audit.Metrics. If a
// future library version adds a method to Metrics, NoOpMetrics
// supplies the default — this assertion only fails if NoOpMetrics
// is removed or renamed (defensive).
var _ audit.Metrics = (*auditMetrics)(nil)

func vec(name, help string, labels ...string) *prometheus.CounterVec {
	return promauto.NewCounterVec(prometheus.CounterOpts{Name: name, Help: help}, labels)
}

// newMetrics constructs the Prometheus adapter and registers every
// counter on the default registry. Call once at startup.
func newMetrics() *auditMetrics {
	return &auditMetrics{
		delivery:   vec("audit_events_total", "Audit deliveries by output and status.", "output", "status"),
		outputErr:  vec("audit_output_errors_total", "Output write errors by output name.", "output"),
		outputFilt: vec("audit_output_filtered_total", "Events filtered per output.", "output"),
		valErr:     vec("audit_validation_errors_total", "Validation errors by event type.", "event_type"),
		filt:       vec("audit_filtered_total", "Events filtered globally by event type.", "event_type"),
		serErr:     vec("audit_serialization_errors_total", "Serialization errors by event type.", "event_type"),
		bufferDrops: promauto.NewCounter(prometheus.CounterOpts{
			Name: "audit_buffer_drops_total",
			Help: "Events dropped due to full core intake buffer.",
		}),
	}
}

// audit.Metrics — the seven methods this adapter instruments.
// RecordSubmitted and RecordQueueDepth remain inherited no-ops from
// audit.NoOpMetrics; wire them up if you want submission and queue-
// depth telemetry on your dashboard.
func (m *auditMetrics) RecordDelivery(output string, status audit.EventStatus) {
	m.delivery.WithLabelValues(output, string(status)).Inc()
}
func (m *auditMetrics) RecordOutputError(output string) {
	m.outputErr.WithLabelValues(output).Inc()
}
func (m *auditMetrics) RecordOutputFiltered(output string) {
	m.outputFilt.WithLabelValues(output).Inc()
}
func (m *auditMetrics) RecordValidationError(ev string) {
	m.valErr.WithLabelValues(ev).Inc()
}
func (m *auditMetrics) RecordFiltered(ev string) {
	m.filt.WithLabelValues(ev).Inc()
}
func (m *auditMetrics) RecordSerializationError(ev string) {
	m.serErr.WithLabelValues(ev).Inc()
}
func (m *auditMetrics) RecordBufferDrop() { m.bufferDrops.Inc() }

// --- per-output OutputMetrics via OutputMetricsFactory ---
//
// audit.OutputMetricsFactory is a separate contract from Metrics.
// It produces a per-output telemetry instance scoped by output type
// (file, syslog, webhook, loki, stdout) and output name (the YAML
// config key, e.g. "compliance_archive"). Histograms and counters
// are registered once here; WithLabelValues looks them up per output.

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

// newOutputMetricsFactory returns an OutputMetricsFactory wiring
// per-output metrics. Pass the result to
// audit.WithOutputMetricsFactory or outputconfig.WithOutputMetrics.
func (m *auditMetrics) newOutputMetricsFactory() audit.OutputMetricsFactory {
	drops := promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "audit_output_drops_total",
		Help: "Per-output events dropped due to internal buffer overflow or retry exhaustion.",
	}, []string{"output_type", "output_name"})
	flushBatch := promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "audit_output_flush_batch_size",
		Help:    "Events per per-output batch flush.",
		Buckets: []float64{1, 5, 10, 25, 50, 100, 250},
	}, []string{"output_type", "output_name"})
	flushDur := promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "audit_output_flush_duration_seconds",
		Help:    "Per-output batch flush duration.",
		Buckets: prometheus.DefBuckets,
	}, []string{"output_type", "output_name"})
	retries := promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "audit_output_retries_total",
		Help: "Per-output retry attempts (1-indexed).",
	}, []string{"output_type", "output_name", "attempt"})
	errs := promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "audit_output_errors_by_output_total",
		Help: "Per-output non-retryable errors.",
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
