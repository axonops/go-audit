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

// Package testhelper provides shared test utilities for the core
// audit module. It is internal-only and never published. Sub-modules
// cannot import this package because internal/ is module-scoped; the
// cross-module-importable equivalents live in [audittest].
package testhelper

import (
	"sync"
	"time"

	"github.com/axonops/audit"
)

// Compile-time assertion: MockMetrics satisfies audit.Metrics.
var _ audit.Metrics = (*MockMetrics)(nil)

// MockMetrics is a thread-safe mock that satisfies [audit.Metrics] and
// structurally satisfies the output-specific extension interfaces
// (file.RotationRecorder, syslog.ReconnectRecorder) without importing
// those packages.
// QueueDepthRecord captures a single RecordQueueDepth call.
type QueueDepthRecord struct {
	Depth    int
	Capacity int
}

type MockMetrics struct { //nolint:govet // fieldalignment: readability preferred
	Events              map[string]int // "output:status" -> count
	OutputErrors        map[string]int
	FilteredCount       map[string]int
	ValidationErrors    map[string]int // eventType -> count
	GlobalFiltered      map[string]int // eventType -> count
	SerializationErrors map[string]int // eventType -> count
	FileRotations       map[string]int // path -> count
	SyslogReconnects    map[string]int // "address:success|failure" -> count
	QueueDepths         []QueueDepthRecord
	// EventCh is signalled (non-blocking) on every RecordDelivery call.
	// It is buffered to 1000 entries and is consumed internally by
	// [MockMetrics.WaitForMetric]; consumers do not need to read it.
	EventCh     chan struct{}
	Mu          sync.Mutex
	BufferDrops int
	Submitted   int
}

// NewMockMetrics creates a ready-to-use MockMetrics.
func NewMockMetrics() *MockMetrics {
	return &MockMetrics{
		Events:              make(map[string]int),
		OutputErrors:        make(map[string]int),
		FileRotations:       make(map[string]int),
		SyslogReconnects:    make(map[string]int),
		FilteredCount:       make(map[string]int),
		ValidationErrors:    make(map[string]int),
		GlobalFiltered:      make(map[string]int),
		SerializationErrors: make(map[string]int),
		EventCh:             make(chan struct{}, 1000),
	}
}

// --- audit.Metrics methods ---

func (m *MockMetrics) RecordSubmitted() {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	m.Submitted++
}

func (m *MockMetrics) RecordDelivery(output string, status audit.EventStatus) {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	m.Events[output+":"+string(status)]++
	select {
	case m.EventCh <- struct{}{}:
	default:
	}
}

func (m *MockMetrics) RecordOutputError(output string) {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	m.OutputErrors[output]++
}

func (m *MockMetrics) RecordOutputFiltered(output string) {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	m.FilteredCount[output]++
}

func (m *MockMetrics) RecordBufferDrop() {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	m.BufferDrops++
}

func (m *MockMetrics) RecordValidationError(eventType string) {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	m.ValidationErrors[eventType]++
}

func (m *MockMetrics) RecordFiltered(eventType string) {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	m.GlobalFiltered[eventType]++
}

func (m *MockMetrics) RecordSerializationError(eventType string) {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	m.SerializationErrors[eventType]++
}

func (m *MockMetrics) RecordQueueDepth(depth, capacity int) {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	m.QueueDepths = append(m.QueueDepths, QueueDepthRecord{Depth: depth, Capacity: capacity})
}

// --- file.RotationRecorder methods (structural satisfaction) ---

func (m *MockMetrics) RecordRotation(path string) {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	m.FileRotations[path]++
}

// --- syslog.ReconnectRecorder methods (structural satisfaction) ---

func (m *MockMetrics) RecordReconnect(address string, success bool) {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	key := address + ":"
	if success {
		key += "success"
	} else {
		key += "failure"
	}
	m.SyslogReconnects[key]++
}

// WaitForMetric blocks until the event metric for key reaches at least n,
// or until timeout expires. The key format is "outputName:status" — the
// same string [MockMetrics.RecordDelivery] indexes into Events (e.g.
// "test-out:success"). Returns true if the count reached n within the
// deadline; returns false on timeout.
func (m *MockMetrics) WaitForMetric(key string, n int, timeout time.Duration) bool {
	deadline := time.After(timeout)
	for {
		m.Mu.Lock()
		v := m.Events[key]
		m.Mu.Unlock()
		if v >= n {
			return true
		}
		select {
		case <-m.EventCh:
		case <-deadline:
			return false
		}
	}
}

// --- Accessors ---

// GetOutputErrorCount returns the count of output errors for the named output.
func (m *MockMetrics) GetOutputErrorCount(output string) int {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	return m.OutputErrors[output]
}

// GetOutputFiltered returns the count of filtered events for the named output.
func (m *MockMetrics) GetOutputFiltered(output string) int {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	return m.FilteredCount[output]
}

// GetEventCount returns the count of events for the named output and status.
func (m *MockMetrics) GetEventCount(output string, status audit.EventStatus) int {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	return m.Events[output+":"+string(status)]
}

// GetSerializationErrorCount returns the count of serialization errors for the event type.
func (m *MockMetrics) GetSerializationErrorCount(eventType string) int {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	return m.SerializationErrors[eventType]
}

// GetBufferDrops returns the total number of buffer drops recorded.
func (m *MockMetrics) GetBufferDrops() int {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	return m.BufferDrops
}

// GetSyslogReconnectCount returns the reconnect count for the given address and outcome.
func (m *MockMetrics) GetSyslogReconnectCount(address string, success bool) int {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	key := address + ":"
	if success {
		key += "success"
	} else {
		key += "failure"
	}
	return m.SyslogReconnects[key]
}

// GetFileRotationCount returns the rotation count for the given path.
func (m *MockMetrics) GetFileRotationCount(path string) int {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	return m.FileRotations[path]
}

// GetSubmitted returns the total number of RecordSubmitted calls.
func (m *MockMetrics) GetSubmitted() int {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	return m.Submitted
}

// GetQueueDepths returns all recorded queue depth samples.
func (m *MockMetrics) GetQueueDepths() []QueueDepthRecord {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	cp := make([]QueueDepthRecord, len(m.QueueDepths))
	copy(cp, m.QueueDepths)
	return cp
}

// ---------------------------------------------------------------------------
// MockOutputMetrics — per-output metrics mock
// ---------------------------------------------------------------------------

// Compile-time assertion: MockOutputMetrics satisfies audit.OutputMetrics.
var _ audit.OutputMetrics = (*MockOutputMetrics)(nil)

// MockOutputMetrics is a thread-safe mock that satisfies
// [audit.OutputMetrics] for per-output delivery metrics.
type MockOutputMetrics struct { //nolint:govet // fieldalignment: readability preferred
	Mu       sync.Mutex
	Drops    int
	Flushes  int
	Errors   int
	Retries  int
	FlushDur []time.Duration
}

// RecordDrop satisfies audit.OutputMetrics.
func (m *MockOutputMetrics) RecordDrop() {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	m.Drops++
}

// RecordFlush satisfies audit.OutputMetrics.
func (m *MockOutputMetrics) RecordFlush(_ int, dur time.Duration) {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	m.Flushes++
	m.FlushDur = append(m.FlushDur, dur)
}

// RecordError satisfies audit.OutputMetrics.
func (m *MockOutputMetrics) RecordError() {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	m.Errors++
}

// RecordRetry satisfies audit.OutputMetrics.
func (m *MockOutputMetrics) RecordRetry(_ int) {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	m.Retries++
}

// RecordQueueDepth satisfies audit.OutputMetrics.
func (m *MockOutputMetrics) RecordQueueDepth(_, _ int) {}

// DropCount returns the number of recorded drops.
func (m *MockOutputMetrics) DropCount() int {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	return m.Drops
}

// FlushCount returns the number of recorded flushes.
func (m *MockOutputMetrics) FlushCount() int {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	return m.Flushes
}

// ErrorCount returns the number of recorded errors.
func (m *MockOutputMetrics) ErrorCount() int {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	return m.Errors
}

// ---------------------------------------------------------------------------
// MockOutputMetricsFactory — factory that records calls
// ---------------------------------------------------------------------------

// OutputMetricsFactoryCall records a single factory invocation.
type OutputMetricsFactoryCall struct {
	OutputType string
	OutputName string
}

// MockOutputMetricsFactory records all factory calls and returns
// MockOutputMetrics instances keyed by "outputType:outputName".
type MockOutputMetricsFactory struct { //nolint:govet // fieldalignment: readability preferred
	Mu      sync.Mutex
	Calls   []OutputMetricsFactoryCall
	Metrics map[string]*MockOutputMetrics
}

// NewMockOutputMetricsFactory creates a factory that records calls.
func NewMockOutputMetricsFactory() *MockOutputMetricsFactory {
	return &MockOutputMetricsFactory{
		Metrics: make(map[string]*MockOutputMetrics),
	}
}

// Factory returns the [audit.OutputMetricsFactory] function.
func (f *MockOutputMetricsFactory) Factory() audit.OutputMetricsFactory {
	return func(outputType, outputName string) audit.OutputMetrics {
		f.Mu.Lock()
		defer f.Mu.Unlock()
		f.Calls = append(f.Calls, OutputMetricsFactoryCall{
			OutputType: outputType,
			OutputName: outputName,
		})
		m := &MockOutputMetrics{}
		f.Metrics[outputType+":"+outputName] = m
		return m
	}
}

// CallCount returns the number of times the factory was invoked.
func (f *MockOutputMetricsFactory) CallCount() int {
	f.Mu.Lock()
	defer f.Mu.Unlock()
	return len(f.Calls)
}

// MetricsFor returns the MockOutputMetrics for the given key.
func (f *MockOutputMetricsFactory) MetricsFor(outputType, outputName string) *MockOutputMetrics {
	f.Mu.Lock()
	defer f.Mu.Unlock()
	return f.Metrics[outputType+":"+outputName]
}
