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

package steps

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/cucumber/godog"

	"github.com/axonops/audit"
	"github.com/axonops/audit/file"
)

// registerAsyncEdgesSteps registers BDD step definitions for async
// delivery edge-case scenarios (#564): sync-mode close, sync-mode
// panic isolation, buffer_size:0 coercion, and the delivery
// accounting invariant.
//
//nolint:gocognit,gocyclo,cyclop // BDD step registration: 4 closures inline; splitting hurts readability
func registerAsyncEdgesSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^an auditor with synchronous delivery, file output, and a panicking output$`, func() error {
		dir, err := tc.EnsureFileDir()
		if err != nil {
			return err
		}
		path := filepath.Join(dir, "audit.log")
		tc.FilePaths["default"] = path

		fileOut, err := file.New(&file.Config{Path: path})
		if err != nil {
			return fmt.Errorf("create file: %w", err)
		}
		tc.AddCleanup(func() { _ = fileOut.Close() })

		opts := []audit.Option{
			audit.WithTaxonomy(tc.Taxonomy),
			audit.WithAppName("test-app"),
			audit.WithHost("test-host"),
			audit.WithNamedOutput(fileOut),
			audit.WithNamedOutput(&panicOutput{}),
			audit.WithSynchronousDelivery(),
		}
		auditor, err := audit.New(opts...)
		if err != nil {
			return fmt.Errorf("create auditor: %w", err)
		}
		tc.Auditor = auditor
		tc.AddCleanup(func() { _ = auditor.Close() })
		return nil
	})

	ctx.Step(`^the effective output buffer capacity should be (\d+)$`, func(want int) error {
		if tc.Auditor != nil {
			_ = tc.Auditor.Close()
		}
		if tc.OutputMetricsMock == nil {
			return errors.New("no MockOutputMetrics configured — precede with 'a file output with buffer_size N and mock output metrics'")
		}
		tc.OutputMetricsMock.mu.Lock()
		defer tc.OutputMetricsMock.mu.Unlock()
		if len(tc.OutputMetricsMock.queueDs) == 0 {
			return errors.New("no RecordQueueDepth call recorded; the output never observed its queue")
		}
		got := tc.OutputMetricsMock.queueDs[len(tc.OutputMetricsMock.queueDs)-1].Capacity
		if got != want {
			return fmt.Errorf("expected effective buffer capacity %d, got %d", want, got)
		}
		return nil
	})

	ctx.Step(`^an auditor with a recording output, pipeline metrics, and synchronous delivery$`, func() error {
		if tc.MockMetrics == nil {
			tc.MockMetrics = NewMockMetrics()
		}

		// Use a non-DeliveryReporter output so RecordDelivery flows
		// through tc.MockMetrics. file/syslog/webhook/loki implement
		// DeliveryReporter and bypass core RecordDelivery — that path
		// has separate coverage; this scenario isolates the core
		// metrics invariant.
		rec := &recordingMockOutput{name: "recording"}

		opts := []audit.Option{
			audit.WithTaxonomy(tc.Taxonomy),
			audit.WithAppName("test-app"),
			audit.WithHost("test-host"),
			audit.WithMetrics(tc.MockMetrics),
			audit.WithOutputs(rec),
			audit.WithSynchronousDelivery(),
		}
		auditor, err := audit.New(opts...)
		if err != nil {
			return fmt.Errorf("create auditor: %w", err)
		}
		tc.Auditor = auditor
		tc.AddCleanup(func() { _ = auditor.Close() })
		return nil
	})

	ctx.Step(`^the delivery accounting invariant should hold$`, func() error {
		if tc.Auditor != nil {
			_ = tc.Auditor.Close()
		}
		if tc.MockMetrics == nil {
			return errors.New("no MockMetrics configured")
		}
		m := tc.MockMetrics
		m.mu.Lock()
		defer m.mu.Unlock()

		successes := 0
		for k, v := range m.Events {
			if strings.HasSuffix(k, ":success") {
				successes += v
			}
		}
		outputErrs := 0
		for _, v := range m.OutputErrors {
			outputErrs += v
		}
		filtered := 0
		for _, v := range m.Filtered {
			filtered += v
		}
		validation := 0
		for _, v := range m.ValidationErrors {
			validation += v
		}
		serial := 0
		for _, v := range m.SerializationErrs {
			serial += v
		}
		total := successes + outputErrs + filtered + validation + serial + m.BufferDrops
		if total != m.Submitted {
			return fmt.Errorf(
				"invariant broken: submitted=%d != successes=%d + output_errors=%d + filtered=%d + validation_errors=%d + serialization_errors=%d + buffer_drops=%d (sum=%d)",
				m.Submitted, successes, outputErrs, filtered, validation, serial, m.BufferDrops, total)
		}
		return nil
	})

	// --- #722: per-counter coverage for the delivery accounting
	// invariant. Three new given-steps + four new assertion steps
	// extend the contract surface so each counter in the invariant
	// equation is forced non-zero in at least one scenario.

	ctx.Step(`^an auditor with an error output, pipeline metrics, and synchronous delivery$`, func() error {
		if tc.MockMetrics == nil {
			tc.MockMetrics = NewMockMetrics()
		}
		auditor, err := audit.New(
			audit.WithTaxonomy(tc.Taxonomy),
			audit.WithAppName("test-app"),
			audit.WithHost("test-host"),
			audit.WithMetrics(tc.MockMetrics),
			audit.WithNamedOutput(&errorOutput{}),
			audit.WithSynchronousDelivery(),
		)
		if err != nil {
			return fmt.Errorf("create auditor: %w", err)
		}
		tc.Auditor = auditor
		tc.AddCleanup(func() { _ = auditor.Close() })
		return nil
	})

	ctx.Step(`^an auditor with an error-returning formatter, a recording output, pipeline metrics, and synchronous delivery$`, func() error {
		if tc.MockMetrics == nil {
			tc.MockMetrics = NewMockMetrics()
		}
		rec := &recordingMockOutput{name: "recording"}
		auditor, err := audit.New(
			audit.WithTaxonomy(tc.Taxonomy),
			audit.WithAppName("test-app"),
			audit.WithHost("test-host"),
			audit.WithMetrics(tc.MockMetrics),
			audit.WithFormatter(&errorReturningFormatter{}),
			audit.WithOutputs(rec),
			audit.WithSynchronousDelivery(),
		)
		if err != nil {
			return fmt.Errorf("create auditor: %w", err)
		}
		tc.Auditor = auditor
		tc.AddCleanup(func() { _ = auditor.Close() })
		return nil
	})

	ctx.Step(`^an auditor with a slow output, pipeline metrics, and async delivery with queue_size (\d+)$`, func(queueSize int) error {
		if tc.MockMetrics == nil {
			tc.MockMetrics = NewMockMetrics()
		}
		// 200 ms per write × queue_size 1. The drain goroutine
		// dequeues one event then blocks 200 ms inside Write — so
		// at any instant up to 2 events are in flight (1 in the
		// queue + 1 held by the drain goroutine). The producer
		// submits 200 events in sub-millisecond wall time, so
		// every submit beyond the second hits the queue-full
		// default branch and is dropped via RecordBufferDrop. The
		// "at least 1" assertion below is intentionally insensitive
		// to the configured ShutdownTimeout — Close abandoning
		// remaining queued events on timeout doesn't change the
		// result because the producer's drops were recorded at
		// submit time, not drain time (#722 AC #4).
		out := &slowMockOutput{delay: 200 * time.Millisecond}
		auditor, err := audit.New(
			audit.WithTaxonomy(tc.Taxonomy),
			audit.WithAppName("test-app"),
			audit.WithHost("test-host"),
			audit.WithMetrics(tc.MockMetrics),
			audit.WithOutputs(out),
			audit.WithQueueSize(queueSize),
		)
		if err != nil {
			return fmt.Errorf("create auditor: %w", err)
		}
		tc.Auditor = auditor
		tc.AddCleanup(func() { _ = auditor.Close() })
		return nil
	})

	ctx.Step(`^I audit (\d+) events with required fields$`, func(n int) error {
		if tc.Auditor == nil {
			return errors.New("no auditor configured")
		}
		// Use only required fields known to the standard test
		// taxonomy's user_create event (outcome, actor_id) so the
		// events pass validation in strict mode and reach the
		// queue. Unknown fields would be rejected with
		// ValidationError before enqueue, never producing a
		// BufferDrop.
		for i := 0; i < n; i++ {
			fields := audit.Fields{
				"actor_id": "u-1",
				"outcome":  "ok",
			}
			// Capture the last error into tc.LastErr so a
			// regression in the auditor (e.g. ErrLoggerClosed) is
			// visible to subsequent assertions. ErrQueueFull is
			// the expected error on overflow and is part of the
			// contract being tested.
			tc.LastErr = tc.Auditor.AuditEvent(audit.NewEvent("user_create", fields))
		}
		return nil
	})

	// The four counter assertions below assume the feature scenario
	// has already executed an explicit "I close the auditor" step.
	// They MUST NOT call Close themselves: doing so masks scenarios
	// that forget the explicit close, and conflates "assert" with
	// "tear down". Cleanup of the auditor is registered via
	// tc.AddCleanup in each given-step.

	ctx.Step(`^the OutputErrors counter should equal (\d+)$`, func(want int) error {
		if tc.MockMetrics == nil {
			return errors.New("no MockMetrics configured")
		}
		m := tc.MockMetrics
		m.mu.Lock()
		defer m.mu.Unlock()
		got := 0
		for _, v := range m.OutputErrors {
			got += v
		}
		if got != want {
			return fmt.Errorf("OutputErrors: want %d, got %d", want, got)
		}
		return nil
	})

	ctx.Step(`^the SerializationErrors counter should equal (\d+)$`, func(want int) error {
		if tc.MockMetrics == nil {
			return errors.New("no MockMetrics configured")
		}
		m := tc.MockMetrics
		m.mu.Lock()
		defer m.mu.Unlock()
		got := 0
		for _, v := range m.SerializationErrs {
			got += v
		}
		if got != want {
			return fmt.Errorf("SerializationErrors: want %d, got %d", want, got)
		}
		return nil
	})

	ctx.Step(`^the BufferDrops counter should be at least (\d+)$`, func(want int) error {
		if tc.MockMetrics == nil {
			return errors.New("no MockMetrics configured")
		}
		m := tc.MockMetrics
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.BufferDrops < want {
			return fmt.Errorf("BufferDrops: want >= %d, got %d", want, m.BufferDrops)
		}
		return nil
	})

	ctx.Step(`^Successes plus BufferDrops should equal (\d+)$`, func(want int) error {
		if tc.MockMetrics == nil {
			return errors.New("no MockMetrics configured")
		}
		m := tc.MockMetrics
		m.mu.Lock()
		defer m.mu.Unlock()
		successes := 0
		for k, v := range m.Events {
			if strings.HasSuffix(k, ":success") {
				successes += v
			}
		}
		got := successes + m.BufferDrops
		if got != want {
			return fmt.Errorf("successes (%d) + buffer_drops (%d) = %d, want %d",
				successes, m.BufferDrops, got, want)
		}
		return nil
	})
}
