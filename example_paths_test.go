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

// This file holds the integration-path Examples added by #467 PR B —
// the canonical patterns a new consumer (or an AI coding assistant)
// should see on pkg.go.dev when figuring out how to integrate the
// library. Each Example uses WithSynchronousDelivery() ONLY so the
// // Output: assertion is deterministic; production code should
// omit it (async is the default and the right choice).

package audit_test

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"testing"

	"github.com/axonops/audit"
	"github.com/axonops/audit/audittest"
)

// exampleTaxonomyYAML is the inline taxonomy reused across the
// integration-path examples in this file. Real projects load this
// from an `//go:embed`-ed file and parse with [audit.ParseTaxonomyYAML].
const exampleTaxonomyYAML = `
version: 1
categories:
  identity:
    - user_login
    - user_logout
events:
  user_login:
    description: Successful or failed authentication attempt.
    fields:
      actor_id: {required: true}
      outcome: {required: true}
  user_logout:
    description: User-initiated session termination.
    fields:
      actor_id: {required: true}
`

// ExampleAuditor_withYAMLConfig shows the production-style declarative
// setup: a taxonomy loaded from embedded YAML, an outputs
// configuration loaded via [outputconfig.New] (a separate
// sub-module), one event emitted, deferred Close.
//
// In a real project the taxonomy and outputs YAML are typically
// `//go:embed`-ed or loaded from disk; here they're inline so the
// Example is self-contained. For the full YAML-driven recipe see
// the `outputconfig` sub-module documentation.
func ExampleAuditor_withYAMLConfig() {
	// Parse the taxonomy. ParseTaxonomyYAML migrates, validates,
	// and precomputes — pass the result straight to WithTaxonomy.
	tax, err := audit.ParseTaxonomyYAML([]byte(exampleTaxonomyYAML))
	if err != nil {
		log.Fatal(err)
	}

	// For the documented YAML-config path see outputconfig.New;
	// here we wire a stdout output in code to keep the example
	// self-contained.
	var buf bytes.Buffer
	stdout, err := audit.NewStdoutOutput(audit.StdoutConfig{Writer: &buf})
	if err != nil {
		log.Fatal(err)
	}

	auditor, err := audit.New(
		audit.WithTaxonomy(tax),
		audit.WithAppName("inventory-api"),
		audit.WithHost("inventory-01"),
		// WithSynchronousDelivery makes this example deterministic.
		// In production, omit this — async is the default and the
		// right choice.
		audit.WithSynchronousDelivery(),
		audit.WithOutputs(stdout),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = auditor.Close() }()

	if err := auditor.AuditEvent(audit.NewEvent("user_login", audit.Fields{
		"actor_id": "alice",
		"outcome":  "success",
	})); err != nil {
		// In real code use log.Printf / return err so the deferred
		// Close still runs; log.Fatal here would skip the defer.
		fmt.Println("emit:", err)
		return
	}

	fmt.Println("delivered:", bytes.Contains(buf.Bytes(), []byte(`"event_type":"user_login"`)))
	// Output:
	// delivered: true
}

// ExampleAuditor_testing shows the canonical pattern for testing
// code that emits audit events. [audittest.NewQuick] (in the
// audit/audittest sub-module) constructs an [audit.Auditor] with an
// in-memory recorder and a permissive ad-hoc taxonomy listing only
// the event types your tests need — no YAML file required.
//
// In a real *_test.go file the `t := &testing.T{}` line is replaced
// with the test's own `t *testing.T` parameter.
func ExampleAuditor_testing() {
	t := &testing.T{}

	auditor, events, _ := audittest.NewQuick(t, "user_login")

	// In a real test, the code under test runs here and emits
	// events via the auditor; we emit one directly to demonstrate
	// the recorder catching it.
	_ = auditor.AuditEvent(audit.NewEvent("user_login", audit.Fields{
		"actor_id": "alice",
		"outcome":  "success",
	}))

	fmt.Println("recorded:", events.Count())
	fmt.Println("type:", events.Events()[0].EventType)
	// Output:
	// recorded: 1
	// type: user_login
}

// ExampleNewEventKV shows dynamic event construction without code
// generation, using the [log/slog]-style key/value variadic form.
// The function returns TWO error paths a caller MUST distinguish:
//
//   - The error from NewEventKV itself is a PROGRAMMER error
//     (odd number of arguments, non-string key) — never recoverable
//     at runtime; log and abort.
//   - The error from [Auditor.AuditEvent] is a RUNTIME error
//     (validation failure, queue full, auditor closed) — handle
//     per the error catalogue on AuditEvent's godoc.
//
// Examples in this codebase MUST check the construction error;
// silently discarding it produces dead error-handling code in
// downstream copy-paste consumers.
func ExampleNewEventKV() {
	tax, err := audit.ParseTaxonomyYAML([]byte(exampleTaxonomyYAML))
	if err != nil {
		log.Fatal(err)
	}
	var buf bytes.Buffer
	stdout, _ := audit.NewStdoutOutput(audit.StdoutConfig{Writer: &buf})
	auditor, err := audit.New(
		audit.WithTaxonomy(tax),
		audit.WithAppName("inventory-api"),
		audit.WithHost("inventory-01"),
		audit.WithSynchronousDelivery(), // see file header — omit in prod
		audit.WithOutputs(stdout),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = auditor.Close() }()

	// Construction error path — handle separately from emission.
	evt, err := audit.NewEventKV("user_login",
		"actor_id", "alice",
		"outcome", "success",
	)
	if err != nil {
		// Programmer error (odd args or non-string key). In real
		// code this is a startup-time panic or `log.Printf` + return
		// — surface but let the deferred Close still run.
		fmt.Println("event construction:", err)
		return
	}

	// Runtime error path — validation, queue, or closed.
	if err := auditor.AuditEvent(evt); err != nil {
		// In production, route by errors.Is on the catalogue from
		// AuditEvent's godoc. See ExampleAuditor_errorHandling.
		fmt.Println("audit emit:", err)
		return
	}

	fmt.Println("delivered:", bytes.Contains(buf.Bytes(), []byte(`"actor_id":"alice"`)))
	// Output:
	// delivered: true
}

// ExampleAuditor_gracefulShutdown shows the canonical signal-driven
// shutdown for a long-running service. Close blocks until the drain
// goroutine flushes every buffered event (up to
// [WithShutdownTimeout]; default 5s). Failing to call Close leaks
// the drain goroutine AND loses every event still in the buffer.
//
// In a real service the `shutdown` channel is closed by a SIGINT /
// SIGTERM handler (e.g. via [os/signal.NotifyContext]); here we
// close it directly to keep the Example deterministic.
func ExampleAuditor_gracefulShutdown() {
	tax, err := audit.ParseTaxonomyYAML([]byte(exampleTaxonomyYAML))
	if err != nil {
		log.Fatal(err)
	}
	var buf bytes.Buffer
	stdout, _ := audit.NewStdoutOutput(audit.StdoutConfig{Writer: &buf})
	auditor, err := audit.New(
		audit.WithTaxonomy(tax),
		audit.WithAppName("inventory-api"),
		audit.WithHost("inventory-01"),
		audit.WithSynchronousDelivery(), // see file header — omit in prod
		audit.WithOutputs(stdout),
	)
	if err != nil {
		log.Fatal(err)
	}

	// Simulate the service emitting events for a while.
	for i := 0; i < 3; i++ {
		_ = auditor.AuditEvent(audit.NewEvent("user_login", audit.Fields{
			"actor_id": fmt.Sprintf("user-%d", i),
			"outcome":  "success",
		}))
	}

	// Production placement: in main(), pair the auditor construction
	// with a deferred Close immediately. The signal handler then
	// returns from main(), triggering the deferred Close.
	//
	//	ctx, stop := signal.NotifyContext(context.Background(),
	//	    syscall.SIGINT, syscall.SIGTERM)
	//	defer stop()
	//	auditor, err := audit.New(/* options */)
	//	if err != nil { return err }
	//	defer func() { _ = auditor.Close() }()
	//	// ... service runs ...
	//	<-ctx.Done()
	//	// defer runs Close which flushes the buffer.
	if err := auditor.Close(); err != nil {
		// A Close error indicates an output's Close returned an
		// error (e.g. file flush failed). Buffered events have
		// still been drained as far as possible; surface the error
		// in service logs so an operator can investigate.
		log.Printf("audit shutdown: %v", err)
	}

	// Close is idempotent — the second call returns the same
	// result as the first.
	fmt.Println("close idempotent:", auditor.Close() == nil)
	fmt.Println("events delivered:", bytes.Count(buf.Bytes(), []byte(`"event_type":"user_login"`)))
	// Output:
	// close idempotent: true
	// events delivered: 3
}

// ExampleAuditor_errorHandling shows the production-grade
// error-handling pattern for [Auditor.AuditEvent]. The error
// catalogue on AuditEvent's godoc enumerates the sentinels a
// caller might see; this Example demonstrates the dispatch.
//
// Use [errors.Is] for discrimination (the project convention;
// string matching is forbidden). Validation errors wrap
// [ErrValidation] AND a specific sub-sentinel; both checks work.
func ExampleAuditor_errorHandling() {
	tax, err := audit.ParseTaxonomyYAML([]byte(exampleTaxonomyYAML))
	if err != nil {
		log.Fatal(err)
	}
	var buf bytes.Buffer
	stdout, _ := audit.NewStdoutOutput(audit.StdoutConfig{Writer: &buf})
	auditor, err := audit.New(
		audit.WithTaxonomy(tax),
		audit.WithAppName("inventory-api"),
		audit.WithHost("inventory-01"),
		audit.WithSynchronousDelivery(), // see file header — omit in prod
		audit.WithOutputs(stdout),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = auditor.Close() }()

	// classify maps an AuditEvent error to one of three actions a
	// production service typically takes. Real implementations
	// route via metrics, structured logging, or backpressure.
	classify := func(err error) string {
		switch {
		case err == nil:
			return "ok"
		case errors.Is(err, audit.ErrQueueFull):
			// Drop notification — under load. Often acceptable;
			// surface via metrics.
			return "drop:queue-full"
		case errors.Is(err, audit.ErrClosed):
			// Auditor was shut down. Stop emitting; do not retry.
			return "stop:closed"
		case errors.Is(err, audit.ErrValidation):
			// Programmer error — the event doesn't match the
			// taxonomy. In strict mode this is a bug, not a
			// runtime condition. Fail loudly.
			return "bug:validation"
		default:
			return "other"
		}
	}

	// Valid event — succeeds.
	good := audit.NewEvent("user_login", audit.Fields{
		"actor_id": "alice", "outcome": "success",
	})
	fmt.Println("valid event:", classify(auditor.AuditEvent(good)))

	// Unknown event type — wraps ErrValidation + ErrUnknownEventType.
	bad := audit.NewEvent("nonexistent_event", audit.Fields{})
	fmt.Println("unknown type:", classify(auditor.AuditEvent(bad)))

	// Missing required field (taxonomy declares actor_id required).
	incomplete := audit.NewEvent("user_login", audit.Fields{"outcome": "success"})
	fmt.Println("missing field:", classify(auditor.AuditEvent(incomplete)))

	// Output:
	// valid event: ok
	// unknown type: bug:validation
	// missing field: bug:validation
}
