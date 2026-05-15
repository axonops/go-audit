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

import (
	"bytes"
	"context"
	"fmt"
	"log"

	"github.com/axonops/audit"
)

func ExampleNew() {
	// Create a stdout output that writes to a buffer for this example.
	var buf bytes.Buffer
	stdout, err := audit.NewStdoutOutput(audit.StdoutConfig{Writer: &buf})
	if err != nil {
		log.Fatal(err)
	}

	auditor, err := audit.New(
		audit.WithTaxonomy(&audit.Taxonomy{
			Version: 1,
			Categories: map[string]*audit.CategoryDef{
				"write": {Events: []string{"user_create"}},
			},
			Events: map[string]*audit.EventDef{
				"user_create": {Required: []string{"outcome", "actor_id"}},
			},
		}),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		// Synchronous delivery — single-event docs example with no
		// async drain goroutine. Avoids a CI flake where loaded
		// runners can starve the drain goroutine past the default 5s
		// shutdown timeout, leaving it runnable when goleak runs.
		audit.WithSynchronousDelivery(),
		audit.WithOutputs(stdout),
	)
	if err != nil {
		log.Fatal(err)
	}

	// Emit an event — synchronous delivery means the buffer is
	// populated before AuditEvent returns; no Close-before-assert
	// ceremony is needed.
	if err := auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
	})); err != nil {
		log.Fatal(err)
	}

	// Close is still called for symmetry; in synchronous mode it is
	// effectively a no-op for delivery and only closes outputs.
	if err := auditor.Close(); err != nil {
		log.Fatal(err)
	}

	// The buffer now contains the JSON-serialised event.
	fmt.Println("has event_type:", bytes.Contains(buf.Bytes(), []byte(`"event_type":"user_create"`)))
	fmt.Println("has actor_id:", bytes.Contains(buf.Bytes(), []byte(`"actor_id":"alice"`)))
	// Output:
	// has event_type: true
	// has actor_id: true
}

func ExampleAuditor_AuditEvent() {
	var buf bytes.Buffer
	stdout, err := audit.NewStdoutOutput(audit.StdoutConfig{Writer: &buf})
	if err != nil {
		log.Fatal(err)
	}

	auditor, err := audit.New(
		audit.WithTaxonomy(&audit.Taxonomy{
			Version:    1,
			Categories: map[string]*audit.CategoryDef{"write": {Events: []string{"doc_create"}}},
			Events: map[string]*audit.EventDef{
				"doc_create": {Required: []string{"outcome"}},
			},
		}),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		// Synchronous delivery — see ExampleNew for rationale.
		audit.WithSynchronousDelivery(),
		audit.WithOutputs(stdout),
	)
	if err != nil {
		log.Fatal(err)
	}

	if err = auditor.AuditEvent(audit.NewEvent("doc_create", audit.Fields{"outcome": "success"})); err != nil {
		fmt.Println("audit error:", err)
		return
	}

	if err = auditor.Close(); err != nil {
		log.Fatal(err)
	}

	// The event is now in the buffer as a JSON line.
	fmt.Println("has event_type:", bytes.Contains(buf.Bytes(), []byte(`"event_type":"doc_create"`)))
	fmt.Println("has outcome:", bytes.Contains(buf.Bytes(), []byte(`"outcome":"success"`)))
	// Output:
	// has event_type: true
	// has outcome: true
}

func ExampleAuditor_MustHandle() {
	auditor, err := audit.New(
		audit.WithTaxonomy(&audit.Taxonomy{
			Version:    1,
			Categories: map[string]*audit.CategoryDef{"write": {Events: []string{"doc_create"}}},
			Events: map[string]*audit.EventDef{
				"doc_create": {Required: []string{"outcome"}},
			},
		}),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithSynchronousDelivery(), // deterministic for goleak under loaded CI runners
	)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if closeErr := auditor.Close(); closeErr != nil {
			log.Printf("audit close: %v", closeErr)
		}
	}()

	// Get a handle for zero-allocation audit calls.
	docCreate := auditor.MustHandle("doc_create")

	if err = docCreate.Audit(audit.Fields{"outcome": "success"}); err != nil {
		fmt.Println("audit error:", err)
		return
	}

	fmt.Println("handle event type:", docCreate.EventType())
	// Output: handle event type: doc_create
}

// ExampleAuditor_Handle demonstrates the EventHandle metadata
// accessors (#597) — Description, Categories with severity, and
// FieldInfoMap with required/optional flags. Middleware and other
// consumers can introspect a handle without constructing an event.
func ExampleAuditor_Handle() {
	sev := 7
	auditor, err := audit.New(
		audit.WithTaxonomy(&audit.Taxonomy{
			Version: 1,
			Categories: map[string]*audit.CategoryDef{
				"security": {Events: []string{"auth_failure"}, Severity: &sev},
			},
			Events: map[string]*audit.EventDef{
				"auth_failure": {
					Description: "Failed authentication attempt",
					Required:    []string{"outcome", "actor_id"},
				},
			},
		}),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithSynchronousDelivery(),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = auditor.Close() }()

	h, err := auditor.Handle("auth_failure")
	if err != nil {
		fmt.Println("handle error:", err)
		return
	}

	fmt.Println("description:", h.Description())
	for _, c := range h.Categories() {
		if c.Severity != nil {
			fmt.Printf("category: %s (severity=%d)\n", c.Name, *c.Severity)
		}
	}
	fmt.Println("outcome required:", h.FieldInfoMap()["outcome"].Required)
	// Output:
	// description: Failed authentication attempt
	// category: security (severity=7)
	// outcome required: true
}

func ExampleAuditor_EnableCategory() {
	auditor, err := audit.New(
		audit.WithTaxonomy(&audit.Taxonomy{
			Version: 1,
			Categories: map[string]*audit.CategoryDef{
				"read":  {Events: []string{"doc_read"}},
				"write": {Events: []string{"doc_create"}},
			},
			Events: map[string]*audit.EventDef{
				"doc_read":   {Required: []string{"outcome"}},
				"doc_create": {Required: []string{"outcome"}},
			},
		}),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithSynchronousDelivery(),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := auditor.Close(); err != nil {
			log.Printf("audit close: %v", err)
		}
	}()

	// "read" category is disabled by default. Enable it at runtime.
	if err := auditor.EnableCategory("read"); err != nil {
		fmt.Println("enable error:", err)
		return
	}

	fmt.Println("read category enabled")
	// Output: read category enabled
}

func ExampleAuditor_Close() {
	auditor, err := audit.New(
		audit.WithTaxonomy(&audit.Taxonomy{
			Version:    1,
			Categories: map[string]*audit.CategoryDef{"write": {Events: []string{"doc_create"}}},
			Events: map[string]*audit.EventDef{
				"doc_create": {Required: []string{"outcome"}},
			},
		}),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithSynchronousDelivery(),
	)
	if err != nil {
		log.Fatal(err)
	}

	// Best practice: defer Close immediately after creation.
	defer func() {
		if err := auditor.Close(); err != nil {
			log.Printf("audit close: %v", err)
		}
	}()

	fmt.Println("auditor will be closed on function exit")
	// Output: auditor will be closed on function exit
}

func ExampleWithFormatter() {
	cef := &audit.CEFFormatter{
		Vendor:  "MyCompany",
		Product: "MyApp",
		Version: "1.0",
		SeverityFunc: func(eventType string) int {
			if eventType == "auth_failure" {
				return 8
			}
			return 5
		},
	}

	auditor, err := audit.New(
		audit.WithTaxonomy(&audit.Taxonomy{
			Version:    1,
			Categories: map[string]*audit.CategoryDef{"security": {Events: []string{"auth_failure"}}},
			Events: map[string]*audit.EventDef{
				"auth_failure": {Required: []string{"outcome"}},
			},
		}),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithFormatter(cef),
		audit.WithSynchronousDelivery(),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := auditor.Close(); err != nil {
			log.Printf("audit close: %v", err)
		}
	}()

	fmt.Println("CEF formatter configured")
	// Output: CEF formatter configured
}

func ExampleNewStdoutOutput() {
	// Create a stdout output for development/debugging. When Writer is
	// nil, os.Stdout is used. Here we use a bytes.Buffer for testing.
	var buf bytes.Buffer
	out, err := audit.NewStdoutOutput(audit.StdoutConfig{
		Writer: &buf,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = out.Close() }()

	fmt.Println("stdout output:", out.Name())
	// Output: stdout output: stdout
}

func ExampleEventRoute_include() {
	// Include mode: only security events are delivered to this output.
	route := audit.EventRoute{
		IncludeCategories: map[string]audit.SeverityRange{"security": {}},
	}
	fmt.Println("empty:", route.IsEmpty())
	// Output: empty: false
}

func ExampleEventRoute_exclude() {
	// Exclude mode: all events except reads are delivered.
	route := audit.EventRoute{
		ExcludeCategories: []string{"read"},
	}
	fmt.Println("empty:", route.IsEmpty())
	// Output: empty: false
}

func ExampleEventRoute_perCategorySeverity() {
	// Per-category severity: the value's SeverityRange constrains
	// each included category independently. The zero value
	// SeverityRange{} means "no severity constraint" — the
	// category is included at every severity.
	sev7 := 7
	route := audit.EventRoute{
		IncludeCategories: map[string]audit.SeverityRange{
			"security": {MinSeverity: &sev7}, // sev 7+ only
			"read":     {},                   // all severities
		},
	}
	fmt.Println("empty:", route.IsEmpty())
	// Output: empty: false
}

func ExampleAuditor_SetOutputRoute() {
	var buf bytes.Buffer
	out, err := audit.NewStdoutOutput(audit.StdoutConfig{Writer: &buf})
	if err != nil {
		log.Fatal(err)
	}

	auditor, err := audit.New(
		audit.WithTaxonomy(&audit.Taxonomy{
			Version: 1,
			Categories: map[string]*audit.CategoryDef{
				"write":    {Events: []string{"user_create"}},
				"security": {Events: []string{"auth_failure"}},
			},
			Events: map[string]*audit.EventDef{
				"user_create":  {Required: []string{"outcome"}},
				"auth_failure": {Required: []string{"outcome"}},
			},
		}),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(out, audit.WithRoute(&audit.EventRoute{})),
		audit.WithSynchronousDelivery(),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if closeErr := auditor.Close(); closeErr != nil {
			log.Printf("audit close: %v", closeErr)
		}
	}()

	// Restrict output to security events only at runtime.
	if err := auditor.SetOutputRoute("stdout", &audit.EventRoute{
		IncludeCategories: map[string]audit.SeverityRange{"security": {}},
	}); err != nil {
		fmt.Println("route error:", err)
		return
	}

	fmt.Println("route set to security only")
	// Output: route set to security only
}

// ExampleAuditor_AuditEventContext demonstrates the ctx-aware emit
// path (#600). When a request-scoped context is cancelled or its
// deadline expires before the audit pipeline accepts the event, the
// call returns the ctx error and the event is dropped — useful for
// graceful-shutdown scenarios where you want to abandon partially
// completed work without waiting for the audit buffer to flush.
//
// Note: trace-correlation plumbing (e.g. extracting a `trace_id`
// from ctx and emitting it as a framework field) is deferred to a
// post-v1.0 follow-up issue — for now consumers extract correlation
// values from ctx in their EventBuilder or before calling
// AuditEventContext.
func ExampleAuditor_AuditEventContext() {
	auditor, err := audit.New(
		audit.WithTaxonomy(&audit.Taxonomy{
			Version:    1,
			Categories: map[string]*audit.CategoryDef{"write": {Events: []string{"doc_create"}}},
			Events: map[string]*audit.EventDef{
				"doc_create": {Required: []string{"outcome"}},
			},
		}),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithSynchronousDelivery(),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = auditor.Close() }()

	// Already-cancelled ctx — call returns context.Canceled.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	emitErr := auditor.AuditEventContext(ctx, audit.NewEvent("doc_create", audit.Fields{
		"outcome": "success",
	}))
	fmt.Println("emit error:", emitErr)
	// Output: emit error: context canceled
}

// ExampleFieldsDonor demonstrates how to verify that an event satisfies
// the [audit.FieldsDonor] extension interface — the trigger for the
// auditor's zero-allocation fast path on the drain side. Generated
// builders from cmd/audit-gen satisfy this interface via the unexported
// donateFields() sentinel; no third party can satisfy it (by design).
//
// Events constructed via [audit.NewEvent] or [audit.NewEventKV] do NOT
// satisfy FieldsDonor and stay on the defensive-copy slow path. This is
// intentional — the donor contract requires a no-mutate, no-retain
// guarantee that only the audit-gen toolchain enforces.
//
// For the fast-path / slow-path ownership model see
// https://github.com/axonops/audit/blob/main/docs/performance.md.
func ExampleFieldsDonor() {
	evt := audit.NewEvent("user_create", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
	})

	_, isDonor := evt.(audit.FieldsDonor)
	fmt.Println("NewEvent is a FieldsDonor:", isDonor)

	// Output:
	// NewEvent is a FieldsDonor: false
}
