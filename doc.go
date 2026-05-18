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

// Package audit provides a standalone, taxonomy-driven audit logging framework
// for Go applications.
//
// The library validates every audit event against a consumer-defined taxonomy,
// delivers events asynchronously via a buffered channel, and fans out to
// multiple configurable outputs.
//
// # Multi-Module Structure
//
// Output backends live in separate Go modules so consumers import only
// what they need:
//
//   - github.com/axonops/audit — core (this package; depends on github.com/goccy/go-yaml for [ParseTaxonomyYAML])
//   - github.com/axonops/audit/file — file output with rotation
//   - github.com/axonops/audit/syslog — RFC 5424 syslog (TCP/UDP/TLS)
//   - github.com/axonops/audit/webhook — batched HTTP webhook
//   - github.com/axonops/audit/loki — Grafana Loki output with stream labels
//   - github.com/axonops/audit/outputconfig — YAML-based output configuration
//   - github.com/axonops/audit/outputs — convenience: blank-import to register all output types
//   - github.com/axonops/audit/secrets — secret provider interface for ref+ URI resolution
//
// [StdoutOutput] and the audittest package ship with core and require
// no additional import.
//
// # Stability
//
// This package follows semantic versioning. The public API is stable as
// of v1.0.0; breaking changes will not be introduced within a major
// version.
//
// # Quick Start
//
// Define your events in a YAML taxonomy, configure outputs in a second YAML
// file, and create an auditor with a single call:
//
//	//go:embed taxonomy.yaml
//	var taxonomyYAML []byte
//
//	auditor, err := outputconfig.New(ctx, taxonomyYAML, "outputs.yaml")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer func() { _ = auditor.Close() }()
//
//	err = auditor.AuditEvent(audit.MustNewEventKV("user_create",
//	    "outcome", "success",
//	    "actor_id", "alice",
//	))
//
// For exploration without YAML files, use [DevTaxonomy] and [NewStdout]:
//
//	stdout, _ := audit.NewStdout()
//	auditor, err := audit.New(
//	    audit.WithTaxonomy(audit.DevTaxonomy("user_create")),
//	    audit.WithAppName("demo"),
//	    audit.WithHost("localhost"),
//	    audit.WithOutputs(stdout),
//	)
//
// See the progressive examples in the examples/ directory for complete
// working applications.
//
// # Core API
//
//   - [Auditor] — core type; created via [New]
//   - [Option] — functional option for [New]: [WithTaxonomy], [WithOutputs],
//     [WithFormatter], [WithMetrics], [WithQueueSize], [WithShutdownTimeout],
//     [WithValidationMode], [WithOmitEmpty]
//
// # Events
//
// There are three emission paths, in order of recommendation:
//
//  1. Generated typed builders from cmd/audit-gen — compile-time
//     field safety, built-in [FieldsDonor] sentinel for the
//     zero-drain-side-allocations fast path. Use these whenever
//     event types are known at compile time.
//  2. [EventHandle] obtained via [Auditor.Handle] or
//     [Auditor.MustHandle] — the recommended path when the event
//     type is known at startup but not at compile time (from
//     configuration, a database, or a plugin registry). Cache the
//     handle at startup; per-event calls via [EventHandle.Audit]
//     skip the basicEvent allocation that [NewEvent] pays via
//     interface escape.
//  3. [NewEvent] and [NewEventKV] — the map-based escape hatch for
//     ad-hoc emission and quick exploration. Each call allocates
//     one basicEvent on the heap (interface escape); [NewEventKV]
//     additionally allocates the intermediate [Fields] map.
//
// Symbols in this group:
//
//   - [Event] — interface for typed audit events; pass to [Auditor.AuditEvent]
//   - [Auditor.AuditEvent] — emit an event with [context.Background] (convenience wrapper)
//   - [Auditor.AuditEventContext] — emit with a request-scoped [context.Context] for cancellation / deadline propagation (#600)
//   - [Auditor.Logger] — read the diagnostic logger configured via [WithDiagnosticLogger] (runtime swap dropped in #696)
//   - [EventHandle] — pre-validated handle for zero-caller-side-allocation audit calls; see [Auditor.Handle] and [Auditor.MustHandle]
//   - [EventHandle.Audit] / [EventHandle.AuditContext] — handle-side ctx-aware variants
//   - [EventHandle.AuditEvent] / [EventHandle.AuditEventContext] — handle-side event-typed variants
//   - [NewEvent] — creates an event for dynamic use without code generation
//   - [NewEventKV] — creates an event from alternating key-value pairs (slog-style)
//   - [Fields] — defined type over map[string]any with [Fields.Has], [Fields.String], [Fields.Int] accessors
//
// See docs/event-emission-paths.md for a side-by-side comparison of
// the three paths with examples and benchmark numbers.
//
// # Outputs
//
//   - [Output] — interface for audit event destinations (file, syslog, webhook, stdout)
//   - [Stdout] — convenience constructor for [StdoutOutput] writing to [os.Stdout]
//   - [StdoutOutput] — writes events to stdout or any io.Writer; included in core
//   - [WithOutputs] — registers unnamed outputs; [WithNamedOutput] for per-output routing
//   - [DeliveryReporter] — optional interface for outputs that handle their own delivery metrics
//   - [MetadataWriter] — optional interface for outputs that need structured per-event context (event type, severity, category, timestamp)
//   - [EventMetadata] — per-event value type passed to [MetadataWriter.WriteWithMetadata]
//
// # Formatters
//
//   - [Formatter] — interface for event serialisation
//   - [JSONFormatter] — default; line-delimited JSON with deterministic field order
//   - [CEFFormatter] — Common Event Format for SIEM integration (Splunk, ArcSight, QRadar)
//   - [FormatOptions] — per-output context for sensitivity label exclusion
//
// # Taxonomy
//
//   - [Taxonomy] — consumer-defined event schema; registered via [WithTaxonomy]
//   - [EventDef] — definition of a single event type's required and optional fields
//   - [CategoryDef] — category grouping with optional default severity
//   - [DevTaxonomy] — creates a permissive development taxonomy (not for production)
//   - [ParseTaxonomyYAML] — parses a YAML document into a [Taxonomy]; use with //go:embed
//   - [ValidateTaxonomy] — validates a [Taxonomy] for internal consistency
//   - [SensitivityConfig] — sensitivity label definitions for field classification
//   - [SensitivityLabel] — a single label with global field mappings and regex patterns
//
// # Generated Typed Event Builders
//
// The `cmd/audit-gen` code generator reads a taxonomy YAML and
// emits a Go source file containing type-safe constants (event
// types, categories, field names), per-event builder types with
// required-field constructor parameters and optional-field setter
// methods, and an [Event]-implementing struct that opts into the
// zero-extra-allocation [FieldsDonor] fast path. Generated builders
// are the recommended consumer pattern — see
// `examples/02-code-generation/` in the source tree for a full
// worked example (taxonomy YAML → generated Go → consumer wiring).
//
//	//go:generate go run github.com/axonops/audit/cmd/audit-gen \
//	    -input taxonomy.yaml -output audit_generated.go -package myapp
//
// For dynamic event construction without code generation (tests,
// table-driven cases, runtime-shaped events) use [NewEvent] or
// [NewEventKV] — see those godoc and the package-level Example
// functions for the patterns.
//
// # Event Routing
//
//   - [EventRoute] — per-output event filter (include/exclude categories, severity range)
//   - [ValidateEventRoute] — validates route configuration against a taxonomy
//   - [MatchesRoute] — checks whether an event matches a route filter
//
// # HTTP Middleware
//
//   - [Middleware] — wraps an HTTP handler to capture request metadata for audit logging
//   - [Hints] — per-request audit metadata populated by handlers via [HintsFromContext]
//   - [TransportMetadata] — auto-captured HTTP fields (client IP, method, status code, duration)
//   - [EventBuilder] — callback that transforms hints + transport into an audit event
//
// # Metrics
//
//   - [Metrics] — optional instrumentation interface; track deliveries, drops, and errors
//
// # Introspection
//
// The auditor exposes runtime introspection primitives for operators:
//
//   - [Auditor.QueueLen], [Auditor.QueueCap] — core queue saturation
//   - [Auditor.OutputNames] — names of configured outputs
//   - [Auditor.IsDisabled] — whether the auditor is a no-op
//   - [Auditor.LastDeliveryAge] — duration since each output last
//     delivered successfully; use in /healthz handlers to detect
//     silently-stalled async outputs (TCP half-open, retries
//     exhausted) where Write enqueues succeed but no events ever land.
//     See examples/16-health-endpoint for a runnable /healthz pattern.
//
// # Error Discrimination
//
// Validation errors returned by [Auditor.AuditEvent] wrap [ErrValidation]
// as a parent sentinel. Specific sub-sentinels identify the failure:
//
//   - [ErrUnknownEventType] — event type not in taxonomy
//   - [ErrMissingRequiredField] — required fields absent
//   - [ErrUnknownField] — unrecognised fields (strict mode only)
//
// Use [errors.Is] to match broadly or narrowly:
//
//	if errors.Is(err, audit.ErrValidation) { /* any validation failure */ }
//	if errors.Is(err, audit.ErrUnknownEventType) { /* specific case */ }
//
// Use [errors.As] to access the [ValidationError] struct:
//
//	var ve *audit.ValidationError
//	if errors.As(err, &ve) { log.Println(ve.Error()) }
//
// [ErrQueueFull] and [ErrClosed] are NOT validation errors and will
// never match [ErrValidation].
//
// # Code Generation Support
//
//   - [LabelInfo] — sensitivity label descriptor; embedded in [FieldInfo]
//   - [FieldInfo] — field descriptor with name, required flag, and labels; returned by generated builders
//   - [CategoryInfo] — category descriptor with name and optional severity; returned by generated builders
//
// # Advanced
//
//   - [OutputFactory] — function signature for output factory registration
//   - [RegisterOutputFactory] — registers a factory by type name (used by output modules)
//   - [LookupOutputFactory] — retrieves a registered factory by type name
//   - [TLSPolicy] — shared TLS version and cipher suite policy for outputs
//   - [HMACConfig] — per-output HMAC integrity configuration
//   - [ComputeHMAC] — computes HMAC over a payload, returns lowercase hex
//   - [VerifyHMAC] — verifies an HMAC value matches a payload
//   - [ValidateHMACConfig] — validates HMAC configuration at startup
//   - [OutputOption] — per-output configuration for [WithNamedOutput]: [WithRoute], [WithOutputFormatter], [WithExcludeLabels], [WithHMAC]
//   - [MigrateTaxonomy] — applies version migration to a [Taxonomy]
//
// # How Taxonomy Validation Works
//
// The framework does not hardcode event types, field names, or categories.
// Consumers register their entire audit taxonomy at bootstrap via
// [WithTaxonomy]. The framework then validates every [Auditor.AuditEvent] call
// against the registered definitions, catching missing required fields,
// unknown event types, and unrecognised field names at runtime.
//
// # Sensitivity Labels
//
// Consumers MAY define sensitivity labels in [SensitivityConfig] to classify
// fields (e.g., "pii", "financial"). Labels are assigned to fields via three
// mechanisms: explicit per-event annotation in the YAML fields: map, global
// field name mapping in [SensitivityLabel.Fields], and regex patterns in
// [SensitivityLabel.Patterns]. Per-output field stripping is configured via
// [WithNamedOutput] using the excludeLabels parameter. Framework fields
// (timestamp, event_type, severity, duration_ms, event_category,
// app_name, host, timezone, pid) are never stripped.
//
// # Reserved Standard Fields
//
// The library defines 31 well-known audit field names (actor_id,
// source_ip, reason, target_id, etc.) that are always accepted without
// taxonomy declaration. These reserved standard fields have generated
// setter methods on every builder and map to standard ArcSight CEF
// extension keys. See [ReservedStandardFieldNames] for the complete list.
//
// # Framework Fields
//
// Every serialised event includes framework fields that identify
// the deployment: app_name, host, timezone (set via [WithAppName],
// [WithHost], [WithTimezone] or outputs YAML), and pid (auto-captured
// via os.Getpid). These fields cannot be stripped by sensitivity labels
// and are emitted in both JSON and CEF output.
//
// # Async Delivery
//
// Events are enqueued to a buffered channel (configurable capacity, default
// 10,000) and drained by a single background goroutine. If the buffer is
// full, [Auditor.AuditEvent] returns [ErrQueueFull] and the drop is recorded via
// the [Metrics] interface.
//
// # Performance — Fast Path and Slow Path
//
// The drain pipeline has two paths with distinct allocation profiles. See
// docs/performance.md for the full table and benchmark methodology.
//
//   - Fast path: events constructed via cmd/audit-gen-generated typed
//     builders satisfy the [FieldsDonor] extension interface (unexported
//     sentinel donateFields()), and the auditor takes ownership of the
//     event's Fields map. The formatter writes into a pool-leased
//     *bytes.Buffer that is shared across every output and category pass
//     for the same event; per-output post-fields (event_category,
//     _hmac_version, _hmac) are appended in place into a per-event
//     scratch buffer.
//     This path achieves zero allocations on the drain side after warm-up.
//
//   - Slow path: events constructed via [NewEvent] or [NewEventKV] do
//     not implement FieldsDonor, so the auditor defensively copies the
//     caller's Fields map. Per-event allocation cost is the map clone
//     plus any-boxing of non-string values, plus one basicEvent on
//     the heap from the interface escape. The drain-side serialisation
//     still benefits from the zero-copy buffer lease. When the event
//     type is dynamic but known at startup, [EventHandle.Audit]
//     eliminates the basicEvent allocation (no interface escape)
//     while still taking the same defensive-copy path for the Fields
//     map.
//
// Outputs receive bytes from the leased formatter buffer. Per the
// [Output.Write] contract, implementations MUST NOT retain data past
// the call — all first-party outputs (file, syslog, webhook, loki) copy
// on enqueue.
//
// # Graceful Shutdown
//
// [Auditor.Close] MUST be called when the auditor is no longer needed. Failing
// to call Close leaks the drain goroutine and causes any buffered events to be
// lost. Close signals the drain goroutine to stop, waits up to the configured
// [WithShutdownTimeout] for pending events to flush, then closes all outputs
// in parallel. Events still in the buffer when the shutdown timeout expires
// are lost; a warning is emitted via [log/slog]. Close is idempotent via
// [sync.Once].
package audit
