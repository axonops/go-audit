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

import (
	"fmt"
	"log/slog"
	"time"
)

// Output is the interface that audit event destinations MUST implement.
// All outputs receive pre-serialised bytes (JSON, CEF, or a custom
// format chosen via [WithFormatter]). Built-in implementations are
// provided by the file, syslog, webhook, loki, and stdout packages.
type Output interface {
	// Write sends a single serialised audit event to the output.
	// data is a complete, newline-terminated byte slice. Write is
	// called from a single goroutine; concurrent calls from the
	// library will not occur. Implementers MAY assume single-caller
	// access.
	//
	// IMPORTANT — buffer ownership: the library MAY reuse data's
	// underlying array after Write returns. Implementations MUST NOT
	// retain data, or any slice that aliases its backing array, past
	// the Write call. If the bytes are needed beyond the call (for
	// example, to enqueue onto an asynchronous worker channel),
	// implementations MUST copy them — for example with
	// append([]byte(nil), data...). All first-party async outputs
	// (file, syslog, webhook, loki) already copy on enqueue.
	//
	// This contract enables the library's drain pipeline to deliver
	// pooled buffer bytes without per-event allocation (#497). Violating
	// it causes cross-event data corruption that is silent in production
	// and impossible to detect after the fact.
	Write(data []byte) error

	// Close flushes any buffered data and releases resources. The
	// library guarantees Write will not be called after Close. Close
	// is called exactly once by [Auditor.Close], from a goroutine that
	// has finished all Write calls — implementations do NOT need to
	// synchronise Close against in-flight Writes (there are none by
	// contract).
	Close() error

	// Name returns a human-readable identifier for the output,
	// used in log messages and metrics labels.
	//
	// Name MUST be safe for concurrent calls — the library reads it
	// from multiple goroutines (metrics emission, diagnostic logs,
	// close fan-out). Implementations typically return a fixed string
	// established at construction; nothing in the library mutates the
	// returned value.
	//
	// Name MUST NOT return an empty string. Empty names corrupt
	// metrics labels, hide outputs in error messages, and break
	// duplicate-name detection. [WithOutputs] and [WithNamedOutput]
	// reject empty-name outputs at construction time.
	Name() string
}

// DestinationKeyer is an optional interface that [Output] implementations
// MAY satisfy to enable duplicate destination detection at construction
// time. When two outputs return the same key from DestinationKey,
// [WithOutputs] and [WithNamedOutput] return an error.
//
// Returning an empty string from DestinationKey opts out of duplicate
// detection for that output.
//
// Key format conventions by output type:
//   - File: absolute filesystem path
//   - Syslog: network address (host:port)
//   - Webhook: full URL
//
// Outputs that do not implement this interface (e.g. [StdoutOutput])
// are silently skipped during destination dedup.
type DestinationKeyer interface {
	DestinationKey() string
}

// DeliveryReporter is an optional interface that [Output] implementations
// may satisfy to indicate they handle their own delivery metrics
// reporting. When satisfied and [DeliveryReporter.ReportsDelivery]
// returns true, the core auditor skips its default per-event
// [Metrics.RecordDelivery] calls for that output — the output is
// responsible for calling them after actual delivery.
//
// Not to be confused with [LastDeliveryReporter] — that interface
// reports a single timestamp for /healthz staleness probes; this
// one controls per-event metrics dispatch (success / error /
// filtered).
type DeliveryReporter interface {
	ReportsDelivery() bool
}

// EventMetadata carries per-event context for outputs that need
// structured access to framework fields (e.g., for Loki labels or
// Elasticsearch index routing). The struct is constructed once per
// delivery pass in [deliverToOutputs] and passed by value to
// [MetadataWriter.WriteWithMetadata].
//
// The struct is small (64 bytes on amd64), passed by value, and
// zero-allocation by design. All fields are read from existing local
// variables in the drain goroutine.
type EventMetadata struct { //nolint:govet // fieldalignment: readability over struct packing for a 4-field value type
	// EventType is the taxonomy event type name (e.g. "user_create").
	EventType string

	// Severity is the resolved severity (0-10) for this event.
	Severity int

	// Category is the delivery-specific category. Empty for
	// uncategorised events. When an event belongs to multiple
	// categories, each delivery pass has a different Category.
	Category string

	// Timestamp is the wall-clock time recorded at drain time.
	Timestamp time.Time
}

// MetadataWriter is an optional interface that [Output] implementations
// may satisfy to receive structured event metadata alongside
// pre-serialised bytes. When an output implements MetadataWriter,
// the library calls WriteWithMetadata instead of [Output.Write].
//
// Implementations MUST NOT retain meta or take its address after
// returning. The library passes meta by value on the stack; retaining
// it forces heap allocation. The caller must not assume the value
// remains valid after return.
//
// IMPORTANT — buffer ownership: the same retention contract documented
// on [Output.Write] applies to data. The library MAY reuse data's
// underlying array after WriteWithMetadata returns; implementations
// MUST copy the bytes before retaining them.
type MetadataWriter interface {
	WriteWithMetadata(data []byte, meta EventMetadata) error
}

// ContentTypeSetter is an optional interface implemented by outputs
// that need to know the MIME type of the bytes their associated
// formatter emits. HTTP-based outputs (notably [webhook.Output])
// use it to set the request Content-Type header without having to
// pin themselves to a specific formatter.
//
// The library calls SetContentType once at auditor construction
// time, after each output has been bound to its effective formatter
// and after [FrameworkFieldSetter.SetFrameworkFields] propagation,
// but BEFORE any event is dispatched. Outputs that do not care
// about Content-Type simply omit the method.
//
// Implementations MUST treat SetContentType as a one-shot
// configuration call from a non-I/O goroutine. Use
// [sync/atomic.Pointer] or equivalent if a concurrent reader (the
// output's background write goroutine) could observe the field
// before the auditor's construction goroutine writes it — otherwise
// the initialisation is a data race per the Go memory model.
//
// Implementations SHOULD validate the value (reject empty strings,
// CRLF, control characters) and return early on bad input rather
// than panicking — a malformed Content-Type ultimately surfaces as
// an HTTP-transport error per request, which is recoverable.
//
// Outputs whose wire format is fixed independently of the
// formatter (e.g., Loki's JSON push API, where the envelope is
// always "application/json" regardless of the inner log-line
// formatter) MUST NOT implement this interface — the library will
// not call SetContentType on them.
type ContentTypeSetter interface {
	SetContentType(contentType string)
}

// FrameworkContext carries auditor-wide framework metadata into
// output constructors so the first connection / first request can
// use the correct app_name, host, timezone, and pid. Construction-
// time cascades (e.g., syslog RFC 5424 APP-NAME defaulting from the
// top-level app_name when the per-output YAML key is omitted) are
// driven through this value.
//
// Populated by [outputconfig.Load] by parsing the top-level `app_name`
// and `host` fields from the outputs YAML. Direct-Go consumers who
// construct outputs themselves pass the zero value
// (FrameworkContext{}) unless they want to pre-populate cascade
// defaults for their use case.
//
// Introduced in #583 to solve the sequencing problem where framework
// fields were propagated to outputs AFTER the initial dial in
// [syslog.New], so the first syslog session used the wrong APP-NAME.
type FrameworkContext struct { //nolint:govet // fieldalignment: readability preferred (constructor-time value type, not on hot path)
	// AppName is the auditor-wide application name. Used as the
	// default RFC 5424 APP-NAME when the syslog per-output config
	// omits `app_name`. May be empty — outputs fall back to their
	// own defaults in that case.
	AppName string
	// Host is the auditor-wide host identifier. Used as the default
	// RFC 5424 HOSTNAME when the syslog per-output config omits
	// `hostname`. May be empty.
	Host string
	// Timezone is the auditor-wide timezone label (e.g. "UTC",
	// "Europe/London"). Populated by outputconfig.Load from the
	// auditor's WithTimezone option (or [time.Local] default).
	// May be empty.
	Timezone string
	// PID is the process ID at auditor construction time.
	// Populated by outputconfig.Load from os.Getpid(). Cached values
	// (e.g. Loki's pre-formatted pid label) should be derived once at
	// construction.
	PID int

	// DiagnosticLogger receives operational warnings emitted by the
	// output (TLS handshake failures, retry exhaustion, drop-rate
	// limit triggers, etc.). When nil, output authors fall back to
	// [slog.Default] at use site:
	//
	//	lg := fctx.DiagnosticLogger
	//	if lg == nil { lg = slog.Default() }
	//
	// Do NOT mutate fctx to backfill defaults — FrameworkContext is a
	// value type and mutation is a footgun. The nil-default contract
	// is applied at every call site.
	//
	// Replaces the post-construction DiagnosticLoggerReceiver
	// interface dropped in #696.
	DiagnosticLogger *slog.Logger
	// OutputMetrics receives per-output delivery counters
	// (RecordSuccess / RecordError / RecordDrop / RecordBufferDrop /
	// RecordRetry). When nil, output authors fall back to
	// [NoOpOutputMetrics] at use site (zero-value-safe).
	//
	// Replaces the post-construction OutputMetricsReceiver interface
	// dropped in #696.
	OutputMetrics OutputMetrics
	// CoreMetrics receives auditor-wide counters (queue depth,
	// drop rate). When nil, output authors fall back to [NoOpMetrics]
	// at use site (zero-value-safe).
	//
	// Distinct from OutputMetrics: CoreMetrics is the metrics value
	// the auditor itself uses; OutputMetrics is per-output and
	// provided by outputconfig.WithOutputMetricsFactory.
	CoreMetrics Metrics
}

// LastDeliveryReporter is an optional interface that [Output]
// implementations may satisfy to expose the timestamp of their most
// recent successful delivery. Outputs implementing this interface
// enable [Auditor.LastDeliveryAge], used by /healthz handlers to
// detect silently-failing async outputs whose own buffer is dropping
// events while the core auditor queue stays low.
//
// Not to be confused with [DeliveryReporter] — that interface
// controls per-event metrics dispatch (success / error / filtered);
// this one reports a single timestamp for staleness probes.
//
// LastDeliveryNanos returns the wall-clock nanos of the last
// successful end-to-end delivery (NOT the moment [Output.Write]
// returned — for async outputs that distinction is the whole
// point), or 0 if no delivery has yet succeeded. Wall-clock means
// the value can jump on system time changes; /healthz thresholds
// SHOULD be ≥ 10 s to absorb sub-second NTP slews. The reference
// example in [examples/16-health-endpoint] uses 30 s — see that
// example's README for picking a threshold for your workload.
//
// The returned value is NOT guaranteed monotonic across calls —
// wall-clock time can step backwards on NTP correction, daylight
// saving transitions, or operator clock changes. Callers reading
// two successive values MUST NOT assume `b >= a`. The canonical
// consumer ([Auditor.LastDeliveryAge]) computes [time.Since] which
// already absorbs negative differences as zero.
//
// Concurrency: implementations MUST be safe for concurrent use
// from any goroutine. The canonical implementation is a single
// [sync/atomic.Int64] updated on every successful delivery and
// loaded on every [LastDeliveryNanos] call.
type LastDeliveryReporter interface {
	LastDeliveryNanos() int64
}

// MaxOutputNameLength is the maximum allowed length for an output name.
const MaxOutputNameLength = 128

// ValidateOutputName checks that an output name is safe for use in
// metric labels, log messages, and YAML keys. Returns an error if
// the name is empty, too long, starts with an underscore (reserved),
// or contains characters outside [a-zA-Z0-9_-].
//
// ValidateOutputName is called by outputconfig.Load for YAML-sourced
// output names. Programmatic names (via [WithNamedOutput]) are not
// validated because auto-generated names may contain characters
// outside the YAML-safe set (e.g. "webhook:host:port").
func ValidateOutputName(name string) error {
	if name == "" {
		return fmt.Errorf("%w: output name must not be empty", ErrConfigInvalid)
	}
	if len(name) > MaxOutputNameLength {
		return fmt.Errorf("%w: output name %q exceeds maximum length %d",
			ErrConfigInvalid, name, MaxOutputNameLength)
	}
	if name[0] == '_' {
		return fmt.Errorf("%w: output name %q must not start with underscore (reserved)",
			ErrConfigInvalid, name)
	}
	if err := validateOutputNameChars(name); err != nil {
		return err
	}
	if c := name[0]; c >= '0' && c <= '9' {
		return fmt.Errorf("%w: output name %q must start with a letter",
			ErrConfigInvalid, name)
	}
	return nil
}

// validateOutputNameChars checks that every byte in name is in the
// allowed set [a-zA-Z0-9_-].
func validateOutputNameChars(name string) error {
	for i := 0; i < len(name); i++ {
		c := name[i]
		if isValidOutputNameChar(c) {
			continue
		}
		return fmt.Errorf("%w: output name %q contains invalid character %q at position %d; "+
			"only [a-zA-Z0-9_-] are allowed", ErrConfigInvalid, name, string(c), i)
	}
	return nil
}

func isValidOutputNameChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') || c == '_' || c == '-'
}
