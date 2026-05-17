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

// Option configures an [Auditor] during construction via [New].
//
// Options fall into three classes (#593 B-45):
//
//   - Required options — [New] returns a sentinel error if the
//     option is absent:
//     [WithTaxonomy] ([ErrTaxonomyRequired]),
//     [WithAppName] ([ErrAppNameRequired]),
//     [WithHost] ([ErrHostRequired]).
//     These inputs have no library-supplied default.
//
//   - Validated-on-call options — optional to call, but reject empty
//     arguments when called:
//     [WithFormatter] (nil rejected; omitting yields a default
//     [JSONFormatter]),
//     [WithTimezone] (empty rejected; omitting defaults to the local
//     timezone reported by [time.Now]().Location().String()).
//
//   - Optional options — accept nil / unset with a documented default:
//     [WithMetrics]         — nil or unset disables metrics collection.
//     [WithDiagnosticLogger] — nil or unset uses [slog.Default].
//     [WithStandardFieldDefaults] — nil or unset uses no defaults.
//
// Remaining options configure behaviour via value types
// ([WithQueueSize], [WithShutdownTimeout], [WithValidationMode],
// [WithOmitEmpty], [WithDisabled], [WithOutputs], [WithNamedOutput],
// [WithSynchronousDelivery]) and have their own documented
// zero-value semantics.
//
// The split mirrors the [net/http] convention — [http.Client.Transport]
// is optional with [http.DefaultTransport] as the documented
// nil-default, but the Handler on [http.Server] is required.
type Option func(*Auditor) error

// WithTaxonomy registers the event taxonomy for validation. This option
// is required; [New] returns an error if no taxonomy is provided.
//
// WARNING: WithTaxonomy SHOULD be called exactly once per [New] call.
// A second WithTaxonomy in the same option list silently replaces the
// first AND resets every runtime override established by an earlier
// [Auditor.EnableCategory] / [Auditor.DisableCategory] /
// [Auditor.EnableEvent] / [Auditor.DisableEvent] call. Mixing
// multiple WithTaxonomy options is almost always a configuration bug;
// build the final taxonomy once before passing it.
//
// WithTaxonomy makes a deep copy of t; mutations to t after this call
// have no effect on the auditor. When t was returned by
// [ParseTaxonomyYAML], redundant re-validation is skipped.
func WithTaxonomy(t *Taxonomy) Option {
	return func(a *Auditor) error {
		if t == nil {
			return fmt.Errorf("%w: taxonomy must not be nil", ErrTaxonomyInvalid)
		}
		cp := deepCopyTaxonomy(t)
		if !cp.validated {
			if err := MigrateTaxonomy(cp); err != nil {
				return err
			}
			if err := ValidateTaxonomy(*cp); err != nil {
				return err
			}
			if err := precomputeTaxonomy(cp); err != nil {
				return err
			}
		}
		a.taxonomy = cp
		a.filter = newFilterState(cp)
		return nil
	}
}

// WithMetrics sets the metrics recorder for the auditor.
//
// Optional. If m is nil, or if WithMetrics is not called, metrics
// are silently discarded (no metrics collection). Implementations
// MUST be safe for concurrent calls from the drain goroutine.
func WithMetrics(m Metrics) Option {
	return func(a *Auditor) error {
		a.metrics = m
		return nil
	}
}

// WithAppName sets the application name emitted as a framework field
// in every serialised event.
//
// Required. [New] returns [ErrAppNameRequired] if WithAppName is
// unset (unless [WithDisabled] is also applied). The value must be
// non-empty and at most 255 bytes.
func WithAppName(name string) Option {
	return func(a *Auditor) error {
		if name == "" {
			return fmt.Errorf("%w: app_name must not be empty", ErrConfigInvalid)
		}
		if len(name) > 255 {
			return fmt.Errorf("%w: app_name exceeds maximum length of 255 bytes", ErrConfigInvalid)
		}
		a.appName = name
		return nil
	}
}

// WithHost sets the hostname emitted as a framework field in every
// serialised event.
//
// Required. [New] returns [ErrHostRequired] if WithHost is unset
// (unless [WithDisabled] is also applied). The value must be
// non-empty and at most 255 bytes.
func WithHost(host string) Option {
	return func(a *Auditor) error {
		if host == "" {
			return fmt.Errorf("%w: host must not be empty", ErrConfigInvalid)
		}
		if len(host) > 255 {
			return fmt.Errorf("%w: host exceeds maximum length of 255 bytes", ErrConfigInvalid)
		}
		a.host = host
		return nil
	}
}

// WithTimezone sets the timezone name emitted as a framework field in
// every serialised event.
//
// Optional to call. If omitted, the timezone defaults to the local
// timezone as reported by [time.Now]().Location().String(); the
// timezone field is therefore always populated on every event. To
// suppress the timezone field entirely, supply a custom [Formatter]
// whose [Formatter.SetFrameworkFields] discards the timezone value.
// The built-in [JSONFormatter] and [CEFFormatter] write the timezone
// framework field unconditionally and cannot suppress it via
// [FormatOptions.IsExcluded]. If called, tz MUST be non-empty (the
// option returns an error for an empty string since there is no
// sane default to substitute at that point). At most 64 bytes.
func WithTimezone(tz string) Option {
	return func(a *Auditor) error {
		if tz == "" {
			return fmt.Errorf("%w: timezone must not be empty", ErrConfigInvalid)
		}
		if len(tz) > 64 {
			return fmt.Errorf("%w: timezone exceeds maximum length of 64 bytes", ErrConfigInvalid)
		}
		a.timezone = tz
		return nil
	}
}

// WithSynchronousDelivery configures the auditor to deliver events
// inline within [Auditor.AuditEvent] instead of via the async channel
// and drain goroutine. Events are immediately available in outputs
// after AuditEvent returns.
//
// This mode is useful for testing (no Close-before-assert ceremony)
// and for simple deployments (CLI tools, Lambda functions) where
// async complexity is unwanted. [Auditor.Close] is still safe to call
// but is not required before reading output.
//
// In synchronous mode there is no async queue, so [WithQueueSize]
// has no effect — the value is recorded on the config but never
// consulted. [ErrQueueFull] is also never returned (synchronous
// delivery has no buffer to overflow).
//
// # Caller-observable contract
//
//   - AuditEvent returns ONLY after every output has received the
//     event. The caller's goroutine blocks for the sum of all
//     outputs' Write durations.
//   - A panic inside an output's Write is RECOVERED — it is NOT
//     propagated to the caller. The auditor logs the panic at error
//     level, records a per-output drop metric, and continues
//     fan-out to subsequent outputs. AuditEvent returns nil even if
//     one or more outputs panicked.
//   - After [Auditor.Close], AuditEvent returns [ErrClosed]
//     synchronously without invoking any output. Close itself is
//     idempotent: repeated calls return nil with no side effects.
func WithSynchronousDelivery() Option {
	return func(a *Auditor) error {
		a.synchronous = true
		return nil
	}
}

// WithDiagnosticLogger sets the [log/slog.Logger] used for library
// diagnostics (lifecycle messages, buffer drops, format errors).
//
// Optional. When not set or when l is nil, [slog.Default] is used.
// Pass slog.New(slog.DiscardHandler) to silence all library output.
//
// The logger is fixed at construction; runtime swap is not supported
// (the prior Auditor.SetLogger API was removed in #696). To redirect
// diagnostics later, rebuild the auditor.
func WithDiagnosticLogger(l *slog.Logger) Option {
	return func(a *Auditor) error {
		if l != nil {
			a.logger.Store(l)
		}
		return nil
	}
}

// WithStandardFieldDefaults sets deployment-wide default values for
// reserved standard fields. Defaults are applied in [Auditor.AuditEvent]
// before validation — a default satisfies required: true constraints.
// Per-event values always override defaults (key existence check, not
// zero value). When called multiple times, the last call wins.
//
// Optional. Nil or empty map means "no defaults".
//
// Each value's Go type MUST match the reserved field's declared type
// reported by [ReservedStandardFieldType]. On mismatch, [New]
// returns an error wrapping [ErrConfigInvalid] so the
// misconfiguration surfaces at startup rather than at the first
// AuditEvent. Numeric port fields (`source_port`, `dest_port`,
// `file_size`) require int; timestamps (`start_time`, `end_time`)
// require time.Time; all other reserved fields require string. The
// authoritative type matrix lives in [ReservedStandardFieldNames] +
// [ReservedStandardFieldType]; consult those for the live list rather
// than counting the string-typed fields here. Pre-#595 callers
// passing `map[string]string` migrate by changing the literal map
// type; values that are already strings for string-typed fields keep
// working unchanged.
func WithStandardFieldDefaults(defaults map[string]any) Option {
	return func(a *Auditor) error {
		for k, v := range defaults {
			t, ok := ReservedStandardFieldType(k)
			if !ok {
				return fmt.Errorf("%w: WithStandardFieldDefaults: %q is not a reserved standard field",
					ErrConfigInvalid, k)
			}
			if !valueMatchesReservedType(v, t) {
				return fmt.Errorf("%w: WithStandardFieldDefaults[%q]: expected %s, got %T",
					ErrConfigInvalid, k, t, v)
			}
		}
		// Copy to prevent caller mutation after construction.
		cp := make(map[string]any, len(defaults))
		for k, v := range defaults {
			cp[k] = v
		}
		a.standardFieldDefaults = cp
		return nil
	}
}

// WithFormatter sets the event serialisation formatter.
//
// Optional to call; if WithFormatter is not called, a [JSONFormatter]
// with default settings is used. If WithFormatter is called, f MUST
// be non-nil — the option returns an error for a nil formatter since
// there is no sane default to substitute at that point. Use this to
// configure a [CEFFormatter] or a custom [Formatter] implementation.
func WithFormatter(f Formatter) Option {
	return func(a *Auditor) error {
		if f == nil {
			return fmt.Errorf("%w: formatter must not be nil", ErrConfigInvalid)
		}
		a.formatter = f
		return nil
	}
}

// Output configuration options — WithOutputs, WithNamedOutput,
// OutputOption, and the per-output options (WithRoute,
// WithOutputFormatter, WithExcludeLabels, WithHMAC) are defined in
// options_output.go.

// WithQueueSize sets the async intake queue capacity for the auditor.
// Zero or negative values are ignored (the default of
// [DefaultQueueSize] applies). Values above [MaxQueueSize] cause
// [New] to return an error wrapping [ErrConfigInvalid].
func WithQueueSize(n int) Option {
	return func(a *Auditor) error {
		a.cfg.QueueSize = n
		return nil
	}
}

// WithShutdownTimeout sets the maximum time [Auditor.Close] waits for
// pending events to flush. Zero or negative values are ignored (the
// default of [DefaultShutdownTimeout] applies). Values above
// [MaxShutdownTimeout] cause [New] to return an error wrapping
// [ErrConfigInvalid].
func WithShutdownTimeout(d time.Duration) Option {
	return func(a *Auditor) error {
		a.cfg.ShutdownTimeout = d
		return nil
	}
}

// WithValidationMode sets how [Auditor.AuditEvent] handles unknown
// fields. Must be one of [ValidationStrict], [ValidationWarn], or
// [ValidationPermissive]. An invalid mode causes [New] to
// return an error wrapping [ErrConfigInvalid].
func WithValidationMode(m ValidationMode) Option {
	return func(a *Auditor) error {
		a.cfg.ValidationMode = m
		return nil
	}
}

// WithOmitEmpty enables omission of empty, nil, and zero-value fields
// from serialised output. When enabled, only non-zero fields are
// serialised. Consumers operating under compliance regimes that
// require all registered fields SHOULD NOT use this option.
func WithOmitEmpty() Option {
	return func(a *Auditor) error {
		a.cfg.OmitEmpty = true
		return nil
	}
}

// WithDisabled creates a no-op auditor that discards all events without
// validation or delivery. [Auditor.AuditEvent] returns nil immediately.
// This is the explicit opt-out for audit logging — the default is
// enabled, because silent audit disablement is worse than noisy audit
// failure.
func WithDisabled() Option {
	return func(a *Auditor) error {
		a.disabled = true
		return nil
	}
}

// WithSanitizer registers a [Sanitizer] with the auditor. The
// Sanitizer's [Sanitizer.SanitizeField] is invoked once per field on
// every [Auditor.Audit] / [Auditor.AuditEvent] call (NOT only the
// middleware path); [Sanitizer.SanitizePanic] is invoked on the
// middleware panic-recovery path before the panic is re-raised.
//
// Passing a nil Sanitizer is a no-op (unset state). When unset, the
// per-event hot path performs a single nil-check and pays no
// further overhead. See the [Sanitizer] godoc for the concurrency,
// ownership, and return-type contracts that implementations MUST
// satisfy.
//
// Use Sanitizer to scrub PII, mask credentials, hash identifiers,
// or replace internal error messages before they reach output sinks
// AND before middleware-recovered panic values flow to outer panic
// handlers (Sentry, panic loggers, parent recovery middleware).
//
// Example:
//
//	type RedactPasswords struct{ audit.NoopSanitizer }
//	func (RedactPasswords) SanitizeField(key string, value any) any {
//	    if key == "password" { return "[redacted]" }
//	    return value
//	}
//	auditor, err := audit.New(
//	    audit.WithTaxonomy(tax),
//	    audit.WithAppName("svc"),
//	    audit.WithHost("h1"),
//	    audit.WithSanitizer(RedactPasswords{}),
//	)
func WithSanitizer(s Sanitizer) Option {
	return func(a *Auditor) error {
		a.sanitizer = s
		return nil
	}
}

// buildLabelSet converts a slice of label names to a set.
func buildLabelSet(labels []string) map[string]struct{} {
	m := make(map[string]struct{}, len(labels))
	for _, l := range labels {
		m[l] = struct{}{}
	}
	return m
}

// checkDestinationDup checks whether the output's destination key
// collides with a previously registered output. If the output does not
// implement [DestinationKeyer], the check is skipped. On collision,
// returns an error naming both outputs and the conflicting key.
func checkDestinationDup(o Output, name string, seen map[string]string) error {
	dk, ok := o.(DestinationKeyer)
	if !ok {
		return nil
	}
	key := dk.DestinationKey()
	if key == "" {
		return nil
	}
	if existing, dup := seen[key]; dup {
		// Deliberately omit the destination key from the error message:
		// for webhook/loki outputs the key contains the URL path, which
		// may carry a secret (Slack /services/<TOKEN>, Splunk HEC path).
		// The two output names are sufficient to identify the conflict
		// (#475).
		return fmt.Errorf("%w: outputs %q and %q share the same destination", ErrDuplicateDestination, existing, name)
	}
	seen[key] = name
	return nil
}
