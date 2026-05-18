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
	"errors"
	"fmt"
	"slices"
)

// Sentinel errors returned by the audit package.
// Use [errors.Is] to test for these in consumer code.
var (
	// ErrClosed is returned by [Auditor.AuditEvent] when the auditor has
	// been shut down via [Auditor.Close]. Once returned, all subsequent
	// [Auditor.AuditEvent] calls return ErrClosed immediately.
	ErrClosed = errors.New("audit: auditor is closed")

	// ErrQueueFull is returned by [Auditor.AuditEvent] when the async
	// intake queue is at capacity and the event is dropped. Consumers
	// SHOULD treat this as a drop notification rather than a fatal error.
	// Increasing [WithQueueSize] or reducing event emission rate
	// reduces the frequency of this error.
	//
	// To diagnose: inspect [Auditor.QueueLen] / [Auditor.QueueCap] for
	// the live ratio, or wire a [Metrics] implementation that observes
	// [Metrics.RecordBufferDrop] for the drop rate over time.
	ErrQueueFull = errors.New("audit: queue full")

	// ErrDuplicateDestination is returned by [WithOutputs] and
	// [WithNamedOutput] when two outputs implement [DestinationKeyer]
	// and return the same key. This prevents accidental double-delivery
	// to the same file, syslog address, or webhook URL.
	//
	// To recover: deduplicate the output list, or give each output a
	// distinct destination key (e.g. write to different files / different
	// syslog addresses / different webhook URLs).
	ErrDuplicateDestination = errors.New("audit: duplicate destination")

	// ErrConfigInvalid is the sentinel error wrapped by all configuration
	// validation failures. Use [errors.Is] to test for it:
	//
	//	if errors.Is(err, audit.ErrConfigInvalid) { ... }
	//
	// The full err.Error() string identifies the specific field and
	// constraint that failed; callers SHOULD surface or log the full
	// message at startup to identify the misconfiguration. Common
	// causes: app_name/host length exceeded (255 bytes), queue_size
	// out of range, invalid validation_mode value, malformed reserved-
	// field default type, two outputs sharing a name, mixing
	// [WithOutputs] with [WithNamedOutput].
	ErrConfigInvalid = errors.New("audit: config validation failed")

	// ErrHandleNotFound is returned by [Auditor.Handle], and wrapped in
	// the panic value of [Auditor.MustHandle], when the requested event
	// type is not registered in the taxonomy.
	//
	// This indicates a programming error: the event type name was not
	// declared in the [Taxonomy] passed to [WithTaxonomy]. To recover,
	// add the event type to your taxonomy YAML (or in-code [Taxonomy]
	// literal) and re-run code generation if you're using audit-gen.
	// Call [Auditor.Handle] at startup to surface this error before
	// any audit-emission code path runs.
	ErrHandleNotFound = errors.New("audit: event type not found")

	// ErrOutputClosed is returned by [Output.Write] when the output has
	// already been closed.
	ErrOutputClosed = errors.New("audit: output is closed")

	// ErrEventTooLarge is returned by async output [Output.Write]
	// methods (syslog, loki, webhook) when the supplied event byte
	// length exceeds the output's configured MaxEventBytes. Wrapped
	// alongside [ErrValidation] so callers can discriminate via
	// errors.Is:
	//
	//	if errors.Is(err, audit.ErrEventTooLarge) { ... }
	//	if errors.Is(err, audit.ErrValidation)    { ... }
	//
	// Introduced by #688 as a DoS defence against consumer-controlled
	// memory pressure — a 10 MiB event × 10 000-slot buffer could
	// pin ~100 GiB before backpressure triggers. Default cap is
	// 1 MiB per output; configurable via each output's MaxEventBytes
	// Config field.
	//
	// To recover: raise the cap via the per-output `max_event_bytes`
	// YAML config key (or the equivalent Go option on the output
	// constructor), or trim the offending event's payload. A
	// [Metrics] implementation observing [Metrics.RecordError] sees
	// these in aggregate for diagnostic dashboards.
	ErrEventTooLarge = errors.New("audit: event exceeds max_event_bytes")

	// ErrDisabled is returned by methods that require a taxonomy
	// ([Auditor.EnableCategory], [Auditor.DisableCategory],
	// [Auditor.EnableEvent], [Auditor.DisableEvent],
	// [Auditor.SetOutputRoute]) when called on a disabled auditor.
	// [Auditor.Handle] returns a valid no-op handle instead.
	ErrDisabled = errors.New("audit: auditor is disabled")

	// ErrTaxonomyRequired is returned by [New] when [WithTaxonomy] was
	// not called (unless [WithDisabled] is applied). Sibling of
	// [ErrAppNameRequired] / [ErrHostRequired] — all three mark missing
	// required options and support [errors.Is] discrimination.
	ErrTaxonomyRequired = errors.New("audit: taxonomy is required: use WithTaxonomy")

	// ErrAppNameRequired is returned by [New] when [WithAppName] was
	// not called. All auditors (except those constructed with
	// [WithDisabled]) must set an app name for compliance — every
	// emitted event carries app_name as a framework field, and a blank
	// value undermines attribution. Matches the [outputconfig.Load]
	// YAML-path requirement for symmetry across construction paths.
	ErrAppNameRequired = errors.New("audit: app_name is required: use WithAppName")

	// ErrHostRequired is returned by [New] when [WithHost] was not
	// called. All auditors (except those constructed with [WithDisabled])
	// must set a host identifier for compliance. Matches the
	// [outputconfig.Load] YAML-path requirement for symmetry across
	// construction paths.
	ErrHostRequired = errors.New("audit: host is required: use WithHost")

	// ErrTaxonomyInvalid is the sentinel error wrapped by taxonomy
	// validation failures. Use [errors.Is] to test for it:
	//
	//	if errors.Is(err, audit.ErrTaxonomyInvalid) { ... }
	//
	// The full err.Error() string lists every validation problem the
	// taxonomy contains, one per line, in deterministic alphabetical
	// order — callers SHOULD log or surface the full message so the
	// taxonomy author can fix every problem in one pass rather than
	// iterating one error at a time.
	ErrTaxonomyInvalid = errors.New("audit: taxonomy validation failed")

	// ErrInvalidTaxonomyName is returned by [ValidateTaxonomy] when a
	// category name, sensitivity label name, event type key, or field
	// name fails the character-set or length rule. Names must match
	// `^[a-z][a-z0-9_]*$` and be no longer than 128 bytes — enforced
	// at load to keep bidi overrides, Unicode confusables, CEF/JSON
	// metacharacters, and all C0/C1 control bytes out of downstream
	// log consumers and SIEM dashboards (issue #477).
	//
	// Always wrapped alongside [ErrTaxonomyInvalid] via [errors.Join],
	// so either sentinel satisfies [errors.Is]:
	//
	//	if errors.Is(err, audit.ErrInvalidTaxonomyName) { ... }
	//	if errors.Is(err, audit.ErrTaxonomyInvalid)     { ... }
	ErrInvalidTaxonomyName = errors.New("audit: invalid taxonomy name")

	// ErrInvalidInput is returned by [ParseTaxonomyYAML] when the input
	// is structurally unsuitable — empty, a multi-document YAML stream,
	// or syntactically invalid. Taxonomy content validation errors wrap
	// [ErrTaxonomyInvalid] instead.
	//
	// To recover: check that the input is a single non-empty YAML
	// document. Multi-document streams are not supported; split into
	// separate files and call [ParseTaxonomyYAML] once per file.
	ErrInvalidInput = errors.New("audit: invalid input")

	// ErrValidation is the parent sentinel for all [Auditor.AuditEvent]
	// validation failures (unknown event type, missing required fields,
	// unknown fields in strict mode). Use [errors.Is] to catch any
	// validation failure:
	//
	//	if errors.Is(err, audit.ErrValidation) { ... }
	//
	// [ErrQueueFull] and [ErrClosed] are NOT validation errors.
	ErrValidation = errors.New("audit: validation error")

	// ErrUnknownEventType is returned by [Auditor.AuditEvent] when the
	// event type is not registered in the taxonomy. Always wrapped
	// alongside [ErrValidation] via [ValidationError].
	//
	// To recover: pass an event type that's declared in your taxonomy.
	// Call [Auditor.Handle] at startup with the event-type names your
	// service emits to pre-validate them and catch this error before
	// any audit-emission code path runs.
	ErrUnknownEventType = errors.New("audit: unknown event type")

	// ErrMissingRequiredField is returned by [Auditor.AuditEvent] when
	// one or more required fields are absent. Always wrapped alongside
	// [ErrValidation] via [ValidationError].
	//
	// The full err.Error() string lists every missing required field
	// for the event, not just the first — callers SHOULD log the full
	// message rather than iterate one fix at a time. Use generated
	// builders from audit-gen (which make required fields constructor
	// parameters) for compile-time safety against this error.
	ErrMissingRequiredField = errors.New("audit: missing required field")

	// ErrUnknownField is returned by [Auditor.AuditEvent] in strict
	// validation mode when one or more fields are not declared in the
	// taxonomy. Always wrapped alongside [ErrValidation] via
	// [ValidationError].
	//
	// To recover: add the field to the event's Optional list in the
	// taxonomy, or switch to [ValidationWarn] (logs a diagnostic but
	// accepts the event) or [ValidationPermissive] (silent accept).
	// Strict mode is the default — see [WithValidationMode].
	ErrUnknownField = errors.New("audit: unknown field")

	// ErrUnknownFieldType is returned by [Auditor.AuditEvent] in
	// strict validation mode when a [Fields] entry carries a value
	// of a type not in the supported set documented on [Fields].
	// Always wrapped alongside [ErrValidation] via [ValidationError].
	//
	// In warn and permissive modes, unsupported values are coerced
	// via fmt.Sprintf("%v", v) instead of returning this error; in
	// warn mode a diagnostic-logger warning is emitted as well. See
	// the Fields godoc for the full type vocabulary and behaviour
	// matrix.
	ErrUnknownFieldType = errors.New("audit: unsupported field value type")

	// ErrHMACMalformed is returned by [VerifyHMAC] when the
	// supplied HMAC value is structurally invalid — empty, the
	// wrong length for the algorithm's hash size, or contains
	// non-hex characters. Validation runs BEFORE the constant-time
	// compare, since malformed inputs are pre-authentication
	// structural rejects and not timing-sensitive.
	//
	// Always paired with [ErrValidation] via [errors.Join] so
	// consumers can discriminate:
	//
	//	if errors.Is(err, audit.ErrHMACMalformed) { ... }
	//	if errors.Is(err, audit.ErrValidation)     { ... }
	ErrHMACMalformed = errors.New("audit: hmac value malformed")

	// ErrSSRFBlocked is the sentinel wrapped by every
	// [SSRFBlockedError] produced by [CheckSSRFIP] /
	// [CheckSSRFAddress]. Use [errors.Is] for broad discrimination
	// and [errors.As] (against `*SSRFBlockedError`) when the
	// specific block reason is needed for metrics or incident
	// routing:
	//
	//	var ssrfErr *audit.SSRFBlockedError
	//	if errors.As(err, &ssrfErr) {
	//	    metricSSRFBlocked.With("reason", string(ssrfErr.Reason)).Inc()
	//	}
	//	if errors.Is(err, audit.ErrSSRFBlocked) { ... }
	ErrSSRFBlocked = errors.New("audit: address blocked by SSRF protection")

	// ErrReservedFieldName is returned by [Auditor.AuditEvent] when
	// the event's Fields map uses a name reserved for library-emitted
	// fields (for example `_hmac`, `_hmac_version`). These names would
	// collide with library output and could enable canonicalisation-
	// ambiguity attacks on HMAC verifiers (issue #473). This check runs
	// regardless of [ValidationMode]; permissive mode cannot opt out.
	// Always wrapped alongside [ErrValidation] via [ValidationError].
	//
	// To recover: rename the offending field. Reserved names include
	// every entry in [ReservedStandardFieldNames] (the 28-or-so
	// standardised fields like `username`, `source_ip`, `event_id`)
	// plus the underscore-prefix family used by the library for its
	// own framework fields (`_hmac`, `_hmac_version`,
	// `_sanitizer_failed`, etc.). As a rule: do not start field names
	// with an underscore.
	ErrReservedFieldName = errors.New("audit: reserved field name")
)

// ValidationError is returned by [Auditor.AuditEvent] for event
// validation failures. It wraps both [ErrValidation] and a specific
// sentinel ([ErrUnknownEventType], [ErrMissingRequiredField],
// [ErrUnknownField], or [ErrReservedFieldName]). Use [errors.Is] to
// match broadly or narrowly, and [errors.As] to access the structured
// error:
//
//	var ve *audit.ValidationError
//	if errors.As(err, &ve) { log.Println(ve.Error()) }
type ValidationError struct {
	wrapped [2]error // pre-allocated to avoid per-Unwrap heap allocation
	msg     string
}

// Error returns the human-readable error message. The text is
// identical to the pre-sentinel format for backwards compatibility.
func (e *ValidationError) Error() string { return e.msg }

// Unwrap returns the sentinel errors that this validation error wraps.
// Always includes [ErrValidation]; also includes the specific sentinel
// when set.
//
// The returned slice is a defensive copy — callers may retain or mutate
// it without affecting the [ValidationError] or subsequent Unwrap
// calls. The copy is a 16-byte allocation on the error-discrimination
// path; Unwrap is only invoked by [errors.Is] / [errors.As], which are
// off the audit hot path (#590).
func (e *ValidationError) Unwrap() []error {
	return slices.Clone(e.wrapped[:])
}

// newValidationError creates a [ValidationError] with the given
// specific sentinel and formatted message.
func newValidationError(sentinel error, format string, args ...any) *ValidationError {
	ve := &ValidationError{
		msg: fmt.Sprintf(format, args...),
	}
	ve.wrapped[0] = ErrValidation
	ve.wrapped[1] = sentinel
	return ve
}
