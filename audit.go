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

// Architecture: async buffer -> single drain goroutine -> serialise -> fan-out
//
// AuditEvent() validates the event against the registered taxonomy, checks
// the global filter, then enqueues the event to a buffered channel. A
// single drain goroutine reads from the channel, serialises the event
// to JSON (or the configured format), and writes to all enabled
// outputs. If the buffer is full the event is dropped and metrics are
// recorded.
//
// Close() cancels the drain goroutine's context, waits up to
// ShutdownTimeout for pending events to flush, then closes all outputs in
// sequence. Close is idempotent via sync.Once.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// dropWarnInterval is the minimum interval between slog.Warn calls
// for buffer-full drop events.
const dropWarnInterval = 10 * time.Second

// auditEntryPool caches auditEntry instances to avoid per-Audit heap
// allocation. Entries are retrieved in AuditEvent(), sent through the
// channel, processed by the drain goroutine, and returned to the pool
// at the end of processEntry(). Fields are nilled before return to
// prevent stale references from keeping caller data alive in the pool.
var auditEntryPool = sync.Pool{
	New: func() any { return new(auditEntry) },
}

// fieldsPool caches Fields maps to avoid per-event heap allocation in
// copyFieldsWithDefaults. Maps are retrieved in auditInternalCtx (caller
// goroutine), populated with copied fields, sent through the channel,
// and returned to the pool after processEntry completes (drain goroutine).
// Maps are cleared before return to prevent stale references.
var fieldsPool = sync.Pool{
	New: func() any { return make(Fields, 8) },
}

// Auditor is the core type. It validates events against a
// registered [Taxonomy], filters by category and per-event overrides,
// and delivers events asynchronously to configured [Output]
// destinations.
//
// The library uses [log/slog] for internal diagnostics (buffer drops,
// serialisation failures, output write errors). Consumers can configure
// the slog default handler to control this output.
//
// An Auditor is safe for concurrent use by multiple goroutines.
//
//nolint:govet // field order: logical grouping over alignment optimisation
type Auditor struct {
	closeErr  error
	filter    *filterState
	metrics   Metrics
	formatter Formatter
	ch        chan *auditEntry
	taxonomy  *Taxonomy
	cancel    context.CancelFunc
	drainDone chan struct{}
	// entries and outputsByName are immutable after construction.
	entries       []*outputEntry
	outputsByName map[string]*outputEntry
	cfg           config
	closeOnce     sync.Once
	closed        atomic.Bool
	// destKeys tracks destination keys during construction to detect
	// duplicate output destinations. Only used by WithNamedOutput;
	// WithOutputs uses a local map.
	destKeys map[string]string
	// usedWithOutputs is set during construction when WithOutputs is
	// applied; prevents mixing WithOutputs and WithNamedOutput.
	usedWithOutputs bool
	// disabled is set by WithDisabled to create a no-op auditor that
	// discards all events without validation or delivery. Replaces
	// the former Config.Enabled field (inverted: disabled=true means
	// the auditor does nothing).
	disabled bool
	// synchronous is set by WithSynchronousDelivery to deliver events
	// inline within AuditEvent instead of via the async channel. No
	// drain goroutine is started. Useful for testing and CLIs.
	synchronous bool
	// syncMu guards processEntry calls in synchronous delivery mode.
	// processEntry reuses per-output state (formatOpts, HMAC) that is
	// only safe under single-goroutine access.
	//
	// Accepted trade-off (#509, master-tracker C-31): synchronous
	// delivery serialises every AuditEvent call through this mutex.
	// That is the intended behaviour — WithSynchronousDelivery exists
	// precisely to give tests and CLI tools a deterministic "audit
	// returned so the write completed" contract, which requires
	// serialisation. Production consumers use the default async
	// path where syncMu is not held and the drain goroutine owns
	// the single-writer invariant.
	syncMu sync.Mutex
	// Framework fields set via WithAppName, WithHost, WithTimezone.
	// PID is captured once at construction via os.Getpid().
	appName  string
	host     string
	timezone string
	pid      int
	// standardFieldDefaults holds deployment-wide default values for
	// reserved standard fields. Set once via WithStandardFieldDefaults;
	// read-only after construction. Applied in auditInternalCtx before
	// validation so that defaults satisfy required: true constraints.
	standardFieldDefaults map[string]any
	// sanitizer scrubs sensitive content from event field values and
	// from re-raised middleware panic values. Nil means no scrubbing
	// — when both [Sanitizer] and the middleware sanitizer-failed
	// flag are unset the per-event overhead is two branches (one
	// nil-check + one bool check on the [auditInternalDonatedFlagsCtx]
	// parameter). Set via [WithSanitizer].
	sanitizer Sanitizer
	// logger is the library diagnostics logger. Set once via
	// [WithDiagnosticLogger]; runtime swap was removed in #696 along
	// with the Auditor.SetLogger API. The atomic.Pointer is retained
	// for zero-value readability and so [Auditor.Logger] returns the
	// fully-published initial value without copying. Construction
	// never stores a nil pointer — readers always observe at minimum
	// [slog.Default].
	logger     atomic.Pointer[slog.Logger]
	drops      dropLimiter // rate-limits buffer-full warnings
	drainCount uint64      // events processed by drain loop; for sampling RecordQueueDepth
}

// New creates a new [Auditor] from the given options.
//
// Required options (unless [WithDisabled] is applied):
//   - [WithTaxonomy] — the event taxonomy. Missing → error.
//   - [WithAppName]  — the application name. Missing → [ErrAppNameRequired].
//   - [WithHost]     — the host identifier. Missing → [ErrHostRequired].
//
// The app_name and host requirements match the [outputconfig.Load]
// YAML-path contract so that programmatic and declarative construction
// produce equally complete framework fields.
//
// Defaults are: queue=10,000, shutdown=5s, validation=strict. Pass
// tuning options like [WithQueueSize], [WithShutdownTimeout],
// [WithValidationMode], or [WithOmitEmpty] to override.
//
// When [WithDisabled] is applied, New returns a valid no-op
// auditor without requiring a taxonomy, app name, or host. All
// [Auditor.AuditEvent] calls return nil immediately without validation
// or delivery. Methods that require a taxonomy
// ([Auditor.EnableCategory], etc.) return [ErrDisabled].
func New(opts ...Option) (*Auditor, error) {
	a := &Auditor{}

	for _, opt := range opts {
		if err := opt(a); err != nil {
			return nil, err
		}
	}

	// validateConfig calls applyDefaults internally, then validates.
	if err := validateConfig(&a.cfg); err != nil {
		return nil, err
	}

	// Release construction-only state.
	a.destKeys = nil

	if a.logger.Load() == nil {
		a.logger.Store(slog.Default())
	}

	if a.disabled {
		a.applyConstructionDefaults()
		return a, nil
	}

	if err := checkRequiredOptions(a); err != nil {
		return nil, err
	}

	a.applyDevTaxonomyOverrides()

	if err := a.validateOutputRoutes(); err != nil {
		return nil, err
	}

	a.prepareOutputEntries()

	a.applyConstructionDefaults()

	if !a.synchronous {
		ctx, cancel := context.WithCancel(context.Background())
		a.cancel = cancel
		a.ch = make(chan *auditEntry, a.cfg.QueueSize)
		a.drainDone = make(chan struct{})
		go a.drainLoop(ctx)
	}

	a.logger.Load().Info("audit: auditor created",
		"queue_size", a.cfg.QueueSize,
		"shutdown_timeout", a.cfg.ShutdownTimeout,
		"validation_mode", string(a.cfg.ValidationMode),
		"outputs", len(a.entries),
		"synchronous", a.synchronous,
	)

	return a, nil
}

// checkRequiredOptions verifies that the non-disabled auditor has
// every required option set. See [Option] godoc for the required /
// optional classification (#593 B-41 / B-45).
func checkRequiredOptions(a *Auditor) error {
	if a.taxonomy == nil {
		return ErrTaxonomyRequired
	}
	if a.appName == "" {
		return ErrAppNameRequired
	}
	if a.host == "" {
		return ErrHostRequired
	}
	return nil
}

// applyDevTaxonomyOverrides warns about DevTaxonomy and forces permissive
// validation mode when a dev taxonomy is used.
func (a *Auditor) applyDevTaxonomyOverrides() {
	if a.taxonomy == nil || !a.taxonomy.dev {
		return
	}
	a.logger.Load().Warn("audit: using DevTaxonomy — not suitable for production; all event types accepted without schema enforcement")
	if a.cfg.ValidationMode == ValidationStrict {
		a.cfg.ValidationMode = ValidationPermissive
	}
}

// applyConstructionDefaults sets formatter, PID, timezone, and propagates
// framework fields to formatters. Called once during New after all
// options are applied. Outputs receive logger / metrics / framework
// fields at construction via [FrameworkContext]; no post-construction
// propagation is required.
func (a *Auditor) applyConstructionDefaults() {
	if a.formatter == nil {
		a.formatter = &JSONFormatter{OmitEmpty: a.cfg.OmitEmpty}
	}
	a.pid = os.Getpid()
	if a.timezone == "" {
		a.timezone = time.Now().Location().String()
	}
	a.propagateFrameworkFields()
}

// Logger returns the diagnostic logger configured via
// [WithDiagnosticLogger], or [slog.Default] if none was supplied.
// Useful for library wrappers that want to share the auditor's
// logger across components.
//
// The logger is fixed at construction; runtime swap is not supported
// (the prior SetLogger API was removed in #696 — direct-Go consumers
// who want to redirect diagnostics should rebuild the auditor).
func (a *Auditor) Logger() *slog.Logger {
	return a.logger.Load()
}

// AuditEvent validates and enqueues a typed audit event. Use
// generated event builders from audit-gen for compile-time field
// safety, or [NewEvent] for dynamic event construction.
//
// AuditEvent returns [ErrQueueFull] if the async buffer is at
// capacity (the event is dropped), [ErrClosed] if the auditor has
// been closed, or a descriptive error for validation failures.
// If the event's category is globally disabled (and no per-event
// override enables it), the event is silently discarded without error.
//
// AuditEvent is a convenience wrapper around [Auditor.AuditEventContext]
// with [context.Background]. Prefer [Auditor.AuditEventContext] when
// you have a request-scoped context (e.g. from an HTTP handler) — it
// honours cancellation and deadlines at the well-defined boundary
// points in the audit pipeline.
func (a *Auditor) AuditEvent(evt Event) error {
	return a.AuditEventContext(context.Background(), evt)
}

// AuditEventContext is the [context.Context]-aware variant of
// [Auditor.AuditEvent]. The context is checked at well-defined
// cancellation points — at the top of the validate / enqueue / sync-
// deliver path and between fan-out outputs in synchronous-delivery
// mode — but is NOT threaded into individual [Output.Write] calls;
// once an event is enqueued for the drain goroutine, it is no longer
// cancellable. See [database/sql.QueryContext] for the analogous
// pattern (ctx checked at boundaries, not mid-syscall).
//
// When ctx is [context.Background] (or any context whose Done channel
// is nil), AuditEventContext takes the same fast path as the legacy
// [Auditor.AuditEvent] — single nil-check, no extra select, no
// measurable overhead.
//
// When ctx is cancelled or its deadline expires before the event is
// queued, AuditEventContext returns ctx.Err ([context.Canceled] or
// [context.DeadlineExceeded]), records a buffer-drop metric via
// [Metrics.RecordBufferDrop], and emits a diagnostic-log warn line
// so operators can distinguish caller-driven drops from queue-full
// drops.
//
// Precedence: a disabled auditor (constructed with [WithDisabled])
// short-circuits BEFORE the ctx check — calls return nil regardless
// of ctx state, matching the pre-#600 contract that disabled
// auditors are a silent no-op.
//
// Race: when ctx is cancelled AND the async buffer is full at the
// same instant, Go's `select` picks either the cancel branch or the
// queue-full branch nondeterministically. The caller may see
// either ctx.Err() or [ErrQueueFull]; in both cases the entry is
// returned to the pool and the buffer-drop metric is incremented.
// Callers that need to distinguish should inspect the error with
// [errors.Is].
func (a *Auditor) AuditEventContext(ctx context.Context, evt Event) error {
	if evt == nil {
		return fmt.Errorf("audit: event must not be nil")
	}
	// Fast-path detection: generated builders from cmd/audit-gen emit
	// the unexported donateFields() sentinel to opt into the zero-extra-
	// alloc path. The auditor takes ownership of the donated Fields map
	// (no defensive copy) and merges standard-field defaults in place.
	// Consumer-defined Event types and NewEvent stay on the slow path.
	// See docs/adr/0001-fields-ownership-contract.md (#497).
	_, donated := evt.(FieldsDonor)
	return a.auditInternalDonatedFlagsCtx(ctx, evt.EventType(), evt.Fields(), donated, false)
}

// auditInternalCtx is the ctx-aware internal entry point used by
// [EventHandle.AuditContext] and any other internal caller that
// needs to thread context through the validate-and-enqueue path.
func (a *Auditor) auditInternalCtx(ctx context.Context, eventType string, fields Fields) error {
	return a.auditInternalDonatedFlagsCtx(ctx, eventType, fields, false, false)
}

// auditInternalDonatedFlagsCtx is the ctx-aware core of the audit-
// emit pipeline. It checks ctx at well-defined boundaries (top of
// function pre-validation; before enqueue) but does not thread ctx
// into [Output.Write]. When `ctx.Done() == nil` (the [context.Background]
// fast path) the per-event overhead is a single nil-check —
// no extra select, no extra atomic, no measurable regression vs
// the pre-#600 path.
//
// All non-ctx callers go through this entry point with
// [context.Background]; it is the unified internal pipeline used by
// [Auditor.AuditEvent], [Auditor.AuditEventContext], and
// [emitAuditEvent] in the middleware path. The donated flag selects
// the donor fast-path vs defensive-copy slow-path; mwSanitizerFailed
// is set by [Middleware]'s panic-recovery hook to inject the
// [FieldSanitizerFailed] framework field after validation.
//
//nolint:gocyclo,cyclop,gocognit // a flat sequence of guard / hook calls; splitting would add indirection without simplifying.
func (a *Auditor) auditInternalDonatedFlagsCtx(ctx context.Context, eventType string, fields Fields, donated, mwSanitizerFailed bool) error {
	if a.disabled {
		return nil
	}
	if a.closed.Load() {
		return ErrClosed
	}

	// Pre-validate ctx check. Cheap when ctx.Done() is nil (the
	// non-cancellable [context.Background] family); for a cancellable
	// ctx this is a single non-blocking select.
	if done := ctx.Done(); done != nil {
		select {
		case <-done:
			a.recordCtxCancelDrop(eventType, ctx.Err())
			return ctx.Err() //nolint:wrapcheck // ctx.Err() returns context.Canceled / DeadlineExceeded sentinels — propagate verbatim per Go convention
		default:
		}
	}

	if a.metrics != nil {
		a.metrics.RecordSubmitted()
	}

	_, copied, err := a.validateEvent(eventType, fields, donated)
	if err != nil {
		return err
	}

	// Sanitizer hot-path hook (#598). Run AFTER validation so the
	// validator rejects unsupported types BEFORE the sanitiser sees
	// them, and BEFORE filter / enqueue so the drain pipeline only
	// ever sees scrubbed values. Single nil-check hoisted out of the
	// per-field loop — when unset (the common case) overhead is one
	// branch per event.
	if a.sanitizer != nil {
		if failed := applyFieldSanitizer(a.sanitizer, copied, a.logger.Load()); len(failed) > 0 {
			copied[FieldSanitizerFailedFields] = failed
		}
	}
	if mwSanitizerFailed {
		copied[FieldSanitizerFailed] = true
	}

	if !a.filter.isEnabled(eventType, a.taxonomy) {
		if a.metrics != nil {
			a.metrics.RecordFiltered(eventType)
		}
		return nil
	}

	entry, ok := auditEntryPool.Get().(*auditEntry)
	if !ok {
		entry = new(auditEntry)
	}
	entry.eventType = eventType
	entry.fields = copied
	entry.donated = donated

	if a.synchronous {
		return a.deliverSyncCtx(ctx, entry)
	}
	return a.enqueueCtx(ctx, entry)
}

// recordCtxCancelDrop emits the metric + diagnostic-log line for a
// drop caused by context cancellation. Reuses [Metrics.RecordBufferDrop]
// per ADR 0005 (#600 Q4) — operators distinguish caller-driven drops
// from queue-full drops via the slog message text.
func (a *Auditor) recordCtxCancelDrop(eventType string, cause error) {
	if a.metrics != nil {
		a.metrics.RecordBufferDrop()
	}
	a.logger.Load().Warn("audit: event dropped due to context cancellation",
		"event_type", eventType,
		"cause", cause)
}

// validateEvent checks the event type exists, merges standard-field
// defaults (in place for donated, via copy for the slow path), and
// validates field constraints. Returns the definition and the fields
// the drain pipeline will see.
func (a *Auditor) validateEvent(eventType string, fields Fields, donated bool) (*EventDef, Fields, error) {
	def, ok := a.taxonomy.Events[eventType]
	if !ok {
		if a.metrics != nil {
			a.metrics.RecordValidationError(eventType)
		}
		return nil, nil, newValidationError(ErrUnknownEventType, "audit: unknown event type %q", eventType)
	}

	var merged Fields
	if donated {
		// Donor contract: caller guarantees no mutation / no retention
		// after AuditEvent returns. We mutate in place, no clone.
		a.mergeDefaultsInPlace(fields)
		merged = fields
	} else {
		merged = a.copyFieldsWithDefaults(fields)
	}

	if err := a.validateFields(eventType, def, merged); err != nil {
		if a.metrics != nil {
			a.metrics.RecordValidationError(eventType)
		}
		return nil, nil, err
	}

	return def, merged, nil
}

// mergeDefaultsInPlace writes standard-field defaults into fields iff
// the key is not already present. Used only on the donor fast path
// (see [FieldsDonor]); the defensive-copy slow path uses
// [Auditor.copyFieldsWithDefaults] which allocates a fresh map.
func (a *Auditor) mergeDefaultsInPlace(fields Fields) {
	if len(a.standardFieldDefaults) == 0 {
		return
	}
	for k, v := range a.standardFieldDefaults {
		if _, ok := fields[k]; !ok {
			fields[k] = v
		}
	}
}

// deliverSyncCtx processes an entry synchronously. ctx is checked
// ONCE before fan-out begins — if cancelled, the entry is dropped,
// the buffer-drop metric is recorded, and ctx.Err() is returned.
// Once [processEntry] starts dispatching, all configured outputs
// receive the event; ctx is NOT threaded into individual
// [Output.Write] calls (#600 Q3). Per-output cancellation is
// deliberately out of scope to keep the Output interface unchanged.
//
// In the common [context.Background] case (`ctx.Done() == nil`),
// deliverSyncCtx is identical to the pre-#600 deliverSync — single
// processEntry call under syncMu, no extra checks.
func (a *Auditor) deliverSyncCtx(ctx context.Context, entry *auditEntry) error {
	a.syncMu.Lock()
	defer a.syncMu.Unlock()
	if done := ctx.Done(); done != nil {
		// Use the ctx-aware processEntry path so cancellation between
		// outputs is observable. Currently processEntry treats outputs
		// as a unit; ctx is rechecked at the top.
		select {
		case <-done:
			a.recordCtxCancelDrop(entry.eventType, ctx.Err())
			a.releaseEntry(entry)
			return ctx.Err() //nolint:wrapcheck // ctx.Err() returns context.Canceled / DeadlineExceeded sentinels — propagate verbatim per Go convention
		default:
		}
	}
	a.processEntry(entry)
	return nil
}

// releaseEntry returns the auditEntry's fields map to the pool (when
// not donated) and the entry itself to auditEntryPool. Used by drop
// paths in [enqueueCtx] and [deliverSyncCtx]; matches the cleanup
// performed inside [drainLoop] when an entry is consumed normally.
func (a *Auditor) releaseEntry(entry *auditEntry) {
	if !entry.donated {
		returnFieldsToPool(entry.fields)
	}
	entry.eventType = ""
	entry.fields = nil
	entry.donated = false
	auditEntryPool.Put(entry)
}

// enqueueCtx attempts a non-blocking send to the async channel,
// honouring ctx cancellation. When ctx.Done() is nil (the
// non-cancellable [context.Background] family), the path is the
// original 2-way select: send-or-drop on buffer-full, identical to
// pre-#600 behaviour. When ctx is cancellable, a 3-way select races
// send / cancel / default — a cancelled ctx aborts before the
// buffer-full drop path runs.
func (a *Auditor) enqueueCtx(ctx context.Context, entry *auditEntry) error {
	done := ctx.Done()
	if done == nil {
		// Non-cancellable fast path — unchanged from pre-#600.
		select {
		case a.ch <- entry:
			return nil
		default:
			return a.dropOnBufferFull(entry)
		}
	}
	// Ctx-aware path — race send vs cancellation.
	select {
	case a.ch <- entry:
		return nil
	case <-done:
		a.recordCtxCancelDrop(entry.eventType, ctx.Err())
		a.releaseEntry(entry)
		return ctx.Err() //nolint:wrapcheck // ctx.Err() returns context.Canceled / DeadlineExceeded sentinels — propagate verbatim per Go convention
	default:
		return a.dropOnBufferFull(entry)
	}
}

// dropOnBufferFull records the drop metric, logs the rate-limited
// warn line, and returns the entry to its pool. Returns [ErrQueueFull]
// to the caller. Extracted from the original [enqueue] body so both
// the Background fast path and the ctx-aware path share the drop
// semantics.
func (a *Auditor) dropOnBufferFull(entry *auditEntry) error {
	a.drops.record(dropWarnInterval, func(dropped int64) {
		a.logger.Load().Warn("audit: buffer full, events dropped",
			"dropped", dropped,
			"queue_size", cap(a.ch))
	})
	if a.metrics != nil {
		a.metrics.RecordBufferDrop()
	}
	a.releaseEntry(entry)
	return ErrQueueFull
}

// Close shuts down the auditor gracefully. Close MUST be called when the
// auditor is no longer needed; failing to call Close leaks the drain
// goroutine and loses all buffered events.
//
// Close signals the drain goroutine to stop, waits up to the
// configured [WithShutdownTimeout] (default 5s) for pending events
// to flush, then closes all outputs in parallel.
//
// Close is idempotent -- subsequent calls return nil (or the same
// error if an output failed to close on the first call).
func (a *Auditor) Close() error {
	a.closeOnce.Do(func() {
		a.closed.Store(true)

		if a.disabled {
			return
		}

		shutdownStart := time.Now()
		a.logger.Load().Info("audit: shutdown started")

		if !a.synchronous {
			a.cancel()
			a.waitForDrain()
		}

		a.closeErr = a.closeOutputs()

		a.logger.Load().Info("audit: shutdown complete",
			"duration", time.Since(shutdownStart))
	})
	return a.closeErr
}

// closeOutputs closes all outputs in parallel. Each output's Close
// runs in its own goroutine. An overall timeout prevents a single
// misbehaving output from blocking shutdown indefinitely.
func (a *Auditor) closeOutputs() error {
	if len(a.entries) == 0 {
		return nil
	}

	type closeResult struct { //nolint:govet // fieldalignment: readability preferred
		name string
		err  error
	}

	results := make(chan closeResult, len(a.entries))
	for _, oe := range a.entries {
		go func(oe *outputEntry) {
			results <- closeResult{
				name: oe.output.Name(),
				err:  oe.output.Close(),
			}
		}(oe)
	}

	// Overall close timeout: drain timeout covers the per-output buffer
	// drain. If any output hangs beyond this, we log and move on.
	closeTimeout := a.cfg.ShutdownTimeout + 5*time.Second
	deadlineTimer := time.NewTimer(closeTimeout)
	defer deadlineTimer.Stop()

	var closeErrs []error
	collected := 0
	for range len(a.entries) {
		select {
		case r := <-results:
			collected++
			if r.err != nil {
				a.logger.Load().Error("audit: output close failed",
					"output", r.name,
					"error", r.err)
				closeErrs = append(closeErrs, fmt.Errorf("audit: output %q: %w", r.name, r.err))
			}
		case <-deadlineTimer.C:
			remaining := len(a.entries) - collected
			a.logger.Load().Error("audit: output close timed out",
				"timeout", closeTimeout,
				"remaining_outputs", remaining)
			closeErrs = append(closeErrs, fmt.Errorf(
				"audit: %d output(s) did not close within %s", remaining, closeTimeout))
			return errors.Join(closeErrs...)
		}
	}

	return errors.Join(closeErrs...)
}

// waitForDrain waits for the drain goroutine to finish, with a
// timeout. No extra goroutine is spawned; we select on the drainDone
// channel that drainLoop closes when it exits.
func (a *Auditor) waitForDrain() {
	timer := time.NewTimer(a.cfg.ShutdownTimeout)
	defer timer.Stop()

	select {
	case <-a.drainDone:
	case <-timer.C:
		a.logger.Load().Warn("audit: drain timed out, some events may be lost",
			"shutdown_timeout", a.cfg.ShutdownTimeout,
			"buffer_remaining", len(a.ch))
	}
}

// Per-event-type and per-category enable/disable controls
// ([Auditor.EnableCategory] etc.) are defined in control.go.
// Per-output route validation and management
// ([Auditor.SetOutputRoute] etc.) are defined in route.go.

// Handle returns an [EventHandle] for the named event type. Call
// once at startup (for example during DI wiring), cache the returned
// handle, and emit via [EventHandle.Audit] per event — this avoids
// the per-call basicEvent allocation that [NewEvent] incurs via
// interface escape. Returns [ErrHandleNotFound] if the event type is
// not registered. For event types known at compile time, prefer
// generated typed builders from audit-gen.
//
// When the auditor was constructed with [WithDisabled], Handle
// returns a no-op [EventHandle] for any event type without
// validating the taxonomy — all subsequent Audit calls on the
// handle are silent no-ops, matching [Auditor.AuditEvent] on a
// disabled auditor. Metadata accessors ([EventHandle.Description],
// [EventHandle.Categories], [EventHandle.FieldInfoMap]) on a
// no-op handle return zero values.
//
// For a side-by-side comparison of NewEvent, EventHandle, and
// generated builders with examples and benchmark numbers, see
// docs/event-emission-paths.md.
func (a *Auditor) Handle(eventType string) (*EventHandle, error) {
	if a.disabled {
		return &EventHandle{name: eventType, auditor: a}, nil
	}
	def, ok := a.taxonomy.Events[eventType]
	if !ok {
		return nil, fmt.Errorf("audit: unknown event type %q: %w", eventType, ErrHandleNotFound)
	}
	// Resolve metadata once at construction so callers can introspect
	// the handle without paying a taxonomy lookup per call (#597).
	return &EventHandle{
		name:         eventType,
		auditor:      a,
		description:  def.Description,
		categories:   resolveCategoryInfos(a.taxonomy, def),
		fieldInfoMap: resolveFieldInfos(a.taxonomy, def),
	}, nil
}

// MustHandle returns an [EventHandle] for the named event type.
// It panics with an error wrapping [ErrHandleNotFound] if the event
// type is not registered. Use [Auditor.Handle] to receive the error
// instead of panicking.
//
// For a side-by-side comparison of NewEvent, EventHandle, and
// generated builders with examples and benchmark numbers, see
// docs/event-emission-paths.md.
func (a *Auditor) MustHandle(eventType string) *EventHandle {
	h, err := a.Handle(eventType)
	if err != nil {
		panic(err)
	}
	return h
}

// maxPooledFieldsLen caps the length of a Fields map that may be
// returned to [fieldsPool]. Maps longer than this are dropped and
// released to the garbage collector instead of being put back — a
// single giant event must not poison the pool for every subsequent
// caller. Matches the 64-entry cap pattern used elsewhere for pool
// hygiene (#579 B-26).
const maxPooledFieldsLen = 64

// fieldsPoolDrops counts how many [Fields] maps were dropped by
// [returnFieldsToPool] because their length exceeded
// [maxPooledFieldsLen]. Read-only in production — incremented
// atomically on each drop for observability via the
// `FieldsPoolDropsForTest` test hook (export_test.go).
var fieldsPoolDrops atomic.Uint64

// returnFieldsToPool clears a Fields map and returns it to the pool.
// Safe to call with nil (no-op). Maps whose length exceeds
// [maxPooledFieldsLen] are dropped rather than pooled so the pool
// cannot be poisoned by an outlier event.
func returnFieldsToPool(fields Fields) {
	if fields == nil {
		return
	}
	if len(fields) > maxPooledFieldsLen {
		// Drop oversized maps — let GC reclaim. Do not Put back.
		fieldsPoolDrops.Add(1)
		return
	}
	clear(fields)
	fieldsPool.Put(fields)
}

// copyFieldsWithDefaults creates a merged copy of fields + standard field
// defaults. Standard field defaults have lower precedence (key existence,
// not zero value). This avoids the double allocation that would result
// from separate copy + merge steps.
func (a *Auditor) copyFieldsWithDefaults(fields Fields) Fields {
	size := len(fields) + len(a.standardFieldDefaults)
	if size == 0 {
		return nil
	}
	cp := fieldsPool.Get().(Fields) //nolint:forcetypeassert // pool New always returns Fields
	clear(cp)
	for k, v := range fields {
		cp[k] = v
	}
	for k, v := range a.standardFieldDefaults {
		if _, exists := cp[k]; !exists {
			cp[k] = v
		}
	}
	return cp
}
