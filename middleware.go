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
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"
)

const (
	// maxRequestIDLen is the maximum length of an X-Request-Id header
	// value accepted by the middleware. Values exceeding this length
	// or containing control characters are replaced with a generated UUID.
	maxRequestIDLen = 128

	// maxUserAgentLen is the maximum length of the User-Agent header
	// stored in [TransportMetadata]. Longer values are truncated to
	// prevent oversized audit events in size-limited outputs (syslog, CEF).
	maxUserAgentLen = 512

	// maxPathLen is the maximum length of the URL path stored in
	// [TransportMetadata]. Longer paths are truncated to prevent
	// oversized audit events in size-limited outputs (syslog, CEF).
	maxPathLen = 2048
)

// hintsKey is the unexported context key for [Hints].
type hintsKey struct{}

// transportMetadataPool reuses *TransportMetadata instances across
// requests to eliminate the per-request heap allocation on the
// middleware hot path (#501). Unlike [Hints], TransportMetadata is
// constructed after the handler returns and is consumed only by the
// synchronous [EventBuilder] callback inside [emitAuditEvent] — it
// is never stored in a context or retained past the middleware, so
// pool reuse is safe.
//
// Both [acquireTransportMetadata] and [releaseTransportMetadata]
// zero every field so neither a missed reset nor a missed Put can
// leak request-scoped data (ClientIP, RequestID, Path) into the
// next request's struct.
var transportMetadataPool = sync.Pool{
	New: func() any { return &TransportMetadata{} },
}

// acquireTransportMetadata returns a zeroed *TransportMetadata
// from the pool. Callers populate all fields before use.
func acquireTransportMetadata() *TransportMetadata {
	t, ok := transportMetadataPool.Get().(*TransportMetadata)
	if !ok {
		t = &TransportMetadata{}
	}
	*t = TransportMetadata{} // reset on Get — defence in depth.
	return t
}

// releaseTransportMetadata zeros every field on t and returns it
// to [transportMetadataPool]. Idempotent; callers typically invoke
// via `defer`.
func releaseTransportMetadata(t *TransportMetadata) {
	if t == nil {
		return
	}
	*t = TransportMetadata{}
	transportMetadataPool.Put(t)
}

// Hints carries mutable, per-request audit metadata through the
// request context. Handlers retrieve it with [HintsFromContext] and populate
// domain-specific fields (actor, target, outcome). The middleware
// reads these fields after the handler returns and passes them to the
// [EventBuilder] callback.
//
// Each request receives its own *Hints allocation; there is no shared
// mutable state between concurrent requests. The middleware does NOT
// pool *Hints because consumer handlers are allowed to capture
// r.Context() into spawned goroutines that outlive ServeHTTP and read
// [HintsFromContext] lazily; pooling Hints would silently expose those
// goroutines to recycled state (#501).
type Hints struct {
	// Extra holds arbitrary domain-specific fields. It is initialised
	// lazily by the handler. Keys and values are passed through to
	// the [EventBuilder] callback.
	Extra map[string]any

	// EventType is the audit event type name (e.g. "user_create").
	// If empty, the [EventBuilder] decides the event type.
	EventType string

	// Outcome is the high-level result: "success", "failure", "denied", etc.
	Outcome string

	// ActorID identifies the authenticated principal (user ID, service account, etc.).
	ActorID string

	// ActorType categorises the actor: "user", "service", "api_key", etc.
	ActorType string

	// AuthMethod describes how the actor authenticated: "bearer", "mtls", "session", etc.
	AuthMethod string

	// Role is the actor's role or permission level at the time of the request.
	Role string

	// TargetType categorises the resource being acted upon: "document", "user", etc.
	TargetType string

	// TargetID identifies the specific resource being acted upon.
	TargetID string

	// Reason is a human-readable justification for the action, if applicable.
	Reason string

	// Error holds an error message when the request fails.
	Error string
}

// TransportMetadata contains HTTP transport-level fields captured
// automatically by the middleware. These are read-only values passed
// to the [EventBuilder] callback; handlers do not need to set them.
//
// TransportMetadata is pool-managed: the pointer passed to
// [EventBuilder] is valid only for the duration of that callback.
// Copy any field values you need to retain; do not store the pointer
// itself, pass it to goroutines, or place it into the returned
// [Fields] map — the pool reset will zero every field before the
// next request sees the struct. See #501.
type TransportMetadata struct {
	// ClientIP is the client's IP address, extracted from the
	// rightmost X-Forwarded-For entry, X-Real-IP, or RemoteAddr.
	ClientIP string

	// TransportSecurity describes the TLS state: "none", "tls", or "mtls".
	TransportSecurity string

	// Method is the HTTP method (GET, POST, etc.).
	Method string

	// Path is the request URL path.
	Path string

	// UserAgent is the request's User-Agent header value.
	UserAgent string

	// RequestID is the request identifier, taken from the X-Request-Id
	// header or generated as a v4 UUID.
	RequestID string

	// Duration is the wall-clock time the handler took to execute.
	Duration time.Duration

	// StatusCode is the HTTP status code written by the handler.
	StatusCode int
}

// EventBuilder is a callback that transforms per-request [Hints] and
// [TransportMetadata] into an audit event. The middleware calls it
// after the handler returns (or panics).
//
// Return values:
//   - eventType: the taxonomy event type name to pass to [Auditor.AuditEvent]
//   - fields: the audit event fields
//   - skip: if true, no audit event is emitted for this request
type EventBuilder func(hints *Hints, transport *TransportMetadata) (eventType string, fields Fields, skip bool)

// HintsFromContext retrieves the [Hints] from the request context. Returns
// nil if the request was not wrapped by [Middleware].
func HintsFromContext(ctx context.Context) *Hints {
	h, _ := ctx.Value(hintsKey{}).(*Hints)
	return h
}

// Middleware returns HTTP middleware that captures transport metadata
// automatically and calls the [EventBuilder] after the handler
// returns. The builder transforms [Hints] (populated by the handler)
// and [TransportMetadata] into an audit event.
//
// If auditor is nil, the returned middleware is an identity function
// that passes requests through without auditing. This allows
// consumers to conditionally disable audit middleware without
// nil-checking at every call site.
//
// Middleware panics if builder is nil. Passing a nil builder is a
// programming error: there is no recoverable behaviour when the
// event-building callback is absent. Pass a nil *[Auditor] instead
// to disable auditing without removing the middleware.
//
// # Placement
//
// Middleware SHOULD be placed OUTSIDE any panic-recovery middleware
// in the chain — i.e. the audit middleware wraps the recovery
// middleware, not the other way round. The rule matters because
// Middleware always catches panics internally (to record an audit
// event before the request goroutine unwinds) and then re-raises so
// that a downstream recovery middleware can render the final
// response.
//
// Correct (audit outermost, recovery inside):
//
//	handler := audit.Middleware(auditor, builder)(     // OUTER
//	    recoveryMiddleware(                            // INNER — catches panic first
//	        yourHandler,
//	    ),
//	)
//
// Flow on a panic: yourHandler panics, the inner recovery middleware
// catches it and writes its chosen response (typically 500), the
// handler returns normally. Middleware sees the already-recorded
// status code on the response writer and records the audit event.
// No re-raise is emitted because invokeHandler observed a clean
// return. The status code in the audit event matches the status the
// recovery middleware actually wrote.
//
// Wrong (recovery outermost — fragile, not recommended):
//
//	handler := recoveryMiddleware(                     // OUTER — catches re-raise
//	    audit.Middleware(auditor, builder)(            // INNER — records event, re-raises
//	        yourHandler,
//	    ),
//	)
//
// Flow on a panic: yourHandler panics, Middleware's internal
// recover() catches it, sets the response-writer status to 500,
// records the audit event, and re-raises. The outer recovery
// middleware then catches the re-raised panic and writes its own
// response. The audit event IS emitted, but with two downsides: the
// status code in the event is always 500 (set internally by
// Middleware before the re-raise), independent of what the outer
// recovery actually renders; and some recovery frameworks mishandle
// a second recover pass for unknown panic values, producing a
// crashed request goroutine with inconsistent logging.
//
// See docs/http-middleware.md for the detailed rationale and
// framework-specific wiring examples (#491).
//
// # Buffer-full behaviour
//
// If the auditor's async queue is at capacity when the middleware
// tries to enqueue the request's audit event, the emission returns
// [ErrQueueFull] and the middleware DROPS the event silently — the
// request handler runs normally and the response is unaffected. To
// observe queue-full drops, configure a [Metrics] implementation
// via [WithMetrics] and watch [Metrics.RecordBufferDrop]; if drop
// rates are non-zero in steady state, raise [WithQueueSize] or
// reduce per-request emission frequency.
func Middleware(auditor *Auditor, builder EventBuilder) func(http.Handler) http.Handler {
	if auditor == nil {
		return func(next http.Handler) http.Handler { return next }
	}
	if builder == nil {
		panic("audit: EventBuilder must not be nil")
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			serveAudit(w, r, next, auditor, builder)
		})
	}
}

// serveAudit is the per-request handler logic extracted from
// [Middleware] to keep cognitive complexity within bounds.
func serveAudit(w http.ResponseWriter, r *http.Request, next http.Handler, auditor *Auditor, builder EventBuilder) {
	hints := &Hints{} // never pooled — see [Hints] godoc for rationale (#501).
	ctx := context.WithValue(r.Context(), hintsKey{}, hints)
	r = r.WithContext(ctx)

	reqID := r.Header.Get("X-Request-Id")
	if !validRequestID(reqID) {
		reqID = newRequestID(auditor.logger.Load())
	}

	rw := acquireResponseWriter(w)
	defer releaseResponseWriter(rw)

	start := time.Now()

	panicked, panicVal := invokeHandler(next, rw, r)

	// Sanitizer panic-path hook (#598). Run BETWEEN the recover() in
	// invokeHandler and the audit emission / re-raise so the same
	// (sanitised) value reaches both sinks. The sanitiser call itself
	// is wrapped in its own recover() inside safeSanitizePanic — a
	// sanitiser-of-sanitiser panic must not poison the panic chain
	// that this handler is already managing.
	var sanitizerFailed bool
	if panicked && auditor.sanitizer != nil {
		panicVal, sanitizerFailed = safeSanitizePanic(auditor.sanitizer, auditor.logger.Load(), panicVal)
	}

	statusCode := rw.statusCode
	if !rw.written {
		statusCode = http.StatusOK
	}

	transport := acquireTransportMetadata()
	defer releaseTransportMetadata(transport)
	transport.ClientIP = clientIP(r)
	transport.TransportSecurity = transportSecurity(r)
	transport.Method = r.Method
	transport.Path = truncateString(r.URL.Path, maxPathLen)
	transport.UserAgent = truncateString(r.UserAgent(), maxUserAgentLen)
	transport.RequestID = reqID
	transport.StatusCode = statusCode
	transport.Duration = time.Since(start)

	emitAuditEvent(r.Context(), auditor, builder, hints, transport, sanitizerFailed)

	if panicked {
		panic(panicVal)
	}
}

// invokeHandler calls next.ServeHTTP with panic recovery. If the
// handler panics, the status code is set to 500 and the panic value
// is captured for re-raising after the audit event is emitted.
func invokeHandler(next http.Handler, rw *responseWriter, r *http.Request) (panicked bool, panicVal any) {
	defer func() {
		if v := recover(); v != nil {
			panicked = true
			panicVal = v
			if !rw.written {
				rw.statusCode = http.StatusInternalServerError
				rw.written = true
			}
		}
	}()
	next.ServeHTTP(rw, r)
	return false, nil
}

// emitAuditEvent calls the EventBuilder and, if not skipped, emits
// the audit event. Builder panics are recovered and logged. When
// sanitizerFailed is true (set when [Sanitizer.SanitizePanic]
// panicked during panic-recovery, see #598), the framework field
// [FieldSanitizerFailed] is injected post-validation so SIEM tooling
// can route on the failure.
//
// The request-scoped ctx is threaded into the audit pipeline via
// [Auditor.auditInternalDonatedFlagsCtx], honouring cancellation /
// deadline at the well-defined boundary points documented on
// [Auditor.AuditEventContext] (#600).
func emitAuditEvent(ctx context.Context, auditor *Auditor, builder EventBuilder, hints *Hints, transport *TransportMetadata, sanitizerFailed bool) {
	var (
		eventType string
		fields    Fields
		skip      bool
	)

	func() {
		defer func() {
			if v := recover(); v != nil {
				panicStr := truncateString(fmt.Sprintf("%v", v), 512)
				auditor.logger.Load().Error("audit: EventBuilder panicked",
					"panic", panicStr,
					"request_id", transport.RequestID)
				skip = true
			}
		}()
		eventType, fields, skip = builder(hints, transport)
	}()

	if skip {
		return
	}

	// Use the ctx + flags-aware internal path so [FieldSanitizerFailed]
	// is injected AFTER validation (the flag is library-set — strict
	// validation MUST not reject it) AND the request-scoped ctx is
	// honoured for cancellation at the boundary points (#600).
	if err := auditor.auditInternalDonatedFlagsCtx(ctx, eventType, fields, false, sanitizerFailed); err != nil {
		auditor.logger.Load().Warn("audit: middleware event failed",
			"event_type", eventType,
			"request_id", transport.RequestID,
			"error", err)
	}
}
