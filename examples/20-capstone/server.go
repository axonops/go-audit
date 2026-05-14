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

package main

import (
	"database/sql"
	"log/slog"
	"net/http"
	"strings"

	"github.com/axonops/audit"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// routeTable maps "METHOD resource" or "METHOD resource/{id}" to audit
// event types. This map is never written after program start — treat it
// as a constant. If runtime mutation were needed, use a sync.Map or a
// mutex-guarded copy. IMPORTANT: when adding routes below, also add
// the event mapping here.
var routeTable = map[string]string{
	// Items
	"GET items":         EventItemList,
	"GET items/{id}":    EventItemRead,
	"POST items":        EventItemCreate,
	"PUT items/{id}":    EventItemUpdate,
	"DELETE items/{id}": EventItemDelete,
	// Users
	"GET users":         EventUserList,
	"GET users/{id}":    EventUserRead,
	"POST users":        EventUserCreate,
	"PUT users/{id}":    EventUserUpdate,
	"DELETE users/{id}": EventUserDelete,
	// Orders — no DELETE: orders are immutable once placed; use status updates.
	"GET orders":      EventOrderList,
	"GET orders/{id}": EventOrderRead,
	"POST orders":     EventOrderCreate,
	"PUT orders/{id}": EventOrderUpdate,
}

type serverOpts struct {
	log *slog.Logger
}

func withAppLogger(l *slog.Logger) func(*serverOpts) {
	return func(o *serverOpts) { o.log = l }
}

// newServer builds the HTTP handler with two layers:
//
//   - outerMux: login/logout (self-auditing, outside middleware chain)
//   - innerMux: CRUD routes (wrapped by auth + audit middleware)
//
// Login/logout emit audit events directly because they ARE the
// security action. CRUD routes emit events via the audit middleware.
func newServer(auditor *audit.Auditor, db *sql.DB, sessions *sessionStore, rl *rateLimiter, settings *settingsStore, opts ...func(*serverOpts)) http.Handler {
	so := &serverOpts{log: slog.Default()}
	for _, o := range opts {
		o(so)
	}

	// --- Inner mux: CRUD + admin routes (auth + audit middleware) ---
	innerMux := http.NewServeMux()

	h := &handlers{db: db, log: so.log}
	adminH := &adminHandlers{db: db, settings: settings, log: so.log}
	registerInfraRoutes(innerMux)
	registerCRUDRoutes(innerMux, h)
	registerAdminRoutes(innerMux, adminH)

	// Apply middleware: auth first, then audit.
	authed := authMiddleware(sessions)(innerMux)
	audited := audit.Middleware(auditor, buildAuditEvent)(authed)

	// --- Outer mux: auth endpoints (self-auditing, no middleware) ---
	outerMux := http.NewServeMux()

	authH := &authHandlers{auditor: auditor, sessions: sessions, rl: rl, log: so.log}

	// Login is wrapped by rate limiter. Logout is not.
	outerMux.Handle("POST /login",
		rateLimitMiddleware(auditor, rl)(http.HandlerFunc(authH.login)))
	outerMux.HandleFunc("POST /logout", authH.logout)

	// Web UI — served directly, not audited (page loads are not audit events).
	outerMux.Handle("GET /{$}", serveUI())

	// Everything else goes through the middleware chain.
	outerMux.Handle("/", audited)

	return outerMux
}

func registerInfraRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.Handle("GET /metrics", promhttp.Handler())
}

func registerCRUDRoutes(mux *http.ServeMux, h *handlers) {
	// Items
	mux.HandleFunc("GET /items", h.listItems)
	mux.HandleFunc("GET /items/{id}", h.getItem)
	mux.HandleFunc("POST /items", h.createItem)
	mux.HandleFunc("PUT /items/{id}", h.updateItem)
	mux.HandleFunc("DELETE /items/{id}", h.deleteItem)

	// Users
	mux.HandleFunc("GET /users", h.listUsers)
	mux.HandleFunc("GET /users/{id}", h.getUser)
	mux.HandleFunc("POST /users", h.createUser)
	mux.HandleFunc("PUT /users/{id}", h.updateUser)
	mux.HandleFunc("DELETE /users/{id}", h.deleteUser)

	// Orders
	mux.HandleFunc("GET /orders", h.listOrders)
	mux.HandleFunc("GET /orders/{id}", h.getOrder)
	mux.HandleFunc("POST /orders", h.createOrder)
	mux.HandleFunc("PUT /orders/{id}", h.updateOrder)
}

func registerAdminRoutes(mux *http.ServeMux, a *adminHandlers) {
	// Admin settings — successful GET reads are not audited (low value);
	// authorization failures are still captured via requireAdmin.
	// PUT writes emit config_change via hints.EventType override.
	mux.HandleFunc("GET /admin/settings", a.getSettings)
	mux.HandleFunc("PUT /admin/settings", a.updateSettings)

	// Compliance endpoints — emit data_export / bulk_delete via
	// hints.EventType override (severity 9, compliance category).
	mux.HandleFunc("GET /export/users", a.exportUsers)
	mux.HandleFunc("DELETE /admin/bulk-delete/items", a.bulkDeleteItems)
}

// buildAuditEvent maps HTTP request metadata to audit events.
func buildAuditEvent(hints *audit.Hints, transport *audit.TransportMetadata) (eventType string, fields audit.Fields, skip bool) {
	// Skip health checks and metrics scrapes.
	if transport.Path == "/healthz" || transport.Path == "/metrics" {
		return "", nil, true
	}

	// If the auth middleware set an event type (e.g., auth_failure),
	// use that instead of the default.
	eventType = hints.EventType
	if eventType == "" {
		eventType = mapHTTPToEvent(transport.Method, transport.Path)
	}

	// Skip unknown routes (e.g., favicon.ico, undefined paths).
	if eventType == "" {
		return "", nil, true
	}

	return eventType, collectFields(hints, transport), false
}

// collectFields builds the audit Fields map from hints and transport metadata.
func collectFields(hints *audit.Hints, transport *audit.TransportMetadata) audit.Fields {
	fields := audit.Fields{
		FieldOutcome: hints.Outcome,
	}

	if hints.ActorID != "" {
		fields[FieldActorID] = hints.ActorID
	}
	if hints.TargetID != "" {
		fields[FieldTargetID] = hints.TargetID
	}
	// Error takes precedence over reason when both are set.
	if hints.Reason != "" {
		fields[FieldReason] = hints.Reason
	}
	if hints.Error != "" {
		fields[FieldReason] = hints.Error
	}
	if transport.ClientIP != "" {
		fields[FieldSourceIP] = transport.ClientIP
	}

	// Copy Extra fields (e.g., PII fields like email, phone) so they
	// flow through sensitivity filtering in the output pipeline.
	// Guard: framework fields take precedence over Extra to prevent
	// audit log spoofing via hints.Extra["outcome"] = "success".
	for k, v := range hints.Extra {
		if _, isFramework := fields[k]; !isFramework {
			fields[k] = v
		}
	}

	return fields
}

// mapHTTPToEvent maps HTTP method + resolved path to an audit event type
// using the routeTable. Returns empty string for unrecognised routes.
func mapHTTPToEvent(method, path string) string {
	resource, hasID := parseResource(path)
	if resource == "" {
		return ""
	}

	key := method + " " + resource
	if hasID {
		key += "/{id}"
	}
	return routeTable[key]
}

// parseResource extracts the resource name and whether an ID segment is
// present from a URL path. "/users" → ("users", false),
// "/users/abc-123" → ("users", true).
func parseResource(path string) (resource string, hasID bool) {
	parts := strings.SplitN(strings.TrimPrefix(path, "/"), "/", 3)
	if len(parts) == 0 || parts[0] == "" {
		return "", false
	}
	return parts[0], len(parts) >= 2 && parts[1] != ""
}
