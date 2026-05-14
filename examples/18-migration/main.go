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

// Migration demonstrates the **coexistence pattern** between an
// application logger (here, log/slog) and the audit library. The two
// loggers serve different purposes and run side-by-side: slog records
// technical details for debugging; audit records compliance events
// validated against a taxonomy.
//
// See docs/migrating-from-application-logging.md for the
// transformation tables that map logrus, zap, zerolog, and slog
// patterns onto the audit equivalents.
//
// Run:
//
//	go generate ./...
//	go run .
//
// Then in another shell:
//
//	curl -X POST http://localhost:8080/users -d '{"name":"alice"}'
//	curl -X POST http://localhost:8080/login -u alice:wrong-password
//
// Watch the JSON output: app-log lines (level=INFO/DEBUG/ERROR with
// msg=) interleave with audit events (event_type=user_create / etc.,
// validated against taxonomy.yaml).
package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/axonops/audit"
	"github.com/axonops/audit/outputconfig"
	_ "github.com/axonops/audit/outputs"
)

//go:generate go run github.com/axonops/audit/cmd/audit-gen -input taxonomy.yaml -output audit_generated.go -package main

//go:embed taxonomy.yaml
var taxonomyYAML []byte

// server holds the two loggers side-by-side. Both are independent;
// the audit library does not depend on slog and slog does not depend
// on the audit library.
type server struct {
	appLog  *slog.Logger
	auditor *audit.Auditor
}

func main() {
	// 1. Application logger — slog at INFO, JSON to stderr. Used for
	//    technical detail (request tracing, errors, performance).
	appLog := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// 2. Audit logger — schema-enforced, JSON to stdout. Used for
	//    compliance events (who did what to which resource).
	auditor, err := outputconfig.New(context.Background(), taxonomyYAML, "outputs.yaml")
	if err != nil {
		appLog.Error("failed to create auditor", "error", err)
		os.Exit(1)
	}
	defer func() { _ = auditor.Close() }()

	srv := &server{appLog: appLog, auditor: auditor}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /users", srv.handleCreateUser)
	mux.HandleFunc("POST /login", srv.handleLogin)

	httpSrv := &http.Server{
		Addr:              ":8080",
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	appLog.Info("server starting", "addr", httpSrv.Addr)
	if listenErr := httpSrv.ListenAndServe(); listenErr != nil && !errors.Is(listenErr, http.ErrServerClosed) {
		appLog.Error("server stopped", "error", listenErr)
	}
}

// handleCreateUser shows the canonical coexistence pattern:
//
//   - appLog records request lifecycle and any technical errors.
//   - auditor records the compliance event (user_create) once, with
//     validated fields, only when the operation succeeds.
//
// Notice: app-log lines and audit events do not duplicate each other.
// The app log says "we processed a request"; the audit event says
// "alice created a user account at 12:34:05".
func (s *server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	s.appLog.Info("create user request received",
		"method", r.Method,
		"path", r.URL.Path,
		"remote_addr", r.RemoteAddr,
	)

	var body struct {
		Name string `json:"name"`
	}
	if decodeErr := json.NewDecoder(r.Body).Decode(&body); decodeErr != nil {
		// Application log: technical decode failure.
		s.appLog.Warn("decode request body", "error", decodeErr)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	actorID := r.Header.Get("X-Actor")
	if actorID == "" {
		actorID = "anonymous"
	}

	// Audit event: who did what, validated against the taxonomy.
	if auditErr := s.auditor.AuditEvent(
		NewUserCreateEvent(actorID, "success").
			SetTargetID(body.Name).
			SetSourceIP(r.RemoteAddr),
	); auditErr != nil {
		// Audit failure is itself a compliance concern — log it on
		// the application channel so SREs see it.
		s.appLog.Error("audit emission failed", "error", auditErr)
	}

	// Application log: outcome and timing for SRE dashboards.
	s.appLog.Info("create user complete",
		"duration_ms", time.Since(start).Milliseconds(),
		"actor_id", actorID,
	)

	w.WriteHeader(http.StatusCreated)
}

// handleLogin shows the failure path: every wrong-password attempt
// emits an auth_failure audit event AND an application warning. The
// app log helps SREs spot brute-force patterns; the audit event is
// the compliance record SOX/HIPAA auditors will request.
func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	user, pass, ok := r.BasicAuth()
	if !ok || pass != "correct-password" {
		// Application log: technical detail.
		s.appLog.Warn("authentication failed",
			"user", user,
			"reason", "invalid credentials",
			"remote_addr", r.RemoteAddr,
		)
		// Audit event: compliance record.
		if auditErr := s.auditor.AuditEvent(
			NewAuthFailureEvent(user, "failure").
				SetSourceIP(r.RemoteAddr).
				SetReason("invalid credentials"),
		); auditErr != nil {
			s.appLog.Error("audit emission failed", "error", auditErr)
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if auditErr := s.auditor.AuditEvent(
		NewAuthSuccessEvent(user, "success").SetSourceIP(r.RemoteAddr),
	); auditErr != nil {
		s.appLog.Error("audit emission failed", "error", auditErr)
	}

	s.appLog.Info("authentication succeeded", "user", user)
	w.WriteHeader(http.StatusOK)
}
