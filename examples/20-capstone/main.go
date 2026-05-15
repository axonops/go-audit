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

// Inventory Demo is a complete REST API example demonstrating audit in
// a realistic application: Postgres-backed CRUD, four audit outputs with
// HMAC integrity via OpenBao, CEF formatting, PII stripping, Loki
// dashboards, Prometheus metrics, HTTP middleware, and graceful shutdown.
//
// Application logs (slog) and audit events are separate concerns:
//   - Application logs → /data/app.log → Promtail → Loki (job=inventory-demo-app)
//   - Audit events → audit library → Loki output (job=inventory-demo-audit)
package main

import (
	"context"
	_ "embed"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/axonops/audit"
)

//go:generate go run github.com/axonops/audit/cmd/audit-gen -input taxonomy.yaml -output audit_generated.go -package main

//go:embed taxonomy.yaml
var taxonomyYAML []byte

func main() {
	// Set up structured application logging to a file.
	// Promtail ships this to Loki as a separate stream from audit events.
	appLog, appLogger := setupAppLogger()
	if appLog != nil {
		defer func() { _ = appLog.Close() }()
	}

	// Set up Prometheus metrics.
	metrics := newMetrics()

	// Set up audit auditor with four outputs.
	auditor, err := setupAuditor(metrics)
	if err != nil {
		appLogger.Error("fatal: setup audit auditor", "error", err)
		return
	}

	// Connect to Postgres.
	db, err := connectDB()
	if err != nil {
		appLogger.Error("fatal: connect db", "error", err)
		return
	}
	defer func() { _ = db.Close() }()

	if schemaErr := createSchema(db); schemaErr != nil {
		appLogger.Error("fatal: create schema", "error", schemaErr)
		return
	}

	// Set up session store, rate limiter, and admin settings.
	sessions := newSessionStore(30 * time.Minute)
	rl := newRateLimiter(1*time.Minute, 5) // 5 failures per minute per IP
	settings := newSettingsStore()

	// Build HTTP server.
	addr := envOr("LISTEN_ADDR", ":8080")
	srv := &http.Server{
		Addr:              addr,
		Handler:           newServer(auditor, db, sessions, rl, settings, withAppLogger(appLogger)),
		ReadHeaderTimeout: 5 * time.Second,
	}

	// Graceful shutdown on SIGINT/SIGTERM.
	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)

	// Emit startup audit event — good practice for compliance.
	emitLifecycleEvent(auditor, appLogger, NewAppStartupEvent("success").
		SetMessage("inventory demo started on "+addr))

	go func() {
		appLogger.Info("server started", "addr", addr)
		if listenErr := srv.ListenAndServe(); listenErr != nil && listenErr != http.ErrServerClosed {
			appLogger.Error("listen failed", "error", listenErr)
		}
	}()

	<-done
	appLogger.Info("shutdown initiated")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		appLogger.Warn("http shutdown error", "error", err)
	}

	// Emit shutdown audit event — good practice for compliance.
	emitLifecycleEvent(auditor, appLogger, NewAppShutdownEvent("success").
		SetMessage("graceful shutdown initiated"))

	// CRITICAL: Close the audit auditor. This flushes all buffered events
	// to every output. Without this call, pending events are lost and the
	// drain goroutine leaks. The shutdown event above is only delivered
	// because Close() drains the buffer before returning.
	if err := auditor.Close(); err != nil {
		appLogger.Warn("close auditor", "error", err)
	}

	appLogger.Info("shutdown complete")
}

// setupAppLogger creates a structured JSON application logger writing to both
// a file (for Promtail → Loki) and stderr (for docker compose logs).
func setupAppLogger() (*os.File, *slog.Logger) {
	logPath := envOr("APP_LOG_PATH", "/data/app.log")
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644) //nolint:gosec // log file, not secret
	if err != nil {
		// Fall back to stderr only — Promtail won't see these logs
		// but the app still works.
		auditor := slog.New(slog.NewJSONHandler(os.Stderr, nil))
		auditor.Warn("could not open app log file, using stderr only",
			"path", logPath, "error", err)
		return nil, auditor
	}
	// Write to both the file (for Promtail) and stderr (for docker compose logs).
	w := io.MultiWriter(f, os.Stderr)
	return f, slog.New(slog.NewJSONHandler(w, nil))
}

func emitLifecycleEvent(auditor *audit.Auditor, appLogger *slog.Logger, evt audit.Event) {
	if err := auditor.AuditEvent(evt); err != nil {
		appLogger.Warn("audit lifecycle event failed", "error", err)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
