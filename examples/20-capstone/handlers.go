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
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/axonops/audit"
)

// handlers holds dependencies shared across all HTTP handlers.
type handlers struct {
	db  *sql.DB
	log *slog.Logger
}

// writeJSON encodes v as JSON and writes it with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// populatePIIHints adds PII fields (email, phone) to hints.Extra so they
// flow through sensitivity filtering. On Loki (exclude_labels: [pii]),
// these fields are stripped. On stdout and audit.log, they appear in full.
func populatePIIHints(hints *audit.Hints, email, phone string) {
	if hints == nil {
		return
	}
	if hints.Extra == nil {
		hints.Extra = make(map[string]any)
	}
	hints.Extra[FieldEmail] = email
	if phone != "" {
		hints.Extra[FieldPhone] = phone
	}
}

// writeError records a failure in audit hints and writes an error response.
func writeError(w http.ResponseWriter, r *http.Request, status int, msg string) {
	if hints := audit.HintsFromContext(r.Context()); hints != nil {
		hints.Outcome = "failure"
		hints.Error = msg
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
