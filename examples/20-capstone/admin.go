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
	"sync"

	"github.com/axonops/audit"
)

// settingsStore holds application settings in memory. In production,
// use a database or configuration service.
type settingsStore struct { //nolint:govet // fieldalignment: readability preferred
	mu       sync.RWMutex
	settings map[string]string
}

func newSettingsStore() *settingsStore {
	return &settingsStore{
		settings: map[string]string{
			"rate_limit_threshold":    "5",
			"session_timeout_minutes": "30",
			"maintenance_mode":        "false",
		},
	}
}

func (s *settingsStore) getAll() map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cp := make(map[string]string, len(s.settings))
	for k, v := range s.settings {
		cp[k] = v
	}
	return cp
}

func (s *settingsStore) update(key, value string) (old string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok = s.settings[key]
	if !ok {
		return "", false
	}
	s.settings[key] = value
	return old, true
}

// --- Admin authorization ---

const adminUser = "admin"

// requireAdmin checks that the authenticated user is the admin.
// Returns true if authorized; writes 403 and sets audit hints on failure.
func requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	hints := audit.HintsFromContext(r.Context())
	if hints == nil || hints.ActorID != adminUser {
		if hints != nil {
			hints.EventType = EventAuthorizationFailure
			hints.Outcome = "failure"
			hints.Reason = "admin access required"
		}
		http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
		return false
	}
	return true
}

// --- Admin handlers ---

// adminHandlers serve admin and compliance endpoints. These go through
// the audit middleware but override hints.EventType because their
// routes don't match the simple resource/{id} pattern in routeTable.
type adminHandlers struct {
	db       *sql.DB
	settings *settingsStore
	log      *slog.Logger
}

func (a *adminHandlers) getSettings(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	writeJSON(w, http.StatusOK, a.settings.getAll())
}

func (a *adminHandlers) updateSettings(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}

	// Set event type early so error paths are audited.
	if hints := audit.HintsFromContext(r.Context()); hints != nil {
		hints.EventType = EventConfigChange
	}

	var req struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}
	// Production: use http.MaxBytesReader to bound request size.
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Key == "" {
		writeError(w, r, http.StatusBadRequest, "key is required")
		return
	}

	oldVal, ok := a.settings.update(req.Key, req.Value)
	if !ok {
		writeError(w, r, http.StatusBadRequest, "unknown setting key")
		return
	}

	// Override event type — admin routes bypass the routeTable.
	if hints := audit.HintsFromContext(r.Context()); hints != nil {
		hints.EventType = EventConfigChange
		if hints.Extra == nil {
			hints.Extra = make(map[string]any)
		}
		hints.Extra[FieldSettingKey] = req.Key
		hints.Extra[FieldOldValue] = oldVal
		hints.Extra[FieldNewValue] = req.Value
	}
	writeJSON(w, http.StatusOK, a.settings.getAll())
}

// exportUsers returns all users including PII (email, phone).
// Production: paginate results, enforce export rate limits, and
// consider a redacted view or async export with download link.
func (a *adminHandlers) exportUsers(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}

	// Set event type early so error paths are audited.
	if hints := audit.HintsFromContext(r.Context()); hints != nil {
		hints.EventType = EventDataExport
	}

	users, err := queryUsers(a.db)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "export failed")
		return
	}

	// Override event type — compliance routes bypass the routeTable.
	if hints := audit.HintsFromContext(r.Context()); hints != nil {
		hints.EventType = EventDataExport
		if hints.Extra == nil {
			hints.Extra = make(map[string]any)
		}
		hints.Extra[FieldRecordCount] = len(users)
	}
	writeJSON(w, http.StatusOK, users)
}

func (a *adminHandlers) bulkDeleteItems(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}

	// Set event type early so error paths are audited.
	if hints := audit.HintsFromContext(r.Context()); hints != nil {
		hints.EventType = EventBulkDelete
	}

	result, err := a.db.Exec("DELETE FROM items WHERE id NOT IN (SELECT DISTINCT item_id FROM orders)")
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "bulk delete failed")
		return
	}
	affected, rowsErr := result.RowsAffected()
	if rowsErr != nil {
		writeError(w, r, http.StatusInternalServerError, "bulk delete failed")
		return
	}

	// Override event type — compliance routes bypass the routeTable.
	if hints := audit.HintsFromContext(r.Context()); hints != nil {
		hints.EventType = EventBulkDelete
		if hints.Extra == nil {
			hints.Extra = make(map[string]any)
		}
		hints.Extra[FieldAffectedCount] = affected
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": affected})
}
