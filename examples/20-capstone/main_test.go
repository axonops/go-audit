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

// Unit tests for the CRUD API capstone example using audittest.
//
// These tests demonstrate how to verify audit events in a realistic
// HTTP application using audittest.New and the full middleware
// stack. The auditor is wired with the production middleware,
// so events flow through buildAuditEvent → collectFields → Auditor
// exactly as they do in the running application.
package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/axonops/audit/audittest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testEnv holds all test dependencies. Call Flush() before asserting
// on the recorder — events are async and need the drain goroutine
// to flush.
type testEnv struct {
	srv     *httptest.Server
	rec     *audittest.Recorder
	auditor interface{ Close() error }
}

// Flush stops the HTTP server and closes the auditor so all
// buffered events are visible in the recorder. Call this before
// any assertions on the recorder. Safe to call multiple times.
func (e *testEnv) Flush(t *testing.T) {
	t.Helper()
	e.srv.Close()
	if closeErr := e.auditor.Close(); closeErr != nil {
		t.Errorf("auditor close: %v", closeErr)
	}
}

func newTestServer(t *testing.T, dbSetup func(mock sqlmock.Sqlmock)) *testEnv {
	t.Helper()

	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	if dbSetup != nil {
		dbSetup(mock)
	}
	t.Cleanup(func() {
		if mockErr := mock.ExpectationsWereMet(); mockErr != nil {
			t.Errorf("sqlmock: unfulfilled expectations: %v", mockErr)
		}
	})

	auditor, rec, _ := audittest.New(t, taxonomyYAML) // metrics not asserted
	sessions := newSessionStore(30 * time.Minute)
	rl := newRateLimiter(1*time.Minute, 5)
	settings := newSettingsStore()
	handler := newServer(auditor, db, sessions, rl, settings)

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close) // safety net — prevents server leak on early failure

	return &testEnv{srv: srv, rec: rec, auditor: auditor}
}

// doRequest makes an HTTP request with optional auth and body.
// Returns the status code. The response body is closed without reading.
func doRequest(t *testing.T, baseURL, method, path, apiKey string, body any) int {
	t.Helper()

	var bodyReader *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		require.NoError(t, err)
		bodyReader = bytes.NewReader(b)
	}

	var req *http.Request
	var err error
	if bodyReader != nil {
		req, err = http.NewRequestWithContext(t.Context(), method, baseURL+path, bodyReader)
	} else {
		req, err = http.NewRequestWithContext(t.Context(), method, baseURL+path, http.NoBody)
	}
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	return resp.StatusCode
}

// --- Auth failure tests (no DB needed) ---

func TestAuthFailure_InvalidAPIKey(t *testing.T) {
	env := newTestServer(t, nil)

	status := doRequest(t, env.srv.URL, "GET", "/items", "bad-key-xyz", nil)
	assert.Equal(t, http.StatusUnauthorized, status)

	// Drain the async buffer so events are visible in the recorder.
	env.Flush(t)

	events := env.rec.FindByType(EventAuthFailure)
	require.Len(t, events, 1, "expected one auth_failure event")

	evt := events[0]
	require.Nil(t, evt.ParseErr)
	// The auth middleware truncates the key to 4 chars + "..."
	assert.Equal(t, "bad-...", evt.StringField(FieldActorID))
	assert.Equal(t, "failure", evt.StringField(FieldOutcome))
	assert.Equal(t, "invalid credentials", evt.StringField(FieldReason))
}

func TestAuthFailure_NoCredentials(t *testing.T) {
	env := newTestServer(t, nil)

	status := doRequest(t, env.srv.URL, "GET", "/items", "", nil)
	assert.Equal(t, http.StatusUnauthorized, status)

	env.Flush(t)

	events := env.rec.FindByType(EventAuthFailure)
	require.Len(t, events, 1)
	assert.Equal(t, "anonymous", events[0].StringField(FieldActorID))
}

// --- Admin authorization tests (no DB needed) ---

func TestAdminSettings_NonAdmin_Forbidden(t *testing.T) {
	env := newTestServer(t, nil)

	status := doRequest(t, env.srv.URL, "GET", "/admin/settings", "key-alice", nil)
	assert.Equal(t, http.StatusForbidden, status)

	env.Flush(t)

	events := env.rec.FindByType(EventAuthorizationFailure)
	require.Len(t, events, 1, "expected one authorization_failure event")

	evt := events[0]
	require.Nil(t, evt.ParseErr)
	assert.Equal(t, "alice", evt.StringField(FieldActorID))
	assert.Equal(t, "failure", evt.StringField(FieldOutcome))
	assert.Equal(t, "admin access required", evt.StringField(FieldReason))
}

func TestAdminSettings_AdminAllowed(t *testing.T) {
	env := newTestServer(t, nil)

	status := doRequest(t, env.srv.URL, "GET", "/admin/settings", "key-admin", nil)
	assert.Equal(t, http.StatusOK, status)

	env.Flush(t)

	// GET /admin/settings does not emit an audit event (read, not audited).
	// But an auth_success is NOT emitted either since the middleware uses
	// hints.EventType only for failures. The route table doesn't match
	// admin paths, so no event is emitted for successful reads.
	events := env.rec.Events()
	for _, e := range events {
		assert.NotEqual(t, EventAuthorizationFailure, e.EventType,
			"admin should not trigger authorization_failure")
	}
}

// --- Config change test (no DB needed) ---

func TestConfigChange_EmitsEventWithOldNewValues(t *testing.T) {
	env := newTestServer(t, nil)

	status := doRequest(t, env.srv.URL, "PUT", "/admin/settings", "key-admin",
		map[string]string{"key": "maintenance_mode", "value": "true"})
	assert.Equal(t, http.StatusOK, status)

	env.Flush(t)

	events := env.rec.FindByType(EventConfigChange)
	require.Len(t, events, 1, "expected one config_change event")

	evt := events[0]
	require.Nil(t, evt.ParseErr)
	assert.Equal(t, "admin", evt.StringField(FieldActorID))
	assert.Equal(t, "success", evt.StringField(FieldOutcome))
	assert.Equal(t, "maintenance_mode", evt.StringField(FieldSettingKey))
	assert.Equal(t, "false", evt.StringField(FieldOldValue))
	assert.Equal(t, "true", evt.StringField(FieldNewValue))
}

// --- Item CRUD test (requires sqlmock) ---

func TestCreateItem_EmitsItemCreateEvent(t *testing.T) {
	now := time.Now()
	env := newTestServer(t, func(mock sqlmock.Sqlmock) {
		mock.ExpectQuery("INSERT INTO items").
			WithArgs(sqlmock.AnyArg(), "Widget", "A test widget").
			WillReturnRows(sqlmock.NewRows(
				[]string{"id", "name", "description", "created_at", "updated_at"},
			).AddRow("item-uuid-1", "Widget", "A test widget", now, now))
	})

	status := doRequest(t, env.srv.URL, "POST", "/items", "key-alice",
		map[string]string{"name": "Widget", "description": "A test widget"})
	assert.Equal(t, http.StatusCreated, status)

	env.Flush(t)

	events := env.rec.FindByType(EventItemCreate)
	require.Len(t, events, 1, "expected one item_create event")

	evt := events[0]
	require.Nil(t, evt.ParseErr)
	assert.Equal(t, "alice", evt.StringField(FieldActorID))
	assert.Equal(t, "success", evt.StringField(FieldOutcome))
	assert.NotEmpty(t, evt.StringField(FieldTargetID))
}

// --- User create with PII fields ---

func TestCreateUser_EmitsPIIFields(t *testing.T) {
	now := time.Now()
	env := newTestServer(t, func(mock sqlmock.Sqlmock) {
		mock.ExpectQuery("INSERT INTO users").
			WithArgs(sqlmock.AnyArg(), "testuser", "test@example.com", "+1555000").
			WillReturnRows(sqlmock.NewRows(
				[]string{"id", "username", "email", "phone", "created_at", "updated_at"},
			).AddRow("user-uuid-1", "testuser", "test@example.com", "+1555000", now, now))
	})

	status := doRequest(t, env.srv.URL, "POST", "/users", "key-alice",
		map[string]string{"username": "testuser", "email": "test@example.com", "phone": "+1555000"})
	assert.Equal(t, http.StatusCreated, status)

	env.Flush(t)

	events := env.rec.FindByType(EventUserCreate)
	require.Len(t, events, 1, "expected one user_create event")

	evt := events[0]
	require.Nil(t, evt.ParseErr)
	assert.Equal(t, "alice", evt.StringField(FieldActorID))
	assert.Equal(t, "success", evt.StringField(FieldOutcome))
	// PII fields should be present in the recorder (they are only
	// stripped by the Loki output's exclude_labels, not by the
	// recorder which captures all fields).
	assert.Equal(t, "test@example.com", evt.StringField(FieldEmail))
	assert.Equal(t, "+1555000", evt.StringField(FieldPhone))
}

// --- Login/Logout tests (direct audit events, no middleware) ---

func TestLogin_Success_EmitsAuthSuccess(t *testing.T) {
	env := newTestServer(t, nil)

	status := doRequest(t, env.srv.URL, "POST", "/login", "",
		map[string]string{"username": "alice", "password": "password"})
	assert.Equal(t, http.StatusOK, status)

	env.Flush(t)

	events := env.rec.FindByType(EventAuthSuccess)
	require.Len(t, events, 1, "expected one auth_success event")
	assert.Equal(t, "alice", events[0].StringField(FieldActorID))
	assert.Equal(t, "success", events[0].StringField(FieldOutcome))
}

func TestLogin_BadPassword_EmitsAuthFailure(t *testing.T) {
	env := newTestServer(t, nil)

	status := doRequest(t, env.srv.URL, "POST", "/login", "",
		map[string]string{"username": "alice", "password": "wrong"})
	assert.Equal(t, http.StatusUnauthorized, status)

	env.Flush(t)

	events := env.rec.FindByType(EventAuthFailure)
	require.Len(t, events, 1, "expected one auth_failure event")
	assert.Equal(t, "alice", events[0].StringField(FieldActorID))
	assert.Equal(t, "invalid credentials", events[0].StringField(FieldReason))
}
