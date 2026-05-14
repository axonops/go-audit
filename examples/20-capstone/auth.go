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
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/axonops/audit"
)

var (
	errTokenExpired    = errors.New("token expired")
	errMalformedTok    = errors.New("malformed token")
	errInvalidSig      = errors.New("invalid signature")
	errSessionNotFound = errors.New("session not found")
)

// sessionStore holds active session tokens. Tokens are removed on
// logout or when individually validated after expiry. Production apps
// should add a periodic background reaper to evict expired tokens
// that are never presented again (memory leak under sustained load).
// In production, use a database or Redis.
type sessionStore struct { //nolint:govet // fieldalignment: readability preferred
	mu       sync.Mutex
	tokens   map[string]sessionInfo // token → info
	secret   []byte                 // HMAC-SHA256 signing key
	lifetime time.Duration
}

type sessionInfo struct { //nolint:govet // fieldalignment: readability preferred
	username string
	expiry   time.Time
}

func newSessionStore(lifetime time.Duration) *sessionStore {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	return &sessionStore{
		tokens:   make(map[string]sessionInfo),
		secret:   secret,
		lifetime: lifetime,
	}
}

// createToken generates an HMAC-signed session token for the given user.
// The username must not contain "|" (used as a delimiter in the token
// format). Production apps should use a non-ambiguous encoding (JWT).
func (s *sessionStore) createToken(username string) string {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		panic("crypto/rand: " + err.Error())
	}

	expiry := time.Now().Add(s.lifetime)
	payload := fmt.Sprintf("%s|%d|%s", username, expiry.Unix(), hex.EncodeToString(nonce))

	mac := hmac.New(sha256.New, s.secret)
	_, _ = mac.Write([]byte(payload)) // hash.Hash.Write never errors
	sig := hex.EncodeToString(mac.Sum(nil))
	token := payload + "|" + sig

	s.mu.Lock()
	s.tokens[token] = sessionInfo{username: username, expiry: expiry}
	s.mu.Unlock()

	return token
}

// validate checks a session token. Returns the username if valid.
func (s *sessionStore) validate(token string) (string, error) {
	// Verify HMAC signature.
	lastPipe := strings.LastIndex(token, "|")
	if lastPipe < 0 {
		return "", errMalformedTok
	}
	payload := token[:lastPipe]
	sig := token[lastPipe+1:]

	mac := hmac.New(sha256.New, s.secret)
	_, _ = mac.Write([]byte(payload)) // hash.Hash.Write never errors
	expected := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(sig), []byte(expected)) {
		return "", errInvalidSig
	}

	// Check store — token must be active (not logged out).
	s.mu.Lock()
	info, ok := s.tokens[token]
	s.mu.Unlock()
	if !ok {
		return "", errSessionNotFound
	}

	// Check expiry.
	if time.Now().After(info.expiry) {
		s.mu.Lock()
		delete(s.tokens, token)
		s.mu.Unlock()
		return info.username, errTokenExpired
	}

	return info.username, nil
}

// revoke invalidates a session token (logout).
func (s *sessionStore) revoke(token string) {
	s.mu.Lock()
	delete(s.tokens, token)
	s.mu.Unlock()
}

// --- Credential store (demo) ---

// credentials maps username → password. Read-only after package init.
// Production: use bcrypt-hashed passwords in a database.
var credentials = map[string]string{
	"alice": "password",
	"bob":   "password",
	"admin": "admin123",
}

// --- Auth handlers (emit events directly, outside middleware) ---

// authHandlers handles login/logout. These endpoints are NOT wrapped
// by the audit middleware — they emit audit events directly because
// they ARE the security action, not a business action that happens
// to need auth.
type authHandlers struct {
	auditor  *audit.Auditor
	sessions *sessionStore
	rl       *rateLimiter
	log      *slog.Logger
}

func (a *authHandlers) login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	// Production: use http.MaxBytesReader to bound request size.
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.log.Warn("login: invalid request body", "ip", clientIP(r), "error", err)
		a.rl.record(clientIP(r))
		if auditErr := a.auditor.AuditEvent(NewAuthFailureEvent("anonymous", "failure").
			SetReason("invalid request body").
			SetSourceIP(clientIP(r))); auditErr != nil {
			a.log.Error("audit event failed", "event_type", EventAuthFailure, "error", auditErr)
		}
		writeLoginError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	// Constant-time comparison prevents timing attacks that leak
	// password content. Production: use bcrypt, never plaintext.
	expected, exists := credentials[req.Username]
	got := sha256.Sum256([]byte(req.Password))
	want := sha256.Sum256([]byte(expected))
	if !exists || subtle.ConstantTimeCompare(got[:], want[:]) != 1 {
		a.log.Warn("login failed", "username", req.Username, "ip", clientIP(r))
		a.rl.record(clientIP(r))
		if auditErr := a.auditor.AuditEvent(NewAuthFailureEvent(req.Username, "failure").
			SetReason("invalid credentials").
			SetSourceIP(clientIP(r))); auditErr != nil {
			a.log.Error("audit event failed", "event_type", EventAuthFailure, "error", auditErr)
		}
		writeLoginError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	a.log.Info("login successful", "username", req.Username, "ip", clientIP(r))
	token := a.sessions.createToken(req.Username)
	if auditErr := a.auditor.AuditEvent(NewAuthSuccessEvent(req.Username, "success").
		SetSourceIP(clientIP(r))); auditErr != nil {
		a.log.Error("audit event failed", "event_type", EventAuthSuccess, "error", auditErr)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"token": token})
}

func (a *authHandlers) logout(w http.ResponseWriter, r *http.Request) {
	token := extractBearerToken(r)
	if token == "" {
		writeLoginError(w, http.StatusBadRequest, "missing bearer token")
		return
	}

	username, err := a.sessions.validate(token)
	if err != nil {
		var ev audit.Event
		if errors.Is(err, errTokenExpired) {
			ev = NewTokenExpiredEvent(username, "failure").
				SetReason("invalid session").
				SetSourceIP(clientIP(r))
		} else {
			ev = NewAuthFailureEvent(username, "failure").
				SetReason("invalid session").
				SetSourceIP(clientIP(r))
		}
		if auditErr := a.auditor.AuditEvent(ev); auditErr != nil {
			a.log.Error("audit event failed", "event_type", ev.EventType(), "error", auditErr)
		}
		writeLoginError(w, http.StatusUnauthorized, "invalid session")
		return
	}

	a.sessions.revoke(token)
	if auditErr := a.auditor.AuditEvent(NewAuthLogoutEvent(username, "success").
		SetSourceIP(clientIP(r))); auditErr != nil {
		a.log.Error("audit event failed", "event_type", EventAuthLogout, "error", auditErr)
	}

	w.WriteHeader(http.StatusNoContent)
}

// --- Auth middleware for CRUD routes ---

// authMiddleware validates the X-API-Key header or Bearer token and
// populates audit hints with the authenticated identity.
func authMiddleware(sessions *sessionStore) func(http.Handler) http.Handler {
	// API key → user ID mapping. In production, use a database.
	apiKeys := map[string]string{
		"key-alice": "alice",
		"key-bob":   "bob",
		"key-admin": "admin",
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip auth for health and metrics endpoints.
			if r.URL.Path == "/healthz" || r.URL.Path == "/metrics" {
				next.ServeHTTP(w, r)
				return
			}

			hints := audit.HintsFromContext(r.Context())

			// Try Bearer token first, then API key.
			if token := extractBearerToken(r); token != "" {
				if authenticateBearer(sessions, token, hints, w) {
					next.ServeHTTP(w, r)
				}
				return
			}

			// Fall back to API key.
			apiKey := r.Header.Get("X-API-Key")
			if userID, ok := apiKeys[apiKey]; ok {
				if hints != nil {
					hints.ActorID = userID
					hints.AuthMethod = "api_key"
					hints.Outcome = "success"
				}
				next.ServeHTTP(w, r)
				return
			}

			// No valid auth.
			if hints != nil {
				hints.EventType = EventAuthFailure
				hints.Outcome = "failure"
				actorID := "anonymous"
				if apiKey != "" {
					actorID = apiKey[:min(4, len(apiKey))] + "..."
				}
				hints.ActorID = actorID
				hints.Reason = "invalid credentials"
			}
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		})
	}
}

// authenticateBearer validates a Bearer token and populates hints.
// Returns true if authentication succeeded (caller should proceed).
func authenticateBearer(sessions *sessionStore, token string, hints *audit.Hints, w http.ResponseWriter) bool {
	username, err := sessions.validate(token)
	if err != nil {
		eventType := EventAuthFailure
		reason := "invalid session token"
		if errors.Is(err, errTokenExpired) {
			eventType = EventTokenExpired
			reason = "session token expired"
		}
		if hints != nil {
			hints.EventType = eventType
			hints.Outcome = "failure"
			hints.ActorID = username
			hints.Reason = reason
		}
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return false
	}
	if hints != nil {
		hints.ActorID = username
		hints.AuthMethod = "bearer"
		hints.Outcome = "success"
	}
	return true
}

// --- Helpers ---

func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return ""
}

func clientIP(r *http.Request) string {
	// WARNING: X-Forwarded-For is trivially spoofable by direct clients.
	// Only trust this header when behind a reverse proxy that overwrites it.
	// For this demo we use RemoteAddr as the safe default. Production apps
	// behind a proxy should use the rightmost-untrusted IP.
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func writeLoginError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
