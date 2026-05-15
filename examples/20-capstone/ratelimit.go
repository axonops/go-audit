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
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/axonops/audit"
)

// rateLimiter tracks failed auth attempts per source IP using a
// sliding window. Cleanup happens inline on each allow() call.
// Production apps should add periodic background cleanup for
// memory bounds under high IP cardinality.
type rateLimiter struct { //nolint:govet // fieldalignment: readability preferred
	mu        sync.Mutex
	attempts  map[string][]time.Time
	window    time.Duration
	threshold int
}

func newRateLimiter(window time.Duration, threshold int) *rateLimiter {
	return &rateLimiter{
		attempts:  make(map[string][]time.Time),
		window:    window,
		threshold: threshold,
	}
}

// record adds a failed attempt for the given IP.
func (rl *rateLimiter) record(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.attempts[ip] = append(rl.attempts[ip], time.Now())
}

// allow checks whether the IP is within the rate limit. It prunes
// expired entries inline to bound memory.
func (rl *rateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	cutoff := time.Now().Add(-rl.window)
	attempts := rl.attempts[ip]

	// Prune expired entries in-place.
	n := 0
	for _, t := range attempts {
		if t.After(cutoff) {
			attempts[n] = t
			n++
		}
	}
	rl.attempts[ip] = attempts[:n]

	return n < rl.threshold
}

// rateLimitMiddleware wraps a handler (typically /login) and blocks
// requests from IPs that have exceeded the auth failure threshold.
// When blocked, it emits a rate_limit_exceeded audit event directly.
func rateLimitMiddleware(auditor *audit.Auditor, rl *rateLimiter, appLog ...*slog.Logger) func(http.Handler) http.Handler {
	var lg *slog.Logger
	if len(appLog) > 0 {
		lg = appLog[0]
	} else {
		lg = slog.Default()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := clientIP(r)
			if !rl.allow(ip) {
				// Emit rate limit event using generated builder.
				ev := NewRateLimitExceededEvent("failure").
					SetReason("too many failed authentication attempts")
				if ip != "" {
					ev.SetSourceIP(ip)
				}
				if err := auditor.AuditEvent(ev); err != nil {
					lg.Error("audit event failed", "event_type", EventRateLimitExceeded, "error", err)
				}
				lg.Warn("rate limit exceeded", "ip", ip)

				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Retry-After", "60")
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = fmt.Fprintf(w, `{"error":"too many requests, try again later"}`)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
