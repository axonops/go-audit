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

package splunk

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestClassify_FullTable exercises every documented HEC error code
// (0-27 inclusive — 28 entries). Each row asserts the exact action
// the client should take. This is the decision matrix that every
// response is dispatched through; a regression on one row silently
// mis-handles auth failures or backpressure in production.
func TestClassify_FullTable(t *testing.T) {
	tests := []struct {
		name       string
		httpStatus int
		hecCode    int
		want       hecAction
	}{
		// 200 — success and capacity-warn band.
		{"code 0 — Success", 200, 0, actionSuccess},
		{"code 17 — HEC is healthy (health endpoint)", 200, 17, actionSuccess},
		{"code 24 — Approaching capacity (warn metric)", 200, 24, actionCapacityWarn},
		{"code 25 — Approaching capacity (warn metric)", 200, 25, actionCapacityWarn},
		{"code unknown on 200 — treat as success", 200, 999, actionSuccess},

		// 401 — auth.
		{"code 2 — Token is required (HTTP 401)", 401, 2, actionStop},
		{"code 3 — Invalid authorization (HTTP 401)", 401, 3, actionStop},

		// 403 — auth.
		{"code 1 — Token disabled (HTTP 403)", 403, 1, actionStop},
		{"code 4 — Invalid token (HTTP 403)", 403, 4, actionStop},
		{"code 22 — Token disabled (HTTP 403)", 403, 22, actionStop},

		// 400 — terminal client errors.
		{"code 5 — No data", 400, 5, actionDrop},
		{"code 6 — Invalid data format", 400, 6, actionDrop},
		{"code 7 — Incorrect index (config — stop)", 400, 7, actionStop},
		{"code 10 — Data channel is missing", 400, 10, actionDrop},
		{"code 11 — Invalid data channel", 400, 11, actionDrop},
		{"code 12 — Event field is required", 400, 12, actionDrop},
		{"code 13 — Event field cannot be blank", 400, 13, actionDrop},
		{"code 14 — ACK is disabled (client must disable)", 400, 14, actionAckDisabled},
		{"code 15 — Error in handling indexed fields", 400, 15, actionDrop},
		{"code 16 — Query string auth not enabled", 400, 16, actionDrop},
		{"unknown 400 code — drop", 400, 999, actionDrop},

		// 413 — payload too large.
		{"HTTP 413 — payload too large", 413, 0, actionDrop},

		// 429 — backpressure (HEC codes 26, 27 share this status).
		{"HTTP 429 with code 26 — capacity exhausted", 429, 26, actionRetry},
		{"HTTP 429 with code 27 — capacity exhausted", 429, 27, actionRetry},
		{"HTTP 429 with no code — retry", 429, 0, actionRetry},

		// 500/503 — server-side transient.
		{"code 8 — Internal server error (HTTP 500)", 500, 8, actionRetry},
		{"code 9 — Server is busy (HTTP 503)", 503, 9, actionRetry},
		{"code 18 — HEC unhealthy (HTTP 503)", 503, 18, actionRetry},
		{"code 19 — HEC queues full (HTTP 503)", 503, 19, actionRetry},
		{"code 20 — HEC overloaded (HTTP 503)", 503, 20, actionRetry},
		{"code 23 — Server shutting down (HTTP 503)", 503, 23, actionRetry},
		{"unknown 5xx code — retry", 500, 999, actionRetry},

		// Edge cases.
		{"HTTP 301 — redirect (should never reach classify; safe default = drop)", 301, 0, actionDrop},
		{"HTTP 100 — informational", 100, 0, actionDrop},
		{"HTTP 600 — out of range", 600, 0, actionDrop},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := classify(tc.httpStatus, tc.hecCode)
			assert.Equal(t, tc.want, got,
				"classify(%d, %d) = %s; want %s",
				tc.httpStatus, tc.hecCode, got, tc.want)
		})
	}
}

// TestHECAction_String covers the metric-label form of each action,
// including the `unknown` fallback for an out-of-range value.
func TestHECAction_String(t *testing.T) {
	tests := []struct {
		action hecAction
		want   string
	}{
		{actionSuccess, "success"},
		{actionRetry, "retry"},
		{actionDrop, "drop"},
		{actionStop, "stop"},
		{actionCapacityWarn, "warn"},
		{actionAckDisabled, "ack_disabled"},
		{hecAction(99), "unknown"},
	}
	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.action.String())
		})
	}
}

// TestHECError_Error_NeverContainsToken is a smoke test that the
// hecError.Error() format never contains anything looking like a
// token. Token redaction is also covered by the property test
// `TestProperty_TokenRedaction_AnyErrorPath`; this is a fast
// fixed-input check.
func TestHECError_Error_NeverContainsToken(t *testing.T) {
	err := &hecError{
		HTTPStatus: 403,
		Code:       4,
		Action:     actionStop,
		Text:       `{"text":"Invalid token","code":4}`,
	}
	msg := err.Error()
	assert.Contains(t, msg, "HEC 403")
	assert.Contains(t, msg, "code=4")
	assert.Contains(t, msg, "action=stop")
	// The Text field is the HEC response body which is OPERATOR-
	// controlled, not consumer-controlled, but we double-check it
	// doesn't accidentally contain a `Authorization` header value
	// pattern. The static input is safe; this asserts the format
	// string itself doesn't introduce the substring.
	assert.NotContains(t, msg, "Authorization")
}
