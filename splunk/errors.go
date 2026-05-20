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
	"errors"
	"fmt"
)

// hecAction classifies how the client should react to a HEC response.
// It is the single source of truth for the 28-entry HEC code table
// (codes 0-27 inclusive). See [classify] for the mapping.
type hecAction int

const (
	// actionSuccess — the request was accepted (HTTP 2xx, HEC code 0).
	// No further action.
	actionSuccess hecAction = iota

	// actionRetry — transient failure (HTTP 5xx or HEC code 8/9/18/19/
	// 20/23 or HTTP 429 or HEC code 26/27). Apply exponential backoff
	// and resend the same batch.
	actionRetry

	// actionDrop — the batch is malformed or violates the index's
	// schema (HTTP 4xx with HEC code 5/6/10/11/12/13/15/16). The batch
	// will never succeed; drop and surface a metric.
	actionDrop

	// actionStop — credentials are wrong, the token is disabled, or
	// the configured index does not exist (HTTP 401/403 with HEC code
	// 1/2/3/4/7/22). The Output enters a permanent stopped state and
	// new writes return [audit.ErrOutputClosed]. Operator action is
	// required.
	actionStop

	// actionCapacityWarn — the request succeeded (HTTP 200) but HEC
	// signalled that the indexer queue is approaching capacity (HEC
	// code 24/25). Surface as a metric; do NOT treat as an error.
	actionCapacityWarn

	// actionAckDisabled — the client sent a channel header for indexer
	// acknowledgement but HEC rejected it (HEC code 14). Disable ACK
	// in the client's config and resend.
	actionAckDisabled
)

// String returns the metric-label form of the action.
func (a hecAction) String() string {
	switch a {
	case actionSuccess:
		return "success"
	case actionRetry:
		return "retry"
	case actionDrop:
		return "drop"
	case actionStop:
		return "stop"
	case actionCapacityWarn:
		return "warn"
	case actionAckDisabled:
		return "ack_disabled"
	default:
		return "unknown"
	}
}

// hecResponse is the JSON shape HEC returns from /event, /raw, and
// /ack endpoints. Fields default to zero values when HEC returns a
// truncated or non-conforming body.
type hecResponse struct {
	Text  string `json:"text,omitempty"`
	Code  int    `json:"code"`
	AckID *int64 `json:"ackId,omitempty"`
}

// classify maps an HTTP status + HEC code to the client action. The
// table is derived from Splunk's documented HEC error codes
// (docs.splunk.com Troubleshoot HEC). Codes 24/25 are HTTP 200 with
// a capacity warning; codes 26/27 are HTTP 429 backpressure. Unknown
// codes default to [actionDrop] (non-retryable; surface as metric) —
// retrying an unknown error risks runaway loops on a misbehaving HEC.
//
// This is the single source of truth for retry/drop/stop/warn
// semantics. The full 28-entry table (codes 0-27 inclusive) is
// exercised by TestOutput_HECErrorCodes_FullTable.
func classify(httpStatus int, hecCode int) hecAction { //nolint:cyclop,gocyclo,funlen // dispatch table; explicit cases are clearer than a map
	// HTTP 200 — success path, but HEC may signal capacity warning.
	if httpStatus >= 200 && httpStatus < 300 {
		switch hecCode {
		case 0, 17:
			// 0 = Success; 17 = HEC is healthy (the /health endpoint
			// returns code 17 on HTTP 200 — clients usually do not
			// classify that response, but we map it for completeness).
			return actionSuccess
		case 24, 25:
			// Capacity warning — request indexed, but HEC's internal
			// queues are filling. Surface as metric; do not error.
			return actionCapacityWarn
		default:
			// HTTP 2xx with unrecognised HEC code — treat as success
			// (the bytes were accepted) but a future-proofing
			// observation point.
			return actionSuccess
		}
	}

	// HTTP 4xx — terminal except for 429 + ack-disabled feedback.
	if httpStatus == 429 {
		// HEC code 26 = "Capacity exhausted, retry later" (HTTP 429).
		// Also covers the older Splunk Cloud ingress's plain HTTP 429
		// without a HEC code envelope.
		return actionRetry
	}
	if httpStatus == 401 {
		// Token authentication failure.
		switch hecCode {
		case 2, 3:
			return actionStop
		}
		return actionStop
	}
	if httpStatus == 403 {
		// Token authorisation failure.
		switch hecCode {
		case 1, 4, 22:
			return actionStop
		}
		return actionStop
	}
	if httpStatus == 413 {
		// Payload too large — non-retryable; the client must reduce
		// batch size before resending. Treated as a drop because the
		// same batch cannot succeed; the next batch may.
		return actionDrop
	}
	if httpStatus >= 400 && httpStatus < 500 {
		switch hecCode {
		case 7:
			// Incorrect index — stop until operator fixes the token.
			return actionStop
		case 14:
			// ACK is disabled but the client sent a channel header.
			return actionAckDisabled
		case 5, 6, 10, 11, 12, 13, 15, 16:
			return actionDrop
		default:
			// Unknown 4xx code — treat as drop, not retry.
			return actionDrop
		}
	}

	// HTTP 5xx — transient. The whole 5xx range is retryable; we don't
	// need to switch on the HEC code, but the code is still surfaced
	// in metric labels for observability.
	if httpStatus >= 500 && httpStatus < 600 {
		switch hecCode {
		case 8, 9, 18, 19, 20, 23:
			// Documented HEC retryable codes.
			return actionRetry
		default:
			return actionRetry
		}
	}

	// Any other status (e.g. 1xx, 3xx — redirects are blocked by
	// CheckRedirect before they reach here) is treated as drop.
	return actionDrop
}

// hecError wraps a HEC response in a Go error so the retry path can
// switch on the action while preserving the response for logging and
// metrics.
type hecError struct {
	HTTPStatus int
	Code       int
	Text       string
	Action     hecAction
}

// Error returns a human-readable form of the HEC error. **Never
// includes the token, the URL, or any header values.**
func (e *hecError) Error() string {
	return fmt.Sprintf("audit/splunk: HEC %d (code=%d action=%s): %s",
		e.HTTPStatus, e.Code, e.Action, e.Text)
}

// Sentinel errors returned by [New] and by the Output's runtime path.
// All sentinels are wrapped with `%w` so callers can discriminate via
// [errors.Is].
var (
	// ErrConfigInvalid wraps every validation error from [Validate]
	// and the constructor pre-checks. Callers use
	// `errors.Is(err, splunk.ErrConfigInvalid)`.
	ErrConfigInvalid = errors.New("audit/splunk: configuration invalid")

	// ErrTokenRejected is returned from a runtime send when HEC
	// classifies the token as disabled or invalid (HEC codes 1/2/3/4/
	// 22) — the Output transitions to its stopped state.
	ErrTokenRejected = errors.New("audit/splunk: token rejected by HEC")

	// ErrIndexRejected is returned from a runtime send when HEC
	// rejects the configured index (HEC code 7) — Output stops.
	ErrIndexRejected = errors.New("audit/splunk: index rejected by HEC")

	// ErrHealthCheckFailed is returned from [New] when the startup
	// health probe fails (and [Config.DisableStartupVerification] is
	// false).
	ErrHealthCheckFailed = errors.New("audit/splunk: HEC health check failed")

	// ErrPR1NotImplemented is returned when PR-1 sees a config
	// requesting a feature deferred to PR 2 (`splunkcloud://` URL
	// scheme; `AckMode != AckModeOff`). Carries a remediation hint
	// in the wrapped message.
	ErrPR1NotImplemented = errors.New("audit/splunk: feature not implemented in PR 1 (ships in PR 2)")
)
