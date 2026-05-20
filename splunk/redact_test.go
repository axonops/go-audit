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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// White-box tests for the defence-in-depth helpers redact and
// scrubForLog. These methods are unexported and not reachable from
// the black-box `splunk_test` package, so the test file lives here.

const redactTestToken = "very-secret-token-1234"

// minimalOutputForRedact constructs the smallest Output instance
// that satisfies redact / scrubForLog's needs (a non-nil cfg with
// the token set). Avoids the construction ceremony of New() (which
// builds an HTTP client, transport, etc.) since these helpers only
// read o.cfg.Token.
func minimalOutputForRedact(token string) *Output {
	return &Output{cfg: &Config{Token: token}}
}

func TestRedact_NilError_ReturnsEmptyString(t *testing.T) {
	o := minimalOutputForRedact(redactTestToken)
	assert.Equal(t, "", o.redact(nil))
}

func TestRedact_PlainError_StripsToken(t *testing.T) {
	o := minimalOutputForRedact(redactTestToken)
	err := fmt.Errorf("auth header bearer %s failed", redactTestToken)
	got := o.redact(err)
	assert.NotContains(t, got, redactTestToken,
		"redact must strip the token literal from any error string")
	assert.Contains(t, got, "[REDACTED]")
}

func TestRedact_HECError_UsesCanonicalForm(t *testing.T) {
	o := minimalOutputForRedact(redactTestToken)
	// hecError.Error() composes a canonical "HEC <status> (code=<n> ..."
	// string without wrapped chains. The redact method extracts it
	// via errors.As so any sensitive wrapped error is suppressed.
	wrapped := fmt.Errorf("outer: %w", &hecError{
		HTTPStatus: 403,
		Code:       4,
		Action:     actionStop,
		Text:       "Invalid token",
	})
	got := o.redact(wrapped)
	assert.Contains(t, got, "HEC 403",
		"hecError canonical form should be surfaced")
	assert.NotContains(t, got, "outer:",
		"hecError path must drop wrapped-chain text")
}

func TestRedact_HECErrorContainingToken_StripsToken(t *testing.T) {
	o := minimalOutputForRedact(redactTestToken)
	// hecError.Text could in theory contain anything echoed by the
	// HEC server — defence-in-depth strips the token here too.
	herr := &hecError{
		HTTPStatus: 403,
		Code:       4,
		Action:     actionStop,
		Text:       "token " + redactTestToken + " rejected",
	}
	got := o.redact(herr)
	assert.NotContains(t, got, redactTestToken)
}

func TestRedact_EmptyTokenConfig_PassesThrough(t *testing.T) {
	o := minimalOutputForRedact("")
	got := o.redact(errors.New("plain error text"))
	assert.Equal(t, "plain error text", got)
}

func TestScrubForLog_StripsCarriageReturnAndLineFeed(t *testing.T) {
	o := minimalOutputForRedact(redactTestToken)
	// A forged panic value: newlines + CR would otherwise let slog's
	// text handler emit a second "log record" — the log-injection
	// primitive the security review flagged as HIGH-1.
	in := "panic: legit message\nFAKE: forged record\r"
	got := o.scrubForLog(in)
	assert.NotContains(t, got, "\n", "newlines must be stripped")
	assert.NotContains(t, got, "\r", "carriage returns must be stripped")
	assert.Contains(t, got, "FAKE: forged record",
		"the original text is preserved (only the control chars change)")
}

func TestScrubForLog_StripsTokenLiteral(t *testing.T) {
	o := minimalOutputForRedact(redactTestToken)
	in := "panic: handler dumped " + redactTestToken + " on stack"
	got := o.scrubForLog(in)
	assert.NotContains(t, got, redactTestToken)
	assert.Contains(t, got, "[REDACTED]")
}

func TestScrubForLog_CapsLength(t *testing.T) {
	o := minimalOutputForRedact(redactTestToken)
	in := strings.Repeat("a", 2000)
	got := o.scrubForLog(in)
	assert.Equal(t, 512, len(got),
		"scrubForLog must cap length at 512 bytes to bound log-line growth")
}

func TestScrubForLog_EmptyInput(t *testing.T) {
	o := minimalOutputForRedact(redactTestToken)
	assert.Equal(t, "", o.scrubForLog(""))
}

func TestScrubForLog_NoTokenConfigured(t *testing.T) {
	o := minimalOutputForRedact("")
	got := o.scrubForLog("plain text without\nnewlines")
	assert.Equal(t, "plain text without newlines", got,
		"empty token must skip the replace step but still strip CR/LF")
}
