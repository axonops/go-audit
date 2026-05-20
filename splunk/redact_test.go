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
	"crypto/x509"
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

// MarshalYAML round-trip tests for the typed string enums. The
// UnmarshalYAML side is covered by the register_test factory tests;
// MarshalYAML needs a direct call because the buildOutput path only
// decodes YAML, never encodes it.

func TestEndpoint_MarshalYAML(t *testing.T) {
	tests := []struct {
		want string
		in   Endpoint
	}{
		{"event", EndpointEvent},
		{"raw", EndpointRaw},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got, err := tt.in.MarshalYAML()
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// Config formatter tests — verify the token is REDACTED in String /
// GoString / Format and the URL is sanitised to scheme+host.

func TestConfig_String_RedactsToken(t *testing.T) {
	gz := true
	cfg := Config{
		URL:           "https://splunk.example.com:8088/path?secret=abc",
		Token:         "very-secret-tok",
		Endpoint:      EndpointEvent,
		Sourcetype:    "audit:event",
		Index:         "main",
		Gzip:          &gz,
		BatchSize:     50,
		MaxBatchBytes: 65536,
		AckMode:       AckModeOff,
	}
	got := cfg.String()
	assert.Contains(t, got, "token=REDACTED")
	assert.NotContains(t, got, "very-secret-tok")
	assert.Contains(t, got, "https://splunk.example.com:8088",
		"URL must be sanitised to scheme+host (no path / no query)")
	assert.NotContains(t, got, "/path",
		"URL path must be stripped")
	assert.NotContains(t, got, "secret=abc",
		"URL query must be stripped")
}

func TestConfig_String_GzipNilShowsDefault(t *testing.T) {
	cfg := Config{
		URL:     "https://splunk.example.com:8088",
		Token:   "tkn",
		Gzip:    nil,
		AckMode: AckModeOff,
	}
	assert.Contains(t, cfg.String(), "gzip=<default>")
}

func TestConfig_String_GzipFalseShowsFalse(t *testing.T) {
	gz := false
	cfg := Config{
		URL:     "https://splunk.example.com:8088",
		Token:   "tkn",
		Gzip:    &gz,
		AckMode: AckModeOff,
	}
	assert.Contains(t, cfg.String(), "gzip=false")
}

func TestConfig_GoString_DelegatesToString(t *testing.T) {
	cfg := Config{
		URL:     "https://splunk.example.com:8088",
		Token:   "tkn",
		AckMode: AckModeOff,
	}
	assert.Equal(t, cfg.String(), cfg.GoString())
}

func TestConfig_Format_VerboseFormatStillRedacts(t *testing.T) {
	cfg := Config{
		URL:     "https://splunk.example.com:8088",
		Token:   "leak-me-if-you-can",
		AckMode: AckModeOff,
	}
	// %+v would normally reflect every field — Format() must override.
	got := fmt.Sprintf("%+v", cfg)
	assert.NotContains(t, got, "leak-me-if-you-can",
		"%+v must redact the token")
	assert.Contains(t, got, "REDACTED")
}

func TestSanitizeURLForLog(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"https://splunk.example.com:8088", "https://splunk.example.com:8088"},
		{"https://splunk.example.com:8088/services/collector/event", "https://splunk.example.com:8088"},
		{"https://user:pass@splunk.example.com:8088/x?q=1", "https://splunk.example.com:8088"},
		{"", ""},
		{"://broken-no-scheme", "<invalid-url>"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			assert.Equal(t, tt.want, sanitizeURLForLog(tt.in))
		})
	}
}

// Endpoint and AckMode UnmarshalYAML error path tests — already
// indirectly exercised via factory tests, but a direct test pins the
// error wrapping (ErrConfigInvalid) and the exact message format.

type yamlEndpointStub struct{ value string }

func (s yamlEndpointStub) unmarshal(v any) error {
	p, ok := v.(*string)
	if !ok {
		return fmt.Errorf("yamlEndpointStub: expected *string target, got %T", v)
	}
	*p = s.value
	return nil
}

// isTLSError tests — covers each error-type branch in the type-switch
// + the string-fallback at the bottom. Used by doPost to classify
// non-retryable TLS errors per AC 54.

func TestIsTLSError_NilReturnsFalse(t *testing.T) {
	assert.False(t, isTLSError(nil))
}

func TestIsTLSError_PlainErrorReturnsFalse(t *testing.T) {
	assert.False(t, isTLSError(errors.New("just an error")))
}

func TestIsTLSError_UnknownAuthorityError(t *testing.T) {
	err := fmt.Errorf("wrapped: %w", &x509.UnknownAuthorityError{})
	assert.True(t, isTLSError(err))
}

func TestIsTLSError_HostnameError(t *testing.T) {
	err := fmt.Errorf("wrapped: %w", &x509.HostnameError{Host: "evil.example.com"})
	assert.True(t, isTLSError(err))
}

func TestIsTLSError_StringFallback_TLSPrefix(t *testing.T) {
	// errors that don't match a concrete type but contain "tls: " or
	// "x509: " — covers the string-match fallback at the bottom of
	// the function.
	assert.True(t, isTLSError(errors.New("net/http: TLS handshake error: tls: bad certificate")))
}

func TestIsTLSError_StringFallback_X509Prefix(t *testing.T) {
	assert.True(t, isTLSError(errors.New("get https://x: x509: certificate has expired")))
}

func TestEndpoint_UnmarshalYAML_UnknownReturnsErrConfigInvalid(t *testing.T) {
	var e Endpoint
	err := e.UnmarshalYAML(yamlEndpointStub{value: "bogus"}.unmarshal)
	assert.ErrorIs(t, err, ErrConfigInvalid)
}

func TestAckMode_UnmarshalYAML_UnknownReturnsErrConfigInvalid(t *testing.T) {
	var a AckMode
	err := a.UnmarshalYAML(yamlEndpointStub{value: "bogus"}.unmarshal)
	assert.ErrorIs(t, err, ErrConfigInvalid)
}

func TestAckMode_MarshalYAML(t *testing.T) {
	tests := []struct {
		want string
		in   AckMode
	}{
		{"off", AckModeOff},
		{"best_effort", AckModeBestEffort},
		{"required", AckModeRequired},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got, err := tt.in.MarshalYAML()
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
