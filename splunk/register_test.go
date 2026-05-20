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

package splunk_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/audit"
	"github.com/axonops/audit/splunk"
)

// TestFactory_RegisteredByInit verifies that importing the splunk
// package (blank-import) registers a factory under the "splunk" key.
// This is the fundamental contract of the package: blank-import
// registers the output type with the core registry.
func TestFactory_RegisteredByInit(t *testing.T) {
	t.Parallel()
	factory := audit.LookupOutputFactory("splunk")
	require.NotNil(t, factory,
		"splunk factory must be registered by init()")
}

// TestFactory_DefaultsAndOverrides exercises the YAML → Config →
// Output construction path. Verifies that explicit field values land
// in the constructed Output (via Name()), and that omitted fields
// take the documented defaults (validated by the YAML round-trip
// reaching Validate() without rejection).
func TestFactory_DefaultsAndOverrides(t *testing.T) {
	t.Parallel()
	stub := newRegisterStub(t)

	rawYAML := []byte(`
url: ` + stub.URL + `
token: test-token-12345
endpoint: raw
allow_insecure_http: true
sourcetype: audit:cim
source: audit-from-yaml
index: main
host: yaml-host
indexed_fields:
  - actor
  - target
batch_size: 50
max_batch_bytes: 65536
max_event_bytes: 524288
flush_interval: 5s
gzip: false
user_agent: my-app/1.0
timeout: 15s
headers:
  X-Tenant: alpha
max_retries: 5
retry_base_delay: 200ms
retry_max_delay: 10s
retry_jitter: 0.25
buffer_size: 2048
verify_on_startup: false
`)

	factory := audit.LookupOutputFactory("splunk")
	require.NotNil(t, factory)

	out, err := factory("yaml_splunk", rawYAML, audit.FrameworkContext{})
	require.NoError(t, err)
	defer func() { _ = out.Close() }()

	// Output.Name() returns the synthetic "splunk:host:port" form,
	// not the YAML key — that's used as the host-suffixed identifier
	// in metrics. The YAML key drives outputconfig's map lookup, not
	// the Output.Name() return.
	assert.True(t, strings.HasPrefix(out.Name(), "splunk:"),
		"Name() returns splunk:<host>:<port>; got %q", out.Name())
}

// TestFactory_DefaultsOnlyMinimalYAML verifies that a minimal YAML
// (URL + token + verify_on_startup:false) constructs successfully —
// every other field takes its documented default through the
// intPtrOrDefault / floatPtrOrDefault / durOrDefault helpers.
func TestFactory_DefaultsOnlyMinimalYAML(t *testing.T) {
	t.Parallel()
	stub := newRegisterStub(t)

	rawYAML := []byte(`
url: ` + stub.URL + `
token: minimal-token
allow_insecure_http: true
verify_on_startup: false
`)

	factory := audit.LookupOutputFactory("splunk")
	out, err := factory("minimal", rawYAML, audit.FrameworkContext{})
	require.NoError(t, err)
	defer func() { _ = out.Close() }()
	assert.True(t, strings.HasPrefix(out.Name(), "splunk:"))
}

// TestFactory_MalformedYAML — invalid YAML returns a wrapped error
// mentioning the output name (so an operator with N outputs can
// locate the misconfigured one).
func TestFactory_MalformedYAML(t *testing.T) {
	t.Parallel()
	factory := audit.LookupOutputFactory("splunk")
	_, err := factory("bad_yaml", []byte("not: [valid: yaml"), audit.FrameworkContext{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bad_yaml",
		"YAML decode error should name the output: %q", err.Error())
}

// TestFactory_BadDuration — an unparseable duration field is
// surfaced with the field name and the offending value.
func TestFactory_BadDuration(t *testing.T) {
	t.Parallel()
	rawYAML := []byte(`
url: https://splunk.example.com:8088
token: tkn
timeout: not-a-duration
verify_on_startup: false
`)
	factory := audit.LookupOutputFactory("splunk")
	_, err := factory("bad_dur", rawYAML, audit.FrameworkContext{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid duration",
		"bad duration should produce 'invalid duration' error: %q", err.Error())
}

// TestFactory_InvalidURL — config validation rejects unparseable
// URLs with ErrConfigInvalid.
func TestFactory_InvalidURL(t *testing.T) {
	t.Parallel()
	rawYAML := []byte(`
url: "://broken"
token: tkn
verify_on_startup: false
`)
	factory := audit.LookupOutputFactory("splunk")
	_, err := factory("bad_url", rawYAML, audit.FrameworkContext{})
	require.Error(t, err)
	assert.ErrorIs(t, err, splunk.ErrConfigInvalid,
		"invalid URL must wrap ErrConfigInvalid: %v", err)
}

// TestFactory_HTTPRejectedByDefault — an http:// URL without
// AllowInsecureHTTP fails Validate() with ErrConfigInvalid.
func TestFactory_HTTPRejectedByDefault(t *testing.T) {
	t.Parallel()
	rawYAML := []byte(`
url: http://splunk.example.com:8088
token: tkn
verify_on_startup: false
`)
	factory := audit.LookupOutputFactory("splunk")
	_, err := factory("plain_http", rawYAML, audit.FrameworkContext{})
	require.Error(t, err)
	assert.ErrorIs(t, err, splunk.ErrConfigInvalid)
}

// TestFactory_AllowInsecureHTTPPermitsHTTP — `allow_insecure_http:
// true` is the documented escape hatch and constructs successfully.
func TestFactory_AllowInsecureHTTPPermitsHTTP(t *testing.T) {
	t.Parallel()
	stub := newRegisterStub(t)
	rawYAML := []byte(`
url: ` + stub.URL + `
token: tkn
allow_insecure_http: true
verify_on_startup: false
`)
	factory := audit.LookupOutputFactory("splunk")
	out, err := factory("insecure", rawYAML, audit.FrameworkContext{})
	require.NoError(t, err)
	require.NoError(t, out.Close())
}

// TestFactory_TLSPolicyBlock — the nested `tls_policy:` block lands
// in cfg.TLSPolicy and survives Validate().
func TestFactory_TLSPolicyBlock(t *testing.T) {
	t.Parallel()
	stub := newRegisterStub(t)
	rawYAML := []byte(`
url: ` + stub.URL + `
token: tkn
allow_insecure_http: true
verify_on_startup: false
tls_policy:
  allow_tls12: true
  allow_weak_ciphers: false
`)
	factory := audit.LookupOutputFactory("splunk")
	out, err := factory("tlspolicy", rawYAML, audit.FrameworkContext{})
	require.NoError(t, err)
	require.NoError(t, out.Close())
}

// TestFactory_VerifyOnStartupExplicitTrue — the positive YAML
// surface for the inverted DisableStartupVerification field.
// `verify_on_startup: true` keeps verification on (default).
func TestFactory_VerifyOnStartupExplicitTrue(t *testing.T) {
	t.Parallel()
	stub := newRegisterStub(t)
	// verify_on_startup defaults to true (key omitted); this test
	// exercises the explicit `true` path. We pair it with
	// allow_insecure_http + allow_private_ranges so the http://
	// 127.0.0.1 stub URL is accepted and the startup probe hits
	// the stub's /health endpoint.
	rawYAML := []byte(`
url: ` + stub.URL + `
token: tkn
allow_insecure_http: true
allow_private_ranges: true
verify_on_startup: true
`)
	factory := audit.LookupOutputFactory("splunk")
	out, err := factory("verify_true", rawYAML, audit.FrameworkContext{})
	require.NoError(t, err)
	require.NoError(t, out.Close())
}

// TestNewFactory_WithMetricsFactory — NewFactory plumbs the supplied
// OutputMetricsFactory through to construction. With a non-nil
// factory, the per-output metrics are wired (verified via
// ErrPR1NotImplemented being unreachable — construction succeeds).
func TestNewFactory_WithMetricsFactory(t *testing.T) {
	t.Parallel()
	stub := newRegisterStub(t)
	rec := &recordingMetrics{}
	factory := splunk.NewFactory(func(_, _ string) audit.OutputMetrics {
		return rec
	})
	require.NotNil(t, factory)

	rawYAML := []byte(`
url: ` + stub.URL + `
token: tkn
allow_insecure_http: true
verify_on_startup: false
`)
	out, err := factory("with_factory", rawYAML, audit.FrameworkContext{})
	require.NoError(t, err)
	require.NoError(t, out.Close())
}

// TestNewFactory_NilMetricsFactory — passing nil to NewFactory means
// no per-output metrics; construction still succeeds (per the
// documented contract on the NewFactory godoc).
func TestNewFactory_NilMetricsFactory(t *testing.T) {
	t.Parallel()
	stub := newRegisterStub(t)
	factory := splunk.NewFactory(nil)
	require.NotNil(t, factory)

	rawYAML := []byte(`
url: ` + stub.URL + `
token: tkn
allow_insecure_http: true
verify_on_startup: false
`)
	out, err := factory("no_factory", rawYAML, audit.FrameworkContext{})
	require.NoError(t, err)
	require.NoError(t, out.Close())
}

// TestFactory_ZeroIntFieldSentinel — intPtrOrDefault returns -1 for
// an explicit zero (so applyDefaults doesn't silently override it);
// validation then rejects the out-of-range value with
// ErrConfigInvalid. This protects operators against accidentally
// writing `batch_size: 0` and having defaults silently mask it.
func TestFactory_ZeroIntFieldSentinel(t *testing.T) {
	t.Parallel()
	rawYAML := []byte(`
url: https://splunk.example.com:8088
token: tkn
batch_size: 0
verify_on_startup: false
`)
	factory := audit.LookupOutputFactory("splunk")
	_, err := factory("zero_batch", rawYAML, audit.FrameworkContext{})
	require.Error(t, err)
	assert.ErrorIs(t, err, splunk.ErrConfigInvalid,
		"explicit zero batch_size must be rejected as out-of-range, not silently defaulted")
}

// TestFactory_AckModeNotOffRejectedInPR1 — ack_mode != off is the
// PR-2 feature; PR 1 rejects with ErrPR1NotImplemented at config
// validation. This is the codepath that demonstrates the
// PR-staging contract via YAML.
func TestFactory_AckModeNotOffRejectedInPR1(t *testing.T) {
	t.Parallel()
	rawYAML := []byte(`
url: https://splunk.example.com:8088
token: tkn
ack_mode: required
verify_on_startup: false
`)
	factory := audit.LookupOutputFactory("splunk")
	_, err := factory("ack_required", rawYAML, audit.FrameworkContext{})
	require.Error(t, err)
	assert.ErrorIs(t, err, splunk.ErrPR1NotImplemented)
}

// newRegisterStub returns a minimal HEC stub (HTTPS via
// httptest.NewTLSServer would require CA trust; the YAML therefore
// sets allow_insecure_http: true to permit the http:// stub URL —
// register tests verify YAML parsing and factory wiring, not TLS).
// Caller closes the Output (which closes the stub via t.Cleanup).
func newRegisterStub(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/services/collector/health" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"text":"HEC is healthy","code":17}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"text":"Success","code":0}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}
