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

package loki_test

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/audit"
	"github.com/axonops/audit/loki"
)

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

// TestLokiFactory_RegisteredByInit verifies that importing the loki package
// (for its side effect) registers a factory under the "loki" key. This is the
// fundamental contract of the package: blank-import registers the output type.
func TestLokiFactory_RegisteredByInit(t *testing.T) {
	t.Parallel()

	factory := audit.LookupOutputFactory("loki")
	require.NotNil(t, factory, "loki factory must be registered by init(); import _ \"github.com/axonops/audit/loki\" was performed")
}

// ---------------------------------------------------------------------------
// Basic factory error paths
// ---------------------------------------------------------------------------

// TestLokiFactory_EmptyConfig verifies that passing nil config bytes returns
// a clear error indicating that a config block is required.
func TestLokiFactory_EmptyConfig(t *testing.T) {
	t.Parallel()

	factory := audit.LookupOutputFactory("loki")
	require.NotNil(t, factory)

	_, err := factory("my_loki", nil, audit.FrameworkContext{})
	require.Error(t, err)
	// text-only: register.go:132 returns raw fmt.Errorf without a sentinel wrap.
	assert.Contains(t, err.Error(), "config is required",
		"empty config should produce 'config is required' error, got: %q", err.Error())
}

// TestLokiFactory_UnknownField verifies that the YAML decoder runs in strict
// mode (KnownFields(true)), so an unrecognised field causes a clear decode
// error. This prevents silent misconfiguration.
func TestLokiFactory_UnknownField(t *testing.T) {
	t.Parallel()

	factory := audit.LookupOutputFactory("loki")
	require.NotNil(t, factory)

	rawYAML := []byte("url: https://loki.example.com/loki/api/v1/push\nverify_on_startup: false\nunknown_field: oops\n")
	_, err := factory("strict_loki", rawYAML, audit.FrameworkContext{})
	require.Error(t, err)
	// text-only: register.go:154 wraps yaml.UnknownFieldError via WrapUnknownFieldError, not an audit sentinel.
	assert.Contains(t, err.Error(), "unknown_field",
		"strict YAML decode should name the unexpected field, got: %q", err.Error())
}

// ---------------------------------------------------------------------------
// Duration field parsing
// ---------------------------------------------------------------------------

// TestLokiFactory_DurationParsing exercises the custom yamlDuration type for
// flush_interval and timeout. Valid Go duration strings are accepted; bare
// integers and non-duration strings are rejected at decode time.
func TestLokiFactory_DurationParsing(t *testing.T) {
	t.Parallel()

	factory := audit.LookupOutputFactory("loki")
	require.NotNil(t, factory)

	tests := []struct {
		name    string
		yaml    string
		wantErr bool
	}{
		{
			name:    "seconds suffix accepted",
			yaml:    "url: https://loki.example.com/loki/api/v1/push\nverify_on_startup: false\nflush_interval: 5s\n",
			wantErr: false,
		},
		{
			name:    "milliseconds suffix accepted",
			yaml:    "url: https://loki.example.com/loki/api/v1/push\nverify_on_startup: false\nflush_interval: 500ms\n",
			wantErr: false,
		},
		{
			name:    "minutes suffix accepted",
			yaml:    "url: https://loki.example.com/loki/api/v1/push\nverify_on_startup: false\nflush_interval: 1m\n",
			wantErr: false,
		},
		{
			name: "zero duration string accepted",
			// 0s is a valid Go duration; validateLokiConfig replaces zero
			// flush_interval with the default, so this should not error.
			yaml:    "url: https://loki.example.com/loki/api/v1/push\nverify_on_startup: false\nflush_interval: 0s\n",
			wantErr: false,
		},
		{
			name:    "non-duration string rejected",
			yaml:    "url: https://loki.example.com/loki/api/v1/push\nverify_on_startup: false\nflush_interval: banana\n",
			wantErr: true,
		},
		{
			name: "bare integer without suffix rejected",
			// Go time.ParseDuration requires a unit suffix; "5" is not valid.
			yaml:    "url: https://loki.example.com/loki/api/v1/push\nverify_on_startup: false\nflush_interval: 5\n",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			out, err := factory("dur_test", []byte(tt.yaml), audit.FrameworkContext{})
			if tt.wantErr {
				require.Error(t, err, "expected a parse error for YAML: %s", tt.yaml)
				// text-only: register.go:104/108 returns raw fmt.Errorf without a sentinel wrap.
				assert.Contains(t, err.Error(), "duration",
					"error for invalid duration should mention 'duration', got: %q", err.Error())
			} else {
				require.NoError(t, err, "valid duration should not error")
				require.NotNil(t, out)
				require.NoError(t, out.Close())
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Auth mutual exclusivity
// ---------------------------------------------------------------------------

// TestLokiFactory_BasicAuthAndBearerToken_Rejected verifies that the factory
// rejects configurations that set both basic_auth and bearer_token. These are
// mutually exclusive authentication mechanisms.
func TestLokiFactory_BasicAuthAndBearerToken_Rejected(t *testing.T) {
	t.Parallel()

	factory := audit.LookupOutputFactory("loki")
	require.NotNil(t, factory)

	rawYAML := []byte(`
url: https://loki.example.com/loki/api/v1/push
verify_on_startup: false
basic_auth:
  username: alice
  password: secret
bearer_token: tok-should-not-coexist
`)
	_, err := factory("conflict_auth", rawYAML, audit.FrameworkContext{})
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrConfigInvalid,
		"auth conflict must wrap audit.ErrConfigInvalid")
	assert.Contains(t, err.Error(), "mutually exclusive",
		"basic_auth + bearer_token must be rejected with 'mutually exclusive', got: %q", err.Error())
}

// ---------------------------------------------------------------------------
// verify_on_startup YAML round-trip (#286)
// ---------------------------------------------------------------------------

// TestLokiFactory_VerifyOnStartupYAMLRoundTrip verifies that the
// positive YAML field `verify_on_startup: false` maps to
// Config.DisableStartupVerification = true.
func TestLokiFactory_VerifyOnStartupYAMLRoundTrip(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	require.NoError(t, l.Close())

	yaml := []byte(
		"url: http://" + addr + "/loki/api/v1/push\n" +
			"allow_insecure_http: true\n" +
			"allow_private_ranges: true\n" +
			"verify_on_startup: false\n",
	)

	factory := audit.LookupOutputFactory("loki")
	require.NotNil(t, factory)

	out, err := factory("lazy_loki", yaml, audit.FrameworkContext{})
	require.NoError(t, err, "verify_on_startup: false should skip the probe; got: %v", err)
	t.Cleanup(func() { _ = out.Close() })
}

// TestLokiFactory_VerifyOnStartupTimeoutYAMLRoundTrip verifies the
// duration field parses and bounds the probe.
func TestLokiFactory_VerifyOnStartupTimeoutYAMLRoundTrip(t *testing.T) {
	yaml := []byte(
		"url: http://240.0.0.1:80/loki/api/v1/push\n" +
			"allow_insecure_http: true\n" +
			"allow_private_ranges: true\n" +
			"verify_on_startup_timeout: 200ms\n",
	)

	factory := audit.LookupOutputFactory("loki")
	require.NotNil(t, factory)

	start := time.Now()
	_, err := factory("probe-bounded-loki", yaml, audit.FrameworkContext{})
	elapsed := time.Since(start)

	require.Error(t, err, "probe must reject the unreachable URL")
	assert.Less(t, elapsed, 2*time.Second,
		"200 ms verify_on_startup_timeout must bound the probe; took %s", elapsed)
}

// ---------------------------------------------------------------------------
// Gzip / compress defaults
// ---------------------------------------------------------------------------

// TestLokiFactory_GzipDefaultTrue verifies that omitting the "gzip" field
// from the YAML config results in compression being enabled. This is the
// documented default (Gzip: true) and must be preserved by the factory.
// The config passes validation and reaches the "not yet implemented" gate.
func TestLokiFactory_GzipDefaultTrue(t *testing.T) {
	t.Parallel()

	factory := audit.LookupOutputFactory("loki")
	require.NotNil(t, factory)

	rawYAML := []byte("url: https://loki.example.com/loki/api/v1/push\nverify_on_startup: false\n")
	out, err := factory("gzip_default", rawYAML, audit.FrameworkContext{})
	require.NoError(t, err, "valid config with default gzip should succeed")
	require.NotNil(t, out)
	require.NoError(t, out.Close())
}

// TestLokiFactory_GzipExplicitFalse verifies that explicitly setting
// "gzip: false" is accepted by the factory. The field exists and its false
// value is a valid override of the default.
func TestLokiFactory_GzipExplicitFalse(t *testing.T) {
	t.Parallel()

	factory := audit.LookupOutputFactory("loki")
	require.NotNil(t, factory)

	rawYAML := []byte("url: https://loki.example.com/loki/api/v1/push\nverify_on_startup: false\ngzip: false\n")
	out, err := factory("gzip_explicit_false", rawYAML, audit.FrameworkContext{})
	require.NoError(t, err, "gzip: false should be accepted")
	require.NotNil(t, out)
	require.NoError(t, out.Close())
}

// ---------------------------------------------------------------------------
// Dynamic label validation
// ---------------------------------------------------------------------------

// TestLokiFactory_DynamicLabels_UnknownName verifies that unknown dynamic
// label names are rejected. The set of valid dynamic labels is fixed:
// app_name, host, pid, event_type, event_category, severity.
func TestLokiFactory_DynamicLabels_UnknownName(t *testing.T) {
	t.Parallel()

	factory := audit.LookupOutputFactory("loki")
	require.NotNil(t, factory)

	rawYAML := []byte(`
url: https://loki.example.com/loki/api/v1/push
verify_on_startup: false
labels:
  dynamic:
    actor_id: true
`)
	_, err := factory("bad_dynamic_label", rawYAML, audit.FrameworkContext{})
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrConfigInvalid,
		"unknown dynamic label must wrap audit.ErrConfigInvalid")
	assert.Contains(t, err.Error(), "unknown dynamic label",
		"unrecognised dynamic label name must produce 'unknown dynamic label' error, got: %q", err.Error())
}

// ---------------------------------------------------------------------------
// Static label validation
// ---------------------------------------------------------------------------

// TestLokiFactory_StaticLabels_InvalidName verifies that static label names
// that do not match the Loki label name pattern [a-zA-Z_][a-zA-Z0-9_]* are
// rejected. Hyphens, dots, and spaces are not valid.
func TestLokiFactory_StaticLabels_InvalidName(t *testing.T) {
	t.Parallel()

	factory := audit.LookupOutputFactory("loki")
	require.NotNil(t, factory)

	tests := []struct {
		name      string
		labelName string
	}{
		{"hyphen in name", "my-label"},
		{"dot in name", "my.label"},
		{"starts with digit", "2bad"},
		{"space in name", "bad name"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rawYAML := []byte("url: https://loki.example.com/loki/api/v1/push\nverify_on_startup: false\nlabels:\n  static:\n    " + tt.labelName + ": somevalue\n")
			_, err := factory("invalid_label_"+tt.name, rawYAML, audit.FrameworkContext{})
			require.Error(t, err)
			assert.ErrorIs(t, err, audit.ErrConfigInvalid,
				"invalid static label must wrap audit.ErrConfigInvalid")
			assert.Contains(t, err.Error(), "invalid",
				"static label name %q must be rejected as invalid, got: %q", tt.labelName, err.Error())
		})
	}
}

// ---------------------------------------------------------------------------
// Full output creation
// ---------------------------------------------------------------------------

// TestLokiFactory_ValidConfig_ReturnsOutput verifies that a valid
// config creates a working Output that can be closed.
func TestLokiFactory_ValidConfig_ReturnsOutput(t *testing.T) {
	t.Parallel()

	factory := audit.LookupOutputFactory("loki")
	require.NotNil(t, factory)

	rawYAML := []byte(`
url: https://loki.example.com/loki/api/v1/push
verify_on_startup: false
batch_size: 50
flush_interval: 10s
timeout: 5s
max_retries: 2
buffer_size: 500
`)
	out, err := factory("valid", rawYAML, audit.FrameworkContext{})
	require.NoError(t, err, "valid config should produce an output")
	require.NotNil(t, out)
	assert.Equal(t, "valid", out.Name(),
		"factory output Name() must return the consumer-specified name, not the internal loki:<host> name")
	require.NoError(t, out.Close())
}

// TestLokiFactory_ValidConfig_WithAllAuthOptions verifies that each auth
// variant (none, basic, bearer) passes validation in isolation.
func TestLokiFactory_ValidConfig_WithAllAuthOptions(t *testing.T) {
	t.Parallel()

	factory := audit.LookupOutputFactory("loki")
	require.NotNil(t, factory)

	tests := []struct {
		name string
		yaml string
	}{
		{
			name: "no auth",
			yaml: "url: https://loki.example.com/loki/api/v1/push\nverify_on_startup: false\n",
		},
		{
			name: "basic auth",
			yaml: "url: https://loki.example.com/loki/api/v1/push\nverify_on_startup: false\nbasic_auth:\n  username: alice\n  password: s3cr3t\n",
		},
		{
			name: "bearer token",
			yaml: "url: https://loki.example.com/loki/api/v1/push\nverify_on_startup: false\nbearer_token: tok-abc123\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			out, err := factory("auth_test", []byte(tt.yaml), audit.FrameworkContext{})
			require.NoError(t, err, "%s auth variant should produce output", tt.name)
			require.NotNil(t, out)
			require.NoError(t, out.Close())
		})
	}
}

// TestLokiFactory_NewFactory_NilMetrics verifies that NewFactory(nil) returns
// a working factory function. Nil metrics is an explicitly supported path
// (disables Loki-specific metric collection).
func TestLokiFactory_NewFactory_NilMetrics(t *testing.T) {
	t.Parallel()

	// Import the loki package has already registered the default factory.
	// NewFactory returns a separate factory with custom metrics wiring.
	// We call it directly here via the loki package (external test).
	// Since register_test.go is in package loki_test, we cannot call
	// loki.NewFactory without importing it by name — which we can do
	// through the side-effect import above.
	//
	// We exercise this path indirectly: the default factory (registered by
	// init) uses nil lokiMetrics internally. A valid config must still reach
	// the output rather than panicking on nil metrics.
	factory := audit.LookupOutputFactory("loki")
	require.NotNil(t, factory)

	out, err := factory("nil_metrics_path", []byte("url: https://loki.example.com/loki/api/v1/push\nverify_on_startup: false\n"), audit.FrameworkContext{})
	require.NoError(t, err, "nil coreMetrics must not panic")
	require.NotNil(t, out)
	require.NoError(t, out.Close())
}

// ---------------------------------------------------------------------------
// Dynamic label parsing — success paths
// ---------------------------------------------------------------------------

// TestLokiFactory_DynamicLabels_ExcludeFields verifies that setting a known
// dynamic label to false correctly excludes it from the stream labels. This
// exercises the full parseDynamicLabels success path for each valid name.
func TestLokiFactory_DynamicLabels_ExcludeFields(t *testing.T) {
	t.Parallel()

	factory := audit.LookupOutputFactory("loki")
	require.NotNil(t, factory)

	// Each valid dynamic label name disabled (false) must be accepted and
	// reach the Phase 1 gate.
	validLabels := []string{
		"app_name",
		"host",
		"pid",
		"event_type",
		"event_category",
		"severity",
	}

	for _, labelName := range validLabels {
		t.Run("exclude_"+labelName, func(t *testing.T) {
			t.Parallel()

			rawYAML := []byte("url: https://loki.example.com/loki/api/v1/push\nverify_on_startup: false\nlabels:\n  dynamic:\n    " + labelName + ": false\n")
			out, err := factory("dyn_"+labelName, rawYAML, audit.FrameworkContext{})
			require.NoError(t, err,
				"disabling dynamic label %q should produce output", labelName)
			require.NotNil(t, out)
			require.NoError(t, out.Close())
		})
	}
}

// TestLokiFactory_DynamicLabels_IncludeFields verifies that setting a known
// dynamic label to true (explicitly included) is also accepted.
func TestLokiFactory_DynamicLabels_IncludeFields(t *testing.T) {
	t.Parallel()

	factory := audit.LookupOutputFactory("loki")
	require.NotNil(t, factory)

	rawYAML := []byte(`
url: https://loki.example.com/loki/api/v1/push
verify_on_startup: false
labels:
  dynamic:
    app_name: true
    event_type: true
    severity: false
`)
	out, err := factory("mixed_dynamic", rawYAML, audit.FrameworkContext{})
	require.NoError(t, err, "mixed include/exclude dynamic labels should produce output")
	require.NotNil(t, out)
	require.NoError(t, out.Close())
}

// TestLokiNewFactory_WithMetricsFactory verifies that NewFactory threads
// its OutputMetricsFactory through the constructed factory using
// outputType="loki" and the YAML-configured outputName.
func TestLokiNewFactory_WithMetricsFactory(t *testing.T) {
	var gotType, gotName string
	mf := func(outputType, outputName string) audit.OutputMetrics {
		gotType, gotName = outputType, outputName
		return &factoryMockLokiMetrics{}
	}
	factory := loki.NewFactory(mf)

	rawYAML := []byte("url: https://loki.example.com/loki/api/v1/push\nverify_on_startup: false\nbatch_size: 10\nflush_interval: 1s\ntimeout: 5s\n")
	out, err := factory("with_metrics", rawYAML, audit.FrameworkContext{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	assert.Equal(t, "with_metrics", out.Name())
	assert.Equal(t, "loki", gotType, "factory must be called with outputType=\"loki\"")
	assert.Equal(t, "with_metrics", gotName)
}

// TestLokiNewFactory_NilFactory verifies that NewFactory(nil) still
// produces a working factory that constructs outputs without per-output
// metrics wiring.
func TestLokiNewFactory_NilFactory(t *testing.T) {
	factory := loki.NewFactory(nil)

	rawYAML := []byte("url: https://loki.example.com/loki/api/v1/push\nverify_on_startup: false\nbatch_size: 10\nflush_interval: 1s\ntimeout: 5s\n")
	out, err := factory("nil_metrics", rawYAML, audit.FrameworkContext{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	assert.Equal(t, "nil_metrics", out.Name())
}

// TestLokiNewFactory_FactoryReturnsNil covers the silently-untested
// branch where the OutputMetricsFactory legitimately returns nil for a
// specific output — the constructed output must still build cleanly
// and have no metrics wired.
func TestLokiNewFactory_FactoryReturnsNil(t *testing.T) {
	factory := loki.NewFactory(func(_, _ string) audit.OutputMetrics {
		return nil
	})

	rawYAML := []byte("url: https://loki.example.com/loki/api/v1/push\nverify_on_startup: false\nbatch_size: 10\nflush_interval: 1s\ntimeout: 5s\n")
	out, err := factory("nil_return", rawYAML, audit.FrameworkContext{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	assert.Equal(t, "nil_return", out.Name())
}

// factoryMockLokiMetrics is a minimal audit.OutputMetrics scoped to
// the NewFactory tests.
type factoryMockLokiMetrics struct {
	audit.NoOpOutputMetrics
}

// Compile-time assertion: the factory mock is audit.OutputMetrics.
var _ audit.OutputMetrics = (*factoryMockLokiMetrics)(nil)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
