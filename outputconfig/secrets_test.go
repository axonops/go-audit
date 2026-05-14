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

package outputconfig_test

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/audit"
	"github.com/axonops/audit/outputconfig"
	"github.com/axonops/audit/secrets"
)

// ---------------------------------------------------------------------------
// Mock secret provider
// ---------------------------------------------------------------------------

type mockSecretProvider struct { //nolint:govet // readability over alignment
	scheme     string
	data       map[string]map[string]string // path → {key → value}
	err        error                        // error to return from Resolve
	calls      atomic.Int64
	delay      time.Duration // delay before resolving (for timeout tests)
	closeCalls atomic.Int64
}

func (m *mockSecretProvider) Scheme() string { return m.scheme }

func (m *mockSecretProvider) Resolve(ctx context.Context, ref secrets.Ref) (string, error) {
	m.calls.Add(1)
	if m.delay > 0 {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(m.delay):
		}
	}
	if m.err != nil {
		return "", m.err
	}
	keys, ok := m.data[ref.Path]
	if !ok {
		return "", fmt.Errorf("%w: path %q", secrets.ErrSecretNotFound, ref.Path)
	}
	val, ok := keys[ref.Key]
	if !ok {
		return "", fmt.Errorf("%w: key %q at path %q", secrets.ErrSecretNotFound, ref.Key, ref.Path)
	}
	return val, nil
}

func (m *mockSecretProvider) ResolvePath(ctx context.Context, path string) (map[string]string, error) {
	m.calls.Add(1)
	if m.delay > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(m.delay):
		}
	}
	if m.err != nil {
		return nil, m.err
	}
	keys, ok := m.data[path]
	if !ok {
		return nil, fmt.Errorf("%w: path %q", secrets.ErrSecretNotFound, path)
	}
	return keys, nil
}

func (m *mockSecretProvider) Close() error {
	m.closeCalls.Add(1)
	return nil
}

func (m *mockSecretProvider) String() string {
	return fmt.Sprintf("mock{scheme: %s, [REDACTED]}", m.scheme)
}

// newMockProvider creates a mock with pre-loaded secrets.
func newMockProvider(scheme string, data map[string]map[string]string) *mockSecretProvider {
	return &mockSecretProvider{scheme: scheme, data: data}
}

// Compile-time check — mock implements BatchProvider.
var _ secrets.BatchProvider = (*mockSecretProvider)(nil)

// ---------------------------------------------------------------------------
// Helper: minimal YAML with a ref+ in a type-config field
// ---------------------------------------------------------------------------

func yamlWithHMACRefs(saltRef, versionRef, hashRef, enabledValue string) []byte {
	return []byte(fmt.Sprintf(`
version: 1
app_name: test
host: test
outputs:
  audit_log:
    type: stdout
    hmac:
      enabled: %s
      salt:
        version: %s
        value: %s
      algorithm: %s
`, enabledValue, versionRef, saltRef, hashRef))
}

// ---------------------------------------------------------------------------
// TestLoad_WithSecretProvider — integration tests
// ---------------------------------------------------------------------------

func TestLoad_WithSecretProvider_AllHMACFieldsResolved(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	mock := newMockProvider("mock", map[string]map[string]string{
		"secret/data/hmac": {
			"salt":      "my-secret-salt-value-32bytes!!!!",
			"version":   "v1",
			"algorithm": "HMAC-SHA-256",
			"enabled":   "true",
		},
	})
	data := yamlWithHMACRefs(
		"ref+mock://secret/data/hmac#salt",
		"ref+mock://secret/data/hmac#version",
		"ref+mock://secret/data/hmac#algorithm",
		"ref+mock://secret/data/hmac#enabled",
	)
	result, err := outputconfig.Load(
		context.Background(), data, tax,
		outputconfig.WithSecretProvider(mock),
	)
	require.NoError(t, err)
	require.Len(t, result.OutputMetadata(), 1)
	hmac := result.OutputMetadata()[0].HMACConfig
	require.NotNil(t, hmac)
	assert.True(t, hmac.Enabled)
	assert.Equal(t, "v1", hmac.Salt.Version)
	assert.Equal(t, []byte("my-secret-salt-value-32bytes!!!!"), hmac.Salt.Value)
	assert.Equal(t, "HMAC-SHA-256", hmac.Algorithm)
	for _, o := range result.OutputMetadata() {
		_ = o.Output.Close()
	}
}

func TestLoad_WithSecretProvider_EnvVarProducesRef(t *testing.T) {
	tax := testTaxonomy(t)
	mock := newMockProvider("mock", map[string]map[string]string{
		"secret/data/hmac": {
			"salt": "env-var-resolved-salt-32bytes!!!",
		},
	})
	t.Setenv("TEST_HMAC_SALT_REF", "ref+mock://secret/data/hmac#salt")
	data := []byte(`
version: 1
app_name: test
host: test
outputs:
  audit_log:
    type: stdout
    hmac:
      enabled: true
      salt:
        version: v1
        value: ${TEST_HMAC_SALT_REF}
      algorithm: HMAC-SHA-256
`)
	result, err := outputconfig.Load(
		context.Background(), data, tax,
		outputconfig.WithSecretProvider(mock),
	)
	require.NoError(t, err)
	require.Len(t, result.OutputMetadata(), 1)
	hmac := result.OutputMetadata()[0].HMACConfig
	require.NotNil(t, hmac)
	assert.Equal(t, []byte("env-var-resolved-salt-32bytes!!!"), hmac.Salt.Value)
	for _, o := range result.OutputMetadata() {
		_ = o.Output.Close()
	}
}

func TestLoad_WithSecretProvider_HMACDisabledSkipsRefs(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	mock := newMockProvider("mock", map[string]map[string]string{
		"secret/data/hmac": {"enabled": "false"},
	})
	// Salt/version/hash use ref+ URIs but enabled resolves to false,
	// so those refs must NOT be resolved.
	data := yamlWithHMACRefs(
		"ref+mock://nonexistent/path#salt",
		"ref+mock://nonexistent/path#version",
		"ref+mock://nonexistent/path#algorithm",
		"ref+mock://secret/data/hmac#enabled",
	)
	result, err := outputconfig.Load(
		context.Background(), data, tax,
		outputconfig.WithSecretProvider(mock),
	)
	require.NoError(t, err)
	require.Len(t, result.OutputMetadata(), 1)
	assert.Nil(t, result.OutputMetadata()[0].HMACConfig)
	// Provider should only have been called once (for the enabled field).
	assert.Equal(t, int64(1), mock.calls.Load())
	for _, o := range result.OutputMetadata() {
		_ = o.Output.Close()
	}
}

func TestLoad_WithSecretProvider_HMACDisabledLiteral_SkipsRefs(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	// No mock needed — enabled is a literal false, remaining refs are
	// never resolved and should not cause errors.
	data := yamlWithHMACRefs(
		"ref+nonexistent://path#salt",
		"ref+nonexistent://path#version",
		"ref+nonexistent://path#hash",
		"false",
	)
	result, err := outputconfig.Load(
		context.Background(), data, tax,
	)
	require.NoError(t, err)
	require.Len(t, result.OutputMetadata(), 1)
	assert.Nil(t, result.OutputMetadata()[0].HMACConfig)
	for _, o := range result.OutputMetadata() {
		_ = o.Output.Close()
	}
}

func TestLoad_WithSecretProvider_NoProviderNoRefsUnchanged(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	data := []byte("version: 1\napp_name: test\nhost: test\noutputs:\n  c:\n    type: stdout\n")
	result, err := outputconfig.Load(context.Background(), data, tax)
	require.NoError(t, err)
	require.Len(t, result.OutputMetadata(), 1)
	for _, o := range result.OutputMetadata() {
		_ = o.Output.Close()
	}
}

func TestLoad_WithSecretProvider_NoProviderWithRefsErrors(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	data := []byte(`
version: 1
app_name: test
host: test
outputs:
  audit_log:
    type: stdout
    stdout:
      format: ref+openbao://secret/data/config#format
`)
	_, err := outputconfig.Load(context.Background(), data, tax)
	require.Error(t, err)
	// No provider registered → resolver is nil → refs pass through
	// env+secret expansion unchanged → safety net catches them.
	assert.ErrorIs(t, err, secrets.ErrUnresolvedRef)
}

func TestLoad_WithSecretProvider_DuplicateSchemeErrors(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	mock1 := newMockProvider("mock", nil)
	mock2 := newMockProvider("mock", nil)
	data := []byte("version: 1\napp_name: test\nhost: test\noutputs:\n  c:\n    type: stdout\n")
	_, err := outputconfig.Load(
		context.Background(), data, tax,
		outputconfig.WithSecretProvider(mock1),
		outputconfig.WithSecretProvider(mock2),
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "duplicate")
}

func TestLoad_WithSecretProvider_ContextTimeout(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	mock := &mockSecretProvider{
		scheme: "mock",
		data:   map[string]map[string]string{"path": {"key": "value"}},
		delay:  5 * time.Second, // will timeout
	}
	data := []byte(`
version: 1
app_name: test
host: test
outputs:
  audit_log:
    type: stdout
    hmac:
      enabled: true
      salt:
        version: v1
        value: ref+mock://path#key
      algorithm: HMAC-SHA-256
`)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := outputconfig.Load(
		ctx, data, tax,
		outputconfig.WithSecretProvider(mock),
		outputconfig.WithSecretTimeout(50*time.Millisecond),
	)
	require.Error(t, err)
}

func TestLoad_WithSecretProvider_ErrorNeverContainsSecretValue(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	secretValue := "SUPER-SECRET-VALUE-MUST-NOT-LEAK"
	mock := newMockProvider("mock", map[string]map[string]string{
		"secret/data/hmac": {"salt": secretValue, "enabled": "true"},
	})
	// Hash ref will fail — check that the error message from that
	// failure does not contain the already-resolved salt value.
	data := yamlWithHMACRefs(
		"ref+mock://secret/data/hmac#salt",
		"v1",
		"ref+mock://nonexistent/path#algorithm",
		"ref+mock://secret/data/hmac#enabled",
	)
	_, err := outputconfig.Load(
		context.Background(), data, tax,
		outputconfig.WithSecretProvider(mock),
	)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), secretValue)
}

// TestClearCaches_EmptiesBothMaps is the direct unit test for the
// defence-in-depth call site. Removing or breaking the `clear()`
// calls in resolver.clearCaches() MUST fail this test — exercised
// via the [outputconfig.ResolverClearCachesForTest] hook so the
// contract is locked in at the line level, not just at the Load
// level where the resolver is already local to the call (#479).
func TestClearCaches_EmptiesBothMaps(t *testing.T) {
	t.Parallel()

	// nil receiver is a no-op — covered explicitly so the guard
	// is not quietly removed in a refactor.
	outputconfig.ResolverClearCachesForTest(nil)

	mock := newMockProvider("mock", nil)
	r, err := outputconfig.NewResolverForTest([]secrets.Provider{mock})
	require.NoError(t, err)
	require.NotNil(t, r)

	outputconfig.ResolverSeedCacheForTest(r)
	pathLen, refLen := outputconfig.ResolverCacheSizesForTest(r)
	require.Equal(t, 1, pathLen, "seed must populate pathCache")
	require.Equal(t, 1, refLen, "seed must populate refCache")

	outputconfig.ResolverClearCachesForTest(r)
	pathLen, refLen = outputconfig.ResolverCacheSizesForTest(r)
	assert.Equal(t, 0, pathLen, "clearCaches() must empty pathCache")
	assert.Equal(t, 0, refLen, "clearCaches() must empty refCache")
}

// TestLoad_ClearsResolverCacheBeforeReturn is the named contract test
// from #479 Testing Requirements. It proves the resolver's path and
// ref caches do not persist across Load invocations — a second Load
// with the same provider and same refs must produce fresh provider
// calls, never hitting a stale intra-process cache.
//
// This is the observable companion to the defence-in-depth
// clearCaches() call in Load: even if a future refactor accidentally
// shares a resolver across Loads, this test fails closed.
func TestLoad_ClearsResolverCacheBeforeReturn(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	mock := newMockProvider("mock", map[string]map[string]string{
		"secret/data/hmac": {
			"salt":      "cached-salt-value-32-bytes!!!!!!",
			"version":   "v1",
			"algorithm": "HMAC-SHA-256",
			"enabled":   "true",
		},
	})
	data := yamlWithHMACRefs(
		"ref+mock://secret/data/hmac#salt",
		"ref+mock://secret/data/hmac#version",
		"ref+mock://secret/data/hmac#algorithm",
		"ref+mock://secret/data/hmac#enabled",
	)

	// First Load — BatchProvider resolves the path once.
	result1, err := outputconfig.Load(
		context.Background(), data, tax,
		outputconfig.WithSecretProvider(mock),
	)
	require.NoError(t, err)
	callsAfterFirst := mock.calls.Load()
	require.Equal(t, int64(1), callsAfterFirst,
		"first Load should produce exactly one provider call (path-level cache)")

	// Second Load with the SAME provider and SAME refs. If Load did
	// not clear the resolver caches before returning (or if caches
	// somehow survived as package state), this second Load would
	// produce zero additional provider calls. The contract is that
	// each Load is self-contained: a fresh resolver is built, the
	// provider is consulted anew.
	result2, err := outputconfig.Load(
		context.Background(), data, tax,
		outputconfig.WithSecretProvider(mock),
	)
	require.NoError(t, err)
	callsAfterSecond := mock.calls.Load()
	assert.Equal(t, int64(2), callsAfterSecond,
		"second Load must produce a second provider call — resolver caches must not persist across Loads (#479)")

	// Sanity: both Loads produced the same resolved values.
	require.Len(t, result1.OutputMetadata(), 1)
	require.Len(t, result2.OutputMetadata(), 1)
	hmac1, hmac2 := result1.OutputMetadata()[0].HMACConfig, result2.OutputMetadata()[0].HMACConfig
	require.NotNil(t, hmac1)
	require.NotNil(t, hmac2)
	assert.Equal(t, hmac1.Salt.Value, hmac2.Salt.Value)
	assert.Equal(t, hmac1.Salt.Version, hmac2.Salt.Version)

	for _, o := range result1.OutputMetadata() {
		_ = o.Output.Close()
	}
	for _, o := range result2.OutputMetadata() {
		_ = o.Output.Close()
	}
}

func TestLoad_WithSecretProvider_PathLevelCache_OneCallForMultipleKeys(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	mock := newMockProvider("mock", map[string]map[string]string{
		"secret/data/hmac": {
			"salt":      "cached-salt-value-32-bytes!!!!!!",
			"version":   "v1",
			"algorithm": "HMAC-SHA-256",
			"enabled":   "true",
		},
	})
	// All 4 HMAC fields from the same path — with BatchProvider
	// (ResolvePath), only 1 API call should be made. The first ref
	// triggers ResolvePath which returns all keys; subsequent refs
	// to the same path hit the path-level cache.
	data := yamlWithHMACRefs(
		"ref+mock://secret/data/hmac#salt",
		"ref+mock://secret/data/hmac#version",
		"ref+mock://secret/data/hmac#algorithm",
		"ref+mock://secret/data/hmac#enabled",
	)
	result, err := outputconfig.Load(
		context.Background(), data, tax,
		outputconfig.WithSecretProvider(mock),
	)
	require.NoError(t, err)
	// Path-level cache: one ResolvePath call for all 4 keys.
	assert.Equal(t, int64(1), mock.calls.Load())
	// Also verify the values were correctly extracted from the batch.
	require.Len(t, result.OutputMetadata(), 1)
	hmac := result.OutputMetadata()[0].HMACConfig
	require.NotNil(t, hmac)
	assert.Equal(t, "v1", hmac.Salt.Version)
	assert.Equal(t, []byte("cached-salt-value-32-bytes!!!!!!"), hmac.Salt.Value)
	assert.Equal(t, "HMAC-SHA-256", hmac.Algorithm)
	for _, o := range result.OutputMetadata() {
		_ = o.Output.Close()
	}
}

func TestLoad_WithSecretProvider_MixedLiteralEnvRef(t *testing.T) {
	tax := testTaxonomy(t)
	mock := newMockProvider("mock", map[string]map[string]string{
		"secret/data/hmac": {"salt": "ref-resolved-salt-value-32bytes!"},
	})
	t.Setenv("TEST_HMAC_VERSION", "v2")
	data := []byte(`
version: 1
app_name: test
host: test
outputs:
  audit_log:
    type: stdout
    hmac:
      enabled: true
      salt:
        version: ${TEST_HMAC_VERSION}
        value: ref+mock://secret/data/hmac#salt
      algorithm: HMAC-SHA-256
`)
	result, err := outputconfig.Load(
		context.Background(), data, tax,
		outputconfig.WithSecretProvider(mock),
	)
	require.NoError(t, err)
	hmac := result.OutputMetadata()[0].HMACConfig
	require.NotNil(t, hmac)
	assert.Equal(t, "v2", hmac.Salt.Version)                                     // from env var
	assert.Equal(t, []byte("ref-resolved-salt-value-32bytes!"), hmac.Salt.Value) // from ref
	assert.Equal(t, "HMAC-SHA-256", hmac.Algorithm)                              // literal
	for _, o := range result.OutputMetadata() {
		_ = o.Output.Close()
	}
}

func TestLoad_WithSecretProvider_UnregisteredSchemeErrors(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	mock := newMockProvider("mock", nil)
	data := []byte(`
version: 1
app_name: test
host: test
outputs:
  audit_log:
    type: stdout
    hmac:
      enabled: true
      salt:
        version: v1
        value: ref+vault://secret/data/hmac#salt
      algorithm: HMAC-SHA-256
`)
	_, err := outputconfig.Load(
		context.Background(), data, tax,
		outputconfig.WithSecretProvider(mock), // mock scheme, not vault
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrProviderNotRegistered)
}

func TestLoad_WithSecretProvider_EmptyResolvedValueRejected(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	mock := newMockProvider("mock", map[string]map[string]string{
		"secret/data/hmac": {
			"salt":    "",
			"enabled": "true",
		},
	})
	data := yamlWithHMACRefs(
		"ref+mock://secret/data/hmac#salt",
		"v1",
		"HMAC-SHA-256",
		"ref+mock://secret/data/hmac#enabled",
	)
	_, err := outputconfig.Load(
		context.Background(), data, tax,
		outputconfig.WithSecretProvider(mock),
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrSecretResolveFailed)
	assert.Contains(t, err.Error(), "empty")
}

func TestLoad_WithSecretProvider_OversizedValueRejected(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	bigValue := strings.Repeat("x", outputconfig.MaxSecretValueSize+1)
	mock := newMockProvider("mock", map[string]map[string]string{
		"secret/data/hmac": {
			"salt":    bigValue,
			"enabled": "true",
		},
	})
	data := yamlWithHMACRefs(
		"ref+mock://secret/data/hmac#salt",
		"v1",
		"HMAC-SHA-256",
		"ref+mock://secret/data/hmac#enabled",
	)
	_, err := outputconfig.Load(
		context.Background(), data, tax,
		outputconfig.WithSecretProvider(mock),
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrSecretResolveFailed)
	assert.NotContains(t, err.Error(), bigValue)
}

func TestLoad_WithSecretProvider_HMACEnabledTrue_RequiresAllFields(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	mock := newMockProvider("mock", map[string]map[string]string{
		"secret/data/hmac": {"enabled": "true"},
		// salt path doesn't exist — will fail.
	})
	data := yamlWithHMACRefs(
		"ref+mock://nonexistent/path#salt",
		"v1",
		"HMAC-SHA-256",
		"ref+mock://secret/data/hmac#enabled",
	)
	_, err := outputconfig.Load(
		context.Background(), data, tax,
		outputconfig.WithSecretProvider(mock),
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrSecretNotFound)
}

// ---------------------------------------------------------------------------
// Ref in non-HMAC field (ensures tree walk covers all fields)
// ---------------------------------------------------------------------------

func TestLoad_WithSecretProvider_RefInNonHMACFieldResolves(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	// Stdout type config doesn't have string fields to resolve,
	// but we can verify the pipeline doesn't error with refs in
	// fields that are processed by the tree walker.
	mock := newMockProvider("mock", map[string]map[string]string{
		"secret/data/config": {"app": "my-resolved-app"},
	})
	data := []byte(`
version: 1
app_name: ref+mock://secret/data/config#app
host: test
outputs:
  c:
    type: stdout
`)
	result, err := outputconfig.Load(
		context.Background(), data, tax,
		outputconfig.WithSecretProvider(mock),
	)
	require.NoError(t, err)
	assert.Equal(t, "my-resolved-app", result.AppName())
	for _, o := range result.OutputMetadata() {
		_ = o.Output.Close()
	}
}

// ---------------------------------------------------------------------------
// Backward compatibility: unused env vars with no refs
// ---------------------------------------------------------------------------

func TestLoad_WithSecretProvider_EnvVarProducesLiteral_NoProviderCall(t *testing.T) {
	tax := testTaxonomy(t)
	mock := newMockProvider("mock", nil)
	t.Setenv("TEST_HMAC_SALT_LITERAL", "literal-salt-value-32-bytes!!!!!")
	data := []byte(`
version: 1
app_name: test
host: test
outputs:
  audit_log:
    type: stdout
    hmac:
      enabled: true
      salt:
        version: v1
        value: ${TEST_HMAC_SALT_LITERAL}
      algorithm: HMAC-SHA-256
`)
	result, err := outputconfig.Load(
		context.Background(), data, tax,
		outputconfig.WithSecretProvider(mock),
	)
	require.NoError(t, err)
	assert.Equal(t, int64(0), mock.calls.Load())
	require.NotNil(t, result.OutputMetadata()[0].HMACConfig)
	assert.Equal(t, []byte("literal-salt-value-32-bytes!!!!!"), result.OutputMetadata()[0].HMACConfig.Salt.Value)
	for _, o := range result.OutputMetadata() {
		_ = o.Output.Close()
	}
}

// ---------------------------------------------------------------------------
// Single-pass guarantee
// ---------------------------------------------------------------------------

func TestLoad_WithSecretProvider_SinglePassGuarantee(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	// Provider returns a value that itself contains ref+.
	// It must NOT be re-resolved.
	mock := newMockProvider("mock", map[string]map[string]string{
		"secret/data/hmac": {
			"salt": "ref+mock://other/path#key",
		},
	})
	data := []byte(`
version: 1
app_name: test
host: test
outputs:
  audit_log:
    type: stdout
    hmac:
      enabled: true
      salt:
        version: v1
        value: ref+mock://secret/data/hmac#salt
      algorithm: HMAC-SHA-256
`)
	// The resolved value contains "ref+mock://..." which the safety
	// net should flag as an unresolved reference.
	_, err := outputconfig.Load(
		context.Background(), data, tax,
		outputconfig.WithSecretProvider(mock),
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrUnresolvedRef)
	// Provider should only have been called once — no re-scan.
	assert.Equal(t, int64(1), mock.calls.Load())
}

// ---------------------------------------------------------------------------
// (*Loaded).String() does not contain secrets
// ---------------------------------------------------------------------------

func TestLoad_WithSecretProvider_LoadedStringNeverContainsSecrets(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	secretSalt := "super-secret-salt-32-bytes!!!!!!"
	mock := newMockProvider("mock", map[string]map[string]string{
		"secret/data/hmac": {"salt": secretSalt},
	})
	data := []byte(`
version: 1
app_name: test
host: test
outputs:
  audit_log:
    type: stdout
    hmac:
      enabled: true
      salt:
        version: v1
        value: ref+mock://secret/data/hmac#salt
      algorithm: HMAC-SHA-256
`)
	result, err := outputconfig.Load(
		context.Background(), data, tax,
		outputconfig.WithSecretProvider(mock),
	)
	require.NoError(t, err)
	s := result.String()
	assert.NotContains(t, s, secretSalt)
	s2 := fmt.Sprintf("%+v", result)
	assert.NotContains(t, s2, secretSalt)
	for _, o := range result.OutputMetadata() {
		_ = o.Output.Close()
	}
}

// ---------------------------------------------------------------------------
// env var pointing to disabled HMAC
// ---------------------------------------------------------------------------

func TestLoad_WithSecretProvider_HMACEnabledEnvRef_RefSalt(t *testing.T) {
	tax := testTaxonomy(t)
	mock := newMockProvider("mock", map[string]map[string]string{
		"secret/data/hmac": {"salt": "env-enabled-ref-salt-32-bytes!!!"},
	})
	t.Setenv("TEST_HMAC_ENABLED", "true")
	data := []byte(`
version: 1
app_name: test
host: test
outputs:
  audit_log:
    type: stdout
    hmac:
      enabled: ${TEST_HMAC_ENABLED}
      salt:
        version: v1
        value: ref+mock://secret/data/hmac#salt
      algorithm: HMAC-SHA-256
`)
	result, err := outputconfig.Load(
		context.Background(), data, tax,
		outputconfig.WithSecretProvider(mock),
	)
	require.NoError(t, err)
	require.NotNil(t, result.OutputMetadata()[0].HMACConfig)
	assert.Equal(t, []byte("env-enabled-ref-salt-32-bytes!!!"), result.OutputMetadata()[0].HMACConfig.Salt.Value)
	for _, o := range result.OutputMetadata() {
		_ = o.Output.Close()
	}
}

// ---------------------------------------------------------------------------
// Cache hit: same ref in two different fields → one provider call
// ---------------------------------------------------------------------------

func TestLoad_WithSecretProvider_CacheHit_SameRefTwoFields(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	// Both app_name and host resolve from the same ref — provider
	// should be called only once (cache hit on second call).
	mock := newMockProvider("mock", map[string]map[string]string{
		"secret/data/config": {"name": "my-app"},
	})
	data := []byte(`
version: 1
app_name: ref+mock://secret/data/config#name
host: ref+mock://secret/data/config#name
outputs:
  c:
    type: stdout
`)
	result, err := outputconfig.Load(
		context.Background(), data, tax,
		outputconfig.WithSecretProvider(mock),
	)
	require.NoError(t, err)
	assert.Equal(t, "my-app", result.AppName())
	assert.Equal(t, "my-app", result.Host())
	// Same scheme+path+key → one provider call, not two.
	assert.Equal(t, int64(1), mock.calls.Load())
	for _, o := range result.OutputMetadata() {
		_ = o.Output.Close()
	}
}

// ---------------------------------------------------------------------------
// Nil provider guard
// ---------------------------------------------------------------------------

func TestLoad_WithSecretProvider_NilProviderErrors(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	data := []byte("version: 1\napp_name: test\nhost: test\noutputs:\n  c:\n    type: stdout\n")
	_, err := outputconfig.Load(
		context.Background(), data, tax,
		outputconfig.WithSecretProvider(nil),
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "nil")
}

// ---------------------------------------------------------------------------
// Unresolved ref in top-level field (no provider registered)
// ---------------------------------------------------------------------------

func TestLoad_UnresolvedRefInAppName_NoProviderErrors(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	data := []byte(`
version: 1
app_name: ref+openbao://secret/data/config#app
host: test
outputs:
  c:
    type: stdout
`)
	_, err := outputconfig.Load(context.Background(), data, tax)
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrUnresolvedRef)
}

func TestLoad_UnresolvedRefInHost_NoProviderErrors(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	data := []byte(`
version: 1
app_name: test
host: ref+vault://secret/data/config#host
outputs:
  c:
    type: stdout
`)
	_, err := outputconfig.Load(context.Background(), data, tax)
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrUnresolvedRef)
}

// ---------------------------------------------------------------------------
// HMAC enabled ref with no provider
// ---------------------------------------------------------------------------

func TestLoad_HMACEnabledRef_NoProvider_ClearError(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	data := []byte(`
version: 1
app_name: test
host: test
outputs:
  audit_log:
    type: stdout
    hmac:
      enabled: ref+openbao://secret/data/hmac#enabled
      salt:
        version: v1
        value: my-salt-value-32-bytes!!!!!!!!
      algorithm: HMAC-SHA-256
`)
	_, err := outputconfig.Load(context.Background(), data, tax)
	require.Error(t, err)
	// Should get a clear error about no provider, not a toBool error
	// leaking the ref URI.
	// text-only: hmac.go:136 returns raw fmt.Errorf without a sentinel wrap.
	assert.Contains(t, err.Error(), "no provider")
}

// ---------------------------------------------------------------------------
// Coverage: expandOutputSecrets route and formatter branches
// ---------------------------------------------------------------------------

func TestLoad_WithSecretProvider_RouteNoRefs_ProviderNotCalled(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	mock := newMockProvider("mock", nil)
	// Route block with no refs — exercises the routeRaw branch of
	// expandOutputSecrets (no-op path: ParseRef returns zero for
	// plain strings). Route category values are taxonomy-validated,
	// so refs in include_categories would fail at buildRoute even
	// after resolution. This test confirms the no-ref path works.
	data := []byte(`
version: 1
app_name: test
host: test
outputs:
  audit_log:
    type: stdout
    route:
      include_categories:
        security: {}
`)
	result, err := outputconfig.Load(
		context.Background(), data, tax,
		outputconfig.WithSecretProvider(mock),
	)
	require.NoError(t, err)
	require.Len(t, result.OutputMetadata(), 1)
	assert.NotNil(t, result.OutputMetadata()[0].Route)
	assert.Equal(t, int64(0), mock.calls.Load())
	for _, o := range result.OutputMetadata() {
		_ = o.Output.Close()
	}
}

func TestLoad_WithSecretProvider_RefInFormatterField(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	mock := newMockProvider("mock", map[string]map[string]string{
		"secret/data/fmt": {"vendor": "SecretVendor"},
	})
	data := []byte(`
version: 1
app_name: test
host: test
outputs:
  audit_log:
    type: stdout
    formatter:
      type: cef
      vendor: ref+mock://secret/data/fmt#vendor
      product: MyProduct
      version: "1.0"
`)
	result, err := outputconfig.Load(
		context.Background(), data, tax,
		outputconfig.WithSecretProvider(mock),
	)
	require.NoError(t, err)
	require.Len(t, result.OutputMetadata(), 1)
	assert.Equal(t, int64(1), mock.calls.Load())
	// Verify the resolved value made it into the formatter.
	cef, ok := result.OutputMetadata()[0].Formatter.(*audit.CEFFormatter)
	require.True(t, ok, "expected *audit.CEFFormatter")
	assert.Equal(t, "SecretVendor", cef.Vendor)
	assert.Equal(t, "MyProduct", cef.Product)
	for _, o := range result.OutputMetadata() {
		_ = o.Output.Close()
	}
}

func TestLoad_WithSecretProvider_UnresolvedRefInFormatter_NoProvider(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	data := []byte(`
version: 1
app_name: test
host: test
outputs:
  audit_log:
    type: stdout
    formatter:
      type: cef
      vendor: ref+openbao://secret/data/fmt#vendor
      product: MyProduct
      version: "1.0"
`)
	_, err := outputconfig.Load(context.Background(), data, tax)
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrUnresolvedRef)
}

func TestLoad_WithSecretProvider_UnresolvedRefInRoute_NoProvider(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	// Route field values go through the tree walker — a ref+ string
	// in a route value with no provider should trigger the safety net.
	data := []byte(`
version: 1
app_name: test
host: test
outputs:
  audit_log:
    type: stdout
    route:
      include_event_types:
        - ref+openbao://secret/data/routing#event_type
`)
	_, err := outputconfig.Load(context.Background(), data, tax)
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrUnresolvedRef)
}

// ---------------------------------------------------------------------------
// Coverage: pre-call context cancellation in resolver
// ---------------------------------------------------------------------------

func TestLoad_WithSecretProvider_PreCallContextCancelled(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	mock := newMockProvider("mock", map[string]map[string]string{
		"secret/data/hmac": {"salt": "salt-value", "enabled": "true"},
	})
	// Cancel context before Load — the resolver should check ctx.Err()
	// before making any provider call.
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled
	data := yamlWithHMACRefs(
		"ref+mock://secret/data/hmac#salt",
		"v1",
		"HMAC-SHA-256",
		"ref+mock://secret/data/hmac#enabled",
	)
	_, err := outputconfig.Load(
		ctx, data, tax,
		outputconfig.WithSecretProvider(mock),
		outputconfig.WithSecretTimeout(time.Second),
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}

// ---------------------------------------------------------------------------
// Coverage: malformed ref+ in HMAC enabled field
// ---------------------------------------------------------------------------

func TestLoad_WithSecretProvider_MalformedRefInHMACEnabled(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	mock := newMockProvider("mock", nil)
	// ref+ with missing key fragment — ParseRef returns ErrMalformedRef.
	data := []byte(`
version: 1
app_name: test
host: test
outputs:
  audit_log:
    type: stdout
    hmac:
      enabled: "ref+mock://secret/data/hmac"
      salt:
        version: v1
        value: my-salt-value-that-is-32-bytes!
      algorithm: HMAC-SHA-256
`)
	_, err := outputconfig.Load(
		context.Background(), data, tax,
		outputconfig.WithSecretProvider(mock),
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrMalformedRef)
}

// ---------------------------------------------------------------------------
// Coverage: malformed ref+ in a type config string field
// ---------------------------------------------------------------------------

func TestLoad_WithSecretProvider_MalformedRefInTypeConfig(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	mock := newMockProvider("mock", nil)
	data := []byte(`
version: 1
app_name: test
host: test
outputs:
  audit_log:
    type: stdout
    stdout:
      format: "ref+mock://no-key-fragment"
`)
	_, err := outputconfig.Load(
		context.Background(), data, tax,
		outputconfig.WithSecretProvider(mock),
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrMalformedRef)
}

// ---------------------------------------------------------------------------
// Gap 1: Non-batch provider — fallback Resolve + refCache path
// ---------------------------------------------------------------------------

// nonBatchProvider implements secrets.Provider but NOT secrets.BatchProvider.
// This forces the resolver to use the single-key Resolve + refCache code path
// (lines ~135–151 in secrets.go).
type nonBatchProvider struct { //nolint:govet // readability over alignment
	scheme string
	data   map[string]map[string]string
	calls  atomic.Int64
}

func (p *nonBatchProvider) Scheme() string { return p.scheme }

func (p *nonBatchProvider) Resolve(_ context.Context, ref secrets.Ref) (string, error) {
	p.calls.Add(1)
	keys, ok := p.data[ref.Path]
	if !ok {
		return "", fmt.Errorf("%w: path %q not found", secrets.ErrSecretNotFound, ref.Path)
	}
	val, ok := keys[ref.Key]
	if !ok {
		return "", fmt.Errorf("%w: key %q not found", secrets.ErrSecretNotFound, ref.Key)
	}
	return val, nil
}

func (p *nonBatchProvider) Close() error { return nil }

// Compile-time check: nonBatchProvider must NOT implement BatchProvider.
// If this line ever fails to compile it means the test's premise is wrong.
var _ secrets.Provider = (*nonBatchProvider)(nil)

func TestLoad_NonBatchProvider_FallbackResolveUsed(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	// Two different keys from the same path — with a non-batch provider
	// the resolver calls Resolve() once per ref (no ResolvePath).
	p := &nonBatchProvider{
		scheme: "nbmock",
		data: map[string]map[string]string{
			"secret/data/hmac": {
				"salt":    "non-batch-salt-value-32bytes!!!",
				"version": "v1",
			},
		},
	}
	data := []byte(`
version: 1
app_name: test
host: test
outputs:
  audit_log:
    type: stdout
    hmac:
      enabled: true
      salt:
        version: ref+nbmock://secret/data/hmac#version
        value: ref+nbmock://secret/data/hmac#salt
      algorithm: HMAC-SHA-256
`)
	result, err := outputconfig.Load(
		context.Background(), data, tax,
		outputconfig.WithSecretProvider(p),
	)
	require.NoError(t, err)
	require.Len(t, result.OutputMetadata(), 1)
	hmac := result.OutputMetadata()[0].HMACConfig
	require.NotNil(t, hmac)
	assert.Equal(t, "v1", hmac.Salt.Version)
	assert.Equal(t, []byte("non-batch-salt-value-32bytes!!!"), hmac.Salt.Value)
	// Two distinct refs → two Resolve calls (no batch path).
	assert.Equal(t, int64(2), p.calls.Load())
	for _, o := range result.OutputMetadata() {
		_ = o.Output.Close()
	}
}

func TestLoad_NonBatchProvider_RefCacheDeduplicates(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	// Same ref used in two places — the refCache means only one Resolve call.
	p := &nonBatchProvider{
		scheme: "nbmock",
		data: map[string]map[string]string{
			"secret/data/config": {"name": "my-app"},
		},
	}
	data := []byte(`
version: 1
app_name: ref+nbmock://secret/data/config#name
host: ref+nbmock://secret/data/config#name
outputs:
  c:
    type: stdout
`)
	result, err := outputconfig.Load(
		context.Background(), data, tax,
		outputconfig.WithSecretProvider(p),
	)
	require.NoError(t, err)
	assert.Equal(t, "my-app", result.AppName())
	assert.Equal(t, "my-app", result.Host())
	// Same scheme+path+key → cached after first call.
	assert.Equal(t, int64(1), p.calls.Load())
	for _, o := range result.OutputMetadata() {
		_ = o.Output.Close()
	}
}

func TestLoad_NonBatchProvider_ProviderErrorPropagated(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	p := &nonBatchProvider{
		scheme: "nbmock",
		data:   nil, // every Resolve will fail with ErrSecretNotFound
	}
	data := []byte(`
version: 1
app_name: test
host: test
outputs:
  audit_log:
    type: stdout
    hmac:
      enabled: true
      salt:
        version: v1
        value: ref+nbmock://secret/data/hmac#salt
      algorithm: HMAC-SHA-256
`)
	_, err := outputconfig.Load(
		context.Background(), data, tax,
		outputconfig.WithSecretProvider(p),
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrSecretNotFound)
}

func TestLoad_NonBatchProvider_EmptyValueRejected(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	p := &nonBatchProvider{
		scheme: "nbmock",
		data: map[string]map[string]string{
			"secret/data/hmac": {
				"salt":    "", // empty — must be rejected
				"enabled": "true",
			},
		},
	}
	data := yamlWithHMACRefs(
		"ref+nbmock://secret/data/hmac#salt",
		"v1",
		"HMAC-SHA-256",
		"ref+nbmock://secret/data/hmac#enabled",
	)
	_, err := outputconfig.Load(
		context.Background(), data, tax,
		outputconfig.WithSecretProvider(p),
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrSecretResolveFailed)
	assert.Contains(t, err.Error(), "empty")
}

func TestLoad_NonBatchProvider_OversizedValueRejected(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	bigValue := strings.Repeat("x", outputconfig.MaxSecretValueSize+1)
	p := &nonBatchProvider{
		scheme: "nbmock",
		data: map[string]map[string]string{
			"secret/data/hmac": {
				"salt":    bigValue,
				"enabled": "true",
			},
		},
	}
	data := yamlWithHMACRefs(
		"ref+nbmock://secret/data/hmac#salt",
		"v1",
		"HMAC-SHA-256",
		"ref+nbmock://secret/data/hmac#enabled",
	)
	_, err := outputconfig.Load(
		context.Background(), data, tax,
		outputconfig.WithSecretProvider(p),
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrSecretResolveFailed)
	assert.Contains(t, err.Error(), "maximum size")
}

// ---------------------------------------------------------------------------
// Gap 7: Multiple providers — openbao and vault schemes coexist in one Load
// ---------------------------------------------------------------------------

func TestLoad_MultipleProviders_TwoSchemesResolveIndependently(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	// Two mock providers with different schemes — each resolves its own key.
	provA := newMockProvider("prova", map[string]map[string]string{
		"secret/data/hmac": {"salt": "salt-from-prov-a-32-bytes!!!!!!"},
	})
	provB := newMockProvider("provb", map[string]map[string]string{
		"secret/data/hmac": {"algorithm": "HMAC-SHA-256"},
	})
	data := []byte(`
version: 1
app_name: test
host: test
outputs:
  audit_log:
    type: stdout
    hmac:
      enabled: true
      salt:
        version: v1
        value: ref+prova://secret/data/hmac#salt
      algorithm: ref+provb://secret/data/hmac#algorithm
`)
	result, err := outputconfig.Load(
		context.Background(), data, tax,
		outputconfig.WithSecretProvider(provA),
		outputconfig.WithSecretProvider(provB),
	)
	require.NoError(t, err)
	require.Len(t, result.OutputMetadata(), 1)
	hmac := result.OutputMetadata()[0].HMACConfig
	require.NotNil(t, hmac)
	assert.Equal(t, []byte("salt-from-prov-a-32-bytes!!!!!!"), hmac.Salt.Value)
	assert.Equal(t, "HMAC-SHA-256", hmac.Algorithm)
	assert.Equal(t, int64(1), provA.calls.Load())
	assert.Equal(t, int64(1), provB.calls.Load())
	for _, o := range result.OutputMetadata() {
		_ = o.Output.Close()
	}
}

// ---------------------------------------------------------------------------
// Gap 10: Key not found in cached path (batch path-level cache miss on key)
// ---------------------------------------------------------------------------

func TestLoad_BatchProvider_CachedPathKeyNotFound_ReturnsNotFound(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	// Strategy: app_name is resolved at the top-level phase, before output
	// fields. Using the same path for app_name (key "name" exists) and the
	// HMAC salt (key "salt" does not exist) guarantees that the path cache
	// is populated from the app_name resolution. When the HMAC resolution
	// then hits the same path in the cache, it must return ErrSecretNotFound
	// for the missing "salt" key from the cache hit branch — without making
	// a second API call.
	mock := newMockProvider("mock", map[string]map[string]string{
		"secret/data/config": {
			"name": "my-app",
			// "salt" is intentionally absent
		},
	})
	data := []byte(`
version: 1
app_name: ref+mock://secret/data/config#name
host: test
outputs:
  audit_log:
    type: stdout
    hmac:
      enabled: true
      salt:
        version: v1
        value: ref+mock://secret/data/config#salt
      algorithm: HMAC-SHA-256
`)
	_, err := outputconfig.Load(
		context.Background(), data, tax,
		outputconfig.WithSecretProvider(mock),
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrSecretNotFound)
	assert.Contains(t, err.Error(), "cached path")
	// Only one provider call — the path cache is populated from app_name,
	// the HMAC salt lookup hits the cache and finds the key absent.
	assert.Equal(t, int64(1), mock.calls.Load())
}

// ---------------------------------------------------------------------------
// Cached-path edge cases
// ---------------------------------------------------------------------------

func TestLoad_BatchProvider_CachedPathEmptyValue(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	// Seed two refs to same path. First resolves "name" (populates cache).
	// Second hits cache for "empty" which has empty value.
	mock := newMockProvider("mock", map[string]map[string]string{
		"secret/data/config": {"name": "my-app", "empty": ""},
	})
	data := []byte(`
version: 1
app_name: ref+mock://secret/data/config#name
host: ref+mock://secret/data/config#empty
outputs:
  c:
    type: stdout
`)
	_, err := outputconfig.Load(
		context.Background(), data, tax,
		outputconfig.WithSecretProvider(mock),
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrSecretResolveFailed)
	assert.Contains(t, err.Error(), "empty")
}

func TestLoad_BatchProvider_EmptyMapFromResolvePath(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	// Provider returns an empty map — no keys at all.
	mock := newMockProvider("mock", map[string]map[string]string{
		"secret/data/empty": {},
	})
	data := []byte(`
version: 1
app_name: ref+mock://secret/data/empty#name
host: test
outputs:
  c:
    type: stdout
`)
	_, err := outputconfig.Load(
		context.Background(), data, tax,
		outputconfig.WithSecretProvider(mock),
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrSecretNotFound)
}

func TestLoad_WithSecretProvider_SameInstanceTwice_Error(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	mock := newMockProvider("mock", nil)
	data := []byte("version: 1\napp_name: test\nhost: test\noutputs:\n  c:\n    type: stdout\n")
	_, err := outputconfig.Load(
		context.Background(), data, tax,
		outputconfig.WithSecretProvider(mock),
		outputconfig.WithSecretProvider(mock), // same instance
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "duplicate")
}

func TestLoad_WithSecretTimeout_ZeroIgnored(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	data := []byte("version: 1\napp_name: test\nhost: test\noutputs:\n  c:\n    type: stdout\n")
	// Zero timeout should be silently ignored (keeps 10s default).
	result, err := outputconfig.Load(
		context.Background(), data, tax,
		outputconfig.WithSecretTimeout(0),
	)
	require.NoError(t, err)
	for _, o := range result.OutputMetadata() {
		_ = o.Output.Close()
	}
}

func TestLoad_WithSecretTimeout_NegativeIgnored(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	data := []byte("version: 1\napp_name: test\nhost: test\noutputs:\n  c:\n    type: stdout\n")
	result, err := outputconfig.Load(
		context.Background(), data, tax,
		outputconfig.WithSecretTimeout(-5*time.Second),
	)
	require.NoError(t, err)
	for _, o := range result.OutputMetadata() {
		_ = o.Output.Close()
	}
}

// ---------------------------------------------------------------------------
// toBool secret value leak prevention
// ---------------------------------------------------------------------------

func TestLoad_HMACEnabled_NonBooleanRef_DoesNotLeakSecret(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	secretPassword := "hunter2-super-secret"
	mock := newMockProvider("mock", map[string]map[string]string{
		"secret/data/creds": {
			"password": secretPassword,
		},
	})
	// enabled points to a non-boolean secret — the error must NOT
	// contain the resolved secret value.
	data := []byte(`
version: 1
app_name: test
host: test
outputs:
  audit_log:
    type: stdout
    hmac:
      enabled: ref+mock://secret/data/creds#password
      salt:
        version: v1
        value: some-salt-value-that-is-32-bytes
      algorithm: HMAC-SHA-256
`)
	_, err := outputconfig.Load(
		context.Background(), data, tax,
		outputconfig.WithSecretProvider(mock),
	)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), secretPassword,
		"resolved secret value must not leak in error message")
	// text-only: hmac.go:163 returns raw fmt.Errorf without a sentinel wrap.
	assert.Contains(t, err.Error(), "not a valid boolean")
}
