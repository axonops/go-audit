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

package vault_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/audit"
	"github.com/axonops/audit/secrets"
	"github.com/axonops/audit/secrets/vault"
)

// Compile-time check.
var _ secrets.Provider = (*vault.Provider)(nil)

func newTestServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

func kvV2Handler(data map[string]any, token string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != token {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		resp := map[string]any{
			"data": map[string]any{"data": data},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
}

func testProvider(t *testing.T, srv *httptest.Server) *vault.Provider {
	t.Helper()
	p, err := vault.NewWithHTTPClient(&vault.Config{
		Address:            srv.URL,
		Token:              "test-token",
		AllowPrivateRanges: true,
	}, srv.Client())
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })
	return p
}

// ---------------------------------------------------------------------------
// New — validation
// ---------------------------------------------------------------------------

func TestNew_RequiresHTTPS(t *testing.T) {
	t.Parallel()
	_, err := vault.New(&vault.Config{Address: "http://vault.example.com", Token: "t"})
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrConfigInvalid)
	assert.Contains(t, err.Error(), "https")
	assert.Contains(t, err.Error(), "AllowInsecureHTTP")
}

func TestNew_AllowInsecureHTTP(t *testing.T) {
	t.Parallel()
	p, err := vault.New(&vault.Config{
		Address:            "http://vault.example.com",
		Token:              "t",
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
	})
	require.NoError(t, err)
	defer func() { _ = p.Close() }()
	assert.Equal(t, "vault", p.Scheme())
}

func TestNewWithHTTPClient_AllowInsecureHTTP(t *testing.T) {
	t.Parallel()
	p, err := vault.NewWithHTTPClient(&vault.Config{
		Address:           "http://vault.example.com",
		Token:             "t",
		AllowInsecureHTTP: true,
	}, http.DefaultClient)
	require.NoError(t, err)
	defer func() { _ = p.Close() }()
	assert.Equal(t, "vault", p.Scheme())
}

func TestNew_RequiresAddress(t *testing.T) {
	t.Parallel()
	_, err := vault.New(&vault.Config{Token: "t"})
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrConfigInvalid)
	assert.Contains(t, err.Error(), "address")
}

func TestNew_RequiresToken(t *testing.T) {
	t.Parallel()
	_, err := vault.New(&vault.Config{Address: "https://vault.example.com"})
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrConfigInvalid)
	assert.Contains(t, err.Error(), "token")
}

// TestVaultNew_NeverLeaksInputInErrorMessage verifies #651: error
// messages from vault.New must not echo caller-supplied substrings.
// The address parser previously wrapped url.Error directly (which
// embeds the input URL) and echoed `u.Scheme` via `got %q`; both have
// been redacted. Sentinel injection across every config-error path
// catches a regression on either of those leaks.
func TestVaultNew_NeverLeaksInputInErrorMessage(t *testing.T) {
	t.Parallel()
	const (
		addrSentinel   = "LEAKADDR"
		schemeSentinel = "leaksentinel"
		tokenSentinel  = "LEAKTOKEN"
	)
	cases := []struct {
		cfg  *vault.Config
		name string
	}{
		{&vault.Config{
			Address: "://malformed-" + addrSentinel + "%zz",
			Token:   tokenSentinel,
		}, "unparseable_address"},
		{&vault.Config{
			Address: schemeSentinel + "://" + addrSentinel + ".invalid",
			Token:   tokenSentinel,
		}, "non_https_address_default"},
		{&vault.Config{
			Address: "https://",
			Token:   tokenSentinel,
		}, "empty_host"},
		{&vault.Config{
			Address: "https://" + tokenSentinel + "@host." + addrSentinel + ".invalid",
			Token:   tokenSentinel,
		}, "embedded_credentials"},
	}
	for _, tc := range cases {
		t.Run("New_"+tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := vault.New(tc.cfg)
			require.Error(t, err)
			require.ErrorIs(t, err, audit.ErrConfigInvalid)
			msg := err.Error()
			assert.NotContains(t, msg, addrSentinel,
				"address sentinel must not appear in the error: %s", msg)
			assert.NotContains(t, msg, schemeSentinel,
				"scheme sentinel must not appear in the error: %s", msg)
			assert.NotContains(t, msg, tokenSentinel,
				"token sentinel must not appear in the error: %s", msg)
		})
		// NewWithHTTPClient shares the same validation pipeline as
		// New; assert the same redaction guarantee on its surface.
		t.Run("NewWithHTTPClient_"+tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := vault.NewWithHTTPClient(tc.cfg, http.DefaultClient)
			require.Error(t, err)
			require.ErrorIs(t, err, audit.ErrConfigInvalid)
			msg := err.Error()
			assert.NotContains(t, msg, addrSentinel,
				"address sentinel must not appear in the error: %s", msg)
			assert.NotContains(t, msg, schemeSentinel,
				"scheme sentinel must not appear in the error: %s", msg)
			assert.NotContains(t, msg, tokenSentinel,
				"token sentinel must not appear in the error: %s", msg)
		})
	}
}

func TestNew_RejectsEmbeddedCredentials(t *testing.T) {
	t.Parallel()
	_, err := vault.New(&vault.Config{Address: "https://user:pass@vault.example.com", Token: "t"})
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrConfigInvalid)
	assert.Contains(t, err.Error(), "credentials")
}

func TestNew_RejectsEmptyHost(t *testing.T) {
	t.Parallel()
	_, err := vault.New(&vault.Config{Address: "https://", Token: "t"})
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrConfigInvalid)
	assert.Contains(t, err.Error(), "empty host")
}

func TestNew_RejectsMismatchedTLSCertKey(t *testing.T) {
	t.Parallel()
	_, err := vault.New(&vault.Config{Address: "https://vault.example.com", Token: "t", TLSCert: "/some/cert.pem"})
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrConfigInvalid)
	assert.Contains(t, err.Error(), "both be set")
}

func TestNew_LazyConnection(t *testing.T) {
	t.Parallel()
	p, err := vault.New(&vault.Config{Address: "https://nonexistent.example.com:8200", Token: "t"})
	require.NoError(t, err)
	_ = p.Close()
}

func TestScheme(t *testing.T) {
	t.Parallel()
	p, err := vault.New(&vault.Config{Address: "https://vault.example.com", Token: "t"})
	require.NoError(t, err)
	assert.Equal(t, "vault", p.Scheme())
	_ = p.Close()
}

// ---------------------------------------------------------------------------
// Resolve
// ---------------------------------------------------------------------------

func TestResolve_Success(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t, kvV2Handler(map[string]any{"salt": "my-secret-salt"}, "test-token"))
	p := testProvider(t, srv)
	val, err := p.Resolve(context.Background(), secrets.Ref{Scheme: "vault", Path: "secret/data/hmac", Key: "salt"})
	require.NoError(t, err)
	assert.Equal(t, "my-secret-salt", val)
}

func TestResolve_NotFound(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	p := testProvider(t, srv)
	_, err := p.Resolve(context.Background(), secrets.Ref{Scheme: "vault", Path: "secret/data/missing", Key: "key"})
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrSecretNotFound)
}

func TestResolve_AuthFailure(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t, kvV2Handler(map[string]any{"key": "value"}, "correct-token"))
	p, err := vault.NewWithHTTPClient(&vault.Config{
		Address: srv.URL, Token: "wrong-token", AllowPrivateRanges: true,
	}, srv.Client())
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })

	_, err = p.Resolve(context.Background(), secrets.Ref{Scheme: "vault", Path: "secret/data/test", Key: "key"})
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrSecretResolveFailed)
	assert.Contains(t, err.Error(), "403")
}

func TestResolve_KeyNotInSecret(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t, kvV2Handler(map[string]any{"existing": "value"}, "test-token"))
	p := testProvider(t, srv)
	_, err := p.Resolve(context.Background(), secrets.Ref{Scheme: "vault", Path: "secret/data/test", Key: "nonexistent"})
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrSecretNotFound)
	assert.NotContains(t, err.Error(), "nonexistent")
}

func TestResolve_InvalidRef(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t, kvV2Handler(map[string]any{"key": "value"}, "test-token"))
	p := testProvider(t, srv)
	_, err := p.Resolve(context.Background(), secrets.Ref{Scheme: "vault", Path: "", Key: "key"})
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrMalformedRef)
}

func TestResolve_ContextCancellation(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	p := testProvider(t, srv)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := p.Resolve(ctx, secrets.Ref{Scheme: "vault", Path: "secret/data/test", Key: "key"})
	require.Error(t, err)
}

func TestResolve_NamespaceHeader(t *testing.T) {
	t.Parallel()
	var receivedNS string
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedNS = r.Header.Get("X-Vault-Namespace")
		resp := map[string]any{"data": map[string]any{"data": map[string]any{"key": "value"}}}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	p, err := vault.NewWithHTTPClient(&vault.Config{
		Address: srv.URL, Token: "test-token", Namespace: "team-b", AllowPrivateRanges: true,
	}, srv.Client())
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })

	_, err = p.Resolve(context.Background(), secrets.Ref{Scheme: "vault", Path: "secret/data/test", Key: "key"})
	require.NoError(t, err)
	assert.Equal(t, "team-b", receivedNS)
}

// ---------------------------------------------------------------------------
// String / GoString / Format — token redaction
// ---------------------------------------------------------------------------

func TestString_RedactsToken(t *testing.T) {
	t.Parallel()
	p, err := vault.New(&vault.Config{Address: "https://vault.example.com:8200", Token: "hvs.super-secret"})
	require.NoError(t, err)
	defer func() { _ = p.Close() }()

	s := p.String()
	assert.Contains(t, s, "vault.example.com:8200")
	assert.Contains(t, s, "[REDACTED]")
	assert.NotContains(t, s, "hvs.super-secret")

	assert.NotContains(t, p.GoString(), "hvs.super-secret")
	assert.NotContains(t, fmt.Sprintf("%+v", p), "hvs.super-secret")
}

func TestClose_ZerosToken_Idempotent(t *testing.T) {
	t.Parallel()
	p, err := vault.New(&vault.Config{Address: "https://vault.example.com", Token: "secret-token"})
	require.NoError(t, err)
	// Close should zero token and be idempotent.
	require.NoError(t, p.Close())
	require.NoError(t, p.Close())
}

// TestVaultClose_ZerosTokenSlice is the named contract test from
// #479 Testing Requirements. Asserts every byte of the internal
// token slice is 0x00 after Close() returns, proving the best-effort
// byte-slice zeroing guarantee documented in SECURITY.md §Secrets
// and Memory Retention. The separate Go string copy created at
// fetchPath (string(p.token) → HTTP header) cannot be zeroed and is
// not covered by this test — see TestVaultResolve_ClearsHeaderAfterDo
// for the request-header narrowing coverage.
func TestVaultClose_ZerosTokenSlice(t *testing.T) {
	t.Parallel()
	const secretToken = "super-secret-vault-token-v1"
	p, err := vault.New(&vault.Config{
		Address: "https://vault.example.com",
		Token:   secretToken,
	})
	require.NoError(t, err)

	// Sanity: before Close the token slice contains the original
	// bytes (rules out "New didn't store it" false positive).
	before := vault.TokenBytesForTest(p)
	require.Equal(t, []byte(secretToken), before,
		"token bytes must match Config.Token before Close")

	require.NoError(t, p.Close())

	after := vault.TokenBytesForTest(p)
	require.Len(t, after, len(secretToken),
		"Close must not resize the token slice — it zeroes in place")
	for i, b := range after {
		assert.Equal(t, byte(0), b,
			"token byte %d must be zero after Close, got %#x", i, b)
	}
}

// TestVaultResolve_ClearsHeaderAfterDo asserts the request's
// X-Vault-Token and X-Vault-Namespace header entries are deleted
// after client.Do returns. Best-effort narrowing of the retention
// window — the string values already exist in memory and cannot be
// zeroed, but dropping the map entry removes one live reference
// held by the request object (#479).
//
// Uses a capturing RoundTripper: the request is snapshotted during
// RoundTrip (headers still present — they must reach the transport)
// and inspected after Resolve returns (headers must be cleared).
func TestVaultResolve_ClearsHeaderAfterDo(t *testing.T) {
	t.Parallel()
	const testToken = "bearer-in-transit-token"
	const testNamespace = "tenants/abc"

	// Inner handler verifies the token reached the server side —
	// the clear happens AFTER Do returns, so the header must still
	// be present during transport.
	backend := kvV2Handler(map[string]any{"k": "v"}, testToken)

	var captured *http.Request
	capturingRT := &captureRoundTripper{
		inner: http.DefaultTransport,
		onRoundTrip: func(req *http.Request) {
			// Snapshot at transport send: header MUST contain the token.
			assert.Equal(t, testToken, req.Header.Get("X-Vault-Token"),
				"token must be present when the request hits the transport")
			assert.Equal(t, testNamespace, req.Header.Get("X-Vault-Namespace"))
			captured = req
		},
	}

	srv := newTestServer(t, backend)
	capturingRT.inner = srv.Client().Transport // keep TLS config

	p, err := vault.NewWithHTTPClient(
		&vault.Config{
			Address:            srv.URL,
			Token:              testToken,
			Namespace:          testNamespace,
			AllowPrivateRanges: true,
		},
		&http.Client{Transport: capturingRT},
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })

	_, err = p.Resolve(context.Background(),
		secrets.Ref{Scheme: "vault", Path: "secret/data/x", Key: "k"})
	require.NoError(t, err)

	// Post-Do: the map entries must have been deleted by the defer.
	require.NotNil(t, captured, "RoundTripper must have captured the request")
	assert.Empty(t, captured.Header.Get("X-Vault-Token"),
		"X-Vault-Token must be cleared from the request header after Do (#479)")
	assert.Empty(t, captured.Header.Get("X-Vault-Namespace"),
		"X-Vault-Namespace must be cleared from the request header after Do (#479)")
}

// captureRoundTripper wraps an inner http.RoundTripper and invokes
// onRoundTrip just before delegating. Used by
// TestVaultResolve_ClearsHeaderAfterDo to observe the request state
// at the transport boundary.
type captureRoundTripper struct {
	inner       http.RoundTripper
	onRoundTrip func(req *http.Request)
}

func (c *captureRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if c.onRoundTrip != nil {
		c.onRoundTrip(req)
	}
	return c.inner.RoundTrip(req)
}

// TestVaultResolve_ClearsHeaderAfterDoError proves the deferred
// header-clear runs on the error path too — not just on the
// Do-success path covered by
// [TestVaultResolve_ClearsHeaderAfterDo]. A RoundTripper that
// captures the request then returns an error simulates any
// transport-level failure. The defer must still delete the
// token/namespace entries (#479).
func TestVaultResolve_ClearsHeaderAfterDoError(t *testing.T) {
	t.Parallel()
	const testToken = "bearer-on-error-token"
	const testNamespace = "tenants/err"

	var captured *http.Request
	errRT := &captureRoundTripper{
		inner: errRoundTripper{},
		onRoundTrip: func(req *http.Request) {
			captured = req
		},
	}

	p, err := vault.NewWithHTTPClient(
		&vault.Config{
			Address:            "https://vault.example.com",
			Token:              testToken,
			Namespace:          testNamespace,
			AllowPrivateRanges: true,
		},
		&http.Client{Transport: errRT},
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })

	// Resolve must fail because the inner RoundTripper errors,
	// but the deferred header-clear must STILL run.
	_, err = p.Resolve(context.Background(),
		secrets.Ref{Scheme: "vault", Path: "secret/data/x", Key: "k"})
	require.Error(t, err,
		"Resolve must return an error when the transport errors")

	require.NotNil(t, captured, "RoundTripper must have captured the request")
	assert.Empty(t, captured.Header.Get("X-Vault-Token"),
		"X-Vault-Token must be cleared even when Do returns an error (#479)")
	assert.Empty(t, captured.Header.Get("X-Vault-Namespace"),
		"X-Vault-Namespace must be cleared even when Do returns an error (#479)")
}

// errRoundTripper always returns a network-ish error. Paired with
// captureRoundTripper to verify post-Do cleanup on error paths.
type errRoundTripper struct{}

func (errRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("simulated transport error")
}

func TestResolve_DifferentKeys(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t, kvV2Handler(map[string]any{
		"salt": "salt-value", "version": "v1",
	}, "test-token"))
	p := testProvider(t, srv)

	v1, err := p.Resolve(context.Background(), secrets.Ref{Scheme: "vault", Path: "secret/data/hmac", Key: "salt"})
	require.NoError(t, err)
	assert.Equal(t, "salt-value", v1)

	v2, err := p.Resolve(context.Background(), secrets.Ref{Scheme: "vault", Path: "secret/data/hmac", Key: "version"})
	require.NoError(t, err)
	assert.Equal(t, "v1", v2)
}

func TestResolve_NonStringValue(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t, kvV2Handler(map[string]any{"count": 42}, "test-token"))
	p := testProvider(t, srv)
	_, err := p.Resolve(context.Background(), secrets.Ref{Scheme: "vault", Path: "secret/data/test", Key: "count"})
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrSecretResolveFailed)
	assert.Contains(t, err.Error(), "non-string")
	assert.NotContains(t, err.Error(), "count")
}

// ---------------------------------------------------------------------------
// ResolvePath — gap 6: direct unit tests for the BatchProvider method
// ---------------------------------------------------------------------------

func TestResolvePath_Success(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t, kvV2Handler(map[string]any{
		"salt":    "my-secret-salt",
		"version": "v1",
	}, "test-token"))
	p := testProvider(t, srv)

	got, err := p.ResolvePath(context.Background(), "secret/data/hmac")
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"salt": "my-secret-salt", "version": "v1"}, got)
}

func TestResolvePath_NotFound(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	p := testProvider(t, srv)

	_, err := p.ResolvePath(context.Background(), "secret/data/missing")
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrSecretNotFound)
}

func TestResolvePath_AuthFailure(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t, kvV2Handler(map[string]any{"key": "value"}, "correct-token"))
	p, err := vault.NewWithHTTPClient(&vault.Config{
		Address: srv.URL, Token: "wrong-token", AllowPrivateRanges: true,
	}, srv.Client())
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })

	_, err = p.ResolvePath(context.Background(), "secret/data/test")
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrSecretResolveFailed)
	assert.Contains(t, err.Error(), "403")
}

func TestResolvePath_ReturnsAllKeys(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t, kvV2Handler(map[string]any{
		"alpha": "a",
		"beta":  "b",
		"gamma": "c",
	}, "test-token"))
	p := testProvider(t, srv)

	got, err := p.ResolvePath(context.Background(), "secret/data/multi")
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"alpha": "a", "beta": "b", "gamma": "c"}, got)
}

// ---------------------------------------------------------------------------
// Gap 2: url.Error unwrapping — secret path must not appear in error message
// ---------------------------------------------------------------------------

func TestFetchPath_URLErrorUnwrapped_PathNotLeaked(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		conn, _, _ := hj.Hijack()
		_ = conn.Close()
	}))
	p := testProvider(t, srv)

	const secretPath = "very/secret/path/that/must/not/leak"
	_, err := p.Resolve(context.Background(), secrets.Ref{
		Scheme: "vault",
		Path:   secretPath,
		Key:    "key",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrSecretResolveFailed)
	assert.NotContains(t, err.Error(), secretPath,
		"vault path must not leak through url.Error into error message")
	assert.NotContains(t, err.Error(), srv.URL+"/v1/"+secretPath,
		"full request URL must not leak into error message")
}

// ---------------------------------------------------------------------------
// Gap 3: SSRF protection — metadata endpoint and loopback without flag
// ---------------------------------------------------------------------------

func TestNew_SSRFDialControl_BlocksMetadataEndpoint(t *testing.T) {
	t.Parallel()
	p, err := vault.New(&vault.Config{
		Address: "https://169.254.169.254",
		Token:   "test-token",
		// AllowPrivateRanges: false (default)
	})
	require.NoError(t, err, "New() must succeed — lazy connection")
	t.Cleanup(func() { _ = p.Close() })

	_, err = p.Resolve(context.Background(), secrets.Ref{
		Scheme: "vault",
		Path:   "latest/meta-data/iam/security-credentials/role",
		Key:    "SecretAccessKey",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrSecretResolveFailed)
	assert.Contains(t, err.Error(), "blocked")
}

func TestNew_SSRFDialControl_BlocksLoopbackWithoutFlag(t *testing.T) {
	t.Parallel()
	srv := httptest.NewTLSServer(kvV2Handler(map[string]any{"key": "value"}, "test-token"))
	t.Cleanup(srv.Close)

	p, err := vault.New(&vault.Config{
		Address: srv.URL,
		Token:   "test-token",
		// AllowPrivateRanges: false
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })

	_, err = p.Resolve(context.Background(), secrets.Ref{
		Scheme: "vault",
		Path:   "secret/data/test",
		Key:    "key",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrSecretResolveFailed)
	assert.Contains(t, err.Error(), "blocked")
}

// ---------------------------------------------------------------------------
// Gap 4: Unexpected HTTP status codes (500, 429)
// ---------------------------------------------------------------------------

func TestResolve_InternalServerError_WrapsResolveFailed(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	p := testProvider(t, srv)

	_, err := p.Resolve(context.Background(), secrets.Ref{Scheme: "vault", Path: "secret/data/test", Key: "key"})
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrSecretResolveFailed)
	assert.Contains(t, err.Error(), "500")
}

func TestResolve_TooManyRequests_WrapsResolveFailed(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	p := testProvider(t, srv)

	_, err := p.Resolve(context.Background(), secrets.Ref{Scheme: "vault", Path: "secret/data/test", Key: "key"})
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrSecretResolveFailed)
	assert.Contains(t, err.Error(), "429")
}

func TestResolve_ServiceUnavailable_WrapsResolveFailed(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	p := testProvider(t, srv)

	_, err := p.Resolve(context.Background(), secrets.Ref{Scheme: "vault", Path: "secret/data/test", Key: "key"})
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrSecretResolveFailed)
	assert.Contains(t, err.Error(), "503")
}

// ---------------------------------------------------------------------------
// Gap 5: Nil/empty data field — soft-deleted KV v2 secrets
// ---------------------------------------------------------------------------

func TestResolve_NullDataField_ReturnsNotFound(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "test-token" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		resp := `{"data": {"data": null}}`
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, resp)
	}))
	p := testProvider(t, srv)

	_, err := p.Resolve(context.Background(), secrets.Ref{Scheme: "vault", Path: "secret/data/deleted", Key: "key"})
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrSecretNotFound)
	assert.Contains(t, err.Error(), "no data")
}

func TestResolve_NullOuterData_ReturnsNotFound(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "test-token" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		resp := `{"data": null}`
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, resp)
	}))
	p := testProvider(t, srv)

	_, err := p.Resolve(context.Background(), secrets.Ref{Scheme: "vault", Path: "secret/data/deleted", Key: "key"})
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrSecretNotFound)
	assert.Contains(t, err.Error(), "no data")
}

// ---------------------------------------------------------------------------
// Gap 8: Malformed JSON response
// ---------------------------------------------------------------------------

func TestResolve_MalformedJSON_WrapsResolveFailed(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "test-token" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, `{"data": {"data": {not valid json`)
	}))
	p := testProvider(t, srv)

	_, err := p.Resolve(context.Background(), secrets.Ref{Scheme: "vault", Path: "secret/data/test", Key: "key"})
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrSecretResolveFailed)
	assert.Contains(t, err.Error(), "parse response")
}

func TestResolve_EmptyBody_WrapsResolveFailed(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "test-token" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	p := testProvider(t, srv)

	_, err := p.Resolve(context.Background(), secrets.Ref{Scheme: "vault", Path: "secret/data/test", Key: "key"})
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrSecretResolveFailed)
}

// ---------------------------------------------------------------------------
// Gap 9: Oversized response body
// ---------------------------------------------------------------------------

func TestResolve_OversizedResponse_WrapsResolveFailed(t *testing.T) {
	t.Parallel()
	const maxResponseSize = 1 << 20 // mirrors the package constant
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "test-token" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
		payload := make([]byte, maxResponseSize+2)
		for i := range payload {
			payload[i] = 'x'
		}
		_, _ = w.Write(payload)
	}))
	p := testProvider(t, srv)

	_, err := p.Resolve(context.Background(), secrets.Ref{Scheme: "vault", Path: "secret/data/test", Key: "key"})
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrSecretResolveFailed)
	assert.Contains(t, err.Error(), "exceeds")
}

// ---------------------------------------------------------------------------
// buildTLSConfig tests (via New with TLS options)
// ---------------------------------------------------------------------------

func TestNew_CustomCA_ValidPEM(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	generateTestCA(t, caPath)

	p, err := vault.New(&vault.Config{
		Address:            "https://vault.example.com",
		Token:              "token",
		TLSCA:              caPath,
		AllowPrivateRanges: true,
	})
	require.NoError(t, err)
	_ = p.Close()
}

func TestNew_CustomCA_FileNotFound(t *testing.T) {
	t.Parallel()
	_, err := vault.New(&vault.Config{
		Address: "https://vault.example.com",
		Token:   "token",
		TLSCA:   "/nonexistent/ca.pem",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrConfigInvalid)
	assert.Contains(t, err.Error(), "ca certificate")
}

func TestNew_CustomCA_InvalidPEM(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	caPath := filepath.Join(dir, "bad.pem")
	require.NoError(t, os.WriteFile(caPath, []byte("not a PEM"), 0o600))

	_, err := vault.New(&vault.Config{
		Address: "https://vault.example.com",
		Token:   "token",
		TLSCA:   caPath,
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrConfigInvalid)
	assert.Contains(t, err.Error(), "parse ca")
}

func TestNew_mTLS_ValidCertAndKey(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	certPath := filepath.Join(dir, "client.pem")
	keyPath := filepath.Join(dir, "client-key.pem")
	generateTestCertAndKey(t, certPath, keyPath)

	p, err := vault.New(&vault.Config{
		Address:            "https://vault.example.com",
		Token:              "token",
		TLSCert:            certPath,
		TLSKey:             keyPath,
		AllowPrivateRanges: true,
	})
	require.NoError(t, err)
	_ = p.Close()
}

func TestNew_mTLS_InvalidCertPath(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "client-key.pem")
	generateTestCertAndKey(t, filepath.Join(dir, "unused.pem"), keyPath)

	_, err := vault.New(&vault.Config{
		Address: "https://vault.example.com",
		Token:   "token",
		TLSCert: "/nonexistent/client.pem",
		TLSKey:  keyPath,
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrConfigInvalid)
	assert.Contains(t, err.Error(), "client certificate")
}

func TestNewWithHTTPClient_NilConfig(t *testing.T) {
	t.Parallel()
	_, err := vault.NewWithHTTPClient(nil, http.DefaultClient)
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrConfigInvalid)
	assert.Contains(t, err.Error(), "nil")
}

func TestNewWithHTTPClient_NilClient(t *testing.T) {
	t.Parallel()
	_, err := vault.NewWithHTTPClient(&vault.Config{
		Address: "https://vault.example.com",
		Token:   "token",
	}, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrConfigInvalid)
	assert.Contains(t, err.Error(), "nil")
}

func TestNewWithHTTPClient_RequiresHTTPS(t *testing.T) {
	t.Parallel()
	_, err := vault.NewWithHTTPClient(&vault.Config{
		Address: "http://vault.example.com",
		Token:   "token",
	}, http.DefaultClient)
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrConfigInvalid)
	assert.Contains(t, err.Error(), "https")
	assert.Contains(t, err.Error(), "AllowInsecureHTTP")
}

func TestResolve_RedirectBlocked(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, nil, "https://evil.example.com", http.StatusMovedPermanently)
	}))
	p := testProvider(t, srv)
	_, err := p.Resolve(context.Background(), secrets.Ref{
		Scheme: "vault", Path: "secret/data/test", Key: "key",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrSecretResolveFailed)
}

func TestResolvePath_TraversalRejected(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t, kvV2Handler(map[string]any{"key": "val"}, "test-token"))
	p := testProvider(t, srv)
	_, err := p.ResolvePath(context.Background(), "secret/../etc/passwd")
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrMalformedRef)
}

// ---------------------------------------------------------------------------
// TLS test helpers
// ---------------------------------------------------------------------------

func generateTestCA(t *testing.T, path string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	f, err := os.Create(path)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	require.NoError(t, pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func generateTestCertAndKey(t *testing.T, certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test Client"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cf, err := os.Create(certPath)
	require.NoError(t, err)
	defer func() { _ = cf.Close() }()
	require.NoError(t, pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: der}))

	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	kf, err := os.Create(keyPath)
	require.NoError(t, err)
	defer func() { _ = kf.Close() }()
	require.NoError(t, pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
}

// TestConfig_String_RedactsCredentials verifies vault.Config String,
// GoString, and Format never leak the Token, and strip the Address to
// scheme+host. Closes #475 vault coverage.
func TestConfig_String_RedactsCredentials(t *testing.T) {
	t.Parallel()
	cfg := vault.Config{
		Address:   "https://vault.example.com/v1/secret/data/path?query=LEAK-QUERY",
		Token:     "LEAK-TOKEN-VALUE",
		Namespace: "my-ns",
	}
	// Each formatter exercises a different fmt code path:
	// %v hits String via Format, %+v same, %#v via GoString.
	outs := []string{
		cfg.String(),
		cfg.GoString(),
	}
	// Use format strings via a local rather than hardcoded verbs so
	// gocritic doesn't flag redundantSprint when the literal equals cfg.String().
	for _, verb := range []string{"%v", "%+v", "%#v"} {
		outs = append(outs, fmt.Sprintf(verb, cfg))
	}
	for _, out := range outs {
		assert.NotContains(t, out, "LEAK-TOKEN-VALUE",
			"Token must never appear in any format verb")
		assert.NotContains(t, out, "LEAK-QUERY",
			"URL query must be stripped")
		assert.NotContains(t, out, "/v1/secret",
			"URL path must be stripped")
		assert.NotContains(t, out, "my-ns",
			"Namespace value must not leak (only its presence)")
		assert.Contains(t, out, "https://vault.example.com",
			"scheme+host must appear")
		assert.Contains(t, out, "[REDACTED]",
			"token presence must be indicated")
	}
}

// TestConfig_String_TokenUnsetShowsUnsetMarker verifies that an empty
// Token prints "unset" rather than "[REDACTED]".
func TestConfig_String_TokenUnsetShowsUnsetMarker(t *testing.T) {
	t.Parallel()
	cfg := vault.Config{
		Address: "https://vault.example.com",
	}
	out := cfg.String()
	assert.Contains(t, out, "token=unset")
	assert.NotContains(t, out, "[REDACTED]")
}

// TestVaultClose_IsIdempotent covers #593 B-33: repeated Close()
// calls are safe and return nil. Token zeroing on an already-zero
// slice is a no-op, and http.Client.CloseIdleConnections is safe to
// invoke multiple times per the stdlib contract.
func TestVaultClose_IsIdempotent(t *testing.T) {
	t.Parallel()
	p, err := vault.New(&vault.Config{
		Address: "https://vault.example.com:8200",
		Token:   "test-token",
	})
	require.NoError(t, err)

	require.NoError(t, p.Close(), "first Close must succeed")
	require.NoError(t, p.Close(), "second Close must be idempotent")
	require.NoError(t, p.Close(), "third Close must be idempotent")
}

// TestResolve_EmptyDataSection proves that a Vault response with
// data.data == null surfaces as ErrSecretNotFound rather than a
// generic resolve failure or a panic on nil dereference. The
// kvV2 wire format uses a nested "data" envelope; an absent
// inner data field is the documented "no secret at this path"
// response when the engine returns 200 OK.
// (#565 G7).
func TestResolve_EmptyDataSection(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// data.data == null — the secret path exists but holds no
		// values. Vault returns 200 OK with this shape rather than
		// 404 in some KV v2 configurations.
		_, _ = w.Write([]byte(`{"data":{"data":null}}`))
	}))
	p := testProvider(t, srv)

	_, err := p.Resolve(context.Background(),
		secrets.Ref{Scheme: "vault", Path: "secret/data/empty", Key: "key"})
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrSecretNotFound,
		"empty data section must surface as ErrSecretNotFound, not a generic failure")
}
