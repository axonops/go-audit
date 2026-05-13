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
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/axonops/audit/loki"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

// TestLokiStartupConnectivityCheck verifies that loki.New returns
// an error when the configured URL is unreachable and
// DisableStartupVerification is false (the default — verification
// is ON).
func TestLokiStartupConnectivityCheck(t *testing.T) {
	defer goleak.VerifyNone(t)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	require.NoError(t, l.Close())

	_, err = loki.New(&loki.Config{
		URL:                "http://" + addr + "/loki/api/v1/push",
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
		BatchSize:          1,
		FlushInterval:      200 * time.Millisecond,
		Timeout:            1 * time.Second,
		BufferSize:         1000,
		Gzip:               true,
	}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "startup verification failed",
		"probe failure must surface as 'startup verification failed' in the error message")
	assert.Contains(t, err.Error(), "verify_on_startup: false",
		"probe error must include the YAML opt-out hint")
}

// TestLokiLazyConnect verifies that DisableStartupVerification:
// true allows loki.New to succeed even when the URL is
// unreachable.
func TestLokiLazyConnect(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	require.NoError(t, l.Close())

	out, err := loki.New(&loki.Config{
		URL:                        "http://" + addr + "/loki/api/v1/push",
		AllowInsecureHTTP:          true,
		AllowPrivateRanges:         true,
		BatchSize:                  1,
		FlushInterval:              200 * time.Millisecond,
		Timeout:                    1 * time.Second,
		BufferSize:                 1000,
		Gzip:                       true,
		DisableStartupVerification: true,
	}, nil)
	require.NoError(t, err, "DisableStartupVerification should allow construction against unreachable URLs")
	require.NoError(t, out.Close())
}

// TestLokiStartupCheckRespectsSSRF verifies that the probe honours
// the same SSRF policy as the runtime transport.
func TestLokiStartupCheckRespectsSSRF(t *testing.T) {
	defer goleak.VerifyNone(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(204)
	}))
	defer srv.Close()

	_, err := loki.New(&loki.Config{
		URL:                srv.URL,
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: false, // SSRF blocks loopback
		BatchSize:          1,
		FlushInterval:      200 * time.Millisecond,
		Timeout:            1 * time.Second,
		BufferSize:         1000,
		Gzip:               true,
	}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "startup verification failed")
	errStr := err.Error()
	assert.True(t,
		containsAny(errStr, "blocked", "ssrf", "loopback", "private", "denied"),
		"SSRF error should describe the block reason; got: %s", errStr)
}

// TestLokiStartupCheck_GoroutineLeakOnFailure verifies that a
// failed probe does not leak the batch-loop goroutine.
func TestLokiStartupCheck_GoroutineLeakOnFailure(t *testing.T) {
	defer goleak.VerifyNone(t)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	require.NoError(t, l.Close())

	for i := 0; i < 10; i++ {
		_, err := loki.New(&loki.Config{
			URL:                "http://" + addr + "/loki/api/v1/push",
			AllowInsecureHTTP:  true,
			AllowPrivateRanges: true,
			BatchSize:          1,
			FlushInterval:      200 * time.Millisecond,
			Timeout:            500 * time.Millisecond,
			BufferSize:         1000,
			Gzip:               true,
		}, nil)
		require.Error(t, err, "iteration %d: probe must reject the unreachable URL", i)
	}
}

// TestLokiStartupCheck_HTTPSAgainstPlainTCP — TLS handshake against
// a TCP-only listener honours the configured probe timeout.
func TestLokiStartupCheck_HTTPSAgainstPlainTCP(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			conn, acceptErr := l.Accept()
			if acceptErr != nil {
				return
			}
			_ = conn
		}
	}()

	start := time.Now()
	_, err = loki.New(&loki.Config{
		URL:                        "https://" + l.Addr().String() + "/loki/api/v1/push",
		AllowPrivateRanges:         true,
		BatchSize:                  1,
		FlushInterval:              200 * time.Millisecond,
		Timeout:                    10 * time.Second,
		BufferSize:                 1000,
		Gzip:                       true,
		StartupVerificationTimeout: 1 * time.Second,
	}, nil)
	elapsed := time.Since(start)

	_ = l.Close()
	<-acceptDone

	defer goleak.VerifyNone(t)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "startup verification failed")
	assert.Less(t, elapsed, 3*time.Second,
		"probe must honour StartupVerificationTimeout (1s); took %s", elapsed)
}

// TestLokiStartupCheck_CustomTimeoutOverridesDefault verifies the
// StartupVerificationTimeout field overrides the 5s default.
func TestLokiStartupCheck_CustomTimeoutOverridesDefault(t *testing.T) {
	defer goleak.VerifyNone(t)

	// Reserved 240.0.0.0/4 address — never responds.
	const blackHole = "http://240.0.0.1:80/loki/api/v1/push"

	start := time.Now()
	_, err := loki.New(&loki.Config{
		URL:                        blackHole,
		AllowInsecureHTTP:          true,
		AllowPrivateRanges:         true,
		BatchSize:                  1,
		FlushInterval:              200 * time.Millisecond,
		Timeout:                    30 * time.Second,
		BufferSize:                 1000,
		Gzip:                       true,
		StartupVerificationTimeout: 100 * time.Millisecond,
	}, nil)
	elapsed := time.Since(start)

	require.Error(t, err)
	assert.Less(t, elapsed, 2*time.Second,
		"custom 100 ms StartupVerificationTimeout should bound the probe; took %s", elapsed)
}

// TestLokiStartupCheck_HTTPSSuccess verifies the success path —
// a TLS handshake against a real httptest server completes within
// budget and loki.New returns successfully.
func TestLokiStartupCheck_HTTPSSuccess(t *testing.T) {
	defer goleak.VerifyNone(t)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(204)
	}))
	defer srv.Close()

	caPath := writeLokiTestServerCA(t, srv)

	out, err := loki.New(&loki.Config{
		URL:                srv.URL + "/loki/api/v1/push",
		TLSCA:              caPath,
		AllowPrivateRanges: true,
		BatchSize:          1,
		FlushInterval:      200 * time.Millisecond,
		Timeout:            5 * time.Second,
		BufferSize:         1000,
		Gzip:               true,
	}, nil)
	require.NoError(t, err)
	require.NoError(t, out.Close())
}

func containsAny(s string, candidates ...string) bool {
	for _, c := range candidates {
		if strings.Contains(s, c) {
			return true
		}
	}
	return false
}

func writeLokiTestServerCA(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	cert := srv.Certificate()
	require.NotNil(t, cert)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	path := filepath.Join(t.TempDir(), "test-ca.pem")
	require.NoError(t, os.WriteFile(path, pemBytes, 0o600))
	return path
}
