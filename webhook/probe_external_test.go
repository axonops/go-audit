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

package webhook_test

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

	"github.com/axonops/audit/webhook"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

// TestWebhookStartupConnectivityCheck verifies that webhook.New
// returns an error when the configured URL is unreachable and
// DisableStartupVerification is false (the default — verification
// is ON).
func TestWebhookStartupConnectivityCheck(t *testing.T) {
	defer goleak.VerifyNone(t)

	// Bind a TCP port then close the listener so the port is
	// unbound — a TCP dial to this port returns ECONNREFUSED
	// synchronously, exercising the probe-failure path without
	// race-y "find an unused port" gymnastics.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	require.NoError(t, l.Close())

	_, err = webhook.New(&webhook.Config{
		URL:                "http://" + addr,
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
		BatchSize:          1,
		FlushInterval:      50 * time.Millisecond,
		Timeout:            1 * time.Second,
		MaxRetries:         1,
		BufferSize:         10,
	}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "startup verification failed",
		"probe failure must surface as 'startup verification failed' in the error message")
	assert.Contains(t, err.Error(), "verify_on_startup: false",
		"probe error must include the YAML opt-out hint")
}

// TestWebhookLazyConnect verifies that
// DisableStartupVerification: true allows webhook.New to succeed
// even when the URL is unreachable. The runtime fail-on-flush
// behaviour is preserved via the existing retry+drop machinery.
func TestWebhookLazyConnect(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	require.NoError(t, l.Close())

	out, err := webhook.New(&webhook.Config{
		URL:                        "http://" + addr,
		AllowInsecureHTTP:          true,
		AllowPrivateRanges:         true,
		BatchSize:                  1,
		FlushInterval:              50 * time.Millisecond,
		Timeout:                    1 * time.Second,
		MaxRetries:                 1,
		BufferSize:                 10,
		DisableStartupVerification: true,
	}, nil)
	require.NoError(t, err, "DisableStartupVerification should allow construction against unreachable URLs")
	require.NoError(t, out.Close())
}

// TestWebhookStartupCheckRespectsSSRF verifies that the probe
// honours the same SSRF policy as the runtime transport.
// AllowPrivateRanges: false against a 127.0.0.1 server must reject
// at probe time with an SSRF-class error, NOT a generic dial error.
func TestWebhookStartupCheckRespectsSSRF(t *testing.T) {
	defer goleak.VerifyNone(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	_, err := webhook.New(&webhook.Config{
		URL:                srv.URL,
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: false, // SSRF blocks loopback
		BatchSize:          1,
		FlushInterval:      50 * time.Millisecond,
		Timeout:            1 * time.Second,
		MaxRetries:         1,
		BufferSize:         10,
	}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "startup verification failed",
		"SSRF rejection at probe time should surface through the same error wrap")
	// SSRF rejection from NewSSRFDialControl surfaces as a generic
	// dial error wrapping the SSRF reason; the substring "blocked"
	// or "ssrf" should appear somewhere in the chain.
	errStr := err.Error()
	assert.True(t,
		assertContainsAny(errStr, "blocked", "ssrf", "loopback", "private", "denied"),
		"SSRF error should describe the block reason; got: %s", errStr)
}

// TestWebhookStartupCheck_GoroutineLeakOnFailure verifies that a
// failed probe does not leak the batch-loop goroutine — New must
// return BEFORE the batch goroutine is started so no cleanup is
// required by the caller on the error path.
func TestWebhookStartupCheck_GoroutineLeakOnFailure(t *testing.T) {
	defer goleak.VerifyNone(t)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	require.NoError(t, l.Close())

	for i := 0; i < 10; i++ {
		_, err := webhook.New(&webhook.Config{
			URL:                "http://" + addr,
			AllowInsecureHTTP:  true,
			AllowPrivateRanges: true,
			BatchSize:          1,
			FlushInterval:      50 * time.Millisecond,
			Timeout:            500 * time.Millisecond,
			MaxRetries:         1,
			BufferSize:         10,
		}, nil)
		require.Error(t, err, "iteration %d: probe must reject the unreachable URL", i)
	}
}

// TestWebhookStartupCheck_HTTPSAgainstPlainTCP verifies that a
// probe against a TCP-only listener (no TLS speaker) bounded by
// StartupVerificationTimeout fails with a TLS handshake error
// within the configured budget — not a hang.
func TestWebhookStartupCheck_HTTPSAgainstPlainTCP(t *testing.T) {
	// A plain-TCP listener that accepts the connection but never
	// sends any bytes. The kernel accept queue absorbs the SYN+ACK
	// so the probe's TCP dial succeeds; the subsequent TLS
	// handshake hangs waiting for ServerHello which never arrives,
	// exercising the context-bounded handshake path.
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
			// Hold the conn open in this goroutine — closing it
			// would let the probe see EOF rather than handshake
			// timeout. The deferred listener close below makes
			// Accept return so this goroutine exits cleanly.
			_ = conn
		}
	}()

	start := time.Now()
	_, err = webhook.New(&webhook.Config{
		URL:                        "https://" + l.Addr().String(),
		AllowPrivateRanges:         true,
		BatchSize:                  1,
		FlushInterval:              50 * time.Millisecond,
		Timeout:                    10 * time.Second, // generous request timeout
		MaxRetries:                 1,
		BufferSize:                 10,
		StartupVerificationTimeout: 1 * time.Second, // tight probe budget
	}, nil)
	elapsed := time.Since(start)

	// Tear down the listener BEFORE goleak verifies so the accept
	// loop exits within the test body, not in t.Cleanup (which
	// runs AFTER deferred goleak.VerifyNone in the function body).
	_ = l.Close()
	<-acceptDone

	defer goleak.VerifyNone(t)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "startup verification failed")
	// Allow generous slack for CI noise; the probe should return
	// at or near the configured 1s budget, not the 10s request
	// timeout or the 5s default.
	assert.Less(t, elapsed, 3*time.Second,
		"probe must honour StartupVerificationTimeout (1s) and return within budget; took %s", elapsed)
}

// TestWebhookStartupCheck_CustomTimeoutOverridesDefault verifies
// that the StartupVerificationTimeout field overrides the 5s
// default. Confirms by setting a 100 ms timeout against a port
// that drops packets — the probe must fail well before the 5s
// default. (Linux: 127.0.0.0/8 with no listener returns
// ECONNREFUSED synchronously; we use a routable but unreachable
// address.)
func TestWebhookStartupCheck_CustomTimeoutOverridesDefault(t *testing.T) {
	defer goleak.VerifyNone(t)

	// 240.0.0.0/4 is reserved for future use; no host will ever
	// respond, so the TCP dial blocks until the OS or our context
	// gives up. The probe's 100 ms budget should bound the wait.
	const blackHole = "http://240.0.0.1:80"

	start := time.Now()
	_, err := webhook.New(&webhook.Config{
		URL:                        blackHole,
		AllowInsecureHTTP:          true,
		AllowPrivateRanges:         true,
		BatchSize:                  1,
		FlushInterval:              50 * time.Millisecond,
		Timeout:                    30 * time.Second,
		MaxRetries:                 1,
		BufferSize:                 10,
		StartupVerificationTimeout: 100 * time.Millisecond,
	}, nil)
	elapsed := time.Since(start)

	require.Error(t, err)
	// Allow CI slack but assert the probe returned far below
	// the 5s default and the 30s request timeout.
	assert.Less(t, elapsed, 2*time.Second,
		"custom 100 ms StartupVerificationTimeout should bound the probe; took %s", elapsed)
}

// TestWebhookStartupCheck_HTTPSuccess verifies the success path
// for plain http://: TCP dial succeeds, the probe closes the conn
// without a TLS handshake, and webhook.New returns the live Output.
func TestWebhookStartupCheck_HTTPSuccess(t *testing.T) {
	defer goleak.VerifyNone(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	out, err := webhook.New(&webhook.Config{
		URL:                srv.URL,
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
		BatchSize:          1,
		FlushInterval:      50 * time.Millisecond,
		Timeout:            5 * time.Second,
		MaxRetries:         1,
		BufferSize:         10,
	}, nil)
	require.NoError(t, err)
	require.NoError(t, out.Close())
}

// TestWebhookStartupCheck_RejectsMissingScheme exercises the
// parseProbeURL "url missing scheme or host" branch. Validation
// upstream of probeEndpoint normally rejects empty-scheme URLs, so
// this is defence-in-depth.
func TestWebhookStartupCheck_RejectsMissingScheme(t *testing.T) {
	defer goleak.VerifyNone(t)

	// This URL passes url.Parse cleanly but has no scheme; webhook
	// config validation will reject it before the probe runs,
	// proving the upstream gate. The test pins the contract that
	// no probe code can be reached with a malformed URL.
	_, err := webhook.New(&webhook.Config{
		URL:                "//example.com/no-scheme",
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
		BatchSize:          1,
		FlushInterval:      50 * time.Millisecond,
		Timeout:            1 * time.Second,
		MaxRetries:         1,
		BufferSize:         10,
	}, nil)
	require.Error(t, err)
}

// TestWebhookStartupCheck_HTTPSSuccess verifies the success path —
// a TLS handshake against a real httptest server completes within
// the probe budget and webhook.New returns successfully.
func TestWebhookStartupCheck_HTTPSSuccess(t *testing.T) {
	defer goleak.VerifyNone(t)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	// Pull the test CA out of srv so the probe's TLS handshake
	// trusts the test server's cert.
	caPath := writeTestServerCAToFile(t, srv)

	out, err := webhook.New(&webhook.Config{
		URL:                srv.URL,
		TLSCA:              caPath,
		AllowPrivateRanges: true,
		BatchSize:          1,
		FlushInterval:      50 * time.Millisecond,
		Timeout:            5 * time.Second,
		MaxRetries:         1,
		BufferSize:         10,
	}, nil)
	require.NoError(t, err)
	require.NoError(t, out.Close())
}

// assertContainsAny reports whether s contains any of the given
// substrings. Helper for SSRF error-message assertions where the
// exact wording from net/http internals is not stable but the
// security property (blocked address surfaced) is.
func assertContainsAny(s string, candidates ...string) bool {
	for _, c := range candidates {
		if strings.Contains(s, c) {
			return true
		}
	}
	return false
}

// writeTestServerCAToFile writes the auto-generated httptest TLS
// certificate to a PEM file so webhook.Config.TLSCA can load it.
// Returns the file path.
func writeTestServerCAToFile(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	cert := srv.Certificate()
	require.NotNil(t, cert, "httptest TLS server must expose its leaf certificate")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	path := filepath.Join(t.TempDir(), "test-ca.pem")
	require.NoError(t, os.WriteFile(path, pemBytes, 0o600))
	return path
}
