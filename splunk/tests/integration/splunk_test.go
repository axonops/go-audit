//go:build integration

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

// Package integration_test contains integration tests for the Splunk
// HEC output against a real Splunk Enterprise instance running in
// Docker. Requires: make test-infra-splunk-up
//
// The test container is configured with `SPLUNK_HEC_SSL=False` for
// CI simplicity — production consumers MUST keep HEC TLS enabled.
// See tests/bdd/docker-compose.splunk.yml.
package integration_test

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/axonops/audit"
	"github.com/axonops/audit/splunk"
)

const (
	splunkURL      = "http://localhost:8088"
	splunkToken    = "bdd-test-hec-token"
	splunkAdminURL = "http://localhost:8089" // Splunkd management port (search)
	splunkUser     = "admin"
	splunkPass     = "ChangeMeForRealUse123!"
)

// searchClient is a dedicated HTTP client for the Splunk search API.
// Not http.DefaultClient per project rules.
var searchClient = &http.Client{Timeout: 30 * time.Second} //nolint:gochecknoglobals // test infrastructure

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m,
		goleak.IgnoreAnyFunction("net/http.(*persistConn).readLoop"),
		goleak.IgnoreAnyFunction("net/http.(*persistConn).writeLoop"),
	)
}

// skipIfArm64 skips on arm64 — Splunk does not publish an arm64
// image for `splunk/splunk`, so the container does not exist on
// Apple Silicon CI runners.
func skipIfArm64(t *testing.T) {
	t.Helper()
	if runtime.GOARCH == "arm64" {
		t.Skip("Splunk container is x86-only; arm64 not supported")
	}
}

// marker generates a unique string for per-test isolation. The
// envelope's `actor_id` carries this so the post-search verification
// can find exactly the test's events without cross-test interference.
func marker(t *testing.T) string {
	t.Helper()
	b := make([]byte, 8)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return "marker_" + hex.EncodeToString(b)
}

// newSplunkOutput builds a Splunk output pointed at the test
// container. Disables startup verification so the test fails on the
// FIRST real send if the container is misconfigured (rather than
// failing during construction with a less specific error).
func newSplunkOutput(t *testing.T, mutate func(*splunk.Config)) *splunk.Output {
	t.Helper()
	gz := false // disable gzip so we can read raw envelope bytes via search
	cfg := &splunk.Config{
		URL:                        splunkURL,
		Token:                      splunkToken,
		Sourcetype:                 "axonops:audit",
		Source:                     "audit",
		Index:                      "main",
		BatchSize:                  10,
		MaxBatchBytes:              819200,
		MaxEventBytes:              1024 * 1024,
		FlushInterval:              200 * time.Millisecond,
		Timeout:                    10 * time.Second,
		BufferSize:                 1000,
		MaxRetries:                 5,
		Gzip:                       &gz,
		AllowInsecureHTTP:          true, // test container runs HEC SSL=false
		AllowPrivateRanges:         true, // 127.0.0.1
		DisableStartupVerification: false,
	}
	if mutate != nil {
		mutate(cfg)
	}
	out, err := splunk.New(cfg, nil)
	require.NoError(t, err)
	return out
}

// waitForEvent polls Splunk's search API until at least `expected`
// events match the given search query. Returns the matching events
// (one map per hit). Times out after 30 seconds.
func waitForEvent(t *testing.T, query string, expected int) []map[string]any {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	var hits []map[string]any
	for time.Now().Before(deadline) {
		hits = searchSplunk(t, query)
		if len(hits) >= expected {
			return hits
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("waitForEvent: expected >= %d hits for query %q within 30s, got %d", expected, query, len(hits))
	return nil
}

// searchSplunk runs a one-shot search against the Splunk REST API
// and returns the matching events. Uses basic auth with the admin
// credentials baked into the docker-compose.
func searchSplunk(t *testing.T, query string) []map[string]any {
	t.Helper()
	// Splunk's "exec" mode runs the search and waits for results.
	form := url.Values{}
	form.Set("search", "search "+query)
	form.Set("exec_mode", "oneshot")
	form.Set("output_mode", "json")
	form.Set("earliest_time", "-5m")
	form.Set("latest_time", "now")

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"https://localhost:8089/services/search/jobs/export",
		strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(splunkUser, splunkPass)

	// Splunkd management port uses TLS with self-signed cert; we
	// accept that for the test environment via a one-off insecure
	// transport (this is the search-API client, NOT the audit
	// output's HTTP client).
	insecureClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: insecureTLS(),
		},
	}

	resp, err := insecureClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		// Splunkd may still be coming up — return empty so the
		// caller retries.
		return nil
	}

	// Splunk search/jobs/export streams one JSON object per line.
	var hits []map[string]any
	dec := json.NewDecoder(strings.NewReader(string(body)))
	for {
		var line struct {
			Result map[string]any `json:"result"`
		}
		if err := dec.Decode(&line); err != nil {
			break
		}
		if line.Result != nil {
			hits = append(hits, line.Result)
		}
	}
	return hits
}

func TestSplunkIntegration_EventEndpoint_SendAndSearch(t *testing.T) {
	skipIfArm64(t)
	out := newSplunkOutput(t, nil)
	defer func() { require.NoError(t, out.Close()) }()

	m := marker(t)
	event := []byte(fmt.Sprintf(
		`{"timestamp":"%s","event_type":"user_login","actor_id":%q,"outcome":"success"}`,
		time.Now().UTC().Format(time.RFC3339Nano), m))
	require.NoError(t, out.Write(event))

	// Search for the marker; should land exactly once.
	hits := waitForEvent(t, fmt.Sprintf(`index=main sourcetype="axonops:audit" actor_id=%q`, m), 1)
	require.GreaterOrEqual(t, len(hits), 1)
	// The first hit's raw event should contain our marker.
	first := hits[0]
	raw, _ := first["_raw"].(string)
	assert.Contains(t, raw, m)
}

func TestSplunkIntegration_BatchMultipleEvents(t *testing.T) {
	skipIfArm64(t)
	out := newSplunkOutput(t, func(c *splunk.Config) {
		c.BatchSize = 100
		c.FlushInterval = 100 * time.Millisecond
	})
	defer func() { require.NoError(t, out.Close()) }()

	m := marker(t)
	const n = 10
	for i := 0; i < n; i++ {
		event := []byte(fmt.Sprintf(
			`{"timestamp":"%s","event_type":"user_login","actor_id":%q,"outcome":"success","seq":%d}`,
			time.Now().UTC().Format(time.RFC3339Nano), m, i))
		require.NoError(t, out.Write(event))
	}

	// Wait for all N events to appear.
	hits := waitForEvent(t, fmt.Sprintf(`index=main sourcetype="axonops:audit" actor_id=%q | stats count`, m), 1)
	require.GreaterOrEqual(t, len(hits), 1)
	countStr, _ := hits[0]["count"].(string)
	assert.Equal(t, fmt.Sprintf("%d", n), countStr,
		"expected exactly %d events in Splunk for marker %s", n, m)
}

func TestSplunkIntegration_GzipCompression_SendAndSearch(t *testing.T) {
	skipIfArm64(t)
	out := newSplunkOutput(t, func(c *splunk.Config) {
		gz := true
		c.Gzip = &gz
	})
	defer func() { require.NoError(t, out.Close()) }()

	m := marker(t)
	event := []byte(fmt.Sprintf(
		`{"timestamp":"%s","event_type":"user_login","actor_id":%q,"outcome":"success"}`,
		time.Now().UTC().Format(time.RFC3339Nano), m))
	require.NoError(t, out.Write(event))

	// Splunk should index the gzipped event identically to the
	// uncompressed case.
	hits := waitForEvent(t, fmt.Sprintf(`index=main sourcetype="axonops:audit" actor_id=%q`, m), 1)
	require.GreaterOrEqual(t, len(hits), 1)
}

func TestSplunkIntegration_RawEndpoint_SendAndSearch(t *testing.T) {
	skipIfArm64(t)
	out := newSplunkOutput(t, func(c *splunk.Config) {
		c.Endpoint = splunk.EndpointRaw
	})
	defer func() { require.NoError(t, out.Close()) }()

	m := marker(t)
	event := []byte(fmt.Sprintf(
		`{"event_type":"user_login","actor_id":%q,"outcome":"success"}`, m))
	require.NoError(t, out.Write(event))

	// /raw bypasses the envelope; metadata is set via the URL query
	// string. Splunk still indexes the event under the configured
	// sourcetype.
	hits := waitForEvent(t, fmt.Sprintf(`index=main sourcetype="axonops:audit" actor_id=%q`, m), 1)
	require.GreaterOrEqual(t, len(hits), 1)
}

func TestSplunkIntegration_InvalidToken_Stops(t *testing.T) {
	skipIfArm64(t)
	out := newSplunkOutput(t, func(c *splunk.Config) {
		c.Token = "definitely-not-a-real-token-99999"
		c.MaxRetries = 0
	})
	defer func() { _ = out.Close() }()

	require.NoError(t, out.Write([]byte(`{"event_type":"x"}`)))

	// The Output should enter the stopped state after HEC returns
	// code 4. Poll for the symptom (Write returns ErrOutputClosed).
	assert.Eventually(t, func() bool {
		return errors.Is(out.Write([]byte(`{"event_type":"y"}`)), audit.ErrOutputClosed)
	}, 10*time.Second, 100*time.Millisecond,
		"expected output to enter stopped state after HEC code 4")
}

func TestSplunkIntegration_HealthCheck_Passes(t *testing.T) {
	skipIfArm64(t)
	// HealthCheck enabled by default in newSplunkOutput — the
	// constructor would have failed if the probe had returned
	// non-200 or an unexpected HEC code.
	out := newSplunkOutput(t, nil)
	require.NoError(t, out.Close())
}

// insecureTLS returns a TLS config that skips verification. ONLY
// used by the test's search client to talk to Splunkd's management
// port (which serves a self-signed cert). The audit output's HTTP
// client NEVER uses this — InsecureSkipVerify is forbidden on the
// hot path per project rules.
func insecureTLS() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true} //nolint:gosec // search-API only; documented above
}
