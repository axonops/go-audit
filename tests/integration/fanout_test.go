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

//go:build integration

// Package integration_test contains fan-out integration tests that
// exercise the full audit pipeline with multiple real output backends.
// Requires Docker Compose infrastructure: `make test-infra-up`.
package integration_test

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/axonops/audit"
	"github.com/axonops/audit/file"
	"github.com/axonops/audit/syslog"
	"github.com/axonops/audit/webhook"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m,
		goleak.IgnoreAnyFunction("net/http.(*persistConn).readLoop"),
		goleak.IgnoreAnyFunction("net/http.(*persistConn).writeLoop"),
	)
}

// marker generates a unique test marker.
func marker(t *testing.T) string {
	t.Helper()
	b := make([]byte, 8)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return "FANOUT_" + hex.EncodeToString(b)
}

const webhookURL = "http://localhost:8080"

// resetWebhook clears webhook receiver state.
func resetWebhook(t *testing.T) {
	t.Helper()
	resp, err := http.Post(webhookURL+"/reset", "", nil)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusNoContent, resp.StatusCode)
}

// configureWebhook sets the webhook receiver's response behaviour.
func configureWebhook(t *testing.T, statusCode int, delayMS int) {
	t.Helper()
	body := fmt.Sprintf(`{"status_code":%d,"delay_ms":%d}`, statusCode, delayMS)
	resp, err := http.Post(webhookURL+"/configure", "application/json",
		strings.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"configure endpoint should accept the configuration")
}

// getWebhookEvents returns stored webhook events.
func getWebhookEvents(t *testing.T) []map[string]any {
	t.Helper()
	resp, err := http.Get(webhookURL + "/events")
	require.NoError(t, err)
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	var events []map[string]any
	require.NoError(t, json.Unmarshal(data, &events))
	return events
}

// readSyslogLog reads the syslog-ng audit log.
func readSyslogLog(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("docker", "exec", "bdd-syslog-ng-1",
		"cat", "/var/log/syslog-ng/audit.log").CombinedOutput()
	if err != nil {
		return ""
	}
	return string(out)
}

func waitForSyslogMarker(t *testing.T, m string, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if strings.Contains(readSyslogLog(t), m) {
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

func waitForWebhookEvents(t *testing.T, n int, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if len(getWebhookEvents(t)) >= n {
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

// testTaxonomy returns a taxonomy for fan-out tests.
func testTaxonomy() *audit.Taxonomy {
	return &audit.Taxonomy{
		Version: 1,
		Categories: map[string]*audit.CategoryDef{
			"write":    {Events: []string{"user_create"}},
			"security": {Events: []string{"auth_failure"}},
		},
		Events: map[string]*audit.EventDef{
			"user_create":  {Required: []string{"outcome", "actor_id"}, Optional: []string{"marker"}},
			"auth_failure": {Required: []string{"outcome", "actor_id"}, Optional: []string{"marker"}},
		},
	}
}

// --- Fan-out tests ---

func TestFanOut_AllOutputs(t *testing.T) {
	resetWebhook(t)
	m := marker(t)
	dir := t.TempDir()
	filePath := filepath.Join(dir, "audit.log")

	// Create file output.
	fileOut, err := file.New(&file.Config{Path: filePath})
	require.NoError(t, err)

	// Create syslog output (TCP plain).
	syslogOut, err := syslog.New(&syslog.Config{
		Network:  "tcp",
		Address:  "localhost:5514",
		Facility: "local0",
		AppName:  "fanout-test",
	})
	require.NoError(t, err)

	// Create webhook output.
	webhookOut, err := webhook.New(&webhook.Config{
		URL:                webhookURL + "/events",
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
		BatchSize:          1,
		FlushInterval:      100 * time.Millisecond,
		Timeout:            5 * time.Second,
	}, nil)
	require.NoError(t, err)

	// Create auditor with all three outputs.
	auditor, err := audit.New(
		audit.WithTaxonomy(testTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(fileOut),
		audit.WithNamedOutput(syslogOut),
		audit.WithNamedOutput(webhookOut),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditor.Close() })

	// Send an event.
	err = auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"marker":   m,
	}))
	require.NoError(t, err)

	// Wait for webhook delivery before closing — the webhook batch
	// goroutine needs time to send the HTTP request.
	assert.True(t, waitForWebhookEvents(t, 1, 10*time.Second),
		"webhook should receive event before close")

	// Close flushes remaining outputs.
	require.NoError(t, auditor.Close())

	// Verify file output.
	data, err := os.ReadFile(filePath)
	require.NoError(t, err)
	assert.Contains(t, string(data), m, "file output should contain marker")

	// Verify syslog output.
	assert.True(t, waitForSyslogMarker(t, m, 10*time.Second),
		"syslog output should contain marker")

	// Verify webhook output.
	assert.True(t, waitForWebhookEvents(t, 1, 5*time.Second),
		"webhook should receive at least 1 event")
}

func TestFanOut_EventRouting(t *testing.T) {
	resetWebhook(t)
	dir := t.TempDir()
	filePath := filepath.Join(dir, "audit.log")

	// File receives all events.
	fileOut, err := file.New(&file.Config{Path: filePath})
	require.NoError(t, err)

	// Webhook receives only security events.
	webhookOut, err := webhook.New(&webhook.Config{
		URL:                webhookURL + "/events",
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
		BatchSize:          1,
		FlushInterval:      100 * time.Millisecond,
		Timeout:            5 * time.Second,
	}, nil)
	require.NoError(t, err)

	auditor, err := audit.New(
		audit.WithTaxonomy(testTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(fileOut), // all events
		audit.WithNamedOutput(webhookOut, audit.WithRoute(&audit.EventRoute{
			IncludeCategories: map[string]audit.SeverityRange{"security": {}},
		})), // security only
	)
	require.NoError(t, err)

	// Send a write event (should go to file, NOT webhook).
	writeMarker := marker(t)
	err = auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"marker":   writeMarker,
	}))
	require.NoError(t, err)

	// Send a security event (should go to BOTH).
	secMarker := marker(t)
	err = auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
		"marker":   secMarker,
	}))
	require.NoError(t, err)

	// Wait for webhook delivery before closing.
	assert.True(t, waitForWebhookEvents(t, 1, 10*time.Second))
	require.NoError(t, auditor.Close())

	// File should have both events.
	data, err := os.ReadFile(filePath)
	require.NoError(t, err)
	assert.Contains(t, string(data), writeMarker, "file should have write event")
	assert.Contains(t, string(data), secMarker, "file should have security event")

	// Webhook should have only the security event.
	assert.True(t, waitForWebhookEvents(t, 1, 5*time.Second))
	events := getWebhookEvents(t)

	// Verify the webhook got the security event, not the write event.
	found := false
	for _, e := range events {
		body, ok := e["body"].(map[string]any)
		if !ok {
			continue
		}
		bodyStr := fmt.Sprintf("%v", body)
		if strings.Contains(bodyStr, secMarker) {
			found = true
		}
		assert.NotContains(t, bodyStr, writeMarker,
			"webhook should NOT receive write events")
	}
	assert.True(t, found, "webhook should receive the security event")
}

func TestFanOut_PartialFailure(t *testing.T) {
	resetWebhook(t)
	configureWebhook(t, 503, 0) // webhook returns 503
	m := marker(t)
	dir := t.TempDir()
	filePath := filepath.Join(dir, "audit.log")

	fileOut, err := file.New(&file.Config{Path: filePath})
	require.NoError(t, err)

	syslogOut, err := syslog.New(&syslog.Config{
		Network:  "tcp",
		Address:  "localhost:5514",
		Facility: "local0",
		AppName:  "fanout-partial",
	})
	require.NoError(t, err)

	webhookOut, err := webhook.New(&webhook.Config{
		URL:                webhookURL + "/events",
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
		BatchSize:          1,
		FlushInterval:      100 * time.Millisecond,
		Timeout:            5 * time.Second,
		MaxRetries:         1,
	}, nil)
	require.NoError(t, err)

	auditor, err := audit.New(
		audit.WithTaxonomy(testTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(fileOut),
		audit.WithNamedOutput(syslogOut),
		audit.WithNamedOutput(webhookOut),
	)
	require.NoError(t, err)

	// Send event while webhook is failing.
	err = auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"marker":   m,
	}))
	require.NoError(t, err)

	// Close flushes file and syslog despite webhook failure.
	require.NoError(t, auditor.Close())

	data, err := os.ReadFile(filePath)
	require.NoError(t, err)
	assert.Contains(t, string(data), m, "file should receive event despite webhook failure")

	assert.True(t, waitForSyslogMarker(t, m, 10*time.Second),
		"syslog should receive event despite webhook failure")
}

func TestFanOut_MixedFormatters(t *testing.T) {
	resetWebhook(t)
	dir := t.TempDir()
	filePath := filepath.Join(dir, "audit.log")

	// File with JSON formatter (default).
	fileOut, err := file.New(&file.Config{Path: filePath})
	require.NoError(t, err)

	// Webhook with CEF formatter.
	webhookOut, err := webhook.New(&webhook.Config{
		URL:                webhookURL + "/events",
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
		BatchSize:          1,
		FlushInterval:      100 * time.Millisecond,
		Timeout:            5 * time.Second,
	}, nil)
	require.NoError(t, err)

	cefFmt := &audit.CEFFormatter{
		Vendor:  "AxonOps",
		Product: "FanoutTest",
		Version: "1.0",
	}

	auditor, err := audit.New(
		audit.WithTaxonomy(testTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(fileOut),                                       // JSON (default)
		audit.WithNamedOutput(webhookOut, audit.WithOutputFormatter(cefFmt)), // CEF
	)
	require.NoError(t, err)

	m := marker(t)
	err = auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"marker":   m,
	}))
	require.NoError(t, err)

	// Wait for webhook delivery before closing.
	assert.True(t, waitForWebhookEvents(t, 1, 10*time.Second))
	require.NoError(t, auditor.Close())

	// File should have JSON format.
	data, err := os.ReadFile(filePath)
	require.NoError(t, err)
	assert.Contains(t, string(data), `"event_type"`, "file should be JSON format")

	// Webhook should have received an event (CEF format as NDJSON).
	// The webhook receiver stores "decode error" for non-JSON bodies,
	// but the delivery itself succeeded — verify at least 1 event stored.
	events := getWebhookEvents(t)
	assert.GreaterOrEqual(t, len(events), 1,
		"webhook should have received at least 1 event")
}
