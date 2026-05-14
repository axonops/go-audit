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

package steps

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/axonops/audit"
	"github.com/axonops/audit/file"
	"github.com/axonops/audit/loki"
	"github.com/cucumber/godog"
)

// registerLokiFanoutSteps registers BDD steps for multi-output
// fan-out scenarios involving Loki alongside file, syslog, and webhook.
func registerLokiFanoutSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	registerLokiFanoutGivenSteps(ctx, tc)
	registerLokiFanoutThenSteps(ctx, tc)
}

func registerLokiFanoutGivenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {

	ctx.Step(`^an auditor with file and loki outputs$`,
		func() error {
			return createFileAndLokiAuditor(tc, nil, nil)
		})

	ctx.Step(`^an auditor with file receiving all events and loki receiving only "([^"]*)"$`,
		func(category string) error {
			lokiRoute := &audit.EventRoute{IncludeCategories: includeCats(category)}
			return createFileAndLokiAuditor(tc, nil, lokiRoute)
		})

	ctx.Step(`^an auditor with file and loki outputs both HMAC-enabled with salt "([^"]*)" version "([^"]*)"$`,
		func(salt, version string) error {
			hmacCfg := &audit.HMACConfig{
				Enabled: true,
				Salt: audit.HMACSalt{
					Version: version,
					Value:   []byte(salt),
				},
				Algorithm: "HMAC-SHA-256",
			}
			return createFileAndLokiAuditor(tc, hmacCfg, nil)
		})

	ctx.Step(`^an auditor with file output keeping all fields and loki output excluding label "([^"]*)"$`,
		func(label string) error {
			return createFileAndLokiAuditorWithExclusion(tc, label)
		})

	ctx.Step(`^an auditor with file output and loki output to unreachable server$`,
		func() error {
			return createFileAndLokiAuditorUnreachable(tc)
		})

}

func registerLokiFanoutThenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	registerLokiFanoutFileSteps(ctx, tc)
	registerLokiFanoutQuerySteps(ctx, tc)
}

func registerLokiFanoutFileSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	// Note: "the file should contain the marker" and "the file should
	// contain X" are registered in fanout_steps.go — not duplicated here.

	ctx.Step(`^the file should contain both markers$`,
		func() error {
			for _, marker := range tc.Markers {
				if err := assertFileContainsText(tc, "default", marker); err != nil {
					return err
				}
			}
			return nil
		})

	ctx.Step(`^the file should contain all (\d+) markers$`,
		func(n int) error {
			count := 0
			for _, marker := range tc.Markers {
				if err := assertFileContainsText(tc, "default", marker); err == nil {
					count++
				}
			}
			if count < n {
				return fmt.Errorf("file contains %d of %d expected markers", count, n)
			}
			return nil
		})

	ctx.Step(`^the file event should contain "_hmac" field$`,
		func() error {
			return assertFileEventHasField(tc, tc.Markers["default"], "_hmac")
		})

}

func registerLokiFanoutQuerySteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	registerLokiFanoutAssertionSteps(ctx, tc)
	registerLokiFanoutCountSteps(ctx, tc)
}

func registerLokiFanoutAssertionSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^the file and Loki "_hmac" values should match for the same event$`,
		func() error {
			return assertFileAndLokiHMACMatch(tc)
		})

	ctx.Step(`^the file event should contain:$`,
		func(table *godog.Table) error {
			return assertFileEventPayload(tc, tc.Markers["default"], table)
		})

	ctx.Step(`^querying Loki by label event_type = "([^"]*)" should return the (\w+) marker within (\d+) seconds$`,
		func(eventType, markerName string, timeout int) error {
			marker := tc.Markers[markerName]
			if marker == "" {
				marker = tc.Markers["default"]
			}
			return assertLokiLabelQueryReturnsMarker(tc, "event_type", eventType, marker, timeout)
		})

	ctx.Step(`^querying Loki by label event_type = "([^"]*)" should return no events within (\d+) seconds$`,
		func(eventType string, timeout int) error {
			return assertLokiLabelQueryReturnsNoEvents(tc, "event_type", eventType, timeout)
		})

	ctx.Step(`^querying Loki for the user_create marker should return no events within (\d+) seconds$`,
		func(timeout int) error {
			marker := tc.Markers["multi_0"]
			if marker == "" {
				marker = tc.Markers["default"]
			}
			return assertLokiMarkerAbsent(tc, marker, timeout)
		})

	ctx.Step(`^the loki server should not contain marker "([^"]*)" within (\d+) seconds$`,
		func(markerName string, timeout int) error {
			m, ok := tc.Markers[markerName]
			if !ok {
				return fmt.Errorf("no marker named %q", markerName)
			}
			return assertLokiMarkerAbsent(tc, m, timeout)
		})
}

func registerLokiFanoutCountSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^the loki fanout server should have at least (\d+) events within (\d+) seconds$`,
		func(minEvents, timeoutSec int) error {
			logql := `{app_name="bdd-audit", test_suite="bdd"}`
			ok := pollUntil(time.Duration(timeoutSec)*time.Second, 500*time.Millisecond, func() bool {
				result, err := queryLokiBDD(tc, logql, defaultLokiTenant)
				if err != nil {
					return false
				}
				return countLokiLines(result) >= minEvents
			})
			if !ok {
				return fmt.Errorf("expected at least %d events within %ds", minEvents, timeoutSec)
			}
			return nil
		})

	ctx.Step(`^I audit (\d+) uniquely marked "([^"]*)" events with actor "([^"]*)" and outcome "([^"]*)"$`,
		func(count int, eventType, actor, outcome string) error {
			for i := range count {
				m := marker("BDD")
				tc.Markers[fmt.Sprintf("multi_%d", i)] = m
				fields := audit.Fields{
					"actor_id": actor,
					"outcome":  outcome,
					"marker":   m,
				}
				if err := tc.Auditor.AuditEvent(audit.NewEvent(eventType, fields)); err != nil {
					return fmt.Errorf("audit event %d: %w", i, err)
				}
			}
			return nil
		})
}

// ---------------------------------------------------------------------------
// Auditor construction helpers
// ---------------------------------------------------------------------------

func createFileAndLokiAuditor(tc *AuditTestContext, hmacCfg *audit.HMACConfig, lokiRoute *audit.EventRoute) error {
	// Create temp file for file output.
	tmpFile, err := os.CreateTemp(tc.FileDir, "fanout-*.log")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	_ = tmpFile.Close()
	tc.FilePaths["default"] = tmpFile.Name()

	fileOut, err := file.New(&file.Config{
		Path:       tmpFile.Name(),
		MaxSizeMB:  10,
		MaxBackups: 1,
	})
	if err != nil {
		return fmt.Errorf("create file output: %w", err)
	}
	tc.AddCleanup(func() { _ = fileOut.Close() })

	lokiCfg := defaultLokiTestConfig(tc)

	lokiOut, err := loki.New(lokiCfg, nil, loki.WithFrameworkContext(audit.FrameworkContext{AppName: "bdd-audit", Host: "bdd-host"}))
	if err != nil {
		return fmt.Errorf("create loki output: %w", err)
	}
	tc.AddCleanup(func() { _ = lokiOut.Close() })
	tc.LokiOutputName = lokiOut.Name()

	opts := []audit.Option{
		audit.WithTaxonomy(tc.Taxonomy),
		audit.WithAppName("bdd-audit"),
		audit.WithHost("bdd-host"),
	}

	var fileOpts, lokiOpts []audit.OutputOption
	lokiOpts = append(lokiOpts, audit.WithRoute(lokiRoute))
	if hmacCfg != nil {
		fileOpts = append(fileOpts, audit.WithHMAC(hmacCfg))
		lokiOpts = append(lokiOpts, audit.WithHMAC(hmacCfg))
	}
	opts = append(opts,
		audit.WithNamedOutput(fileOut, fileOpts...),
		audit.WithNamedOutput(lokiOut, lokiOpts...),
	)
	auditor, err := audit.New(opts...)
	if err != nil {
		return fmt.Errorf("create auditor: %w", err)
	}
	tc.Auditor = auditor
	tc.AddCleanup(func() { _ = auditor.Close() })
	return nil
}

func createFileAndLokiAuditorWithExclusion(tc *AuditTestContext, excludeLabel string) error {
	tmpFile, err := os.CreateTemp(tc.FileDir, "fanout-pii-*.log")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	_ = tmpFile.Close()
	tc.FilePaths["default"] = tmpFile.Name()

	fileOut, err := file.New(&file.Config{
		Path:       tmpFile.Name(),
		MaxSizeMB:  10,
		MaxBackups: 1,
	})
	if err != nil {
		return fmt.Errorf("create file output: %w", err)
	}
	tc.AddCleanup(func() { _ = fileOut.Close() })

	lokiCfg := defaultLokiTestConfig(tc)

	lokiOut, err := loki.New(lokiCfg, nil, loki.WithFrameworkContext(audit.FrameworkContext{AppName: "bdd-audit", Host: "bdd-host"}))
	if err != nil {
		return fmt.Errorf("create loki output: %w", err)
	}
	tc.AddCleanup(func() { _ = lokiOut.Close() })
	tc.LokiOutputName = lokiOut.Name()

	auditor, err := audit.New(
		audit.WithTaxonomy(tc.Taxonomy),
		audit.WithAppName("bdd-audit"),
		audit.WithHost("bdd-host"),
		audit.WithNamedOutput(fileOut),                                        // no exclusions
		audit.WithNamedOutput(lokiOut, audit.WithExcludeLabels(excludeLabel)), // strip PII
	)
	if err != nil {
		return fmt.Errorf("create auditor: %w", err)
	}
	tc.Auditor = auditor
	tc.AddCleanup(func() { _ = auditor.Close() })
	return nil
}

func createFileAndLokiAuditorUnreachable(tc *AuditTestContext) error {
	tmpFile, err := os.CreateTemp(tc.FileDir, "fanout-unreachable-*.log")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	_ = tmpFile.Close()
	tc.FilePaths["default"] = tmpFile.Name()

	fileOut, err := file.New(&file.Config{
		Path:       tmpFile.Name(),
		MaxSizeMB:  10,
		MaxBackups: 1,
	})
	if err != nil {
		return fmt.Errorf("create file output: %w", err)
	}
	tc.AddCleanup(func() { _ = fileOut.Close() })

	// Unreachable Loki — connect to a port nothing is listening on.
	// Skip the startup probe so the runtime fan-out-isolates-failure
	// behaviour (the property under test) is exercised.
	lokiCfg := &loki.Config{
		URL:                        "http://localhost:39999/loki/api/v1/push",
		AllowInsecureHTTP:          true,
		AllowPrivateRanges:         true,
		BatchSize:                  1,
		FlushInterval:              1e9,
		Timeout:                    1e9, // 1 second timeout
		MaxRetries:                 1,
		BufferSize:                 100,
		Gzip:                       false,
		DisableStartupVerification: true,
	}

	lokiOut, err := loki.New(lokiCfg, nil, loki.WithFrameworkContext(audit.FrameworkContext{AppName: "bdd-audit", Host: "bdd-host"}))
	if err != nil {
		return fmt.Errorf("create loki output: %w", err)
	}
	tc.AddCleanup(func() { _ = lokiOut.Close() })

	auditor, err := audit.New(
		audit.WithTaxonomy(tc.Taxonomy),
		audit.WithAppName("bdd-audit"),
		audit.WithHost("bdd-host"),
		audit.WithNamedOutput(fileOut),
		audit.WithNamedOutput(lokiOut),
	)
	if err != nil {
		return fmt.Errorf("create auditor: %w", err)
	}
	tc.Auditor = auditor
	tc.AddCleanup(func() { _ = auditor.Close() })
	return nil
}

// ---------------------------------------------------------------------------
// File assertion helpers
// ---------------------------------------------------------------------------

func assertFileEventHasField(tc *AuditTestContext, marker, field string) error {
	raw, err := findFileEventByMarker(tc, marker)
	if err != nil {
		return err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return fmt.Errorf("parse file event: %w", err)
	}
	if _, ok := m[field]; !ok {
		return fmt.Errorf("file event does not contain field %q", field)
	}
	return nil
}

func assertFileEventPayload(tc *AuditTestContext, marker string, table *godog.Table) error {
	raw, err := findFileEventByMarker(tc, marker)
	if err != nil {
		return err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return fmt.Errorf("parse file event: %w", err)
	}
	for _, row := range table.Rows[1:] { // skip header
		field := row.Cells[0].Value
		want := row.Cells[1].Value
		got := fmt.Sprint(m[field])
		if got != want {
			return fmt.Errorf("file event field %q: want %q, got %q", field, want, got)
		}
	}
	return nil
}

func assertFileAndLokiHMACMatch(tc *AuditTestContext) error {
	marker := tc.Markers["default"]

	// Extract HMAC from file.
	raw, err := findFileEventByMarker(tc, marker)
	if err != nil {
		return fmt.Errorf("file: %w", err)
	}
	var fileMap map[string]any
	if unmarshalErr := json.Unmarshal(raw, &fileMap); unmarshalErr != nil {
		return fmt.Errorf("parse file event: %w", unmarshalErr)
	}
	fileHMAC, ok := fileMap["_hmac"].(string)
	if !ok {
		return fmt.Errorf("file event does not contain _hmac field")
	}

	// Extract HMAC from Loki.
	lokiHMAC, err := extractLokiHMACField(tc, marker)
	if err != nil {
		return fmt.Errorf("loki: %w", err)
	}

	if fileHMAC != lokiHMAC {
		return fmt.Errorf("HMAC mismatch: file=%q, loki=%q", fileHMAC, lokiHMAC)
	}
	return nil
}

func assertLokiLabelQueryReturnsMarker(tc *AuditTestContext, label, value, marker string, timeoutSec int) error {
	logql := fmt.Sprintf(`{%s=%q, app_name="bdd-audit"}`, label, value)
	var lastErr error
	ok := pollUntil(time.Duration(timeoutSec)*time.Second, 500*time.Millisecond, func() bool {
		result, err := queryLokiBDD(tc, logql, defaultLokiTenant)
		if err != nil {
			lastErr = err
			return false
		}
		for _, stream := range result.Data.Result {
			for _, v := range stream.Values {
				if len(v) >= 2 && strings.Contains(v[1], marker) {
					return true
				}
			}
		}
		return false
	})
	if ok {
		return nil
	}
	if lastErr != nil {
		return fmt.Errorf("loki query failed: %w", lastErr)
	}
	return fmt.Errorf("marker %q not found in Loki query {%s=%q} within %ds", marker, label, value, timeoutSec)
}

// assertLokiMarkerAbsent checks that a specific marker string does NOT
// appear in Loki. This is more precise than assertLokiLabelQueryReturnsNoEvents
// which queries by label and can find stale data from previous runs.
func assertLokiMarkerAbsent(tc *AuditTestContext, marker string, timeoutSec int) error {
	logql := fmt.Sprintf(`{app_name="bdd-audit"} |= %q`, marker)
	// scenario-control delay (#559): wait the full window before
	// asserting absence — early-exit polling cannot prove never-arrived.
	time.Sleep(time.Duration(timeoutSec) * time.Second)
	result, err := queryLokiBDD(tc, logql, defaultLokiTenant)
	if err != nil {
		return err
	}
	n := countLokiLines(result)
	if n > 0 {
		return fmt.Errorf("expected marker %q absent from Loki but found %d events", marker, n)
	}
	return nil
}

func assertLokiLabelQueryReturnsNoEvents(tc *AuditTestContext, label, value string, timeoutSec int) error {
	logql := fmt.Sprintf(`{%s=%q, app_name="bdd-audit"}`, label, value)
	// scenario-control delay (#559): wait the full window before
	// asserting absence — events may still be ingesting under this label.
	time.Sleep(time.Duration(timeoutSec) * time.Second)
	result, err := queryLokiBDD(tc, logql, defaultLokiTenant)
	if err != nil {
		return err
	}
	n := countLokiLines(result)
	if n > 0 {
		return fmt.Errorf("expected no events for {%s=%q} but found %d", label, value, n)
	}
	return nil
}

// findFileEventByMarker reads the file output and returns the raw JSON
// line containing the marker.
func findFileEventByMarker(tc *AuditTestContext, marker string) ([]byte, error) {
	path := tc.FilePaths["default"]
	if path == "" {
		return nil, fmt.Errorf("no file output configured")
	}
	data, err := os.ReadFile(path) //nolint:gosec // G304: path is from test temp dir, not user input
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, marker) {
			return []byte(line), nil
		}
	}
	return nil, fmt.Errorf("marker %q not found in file", marker)
}
