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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cucumber/godog"

	"github.com/axonops/audit"
	"github.com/axonops/audit/loki"
)

// lokiQueryClient is a dedicated HTTP client for querying Loki in BDD tests.
var lokiQueryClient = &http.Client{Timeout: 15 * time.Second} //nolint:gochecknoglobals // test infrastructure

const defaultLokiTenant = "bdd-test"

// registerLokiSteps registers all Loki-specific Given/When/Then steps.
func registerLokiSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	registerLokiGivenSteps(ctx, tc)
	registerLokiWhenSteps(ctx, tc)
	registerLokiThenSteps(ctx, tc)
}

// ---------------------------------------------------------------------------
// Given steps — construction
// ---------------------------------------------------------------------------

func registerLokiGivenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	registerLokiGivenConstructionSteps(ctx, tc)
	registerLokiGivenValidationSteps(ctx, tc)
	registerLokiGivenConfigSteps(ctx, tc)
}

func registerLokiGivenConstructionSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {

	ctx.Step(`^an auditor with loki output$`, func() error {
		return createLokiAuditor(tc, &loki.Config{Gzip: true})
	})

	ctx.Step(`^an auditor with loki output to tenant "([^"]*)"$`, func(tenant string) error {
		return createLokiAuditor(tc, &loki.Config{TenantID: tenant, Gzip: true})
	})

	ctx.Step(`^an auditor with loki output with static label "([^"]*)" = "([^"]*)"$`, func(name, value string) error {
		return createLokiAuditor(tc, &loki.Config{
			Gzip:   true,
			Labels: loki.LabelConfig{Static: map[string]string{name: value}},
		})
	})

	ctx.Step(`^an auditor with loki output with batch size (\d+)$`, func(size int) error {
		return createLokiAuditor(tc, &loki.Config{BatchSize: size, Gzip: true})
	})

	// Max event size (#688).
	ctx.Step(`^an auditor with loki output with max event bytes (\d+)$`,
		func(maxEventBytes int) error {
			return createLokiAuditor(tc, &loki.Config{
				BatchSize:     1,
				FlushInterval: 100 * time.Millisecond,
				MaxEventBytes: maxEventBytes,
				Gzip:          true,
			})
		})

	ctx.Step(`^an auditor with loki output with batch size (\d+) and flush interval (\d+)ms$`, func(size, ms int) error {
		return createLokiAuditor(tc, &loki.Config{
			BatchSize:     size,
			FlushInterval: time.Duration(ms) * time.Millisecond,
			Gzip:          true,
		})
	})

	ctx.Step(`^an auditor with loki output with batch size (\d+) and flush interval (\d+)s$`, func(size, s int) error {
		return createLokiAuditor(tc, &loki.Config{
			BatchSize:     size,
			FlushInterval: time.Duration(s) * time.Second,
			Gzip:          true,
		})
	})

	ctx.Step(`^an auditor with loki output excluding dynamic label "([^"]*)"$`, func(label string) error {
		cfg := &loki.Config{Gzip: true}
		switch label {
		case "severity":
			cfg.Labels.Dynamic.ExcludeSeverity = true
		case "event_type":
			cfg.Labels.Dynamic.ExcludeEventType = true
		case "event_category":
			cfg.Labels.Dynamic.ExcludeEventCategory = true
		case "app_name":
			cfg.Labels.Dynamic.ExcludeAppName = true
		case "host":
			cfg.Labels.Dynamic.ExcludeHost = true
		case "pid":
			cfg.Labels.Dynamic.ExcludePID = true
		default:
			return fmt.Errorf("unknown dynamic label: %s", label)
		}
		return createLokiAuditor(tc, cfg)
	})

	ctx.Step(`^an auditor with loki output with gzip enabled$`, func() error {
		return createLokiAuditor(tc, &loki.Config{Gzip: true})
	})

	ctx.Step(`^an auditor with loki output with gzip disabled$`, func() error {
		cfg := &loki.Config{}
		cfg.Gzip = false
		return createLokiAuditor(tc, cfg)
	})
}

func registerLokiGivenValidationSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^I try to create a loki output with empty URL$`, func() error {
		return tryCreateLokiOutput(tc, &loki.Config{URL: ""})
	})

	ctx.Step(`^I try to create a loki output to "([^"]*)"$`, func(rawURL string) error {
		return tryCreateLokiOutput(tc, &loki.Config{URL: rawURL})
	})

	ctx.Step(`^I try to create a loki output to an unreachable URL$`, func() error {
		addr, err := reserveUnboundPort()
		if err != nil {
			return err
		}
		return tryCreateLokiOutput(tc, &loki.Config{
			URL:                "http://" + addr + "/loki/api/v1/push",
			AllowInsecureHTTP:  true,
			AllowPrivateRanges: true,
			BatchSize:          1,
			FlushInterval:      200 * time.Millisecond,
			BufferSize:         1000,
			Gzip:               true,
		})
	})

	ctx.Step(`^I try to create a loki output to an unreachable URL with verify_on_startup false$`, func() error {
		addr, err := reserveUnboundPort()
		if err != nil {
			return err
		}
		return tryCreateLokiOutput(tc, &loki.Config{
			URL:                        "http://" + addr + "/loki/api/v1/push",
			AllowInsecureHTTP:          true,
			AllowPrivateRanges:         true,
			BatchSize:                  1,
			FlushInterval:              200 * time.Millisecond,
			BufferSize:                 1000,
			Gzip:                       true,
			DisableStartupVerification: true,
		})
	})

	ctx.Step(`^I try to create a loki output with basic auth and bearer token$`, func() error {
		return tryCreateLokiOutput(tc, &loki.Config{
			URL:         "https://loki.example.com/push",
			BasicAuth:   &loki.BasicAuth{Username: "user", Password: "pass"},
			BearerToken: "token",
		})
	})

	ctx.Step(`^I try to create a loki output with basic auth username "([^"]*)" and password "([^"]*)"$`, func(user, pass string) error {
		return tryCreateLokiOutput(tc, &loki.Config{
			URL:       "https://loki.example.com/push",
			BasicAuth: &loki.BasicAuth{Username: user, Password: pass},
		})
	})

	ctx.Step(`^I try to create a loki output with static label "([^"]*)" = "([^"]*)"$`, func(name, value string) error {
		return tryCreateLokiOutput(tc, &loki.Config{
			URL:    "https://loki.example.com/push",
			Labels: loki.LabelConfig{Static: map[string]string{name: value}},
		})
	})

	ctx.Step(`^I try to create a loki output with static label "([^"]*)" containing control chars$`, func(name string) error {
		return tryCreateLokiOutput(tc, &loki.Config{
			URL:    "https://loki.example.com/push",
			Labels: loki.LabelConfig{Static: map[string]string{name: "prod\ninjected"}},
		})
	})

	ctx.Step(`^I try to create a loki output with unknown dynamic label "([^"]*)"$`, func(name string) error {
		// Use the YAML factory path to test dynamic label validation.
		yamlCfg := fmt.Sprintf("url: https://loki.example.com/push\nlabels:\n  dynamic:\n    %s: true\n", name)
		factory := audit.LookupOutputFactory("loki")
		if factory == nil {
			return fmt.Errorf("loki factory not registered")
		}
		_, err := factory("test", []byte(yamlCfg), audit.FrameworkContext{})
		tc.LastErr = err
		return nil
	})

	ctx.Step(`^I try to create a loki output with header containing CRLF$`, func() error {
		return tryCreateLokiOutput(tc, &loki.Config{
			URL:     "https://loki.example.com/push",
			Headers: map[string]string{"X-Bad\r\nHeader": "value"},
		})
	})

	ctx.Step(`^I try to create a loki output with restricted header "([^"]*)"$`, func(header string) error {
		return tryCreateLokiOutput(tc, &loki.Config{
			URL:     "https://loki.example.com/push",
			Headers: map[string]string{header: "value"},
		})
	})

	ctx.Step(`^I try to create a loki output with (\w+) set to (-?\d+)$`, func(field string, value int) error {
		cfg := &loki.Config{URL: "https://loki.example.com/push"}
		switch field {
		case "batch_size":
			cfg.BatchSize = value
		case "buffer_size":
			cfg.BufferSize = value
		case "max_retries":
			cfg.MaxRetries = value
		default:
			return fmt.Errorf("unknown field: %s", field)
		}
		return tryCreateLokiOutput(tc, cfg)
	})

	ctx.Step(`^I try to create a loki output with tls_cert but no tls_key$`, func() error {
		return tryCreateLokiOutput(tc, &loki.Config{
			URL:     "https://loki.example.com/push",
			TLSCert: "/tmp/cert.pem",
		})
	})

}

func registerLokiGivenConfigSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	// Config.String() credential redaction steps.
	ctx.Step(`^a loki config with basic auth username "([^"]*)" and password "([^"]*)"$`, func(user, pass string) error {
		cfg := loki.Config{
			URL:       "https://loki.example.com/push",
			BasicAuth: &loki.BasicAuth{Username: user, Password: pass},
			BatchSize: 100,
		}
		tc.Markers["config_string"] = cfg.String()
		return nil
	})

	ctx.Step(`^a loki config with bearer token "([^"]*)"$`, func(token string) error {
		cfg := loki.Config{
			URL:         "https://loki.example.com/push",
			BearerToken: token,
			BatchSize:   100,
		}
		tc.Markers["config_string"] = cfg.String()
		return nil
	})

	ctx.Step(`^the config string should not contain "([^"]*)"$`, func(s string) error {
		cfgStr := tc.Markers["config_string"]
		if strings.Contains(cfgStr, s) {
			return fmt.Errorf("config string should not contain %q but got: %s", s, cfgStr)
		}
		return nil
	})

	ctx.Step(`^the config string should contain "([^"]*)"$`, func(s string) error {
		cfgStr := tc.Markers["config_string"]
		if !strings.Contains(cfgStr, s) {
			return fmt.Errorf("config string should contain %q but got: %s", s, cfgStr)
		}
		return nil
	})
}

// ---------------------------------------------------------------------------
// When steps — Loki-specific event emission
// ---------------------------------------------------------------------------

func registerLokiWhenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	registerLokiWhenAuditSteps(ctx, tc)
	registerLokiWhenLifecycleSteps(ctx, tc)
}

func registerLokiWhenAuditSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^I audit a uniquely marked "([^"]*)" event with field "([^"]*)" = "([^"]*)"$`,
		func(eventType, field, value string) error {
			m := marker("BDD")
			tc.Markers["default"] = m
			fields := defaultRequiredFields(tc.Taxonomy, eventType)
			fields["marker"] = m
			fields[field] = value
			return tc.Auditor.AuditEvent(audit.NewEvent(eventType, fields))
		})

	ctx.Step(`^I audit (\d+) loki events with a shared marker$`, func(count int) error {
		m := marker("BDD")
		tc.Markers["default"] = m
		for i := range count {
			fields := defaultRequiredFields(tc.Taxonomy, "user_create")
			fields["marker"] = m
			if err := tc.Auditor.AuditEvent(audit.NewEvent("user_create", fields)); err != nil {
				return fmt.Errorf("audit event %d: %w", i, err)
			}
		}
		return nil
	})

	ctx.Step(`^I audit (?:a|an) "([^"]*)" event with marker "([^"]*)"$`,
		func(eventType, markerName string) error {
			m := marker("BDD")
			tc.Markers[markerName] = m
			// Also set as default if not already set.
			if tc.Markers["default"] == "" {
				tc.Markers["default"] = m
			}
			fields := defaultRequiredFields(tc.Taxonomy, eventType)
			fields["marker"] = m
			return tc.Auditor.AuditEvent(audit.NewEvent(eventType, fields))
		})

	ctx.Step(`^I audit a uniquely marked "([^"]*)" event with a (\d+)-byte payload$`,
		auditLokiSizedPayloadStep(tc))

	ctx.Step(`^I audit (\d+) uniquely marked events with the same timestamp$`,
		func(count int) error {
			for i := range count {
				m := marker("BDD")
				tc.Markers[fmt.Sprintf("multi_%d", i)] = m
				if i == 0 {
					tc.Markers["default"] = m
				}
				fields := defaultRequiredFields(tc.Taxonomy, "user_create")
				fields["marker"] = m
				if err := tc.Auditor.AuditEvent(audit.NewEvent("user_create", fields)); err != nil {
					return fmt.Errorf("audit event %d: %w", i, err)
				}
			}
			return nil
		})

}

// auditLokiSizedPayloadStep returns a handler for the #688 sized-payload
// step. The padding is concatenated into the marker field because the
// standard test taxonomy only declares the marker field, not a separate
// payload field.
func auditLokiSizedPayloadStep(tc *AuditTestContext) func(string, int) error {
	return func(eventType string, size int) error {
		if tc.Auditor == nil {
			return fmt.Errorf("auditor is nil (construction may have failed: %w)", tc.LastErr)
		}
		m := marker("LKOS")
		tc.Markers["default"] = m
		fields := defaultRequiredFields(tc.Taxonomy, eventType)
		fields["marker"] = m + "|" + strings.Repeat("x", size)
		return tc.Auditor.AuditEvent(audit.NewEvent(eventType, fields))
	}
}

func registerLokiWhenLifecycleSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^I try to audit a "([^"]*)" event$`, func(eventType string) error {
		fields := defaultRequiredFields(tc.Taxonomy, eventType)
		tc.LastErr = tc.Auditor.AuditEvent(audit.NewEvent(eventType, fields))
		return nil
	})

	ctx.Step(`^no error should occur$`, func() error {
		if tc.LastErr != nil {
			return fmt.Errorf("expected no error but got: %w", tc.LastErr)
		}
		return nil
	})
}

// ---------------------------------------------------------------------------
// Then steps — assertions
// ---------------------------------------------------------------------------

func registerLokiThenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	registerLokiThenDeliverySteps(ctx, tc)
	registerLokiThenLabelQuerySteps(ctx, tc)
	registerLokiThenLabelSteps(ctx, tc)
	registerLokiThenErrorSteps(ctx, tc)
}

func registerLokiThenDeliverySteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {

	ctx.Step(`^the loki server should contain the marker within (\d+) seconds$`, func(secs int) error {
		return assertLokiContainsMarker(tc, time.Duration(secs)*time.Second)
	})

	ctx.Step(`^the loki server should have at least (\d+) events? within (\d+) seconds$`, func(n, secs int) error {
		return assertLokiEventCount(tc, n, time.Duration(secs)*time.Second)
	})

	ctx.Step(`^the loki event should contain field "([^"]*)" with value "([^"]*)"$`, func(field, value string) error {
		return assertLokiEventField(tc, field, value)
	})

	ctx.Step(`^the loki server should have events in stream "([^"]*)" within (\d+) seconds$`, func(eventType string, secs int) error {
		return assertLokiStreamExists(tc, eventType, time.Duration(secs)*time.Second)
	})

	ctx.Step(`^the loki server for tenant "([^"]*)" should contain the marker within (\d+) seconds$`, func(tenant string, secs int) error {
		return assertLokiContainsMarkerForTenant(tc, tenant, time.Duration(secs)*time.Second)
	})

	ctx.Step(`^the loki server for tenant "([^"]*)" should not contain the marker within (\d+) seconds$`, func(tenant string, secs int) error {
		return assertLokiMarkerAbsentForTenant(tc, tenant, time.Duration(secs)*time.Second)
	})

	// Complete payload assertion: verify every field in the Loki log line.
	ctx.Step(`^the loki event payload should contain:$`, func(table *godog.Table) error {
		return assertLokiCompletePayload(tc, table)
	})
}

// registerLokiThenLabelQuerySteps registers steps that QUERY Loki using
// label selectors — proving the labels work as search criteria.
func registerLokiThenLabelQuerySteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	// Query by a specific label value and verify the event payload.
	ctx.Step(`^querying Loki by label "([^"]*)" = "([^"]*)" should return the marker event within (\d+) seconds$`,
		func(label, value string, secs int) error {
			return assertLokiQueryByLabel(tc, label, value, time.Duration(secs)*time.Second)
		})

	// Query by label and verify exact payload fields.
	ctx.Step(`^querying Loki by label "([^"]*)" = "([^"]*)" should return an event with:$`,
		func(label, value string, table *godog.Table) error {
			return assertLokiQueryByLabelWithPayload(tc, label, value, table)
		})

	// Negative: query by a label value and verify NO events match.
	ctx.Step(`^querying Loki by label "([^"]*)" = "([^"]*)" should return no events within (\d+) seconds$`,
		func(label, value string, secs int) error {
			return assertLokiQueryByLabelEmpty(tc, label, value, time.Duration(secs)*time.Second)
		})
}

func registerLokiThenLabelSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^the loki stream should have label "([^"]*)" with value "([^"]*)"$`, func(label, value string) error {
		return assertLokiStreamLabel(tc, label, value)
	})

	ctx.Step(`^the loki stream should not have label "([^"]*)"$`, func(label string) error {
		return assertLokiStreamLabelAbsent(tc, label)
	})
}

func registerLokiThenErrorSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^the loki construction should fail with an error containing "([^"]*)"$`, func(substr string) error {
		if tc.LastErr == nil {
			return fmt.Errorf("expected construction error containing %q but got nil", substr)
		}
		if !strings.Contains(tc.LastErr.Error(), substr) {
			return fmt.Errorf("expected error containing %q, got: %s", substr, tc.LastErr.Error())
		}
		return nil
	})

	ctx.Step(`^the loki construction should succeed$`, func() error {
		if tc.LastErr != nil {
			return fmt.Errorf("expected loki construction to succeed, got: %w", tc.LastErr)
		}
		return nil
	})
}

// ---------------------------------------------------------------------------
// Helpers — construction
// ---------------------------------------------------------------------------

// applyLokiTestDefaults fills zero-value config fields with BDD test defaults.
func applyLokiTestDefaults(tc *AuditTestContext, cfg *loki.Config) {
	if cfg.URL == "" {
		cfg.URL = tc.LokiURL + "/loki/api/v1/push"
	}
	cfg.AllowInsecureHTTP = true
	cfg.AllowPrivateRanges = true

	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.FlushInterval == 0 {
		cfg.FlushInterval = 200 * time.Millisecond
	}
	if cfg.BatchSize == 0 {
		cfg.BatchSize = 1
	}
	if cfg.MaxRetries == 0 {
		cfg.MaxRetries = 3
	}
	if cfg.BufferSize == 0 {
		cfg.BufferSize = 1000
	}
	if cfg.TenantID == "" {
		cfg.TenantID = defaultLokiTenant
	}
	// Do NOT set cfg.Gzip here — let each step control it.
	// The default zero value (false) is overridden by individual steps.

	if cfg.Labels.Static == nil {
		cfg.Labels.Static = make(map[string]string)
	}
	cfg.Labels.Static["test_suite"] = "bdd"
}

func createLokiAuditor(tc *AuditTestContext, cfg *loki.Config) error {
	applyLokiTestDefaults(tc, cfg)

	out, err := loki.New(cfg, nil, loki.WithFrameworkContext(audit.FrameworkContext{
		AppName: "bdd-audit",
		Host:    "bdd-host",
	}))
	if err != nil {
		return fmt.Errorf("create loki output: %w", err)
	}
	tc.AddCleanup(func() { _ = out.Close() })

	auditor, err := audit.New(
		audit.WithTaxonomy(tc.Taxonomy),
		audit.WithAppName("bdd-audit"),
		audit.WithHost("bdd-host"),
		audit.WithOutputs(out),
	)
	if err != nil {
		return fmt.Errorf("create auditor: %w", err)
	}
	tc.Auditor = auditor
	tc.AddCleanup(func() { _ = auditor.Close() })
	return nil
}

func tryCreateLokiOutput(tc *AuditTestContext, cfg *loki.Config) error {
	out, err := loki.New(cfg, nil)
	if out != nil {
		tc.AddCleanup(func() { _ = out.Close() })
	}
	tc.LastErr = err
	return nil
}

// ---------------------------------------------------------------------------
// Helpers — Loki query
// ---------------------------------------------------------------------------

type lokiBDDQueryResult struct {
	Status string `json:"status"`
	Data   struct {
		ResultType string `json:"resultType"`
		Result     []struct {
			Stream map[string]string `json:"stream"`
			Values [][]string        `json:"values"`
		} `json:"result"`
	} `json:"data"`
}

func queryLokiBDD(tc *AuditTestContext, logql, tenant string) (lokiBDDQueryResult, error) {
	now := time.Now()
	params := url.Values{
		"query": {logql},
		"start": {fmt.Sprintf("%d", now.Add(-5*time.Minute).UnixNano())},
		"end":   {fmt.Sprintf("%d", now.Add(1*time.Minute).UnixNano())},
		"limit": {"1000"},
	}

	lokiBase := tc.LokiURL
	if lokiBase == "" {
		lokiBase = "http://localhost:3100"
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		lokiBase+"/loki/api/v1/query_range?"+params.Encode(), http.NoBody)
	if err != nil {
		return lokiBDDQueryResult{}, fmt.Errorf("build query request: %w", err)
	}
	if tenant == "" {
		tenant = defaultLokiTenant
	}
	req.Header.Set("X-Scope-OrgID", tenant)

	resp, err := lokiQueryClient.Do(req)
	if err != nil {
		return lokiBDDQueryResult{}, fmt.Errorf("loki query: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return lokiBDDQueryResult{}, fmt.Errorf("read loki response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return lokiBDDQueryResult{}, fmt.Errorf("loki query returned %d: %s", resp.StatusCode, string(body))
	}

	var result lokiBDDQueryResult
	if err := json.Unmarshal(body, &result); err != nil {
		return lokiBDDQueryResult{}, fmt.Errorf("parse loki response: %w", err)
	}
	return result, nil
}

func countLokiLines(result lokiBDDQueryResult) int {
	n := 0
	for _, s := range result.Data.Result {
		n += len(s.Values)
	}
	return n
}

// ---------------------------------------------------------------------------
// Helpers — assertions
// ---------------------------------------------------------------------------

//nolint:gocritic // sprintfQuotedString: LogQL requires literal quotes
func assertLokiContainsMarker(tc *AuditTestContext, timeout time.Duration) error {
	m := tc.Markers["default"]
	if m == "" {
		return fmt.Errorf("no default marker set")
	}
	logql := fmt.Sprintf(`{test_suite="bdd"} |= "%s"`, m)
	return pollLoki(tc, logql, defaultLokiTenant, 1, timeout)
}

//nolint:gocritic // sprintfQuotedString: LogQL requires literal quotes
func assertLokiContainsMarkerForTenant(tc *AuditTestContext, tenant string, timeout time.Duration) error {
	m := tc.Markers["default"]
	if m == "" {
		return fmt.Errorf("no default marker set")
	}
	logql := fmt.Sprintf(`{test_suite="bdd"} |= "%s"`, m)
	return pollLoki(tc, logql, tenant, 1, timeout)
}

//nolint:gocritic // sprintfQuotedString: LogQL requires literal quotes
func assertLokiMarkerAbsentForTenant(tc *AuditTestContext, tenant string, timeout time.Duration) error {
	m := tc.Markers["default"]
	if m == "" {
		return fmt.Errorf("no default marker set")
	}
	logql := fmt.Sprintf(`{test_suite="bdd"} |= "%s"`, m)

	// Poll for the timeout — if events appear, that's a failure.
	deadline := time.After(timeout)
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		result, err := queryLokiBDD(tc, logql, tenant)
		if err == nil && countLokiLines(result) > 0 {
			return fmt.Errorf("tenant %q should NOT contain marker %s but found %d events", tenant, m, countLokiLines(result))
		}
		select {
		case <-deadline:
			return nil // timeout without finding events = success
		case <-tick.C:
		}
	}
}

//nolint:gocritic // sprintfQuotedString: LogQL requires literal quotes
func assertLokiEventCount(tc *AuditTestContext, n int, timeout time.Duration) error {
	m := tc.Markers["default"]
	if m == "" {
		return fmt.Errorf("no default marker set — use a step that sets tc.Markers[\"default\"]")
	}
	logql := fmt.Sprintf(`{test_suite="bdd"} |= "%s"`, m)
	return pollLoki(tc, logql, defaultLokiTenant, n, timeout)
}

//nolint:gocritic // sprintfQuotedString: LogQL requires literal quotes
func assertLokiStreamLabel(tc *AuditTestContext, label, value string) error {
	m := tc.Markers["default"]
	if m == "" {
		return fmt.Errorf("no default marker set")
	}
	logql := fmt.Sprintf(`{test_suite="bdd"} |= "%s"`, m)
	result, err := queryLokiBDD(tc, logql, defaultLokiTenant)
	if err != nil {
		return err
	}
	// Find the stream that contains our marker and check its labels.
	for _, s := range result.Data.Result {
		for _, v := range s.Values {
			if len(v) >= 2 && strings.Contains(v[1], m) {
				got, ok := s.Stream[label]
				if ok && got == value {
					return nil
				}
				return fmt.Errorf("stream with marker has label %s=%q, want %q (stream labels: %v)",
					label, got, value, s.Stream)
			}
		}
	}
	return fmt.Errorf("no stream found containing marker %s with label %s=%q", m, label, value)
}

//nolint:gocritic // sprintfQuotedString: LogQL requires literal quotes
func assertLokiStreamLabelAbsent(tc *AuditTestContext, label string) error {
	m := tc.Markers["default"]
	if m == "" {
		return fmt.Errorf("no default marker set")
	}
	logql := fmt.Sprintf(`{test_suite="bdd"} |= "%s"`, m)
	result, err := queryLokiBDD(tc, logql, defaultLokiTenant)
	if err != nil {
		return err
	}
	for _, s := range result.Data.Result {
		if _, ok := s.Stream[label]; ok {
			return fmt.Errorf("stream should NOT have label %q but it does", label)
		}
	}
	return nil
}

//nolint:gocritic // sprintfQuotedString: LogQL requires literal quotes
func assertLokiEventField(tc *AuditTestContext, field, value string) error {
	m := tc.Markers["default"]
	if m == "" {
		return fmt.Errorf("no default marker set")
	}
	logql := fmt.Sprintf(`{test_suite="bdd"} |= "%s"`, m)
	result, err := queryLokiBDD(tc, logql, defaultLokiTenant)
	if err != nil {
		return err
	}
	for _, s := range result.Data.Result {
		for _, v := range s.Values {
			if len(v) < 2 {
				continue
			}
			var parsed map[string]any
			if err := json.Unmarshal([]byte(v[1]), &parsed); err != nil {
				continue
			}
			if got, ok := parsed[field]; ok && fmt.Sprintf("%v", got) == value {
				return nil
			}
		}
	}
	return fmt.Errorf("no event found with field %s=%q", field, value)
}

// assertLokiCompletePayload verifies that every field in the Gherkin table
// matches the actual JSON log line retrieved from Loki. This is the
// COMPLETE payload assertion — every sent field must be verified.
//
//nolint:gocritic // sprintfQuotedString: LogQL requires literal quotes
func assertLokiCompletePayload(tc *AuditTestContext, table *godog.Table) error {
	m := tc.Markers["default"]
	if m == "" {
		return fmt.Errorf("no default marker set")
	}
	logql := fmt.Sprintf(`{test_suite="bdd"} |= "%s"`, m)
	result, err := queryLokiBDD(tc, logql, defaultLokiTenant)
	if err != nil {
		return err
	}
	return verifyPayloadInResult(result, m, table)
}

// verifyPayloadInResult finds the event with the marker and verifies
// every field in the Gherkin table matches the parsed JSON.
func verifyPayloadInResult(result lokiBDDQueryResult, m string, table *godog.Table) error {
	for _, s := range result.Data.Result {
		for _, v := range s.Values {
			if len(v) < 2 || !strings.Contains(v[1], m) {
				continue
			}
			var parsed map[string]any
			if err := json.Unmarshal([]byte(v[1]), &parsed); err != nil {
				return fmt.Errorf("loki event JSON is corrupt: %w\nraw: %s", err, v[1])
			}
			return verifyFieldsMatch(parsed, v[1], table)
		}
	}
	return fmt.Errorf("no event found containing marker %s", m)
}

// verifyFieldsMatch checks every row in the Gherkin table against the
// parsed JSON payload. Reports ALL mismatches, not just the first.
func verifyFieldsMatch(parsed map[string]any, raw string, table *godog.Table) error {
	var mismatches []string
	for i, row := range table.Rows {
		if i == 0 || len(row.Cells) < 2 {
			continue
		}
		field := row.Cells[0].Value
		expected := row.Cells[1].Value

		got, ok := parsed[field]
		if !ok {
			mismatches = append(mismatches, fmt.Sprintf("field %q: MISSING", field))
			continue
		}
		if fmt.Sprintf("%v", got) != expected {
			mismatches = append(mismatches, fmt.Sprintf("field %q: want %q, got %q", field, expected, fmt.Sprintf("%v", got)))
		}
	}
	if len(mismatches) > 0 {
		return fmt.Errorf("payload verification failed:\n  %s\nfull payload: %s",
			strings.Join(mismatches, "\n  "), raw)
	}
	return nil
}

//nolint:gocritic // sprintfQuotedString: LogQL requires literal quotes
func assertLokiStreamExists(tc *AuditTestContext, eventType string, timeout time.Duration) error {
	// Query by event_type + test_suite label. Don't filter by marker
	// since multi-event-type scenarios may have different markers per event.
	logql := fmt.Sprintf(`{test_suite="bdd",event_type="%s"}`, eventType)
	return pollLoki(tc, logql, defaultLokiTenant, 1, timeout)
}

func pollLoki(tc *AuditTestContext, logql, tenant string, minCount int, timeout time.Duration) error {
	deadline := time.After(timeout)
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	var lastCount int
	for {
		result, err := queryLokiBDD(tc, logql, tenant)
		if err == nil {
			lastCount = countLokiLines(result)
			if lastCount >= minCount {
				return nil
			}
		}
		select {
		case <-deadline:
			return fmt.Errorf("timed out: wanted %d events, got %d (query: %s)", minCount, lastCount, logql)
		case <-tick.C:
		}
	}
}

// ---------------------------------------------------------------------------
// Label query assertions — prove labels work as search criteria
// ---------------------------------------------------------------------------

// assertLokiQueryByLabel queries Loki using a specific label selector
// and verifies the marker event is found. This proves the label is
// indexed and usable as a search criterion.
//
//nolint:gocritic // sprintfQuotedString: LogQL requires literal quotes
func assertLokiQueryByLabel(tc *AuditTestContext, label, value string, timeout time.Duration) error {
	m := tc.Markers["default"]
	if m == "" {
		return fmt.Errorf("no default marker set")
	}
	// Query using ONLY the label as the selector — not the marker.
	// The marker is used only to find our specific event in the results.
	logql := fmt.Sprintf(`{test_suite="bdd",%s="%s"} |= "%s"`, label, value, m)
	return pollLoki(tc, logql, defaultLokiTenant, 1, timeout)
}

// assertLokiQueryByLabelWithPayload queries by label and verifies the
// complete payload of the found event.
//
//nolint:gocritic // sprintfQuotedString: LogQL requires literal quotes
func assertLokiQueryByLabelWithPayload(tc *AuditTestContext, label, value string, table *godog.Table) error {
	// Query using ONLY the label selector — proving the label works as a filter.
	logql := fmt.Sprintf(`{test_suite="bdd",%s="%s"}`, label, value)

	// Poll until at least one event appears.
	deadline := time.After(15 * time.Second)
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		result, err := queryLokiBDD(tc, logql, defaultLokiTenant)
		if err == nil && countLokiLines(result) > 0 {
			// Find THIS scenario's event by scanning for any known marker,
			// then verify its payload. This avoids cross-pollution from other scenarios.
			return verifyScenarioEventPayload(tc, result, table)
		}
		select {
		case <-deadline:
			return fmt.Errorf("no events found querying by %s=%q", label, value)
		case <-tick.C:
		}
	}
}

// verifyScenarioEventPayload finds an event belonging to this scenario
// (by checking all known markers) and verifies the payload table.
func verifyScenarioEventPayload(tc *AuditTestContext, result lokiBDDQueryResult, table *godog.Table) error {
	for _, s := range result.Data.Result {
		for _, v := range s.Values {
			if len(v) < 2 {
				continue
			}
			if !eventBelongsToScenario(tc, v[1]) {
				continue
			}
			var parsed map[string]any
			if err := json.Unmarshal([]byte(v[1]), &parsed); err != nil {
				return fmt.Errorf("loki event JSON is corrupt: %w\nraw: %s", err, v[1])
			}
			return verifyFieldsMatch(parsed, v[1], table)
		}
	}
	return fmt.Errorf("no event belonging to this scenario found in label query results")
}

// eventBelongsToScenario checks if a log line contains any marker from
// the current scenario's marker set.
func eventBelongsToScenario(tc *AuditTestContext, line string) bool {
	for _, m := range tc.Markers {
		if strings.Contains(line, m) {
			return true
		}
	}
	return false
}

// assertLokiQueryByLabelEmpty queries by label and verifies NO events match.
//
//nolint:gocritic // sprintfQuotedString: LogQL requires literal quotes
func assertLokiQueryByLabelEmpty(tc *AuditTestContext, label, value string, timeout time.Duration) error {
	logql := fmt.Sprintf(`{test_suite="bdd",%s="%s"}`, label, value)
	deadline := time.After(timeout)
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		result, err := queryLokiBDD(tc, logql, defaultLokiTenant)
		if err == nil && countLokiLines(result) > 0 {
			return fmt.Errorf("expected no events for %s=%q but found %d", label, value, countLokiLines(result))
		}
		select {
		case <-deadline:
			return nil // timeout without finding events = success
		case <-tick.C:
		}
	}
}
