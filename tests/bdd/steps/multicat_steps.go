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
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/axonops/audit"
	"github.com/cucumber/godog"
)

// RegisterMultiCatSteps registers step definitions for multi-category
// event delivery and severity BDD scenarios.
func RegisterMultiCatSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	registerMultiCatTaxonomySteps(ctx, tc)
	registerMultiCatLoggerSteps(ctx, tc)
	registerMultiCatAssertionSteps(ctx, tc)
}

func registerMultiCatTaxonomySteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^a multi-category taxonomy$`, func() error {
		tax, err := audit.ParseTaxonomyYAML([]byte(`
version: 1
categories:
  security:
    - auth_failure
  compliance:
    - auth_failure
events:
  auth_failure:
    fields:
      outcome: {required: true}
      actor_id: {required: true}
  data_export:
    fields:
      outcome: {required: true}
`))
		if err != nil {
			return fmt.Errorf("parse multi-category taxonomy: %w", err)
		}
		tc.Taxonomy = tax
		return nil
	})

	ctx.Step(`^a multi-category severity taxonomy$`, func() error {
		tax, err := audit.ParseTaxonomyYAML([]byte(`
version: 1
categories:
  compliance:
    severity: 3
    events: [auth_failure]
  security:
    severity: 8
    events: [auth_failure]
events:
  auth_failure:
    fields:
      outcome: {required: true}
      actor_id: {required: true}
`))
		if err != nil {
			return fmt.Errorf("parse multi-category severity taxonomy: %w", err)
		}
		tc.Taxonomy = tax
		return nil
	})

	ctx.Step(`^a taxonomy where auth_failure has event severity (\d+) in category with severity (\d+)$`, func(eventSev, catSev int) error {
		tax, err := audit.ParseTaxonomyYAML([]byte(fmt.Sprintf(`
version: 1
categories:
  security:
    severity: %d
    events: [auth_failure]
events:
  auth_failure:
    severity: %d
    fields:
      outcome: {required: true}
      actor_id: {required: true}
`, catSev, eventSev)))
		if err != nil {
			return fmt.Errorf("parse severity taxonomy: %w", err)
		}
		tc.Taxonomy = tax
		return nil
	})
}

func registerMultiCatLoggerSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^an auditor with stdout output routed to include only "([^"]*)"$`, func(category string) error {
		return createMultiCatAuditor(tc, &audit.EventRoute{IncludeCategories: includeCats(category)}, nil)
	})

	ctx.Step(`^an auditor with stdout output routed to exclude "([^"]*)"$`, func(category string) error {
		return createMultiCatAuditor(tc, &audit.EventRoute{ExcludeCategories: []string{category}}, nil)
	})

	ctx.Step(`^an auditor with stdout output routed to include event type "([^"]*)"$`, func(eventType string) error {
		return createMultiCatAuditor(tc, &audit.EventRoute{IncludeEventTypes: []string{eventType}}, nil)
	})

	ctx.Step(`^an auditor with stdout output using CEF formatter$`, func() error {
		cefFmt := &audit.CEFFormatter{
			Vendor:  "Test",
			Product: "BDD",
			Version: "1.0",
		}
		return createMultiCatAuditor(tc, nil, cefFmt)
	})
}

func createMultiCatAuditor(tc *AuditTestContext, route *audit.EventRoute, formatter audit.Formatter) error {
	tc.StdoutBuf = &bytes.Buffer{}
	stdout, err := audit.NewStdoutOutput(audit.StdoutConfig{Writer: tc.StdoutBuf})
	if err != nil {
		return fmt.Errorf("create stdout: %w", err)
	}
	auditor, err := audit.New(
		audit.WithTaxonomy(tc.Taxonomy),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(stdout, audit.WithRoute(route), audit.WithOutputFormatter(formatter)),
	)
	if err != nil {
		return fmt.Errorf("create auditor: %w", err)
	}
	tc.Auditor = auditor
	return nil
}

func registerMultiCatAssertionSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	registerMultiCatCountSteps(ctx, tc)
	registerMultiCatContentSteps(ctx, tc)
	registerMultiCatCEFSteps(ctx, tc)
}

func registerMultiCatCountSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^the output should contain exactly (\d+) events?$`, func(expected int) error {
		if err := flushAuditor(tc); err != nil {
			return err
		}
		lines := nonEmptyLines(tc.StdoutBuf.String())
		if len(lines) != expected {
			return fmt.Errorf("expected %d events, got %d:\n%s", expected, len(lines), tc.StdoutBuf.String())
		}
		return nil
	})
}

func registerMultiCatContentSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^all delivered events should have event_type "([^"]*)"$`, func(et string) error {
		if err := flushAuditor(tc); err != nil {
			return err
		}
		return assertAllEventsHaveField(tc, "event_type", et)
	})

	ctx.Step(`^all delivered events should have JSON field "([^"]*)" equal to (\d+)$`, func(field string, expected int) error {
		if err := flushAuditor(tc); err != nil {
			return err
		}
		return assertAllEventsHaveNumericField(tc, field, expected)
	})
}

func registerMultiCatCEFSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^the CEF output severity should be (\d+)$`, func(expected int) error {
		if err := flushAuditor(tc); err != nil {
			return err
		}
		return assertMultiCatCEFSeverity(tc, expected)
	})
}

// flushAuditor closes the auditor to flush buffered events. Safe to
// call multiple times — subsequent calls are no-ops.
func flushAuditor(tc *AuditTestContext) error {
	if tc.Auditor != nil {
		if err := tc.Auditor.Close(); err != nil {
			return fmt.Errorf("close auditor: %w", err)
		}
		tc.Auditor = nil
	}
	return nil
}

func assertMultiCatCEFSeverity(tc *AuditTestContext, expected int) error {
	lines := nonEmptyLines(tc.StdoutBuf.String())
	for _, line := range lines {
		if !strings.HasPrefix(line, "CEF:") {
			continue
		}
		parts := strings.SplitN(line, "|", 8)
		if len(parts) < 8 {
			return fmt.Errorf("CEF line has fewer than 8 pipe-separated parts: %s", line)
		}
		sev, err := strconv.Atoi(parts[6])
		if err != nil {
			return fmt.Errorf("CEF severity is not an integer: %q", parts[6])
		}
		if sev != expected {
			return fmt.Errorf("CEF severity = %d, want %d", sev, expected)
		}
	}
	return nil
}

func assertAllEventsHaveField(tc *AuditTestContext, field, expected string) error {
	lines := nonEmptyLines(tc.StdoutBuf.String())
	for i, line := range lines {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			return fmt.Errorf("line %d: unmarshal: %w", i, err)
		}
		if got, _ := m[field].(string); got != expected {
			return fmt.Errorf("line %d: %s = %q, want %q", i, field, got, expected)
		}
	}
	return nil
}

func assertAllEventsHaveNumericField(tc *AuditTestContext, field string, expected int) error {
	lines := nonEmptyLines(tc.StdoutBuf.String())
	if len(lines) == 0 {
		return fmt.Errorf("no events delivered")
	}
	for i, line := range lines {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			return fmt.Errorf("line %d: unmarshal: %w", i, err)
		}
		val, ok := m[field]
		if !ok {
			return fmt.Errorf("line %d: field %q not found in JSON", i, field)
		}
		num, ok := val.(float64)
		if !ok {
			return fmt.Errorf("line %d: field %q is %T, not a number", i, field, val)
		}
		if int(num) != expected {
			return fmt.Errorf("line %d: field %q = %v, want %d", i, field, num, expected)
		}
	}
	return nil
}

// nonEmptyLines splits s by newlines and returns non-empty lines.
func nonEmptyLines(s string) []string {
	var lines []string
	for _, line := range strings.Split(s, "\n") {
		if strings.TrimSpace(line) != "" {
			lines = append(lines, line)
		}
	}
	return lines
}
