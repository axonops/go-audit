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
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/cucumber/godog"

	"github.com/axonops/audit"
	"github.com/axonops/audit/file"
	"github.com/axonops/audit/syslog"
	"github.com/axonops/audit/webhook"
)

// routingTaxonomyYAML provides write, read, and security categories.
const routingTaxonomyYAML = `
version: 1
categories:
  write:
    - user_create
    - config_update
  read:
    - user_get
    - config_read
  security:
    - auth_failure
    - permission_denied
events:
  user_create:
    fields:
      outcome: {required: true}
      actor_id: {required: true}
      marker: {}
  config_update:
    fields:
      outcome: {required: true}
      actor_id: {required: true}
      marker: {}
  user_get:
    fields:
      outcome: {required: true}
      marker: {}
  config_read:
    fields:
      outcome: {required: true}
      marker: {}
  auth_failure:
    fields:
      outcome: {required: true}
      actor_id: {required: true}
      marker: {}
  permission_denied:
    fields:
      outcome: {required: true}
      actor_id: {required: true}
      marker: {}
`

// includeCats builds an EventRoute.IncludeCategories map from a list
// of category names with nil SeverityRange (the "no severity filter"
// shorthand). Used throughout the fanout step definitions to keep
// the call sites concise.
func includeCats(names ...string) map[string]*audit.SeverityRange {
	if len(names) == 0 {
		return nil
	}
	m := make(map[string]*audit.SeverityRange, len(names))
	for _, n := range names {
		m[n] = nil
	}
	return m
}

func registerFanoutSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	registerFanoutGivenSteps(ctx, tc)
	registerFanoutWhenSteps(ctx, tc)
	registerFanoutThenSteps(ctx, tc)
}

func registerFanoutGivenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	registerFanoutGivenOutputSteps(ctx, tc)
	registerFanoutGivenRoutingSteps(ctx, tc)
	registerFanoutGivenRuntimeSteps(ctx, tc)
	registerFanoutGivenSharedFmtSteps(ctx, tc)
	registerFanoutGivenMultiOutputSteps(ctx, tc)
}

func registerFanoutGivenOutputSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^an auditor with file and webhook outputs$`, func() error {
		return createFanoutAuditor(tc, true, false, true, nil, nil)
	})
	ctx.Step(`^an auditor with file and webhook outputs configured for batch size (\d+)$`, func(bs int) error {
		return createFanoutAuditor(tc, true, false, true, nil, &bs)
	})
	ctx.Step(`^an auditor with file and syslog outputs$`, func() error {
		return createFanoutAuditor(tc, true, true, false, nil, nil)
	})
	ctx.Step(`^an auditor with file, syslog, and webhook outputs$`, func() error {
		return createFanoutAuditor(tc, true, true, true, nil, nil)
	})
	ctx.Step(`^an auditor with file output and an error-returning output$`, func() error {
		return createErrorOutputAuditor(tc)
	})
	ctx.Step(`^an auditor with file output and a panicking output$`, func() error {
		return createPanicOutputAuditor(tc)
	})
	ctx.Step(`^an auditor with file output and a panicking formatter on a second output$`, func() error {
		return createPanicFormatterAuditor(tc)
	})
	ctx.Step(`^an auditor with file output using JSON and webhook output using CEF$`, func() error {
		cefFmt := &audit.CEFFormatter{Vendor: "Test", Product: "BDD", Version: "1.0"}
		return createFanoutAuditor(tc, true, false, true, cefFmt, nil)
	})
}

func registerFanoutGivenRoutingSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^a routing taxonomy with write, read, and security categories$`, func() error {
		tax, err := audit.ParseTaxonomyYAML([]byte(routingTaxonomyYAML))
		if err != nil {
			return fmt.Errorf("parse routing taxonomy: %w", err)
		}
		tc.Taxonomy = tax
		return nil
	})
	ctx.Step(`^an auditor with file receiving all events and webhook receiving only "([^"]*)"$`, func(cat string) error {
		return createRoutedAuditor(tc, &audit.EventRoute{IncludeCategories: includeCats(cat)})
	})
	ctx.Step(`^an auditor with file receiving all events and webhook including event types "([^"]*)"$`, func(types string) error {
		return createRoutedAuditor(tc, &audit.EventRoute{IncludeEventTypes: strings.Split(types, ",")})
	})
	ctx.Step(`^an auditor with file receiving all events and webhook excluding categories "([^"]*)"$`, func(cat string) error {
		return createRoutedAuditor(tc, &audit.EventRoute{ExcludeCategories: []string{cat}})
	})
	ctx.Step(`^an auditor with file receiving all events and webhook including categories "([^"]*)" and "([^"]*)"$`, func(cat1, cat2 string) error {
		return createRoutedAuditor(tc, &audit.EventRoute{IncludeCategories: includeCats(cat1, cat2)})
	})
	ctx.Step(`^an auditor with file receiving all events and webhook including categories "([^"]*)" and event types "([^"]*)"$`, func(cats, types string) error {
		return createRoutedAuditor(tc, &audit.EventRoute{
			IncludeCategories: includeCats(strings.Split(cats, ",")...),
			IncludeEventTypes: strings.Split(types, ","),
		})
	})
	ctx.Step(`^an auditor with file receiving all events and webhook excluding categories "([^"]*)" and "([^"]*)"$`, func(cat1, cat2 string) error {
		return createRoutedAuditor(tc, &audit.EventRoute{ExcludeCategories: []string{cat1, cat2}})
	})
	ctx.Step(`^an auditor with file receiving all events and webhook excluding categories "([^"]*)" and event types "([^"]*)"$`, func(cat, types string) error {
		return createRoutedAuditor(tc, &audit.EventRoute{
			ExcludeCategories: []string{cat},
			ExcludeEventTypes: strings.Split(types, ","),
		})
	})
	ctx.Step(`^an auditor with file receiving all events and webhook excluding event types "([^"]*)"$`, func(types string) error {
		return createRoutedAuditor(tc, &audit.EventRoute{ExcludeEventTypes: strings.Split(types, ",")})
	})
}

func registerFanoutGivenRuntimeSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^an auditor with file and webhook both receiving all events$`, func() error {
		return createRoutedAuditor(tc, nil) // nil route = all events
	})
	ctx.Step(`^I set the webhook output route to include only "([^"]*)"$`, func(cat string) error {
		// Webhook output name is "webhook:<host:port>" (from url.Parse).
		// tc.WebhookURL is "http://localhost:8080", so name is "webhook:localhost:8080".
		u := strings.TrimPrefix(tc.WebhookURL, "http://")
		u = strings.TrimPrefix(u, "https://")
		return tc.Auditor.SetOutputRoute(
			"webhook:"+u,
			&audit.EventRoute{IncludeCategories: includeCats(cat)},
		)
	})
}

func registerFanoutGivenSharedFmtSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^an auditor with two file outputs sharing the same formatter$`, func() error {
		return createSharedFormatterAuditor(tc)
	})
	ctx.Step(`^both files should contain identical content$`, func() error {
		return assertFilesIdentical(tc, "file-a", "file-b")
	})
}

func createSharedFormatterAuditor(tc *AuditTestContext) error {
	dir, err := tc.EnsureFileDir()
	if err != nil {
		return err
	}
	pathA := filepath.Join(dir, "a.log")
	pathB := filepath.Join(dir, "b.log")
	tc.FilePaths["file-a"] = pathA
	tc.FilePaths["file-b"] = pathB

	fA, err := file.New(&file.Config{Path: pathA})
	if err != nil {
		return fmt.Errorf("create file a: %w", err)
	}
	tc.AddCleanup(func() { _ = fA.Close() })
	fB, err := file.New(&file.Config{Path: pathB})
	if err != nil {
		return fmt.Errorf("create file b: %w", err)
	}
	tc.AddCleanup(func() { _ = fB.Close() })

	// Both outputs share the default JSON formatter (nil = auditor default).
	opts := []audit.Option{
		audit.WithTaxonomy(tc.Taxonomy),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(fA),
		audit.WithNamedOutput(fB),
	}
	auditor, err := audit.New(opts...)
	if err != nil {
		return fmt.Errorf("create auditor: %w", err)
	}
	tc.Auditor = auditor
	tc.AddCleanup(func() { _ = auditor.Close() })
	return nil
}

func assertFilesIdentical(tc *AuditTestContext, nameA, nameB string) error {
	rawA, err := readRawFile(tc, nameA)
	if err != nil {
		return fmt.Errorf("read %s: %w", nameA, err)
	}
	rawB, err := readRawFile(tc, nameB)
	if err != nil {
		return fmt.Errorf("read %s: %w", nameB, err)
	}
	if rawA != rawB {
		return fmt.Errorf("files %s and %s differ:\n  %s: %d bytes\n  %s: %d bytes",
			nameA, nameB, nameA, len(rawA), nameB, len(rawB))
	}
	return nil
}

func registerFanoutGivenMultiOutputSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^an auditor with two file outputs where security goes to file-a and write goes to file-b$`, func() error { return createDualFileRoutedAuditor(tc) })
	ctx.Step(`^an auditor with file getting all, syslog getting security, and webhook getting write$`, func() error { return createTripleRoutedAuditor(tc) })
	ctx.Step(`^I query the webhook output route$`, func() error { return queryWebhookRoute(tc) })
	ctx.Step(`^the route should include category "([^"]*)"$`, func(cat string) error { return assertRouteIncludesCategory(tc, cat) })
	ctx.Step(`^I try to set route for unknown output "([^"]*)"$`, func(name string) error {
		tc.LastErr = tc.Auditor.SetOutputRoute(name, &audit.EventRoute{IncludeCategories: includeCats("write")})
		return nil
	})
	ctx.Step(`^I clear the webhook output route$`, func() error {
		u := strings.TrimPrefix(tc.WebhookURL, "http://")
		u = strings.TrimPrefix(u, "https://")
		return tc.Auditor.ClearOutputRoute("webhook:" + u)
	})
	// Note: "I disable category" step is registered in filter_steps.go
	ctx.Step(`^file "([^"]*)" should contain "([^"]*)"$`, func(name, text string) error {
		return assertFileContainsText(tc, name, text)
	})
	ctx.Step(`^file "([^"]*)" should not contain "([^"]*)"$`, func(name, text string) error {
		raw, err := readRawFile(tc, name)
		if err != nil {
			return err
		}
		if strings.Contains(raw, text) {
			return fmt.Errorf("file %q unexpectedly contains %q", name, text)
		}
		return nil
	})
	ctx.Step(`^the file should not contain "([^"]*)"$`, func(text string) error {
		raw, err := readRawFile(tc, "default")
		if err != nil {
			return err
		}
		if strings.Contains(raw, text) {
			return fmt.Errorf("file unexpectedly contains %q", text)
		}
		return nil
	})
}

func registerFanoutWhenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^I audit (?:a|an) "([^"]*)" event in category "[^"]*" with marker "([^"]*)"$`, func(eventType, m string) error {
		return auditEventWithMarker(tc, eventType, m)
	})
	ctx.Step(`^I try to create an auditor with two syslog outputs to the same address$`, func() error {
		return tryDuplicateSyslogAddress(tc)
	})
	ctx.Step(`^I try to create an auditor with duplicate output names$`, func() error {
		return tryDuplicateOutputNames(tc)
	})
	ctx.Step(`^I try to create an auditor with two file outputs to the same path$`, func() error {
		return tryDuplicateFilePath(tc)
	})
	ctx.Step(`^I try to create an auditor with mixed include and exclude route$`, func() error {
		return tryMixedRoute(tc)
	})
	ctx.Step(`^I try to create an auditor with route referencing unknown category$`, func() error {
		return tryUnknownCategoryRoute(tc)
	})
	ctx.Step(`^I try to create an auditor with route referencing unknown event type$`, func() error {
		return tryUnknownEventTypeRoute(tc)
	})
}

func registerFanoutThenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^the file should contain the marker$`, func() error {
		m, ok := tc.Markers["default"]
		if !ok {
			return fmt.Errorf("no default marker set")
		}
		return assertFileContainsText(tc, "default", m)
	})
	ctx.Step(`^the file should contain "([^"]*)"$`, func(text string) error {
		return assertFileContainsText(tc, "default", text)
	})
	ctx.Step(`^the file should contain JSON format with "([^"]*)"$`, func(text string) error {
		return assertFileContainsText(tc, "default", text)
	})
	ctx.Step(`^the file should have no events$`, func() error {
		events, err := readFileEvents(tc, "default")
		if err != nil {
			return err
		}
		if len(events) > 0 {
			return fmt.Errorf("expected no events in file, got %d", len(events))
		}
		return nil
	})
}

// --- Extracted when-step helpers ---

func auditEventWithMarker(tc *AuditTestContext, eventType, m string) error {
	if tc.Auditor == nil {
		return fmt.Errorf("auditor is nil")
	}
	tc.Markers[m] = m
	fields := defaultRequiredFields(tc.Taxonomy, eventType)
	fields["marker"] = m
	tc.LastErr = tc.Auditor.AuditEvent(audit.NewEvent(eventType, fields))
	return nil
}

func tryDuplicateOutputNames(tc *AuditTestContext) error {
	dir, err := tc.EnsureFileDir()
	if err != nil {
		return err
	}
	f1, err := file.New(&file.Config{Path: filepath.Join(dir, "a.log")})
	if err != nil {
		return fmt.Errorf("create file a: %w", err)
	}
	tc.AddCleanup(func() { _ = f1.Close() })
	_, err = audit.New(
		audit.WithTaxonomy(tc.Taxonomy),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(f1, f1), // same output = duplicate name
	)
	tc.LastErr = err
	return nil
}

func tryDuplicateFilePath(tc *AuditTestContext) error {
	dir, err := tc.EnsureFileDir()
	if err != nil {
		return err
	}
	samePath := filepath.Join(dir, "same.log")
	f1, err := file.New(&file.Config{Path: samePath})
	if err != nil {
		return fmt.Errorf("create file 1: %w", err)
	}
	tc.AddCleanup(func() { _ = f1.Close() })
	f2, err := file.New(&file.Config{Path: samePath})
	if err != nil {
		return fmt.Errorf("create file 2: %w", err)
	}
	tc.AddCleanup(func() { _ = f2.Close() })
	_, err = audit.New(
		audit.WithTaxonomy(tc.Taxonomy),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(f1, f2),
	)
	tc.LastErr = err
	return nil
}

func tryMixedRoute(tc *AuditTestContext) error {
	dir, err := tc.EnsureFileDir()
	if err != nil {
		return err
	}
	f, err := file.New(&file.Config{Path: filepath.Join(dir, "mixed.log")})
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	tc.AddCleanup(func() { _ = f.Close() })
	_, err = audit.New(
		audit.WithTaxonomy(tc.Taxonomy),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(f, audit.WithRoute(&audit.EventRoute{
			IncludeCategories: includeCats("write"),
			ExcludeCategories: []string{"read"},
		})),
	)
	tc.LastErr = err
	return nil
}

func tryUnknownCategoryRoute(tc *AuditTestContext) error {
	dir, err := tc.EnsureFileDir()
	if err != nil {
		return err
	}
	f, err := file.New(&file.Config{Path: filepath.Join(dir, "unknown.log")})
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	tc.AddCleanup(func() { _ = f.Close() })
	_, err = audit.New(
		audit.WithTaxonomy(tc.Taxonomy),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(f, audit.WithRoute(&audit.EventRoute{
			IncludeCategories: includeCats("nonexistent"),
		})),
	)
	tc.LastErr = err
	return nil
}

func queryWebhookRoute(tc *AuditTestContext) error {
	u := strings.TrimPrefix(tc.WebhookURL, "http://")
	u = strings.TrimPrefix(u, "https://")
	route, err := tc.Auditor.OutputRoute("webhook:" + u)
	if err != nil {
		return fmt.Errorf("OutputRoute: %w", err)
	}
	tc.QueriedRoute = &route
	return nil
}

func assertRouteIncludesCategory(tc *AuditTestContext, cat string) error {
	if tc.QueriedRoute == nil {
		return fmt.Errorf("no route queried")
	}
	if _, ok := tc.QueriedRoute.IncludeCategories[cat]; ok {
		return nil
	}
	keys := make([]string, 0, len(tc.QueriedRoute.IncludeCategories))
	for k := range tc.QueriedRoute.IncludeCategories {
		keys = append(keys, k)
	}
	return fmt.Errorf("route does not include category %q (includes: %v)", cat, keys)
}

func tryDuplicateSyslogAddress(tc *AuditTestContext) error {
	s1, err := syslog.New(&syslog.Config{Network: "tcp", Address: "localhost:5514", Facility: "local0"})
	if err != nil {
		return fmt.Errorf("create syslog 1: %w", err)
	}
	tc.AddCleanup(func() { _ = s1.Close() })
	s2, err := syslog.New(&syslog.Config{Network: "tcp", Address: "localhost:5514", Facility: "local0"})
	if err != nil {
		return fmt.Errorf("create syslog 2: %w", err)
	}
	tc.AddCleanup(func() { _ = s2.Close() })
	_, err = audit.New(
		audit.WithTaxonomy(tc.Taxonomy),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(s1, s2),
	)
	tc.LastErr = err
	return nil
}

func tryUnknownEventTypeRoute(tc *AuditTestContext) error {
	dir, err := tc.EnsureFileDir()
	if err != nil {
		return err
	}
	f, err := file.New(&file.Config{Path: filepath.Join(dir, "unknown_evt.log")})
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	tc.AddCleanup(func() { _ = f.Close() })
	_, err = audit.New(
		audit.WithTaxonomy(tc.Taxonomy),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(f, audit.WithRoute(&audit.EventRoute{
			IncludeEventTypes: []string{"nonexistent_event"},
		})),
	)
	tc.LastErr = err
	return nil
}

// --- Internal helpers ---

func assertFileContainsText(tc *AuditTestContext, name, text string) error {
	raw, err := readRawFile(tc, name)
	if err != nil {
		return err
	}
	if !strings.Contains(raw, text) {
		return fmt.Errorf("file %q does not contain %q (length: %d bytes)", name, text, len(raw))
	}
	return nil
}

func createFanoutAuditor(tc *AuditTestContext, useFile, useSyslog, useWebhook bool, webhookFmt audit.Formatter, batchSize *int) error {
	opts := []audit.Option{
		audit.WithTaxonomy(tc.Taxonomy),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
	}

	if useFile {
		dir, err := tc.EnsureFileDir()
		if err != nil {
			return err
		}
		path := filepath.Join(dir, "audit.log")
		tc.FilePaths["default"] = path
		f, err := file.New(&file.Config{Path: path})
		if err != nil {
			return fmt.Errorf("create file output: %w", err)
		}
		tc.AddCleanup(func() { _ = f.Close() })
		opts = append(opts, audit.WithNamedOutput(f))
	}

	if useSyslog {
		s, err := syslog.New(&syslog.Config{
			Network: "tcp", Address: "localhost:5514",
			Facility: "local0", AppName: "bdd-fanout",
		})
		if err != nil {
			return fmt.Errorf("create syslog output: %w", err)
		}
		tc.AddCleanup(func() { _ = s.Close() })
		opts = append(opts, audit.WithNamedOutput(s))
	}

	if useWebhook {
		bs := 1
		if batchSize != nil {
			bs = *batchSize
		}
		w, err := webhook.New(&webhook.Config{
			URL: tc.WebhookURL + "/events", AllowInsecureHTTP: true,
			AllowPrivateRanges: true, BatchSize: bs,
			FlushInterval: 100 * time.Millisecond, Timeout: 5 * time.Second,
		}, nil)
		if err != nil {
			return fmt.Errorf("create webhook output: %w", err)
		}
		tc.AddCleanup(func() { _ = w.Close() })
		opts = append(opts, audit.WithNamedOutput(w, audit.WithOutputFormatter(webhookFmt)))
	}
	auditor, err := audit.New(opts...)
	if err != nil {
		tc.LastErr = err
		return nil //nolint:nilerr // scenario may assert on tc.LastErr
	}
	tc.Auditor = auditor
	tc.AddCleanup(func() { _ = auditor.Close() })
	return nil
}

// errorOutput returns an error on every Write call.
type errorOutput struct{}

func (e *errorOutput) Write(_ []byte) error { return fmt.Errorf("intentional write error") }
func (e *errorOutput) Close() error         { return nil }
func (e *errorOutput) Name() string         { return "error-output" }

func createErrorOutputAuditor(tc *AuditTestContext) error {
	dir, err := tc.EnsureFileDir()
	if err != nil {
		return err
	}
	path := filepath.Join(dir, "audit.log")
	tc.FilePaths["default"] = path

	fileOut, err := file.New(&file.Config{Path: path})
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	tc.AddCleanup(func() { _ = fileOut.Close() })

	opts := []audit.Option{
		audit.WithTaxonomy(tc.Taxonomy),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(fileOut),
		audit.WithNamedOutput(&errorOutput{}),
	}
	auditor, err := audit.New(opts...)
	if err != nil {
		return fmt.Errorf("create auditor: %w", err)
	}
	tc.Auditor = auditor
	tc.AddCleanup(func() { _ = auditor.Close() })
	return nil
}

// panicOutput panics on every Write call.
type panicOutput struct{}

func (p *panicOutput) Write(_ []byte) error { panic("intentional panic in output.Write") }
func (p *panicOutput) Close() error         { return nil }
func (p *panicOutput) Name() string         { return "panic-output" }

func createPanicOutputAuditor(tc *AuditTestContext) error {
	dir, err := tc.EnsureFileDir()
	if err != nil {
		return err
	}
	path := filepath.Join(dir, "audit.log")
	tc.FilePaths["default"] = path

	fileOut, err := file.New(&file.Config{Path: path})
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	tc.AddCleanup(func() { _ = fileOut.Close() })

	opts := []audit.Option{
		audit.WithTaxonomy(tc.Taxonomy),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(fileOut),
		audit.WithNamedOutput(&panicOutput{}),
	}
	auditor, err := audit.New(opts...)
	if err != nil {
		return fmt.Errorf("create auditor: %w", err)
	}
	tc.Auditor = auditor
	tc.AddCleanup(func() { _ = auditor.Close() })
	return nil
}

// panicFormatter panics on every Format call.
type panicFormatter struct{}

func (p *panicFormatter) Format(_ time.Time, _ string, _ audit.Fields, _ *audit.EventDef, _ *audit.FormatOptions) ([]byte, error) {
	panic("intentional panic in formatter")
}

func (p *panicFormatter) ContentType() string { return "application/x-ndjson" }

// errorReturningFormatter returns an error on every Format call (no panic).
type errorReturningFormatter struct{}

func (e *errorReturningFormatter) Format(_ time.Time, _ string, _ audit.Fields, _ *audit.EventDef, _ *audit.FormatOptions) ([]byte, error) {
	return nil, fmt.Errorf("intentional format error")
}

func (e *errorReturningFormatter) ContentType() string { return "application/x-ndjson" }

// devNullOutput discards all writes.
type devNullOutput struct{}

func (d *devNullOutput) Write(_ []byte) error { return nil }
func (d *devNullOutput) Close() error         { return nil }
func (d *devNullOutput) Name() string         { return "devnull" }

func createPanicFormatterAuditor(tc *AuditTestContext) error {
	dir, err := tc.EnsureFileDir()
	if err != nil {
		return err
	}
	path := filepath.Join(dir, "audit.log")
	tc.FilePaths["default"] = path

	fileOut, err := file.New(&file.Config{Path: path})
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	tc.AddCleanup(func() { _ = fileOut.Close() })

	opts := []audit.Option{
		audit.WithTaxonomy(tc.Taxonomy),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(fileOut), // normal file
		audit.WithNamedOutput(&devNullOutput{}, audit.WithOutputFormatter(&panicFormatter{})), // panicking formatter
	}
	auditor, err := audit.New(opts...)
	if err != nil {
		return fmt.Errorf("create auditor: %w", err)
	}
	tc.Auditor = auditor
	tc.AddCleanup(func() { _ = auditor.Close() })
	return nil
}

func createDualFileRoutedAuditor(tc *AuditTestContext) error {
	dir, err := tc.EnsureFileDir()
	if err != nil {
		return err
	}
	secPath := filepath.Join(dir, "security.log")
	writePath := filepath.Join(dir, "write.log")
	tc.FilePaths["security"] = secPath
	tc.FilePaths["write"] = writePath

	secOut, err := file.New(&file.Config{Path: secPath})
	if err != nil {
		return fmt.Errorf("create security file: %w", err)
	}
	tc.AddCleanup(func() { _ = secOut.Close() })
	writeOut, err := file.New(&file.Config{Path: writePath})
	if err != nil {
		return fmt.Errorf("create write file: %w", err)
	}
	tc.AddCleanup(func() { _ = writeOut.Close() })

	opts := []audit.Option{
		audit.WithTaxonomy(tc.Taxonomy),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(secOut, audit.WithRoute(&audit.EventRoute{IncludeCategories: includeCats("security")})),
		audit.WithNamedOutput(writeOut, audit.WithRoute(&audit.EventRoute{IncludeCategories: includeCats("write")})),
	}
	auditor, err := audit.New(opts...)
	if err != nil {
		return fmt.Errorf("create auditor: %w", err)
	}
	tc.Auditor = auditor
	tc.AddCleanup(func() { _ = auditor.Close() })
	return nil
}

func createTripleRoutedAuditor(tc *AuditTestContext) error {
	dir, err := tc.EnsureFileDir()
	if err != nil {
		return err
	}
	path := filepath.Join(dir, "audit.log")
	tc.FilePaths["default"] = path

	fileOut, err := file.New(&file.Config{Path: path})
	if err != nil {
		return fmt.Errorf("create file output: %w", err)
	}
	tc.AddCleanup(func() { _ = fileOut.Close() })
	syslogOut, err := syslog.New(&syslog.Config{
		Network: "tcp", Address: "localhost:5514",
		Facility: "local0", AppName: "bdd-triple",
	})
	if err != nil {
		return fmt.Errorf("create syslog output: %w", err)
	}
	tc.AddCleanup(func() { _ = syslogOut.Close() })
	webhookOut, err := webhook.New(&webhook.Config{
		URL: tc.WebhookURL + "/events", AllowInsecureHTTP: true,
		AllowPrivateRanges: true, BatchSize: 1,
		FlushInterval: 100 * time.Millisecond, Timeout: 5 * time.Second,
	}, nil)
	if err != nil {
		return fmt.Errorf("create webhook output: %w", err)
	}
	tc.AddCleanup(func() { _ = webhookOut.Close() })

	opts := []audit.Option{
		audit.WithTaxonomy(tc.Taxonomy),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(fileOut), // all events
		audit.WithNamedOutput(syslogOut, audit.WithRoute(&audit.EventRoute{IncludeCategories: includeCats("security")})), // security only
		audit.WithNamedOutput(webhookOut, audit.WithRoute(&audit.EventRoute{IncludeCategories: includeCats("write")})),   // write only
	}
	auditor, err := audit.New(opts...)
	if err != nil {
		return fmt.Errorf("create auditor: %w", err)
	}
	tc.Auditor = auditor
	tc.AddCleanup(func() { _ = auditor.Close() })
	return nil
}

func createRoutedAuditor(tc *AuditTestContext, webhookRoute *audit.EventRoute) error {
	dir, err := tc.EnsureFileDir()
	if err != nil {
		return err
	}
	path := filepath.Join(dir, "audit.log")
	tc.FilePaths["default"] = path

	f, err := file.New(&file.Config{Path: path})
	if err != nil {
		return fmt.Errorf("create file output: %w", err)
	}
	tc.AddCleanup(func() { _ = f.Close() })
	w, err := webhook.New(&webhook.Config{
		URL: tc.WebhookURL + "/events", AllowInsecureHTTP: true,
		AllowPrivateRanges: true, BatchSize: 1,
		FlushInterval: 100 * time.Millisecond, Timeout: 5 * time.Second,
	}, nil)
	if err != nil {
		return fmt.Errorf("create webhook output: %w", err)
	}
	tc.AddCleanup(func() { _ = w.Close() })

	opts := []audit.Option{
		audit.WithTaxonomy(tc.Taxonomy),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(f),
		audit.WithNamedOutput(w, audit.WithRoute(webhookRoute)),
	}
	auditor, err := audit.New(opts...)
	if err != nil {
		tc.LastErr = err
		return nil //nolint:nilerr // scenario may assert on tc.LastErr
	}
	tc.Auditor = auditor
	tc.AddCleanup(func() { _ = auditor.Close() })
	return nil
}
