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
	"strings"
	"time"

	"github.com/cucumber/godog"

	"github.com/axonops/audit"
	"github.com/axonops/audit/syslog"
)

// severityTaxonomyYAML defines events with explicit severity levels
// for testing the audit-severity-to-syslog-severity mapping. Includes
// boundary values at each mapping band edge to catch off-by-one bugs.
const severityTaxonomyYAML = `
version: 1

categories:
  write:
    severity: 5
    events:
      - sev5_event
      - sev4_event
      - sev6_event
      - sev7_event
  security:
    severity: 8
    events:
      - sev8_event
      - sev9_event
      - sev10_event
      - sev1_event
      - sev3_event
      - sev0_event

events:
  sev0_event:
    severity: 0
    fields:
      outcome: {required: true}
      actor_id: {required: true}
      marker: {}
  sev1_event:
    severity: 1
    fields:
      outcome: {required: true}
      actor_id: {required: true}
      marker: {}
  sev3_event:
    severity: 3
    fields:
      outcome: {required: true}
      actor_id: {required: true}
      marker: {}
  sev4_event:
    severity: 4
    fields:
      outcome: {required: true}
      actor_id: {required: true}
      marker: {}
  sev5_event:
    fields:
      outcome: {required: true}
      actor_id: {required: true}
      marker: {}
  sev6_event:
    severity: 6
    fields:
      outcome: {required: true}
      actor_id: {required: true}
      marker: {}
  sev7_event:
    severity: 7
    fields:
      outcome: {required: true}
      actor_id: {required: true}
      marker: {}
  sev8_event:
    fields:
      outcome: {required: true}
      actor_id: {required: true}
      marker: {}
  sev9_event:
    severity: 9
    fields:
      outcome: {required: true}
      actor_id: {required: true}
      marker: {}
  sev10_event:
    severity: 10
    fields:
      outcome: {required: true}
      actor_id: {required: true}
      marker: {}
`

func registerSyslogSeveritySteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	registerSyslogSeverityGivenSteps(ctx, tc)
	registerSyslogSeverityWhenSteps(ctx, tc)
	registerSyslogSeverityThenSteps(ctx, tc)
}

// sensitivityTaxonomyYAML defines events with sensitivity-labelled
// fields for testing field stripping through syslog output.
const sensitivityTaxonomyYAML = `
version: 1

sensitivity:
  labels:
    pii:
      fields: [email]

categories:
  write:
    events:
      - user_create

events:
  user_create:
    fields:
      outcome: {required: true}
      actor_id: {required: true}
      marker: {}
      email: {}
`

func registerSyslogSeverityGivenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^a severity test taxonomy$`, func() error {
		tax, err := audit.ParseTaxonomyYAML([]byte(severityTaxonomyYAML))
		if err != nil {
			return fmt.Errorf("parse severity taxonomy: %w", err)
		}
		tc.Taxonomy = tax
		return nil
	})

	ctx.Step(`^a routing taxonomy$`, func() error {
		// Reuse the standard taxonomy which has write and security categories.
		tax, err := audit.ParseTaxonomyYAML([]byte(standardTaxonomyYAML))
		if err != nil {
			return fmt.Errorf("parse routing taxonomy: %w", err)
		}
		tc.Taxonomy = tax
		return nil
	})

	ctx.Step(`^a sensitivity test taxonomy$`, func() error {
		tax, err := audit.ParseTaxonomyYAML([]byte(sensitivityTaxonomyYAML))
		if err != nil {
			return fmt.Errorf("parse sensitivity taxonomy: %w", err)
		}
		tc.Taxonomy = tax
		return nil
	})

	ctx.Step(`^an auditor with syslog output on "([^"]*)" to "([^"]*)" and HMAC enabled with salt "([^"]*)" version "([^"]*)" hash "([^"]*)"$`,
		func(network, address, salt, version, hash string) error {
			return createSyslogAuditorWithHMAC(tc, &syslog.Config{
				Network: network, Address: address,
			}, salt, version, hash)
		})

	ctx.Step(`^an auditor with syslog output on "([^"]*)" to "([^"]*)" excluding labels "([^"]*)"$`,
		func(network, address, labels string) error {
			excludeLabels := strings.Split(labels, ",")
			for i := range excludeLabels {
				excludeLabels[i] = strings.TrimSpace(excludeLabels[i])
			}
			return createSyslogAuditorWithExcludeLabels(tc, &syslog.Config{
				Network: network, Address: address,
			}, excludeLabels)
		})

	ctx.Step(`^an auditor with syslog output on "([^"]*)" to "([^"]*)" routed to exclude "([^"]*)"$`,
		func(network, address, category string) error {
			return createSyslogAuditorWithRoute(tc, &syslog.Config{
				Network: network, Address: address,
			}, &audit.EventRoute{
				ExcludeCategories: []string{category},
			})
		})

	ctx.Step(`^an auditor with syslog output on "([^"]*)" to "([^"]*)" using CEF formatter$`,
		func(network, address string) error {
			return createSyslogAuditorWithFormatter(tc, &syslog.Config{
				Network: network, Address: address,
			}, &audit.CEFFormatter{
				Vendor: "BDDTest", Product: "Audit", Version: "1.0",
			})
		})

	ctx.Step(`^an auditor with syslog output on "([^"]*)" to "([^"]*)" routed to include only "([^"]*)"$`,
		func(network, address, category string) error {
			return createSyslogAuditorWithRoute(tc, &syslog.Config{
				Network: network, Address: address,
			}, &audit.EventRoute{
				IncludeCategories: includeCats(category),
			})
		})
}

func registerSyslogSeverityWhenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^I audit event "([^"]*)" with fields and marker "([^"]*)":$`,
		func(eventType, markerName string, table *godog.Table) error {
			fields := audit.Fields{}
			for _, row := range table.Rows[1:] {
				fields[row.Cells[0].Value] = row.Cells[1].Value
			}
			m := marker("BDD")
			tc.Markers[markerName] = m
			fields["marker"] = m
			return tc.Auditor.AuditEvent(audit.NewEvent(eventType, fields))
		})
}

func registerSyslogSeverityThenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^the syslog line with the marker should contain PRI "([^"]*)"$`,
		func(pri string) error {
			m, ok := tc.Markers["default"]
			if !ok {
				return fmt.Errorf("no default marker set")
			}
			return assertSyslogMarkerLineContainsPRI(m, pri)
		})

	ctx.Step(`^the syslog line with "([^"]*)" should contain PRI "([^"]*)"$`,
		func(searchMarker, pri string) error {
			m, ok := tc.Markers[searchMarker]
			if !ok {
				m = searchMarker
			}
			return assertSyslogMarkerLineContainsPRI(m, pri)
		})

	ctx.Step(`^the syslog line with marker "([^"]*)" should contain "([^"]*)"$`,
		func(markerName, text string) error {
			m, ok := tc.Markers[markerName]
			if !ok {
				return fmt.Errorf("no marker named %q", markerName)
			}
			return assertSyslogLineContainsBoth(m, text)
		})

	ctx.Step(`^the syslog line with marker "([^"]*)" should not contain "([^"]*)"$`,
		func(markerName, text string) error {
			m, ok := tc.Markers[markerName]
			if !ok {
				return fmt.Errorf("no marker named %q", markerName)
			}
			return assertSyslogMarkerLineNotContains(m, text)
		})

	ctx.Step(`^the syslog line with marker "([^"]*)" should contain PRI "([^"]*)"$`,
		func(markerName, pri string) error {
			m, ok := tc.Markers[markerName]
			if !ok {
				return fmt.Errorf("no marker named %q", markerName)
			}
			return assertSyslogMarkerLineContainsPRI(m, pri)
		})

	ctx.Step(`^the syslog server should contain marker "([^"]*)" within (\d+) seconds$`,
		func(markerName string, timeout int) error {
			m, ok := tc.Markers[markerName]
			if !ok {
				return fmt.Errorf("no marker named %q", markerName)
			}
			return assertSyslogContains(m, time.Duration(timeout)*time.Second)
		})

	ctx.Step(`^the syslog server should not contain marker "([^"]*)" within (\d+) seconds$`,
		func(markerName string, timeout int) error {
			m, ok := tc.Markers[markerName]
			if !ok {
				return fmt.Errorf("no marker named %q", markerName)
			}
			return assertSyslogNotContains(m, time.Duration(timeout)*time.Second)
		})
}

// assertSyslogMarkerLineStartsWith finds the syslog line containing
// the marker and asserts it starts with the given prefix (typically
// an RFC 5424 PRI field like "<131>").
// assertSyslogMarkerLineContainsPRI finds the syslog line containing
// the marker and asserts it contains the RFC 5424 PRI field "<NNN>"
// where NNN is the expected priority value. The raw RFC 5424 message
// (including the <PRI> prefix) is preserved in syslog-ng's $MSG macro.
func assertSyslogMarkerLineContainsPRI(searchMarker, expectedPRI string) error {
	priToken := "<" + expectedPRI + ">"
	log := readSyslogLogFromDocker()
	for _, line := range strings.Split(log, "\n") {
		if strings.Contains(line, searchMarker) {
			if strings.Contains(line, priToken) {
				return nil
			}
			return fmt.Errorf("syslog line with marker %q does not contain PRI %q\nfull line: %s",
				searchMarker, priToken, strings.TrimSpace(line))
		}
	}
	return fmt.Errorf("no syslog line found with marker %q", searchMarker)
}

// assertSyslogNotContains verifies that the syslog log does NOT contain
// the given text within the timeout. This is used for routing exclusion
// tests where we need to confirm an event was NOT delivered.
func assertSyslogNotContains(text string, timeout time.Duration) error {
	// scenario-control delay (#559): we MUST wait the full timeout
	// before asserting absence — early-exit polling cannot prove "did
	// not arrive". This is a deliberate-delay site, not a busy-poll.
	time.Sleep(timeout)
	log := readSyslogLogFromDocker()
	if strings.Contains(log, text) {
		return fmt.Errorf("syslog unexpectedly contains %q", text)
	}
	return nil
}

// createSyslogAuditorWithFormatter creates a syslog auditor with a
// per-output formatter (e.g., CEF).
func createSyslogAuditorWithFormatter(tc *AuditTestContext, cfg *syslog.Config, formatter audit.Formatter) error {
	if cfg.Facility == "" {
		cfg.Facility = "local0"
	}
	out, err := syslog.New(cfg)
	if err != nil {
		tc.LastErr = err
		return nil //nolint:nilerr // scenario may assert on tc.LastErr
	}
	tc.AddCleanup(func() { _ = out.Close() })

	opts := []audit.Option{
		audit.WithTaxonomy(tc.Taxonomy),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(out, audit.WithOutputFormatter(formatter)),
	}
	opts = append(opts, tc.Options...)
	auditor, err := audit.New(opts...)
	if err != nil {
		return fmt.Errorf("create auditor: %w", err)
	}
	tc.Auditor = auditor
	tc.AddCleanup(func() { _ = auditor.Close() })
	return nil
}

// createSyslogAuditorWithHMAC creates a syslog auditor with per-output
// HMAC integrity enabled.
func createSyslogAuditorWithHMAC(tc *AuditTestContext, cfg *syslog.Config, salt, version, hash string) error {
	if cfg.Facility == "" {
		cfg.Facility = "local0"
	}
	out, err := syslog.New(cfg)
	if err != nil {
		tc.LastErr = err
		return nil //nolint:nilerr // scenario may assert on tc.LastErr
	}
	tc.AddCleanup(func() { _ = out.Close() })

	opts := []audit.Option{
		audit.WithTaxonomy(tc.Taxonomy),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(out, audit.WithHMAC(&audit.HMACConfig{
			Enabled: true,
			Salt: audit.HMACSalt{
				Version: version,
				Value:   []byte(salt),
			},
			Algorithm: hash,
		})),
	}
	opts = append(opts, tc.Options...)
	auditor, err := audit.New(opts...)
	if err != nil {
		return fmt.Errorf("create auditor: %w", err)
	}
	tc.Auditor = auditor
	tc.AddCleanup(func() { _ = auditor.Close() })
	return nil
}

// createSyslogAuditorWithExcludeLabels creates a syslog auditor with
// sensitivity label exclusions.
func createSyslogAuditorWithExcludeLabels(tc *AuditTestContext, cfg *syslog.Config, excludeLabels []string) error {
	if cfg.Facility == "" {
		cfg.Facility = "local0"
	}
	out, err := syslog.New(cfg)
	if err != nil {
		tc.LastErr = err
		return nil //nolint:nilerr // scenario may assert on tc.LastErr
	}
	tc.AddCleanup(func() { _ = out.Close() })

	opts := []audit.Option{
		audit.WithTaxonomy(tc.Taxonomy),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(out, audit.WithExcludeLabels(excludeLabels...)),
	}
	opts = append(opts, tc.Options...)
	auditor, err := audit.New(opts...)
	if err != nil {
		return fmt.Errorf("create auditor: %w", err)
	}
	tc.Auditor = auditor
	tc.AddCleanup(func() { _ = auditor.Close() })
	return nil
}

// assertSyslogMarkerLineNotContains finds the syslog line with the
// marker and asserts it does NOT contain the given text.
func assertSyslogMarkerLineNotContains(searchMarker, text string) error {
	log := readSyslogLogFromDocker()
	for _, line := range strings.Split(log, "\n") {
		if strings.Contains(line, searchMarker) {
			if strings.Contains(line, text) {
				return fmt.Errorf("syslog line with marker %q unexpectedly contains %q", searchMarker, text)
			}
			return nil
		}
	}
	return fmt.Errorf("no syslog line found with marker %q", searchMarker)
}

// createSyslogAuditorWithRoute creates a syslog auditor with a per-output
// event route.
func createSyslogAuditorWithRoute(tc *AuditTestContext, cfg *syslog.Config, route *audit.EventRoute) error {
	if cfg.Facility == "" {
		cfg.Facility = "local0"
	}
	out, err := syslog.New(cfg)
	if err != nil {
		tc.LastErr = err
		return nil //nolint:nilerr // scenario may assert on tc.LastErr
	}
	tc.AddCleanup(func() { _ = out.Close() })

	opts := []audit.Option{
		audit.WithTaxonomy(tc.Taxonomy),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(out, audit.WithRoute(route)),
	}
	opts = append(opts, tc.Options...)
	auditor, err := audit.New(opts...)
	if err != nil {
		return fmt.Errorf("create auditor: %w", err)
	}
	tc.Auditor = auditor
	tc.AddCleanup(func() { _ = auditor.Close() })
	return nil
}
