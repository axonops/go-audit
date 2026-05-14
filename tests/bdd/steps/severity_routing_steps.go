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
	"fmt"
	"strings"

	"github.com/axonops/audit"
	"github.com/cucumber/godog"
)

// registerSeverityRoutingSteps registers BDD step definitions for
// severity-based event routing scenarios.
func registerSeverityRoutingSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	registerSeverityTaxonomySteps(ctx, tc)
	registerSeverityLoggerSteps(ctx, tc)
	registerSeverityValidationSteps(ctx, tc)
	registerSeverityRuntimeSteps(ctx, tc)
}

func registerSeverityTaxonomySteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^a severity routing taxonomy$`, func() error {
		tax, err := audit.ParseTaxonomyYAML([]byte(`
version: 1
categories:
  security:
    severity: 8
    events: [auth_failure, permission_denied]
  write:
    severity: 4
    events: [user_create, config_update]
  read:
    severity: 2
    events: [user_get]
  critical:
    severity: 10
    events: [system_breach]
  info:
    severity: 1
    events: [health_check]
events:
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
  system_breach:
    fields:
      outcome: {required: true}
      actor_id: {required: true}
      marker: {}
  health_check:
    fields:
      outcome: {required: true}
      marker: {}
  custom_event:
    severity: 6
    fields:
      outcome: {required: true}
      marker: {}
`))
		if err != nil {
			return fmt.Errorf("parse severity routing taxonomy: %w", err)
		}
		tc.Taxonomy = tax
		return nil
	})
}

func registerSeverityLoggerSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^an auditor with stdout output routed with min_severity (\d+)$`, func(minSev int) error {
		return createSeverityRoutedAuditor(tc, &minSev, nil, nil, nil)
	})

	ctx.Step(`^an auditor with stdout output routed with max_severity (\d+)$`, func(maxSev int) error {
		return createSeverityRoutedAuditor(tc, nil, &maxSev, nil, nil)
	})

	ctx.Step(`^an auditor with stdout output routed with min_severity (\d+) and max_severity (\d+)$`, func(minSev, maxSev int) error {
		return createSeverityRoutedAuditor(tc, &minSev, &maxSev, nil, nil)
	})

	ctx.Step(`^an auditor with stdout output routed to include only "([^"]*)" with min_severity (\d+)$`, func(cat string, minSev int) error {
		// Per-category severity (#193): the min_severity is attached
		// to the category's filter, not to the route. Route-level
		// MinSeverity no longer applies to category matches.
		return createPerCategorySeverityRoutedAuditor(tc, cat, &minSev, nil)
	})

	ctx.Step(`^an auditor with stdout output routed to exclude "([^"]*)" with min_severity (\d+)$`, func(cat string, minSev int) error {
		exclude := []string{cat}
		return createSeverityRoutedAuditor(tc, &minSev, nil, nil, exclude)
	})

	ctx.Step(`^an auditor with named stdout output "([^"]*)" receiving all events$`, func(name string) error {
		tc.StdoutBuf = &bytes.Buffer{}
		stdout, err := audit.NewStdoutOutput(audit.StdoutConfig{Writer: tc.StdoutBuf})
		if err != nil {
			return fmt.Errorf("create stdout: %w", err)
		}
		auditor, err := audit.New(
			audit.WithTaxonomy(tc.Taxonomy),
			audit.WithAppName("test-app"),
			audit.WithHost("test-host"),
			audit.WithNamedOutput(audit.WrapOutput(stdout, name)),
			audit.WithSynchronousDelivery(),
		)
		if err != nil {
			return fmt.Errorf("create auditor: %w", err)
		}
		tc.Auditor = auditor
		return nil
	})

	// Note: "the auditor should be created successfully" is registered
	// in config_steps.go. Do not duplicate here.
}

func createSeverityRoutedAuditor(tc *AuditTestContext, minSev, maxSev *int, incCats, excludeCats []string) error {
	tc.StdoutBuf = &bytes.Buffer{}
	stdout, err := audit.NewStdoutOutput(audit.StdoutConfig{Writer: tc.StdoutBuf})
	if err != nil {
		return fmt.Errorf("create stdout: %w", err)
	}
	route := &audit.EventRoute{
		MinSeverity:       minSev,
		MaxSeverity:       maxSev,
		IncludeCategories: includeCats(incCats...),
		ExcludeCategories: excludeCats,
	}
	auditor, err := audit.New(
		audit.WithTaxonomy(tc.Taxonomy),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(stdout, audit.WithRoute(route)),
	)
	if err != nil {
		return fmt.Errorf("create auditor: %w", err)
	}
	tc.Auditor = auditor
	return nil
}

// createPerCategorySeverityRoutedAuditor builds an auditor whose
// single output uses a per-category SeverityRange filter for the
// named category (#193). Route-level MinSeverity/MaxSeverity are
// NOT set — the per-category bounds are authoritative for category
// matches.
func createPerCategorySeverityRoutedAuditor(tc *AuditTestContext, cat string, minSev, maxSev *int) error {
	tc.StdoutBuf = &bytes.Buffer{}
	stdout, err := audit.NewStdoutOutput(audit.StdoutConfig{Writer: tc.StdoutBuf})
	if err != nil {
		return fmt.Errorf("create stdout: %w", err)
	}
	route := &audit.EventRoute{
		IncludeCategories: map[string]*audit.SeverityRange{
			cat: {MinSeverity: minSev, MaxSeverity: maxSev},
		},
	}
	auditor, err := audit.New(
		audit.WithTaxonomy(tc.Taxonomy),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(stdout, audit.WithRoute(route)),
	)
	if err != nil {
		return fmt.Errorf("create auditor: %w", err)
	}
	tc.Auditor = auditor
	return nil
}

func registerSeverityValidationSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^I try to create an auditor with route min_severity (\-?\d+)$`, func(minSev int) error {
		return trySeverityLoggerCreation(tc, &minSev, nil)
	})

	ctx.Step(`^I try to create an auditor with route max_severity (\-?\d+)$`, func(maxSev int) error {
		return trySeverityLoggerCreation(tc, nil, &maxSev)
	})

	ctx.Step(`^I try to create an auditor with route min_severity (\d+) and max_severity (\d+)$`, func(minSev, maxSev int) error {
		return trySeverityLoggerCreation(tc, &minSev, &maxSev)
	})

	// Per-category validation (#193): per-category severity bounds
	// are attached to category map entries, not to the route.
	ctx.Step(`^I try to create an auditor with per-category route for "([^"]*)" min_severity (\-?\d+)$`,
		func(cat string, minSev int) error {
			return tryPerCategoryAuditorCreation(tc, cat, &minSev, nil)
		})
	ctx.Step(`^I try to create an auditor with per-category route for "([^"]*)" min_severity (\d+) and max_severity (\d+)$`,
		func(cat string, minSev, maxSev int) error {
			return tryPerCategoryAuditorCreation(tc, cat, &minSev, &maxSev)
		})

	ctx.Step(`^the auditor creation should fail with error containing "([^"]*)"$`, func(expected string) error {
		if tc.LastErr == nil {
			return fmt.Errorf("expected error containing %q, got nil", expected)
		}
		if !strings.Contains(tc.LastErr.Error(), expected) {
			return fmt.Errorf("error %q does not contain %q", tc.LastErr.Error(), expected)
		}
		return nil
	})
}

// tryPerCategoryAuditorCreation attempts to construct an auditor
// whose single output uses a per-category SeverityRange for the
// named category. The constructor error is captured for later
// assertion via the shared `the auditor creation should fail...`
// step.
func tryPerCategoryAuditorCreation(tc *AuditTestContext, cat string, minSev, maxSev *int) error {
	tc.StdoutBuf = &bytes.Buffer{}
	stdout, err := audit.NewStdoutOutput(audit.StdoutConfig{Writer: tc.StdoutBuf})
	if err != nil {
		return fmt.Errorf("create stdout: %w", err)
	}
	route := &audit.EventRoute{
		IncludeCategories: map[string]*audit.SeverityRange{
			cat: {MinSeverity: minSev, MaxSeverity: maxSev},
		},
	}
	auditor, lErr := audit.New(
		audit.WithTaxonomy(tc.Taxonomy),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(stdout, audit.WithRoute(route)),
	)
	tc.LastErr = lErr
	if auditor != nil {
		tc.Auditor = auditor
	}
	return nil
}

func trySeverityLoggerCreation(tc *AuditTestContext, minSev, maxSev *int) error {
	tc.StdoutBuf = &bytes.Buffer{}
	stdout, err := audit.NewStdoutOutput(audit.StdoutConfig{Writer: tc.StdoutBuf})
	if err != nil {
		return fmt.Errorf("create stdout: %w", err)
	}
	route := &audit.EventRoute{
		MinSeverity: minSev,
		MaxSeverity: maxSev,
	}
	auditor, lErr := audit.New(
		audit.WithTaxonomy(tc.Taxonomy),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(stdout, audit.WithRoute(route)),
	)
	tc.LastErr = lErr
	if auditor != nil {
		tc.Auditor = auditor
	}
	return nil
}

func registerSeverityRuntimeSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^I set output "([^"]*)" route to min_severity (\d+)$`, func(name string, minSev int) error {
		if tc.Auditor == nil {
			return fmt.Errorf("auditor not created")
		}
		route := &audit.EventRoute{MinSeverity: &minSev}
		return tc.Auditor.SetOutputRoute(name, route)
	})

	// Per-category runtime route change (#193).
	ctx.Step(`^I set output "([^"]*)" route to per-category "([^"]*)" with min_severity (\d+)$`,
		func(name, cat string, minSev int) error {
			if tc.Auditor == nil {
				return fmt.Errorf("auditor not created")
			}
			route := &audit.EventRoute{
				IncludeCategories: map[string]*audit.SeverityRange{
					cat: {MinSeverity: &minSev},
				},
			}
			return tc.Auditor.SetOutputRoute(name, route)
		})

	// Precedence assertion (#193): a route with a category in
	// IncludeCategories carrying a nil filter must deliver category
	// matches regardless of route-level MinSeverity.
	ctx.Step(`^a per-category route including "([^"]*)" with no severity AND route-level min_severity (\d+)$`,
		func(cat string, minSev int) error {
			tc.StdoutBuf = &bytes.Buffer{}
			stdout, err := audit.NewStdoutOutput(audit.StdoutConfig{Writer: tc.StdoutBuf})
			if err != nil {
				return fmt.Errorf("create stdout: %w", err)
			}
			route := &audit.EventRoute{
				IncludeCategories: map[string]*audit.SeverityRange{cat: nil},
				MinSeverity:       &minSev,
			}
			auditor, lErr := audit.New(
				audit.WithTaxonomy(tc.Taxonomy),
				audit.WithAppName("test-app"),
				audit.WithHost("test-host"),
				audit.WithNamedOutput(stdout, audit.WithRoute(route)),
			)
			if lErr != nil {
				return fmt.Errorf("create auditor: %w", lErr)
			}
			tc.Auditor = auditor
			return nil
		})
}
