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

	"github.com/cucumber/godog"

	"github.com/axonops/audit"
)

// filteringTaxonomyYAML is a taxonomy with write and security categories,
// used by event filtering scenarios. All categories are enabled by default.
const filteringTaxonomyYAML = `
version: 1

categories:
  write:
    - user_create
    - user_update
  security:
    - auth_failure
    - permission_denied

events:
  user_create:
    fields:
      outcome: {required: true}
      actor_id: {required: true}
      marker: {}
  user_update:
    fields:
      outcome: {required: true}
      actor_id: {required: true}
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

func registerFilterSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	registerFilterGivenSteps(ctx, tc)
	registerFilterWhenSteps(ctx, tc)
	registerFilterThenSteps(ctx, tc)
}

func registerFilterGivenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^a taxonomy with categories "write" and "security"$`, func() error {
		tax, err := audit.ParseTaxonomyYAML([]byte(filteringTaxonomyYAML))
		if err != nil {
			return fmt.Errorf("parse filtering taxonomy: %w", err)
		}
		tc.Taxonomy = tax
		return nil
	})

	ctx.Step(`^I enable category "([^"]*)"$`, func(category string) error {
		tc.LastErr = tc.Auditor.EnableCategory(category)
		return nil
	})

	ctx.Step(`^I disable category "([^"]*)"$`, func(category string) error {
		tc.LastErr = tc.Auditor.DisableCategory(category)
		return nil
	})

	ctx.Step(`^I enable event "([^"]*)"$`, func(eventType string) error {
		tc.LastErr = tc.Auditor.EnableEvent(eventType)
		return nil
	})

	ctx.Step(`^I disable event "([^"]*)"$`, func(eventType string) error {
		tc.LastErr = tc.Auditor.DisableEvent(eventType)
		return nil
	})
}

func registerFilterWhenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^I try to enable category "([^"]*)"$`, func(category string) error {
		tc.LastErr = tc.Auditor.EnableCategory(category)
		return nil
	})

	ctx.Step(`^I try to disable category "([^"]*)"$`, func(category string) error {
		tc.LastErr = tc.Auditor.DisableCategory(category)
		return nil
	})

	ctx.Step(`^I try to enable event "([^"]*)"$`, func(eventType string) error {
		tc.LastErr = tc.Auditor.EnableEvent(eventType)
		return nil
	})

	ctx.Step(`^I try to disable event "([^"]*)"$`, func(eventType string) error {
		tc.LastErr = tc.Auditor.DisableEvent(eventType)
		return nil
	})
}

func registerFilterThenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^the operation should return an error matching:$`, func(doc *godog.DocString) error {
		expected := strings.TrimSpace(doc.Content)
		if tc.LastErr == nil {
			return fmt.Errorf("expected error:\n  %q\ngot: nil", expected)
		}
		if tc.LastErr.Error() != expected {
			return fmt.Errorf("expected error:\n  %q\ngot:\n  %q", expected, tc.LastErr.Error())
		}
		return nil
	})

	ctx.Step(`^the operation should return an error containing "([^"]*)"$`, func(substr string) error {
		if tc.LastErr == nil {
			return fmt.Errorf("expected error containing %q, got nil", substr)
		}
		if !strings.Contains(tc.LastErr.Error(), substr) {
			return fmt.Errorf("expected error containing %q, got: %w", substr, tc.LastErr)
		}
		return nil
	})

	// Sentinel wrapping check (#467). Proves the operation error is
	// discriminable via errors.Is, not just by string match.
	ctx.Step(`^the operation should return an error wrapping "([^"]*)"$`,
		func(sentinel string) error { return assertSentinelError(tc, sentinel) })
}
