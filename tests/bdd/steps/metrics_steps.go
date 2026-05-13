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
	"path/filepath"
	"strings"
	"time"

	"github.com/cucumber/godog"

	"github.com/axonops/audit"
	"github.com/axonops/audit/file"
	"github.com/axonops/audit/webhook"
)

func registerMetricsSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	registerMetricsGivenSteps(ctx, tc)
	registerMetricsWhenSteps(ctx, tc)
	registerMetricsThenSteps(ctx, tc)
}

func registerMetricsGivenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	registerMetricsGivenBasicSteps(ctx, tc)
	registerMetricsGivenAdvancedSteps(ctx, tc)
	registerMetricsGivenWebhookSteps(ctx, tc)
	registerMetricsGivenFilterSteps(ctx, tc)
}

func registerMetricsGivenBasicSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^mock metrics are configured$`, func() error {
		tc.MockMetrics = NewMockMetrics()
		return nil
	})

	ctx.Step(`^an auditor with stdout output and metrics$`, func() error {
		tc.Options = append(tc.Options, audit.WithMetrics(tc.MockMetrics))
		return createStdoutAuditor(tc)
	})

	ctx.Step(`^an auditor with stdout output and metrics in strict mode$`, func() error {
		tc.Options = append(tc.Options, audit.WithMetrics(tc.MockMetrics))
		return createStdoutAuditor(tc)
	})

	ctx.Step(`^an auditor with stdout output and metrics in warn mode$`, func() error {
		tc.Options = append(tc.Options, audit.WithMetrics(tc.MockMetrics))
		return createStdoutAuditorWithOpts(tc, audit.WithValidationMode(audit.ValidationWarn))
	})

	ctx.Step(`^an auditor with stdout output and metrics and buffer size (\d+)$`, func(bufSize int) error {
		tc.Options = append(tc.Options, audit.WithMetrics(tc.MockMetrics))
		return createStdoutAuditorWithOpts(tc, audit.WithQueueSize(bufSize))
	})

}

func registerMetricsGivenAdvancedSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^an auditor with file and stdout outputs and metrics$`, func() error {
		buf := &bytes.Buffer{}
		tc.StdoutBuf = buf

		stdoutOut, err := audit.NewStdoutOutput(audit.StdoutConfig{Writer: buf})
		if err != nil {
			return fmt.Errorf("create stdout: %w", err)
		}

		dir, err := tc.EnsureFileDir()
		if err != nil {
			return err
		}
		path := filepath.Join(dir, "metrics.log")
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
			audit.WithMetrics(tc.MockMetrics),
			audit.WithNamedOutput(stdoutOut),
			audit.WithNamedOutput(fileOut),
		}

		auditor, err := audit.New(opts...)
		if err != nil {
			return fmt.Errorf("create auditor: %w", err)
		}
		tc.Auditor = auditor
		tc.AddCleanup(func() { _ = auditor.Close() })
		return nil
	})

}

func registerMetricsGivenWebhookSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^an auditor with webhook output and metrics$`, func() error {
		// Pass nil for core metrics to the webhook output — it self-reports
		// delivery via DeliveryReporter. The core auditor's global metrics
		// (tc.MockMetrics) should NOT record for webhook because
		// ReportsDelivery() returns true.
		w, err := webhook.New(&webhook.Config{
			URL: tc.WebhookURL + "/events", AllowInsecureHTTP: true,
			AllowPrivateRanges: true, BatchSize: 1,
			FlushInterval: 100 * time.Millisecond, Timeout: 5 * time.Second,
		}, nil)
		if err != nil {
			return fmt.Errorf("create webhook: %w", err)
		}
		tc.AddCleanup(func() { _ = w.Close() })

		opts := []audit.Option{
			audit.WithTaxonomy(tc.Taxonomy),
			audit.WithAppName("test-app"),
			audit.WithHost("test-host"),
			audit.WithMetrics(tc.MockMetrics),
			audit.WithOutputs(w),
		}

		auditor, err := audit.New(opts...)
		if err != nil {
			return fmt.Errorf("create auditor: %w", err)
		}
		tc.Auditor = auditor
		tc.AddCleanup(func() { _ = auditor.Close() })
		return nil
	})

	ctx.Step(`^an auditor with panicking formatter and metrics$`, func() error {
		buf := &bytes.Buffer{}
		tc.StdoutBuf = buf

		stdoutOut, err := audit.NewStdoutOutput(audit.StdoutConfig{Writer: buf})
		if err != nil {
			return fmt.Errorf("create stdout: %w", err)
		}

		opts := []audit.Option{
			audit.WithTaxonomy(tc.Taxonomy),
			audit.WithAppName("test-app"),
			audit.WithHost("test-host"),
			audit.WithMetrics(tc.MockMetrics),
			audit.WithFormatter(&panicFormatter{}),
			audit.WithOutputs(stdoutOut),
		}

		auditor, err := audit.New(opts...)
		if err != nil {
			return fmt.Errorf("create auditor: %w", err)
		}
		tc.Auditor = auditor
		tc.AddCleanup(func() { _ = auditor.Close() })
		return nil
	})

	ctx.Step(`^an auditor with error-returning formatter and metrics$`, func() error {
		buf := &bytes.Buffer{}
		tc.StdoutBuf = buf

		stdoutOut, err := audit.NewStdoutOutput(audit.StdoutConfig{Writer: buf})
		if err != nil {
			return fmt.Errorf("create stdout: %w", err)
		}

		opts := []audit.Option{
			audit.WithTaxonomy(tc.Taxonomy),
			audit.WithAppName("test-app"),
			audit.WithHost("test-host"),
			audit.WithMetrics(tc.MockMetrics),
			audit.WithFormatter(&errorReturningFormatter{}),
			audit.WithOutputs(stdoutOut),
		}

		auditor, err := audit.New(opts...)
		if err != nil {
			return fmt.Errorf("create auditor: %w", err)
		}
		tc.Auditor = auditor
		tc.AddCleanup(func() { _ = auditor.Close() })
		return nil
	})

	ctx.Step(`^an auditor with error output and metrics$`, func() error {
		opts := []audit.Option{
			audit.WithTaxonomy(tc.Taxonomy),
			audit.WithAppName("test-app"),
			audit.WithHost("test-host"),
			audit.WithMetrics(tc.MockMetrics),
			audit.WithNamedOutput(&errorOutput{}),
		}

		auditor, err := audit.New(opts...)
		if err != nil {
			return fmt.Errorf("create auditor: %w", err)
		}
		tc.Auditor = auditor
		tc.AddCleanup(func() { _ = auditor.Close() })
		return nil
	})
}

func registerMetricsGivenFilterSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^an auditor with routed outputs and metrics where webhook excludes "([^"]*)"$`, func(excludeCat string) error {
		dir, err := tc.EnsureFileDir()
		if err != nil {
			return err
		}
		path := filepath.Join(dir, "audit.log")
		tc.FilePaths["default"] = path

		fileOut, err := audit.NewStdoutOutput(audit.StdoutConfig{Writer: &bytes.Buffer{}})
		if err != nil {
			return fmt.Errorf("create stdout: %w", err)
		}

		whOut, err := webhook.New(&webhook.Config{
			URL: tc.WebhookURL + "/events", AllowInsecureHTTP: true,
			AllowPrivateRanges: true, BatchSize: 1,
			FlushInterval: 100 * time.Millisecond, Timeout: 5 * time.Second,
			// Core BDD shard does not run a webhook receiver; skip
			// the construction-time probe so the route-filter metric
			// behaviour (the property under test) is exercised.
			DisableStartupVerification: true,
		}, nil)
		if err != nil {
			return fmt.Errorf("create webhook: %w", err)
		}
		tc.AddCleanup(func() { _ = whOut.Close() })

		opts := []audit.Option{
			audit.WithTaxonomy(tc.Taxonomy),
			audit.WithAppName("test-app"),
			audit.WithHost("test-host"),
			audit.WithMetrics(tc.MockMetrics),
			audit.WithNamedOutput(fileOut),
			audit.WithNamedOutput(whOut, audit.WithRoute(&audit.EventRoute{ExcludeCategories: []string{excludeCat}})),
		}

		auditor, err := audit.New(opts...)
		if err != nil {
			return fmt.Errorf("create auditor: %w", err)
		}
		tc.Auditor = auditor
		tc.AddCleanup(func() { _ = auditor.Close() })
		return nil
	})
}

func registerMetricsWhenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^I fill the auditor buffer beyond capacity$`, func() error {
		// Send more events than buffer can hold. Some will be dropped.
		for range 100 {
			_ = tc.Auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
				"outcome":  "success",
				"actor_id": "overflow",
			}))
		}
		return nil
	})
}

func registerMetricsThenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^the metrics should have recorded event "([^"]*)" for output "([^"]*)"$`, func(status, output string) error {
		return assertMetricsEvent(tc, output, status)
	})
	ctx.Step(`^the metrics should have recorded at least (\d+) success events$`, func(minCount int) error {
		return assertMetricsTotalSuccessEvents(tc, minCount)
	})
	ctx.Step(`^the metrics should have recorded a validation error$`, func() error {
		return assertMetricsValidationError(tc, true)
	})
	ctx.Step(`^the metrics should not have recorded a validation error$`, func() error {
		return assertMetricsValidationError(tc, false)
	})
	ctx.Step(`^the metrics should have recorded a filtered event "([^"]*)"$`, func(et string) error {
		return assertMetricsFiltered(tc, et)
	})
	ctx.Step(`^the metrics should have recorded at least (\d+) buffer drop$`, func(minCount int) error {
		return assertMetricsBufferDrops(tc, minCount)
	})
	ctx.Step(`^the metrics should not have recorded a success event for webhook output$`, func() error {
		return assertMetricsNoWebhookCoreSuccess(tc)
	})
	ctx.Step(`^the metrics should have recorded a serialization error$`, func() error {
		return assertMetricsSerializationError(tc)
	})
	ctx.Step(`^the metrics should have recorded an output filtered event$`, func() error {
		return assertMetricsOutputFiltered(tc)
	})
	ctx.Step(`^the metrics should have recorded an output error for "([^"]*)"$`, func(output string) error {
		return assertMetricsOutputError(tc, output)
	})
}

// --- Metrics assertion helpers ---

func assertMetricsEvent(tc *AuditTestContext, output, status string) error {
	if tc.Auditor != nil {
		_ = tc.Auditor.Close()
	}
	tc.MockMetrics.mu.Lock()
	defer tc.MockMetrics.mu.Unlock()
	key := output + ":" + status
	if tc.MockMetrics.Events[key] == 0 {
		return fmt.Errorf("expected RecordDelivery(%q, %q), got 0 (all: %v)", output, status, tc.MockMetrics.Events)
	}
	return nil
}

func assertMetricsTotalSuccessEvents(tc *AuditTestContext, minCount int) error {
	if tc.Auditor != nil {
		_ = tc.Auditor.Close()
	}
	tc.MockMetrics.mu.Lock()
	defer tc.MockMetrics.mu.Unlock()
	total := 0
	for k, v := range tc.MockMetrics.Events {
		if strings.HasSuffix(k, ":success") {
			total += v
		}
	}
	if total < minCount {
		return fmt.Errorf("expected >= %d success events, got %d", minCount, total)
	}
	return nil
}

func assertMetricsValidationError(tc *AuditTestContext, expectPresent bool) error {
	tc.MockMetrics.mu.Lock()
	defer tc.MockMetrics.mu.Unlock()
	total := 0
	for _, v := range tc.MockMetrics.ValidationErrors {
		total += v
	}
	if expectPresent && total == 0 {
		return fmt.Errorf("expected validation error, got 0")
	}
	if !expectPresent && total > 0 {
		return fmt.Errorf("expected no validation error, got %d", total)
	}
	return nil
}

func assertMetricsFiltered(tc *AuditTestContext, eventType string) error {
	if tc.Auditor != nil {
		_ = tc.Auditor.Close()
	}
	tc.MockMetrics.mu.Lock()
	defer tc.MockMetrics.mu.Unlock()
	if tc.MockMetrics.Filtered[eventType] == 0 {
		return fmt.Errorf("expected RecordFiltered(%q), got 0 (all: %v)", eventType, tc.MockMetrics.Filtered)
	}
	return nil
}

func assertMetricsBufferDrops(tc *AuditTestContext, minCount int) error {
	if tc.Auditor != nil {
		_ = tc.Auditor.Close()
	}
	tc.MockMetrics.mu.Lock()
	defer tc.MockMetrics.mu.Unlock()
	if tc.MockMetrics.BufferDrops < minCount {
		return fmt.Errorf("expected >= %d buffer drops, got %d", minCount, tc.MockMetrics.BufferDrops)
	}
	return nil
}

func assertMetricsSerializationError(tc *AuditTestContext) error {
	if tc.Auditor != nil {
		_ = tc.Auditor.Close()
	}
	tc.MockMetrics.mu.Lock()
	defer tc.MockMetrics.mu.Unlock()
	total := 0
	for _, v := range tc.MockMetrics.SerializationErrs {
		total += v
	}
	if total == 0 {
		return fmt.Errorf("expected at least 1 serialization error, got 0")
	}
	return nil
}

func assertMetricsNoWebhookCoreSuccess(tc *AuditTestContext) error {
	if tc.Auditor != nil {
		_ = tc.Auditor.Close()
	}
	tc.MockMetrics.mu.Lock()
	defer tc.MockMetrics.mu.Unlock()
	// Webhook output implements DeliveryReporter, so core metrics
	// (RecordDelivery) should NOT be called for webhook outputs.
	// Check that no "webhook:*:success" key exists.
	for k, v := range tc.MockMetrics.Events {
		if strings.Contains(k, "webhook") && strings.HasSuffix(k, ":success") && v > 0 {
			return fmt.Errorf("expected no core success metrics for webhook, but found %q=%d", k, v)
		}
	}
	return nil
}

func assertMetricsOutputFiltered(tc *AuditTestContext) error {
	if tc.Auditor != nil {
		_ = tc.Auditor.Close()
	}
	tc.MockMetrics.mu.Lock()
	defer tc.MockMetrics.mu.Unlock()
	total := 0
	for _, v := range tc.MockMetrics.OutputFiltered {
		total += v
	}
	if total == 0 {
		return fmt.Errorf("expected at least 1 RecordOutputFiltered, got 0 (all: %v)", tc.MockMetrics.OutputFiltered)
	}
	return nil
}

func assertMetricsOutputError(tc *AuditTestContext, output string) error {
	if tc.Auditor != nil {
		_ = tc.Auditor.Close()
	}
	tc.MockMetrics.mu.Lock()
	defer tc.MockMetrics.mu.Unlock()
	count := tc.MockMetrics.OutputErrors[output]
	if count == 0 {
		return fmt.Errorf("expected RecordOutputError for %q, got 0 (all: %v)", output, tc.MockMetrics.OutputErrors)
	}
	return nil
}
