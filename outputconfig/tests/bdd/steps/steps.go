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

// Package steps provides Godog step definitions for outputconfig BDD tests.
package steps

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cucumber/godog"
	"github.com/goccy/go-yaml"

	"github.com/axonops/audit"
	_ "github.com/axonops/audit/file" // register file factory
	"github.com/axonops/audit/outputconfig"
)

// capturedStdoutBuf collects bytes that the registered stdout factory
// writes during the current scenario. BDD runs single-goroutine
// (Concurrency: 1) so a package-level buffer is safe; Reset clears
// it per scenario. Used by `the captured output should contain`.
var capturedStdoutBuf = &bytes.Buffer{}

func init() {
	// Register a buffer-capturing stdout factory so BDD scenarios can
	// inspect what reached the output. The original os.Stdout target
	// from audit.StdoutFactory() is irrelevant here — tests assert on
	// captured bytes, not console visibility.
	audit.MustRegisterOutputFactory("stdout", func(name string, rawConfig []byte, _ audit.FrameworkContext) (audit.Output, error) {
		if len(rawConfig) > 0 {
			return nil, fmt.Errorf("audit: stdout output %q: stdout does not accept configuration", name)
		}
		out, err := audit.NewStdoutOutput(audit.StdoutConfig{Writer: capturedStdoutBuf})
		if err != nil {
			return nil, fmt.Errorf("create stdout: %w", err)
		}
		return audit.WrapOutput(out, name), nil
	})
	// Register a stub "loki" factory for BDD tests that validate
	// outputconfig formatter behaviour without depending on the real
	// Loki module. The stub ignores the raw config and returns a
	// minimal output.
	audit.MustRegisterOutputFactory("loki", func(_ string, _ []byte, _ audit.FrameworkContext) (audit.Output, error) {
		return &lokiStub{}, nil
	})
	// Stub webhook factory — captures raw config bytes so #487
	// envsubst-string-semantics scenarios can inspect them.
	audit.MustRegisterOutputFactory("webhook", func(_ string, rawConfig []byte, _ audit.FrameworkContext) (audit.Output, error) {
		capturedWebhookRawConfig = append(capturedWebhookRawConfig[:0], rawConfig...)
		return &webhookStub{}, nil
	})
}

// lokiStub is a minimal output stub for Loki formatter BDD tests.
type lokiStub struct{}

func (l *lokiStub) Write([]byte) error { return nil }
func (l *lokiStub) Close() error       { return nil }
func (l *lokiStub) Name() string       { return "loki-stub" }

// capturedWebhookRawConfig holds the most recent raw config bytes
// that reached the BDD "webhook" stub factory. Single-goroutine BDD
// runner (Concurrency: 1) makes a package-level variable sufficient;
// Reset clears it per scenario. Used by the #487 envsubst-string-
// semantics scenario to assert header values survived the re-marshal
// as literal strings.
var capturedWebhookRawConfig []byte

// webhookStub is a minimal output stub used by BDD scenarios that
// need to inspect the raw config bytes reaching the factory.
type webhookStub struct{}

func (w *webhookStub) Write([]byte) error { return nil }
func (w *webhookStub) Close() error       { return nil }
func (w *webhookStub) Name() string       { return "webhook-stub" }

// TestContext holds mutable state for a single BDD scenario.
type TestContext struct { //nolint:govet // fieldalignment: readability preferred
	Taxonomy      *audit.Taxonomy
	Auditor       *audit.Auditor
	Options       []audit.Option
	LoadResult    *outputconfig.Loaded
	LastErr       error
	FileDir       string
	MockProvider  *mockSecretProvider       // most recently registered mock provider
	LoadOptions   []outputconfig.LoadOption // accumulated options for Load (providers, timeout)
	SecretTimeout time.Duration             // secret resolution timeout for WithSecretTimeout
	envVarsSet    []string                  // env vars set by steps, cleaned up in After

	// Real container provider state (for @docker scenarios).
	realProviderAddr   string
	realProviderToken  string
	realProviderCAPath string
	// realSecretsTempDir is a per-scenario temp dir used by both
	// the @docker Vault/OpenBao steps (for the extracted CA cert)
	// and the file:// secret-provider steps (for fixture files).
	// Mutually exclusive in practice — a scenario uses one provider
	// family or the other — but both code paths cooperate to set
	// and to clean up via the After hook below.
	realSecretsTempDir       string
	realProviderPendingSeeds map[string]map[string]string
	realProviderCleanup      []func()
}

// Reset prepares the context for a new scenario.
func (tc *TestContext) Reset() {
	tc.Auditor = nil
	tc.Options = nil
	tc.LoadResult = nil
	tc.LastErr = nil
	tc.FileDir = ""
	tc.MockProvider = nil
	tc.LoadOptions = nil
	tc.SecretTimeout = 0
	tc.envVarsSet = nil
	tc.realProviderAddr = ""
	tc.realProviderToken = ""
	tc.realProviderCAPath = ""
	tc.realSecretsTempDir = ""
	tc.realProviderPendingSeeds = nil
	tc.realProviderCleanup = nil
	capturedWebhookRawConfig = nil
	capturedStdoutBuf.Reset()
}

// InitializeScenario wires all step definitions.
func InitializeScenario(ctx *godog.ScenarioContext) {
	tc := &TestContext{}

	ctx.Before(func(goctx context.Context, sc *godog.Scenario) (context.Context, error) {
		tc.Reset()
		return goctx, nil
	})

	ctx.After(func(goctx context.Context, sc *godog.Scenario, err error) (context.Context, error) {
		if tc.Auditor != nil {
			// Auditor.Close drains and closes its wrapped outputs.
			_ = tc.Auditor.Close()
		} else if tc.LoadResult != nil {
			// Outputs were constructed but never handed to an Auditor —
			// close them directly to avoid resource leaks.
			_ = tc.LoadResult.Close()
		}
		if tc.FileDir != "" {
			_ = os.RemoveAll(tc.FileDir)
		}
		_ = os.Unsetenv("AUDIT_BDD_DIR")
		for _, name := range tc.envVarsSet {
			_ = os.Unsetenv(name)
		}
		// Clean up real container provider resources.
		for _, cleanup := range tc.realProviderCleanup {
			cleanup()
		}
		if tc.realSecretsTempDir != "" {
			_ = os.RemoveAll(tc.realSecretsTempDir)
		}
		return goctx, nil
	})

	registerGivenSteps(ctx, tc)
	registerWhenSteps(ctx, tc)
	registerThenSteps(ctx, tc)
	registerRealSecretSteps(ctx, tc)
	registerSecretSteps(ctx, tc)
	registerSecretsTLSNegativeSteps(ctx, tc)
	registerEnvFileSecretSteps(ctx, tc)
}

func registerGivenSteps(ctx *godog.ScenarioContext, tc *TestContext) {
	ctx.Step(`^a test taxonomy$`, func() error {
		tax, err := audit.ParseTaxonomyYAML([]byte(`
version: 1
categories:
  write:
    - user_create
    - user_delete
  security:
    - auth_failure
  read:
    - user_read
events:
  user_create:
    fields:
      outcome: {required: true}
      actor_id: {required: true}
  user_delete:
    fields:
      outcome: {required: true}
      actor_id: {required: true}
  auth_failure:
    fields:
      outcome: {required: true}
  user_read:
    fields:
      outcome: {required: true}
`))
		if err != nil {
			return fmt.Errorf("parse taxonomy: %w", err)
		}
		tc.Taxonomy = tax
		return nil
	})

	ctx.Step(`^the following output configuration YAML:$`, func(doc *godog.DocString) error {
		dir, err := os.MkdirTemp("", "bdd-outputconfig-*")
		if err != nil {
			return fmt.Errorf("create temp dir: %w", err)
		}
		tc.FileDir = dir
		if err := os.Setenv("AUDIT_BDD_DIR", dir); err != nil {
			return fmt.Errorf("set AUDIT_BDD_DIR: %w", err)
		}

		result, loadErr := outputconfig.Load(context.Background(), []byte(doc.Content), tc.Taxonomy)
		if loadErr != nil {
			tc.LastErr = loadErr
			return nil //nolint:nilerr // scenario may assert on tc.LastErr
		}
		tc.Options = result.Options()
		tc.LoadResult = result
		return nil
	})
}

func registerWhenSteps(ctx *godog.ScenarioContext, tc *TestContext) {
	ctx.Step(`^I create an auditor from the YAML config$`, func() error {
		if tc.LastErr != nil {
			return fmt.Errorf("config load already failed: %w", tc.LastErr)
		}
		opts := []audit.Option{audit.WithTaxonomy(tc.Taxonomy)}
		opts = append(opts, tc.Options...)
		auditor, err := audit.New(opts...)
		if err != nil {
			return fmt.Errorf("create auditor: %w", err)
		}
		tc.Auditor = auditor
		return nil
	})

	ctx.Step(`^I try to create an auditor from the YAML config$`, func() error {
		if tc.LastErr != nil {
			return nil //nolint:nilerr // Load already set tc.LastErr
		}
		opts := []audit.Option{audit.WithTaxonomy(tc.Taxonomy)}
		opts = append(opts, tc.Options...)
		auditor, logErr := audit.New(opts...)
		if logErr != nil {
			tc.LastErr = logErr
			return nil //nolint:nilerr // scenario asserts on tc.LastErr
		}
		tc.Auditor = auditor
		return nil
	})

	ctx.Step(`^I audit event "([^"]*)" with fields:$`, func(eventType string, table *godog.Table) error {
		if tc.Auditor == nil {
			return fmt.Errorf("no auditor created")
		}
		fields := audit.Fields{}
		for _, row := range table.Rows[1:] { // skip header
			fields[row.Cells[0].Value] = row.Cells[1].Value
		}
		tc.LastErr = tc.Auditor.AuditEvent(audit.NewEvent(eventType, fields))
		return nil
	})

	ctx.Step(`^I close the auditor$`, func() error {
		if tc.Auditor == nil {
			return nil
		}
		tc.LastErr = tc.Auditor.Close()
		return nil
	})
}

//nolint:gocognit,gocyclo,cyclop // BDD step registration: many closures inline; splitting hurts readability
func registerThenSteps(ctx *godog.ScenarioContext, tc *TestContext) {
	ctx.Step(`^the audit call should have succeeded$`, func() error {
		if tc.LastErr != nil {
			return fmt.Errorf("expected no error, got: %w", tc.LastErr)
		}
		return nil
	})

	ctx.Step(`^the audit call should have failed with an error containing "([^"]*)"$`, func(substr string) error {
		if tc.LastErr == nil {
			return fmt.Errorf("expected an error containing %q, got nil", substr)
		}
		if !strings.Contains(tc.LastErr.Error(), substr) {
			return fmt.Errorf("expected error containing %q, got: %w", substr, tc.LastErr)
		}
		return nil
	})

	// Strengthened-assertion steps for #551 — concrete observable
	// effects that follow up "should succeed".
	ctx.Step(`^the captured output should contain "([^"]*)"$`, func(needle string) error {
		// Auditor uses sync delivery via WithSynchronousDelivery, OR
		// async with the output's drain. To make assertions
		// deterministic, close the auditor first (idempotent) so the
		// drain finishes.
		if tc.Auditor != nil {
			_ = tc.Auditor.Close()
			tc.Auditor = nil
		}
		got := capturedStdoutBuf.String()
		if !strings.Contains(got, needle) {
			return fmt.Errorf("captured output does not contain %q; got: %s", needle, got)
		}
		return nil
	})

	ctx.Step(`^the loaded auditor metadata should have app_name "([^"]*)"$`, func(want string) error {
		if tc.LoadResult == nil {
			return fmt.Errorf("no load result")
		}
		if got := tc.LoadResult.AppName(); got != want {
			return fmt.Errorf("app_name: got %q, want %q", got, want)
		}
		return nil
	})

	ctx.Step(`^the loaded auditor metadata should have host "([^"]*)"$`, func(want string) error {
		if tc.LoadResult == nil {
			return fmt.Errorf("no load result")
		}
		if got := tc.LoadResult.Host(); got != want {
			return fmt.Errorf("host: got %q, want %q", got, want)
		}
		return nil
	})

	ctx.Step(`^the loaded auditor metadata should have timezone "([^"]*)"$`, func(want string) error {
		if tc.LoadResult == nil {
			return fmt.Errorf("no load result")
		}
		if got := tc.LoadResult.Timezone(); got != want {
			return fmt.Errorf("timezone: got %q, want %q", got, want)
		}
		return nil
	})

	ctx.Step(`^the loaded outputs should number (\d+)$`, func(n int) error {
		if tc.LoadResult == nil {
			return fmt.Errorf("no load result")
		}
		got := len(tc.LoadResult.Outputs())
		if got != n {
			return fmt.Errorf("outputs count: got %d, want %d", got, n)
		}
		return nil
	})

	ctx.Step(`^the loaded outputs should not include "([^"]*)"$`, func(name string) error {
		if tc.LoadResult == nil {
			return fmt.Errorf("no load result")
		}
		for _, m := range tc.LoadResult.OutputMetadata() {
			if m.Name == name {
				return fmt.Errorf("output %q unexpectedly present in loaded metadata", name)
			}
		}
		return nil
	})

	ctx.Step(`^the config load should fail with an error containing "([^"]*)"$`, func(substr string) error {
		return assertError(tc, substr)
	})

	ctx.Step(`^the config load should succeed$`, func() error {
		if tc.LastErr != nil {
			return fmt.Errorf("expected config load to succeed, got: %w", tc.LastErr)
		}
		return nil
	})

	ctx.Step(`^the config load error should contain "([^"]*)"$`, func(substr string) error {
		return assertError(tc, substr)
	})

	// Docstring variant: use when the substring contains literal
	// double-quote characters, which Gherkin's `"..."` step-argument
	// syntax cannot express (the embedded `\"` escape is not honoured
	// by godog v0.15).
	ctx.Step(`^the config load should fail with an error containing:$`, func(doc *godog.DocString) error {
		return assertError(tc, doc.Content)
	})

	ctx.Step(`^the loki output formatter should be JSON$`, func() error {
		return assertLokiFormatterJSON(tc)
	})

	ctx.Step(`^the captured webhook raw config should have header "([^"]*)" with value "([^"]*)"$`, assertCapturedWebhookHeader)

	registerFileAssertionSteps(ctx, tc)
}

// assertCapturedWebhookHeader parses the most recent raw config the BDD
// webhook stub saw and asserts a specific header carries the expected
// literal value (#487 — no magic-value re-interpretation).
func assertCapturedWebhookHeader(name, want string) error {
	if len(capturedWebhookRawConfig) == 0 {
		return fmt.Errorf("no webhook factory invocation captured — did the scenario declare type: webhook?")
	}
	var cfg struct {
		Headers map[string]string `yaml:"headers"`
	}
	if err := yaml.Unmarshal(capturedWebhookRawConfig, &cfg); err != nil {
		return fmt.Errorf("unmarshal captured webhook config: %w\nraw:\n%s", err, string(capturedWebhookRawConfig))
	}
	got, ok := cfg.Headers[name]
	if !ok {
		return fmt.Errorf("header %q missing from captured webhook config\nraw:\n%s", name, string(capturedWebhookRawConfig))
	}
	if got != want {
		return fmt.Errorf("header %q: factory saw %q, want %q\nraw:\n%s", name, got, want, string(capturedWebhookRawConfig))
	}
	return nil
}

func registerFileAssertionSteps(ctx *godog.ScenarioContext, tc *TestContext) {
	ctx.Step(`^the file "([^"]*)" should contain "([^"]*)"$`, func(filename, text string) error {
		path := filepath.Join(tc.FileDir, filename)
		data, err := os.ReadFile(path) //nolint:gosec // test fixture path
		if err != nil {
			return fmt.Errorf("read %s: %w", filename, err)
		}
		if !strings.Contains(string(data), text) {
			return fmt.Errorf("file %s does not contain %q", filename, text)
		}
		return nil
	})

	ctx.Step(`^the file "([^"]*)" should not contain "([^"]*)"$`, func(filename, text string) error {
		path := filepath.Join(tc.FileDir, filename)
		data, err := os.ReadFile(path) //nolint:gosec // test fixture path
		if err != nil {
			return nil //nolint:nilerr // missing file = no content
		}
		if strings.Contains(string(data), text) {
			return fmt.Errorf("file %s unexpectedly contains %q", filename, text)
		}
		return nil
	})
}

// assertLokiFormatterJSON verifies the loki_out output has a JSON formatter.
func assertLokiFormatterJSON(tc *TestContext) error {
	if tc.LoadResult == nil {
		return fmt.Errorf("no load result available")
	}
	for _, o := range tc.LoadResult.OutputMetadata() {
		if o.Name == "loki_out" {
			if o.Formatter == nil {
				return fmt.Errorf("loki output formatter is nil (would inherit default)")
			}
			if _, ok := o.Formatter.(*audit.JSONFormatter); !ok {
				return fmt.Errorf("loki output formatter is %T, want *audit.JSONFormatter", o.Formatter)
			}
			return nil
		}
	}
	return fmt.Errorf("no output named 'loki_out' found")
}

func assertError(tc *TestContext, substr string) error {
	if tc.LastErr == nil {
		return fmt.Errorf("expected error containing %q, got nil", substr)
	}
	if !strings.Contains(tc.LastErr.Error(), substr) {
		return fmt.Errorf("expected error containing %q, got: %w", substr, tc.LastErr)
	}
	return nil
}
