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

// Package steps provides Godog step definitions for audit BDD tests.
// Each step translates Gherkin into audit public API calls. Step
// definitions are deliberately thin — no business logic, just API calls
// and assertions.
package steps

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"time"

	"github.com/cucumber/godog"

	"github.com/axonops/audit"
)

// AuditTestContext holds all mutable state for a single BDD scenario.
// A fresh context is created for every scenario in BeforeScenario.
type AuditTestContext struct { //nolint:govet // fieldalignment: readability preferred over packing
	// Auditor state.
	Auditor             *audit.Auditor
	EventHandle         *audit.EventHandle
	LastEvent           audit.Event // captured by NewEvent / NewEventKV scenarios (#597)
	LastErr             error
	LastAuditDuration   time.Duration // measured by `I audit event ... with required fields` (#549 sync timing)
	LastDeliveryAge     time.Duration // captured by `I read LastDeliveryAge for ...` (#753)
	LastDeliveryAgeName string        // associated output name for the staleness assertion (#753)
	Taxonomy            *audit.Taxonomy
	Options             []audit.Option

	// Output capture.
	StdoutBuf         *bytes.Buffer     // in-memory output for non-Docker scenarios
	FilePaths         map[string]string // logical name -> temp file path
	FileDir           string            // temp directory (cleaned up after scenario)
	Markers           map[string]string // logical name -> unique marker string
	SymlinkTargetPath string            // file.Output symlink-safety scenarios — real path behind the symlink

	// Docker infrastructure.
	WebhookURL     string // "http://localhost:8080"
	LokiURL        string // "http://localhost:3100"
	TLSReceiver    any    // *tlsWebhookReceiver for HTTPS webhook tests
	LocalReceiver  any    // *localWebhookReceiver or *localLokiReceiver for SSRF/redirect/retry tests
	LocalReceiverB any    // secondary local webhook receiver (used by #463 fan-out scenarios)

	// Middleware state.
	TestServer   *httptest.Server
	LastHTTPResp *http.Response

	// Route query result.
	QueriedRoute *audit.EventRoute

	// Loki output name (dynamic: "loki:<host>").
	LokiOutputName string

	// TLS negative-path scenarios (#552).
	BadCerts        *badCerts // bad-cert generation + cleanup
	BadReceiverAddr string    // host:port of the in-process bad-cert receiver
	BadReceiverHits *uint32   // request counter for HTTPS bad-cert receiver
	flappingDrops   *uint32   // dropped-connection counter for flapping receiver

	// HMAC capture.
	CaptureOutput  *captureOutput            // raw event bytes for HMAC verification
	CaptureOutputs map[string]*captureOutput // named outputs for multi-output HMAC tests

	// MetadataWriter capture.
	MetadataMock *MetadataWriterMock

	// Metrics capture.
	MockMetrics              *MockMetrics
	WebhookMetrics           *MockOutputMetrics
	FileMetrics              *MockFileMetrics
	SyslogMetrics            *MockSyslogMetrics
	LokiMetrics              *MockOutputMetrics
	OutputMetricsMock        *MockOutputMetrics        // generic per-output metrics for isolation/drop tests
	OutputMetricsFactoryMock *MockOutputMetricsFactory // factory mock for outputconfig BDD scenarios
	AuditDuration            time.Duration             // measured duration for timing assertions

	// Schema-artifact scenario state (#548). The compiled schema is
	// stored as `any` so this struct does not transitively pull
	// `github.com/santhosh-tekuri/jsonschema/v5` into the non-test
	// build graph — the schema_artifacts_steps.go file is gated by
	// the `integration` build tag and performs the type assertion
	// at use site.
	GeneratedSchema any   // *jsonschema.Schema when set
	LastSchemaErr   error // result of the most recent schema validation call

	// Cleanup functions run in AfterScenario (LIFO order).
	cleanups []func()
	mu       sync.Mutex

	// ScenarioName is the name of the running scenario, captured by
	// the Before hook for use by the step-error enrichment hook
	// (#570 AC#3). Safe without a mutex only because the BDD runner
	// uses Concurrency: 1 (see tests/bdd/bdd_test.go); if that ever
	// changes, this field must move onto context.Context with a
	// typed key, since steps within different scenarios would
	// otherwise race on it.
	ScenarioName string
}

// AddCleanup registers a cleanup function to run after the scenario.
func (tc *AuditTestContext) AddCleanup(fn func()) {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	tc.cleanups = append(tc.cleanups, fn)
}

// Cleanup runs all registered cleanup functions in reverse order.
func (tc *AuditTestContext) Cleanup() {
	tc.mu.Lock()
	fns := make([]func(), len(tc.cleanups))
	copy(fns, tc.cleanups)
	tc.mu.Unlock()

	for i := len(fns) - 1; i >= 0; i-- {
		fns[i]()
	}
}

// Reset prepares the context for a new scenario.
func (tc *AuditTestContext) Reset() {
	tc.Auditor = nil
	tc.EventHandle = nil
	tc.LastErr = nil
	tc.LastAuditDuration = 0
	tc.LastDeliveryAge = 0
	tc.LastDeliveryAgeName = ""
	tc.Taxonomy = nil
	tc.Options = nil
	tc.StdoutBuf = nil
	tc.FilePaths = make(map[string]string)
	tc.FileDir = ""
	tc.Markers = make(map[string]string)
	tc.TestServer = nil
	tc.LastHTTPResp = nil
	tc.QueriedRoute = nil
	tc.CaptureOutput = nil
	tc.CaptureOutputs = nil
	tc.MockMetrics = nil
	tc.WebhookMetrics = nil
	tc.FileMetrics = nil
	tc.SyslogMetrics = nil
	tc.LokiMetrics = nil
	tc.OutputMetricsMock = nil
	tc.OutputMetricsFactoryMock = nil
	tc.AuditDuration = 0
	tc.TLSReceiver = nil
	tc.LocalReceiver = nil
	tc.LocalReceiverB = nil
	tc.cleanups = nil
	tc.ScenarioName = ""
}

// EnsureFileDir creates a temp directory for file outputs if not already set.
func (tc *AuditTestContext) EnsureFileDir() (string, error) {
	if tc.FileDir != "" {
		return tc.FileDir, nil
	}
	dir, err := os.MkdirTemp("", "bdd-audit-*")
	if err != nil {
		return "", fmt.Errorf("create temp dir: %w", err)
	}
	tc.FileDir = dir
	tc.AddCleanup(func() { _ = os.RemoveAll(dir) })
	return dir, nil
}

// InitializeScenario wires all step definitions and lifecycle hooks.
func InitializeScenario(ctx *godog.ScenarioContext) {
	tc := &AuditTestContext{
		WebhookURL: "http://localhost:8080",
		LokiURL:    "http://localhost:3100",
	}

	ctx.Before(func(ctx context.Context, sc *godog.Scenario) (context.Context, error) {
		tc.Reset()
		tc.ScenarioName = sc.Name
		// Reset webhook receiver if Docker is available (ignore errors
		// for non-Docker scenarios).
		_ = resetWebhookReceiver(tc.WebhookURL)
		return ctx, nil
	})

	ctx.After(func(ctx context.Context, sc *godog.Scenario, err error) (context.Context, error) {
		// Close auditor if not already closed.
		if tc.Auditor != nil {
			_ = tc.Auditor.Close()
		}
		tc.Cleanup()
		return ctx, nil
	})

	// Step-error enrichment hook (#570 AC#3). When a step fails,
	// godog's default failure log shows only the underlying error.
	// Wrap it with scenario+step context so CI logs are diagnosable
	// without local repro.
	ctx.StepContext().After(func(ctx context.Context, st *godog.Step, status godog.StepResultStatus, err error) (context.Context, error) {
		if err == nil {
			return ctx, nil
		}
		return ctx, fmt.Errorf("scenario %q step %q: %w", tc.ScenarioName, st.Text, err)
	})

	// Register all step definitions.
	registerAuditSteps(ctx, tc)
	registerEventMetadataSteps(ctx, tc)
	registerTaxonomySteps(ctx, tc)
	registerFilterSteps(ctx, tc)
	registerConfigSteps(ctx, tc)
	registerFileSteps(ctx, tc)
	registerFormatterSteps(ctx, tc)
	registerShutdownSteps(ctx, tc)
	registerMetricsSteps(ctx, tc)
	registerSyslogSteps(ctx, tc)
	registerWebhookSteps(ctx, tc)
	registerWebhookBatchingSteps(ctx, tc)
	registerFanoutSteps(ctx, tc)
	registerMiddlewareSteps(ctx, tc)
	RegisterMultiCatSteps(ctx, tc)
	registerSeverityRoutingSteps(ctx, tc)
	registerSensitivitySteps(ctx, tc)
	registerStdoutSteps(ctx, tc)
	registerBuilderSteps(ctx, tc)
	registerTypedBuilderSteps(ctx, tc)
	registerHMACSteps(ctx, tc)
	registerMetadataWriterSteps(ctx, tc)
	registerLokiSteps(ctx, tc)
	registerLokiReceiverSteps(ctx, tc)
	registerLokiHMACSteps(ctx, tc)
	registerLokiFanoutSteps(ctx, tc)
	registerLokiUncategorisedSteps(ctx, tc)
	registerSplunkSteps(ctx, tc)
	registerSyslogSeveritySteps(ctx, tc)
	registerSyslogCrashReplaySteps(ctx, tc)
	registerTLSNegativeSteps(ctx, tc)
	registerTLSHandshakeSteps(ctx, tc)
	registerFailureModeSteps(ctx, tc)
	registerIsolationSteps(ctx, tc)
	registerEventMetricsSteps(ctx, tc)
	registerOutputConfigSteps(ctx, tc)
	registerSSRFSteps(ctx, tc)
	registerAudittestSteps(ctx, tc)
	registerSanitizerSteps(ctx, tc)
	registerContextAPISteps(ctx, tc)
	registerAsyncEdgesSteps(ctx, tc)
	registerSyncDeliverySteps(ctx, tc)
	registerMissingCoverageSteps(ctx, tc)
	registerLastDeliveryAgeSteps(ctx, tc)
	registerSchemaArtifactsStepsIfBuilt(ctx, tc)
}
