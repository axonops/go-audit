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

//go:build integration

// Package bdd_test runs Godog BDD feature files against the audit
// library. Feature files in features/ define the executable specification;
// step definitions in steps/ translate Gherkin to API calls.
//
// Run with: make test-bdd (requires Docker for syslog/webhook scenarios)
// Run core-only: make test-bdd-core (or BDD_TAGS=@core go test ...)
package bdd_test

import (
	"os"
	"runtime"
	"testing"

	"github.com/cucumber/godog"
	"github.com/cucumber/godog/colors"
	"go.uber.org/goleak"

	"github.com/axonops/audit"
	"github.com/axonops/audit/tests/bdd/steps"
)

// init registers the stdout output factory via the public API. The
// core `audit` package's stdout init() was dropped in #578 to
// eliminate hidden global mutation; blank-importing `audit/outputs`
// from core tests would create a cross-module cycle (audit <->
// outputs), so we register via the public API here instead.
func init() {
	audit.MustRegisterOutputFactory("stdout", audit.StdoutFactory())
}

func TestFeatures(t *testing.T) {
	defer goleak.VerifyNone(t,
		// HTTP transport persistent connection goroutines linger
		// briefly after httptest.Server.Close() and webhook HTTP
		// clients. These are harmless and cleaned up by the
		// runtime's connection pool.
		goleak.IgnoreAnyFunction("net/http.(*persistConn).writeLoop"),
		goleak.IgnoreAnyFunction("net/http.(*persistConn).readLoop"),
		goleak.IgnoreAnyFunction("net/http.(*conn).serve"),
		goleak.IgnoreAnyFunction("internal/poll.runtime_pollWait"),
		goleak.IgnoreAnyFunction("crypto/tls.(*Conn).Read"),
	)

	// BDD_TAGS allows filtering scenarios by godog tag expression.
	// Examples:
	//   BDD_TAGS=@core          — run only @core scenarios (no Docker needed)
	//   BDD_TAGS=@syslog        — run only @syslog scenarios
	//   BDD_TAGS="@loki and not @fanout" — loki scenarios excluding fan-out
	//
	// When unset, all scenarios run (original behaviour).
	tags := os.Getenv("BDD_TAGS")

	// Auto-exclude @linux scenarios on non-Linux runners. The
	// file-output OS-failure scenarios (#748) use Linux-specific
	// primitives (RLIMIT_NOFILE, /proc/self/fd, /dev/full); under
	// `Strict: true` an unfiltered run on macOS/Windows would
	// surface them as failures. The exclusion is platform-aware
	// rather than scenario-defaulted so a Linux runner without
	// BDD_TAGS still exercises every scenario.
	if runtime.GOOS != "linux" {
		if tags == "" {
			tags = "~@linux"
		} else {
			tags = "(" + tags + ") && ~@linux"
		}
	}

	opts := godog.Options{
		Output:      colors.Colored(os.Stdout),
		Format:      "pretty",
		Paths:       []string{"features"},
		Tags:        tags,
		Randomize:   0,
		Strict:      true, // undefined steps are failures, not silent skips
		Concurrency: 1,    // sequential: shared Docker infrastructure
		TestingT:    t,
	}

	suite := godog.TestSuite{
		Name:                "audit",
		ScenarioInitializer: steps.InitializeScenario,
		Options:             &opts,
	}

	if suite.Run() != 0 {
		t.Fatal("BDD tests failed")
	}
}
