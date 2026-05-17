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

package bdd_test

import (
	"os"
	"testing"

	"github.com/cucumber/godog"
	"github.com/cucumber/godog/colors"

	"github.com/axonops/audit/outputconfig/tests/bdd/steps"
)

func TestOutputConfigFeatures(t *testing.T) {
	// Format is "pretty" by default for local-dev readability.
	// When BDD_REPORT_FILE is set, godog additionally writes a
	// cucumber JSON report at that path — consumed by
	// cmd/bdd-report-html to publish per-suite HTML artefacts in CI.
	format := "pretty"
	if reportFile := os.Getenv("BDD_REPORT_FILE"); reportFile != "" {
		format = "pretty,cucumber:" + reportFile
	}

	opts := godog.Options{
		Output:      colors.Colored(os.Stdout),
		Format:      format,
		Paths:       []string{"features"},
		Tags:        "~@docker",
		Randomize:   0,
		Concurrency: 1,
		Strict:      true, // undefined steps fail the suite (#622 philosophy)
		TestingT:    t,
	}

	suite := godog.TestSuite{
		Name:                "outputconfig",
		ScenarioInitializer: steps.InitializeScenario,
		Options:             &opts,
	}

	if suite.Run() != 0 {
		t.Fatal("outputconfig BDD tests failed")
	}
}
