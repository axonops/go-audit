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

package bdd_test

import (
	"os"
	"testing"

	"github.com/cucumber/godog"
	"github.com/cucumber/godog/colors"

	"github.com/axonops/audit/outputconfig/tests/bdd/steps"
)

// TestOutputConfigDockerFeatures runs BDD scenarios tagged @docker
// that require real OpenBao/Vault containers.
//
// Prerequisites:
//
//	make test-infra-openbao-up
//	make test-infra-vault-up
func TestOutputConfigDockerFeatures(t *testing.T) {
	// Same env-toggled format pattern as TestOutputConfigFeatures —
	// "pretty" by default, additional "cucumber:<file>" when
	// BDD_REPORT_FILE is set so CI can publish HTML artefacts.
	format := "pretty"
	if reportFile := os.Getenv("BDD_REPORT_FILE"); reportFile != "" {
		format = "pretty,cucumber:" + reportFile
	}

	opts := godog.Options{
		Output:      colors.Colored(os.Stdout),
		Format:      format,
		Paths:       []string{"features"},
		Tags:        "@docker",
		Randomize:   0,
		Strict:      true,
		Concurrency: 1,
		TestingT:    t,
	}

	suite := godog.TestSuite{
		Name:                "outputconfig-docker",
		ScenarioInitializer: steps.InitializeScenario,
		Options:             &opts,
	}

	if suite.Run() != 0 {
		t.Fatal("outputconfig Docker BDD tests failed")
	}
}
