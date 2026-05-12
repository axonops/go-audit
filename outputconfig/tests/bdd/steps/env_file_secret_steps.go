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

// Step definitions for env:// and file:// real-provider BDD
// scenarios (#720). Unlike the mock-provider steps in
// secret_steps.go, these register the actual
// audit/secrets/env and audit/secrets/file packages — proving
// the providers integrate with outputconfig.Load end-to-end.

package steps

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cucumber/godog"

	"github.com/axonops/audit/outputconfig"
	"github.com/axonops/audit/secrets/env"
	"github.com/axonops/audit/secrets/file"
)

// registerEnvFileSecretSteps registers steps that wire the real
// env:// and file:// secret providers into the outputconfig.Load
// path.
func registerEnvFileSecretSteps(ctx *godog.ScenarioContext, tc *TestContext) {
	ctx.Step(`^an env:// secret provider is registered$`, tc.stepRegisterEnvProvider)
	ctx.Step(`^a file:// secret provider is registered$`, tc.stepRegisterFileProvider)
	ctx.Step(`^a file in the temp dir named "([^"]*)" with content "([^"]*)"$`, tc.stepWriteFixtureFile)
	ctx.Step(`^a file in the temp dir named "([^"]*)" with (\d+) bytes of content$`, tc.stepWriteFixtureFileWithSize)
	ctx.Step(`^a JSON file in the temp dir named "([^"]*)" with content:$`, tc.stepWriteFixtureJSONFile)
	ctx.Step(`^a Kubernetes-style atomic-swap secret named "([^"]*)" with content "([^"]*)"$`, tc.stepWriteAtomicSwapSecret)
}

func (tc *TestContext) stepRegisterEnvProvider() error {
	tc.LoadOptions = append(tc.LoadOptions, outputconfig.WithSecretProvider(env.New()))
	return nil
}

func (tc *TestContext) stepRegisterFileProvider() error {
	// Eagerly create the per-scenario temp dir and export
	// BDD_SECRETS_DIR so YAML scenarios referencing
	// ref+file://${BDD_SECRETS_DIR}/... resolve through the
	// outputconfig envsubst pass — even scenarios that don't
	// otherwise create a fixture file (e.g. the "rejects .."
	// path-traversal scenario, which validates structural
	// rejection without touching the filesystem).
	if _, err := tc.ensureSecretsTempDir(); err != nil {
		return err
	}
	tc.LoadOptions = append(tc.LoadOptions, outputconfig.WithSecretProvider(file.New()))
	return nil
}

func (tc *TestContext) stepWriteFixtureFile(name, content string) error {
	dir, err := tc.ensureSecretsTempDir()
	if err != nil {
		return err
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func (tc *TestContext) stepWriteFixtureFileWithSize(name string, size int) error {
	dir, err := tc.ensureSecretsTempDir()
	if err != nil {
		return err
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, bytes.Repeat([]byte{'x'}, size), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func (tc *TestContext) stepWriteFixtureJSONFile(name string, doc *godog.DocString) error {
	dir, err := tc.ensureSecretsTempDir()
	if err != nil {
		return err
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(doc.Content), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// stepWriteAtomicSwapSecret builds the layered symlink structure
// that the Kubernetes kubelet creates when mounting a Secret as a
// directory:
//
//	<dir>/<name>   → ..data/<name>   (public path; symlink)
//	<dir>/..data   → ..<timestamp>   (atomically swapped on rotation)
//	<dir>/..<ts>/<name>              (the real file)
//
// On rotation the kubelet writes a new timestamped dir, then
// atomically replaces ..data. file:// must follow both indirections.
func (tc *TestContext) stepWriteAtomicSwapSecret(name, content string) error {
	dir, err := tc.ensureSecretsTempDir()
	if err != nil {
		return err
	}
	// Synthetic versioned dirname mirroring the kubelet AtomicWriter
	// timestamp format; the literal date is irrelevant to the test.
	versionDir := filepath.Join(dir, "..0000_00_00_00_00_00.000000000")
	if err := os.MkdirAll(versionDir, 0o700); err != nil {
		return fmt.Errorf("create versioned dir: %w", err)
	}
	if err := os.WriteFile(filepath.Join(versionDir, name), []byte(content), 0o600); err != nil {
		return fmt.Errorf("write versioned file: %w", err)
	}
	dataLink := filepath.Join(dir, "..data")
	if err := os.Symlink(versionDir, dataLink); err != nil {
		return fmt.Errorf("create ..data symlink: %w", err)
	}
	publicLink := filepath.Join(dir, name)
	if err := os.Symlink(filepath.Join(dataLink, name), publicLink); err != nil {
		return fmt.Errorf("create public symlink: %w", err)
	}
	return nil
}

// ensureSecretsTempDir returns the per-scenario temp dir for
// file:// fixtures, creating it on first use. The directory is
// removed by InitializeScenario's After hook (see steps.go).
// The path is also exported as the BDD_SECRETS_DIR env var so
// YAML scenarios can reference fixture files via standard env
// expansion in ref+file:// URLs.
func (tc *TestContext) ensureSecretsTempDir() (string, error) {
	if tc.realSecretsTempDir != "" {
		return tc.realSecretsTempDir, nil
	}
	dir, err := os.MkdirTemp("", "bdd-env-file-*")
	if err != nil {
		return "", fmt.Errorf("create secrets temp dir: %w", err)
	}
	tc.realSecretsTempDir = dir
	if err := os.Setenv("BDD_SECRETS_DIR", dir); err != nil {
		return "", fmt.Errorf("set BDD_SECRETS_DIR: %w", err)
	}
	tc.envVarsSet = append(tc.envVarsSet, "BDD_SECRETS_DIR")
	return dir, nil
}
