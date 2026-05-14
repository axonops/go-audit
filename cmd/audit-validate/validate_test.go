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

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// validTaxonomy is a minimal but complete taxonomy YAML used as the
// happy-path baseline for most tests.
const validTaxonomy = `
version: 1
categories:
  write:
    - user_create
events:
  user_create:
    fields:
      outcome: {required: true}
      actor_id: {required: true}
`

// validOutputs is a minimal but complete outputs YAML pointing at a
// stdout sink — no external dependencies, sufficient for schema and
// semantic validation.
const validOutputs = `
version: 1
app_name: test-app
host: test-host
outputs:
  audit_log:
    type: stdout
`

// outputsRouteUnknownCategory drives an EventRoute that references a
// category absent from the taxonomy. The runtime emits
// `EventRoute references unknown taxonomy entries: [category "..."]`
// — exercising the validator's semantic-class classifier (#611 AC#2).
const outputsRouteUnknownCategory = `
version: 1
app_name: test-app
host: test-host
outputs:
  audit_log:
    type: stdout
    route:
      include_categories:
        does_not_exist: {}
`

// outputsRouteUnknownEventType drives an EventRoute that references
// an event type absent from the taxonomy. Same classifier path as
// the unknown-category case, distinct error wording.
const outputsRouteUnknownEventType = `
version: 1
app_name: test-app
host: test-host
outputs:
  audit_log:
    type: stdout
    route:
      include_event_types:
        - bogus_event
`

// writeFile creates a temp YAML file with content and returns its path.
func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(p, []byte(content), 0o644))
	return p
}

// runCLI executes run() with the supplied args and stdin, returning
// the exit code and captured streams.
func runCLI(t *testing.T, args []string, stdin string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	in := strings.NewReader(stdin)
	code = run(args, in, &out, &errb)
	return code, out.String(), errb.String()
}

// TestValidate_Valid_ExitsZero — happy path returns 0.
func TestValidate_Valid_ExitsZero(t *testing.T) {
	t.Parallel()
	taxPath := writeFile(t, "taxonomy.yaml", validTaxonomy)
	outPath := writeFile(t, "outputs.yaml", validOutputs)
	code, stdout, _ := runCLI(t, []string{"-taxonomy", taxPath, "-outputs", outPath}, "")
	assert.Equal(t, exitValid, code)
	assert.Contains(t, stdout, "valid")
}

// TestValidate_TaxonomyParseError_ExitsOne — malformed taxonomy YAML
// is a parse failure (exit 1).
func TestValidate_TaxonomyParseError_ExitsOne(t *testing.T) {
	t.Parallel()
	taxPath := writeFile(t, "taxonomy.yaml", "this: is: not: valid: yaml: [")
	outPath := writeFile(t, "outputs.yaml", validOutputs)
	code, _, stderr := runCLI(t, []string{"-taxonomy", taxPath, "-outputs", outPath}, "")
	assert.Equal(t, exitParse, code)
	assert.Contains(t, stderr, "parse")
}

// TestValidate_OutputsSchemaError_ExitsTwo — outputs.yaml missing a
// required field is a schema failure (exit 2).
func TestValidate_OutputsSchemaError_ExitsTwo(t *testing.T) {
	t.Parallel()
	bad := `
version: 1
app_name: test-app
host: test-host
outputs:
  audit_log:
    type: file
    # missing required path
`
	taxPath := writeFile(t, "taxonomy.yaml", validTaxonomy)
	outPath := writeFile(t, "outputs.yaml", bad)
	code, _, stderr := runCLI(t, []string{"-taxonomy", taxPath, "-outputs", outPath}, "")
	assert.Equal(t, exitSchema, code)
	assert.Contains(t, stderr, "schema error")
}

// TestValidate_OutputsSemanticError_ExitsThree — output type unknown
// is a semantic failure (exit 3).
func TestValidate_OutputsSemanticError_ExitsThree(t *testing.T) {
	t.Parallel()
	bad := `
version: 1
app_name: test-app
host: test-host
outputs:
  audit_log:
    type: nonexistent_output_type
`
	taxPath := writeFile(t, "taxonomy.yaml", validTaxonomy)
	outPath := writeFile(t, "outputs.yaml", bad)
	code, _, stderr := runCLI(t, []string{"-taxonomy", taxPath, "-outputs", outPath}, "")
	assert.Equal(t, exitSemantic, code)
	assert.Contains(t, stderr, "semantic error")
}

// TestValidate_RouteUnknownCategory_ExitsThree — an EventRoute
// referencing a category absent from the taxonomy is a semantic
// failure (exit 3). Locks #611 AC#2 against classifier regression.
func TestValidate_RouteUnknownCategory_ExitsThree(t *testing.T) {
	t.Parallel()
	taxPath := writeFile(t, "taxonomy.yaml", validTaxonomy)
	outPath := writeFile(t, "outputs.yaml", outputsRouteUnknownCategory)
	code, _, stderr := runCLI(t, []string{"-taxonomy", taxPath, "-outputs", outPath}, "")
	assert.Equal(t, exitSemantic, code)
	assert.Contains(t, stderr, "semantic error")
	assert.Contains(t, stderr, "unknown taxonomy entries")
}

// TestValidate_RouteUnknownEventType_ExitsThree — symmetric to the
// unknown-category test but for `include_event_types`.
func TestValidate_RouteUnknownEventType_ExitsThree(t *testing.T) {
	t.Parallel()
	taxPath := writeFile(t, "taxonomy.yaml", validTaxonomy)
	outPath := writeFile(t, "outputs.yaml", outputsRouteUnknownEventType)
	code, _, stderr := runCLI(t, []string{"-taxonomy", taxPath, "-outputs", outPath}, "")
	assert.Equal(t, exitSemantic, code)
	assert.Contains(t, stderr, "semantic error")
	assert.Contains(t, stderr, "unknown taxonomy entries")
}

// TestValidate_UnresolvedRef_ExitsThree — `ref+vault://...` with no
// provider registered is a semantic failure (exit 3).
func TestValidate_UnresolvedRef_ExitsThree(t *testing.T) {
	t.Parallel()
	bad := `
version: 1
app_name: test-app
host: test-host
outputs:
  audit_log:
    type: stdout
    hmac:
      enabled: true
      salt:
        version: v1
        value: ref+vault://secret/data/audit/hmac#salt
      algorithm: HMAC-SHA-256
`
	taxPath := writeFile(t, "taxonomy.yaml", validTaxonomy)
	outPath := writeFile(t, "outputs.yaml", bad)
	code, _, stderr := runCLI(t, []string{"-taxonomy", taxPath, "-outputs", outPath}, "")
	assert.Equal(t, exitSemantic, code)
	assert.Contains(t, stderr, "semantic error")
	assert.Contains(t, stderr, "ref+")
}

// TestValidate_ResolveSecretsRejected_ExitsTwo — `-resolve-secrets`
// is rejected as a schema-class usage error in the default binary.
// Without this guard, an operator passing the flag would skip the
// offline ref+ pre-scan and outputconfig.Load (with no providers)
// would silently accept the unresolved literal — a CI-gate
// false-positive.
func TestValidate_ResolveSecretsRejected_ExitsTwo(t *testing.T) {
	t.Parallel()
	taxPath := writeFile(t, "taxonomy.yaml", validTaxonomy)
	outPath := writeFile(t, "outputs.yaml", validOutputs)
	code, _, stderr := runCLI(t,
		[]string{"-taxonomy", taxPath, "-outputs", outPath, "-resolve-secrets"}, "")
	assert.Equal(t, exitSchema, code)
	assert.Contains(t, stderr, "-resolve-secrets is not supported")
}

// TestValidate_StdinTaxonomy_Works — `-taxonomy -` reads from stdin.
func TestValidate_StdinTaxonomy_Works(t *testing.T) {
	t.Parallel()
	outPath := writeFile(t, "outputs.yaml", validOutputs)
	code, stdout, _ := runCLI(t, []string{"-taxonomy", "-", "-outputs", outPath}, validTaxonomy)
	assert.Equal(t, exitValid, code)
	assert.Contains(t, stdout, "valid")
}

// TestValidate_StdinOutputs_Works — `-outputs -` reads from stdin.
func TestValidate_StdinOutputs_Works(t *testing.T) {
	t.Parallel()
	taxPath := writeFile(t, "taxonomy.yaml", validTaxonomy)
	code, stdout, _ := runCLI(t, []string{"-taxonomy", taxPath, "-outputs", "-"}, validOutputs)
	assert.Equal(t, exitValid, code)
	assert.Contains(t, stdout, "valid")
}

// TestValidate_BothStdin_ExitsTwo — `-taxonomy - -outputs -` is a
// usage error rejected at flag-validation time. Returns exitSchema
// so all usage-class errors share one exit code (Go convention).
func TestValidate_BothStdin_ExitsTwo(t *testing.T) {
	t.Parallel()
	code, _, stderr := runCLI(t, []string{"-taxonomy", "-", "-outputs", "-"}, "")
	assert.Equal(t, exitSchema, code)
	assert.Contains(t, stderr, "stdin can be read once")
}

// TestValidate_VersionFlag_PrintsBanner — `-version` exits 0 and
// prints a "audit-validate <version>" banner. The version variable
// is wired by GoReleaser via -ldflags "-X main.version=…"; in tests
// it carries the zero-value "dev".
func TestValidate_VersionFlag_PrintsBanner(t *testing.T) {
	t.Parallel()
	code, stdout, _ := runCLI(t, []string{"-version"}, "")
	assert.Equal(t, exitValid, code)
	assert.Contains(t, stdout, "audit-validate")
}

// TestValidate_HelpFlag_ExitsZero — `-h` returns exit 0. Stdlib
// CLIs (cmd/go, gopls, golangci-lint) all exit 0 when help is
// requested explicitly so probe scripts don't fail their CI gate.
func TestValidate_HelpFlag_ExitsZero(t *testing.T) {
	t.Parallel()
	code, _, _ := runCLI(t, []string{"-h"}, "")
	assert.Equal(t, exitValid, code)
}

// TestValidate_FormatJSON_ValidShape emits a structured success JSON.
func TestValidate_FormatJSON_ValidShape(t *testing.T) {
	t.Parallel()
	taxPath := writeFile(t, "taxonomy.yaml", validTaxonomy)
	outPath := writeFile(t, "outputs.yaml", validOutputs)
	code, stdout, _ := runCLI(t,
		[]string{"-taxonomy", taxPath, "-outputs", outPath, "-format", "json"}, "")
	assert.Equal(t, exitValid, code)

	var rep jsonReport
	require.NoError(t, json.Unmarshal([]byte(stdout), &rep))
	assert.True(t, rep.Valid)
	assert.Empty(t, rep.Errors)
}

// TestValidate_FormatJSON_StructuredOutput emits structured failure
// JSON with the expected `code`/`message` shape.
func TestValidate_FormatJSON_StructuredOutput(t *testing.T) {
	t.Parallel()
	taxPath := writeFile(t, "taxonomy.yaml", validTaxonomy)
	outPath := writeFile(t, "outputs.yaml", `
version: 1
app_name: test-app
host: test-host
outputs:
  audit_log:
    type: nonexistent_type
`)
	code, stdout, _ := runCLI(t,
		[]string{"-taxonomy", taxPath, "-outputs", outPath, "-format", "json"}, "")
	assert.Equal(t, exitSemantic, code)

	var rep jsonReport
	require.NoError(t, json.Unmarshal([]byte(stdout), &rep))
	assert.False(t, rep.Valid)
	require.Len(t, rep.Errors, 1)
	assert.Equal(t, "semantic", rep.Errors[0].Code)
	assert.Contains(t, rep.Errors[0].Message, "nonexistent_type")
}

// TestValidate_Quiet_NoOutput — `-quiet` produces no stdout/stderr
// even on failure. Uses an unknown output type (semantic-class
// failure, exit 3) to confirm the failure-path output suppression.
func TestValidate_Quiet_NoOutput(t *testing.T) {
	t.Parallel()
	taxPath := writeFile(t, "taxonomy.yaml", validTaxonomy)
	outPath := writeFile(t, "outputs.yaml", `
version: 1
app_name: test-app
host: test-host
outputs:
  audit_log:
    type: nonexistent_type
`)
	code, stdout, stderr := runCLI(t,
		[]string{"-taxonomy", taxPath, "-outputs", outPath, "-quiet"}, "")
	assert.Equal(t, exitSemantic, code)
	assert.Empty(t, stdout)
	assert.Empty(t, stderr)
}

// TestValidate_MissingTaxonomyFlag_ExitsTwo — usage error.
func TestValidate_MissingTaxonomyFlag_ExitsTwo(t *testing.T) {
	t.Parallel()
	code, _, stderr := runCLI(t, []string{"-outputs", "x"}, "")
	assert.Equal(t, exitSchema, code)
	assert.Contains(t, stderr, "required")
}

// TestValidate_UnknownFormat_ExitsTwo rejects an unknown -format.
func TestValidate_UnknownFormat_ExitsTwo(t *testing.T) {
	t.Parallel()
	taxPath := writeFile(t, "taxonomy.yaml", validTaxonomy)
	outPath := writeFile(t, "outputs.yaml", validOutputs)
	code, _, stderr := runCLI(t,
		[]string{"-taxonomy", taxPath, "-outputs", outPath, "-format", "xml"}, "")
	assert.Equal(t, exitSchema, code)
	assert.Contains(t, stderr, "unknown -format")
}

// TestValidate_MissingTaxonomyFile_ExitsOne — file not found is a
// parse-class failure.
func TestValidate_MissingTaxonomyFile_ExitsOne(t *testing.T) {
	t.Parallel()
	code, _, stderr := runCLI(t,
		[]string{"-taxonomy", "/nonexistent.yaml", "-outputs", "/nonexistent.yaml"}, "")
	assert.Equal(t, exitParse, code)
	assert.Contains(t, stderr, "read taxonomy")
}

// TestValidate_MissingOutputsFile_ExitsOne — missing outputs file
// is a parse-class failure. Symmetric coverage to the missing
// taxonomy test, locking the read-error branch on the outputs path.
func TestValidate_MissingOutputsFile_ExitsOne(t *testing.T) {
	t.Parallel()
	taxPath := writeFile(t, "taxonomy.yaml", validTaxonomy)
	code, _, stderr := runCLI(t,
		[]string{"-taxonomy", taxPath, "-outputs", "/nonexistent-outputs.yaml"}, "")
	assert.Equal(t, exitParse, code)
	assert.Contains(t, stderr, "read outputs")
}
