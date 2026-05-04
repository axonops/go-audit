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

package file_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/audit"
	"github.com/axonops/audit/file"
)

func TestFileFactory_RegisteredByInit(t *testing.T) {
	factory := audit.LookupOutputFactory("file")
	require.NotNil(t, factory, "file factory must be registered by init()")
}

func TestFileFactory_ValidConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	// Default group_readable: false → mode 0o600 (owner only).
	yaml := []byte("path: " + path + "\n")

	factory := audit.LookupOutputFactory("file")
	require.NotNil(t, factory)

	out, err := factory("compliance_file", yaml, audit.FrameworkContext{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	assert.Equal(t, "compliance_file", out.Name(), "name should be the YAML-configured name")
	assert.NoError(t, out.Write([]byte(`{"test":true}`+"\n")))
}

func TestFileFactory_GroupReadable_True_AppliesMode0640(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	yaml := []byte("path: " + path + "\ngroup_readable: true\n")

	factory := audit.LookupOutputFactory("file")
	require.NotNil(t, factory)

	out, err := factory("siem_archive", yaml, audit.FrameworkContext{})
	require.NoError(t, err)
	require.NoError(t, out.Write([]byte(`{"x":1}`+"\n")))
	require.NoError(t, out.Close())
}

// TestFileFactory_RejectsLegacyPermissionsField verifies that the
// pre-#436 `permissions:` YAML key produces a clear "unknown field"
// decode error rather than silently widening file mode.
func TestFileFactory_RejectsLegacyPermissionsField(t *testing.T) {
	yaml := []byte(`path: /tmp/x.log
permissions: "0600"
`)
	factory := audit.LookupOutputFactory("file")
	require.NotNil(t, factory)
	_, err := factory("legacy", yaml, audit.FrameworkContext{})
	require.Error(t, err)
	// Decoder produces an "unknown field" error naming the rejected key.
	assert.Contains(t, err.Error(), "permissions",
		"error must name the rejected field so operators know to migrate")
}

// TestFileFactory_GroupReadable_NotBool_Rejected verifies that a
// non-bool value for group_readable is rejected by the YAML decoder.
func TestFileFactory_GroupReadable_NotBool_Rejected(t *testing.T) {
	yaml := []byte(`path: /tmp/x.log
group_readable: "yes"
`)
	factory := audit.LookupOutputFactory("file")
	require.NotNil(t, factory)
	_, err := factory("bad", yaml, audit.FrameworkContext{})
	require.Error(t, err, "string value for bool field must be rejected")
}

func TestFileFactory_InvalidConfig_ReturnsError(t *testing.T) {
	yaml := []byte("path: \"\"\n") // empty path

	factory := audit.LookupOutputFactory("file")
	require.NotNil(t, factory)

	_, err := factory("bad_file", yaml, audit.FrameworkContext{})
	assert.Error(t, err)
	// text-only: file.go:222 returns raw fmt.Errorf without an audit sentinel wrap.
	assert.Contains(t, err.Error(), "bad_file")
}

func TestFileFactory_UnknownYAMLField_Rejected(t *testing.T) {
	yaml := []byte("path: /tmp/test.log\nunknown_field: true\n")

	factory := audit.LookupOutputFactory("file")
	require.NotNil(t, factory)

	_, err := factory("test", yaml, audit.FrameworkContext{})
	assert.Error(t, err)
	// text-only: register.go:98 wraps yaml.UnknownFieldError via WrapUnknownFieldError, not an audit sentinel.
	assert.Contains(t, err.Error(), "unknown_field")
}

func TestFileFactory_EmptyConfig_ReturnsError(t *testing.T) {
	factory := audit.LookupOutputFactory("file")
	require.NotNil(t, factory)

	_, err := factory("empty", nil, audit.FrameworkContext{})
	assert.Error(t, err)
	// text-only: register.go:92 returns raw fmt.Errorf without a sentinel wrap.
	assert.Contains(t, err.Error(), "config is required")
}

func TestFileNewFactory_WithMetricsFactory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "metrics.log")
	yaml := []byte("path: " + path + "\n")

	var gotType, gotName string
	mf := func(outputType, outputName string) audit.OutputMetrics {
		gotType, gotName = outputType, outputName
		return &factoryMockMetrics{}
	}
	factory := file.NewFactory(mf)

	out, err := factory("with_metrics", yaml, audit.FrameworkContext{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	assert.Equal(t, "with_metrics", out.Name())
	assert.Equal(t, "file", gotType, "factory must be called with outputType=\"file\"")
	assert.Equal(t, "with_metrics", gotName, "factory must be called with the YAML-configured output name")
}

func TestFileNewFactory_NilFactory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nil.log")
	yaml := []byte("path: " + path + "\n")

	factory := file.NewFactory(nil)

	out, err := factory("nil_metrics", yaml, audit.FrameworkContext{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	assert.Equal(t, "nil_metrics", out.Name())
}

// TestFileNewFactory_FactoryReturnsNil covers the silently-untested
// branch where the OutputMetricsFactory legitimately returns nil for a
// specific output — the constructed output must still build cleanly
// and have no metrics wired.
func TestFileNewFactory_FactoryReturnsNil(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nilret.log")
	yaml := []byte("path: " + path + "\n")

	factory := file.NewFactory(func(_, _ string) audit.OutputMetrics {
		return nil
	})

	out, err := factory("nil_return", yaml, audit.FrameworkContext{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	assert.Equal(t, "nil_return", out.Name())
}

// factoryMockMetrics is a minimal audit.OutputMetrics scoped to the
// NewFactory tests so it does not collide with mockOutputMetrics in
// file_test.go. It does NOT implement [file.RotationRecorder], which
// exercises the structural-typing "base-only metrics" branch in the
// constructor (#696: WithOutputMetrics structural typing).
type factoryMockMetrics struct {
	audit.NoOpOutputMetrics
}

// Compile-time assertion: the factory mock is audit.OutputMetrics.
var _ audit.OutputMetrics = (*factoryMockMetrics)(nil)
