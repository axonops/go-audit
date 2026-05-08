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

package outputconfig

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/axonops/audit"
)

type outputFields struct { //nolint:govet // fieldalignment: readability preferred
	typeName      string
	excludeLabels []string
	enabled       bool
	routeRaw      any
	formatterRaw  any
	typeConfigRaw any
	hmacRaw       any
}

// buildOutput constructs a single named output from its raw YAML value.
// Returns nil (not error) when the output is disabled (enabled: false).
func buildOutput(ctx context.Context, name string, raw any, taxonomy *audit.Taxonomy, globalAppName, globalHost, globalTimezone string, coreMetrics audit.Metrics, omf audit.OutputMetricsFactory, factories map[string]audit.OutputFactory, logger *slog.Logger, r *resolver) (*namedOutput, error) { //nolint:gocyclo,cyclop // linear pipeline with secret resolution added
	fields, err := extractOutputFields(name, raw)
	if err != nil {
		return nil, err
	}
	if !fields.enabled {
		return nil, nil //nolint:nilnil // nil signals disabled output
	}
	if expandErr := expandOutputEnvVars(name, fields); expandErr != nil {
		return nil, expandErr
	}
	// Resolve secret references in per-output config (excluding HMAC,
	// which is handled by buildHMACConfig with its disabled bypass).
	if secretErr := expandOutputSecrets(ctx, name, fields, r); secretErr != nil {
		return nil, secretErr
	}
	// Safety net: check for unresolved refs in expanded fields.
	if unresErr := validateOutputNoUnresolvedRefs(name, fields); unresErr != nil {
		return nil, unresErr
	}

	if fmtErr := validateLokiFormatter(name, fields); fmtErr != nil {
		return nil, fmtErr
	}

	output, err := invokeFactory(name, fields, globalAppName, globalHost, globalTimezone, coreMetrics, omf, factories, logger)
	if err != nil {
		return nil, err
	}
	route, err := buildRoute(name, fields.routeRaw, taxonomy)
	if err != nil {
		_ = output.Close() // best-effort cleanup; returning the original error
		return nil, err
	}
	formatter, err := buildOutputFormatter(name, fields.formatterRaw)
	if err != nil {
		_ = output.Close() // best-effort cleanup; returning the original error
		return nil, err
	}

	hmacCfg, err := buildHMACConfig(ctx, name, fields.hmacRaw, r)
	if err != nil {
		_ = output.Close()
		return nil, err
	}
	no := &namedOutput{Name: name, Type: fields.typeName, Output: output, Route: route, Formatter: formatter, HMACConfig: hmacCfg}
	if len(fields.excludeLabels) > 0 {
		no.ExcludeLabels = fields.excludeLabels
	}
	return no, nil
}

// validateLokiFormatter rejects non-JSON formatters on Loki outputs
// before invoking the factory. Loki requires JSON format for label
// extraction and LogQL queries.
func validateLokiFormatter(name string, fields *outputFields) error {
	if fields.typeName != "loki" || fields.formatterRaw == nil {
		return nil
	}
	fmtType := extractFormatterType(fields.formatterRaw)
	if fmtType != "" && fmtType != "json" {
		return fmt.Errorf("output %q: loki does not support custom formatters; "+
			"loki requires JSON format for label extraction and LogQL queries", name)
	}
	return nil
}

func extractOutputFields(name string, raw any) (*outputFields, error) { //nolint:gocognit,gocyclo,cyclop // YAML field extraction with validation
	m, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("output %q: expected a YAML mapping", name)
	}
	f := &outputFields{enabled: true}
	var foundType bool
	var typeConfigKey string
	for key, val := range m {
		switch key {
		case "type":
			s, err := toString(val)
			if err != nil {
				return nil, fmt.Errorf("output %q: type: %w", name, err)
			}
			f.typeName = s
			foundType = true
		case "enabled":
			v, err := toBool(val)
			if err != nil {
				return nil, fmt.Errorf("output %q: enabled: %w", name, err)
			}
			f.enabled = v
		case "route":
			f.routeRaw = val
		case "formatter":
			f.formatterRaw = val
		case "exclude_labels":
			labels, err := toStringSlice(val)
			if err != nil {
				return nil, fmt.Errorf("output %q: exclude_labels: %w", name, err)
			}
			f.excludeLabels = labels
		case "hmac":
			f.hmacRaw = val
		default:
			if f.typeConfigRaw != nil {
				return nil, fmt.Errorf("output %q: unexpected key %q; only 'type', 'enabled', 'route', 'formatter', 'exclude_labels', 'hmac', and one type-specific config block are allowed", name, key)
			}
			f.typeConfigRaw = val
			typeConfigKey = key
		}
	}
	if !foundType {
		return nil, fmt.Errorf("output %q: missing required field 'type'", name)
	}
	// Validate config key matches type name.
	if f.typeConfigRaw != nil && typeConfigKey != f.typeName {
		return nil, fmt.Errorf("output %q: config key %q does not match type %q", name, typeConfigKey, f.typeName)
	}
	return f, nil
}

func expandOutputEnvVars(name string, f *outputFields) error {
	base := "outputs." + name
	if f.typeConfigRaw != nil {
		expanded, err := expandEnvInValue(f.typeConfigRaw, base+"."+f.typeName)
		if err != nil {
			return fmt.Errorf("output %q: %w", name, err)
		}
		f.typeConfigRaw = expanded
	}
	if f.routeRaw != nil {
		expanded, err := expandEnvInValue(f.routeRaw, base+".route")
		if err != nil {
			return fmt.Errorf("output %q: %w", name, err)
		}
		f.routeRaw = expanded
	}
	if f.formatterRaw != nil {
		expanded, err := expandEnvInValue(f.formatterRaw, base+".formatter")
		if err != nil {
			return fmt.Errorf("output %q: %w", name, err)
		}
		f.formatterRaw = expanded
	}
	return nil
}

// deepCopyValue creates a deep copy of a YAML value tree so that
// mutations in one consumer do not affect others.
func deepCopyValue(v any) any {
	switch val := v.(type) {
	case map[string]any:
		cp := make(map[string]any, len(val))
		for k, child := range val {
			cp[k] = deepCopyValue(child)
		}
		return cp
	case []any:
		cp := make([]any, len(val))
		for i, child := range val {
			cp[i] = deepCopyValue(child)
		}
		return cp
	default:
		// Scalars (string, int, float64, bool, nil) are immutable.
		return v
	}
}

// injectSyslogGlobals injects global app_name and hostname into a
// syslog output's type-config map if not already set per-output.
func injectSyslogGlobals(f *outputFields, globalAppName, globalHost string) {
	if f.typeName != "syslog" {
		return
	}
	m, ok := f.typeConfigRaw.(map[string]any)
	if !ok {
		return
	}
	if globalAppName != "" {
		injectStringField(m, "app_name", globalAppName)
	}
	if globalHost != "" {
		injectStringField(m, "hostname", globalHost)
	}
}

// injectStringField adds a string key-value pair to a map if the key
// does not already exist.
func injectStringField(m map[string]any, key, value string) {
	if m == nil {
		return
	}
	if _, exists := m[key]; exists {
		return // per-output value exists — do not override
	}
	m[key] = value
}

// yamlTLSPolicy is the YAML shape of a TLS policy block. It is used
// by per-provider config parsing in provider_config.go. Each output
// module (syslog, webhook, loki) declares its own local yamlTLSPolicy
// type in its register.go; they are not coupled to this one. Root-
// level tls_policy: was removed in #476.
type yamlTLSPolicy struct {
	AllowTLS12       bool `yaml:"allow_tls12"`
	AllowWeakCiphers bool `yaml:"allow_weak_ciphers"`
}

func invokeFactory(name string, f *outputFields, globalAppName, globalHost, globalTimezone string, coreMetrics audit.Metrics, omf audit.OutputMetricsFactory, factories map[string]audit.OutputFactory, logger *slog.Logger) (audit.Output, error) {
	// Per-call factory overrides take precedence over global registry.
	factory := factories[f.typeName]
	if factory == nil {
		factory = audit.LookupOutputFactory(f.typeName)
	}
	if factory == nil {
		registered := audit.RegisteredOutputTypes()
		// Only suggest a per-output import path when the type name
		// looks like a valid Go package path (printable, no spaces,
		// no control characters). Otherwise, embedding the raw type
		// name unquoted leaks invalid bytes into the error message
		// — caught by FuzzOutputConfigLoad on a NUL-containing
		// input. The %q above still surfaces the offending name to
		// the operator, just in escaped form.
		if isValidImportPathSegment(f.typeName) {
			return nil, fmt.Errorf("output %q: unknown output type %q (registered: [%s]); "+
				"add import _ \"github.com/axonops/audit/outputs\" for all built-in types "+
				"(or import _ \"github.com/axonops/audit/%s\" for only this one)",
				name, f.typeName, strings.Join(registered, ", "), f.typeName)
		}
		return nil, fmt.Errorf("output %q: unknown output type %q (registered: [%s]); "+
			"add import _ \"github.com/axonops/audit/outputs\" for all built-in types",
			name, f.typeName, strings.Join(registered, ", "))
	}
	// Inject global app_name and hostname into syslog config if not already set.
	injectSyslogGlobals(f, globalAppName, globalHost)

	var rawConfig []byte
	if f.typeConfigRaw != nil {
		var err error
		// safeMarshal (not yaml.Marshal) because typeConfigRaw is a
		// post-envsubst / post-secrets-resolution tree: every string
		// leaf must survive the round-trip as a string (#487).
		rawConfig, err = safeMarshal(f.typeConfigRaw)
		if err != nil {
			return nil, fmt.Errorf("output %q: marshal %q config: %w", name, f.typeName, err)
		}
	}
	// Invoke the per-output metrics factory ONLY after the type
	// lookup succeeds (#696). The pre-#696 wiring deferred this to a
	// post-construction phase that ran after all outputs validated;
	// this gates the call against the same checks (unknown type ->
	// no call) so the contract is preserved.
	var outputMetrics audit.OutputMetrics
	if omf != nil {
		outputMetrics = omf(f.typeName, name)
	}
	fctx := audit.FrameworkContext{
		AppName:          globalAppName,
		Host:             globalHost,
		Timezone:         globalTimezone,
		PID:              os.Getpid(),
		DiagnosticLogger: logger,
		OutputMetrics:    outputMetrics,
		CoreMetrics:      coreMetrics,
	}
	output, err := factory(name, rawConfig, fctx)
	if err != nil {
		return nil, fmt.Errorf("output %q: %w", name, err)
	}
	if output == nil {
		return nil, fmt.Errorf("output %q: factory for type %q returned nil output without an error — this is a factory bug",
			name, f.typeName)
	}
	return output, nil
}

// isValidImportPathSegment reports whether s is plausibly a Go
// package-path segment safe to embed unquoted in an error message.
// The check rejects empty strings, anything containing whitespace,
// control characters (NUL/0x7F), backslashes, or double quotes —
// all of which would either break the suggested `import _ "..."`
// line or leak invalid bytes into the error message.
//
// This is intentionally narrower than the Go spec's actual import
// path grammar: any plausible audit sub-module name (lowercase
// letters, digits, hyphen, underscore, slash, dot) is accepted;
// anything else falls back to a generic error message in
// invokeFactory.
func isValidImportPathSegment(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < 0x21 || r == 0x7f || r == '"' || r == '\\' {
			return false
		}
	}
	return true
}
