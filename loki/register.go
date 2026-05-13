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

package loki

import (
	"bytes"
	"fmt"
	"time"

	"github.com/axonops/audit"
	"github.com/goccy/go-yaml"
)

func init() {
	audit.MustRegisterOutputFactory("loki", defaultFactory)
}

// defaultFactory creates a Loki output from YAML config. Core metrics
// from fctx are forwarded for delivery reporting; per-output metrics
// from fctx.OutputMetrics are honoured at construction. The diagnostic
// logger and framework context from fctx are plumbed through to
// construction-time TLS warnings and stream-label computation.
func defaultFactory(name string, rawConfig []byte, fctx audit.FrameworkContext) (audit.Output, error) { //nolint:gocritic // hugeParam: signature fixed by audit.OutputFactory (#696)
	return buildOutput(name, rawConfig, fctx.OutputMetrics, fctx)
}

// NewFactory returns an [audit.OutputFactory] that creates Loki
// outputs from YAML configuration and wires per-output metrics via
// the supplied [audit.OutputMetricsFactory]. When factory is non-nil,
// the returned [audit.Output] receives its per-output
// [audit.OutputMetrics] via [WithOutputMetrics] at construction time.
// Pass nil to disable per-output metrics.
//
// Signature is identical to the other output modules'
// `NewFactory` (file, syslog, webhook) for consistency (#581).
func NewFactory(factory audit.OutputMetricsFactory) audit.OutputFactory {
	return func(name string, rawConfig []byte, fctx audit.FrameworkContext) (audit.Output, error) {
		var om audit.OutputMetrics
		if factory != nil {
			om = factory("loki", name)
		}
		return buildOutput(name, rawConfig, om, fctx)
	}
}

// yamlLokiConfig is the YAML-specific representation of Loki output
// configuration. Maps snake_case YAML fields to the Go Config struct.
type yamlLokiConfig struct { //nolint:govet // fieldalignment: readability preferred
	URL        string            `yaml:"url"`
	BasicAuth  *yamlBasicAuth    `yaml:"basic_auth"`
	BearerTkn  string            `yaml:"bearer_token"`
	TenantID   string            `yaml:"tenant_id"`
	Headers    map[string]string `yaml:"headers"`
	Labels     *yamlLabelConfig  `yaml:"labels"`
	TLSCA      string            `yaml:"tls_ca"`
	TLSCert    string            `yaml:"tls_cert"`
	TLSKey     string            `yaml:"tls_key"`
	TLSPolicy  *yamlTLSPolicy    `yaml:"tls_policy"`
	BatchSize  *int              `yaml:"batch_size"`
	MaxBatchB  *int              `yaml:"max_batch_bytes"`
	MaxEventB  *int              `yaml:"max_event_bytes"`
	FlushIvl   yamlDuration      `yaml:"flush_interval"`
	BufferSize *int              `yaml:"buffer_size"`
	Timeout    yamlDuration      `yaml:"timeout"`
	MaxRetries *int              `yaml:"max_retries"`
	Gzip       *bool             `yaml:"gzip"`
	AllowHTTP  bool              `yaml:"allow_insecure_http"`
	AllowPriv  bool              `yaml:"allow_private_ranges"`
	// VerifyOnStartup is the positive YAML surface for the inverted
	// Config.DisableStartupVerification field. A nil pointer (key
	// omitted) maps to verification ON; an explicit `true` keeps it
	// ON; an explicit `false` opts out. See [Config.DisableStartupVerification].
	VerifyOnStartup        *bool        `yaml:"verify_on_startup"`
	VerifyOnStartupTimeout yamlDuration `yaml:"verify_on_startup_timeout"`
}

type yamlBasicAuth struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type yamlLabelConfig struct {
	Static  map[string]string `yaml:"static"`
	Dynamic map[string]bool   `yaml:"dynamic"`
}

type yamlTLSPolicy struct {
	AllowTLS12       bool `yaml:"allow_tls12"`
	AllowWeakCiphers bool `yaml:"allow_weak_ciphers"`
}

// yamlDuration is a time.Duration that unmarshals from a YAML string.
type yamlDuration time.Duration

func (d *yamlDuration) UnmarshalYAML(data []byte) error {
	var s string
	if err := yaml.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("decode duration: %w", err)
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = yamlDuration(parsed)
	return nil
}

// intPtrOrDefault returns the pointed-to value if non-nil, or the
// default if nil (field not specified in YAML). When the pointer is
// non-nil and the value is zero, returns -1 as a sentinel so that
// applyDefaults (which treats 0 as "not set") does not silently
// override the explicit zero. The -1 sentinel is caught by validation
// which rejects values < 1.
//
// SYNC: identical implementation in file/register.go,
// syslog/register.go, webhook/register.go, loki/register.go. The
// helper is unexported and cannot be shared across Go modules (each
// output module is independently versioned and published). Keep all
// four copies in sync when making changes (#542).
func intPtrOrDefault(p *int, def int) int {
	if p == nil {
		return def
	}
	if *p == 0 {
		return -1 // sentinel: explicit zero from YAML
	}
	return *p
}

func buildOutput(name string, rawConfig []byte, om audit.OutputMetrics, fctx audit.FrameworkContext) (audit.Output, error) { //nolint:gocritic // hugeParam: fctx mirrors audit.FrameworkContext (constructor-time)
	if len(rawConfig) == 0 {
		return nil, fmt.Errorf("audit/loki: output %q: config is required", name)
	}

	cfg, err := parseLokiConfig(name, rawConfig)
	if err != nil {
		return nil, err
	}

	opts := []Option{
		WithDiagnosticLogger(fctx.DiagnosticLogger),
		WithFrameworkContext(fctx),
	}
	if om != nil {
		opts = append(opts, WithOutputMetrics(om))
	}

	output, err := New(cfg, fctx.CoreMetrics, opts...)
	if err != nil {
		return nil, fmt.Errorf("audit/loki: output %q: %w", name, err)
	}
	return audit.WrapOutput(output, name), nil
}

func parseLokiConfig(name string, rawConfig []byte) (*Config, error) {
	var yc yamlLokiConfig
	dec := yaml.NewDecoder(bytes.NewReader(rawConfig), yaml.DisallowUnknownField())
	if err := dec.Decode(&yc); err != nil {
		return nil, fmt.Errorf("audit/loki: output %q: %w", name, audit.WrapUnknownFieldError(err, yc))
	}

	cfg := &Config{
		URL:                        yc.URL,
		BearerToken:                yc.BearerTkn,
		TenantID:                   yc.TenantID,
		Headers:                    yc.Headers,
		TLSCA:                      yc.TLSCA,
		TLSCert:                    yc.TLSCert,
		TLSKey:                     yc.TLSKey,
		BatchSize:                  intPtrOrDefault(yc.BatchSize, DefaultBatchSize),
		MaxBatchBytes:              intPtrOrDefault(yc.MaxBatchB, DefaultMaxBatchBytes),
		MaxEventBytes:              intPtrOrDefault(yc.MaxEventB, DefaultMaxEventBytes),
		FlushInterval:              time.Duration(yc.FlushIvl),
		BufferSize:                 intPtrOrDefault(yc.BufferSize, DefaultBufferSize),
		Timeout:                    time.Duration(yc.Timeout),
		MaxRetries:                 intPtrOrDefault(yc.MaxRetries, DefaultMaxRetries),
		AllowInsecureHTTP:          yc.AllowHTTP,
		AllowPrivateRanges:         yc.AllowPriv,
		StartupVerificationTimeout: time.Duration(yc.VerifyOnStartupTimeout),
	}
	// YAML verify_on_startup → inverted internal DisableStartupVerification.
	// Default (key omitted) leaves DisableStartupVerification = false → verify ON.
	if yc.VerifyOnStartup != nil && !*yc.VerifyOnStartup {
		cfg.DisableStartupVerification = true
	}

	if yc.BasicAuth != nil {
		cfg.BasicAuth = &BasicAuth{
			Username: yc.BasicAuth.Username,
			Password: yc.BasicAuth.Password,
		}
	}

	if yc.TLSPolicy != nil {
		cfg.TLSPolicy = &audit.TLSPolicy{
			AllowTLS12:       yc.TLSPolicy.AllowTLS12,
			AllowWeakCiphers: yc.TLSPolicy.AllowWeakCiphers,
		}
	}

	cfg.Gzip = true
	if yc.Gzip != nil {
		cfg.Gzip = *yc.Gzip
	}

	if yc.Labels != nil {
		cfg.Labels.Static = yc.Labels.Static
		if yc.Labels.Dynamic != nil {
			if err := parseDynamicLabels(yc.Labels.Dynamic, &cfg.Labels.Dynamic); err != nil {
				return nil, fmt.Errorf("audit/loki: output %q: %w", name, err)
			}
		}
	}

	return cfg, nil
}

// parseDynamicLabels converts the YAML dynamic labels map into the
// DynamicLabels struct. Unknown label names are rejected.
func parseDynamicLabels(m map[string]bool, dl *DynamicLabels) error {
	// Map label names to the corresponding Exclude* field pointers.
	excludeFields := map[string]*bool{
		"app_name":       &dl.ExcludeAppName,
		"host":           &dl.ExcludeHost,
		"timezone":       &dl.ExcludeTimezone,
		"pid":            &dl.ExcludePID,
		"event_type":     &dl.ExcludeEventType,
		"event_category": &dl.ExcludeEventCategory,
		"severity":       &dl.ExcludeSeverity,
	}

	for name, enabled := range m {
		field, ok := excludeFields[name]
		if !ok {
			return fmt.Errorf("%w: loki: unknown dynamic label %q: valid labels are app_name, host, timezone, pid, event_type, event_category, severity", audit.ErrConfigInvalid, name)
		}
		if !enabled {
			*field = true
		}
	}
	return nil
}
