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

package webhook

import (
	"bytes"
	"fmt"
	"log/slog"
	"time"

	"github.com/axonops/audit"
	"github.com/goccy/go-yaml"
)

func init() {
	audit.MustRegisterOutputFactory("webhook", defaultFactory)
}

// defaultFactory creates a webhook output from YAML config. Core
// metrics from fctx are forwarded for delivery reporting; per-output
// metrics from fctx.OutputMetrics are honoured at construction. The
// diagnostic logger from fctx is plumbed through to construction-time
// TLS warnings.
func defaultFactory(name string, rawConfig []byte, fctx audit.FrameworkContext) (audit.Output, error) { //nolint:gocritic // hugeParam: signature fixed by audit.OutputFactory (#696)
	return buildOutput(name, rawConfig, fctx.CoreMetrics, fctx.OutputMetrics, fctx.DiagnosticLogger)
}

// NewFactory returns an [audit.OutputFactory] that creates webhook
// outputs from YAML configuration and wires per-output metrics via
// the supplied [audit.OutputMetricsFactory]. When factory is non-nil,
// the returned [audit.Output] receives its per-output
// [audit.OutputMetrics] via [WithOutputMetrics] at construction time.
// Pass nil to disable per-output metrics.
//
// Signature is identical to the other output modules'
// `NewFactory` (file, syslog, loki) for consistency (#581).
func NewFactory(factory audit.OutputMetricsFactory) audit.OutputFactory {
	return func(name string, rawConfig []byte, fctx audit.FrameworkContext) (audit.Output, error) {
		var om audit.OutputMetrics
		if factory != nil {
			om = factory("webhook", name)
		}
		return buildOutput(name, rawConfig, fctx.CoreMetrics, om, fctx.DiagnosticLogger)
	}
}

// yamlWebhookConfig is the YAML-specific representation of webhook
// output configuration. Maps snake_case YAML fields to the Go Config
// struct.
type yamlWebhookConfig struct { //nolint:govet // fieldalignment: readability preferred
	URL                string            `yaml:"url"`
	Headers            map[string]string `yaml:"headers"`
	TLSCA              string            `yaml:"tls_ca"`
	TLSCert            string            `yaml:"tls_cert"`
	TLSKey             string            `yaml:"tls_key"`
	TLSPolicy          *yamlTLSPolicy    `yaml:"tls_policy"`
	FlushInterval      yamlDuration      `yaml:"flush_interval"`
	Timeout            yamlDuration      `yaml:"timeout"`
	BatchSize          *int              `yaml:"batch_size"`
	MaxBatchBytes      *int              `yaml:"max_batch_bytes"`
	MaxEventBytes      *int              `yaml:"max_event_bytes"`
	BufferSize         *int              `yaml:"buffer_size"`
	MaxRetries         *int              `yaml:"max_retries"`
	AllowInsecureHTTP  bool              `yaml:"allow_insecure_http"`
	AllowPrivateRanges bool              `yaml:"allow_private_ranges"`
	// VerifyOnStartup is the positive YAML surface for the inverted
	// Config.DisableStartupVerification field. A nil pointer (key
	// omitted) maps to verification ON; an explicit `true` keeps it
	// ON; an explicit `false` opts out. See [Config.DisableStartupVerification].
	VerifyOnStartup *bool `yaml:"verify_on_startup"`
	// VerifyOnStartupTimeout overrides
	// [DefaultStartupVerificationTimeout] (5s) when set.
	VerifyOnStartupTimeout yamlDuration `yaml:"verify_on_startup_timeout"`
}

// yamlTLSPolicy maps TLS policy fields from YAML.
type yamlTLSPolicy struct {
	AllowTLS12       bool `yaml:"allow_tls12"`
	AllowWeakCiphers bool `yaml:"allow_weak_ciphers"`
}

// yamlDuration is a time.Duration that unmarshals from a YAML string
// like "5s", "100ms", "10m".
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
		return -1 // sentinel: explicit zero from YAML → rejected by validation
	}
	return *p
}

func buildOutput(name string, rawConfig []byte, coreMetrics audit.Metrics, om audit.OutputMetrics, logger *slog.Logger) (audit.Output, error) {
	if len(rawConfig) == 0 {
		return nil, fmt.Errorf("audit/webhook: output %q: config is required", name)
	}

	var yc yamlWebhookConfig
	dec := yaml.NewDecoder(bytes.NewReader(rawConfig), yaml.DisallowUnknownField())
	if err := dec.Decode(&yc); err != nil {
		return nil, fmt.Errorf("audit/webhook: output %q: %w", name, audit.WrapUnknownFieldError(err, yc))
	}

	cfg := &Config{
		URL:                        yc.URL,
		Headers:                    yc.Headers,
		TLSCA:                      yc.TLSCA,
		TLSCert:                    yc.TLSCert,
		TLSKey:                     yc.TLSKey,
		FlushInterval:              time.Duration(yc.FlushInterval),
		Timeout:                    time.Duration(yc.Timeout),
		BatchSize:                  intPtrOrDefault(yc.BatchSize, DefaultBatchSize),
		MaxBatchBytes:              intPtrOrDefault(yc.MaxBatchBytes, DefaultMaxBatchBytes),
		MaxEventBytes:              intPtrOrDefault(yc.MaxEventBytes, DefaultMaxEventBytes),
		BufferSize:                 intPtrOrDefault(yc.BufferSize, DefaultBufferSize),
		MaxRetries:                 intPtrOrDefault(yc.MaxRetries, DefaultMaxRetries),
		AllowInsecureHTTP:          yc.AllowInsecureHTTP,
		AllowPrivateRanges:         yc.AllowPrivateRanges,
		StartupVerificationTimeout: time.Duration(yc.VerifyOnStartupTimeout),
	}
	// YAML verify_on_startup → inverted internal DisableStartupVerification.
	// Default (key omitted) leaves DisableStartupVerification = false → verify ON.
	if yc.VerifyOnStartup != nil && !*yc.VerifyOnStartup {
		cfg.DisableStartupVerification = true
	}
	if yc.TLSPolicy != nil {
		cfg.TLSPolicy = &audit.TLSPolicy{
			AllowTLS12:       yc.TLSPolicy.AllowTLS12,
			AllowWeakCiphers: yc.TLSPolicy.AllowWeakCiphers,
		}
	}

	opts := []Option{WithDiagnosticLogger(logger)}
	if om != nil {
		opts = append(opts, WithOutputMetrics(om))
	}

	out, err := New(cfg, coreMetrics, opts...)
	if err != nil {
		return nil, fmt.Errorf("audit/webhook: output %q: %w", name, err)
	}
	return audit.WrapOutput(out, name), nil
}
