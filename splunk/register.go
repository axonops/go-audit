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

package splunk

import (
	"fmt"
	"time"

	"github.com/axonops/audit"
	"github.com/goccy/go-yaml"
)

func init() {
	audit.MustRegisterOutputFactory("splunk", defaultFactory)
}

// defaultFactory creates a Splunk output from YAML config. Core
// metrics from fctx are forwarded for delivery reporting; per-output
// metrics from fctx.OutputMetrics are honoured at construction.
// Mirrors loki/register.go:35.
func defaultFactory(name string, rawConfig []byte, fctx audit.FrameworkContext) (audit.Output, error) { //nolint:gocritic // hugeParam: signature fixed by audit.OutputFactory
	return buildOutput(name, rawConfig, fctx.OutputMetrics, fctx)
}

// NewFactory returns an [audit.OutputFactory] that creates Splunk
// outputs from YAML configuration and wires per-output metrics via
// the supplied [audit.OutputMetricsFactory]. When factory is non-nil,
// the returned [audit.Output] receives its per-output
// [audit.OutputMetrics] via [WithOutputMetrics] at construction time.
// Pass nil to disable per-output metrics.
//
// Signature mirrors the other output modules' `NewFactory` (file,
// syslog, webhook, loki) for consistency (#581).
func NewFactory(factory audit.OutputMetricsFactory) audit.OutputFactory {
	return func(name string, rawConfig []byte, fctx audit.FrameworkContext) (audit.Output, error) {
		var om audit.OutputMetrics
		if factory != nil {
			om = factory("splunk", name)
		}
		return buildOutput(name, rawConfig, om, fctx)
	}
}

// yamlSplunkConfig is the YAML-specific representation of the Splunk
// output configuration. Maps snake_case YAML fields to the Go Config
// struct. Nested under the `splunk:` key inside `outputs.<name>:`
// (per the outputconfig nested-block convention enforced at
// outputconfig/output.go:153-154).
type yamlSplunkConfig struct { //nolint:govet // fieldalignment: readability preferred
	URL                string            `yaml:"url"`
	Token              string            `yaml:"token"`
	Endpoint           Endpoint          `yaml:"endpoint"`
	Sourcetype         string            `yaml:"sourcetype"`
	Source             string            `yaml:"source"`
	Index              string            `yaml:"index"`
	Host               string            `yaml:"host"`
	IndexedFields      []string          `yaml:"indexed_fields"`
	BatchSize          *int              `yaml:"batch_size"`
	MaxBatchBytes      *int              `yaml:"max_batch_bytes"`
	MaxEventBytes      *int              `yaml:"max_event_bytes"`
	FlushInterval      yamlDuration      `yaml:"flush_interval"`
	Gzip               *bool             `yaml:"gzip"`
	UserAgent          string            `yaml:"user_agent"`
	Timeout            yamlDuration      `yaml:"timeout"`
	Headers            map[string]string `yaml:"headers"`
	MaxRetries         *int              `yaml:"max_retries"`
	RetryBaseDelay     yamlDuration      `yaml:"retry_base_delay"`
	RetryMaxDelay      yamlDuration      `yaml:"retry_max_delay"`
	RetryJitter        *float64          `yaml:"retry_jitter"`
	BufferSize         *int              `yaml:"buffer_size"`
	AckMode            AckMode           `yaml:"ack_mode"`
	AckPollInterval    yamlDuration      `yaml:"ack_poll_interval"`
	AckResendWindow    yamlDuration      `yaml:"ack_resend_window"`
	TLSCA              string            `yaml:"tls_ca"`
	TLSCert            string            `yaml:"tls_cert"`
	TLSKey             string            `yaml:"tls_key"`
	TLSPolicy          *yamlTLSPolicy    `yaml:"tls_policy"`
	AllowInsecureHTTP  bool              `yaml:"allow_insecure_http"`
	AllowPrivateRanges bool              `yaml:"allow_private_ranges"`
	// VerifyOnStartup is the positive YAML surface for the inverted
	// Config.DisableStartupVerification field. A nil pointer (key
	// omitted) maps to verification ON; an explicit `true` keeps it
	// ON; an explicit `false` opts out.
	VerifyOnStartup            *bool        `yaml:"verify_on_startup"`
	StartupVerificationTimeout yamlDuration `yaml:"startup_verification_timeout"`
}

// yamlTLSPolicy mirrors the loki/syslog/webhook pattern (#581).
type yamlTLSPolicy struct {
	AllowTLS12       bool `yaml:"allow_tls12"`
	AllowWeakCiphers bool `yaml:"allow_weak_ciphers"`
}

// yamlDuration is a time.Duration that unmarshals from a YAML string.
// SYNC: identical to loki/register.go:104.
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
// default if nil. When the pointer is non-nil and the value is zero,
// returns -1 as a sentinel so applyDefaults does not silently
// override the explicit zero. The -1 sentinel is caught by validation
// which rejects out-of-range values.
//
// SYNC: identical implementation in file/register.go, syslog/register.go,
// webhook/register.go, loki/register.go (#581).
func intPtrOrDefault(p *int, dflt int) int {
	if p == nil {
		return dflt
	}
	if *p == 0 {
		return -1
	}
	return *p
}

// floatPtrOrDefault is the float64 analogue of intPtrOrDefault for the
// retry-jitter field.
func floatPtrOrDefault(p *float64, dflt float64) float64 {
	if p == nil {
		return dflt
	}
	if *p == 0 {
		return -1
	}
	return *p
}

// buildOutput is the shared construction path used by defaultFactory
// and NewFactory.
func buildOutput(name string, rawConfig []byte, om audit.OutputMetrics, fctx audit.FrameworkContext) (audit.Output, error) { //nolint:gocritic // hugeParam: signature constrained by precedent
	var y yamlSplunkConfig
	if err := yaml.Unmarshal(rawConfig, &y); err != nil {
		return nil, fmt.Errorf("audit/splunk: parse YAML config for %q: %w", name, err)
	}

	cfg := &Config{
		URL:                        y.URL,
		Token:                      y.Token,
		Endpoint:                   y.Endpoint,
		Sourcetype:                 y.Sourcetype,
		Source:                     y.Source,
		Index:                      y.Index,
		Host:                       y.Host,
		IndexedFields:              y.IndexedFields,
		BatchSize:                  intPtrOrDefault(y.BatchSize, DefaultBatchSize),
		MaxBatchBytes:              intPtrOrDefault(y.MaxBatchBytes, DefaultMaxBatchBytes),
		MaxEventBytes:              intPtrOrDefault(y.MaxEventBytes, DefaultMaxEventBytes),
		FlushInterval:              durOrDefault(y.FlushInterval, DefaultFlushInterval),
		Gzip:                       y.Gzip,
		UserAgent:                  y.UserAgent,
		Timeout:                    durOrDefault(y.Timeout, DefaultTimeout),
		Headers:                    y.Headers,
		MaxRetries:                 intPtrOrDefault(y.MaxRetries, DefaultMaxRetries),
		RetryBaseDelay:             durOrDefault(y.RetryBaseDelay, DefaultRetryBaseDelay),
		RetryMaxDelay:              durOrDefault(y.RetryMaxDelay, DefaultRetryMaxDelay),
		RetryJitter:                floatPtrOrDefault(y.RetryJitter, DefaultRetryJitter),
		BufferSize:                 intPtrOrDefault(y.BufferSize, DefaultBufferSize),
		AckMode:                    y.AckMode,
		AckPollInterval:            durOrDefault(y.AckPollInterval, DefaultAckPollInterval),
		AckResendWindow:            durOrDefault(y.AckResendWindow, DefaultAckResendWindow),
		TLSCA:                      y.TLSCA,
		TLSCert:                    y.TLSCert,
		TLSKey:                     y.TLSKey,
		AllowInsecureHTTP:          y.AllowInsecureHTTP,
		AllowPrivateRanges:         y.AllowPrivateRanges,
		DisableStartupVerification: y.VerifyOnStartup != nil && !*y.VerifyOnStartup,
		StartupVerificationTimeout: durOrDefault(y.StartupVerificationTimeout, DefaultStartupVerificationTimeout),
	}
	if y.TLSPolicy != nil {
		cfg.TLSPolicy = &audit.TLSPolicy{
			AllowTLS12:       y.TLSPolicy.AllowTLS12,
			AllowWeakCiphers: y.TLSPolicy.AllowWeakCiphers,
		}
	}

	opts := []Option{
		WithDiagnosticLogger(fctx.DiagnosticLogger),
		WithFrameworkContext(fctx),
	}
	if om != nil {
		opts = append(opts, WithOutputMetrics(om))
	}

	return New(cfg, fctx.CoreMetrics, opts...)
}

// durOrDefault returns the wrapped duration if non-zero, else the
// default.
func durOrDefault(y yamlDuration, dflt time.Duration) time.Duration {
	if y == 0 {
		return dflt
	}
	return time.Duration(y)
}
