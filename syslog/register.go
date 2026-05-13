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

package syslog

import (
	"bytes"
	"fmt"
	"log/slog"
	"time"

	"github.com/axonops/audit"
	"github.com/goccy/go-yaml"
)

func init() {
	audit.MustRegisterOutputFactory("syslog", defaultFactory)
}

// defaultFactory creates a syslog output from YAML config. Reads the
// diagnostic logger and per-output metrics from fctx; the framework
// AppName is honoured as the RFC 5424 APP-NAME default when the
// per-output `app_name` is omitted. Use [NewFactory] when
// constructing outside outputconfig and you want to wire an
// [audit.OutputMetricsFactory] directly.
func defaultFactory(name string, rawConfig []byte, fctx audit.FrameworkContext) (audit.Output, error) { //nolint:gocritic // hugeParam: signature fixed by audit.OutputFactory (#696)
	return buildOutput(name, rawConfig, fctx.OutputMetrics, fctx.DiagnosticLogger)
}

// NewFactory returns an [audit.OutputFactory] that creates syslog
// outputs from YAML configuration and wires per-output metrics via
// the supplied [audit.OutputMetricsFactory]. When factory is non-nil,
// the returned [audit.Output] receives its per-output
// [audit.OutputMetrics] via [WithOutputMetrics] at construction time;
// if the returned metrics also implement [ReconnectRecorder],
// reconnection telemetry is wired in automatically. Pass nil to
// disable per-output metrics.
//
// Signature is identical to the other output modules'
// `NewFactory` (file, webhook, loki) for consistency (#581).
func NewFactory(factory audit.OutputMetricsFactory) audit.OutputFactory {
	return func(name string, rawConfig []byte, fctx audit.FrameworkContext) (audit.Output, error) {
		var om audit.OutputMetrics
		if factory != nil {
			om = factory("syslog", name)
		}
		return buildOutput(name, rawConfig, om, fctx.DiagnosticLogger)
	}
}

// yamlTLSPolicy maps TLS policy fields from YAML.
type yamlTLSPolicy struct {
	AllowTLS12       bool `yaml:"allow_tls12"`
	AllowWeakCiphers bool `yaml:"allow_weak_ciphers"`
}

// yamlSyslogConfig is the YAML-specific representation of syslog
// output configuration. Maps snake_case YAML fields to the Go
// Config struct.
type yamlSyslogConfig struct { //nolint:govet // fieldalignment: readability preferred
	Network       string         `yaml:"network"`
	Address       string         `yaml:"address"`
	AppName       string         `yaml:"app_name"`
	Facility      string         `yaml:"facility"`
	TLSCert       string         `yaml:"tls_cert"`
	TLSKey        string         `yaml:"tls_key"`
	TLSCA         string         `yaml:"tls_ca"`
	TLSPolicy     *yamlTLSPolicy `yaml:"tls_policy"`
	Hostname      string         `yaml:"hostname"`
	MaxRetries    int            `yaml:"max_retries"`
	BufferSize    *int           `yaml:"buffer_size"`
	BatchSize     *int           `yaml:"batch_size"`
	FlushInterval string         `yaml:"flush_interval"`
	MaxBatchBytes *int           `yaml:"max_batch_bytes"`
	MaxEventBytes *int           `yaml:"max_event_bytes"`
	// VerifyOnStartup is the positive YAML surface for the inverted
	// Config.DisableStartupVerification field. A nil pointer (key
	// omitted) maps to verification ON; an explicit `true` keeps it
	// ON; an explicit `false` opts out. See [Config.DisableStartupVerification].
	VerifyOnStartup        *bool  `yaml:"verify_on_startup"`
	VerifyOnStartupTimeout string `yaml:"verify_on_startup_timeout"`
}

// intPtrOrDefault returns the pointed-to value if non-nil, or the
// default if nil (field not specified in YAML). When the pointer is
// non-nil and the value is zero, returns -1 as a sentinel.
// applyDefaults treats values <= 0 as "not set" and replaces them
// with the default, so explicit YAML zero silently becomes the
// default.
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

func buildOutput(name string, rawConfig []byte, om audit.OutputMetrics, logger *slog.Logger) (audit.Output, error) {
	if len(rawConfig) == 0 {
		return nil, fmt.Errorf("audit/syslog: output %q: config is required", name)
	}

	var yc yamlSyslogConfig
	dec := yaml.NewDecoder(bytes.NewReader(rawConfig), yaml.DisallowUnknownField())
	if err := dec.Decode(&yc); err != nil {
		return nil, fmt.Errorf("audit/syslog: output %q: %w", name, audit.WrapUnknownFieldError(err, yc))
	}

	cfg, err := yamlToSyslogConfig(name, &yc)
	if err != nil {
		return nil, err
	}

	opts := []Option{WithDiagnosticLogger(logger)}
	if om != nil {
		opts = append(opts, WithOutputMetrics(om))
	}

	out, err := New(cfg, opts...)
	if err != nil {
		return nil, fmt.Errorf("audit/syslog: output %q: %w", name, err)
	}
	return audit.WrapOutput(out, name), nil
}

// yamlToSyslogConfig converts the YAML decoder struct into the typed
// Config, applying defaults and parsing duration strings.
func yamlToSyslogConfig(name string, yc *yamlSyslogConfig) (*Config, error) {
	cfg := &Config{
		Network:       yc.Network,
		Address:       yc.Address,
		AppName:       yc.AppName,
		Facility:      yc.Facility,
		TLSCert:       yc.TLSCert,
		TLSKey:        yc.TLSKey,
		TLSCA:         yc.TLSCA,
		Hostname:      yc.Hostname,
		MaxRetries:    yc.MaxRetries,
		BufferSize:    intPtrOrDefault(yc.BufferSize, DefaultBufferSize),
		BatchSize:     intPtrOrDefault(yc.BatchSize, DefaultBatchSize),
		MaxBatchBytes: intPtrOrDefault(yc.MaxBatchBytes, DefaultMaxBatchBytes),
		MaxEventBytes: intPtrOrDefault(yc.MaxEventBytes, DefaultMaxEventBytes),
	}
	if yc.FlushInterval != "" {
		d, err := time.ParseDuration(yc.FlushInterval)
		if err != nil {
			return nil, fmt.Errorf("audit/syslog: output %q: flush_interval %q: %w", name, yc.FlushInterval, audit.ErrConfigInvalid)
		}
		cfg.FlushInterval = d
	}
	if yc.VerifyOnStartupTimeout != "" {
		d, err := time.ParseDuration(yc.VerifyOnStartupTimeout)
		if err != nil {
			return nil, fmt.Errorf("audit/syslog: output %q: verify_on_startup_timeout %q: %w", name, yc.VerifyOnStartupTimeout, audit.ErrConfigInvalid)
		}
		cfg.StartupVerificationTimeout = d
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
	return cfg, nil
}
