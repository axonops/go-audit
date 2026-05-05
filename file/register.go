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

package file

import (
	"bytes"
	"fmt"
	"log/slog"

	"github.com/axonops/audit"
	"github.com/goccy/go-yaml"
)

func init() {
	audit.MustRegisterOutputFactory("file", defaultFactory)
}

// defaultFactory creates a file output from YAML config. Reads the
// diagnostic logger and per-output metrics from fctx; framework
// fields (AppName/Host/Timezone/PID) are not used by the file output
// (no per-event labels needed). Use [NewFactory] when constructing
// outside outputconfig and you want to wire an
// [audit.OutputMetricsFactory] directly.
func defaultFactory(name string, rawConfig []byte, fctx audit.FrameworkContext) (audit.Output, error) { //nolint:gocritic // hugeParam: signature fixed by audit.OutputFactory (#696)
	return buildOutput(name, rawConfig, fctx.OutputMetrics, fctx.DiagnosticLogger)
}

// NewFactory returns an [audit.OutputFactory] that creates file
// outputs from YAML configuration and wires per-output metrics via
// the supplied [audit.OutputMetricsFactory]. When factory is non-nil,
// the returned [audit.Output] receives its per-output
// [audit.OutputMetrics] via [WithOutputMetrics] at construction time;
// if the returned metrics also implement [RotationRecorder], rotation
// telemetry is wired in automatically. Pass nil to disable per-output
// metrics (equivalent to the init()-registered default factory).
//
// Signature is identical to the other output modules'
// `NewFactory` (syslog, webhook, loki) for consistency (#581).
func NewFactory(factory audit.OutputMetricsFactory) audit.OutputFactory {
	return func(name string, rawConfig []byte, fctx audit.FrameworkContext) (audit.Output, error) {
		var om audit.OutputMetrics
		if factory != nil {
			om = factory("file", name)
		}
		return buildOutput(name, rawConfig, om, fctx.DiagnosticLogger)
	}
}

// yamlFileConfig is the YAML-specific representation of file output
// configuration. It maps snake_case YAML fields to the Go Config
// struct. The existing Config struct does not gain yaml tags —
// this struct is the mapping layer.
type yamlFileConfig struct { //nolint:govet // fieldalignment: readability preferred over packing
	Path          string `yaml:"path"`
	GroupReadable bool   `yaml:"group_readable"`
	MaxSizeMB     int    `yaml:"max_size_mb"`
	MaxBackups    int    `yaml:"max_backups"`
	MaxAgeDays    int    `yaml:"max_age_days"`
	Compress      *bool  `yaml:"compress"`
	BufferSize    *int   `yaml:"buffer_size"`
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
		return -1 // sentinel: explicit zero from YAML → rejected by validation
	}
	return *p
}

func buildOutput(name string, rawConfig []byte, om audit.OutputMetrics, logger *slog.Logger) (audit.Output, error) {
	if len(rawConfig) == 0 {
		return nil, fmt.Errorf("audit/file: output %q: config is required", name)
	}

	var yc yamlFileConfig
	dec := yaml.NewDecoder(bytes.NewReader(rawConfig), yaml.DisallowUnknownField())
	if err := dec.Decode(&yc); err != nil {
		return nil, fmt.Errorf("audit/file: output %q: %w", name, audit.WrapUnknownFieldError(err, yc))
	}

	cfg := Config{
		Path:          yc.Path,
		GroupReadable: yc.GroupReadable,
		MaxSizeMB:     yc.MaxSizeMB,
		MaxBackups:    yc.MaxBackups,
		MaxAgeDays:    yc.MaxAgeDays,
		Compress:      yc.Compress,
		BufferSize:    intPtrOrDefault(yc.BufferSize, DefaultBufferSize),
	}

	opts := []Option{WithDiagnosticLogger(logger)}
	if om != nil {
		opts = append(opts, WithOutputMetrics(om))
	}

	out, err := New(&cfg, opts...)
	if err != nil {
		return nil, fmt.Errorf("audit/file: output %q: %w", name, err)
	}
	return audit.WrapOutput(out, name), nil
}
