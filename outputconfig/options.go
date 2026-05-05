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
	"log/slog"
	"time"

	"github.com/axonops/audit"
	"github.com/axonops/audit/secrets"
)

// DefaultSecretTimeout is the default timeout for secret resolution
// when no explicit timeout is configured via [WithSecretTimeout].
const DefaultSecretTimeout = 10 * time.Second

// LoadOption configures optional behaviour for [Load].
type LoadOption func(*loadOptions)

// loadOptions holds the resolved options for a Load call.
type loadOptions struct {
	coreMetrics          audit.Metrics
	outputMetricsFactory audit.OutputMetricsFactory
	factories            map[string]audit.OutputFactory
	diagnosticLogger     *slog.Logger
	providers            []secrets.Provider
	secretTimeout        time.Duration
	secretTimeoutSet     bool // true when WithSecretTimeout was called explicitly
}

// WithSecretProvider registers a secret provider for resolving ref+
// URIs during config loading. Multiple providers can be registered
// for different schemes. Duplicate schemes cause [Load] to return an
// error.
func WithSecretProvider(p secrets.Provider) LoadOption {
	return func(o *loadOptions) {
		o.providers = append(o.providers, p)
	}
}

// WithSecretTimeout sets the overall timeout for secret resolution.
// This timeout applies to all provider Resolve calls combined during
// a single [Load] invocation. Default: [DefaultSecretTimeout] (10s).
// The caller's context deadline takes precedence when earlier.
func WithSecretTimeout(d time.Duration) LoadOption {
	return func(o *loadOptions) {
		if d > 0 {
			o.secretTimeout = d
			o.secretTimeoutSet = true
		}
	}
}

// WithCoreMetrics sets the core [audit.Metrics] implementation that is
// forwarded to output factories during construction. If m is nil,
// factories receive nil metrics (equivalent to not calling this option).
// This option replaces the former positional `coreMetrics` parameter
// on [Load].
func WithCoreMetrics(m audit.Metrics) LoadOption {
	return func(o *loadOptions) {
		o.coreMetrics = m
	}
}

// WithOutputMetrics sets the [audit.OutputMetricsFactory] used to
// create per-output metrics during [Load]. The factory is called once
// per output with the output type name and YAML key name. Pass nil to
// disable per-output metrics.
//
// The factory is invoked BEFORE output construction (#696). The
// resulting [audit.OutputMetrics] value is threaded into the output's
// constructor via [audit.FrameworkContext], which means rotation /
// reconnect telemetry sees the correct sink from the very first
// event onward.
func WithOutputMetrics(factory audit.OutputMetricsFactory) LoadOption {
	return func(o *loadOptions) {
		o.outputMetricsFactory = factory
	}
}

// WithFactory registers a per-call output factory override for the
// given type name. Per-call factories take precedence over globally
// registered factories. Multiple calls for the same type: last wins.
//
// # Choosing a registration path
//
// WithFactory is one of two registration paths. The other is
// [github.com/axonops/audit.RegisterOutputFactory] (typically
// invoked from init() via a blank-import of an output sub-module
// such as [github.com/axonops/audit/outputs] or
// [github.com/axonops/audit/file]), which mutates the global
// registry and applies process-wide.
//
// Use WithFactory for tests, per-call overrides, or multiple
// auditors in one process with different factory bindings. Use
// RegisterOutputFactory (via blank-import) for default production
// setup. See the "Output Factory Registration" section of
// docs/output-configuration.md for full guidance on choosing between
// them.
func WithFactory(typeName string, factory audit.OutputFactory) LoadOption {
	return func(o *loadOptions) {
		if o.factories == nil {
			o.factories = make(map[string]audit.OutputFactory)
		}
		o.factories[typeName] = factory
	}
}

// WithDiagnosticLogger sets the diagnostic logger that is threaded
// through to every output constructed by [Load]. The logger reaches
// each output's [OutputFactory] via its logger parameter, so
// construction-time warnings (TLS policy, file permission mode) route
// to the consumer's configured handler rather than [slog.Default].
//
// Pair this with [audit.WithDiagnosticLogger] on the [audit.Auditor]
// so that construction-time AND runtime warnings route through the
// same handler. Passing nil is valid and equivalent to not calling
// this option — factories fall back to [slog.Default].
func WithDiagnosticLogger(l *slog.Logger) LoadOption {
	return func(o *loadOptions) {
		o.diagnosticLogger = l
	}
}

// resolveOptions applies all LoadOptions and returns the resolved config.
func resolveOptions(opts []LoadOption) loadOptions {
	lo := loadOptions{
		secretTimeout: DefaultSecretTimeout,
	}
	for _, opt := range opts {
		opt(&lo)
	}
	return lo
}
