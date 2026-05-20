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
	"log/slog"

	"github.com/axonops/audit"
)

// Option configures a Splunk [Output] at construction time. Options
// are passed as variadic arguments to [New] and applied in order
// before configuration validation, TLS setup, or warning emission.
type Option func(*options)

// options holds resolved construction-time settings. Zero value is
// valid — all fields receive sensible defaults inside [New].
type options struct {
	logger        *slog.Logger
	outputMetrics audit.OutputMetrics
	fctx          audit.FrameworkContext
	maxIdleConns  int
}

// WithDiagnosticLogger routes construction-time and runtime warnings
// (TLS policy, retry, buffer-full drops) to the given logger. When
// nil or not supplied, warnings go to [slog.Default].
//
// Consumers normally do not call this directly when using
// [github.com/axonops/audit/outputconfig.New] — outputconfig plumbs
// the auditor's diagnostic logger into every output it constructs.
// Use this option when constructing a Splunk output programmatically
// and you want its warnings to match your application's log handler.
//
// Mirrors [github.com/axonops/audit.WithDiagnosticLogger] at the
// auditor level; the same logger may be passed to both for
// consistent routing.
func WithDiagnosticLogger(l *slog.Logger) Option {
	return func(o *options) { o.logger = l }
}

// WithOutputMetrics sets the [audit.OutputMetrics] sink for this
// output. When omitted or nil, metrics calls become no-ops via
// [audit.NoOpOutputMetrics]. Mirrors [WithDiagnosticLogger] in usage
// and zero-value semantics.
//
// Consumers normally do not call this directly when using
// [github.com/axonops/audit/outputconfig.New] — outputconfig wires
// per-output metrics through the [audit.OutputMetricsFactory]
// supplied via outputconfig.WithOutputMetricsFactory.
func WithOutputMetrics(m audit.OutputMetrics) Option {
	return func(o *options) {
		if m == nil {
			m = audit.NoOpOutputMetrics{}
		}
		o.outputMetrics = m
	}
}

// WithFrameworkContext seeds the auditor-wide framework metadata
// (AppName, Host, Timezone, PID) used for envelope `host` defaulting.
// When omitted, the Output falls back to [os.Hostname] at
// construction time.
//
// Consumers normally do not call this directly when using
// [github.com/axonops/audit/outputconfig.New] — outputconfig
// populates the equivalent values from the auditor configuration.
// Use this option when constructing a Splunk output programmatically
// (for example in integration tests).
func WithFrameworkContext(fctx audit.FrameworkContext) Option { //nolint:gocritic // hugeParam: shape mirrors audit.FrameworkContext (constructor-time, not on hot path)
	return func(o *options) { o.fctx = fctx }
}

// WithMaxIdleConns sets the HTTP transport's maximum idle connection
// pool size. Default is 100, matching the loki/webhook precedent.
// Increase for tier-1 SaaS pushing tens of MB/s to a single HEC
// endpoint; decrease only if you understand the keep-alive cost
// trade-off.
//
// Exposed as an Option (not a Config field) because it is a HTTP
// transport tuning knob, not a feature surface. Mirrors the
// established escape-hatch pattern used by loki and webhook for
// the small set of low-level transport tunings (#688 / #770).
func WithMaxIdleConns(n int) Option {
	return func(o *options) {
		if n > 0 {
			o.maxIdleConns = n
		}
	}
}

// defaultMaxIdleConns matches the loki/webhook precedent.
const defaultMaxIdleConns = 100

// resolveOptions applies the given options over a defaulted value.
// A nil logger (either absent or explicitly WithDiagnosticLogger(nil))
// falls back to [slog.Default]. A nil outputMetrics falls back to
// [audit.NoOpOutputMetrics]. maxIdleConns falls back to 100.
func resolveOptions(opts []Option) options {
	o := options{}
	for _, opt := range opts {
		opt(&o)
	}
	if o.logger == nil {
		o.logger = slog.Default()
	}
	if o.outputMetrics == nil {
		o.outputMetrics = audit.NoOpOutputMetrics{}
	}
	if o.maxIdleConns <= 0 {
		o.maxIdleConns = defaultMaxIdleConns
	}
	return o
}
