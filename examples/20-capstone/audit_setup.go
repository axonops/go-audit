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
	"context"

	"github.com/axonops/audit"
	"github.com/axonops/audit/outputconfig"
	_ "github.com/axonops/audit/outputs" // registers stdout, file, syslog, webhook, loki
)

// setupAuditor creates an auditor using the outputconfig.New facade.
// The taxonomy is embedded (compile-time contract), and output
// configuration is loaded from the filesystem at runtime so it can
// change per environment without rebuilding the binary.
//
// Blank imports register each output type's factory via init().
// The YAML file defines which outputs are active — adding or removing
// outputs is a config change, not a code change. Per-output delivery
// metrics (drops, flushes, errors, retries) are scoped by output
// type and name via the OutputMetricsFactory.
//
// HMAC salts, versions, algorithms, and enabled flags are resolved
// from OpenBao at startup via ref+openbao:// URIs in outputs.yaml.
// The OpenBao provider is configured declaratively in the outputs.yaml
// secrets: section — no programmatic provider setup is needed.
func setupAuditor(m *auditMetrics) (*audit.Auditor, error) {
	configPath := envOr("AUDIT_CONFIG_PATH", "outputs.yaml")
	return outputconfig.NewWithLoad(context.Background(), taxonomyYAML, configPath,
		[]outputconfig.LoadOption{
			outputconfig.WithCoreMetrics(m),
			outputconfig.WithOutputMetrics(m.newOutputMetricsFactory()),
		},
		audit.WithMetrics(m),
	)
}
