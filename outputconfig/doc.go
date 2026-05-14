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

// Package outputconfig loads audit output configuration from a YAML
// document and returns ready-to-use [audit.Option] values for
// [audit.New].
//
// # Registry Pattern
//
// Output modules register factories via [audit.RegisterOutputFactory]
// in their init() functions. This package constructs outputs from YAML
// type strings without importing the output modules directly. The
// consumer controls which output types are available via blank imports:
//
//	import (
//	    "github.com/axonops/audit/outputconfig"
//	    _ "github.com/axonops/audit/file"
//	    _ "github.com/axonops/audit/syslog"
//	    _ "github.com/axonops/audit/webhook"
//	)
//
// If an output type's module is not blank-imported, [Load] returns an
// error for that output — no output is silently dropped.
//
// # YAML Schema
//
// The configuration document has the following top-level keys:
//
//	version: 1                      # required, must be 1
//	app_name: "my-service"          # required, application name (max 255 bytes)
//	host: "${HOSTNAME:-localhost}"   # required, hostname (max 255 bytes; env vars supported)
//	timezone: "UTC"                 # optional, overrides auto-detected timezone
//	auditor:                         # optional, core auditor settings
//	  enabled: true                 # default: true
//	  queue_size: 10000             # default: 10,000 (max: 1,000,000)
//	  shutdown_timeout: "5s"           # default: "5s" (max: "60s")
//	  validation_mode: strict       # "strict" (default), "warn", "permissive"
//	  omit_empty: false             # default: false
//	outputs:                        # required, map of named outputs
//	                                # TLS policy is configured per-output
//	                                # (see each output type's docs).
//	  audit_log:
//	    type: file                  # registered output type
//	    enabled: true               # optional, default true
//	    file:                       # output-specific config block
//	      path: /var/log/audit.log
//	      max_size_mb: 100
//	    formatter:                  # optional per-output formatter
//	      type: cef
//	      vendor: MyCompany
//	      product: MyApp
//	    route:                      # optional per-output event filter
//	      include_categories:
//	        security: {}             # nil filter = any severity for this cat
//	    exclude_labels: [pii]       # optional sensitivity label filter
//	    hmac:                       # optional per-output HMAC integrity
//	      enabled: true
//	      salt:
//	        version: "v1"
//	        value: "${HMAC_SALT}"
//	      algorithm: HMAC-SHA-256
//
// # Environment Variables
//
// Values support ${VAR} and ${VAR:-default} substitution. Expansion
// happens after YAML parsing for injection safety — the raw YAML
// structure is validated first, then string values are expanded.
//
// # Secret References
//
// String values in the YAML configuration can contain ref+SCHEME://PATH#KEY
// URIs that are resolved from external secret backends (OpenBao, Vault)
// at load time. Register providers with [WithSecretProvider]:
//
//	loaded, err := outputconfig.Load(ctx, yamlData, taxonomy,
//	    outputconfig.WithSecretProvider(provider),
//	    outputconfig.WithSecretTimeout(30*time.Second),
//	)
//
// [WithSecretTimeout] controls the overall timeout for all secret
// resolution network I/O. Default: [DefaultSecretTimeout] (10s).
// The caller's context deadline takes precedence when earlier.
//
// # Usage
//
// The primary entry point is [New]; use [NewWithLoad] when [LoadOption]
// values are needed. Both construct a ready-to-use [audit.Auditor] in
// a single call:
//
//	auditor, err := outputconfig.New(ctx, taxonomyYAML, "outputs.yaml")
//	if err != nil {
//	    return fmt.Errorf("audit config: %w", err)
//	}
//	defer auditor.Close()
//
// When the pre-built auditor is not what you want — for example, you
// want to inspect the parsed outputs before constructing the auditor —
// call [Load] directly:
//
//	loaded, err := outputconfig.Load(ctx, yamlData, taxonomy)
//	if err != nil {
//	    return fmt.Errorf("audit config: %w", err)
//	}
//	opts := append([]audit.Option{audit.WithTaxonomy(taxonomy)}, loaded.Options()...)
//	auditor, err := audit.New(opts...)
//	if err != nil {
//	    _ = loaded.Close() // clean up outputs the auditor would have owned
//	    return err
//	}
//
// [Load] fails hard on any configuration error — partial configurations
// are never returned. This ensures that a misconfigured output does not
// silently drop audit events.
package outputconfig
