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
	"fmt"

	"github.com/goccy/go-yaml"

	"github.com/axonops/audit"
)

// yamlFormatterConfig is the YAML representation of a formatter.
// CEF SeverityFunc, DescriptionFunc, and FieldMapping are NOT
// configurable via YAML — they require Go code.
type yamlFormatterConfig struct { //nolint:govet // fieldalignment: readability preferred
	Type          string `yaml:"type"`
	Timestamp     string `yaml:"timestamp"`
	OmitEmpty     bool   `yaml:"omit_empty"`
	Vendor        string `yaml:"vendor"`
	Product       string `yaml:"product"`
	Version       string `yaml:"version"`
	VendorProduct string `yaml:"vendor_product"`
}

// extractFormatterType returns the formatter type string from a raw
// YAML value without constructing the formatter. Returns "" for nil
// values or values with no explicit type (which default to JSON).
func extractFormatterType(raw any) string {
	if raw == nil {
		return ""
	}
	// Scalar: formatter: cef
	if s, ok := raw.(string); ok {
		return s
	}
	// Mapping: formatter: { type: cef, ... }
	if m, ok := raw.(map[string]any); ok {
		if t, ok := m["type"]; ok {
			if s, ok := t.(string); ok {
				return s
			}
		}
	}
	return ""
}

// buildFormatter constructs an [audit.Formatter] from a raw YAML value.
// Returns nil if the value is nil or empty (use auditor default).
// Returns an error for unknown formatter types or invalid options.
func buildFormatter(raw any) (audit.Formatter, error) {
	if raw == nil {
		return nil, nil
	}
	if s, ok := raw.(string); ok && s == "" {
		return nil, nil
	}

	// safeMarshal (not yaml.Marshal) — see safe_marshal.go (#487).
	fmtBytes, marshalErr := safeMarshal(raw)
	if marshalErr != nil {
		return nil, fmt.Errorf("formatter: %w", marshalErr)
	}
	var cfg yamlFormatterConfig
	if err := yaml.UnmarshalWithOptions(fmtBytes, &cfg, yaml.DisallowUnknownField()); err != nil {
		return nil, fmt.Errorf("formatter: %w", audit.WrapUnknownFieldError(err, cfg))
	}

	switch cfg.Type {
	case "json", "":
		return buildJSONFormatter(&cfg)
	case "cef":
		return buildCEFFormatter(&cfg)
	case "cim_change":
		return buildCIMChangeFormatter(&cfg)
	default:
		return nil, fmt.Errorf("formatter: unknown type %q (valid: json, cef, cim_change)", cfg.Type)
	}
}

func buildJSONFormatter(cfg *yamlFormatterConfig) (*audit.JSONFormatter, error) {
	// Reject CEF-specific fields on a JSON formatter.
	if cfg.Vendor != "" || cfg.Product != "" || cfg.Version != "" {
		return nil, fmt.Errorf("formatter: json does not support vendor/product/version options")
	}
	// Reject CIM-specific fields on a JSON formatter.
	if cfg.VendorProduct != "" {
		return nil, fmt.Errorf("formatter: json does not support vendor_product option (use cim_change for that)")
	}

	ts := audit.TimestampFormat(cfg.Timestamp)
	if ts == "" {
		ts = audit.TimestampRFC3339Nano
	}
	switch ts {
	case audit.TimestampRFC3339Nano, audit.TimestampUnixMillis:
		// valid
	default:
		return nil, fmt.Errorf("formatter: unknown timestamp format %q (valid: rfc3339nano, unix_ms)", cfg.Timestamp)
	}
	return &audit.JSONFormatter{
		Timestamp: ts,
		OmitEmpty: cfg.OmitEmpty,
	}, nil
}

func buildCEFFormatter(cfg *yamlFormatterConfig) (*audit.CEFFormatter, error) {
	// Reject JSON-specific fields on a CEF formatter.
	if cfg.Timestamp != "" {
		return nil, fmt.Errorf("formatter: cef does not support timestamp option (got %q)", cfg.Timestamp)
	}
	// Reject CIM-specific fields on a CEF formatter.
	if cfg.VendorProduct != "" {
		return nil, fmt.Errorf("formatter: cef does not support vendor_product option (use vendor and product separately)")
	}

	return &audit.CEFFormatter{
		Vendor:    cfg.Vendor,
		Product:   cfg.Product,
		Version:   cfg.Version,
		OmitEmpty: cfg.OmitEmpty,
		// SeverityFunc, DescriptionFunc, and FieldMapping are NOT
		// configurable via YAML. Consumers who need these should
		// construct the CEFFormatter programmatically.
	}, nil
}

// buildCIMChangeFormatter constructs a [audit.CIMChangeFormatter]
// from YAML. The CIM Change formatter targets the Splunk CIM 6.1
// Change data model. Wire format is NDJSON (`application/x-ndjson`).
// Only the `vendor_product` option is honoured; `timestamp` is
// rejected because CIM canonicalises `_time` to epoch milliseconds
// and an alternate timestamp format would silently mis-index.
func buildCIMChangeFormatter(cfg *yamlFormatterConfig) (*audit.CIMChangeFormatter, error) {
	if cfg.Timestamp != "" {
		return nil, fmt.Errorf("formatter: cim_change does not support timestamp option (CIM uses epoch milliseconds in _time)")
	}
	if cfg.Vendor != "" || cfg.Product != "" || cfg.Version != "" {
		return nil, fmt.Errorf("formatter: cim_change does not support vendor/product/version (use vendor_product instead)")
	}
	if cfg.OmitEmpty {
		return nil, fmt.Errorf("formatter: cim_change does not support omit_empty (CIM mapping is explicit)")
	}
	return &audit.CIMChangeFormatter{
		VendorProduct: cfg.VendorProduct,
	}, nil
}
