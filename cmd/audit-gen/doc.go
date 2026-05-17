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

// Command audit-gen reads a YAML taxonomy file and emits one of
// three artifact types:
//
//   - Go source — type-safe Go constants for event types,
//     categories, fields, and typed event builders. The default
//     and the most common use; consume from a `go generate` step
//     or a Makefile rule.
//
//   - JSON Schema (Draft 2020-12) — a language-neutral validator
//     for the audit event JSON shape. Use it from non-Go consumers
//     (Python, Java, SIEM rule authors) to validate events produced
//     by the audit library's JSON formatter (#548).
//
//   - CEF template — a documentation artifact describing the CEF
//     mapping the library applies. SIEM rule authors read it to
//     align field-extraction rules with the library's CEF output
//     (#548).
//
// Usage (Go source — default):
//
//	audit-gen -input taxonomy.yaml -output audit_generated.go -package mypackage
//
// Usage (JSON Schema):
//
//	audit-gen -format json-schema -input taxonomy.yaml -output audit-event.schema.json
//
// Usage (CEF template):
//
//	audit-gen -format cef-template -input taxonomy.yaml -output audit-event.cef.template
//
// Run `audit-gen -help` for the full flag list.
//
// Exit codes:
//
//	0  success
//	1  invalid arguments or missing required flags
//	2  YAML parse error or taxonomy validation failure
//	3  output file write error
package main
