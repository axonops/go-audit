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

// Package splunk provides a Splunk HTTP Event Collector (HEC) output
// for the audit library.
//
// The output posts audit events to a Splunk indexer (Splunk Enterprise
// or Splunk Cloud) via the HEC POST API. Events are batched, gzipped
// by default, and delivered with full HEC error-code handling and
// exponential backoff on retryable failures.
//
// # Endpoints
//
// Two HEC endpoints are supported, selected via [Config.Endpoint]:
//
//   - [EndpointEvent] (default) — POST /services/collector/event with
//     a JSON envelope per event (`{"event":...,"time":...,"sourcetype":...,...}`).
//     Multiple events are concatenated (no separator, whitespace tolerated).
//   - [EndpointRaw] — POST /services/collector/raw with newline-delimited
//     bodies. Metadata (sourcetype, source, index, host) travels in the
//     URL query string. Splunk-side `props.conf` controls parsing.
//
// # Authentication
//
// HEC tokens authenticate via the `Authorization: Splunk <token>` header
// — note the literal "Splunk" scheme (not "Bearer"). Tokens are opaque
// strings (GUIDs in Splunk Web; arbitrary on Enterprise via
// `inputs.conf`). The library rejects tokens that start with "Splunk "
// or "Bearer " (foot-gun: the consumer accidentally including the scheme
// prefix) and tokens containing CR/LF/NUL (HTTP header-injection
// defence).
//
// # Splunk Cloud
//
// Splunk Cloud HEC endpoints use the URL form
// `https://http-inputs-<stack>.splunkcloud.com/services/collector/event`.
// In PR 2 the `splunkcloud://<stack>` URL scheme expands to this form
// automatically. In PR 1 use the full URL.
//
// # Indexer Acknowledgement
//
// HEC indexer acknowledgement is the durability gap between "HEC
// accepted" (HTTP 200) and "indexer replicated at the cluster's
// replication factor". Three modes are exposed via [Config.AckMode]:
//
//   - [AckModeOff] (default) — no channel header, no polling. Lowest
//     overhead; HTTP 200 is the only durability signal.
//   - [AckModeBestEffort] — channel GUID generated, ack polled at
//     [Config.AckPollInterval], surfaced as metrics; buffer progress
//     is NOT gated. Good observability without back-pressure cost.
//   - [AckModeRequired] — events stay in the outbound buffer until ack
//     returns positive. Compliance-grade durability. PR 2.
//
// In PR 1, only [AckModeOff] is implemented; non-Off values are
// accepted at config time but produce a "not implemented in PR 1"
// error from [New].
//
// # TLS and SSRF
//
// TLS is configured via [Config.TLSPolicy] (which uses the core
// [audit.TLSPolicy] type — TLS 1.2 floor). Custom CA via [Config.TLSCA]
// (file path). mTLS via [Config.TLSCert] and [Config.TLSKey] (file
// paths; Splunk Enterprise 10.0+ only — Splunk Cloud does not support
// mTLS for HEC).
//
// SSRF prevention is wired via the core's [audit.NewSSRFDialControl].
// Requests to private, loopback, link-local, multicast, and
// cloud-metadata IPs are blocked by default;
// [Config.AllowPrivateRanges] = true opts in for test or dev
// deployments.
//
// # Import
//
// Import this package for its side effect of registering the "splunk"
// output type with the audit output registry:
//
//	import _ "github.com/axonops/audit/splunk"
//
// Or import the convenience [github.com/axonops/audit/outputs] package
// which blank-imports every built-in output backend.
package splunk
