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

// Package webhook provides a batched HTTP webhook [audit.Output]
// implementation with retry, SSRF prevention, and graceful shutdown.
//
// # Security
//
// HTTPS is required by default. [Config.AllowInsecureHTTP] MUST NOT be
// set to true in production — plaintext HTTP exposes credentials in
// request headers to network observers. Private and loopback IP ranges
// are blocked unless [Config.AllowPrivateRanges] is explicitly enabled.
//
// # Batching and Delivery
//
// Events are buffered in memory and flushed using the Content-Type
// reported by the output's configured formatter — application/x-ndjson
// for the built-in [audit.JSONFormatter], text/plain for [audit.CEFFormatter],
// or whatever a third-party Formatter declares via
// [audit.Formatter.ContentType]. The batch flushes when it reaches
// [Config.BatchSize] events or [Config.FlushInterval] elapses. Failed
// batches are retried with exponential backoff up to [Config.MaxRetries]
// times. Delivery semantics are at-least-once: a batch may be delivered
// more than once if the server accepts the payload but the
// acknowledgement is lost.
//
// # Construction
//
//	out, err := webhook.New(&webhook.Config{
//	    URL:       "https://ingest.example.com/audit",
//	    BatchSize: 50,
//	    Timeout:   15 * time.Second,
//	}, nil) // optional audit.Metrics for pipeline delivery reporting
//
// Recommended import alias:
//
//	import auditwebhook "github.com/axonops/audit/webhook"
package webhook
