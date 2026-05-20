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

package splunk_test

import (
	"fmt"

	"github.com/axonops/audit/splunk"
)

// ExampleNew shows the minimal construction shape against the
// default `/event` endpoint with JSON envelope wrapping and the
// `Authorization: Splunk <token>` header.
//
// In production code, pass a real [audit.OutputMetrics] via
// [splunk.WithOutputMetrics]. The auditor will wire the output via
// [audit.WithOutputs] (or via the outputconfig YAML loader) and
// call `Write` on every emitted event.
func ExampleNew() {
	// Note: this example does NOT contact a real Splunk endpoint —
	// DisableStartupVerification skips the /health probe so the
	// example can run without network access.
	cfg := &splunk.Config{
		URL:                        "https://splunk.example.com:8088",
		Token:                      "your-hec-token",
		Sourcetype:                 "axonops:audit",
		Index:                      "audit_logs",
		DisableStartupVerification: true,
	}
	out, err := splunk.New(cfg, nil)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	defer func() { _ = out.Close() }()

	// In real code: pass the output to audit.New via audit.WithOutputs.
	fmt.Println(out.Name() != "")
	// Output: true
}

// ExampleNew_raw shows the `/services/collector/raw` endpoint mode,
// where events are sent as newline-delimited bodies and metadata
// travels in the URL query string. Useful when consumer events are
// already line-oriented (e.g. CEF) and Splunk-side `props.conf`
// owns the parsing.
func ExampleNew_raw() {
	cfg := &splunk.Config{
		URL:                        "https://splunk.example.com:8088",
		Token:                      "your-hec-token",
		Endpoint:                   splunk.EndpointRaw,
		Sourcetype:                 "axonops:audit",
		Source:                     "axonops-audit",
		Index:                      "audit_logs",
		DisableStartupVerification: true,
	}
	out, err := splunk.New(cfg, nil)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	defer func() { _ = out.Close() }()
	fmt.Println("ok")
	// Output: ok
}

// ExampleConfig_redaction demonstrates that Config's String /
// GoString / Format methods redact the token across every fmt verb.
// This is a load-bearing security guarantee — the token must NEVER
// appear in log lines, error messages, or stack traces.
func ExampleConfig_redaction() {
	cfg := splunk.Config{
		URL:   "https://splunk.example.com:8088",
		Token: "super-secret-token",
	}
	fmt.Println(cfg.String())
	// Output: SplunkConfig{url="https://splunk.example.com:8088", endpoint=event, sourcetype="", index="", gzip=<default>, batch_size=0, max_batch_bytes=0, ack_mode=off, token=REDACTED}
}
