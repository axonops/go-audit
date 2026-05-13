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

package loki_test

import (
	"fmt"
	"time"

	"github.com/axonops/audit/loki"
)

// ExampleNew demonstrates creating a Loki output with stream labels
// and gzip compression.
func ExampleNew() {
	cfg := &loki.Config{
		URL:                "http://localhost:3100/loki/api/v1/push",
		AllowInsecureHTTP:  true, // local dev only
		AllowPrivateRanges: true, // local dev only
		BatchSize:          100,
		FlushInterval:      5 * time.Second,
		Timeout:            10 * time.Second,
		MaxRetries:         3,
		BufferSize:         10000,
		Gzip:               true,
		Labels: loki.LabelConfig{
			Static: map[string]string{
				"job":         "audit",
				"environment": "development",
			},
		},
		// In production, keep verify_on_startup at its default (true)
		// so misconfigured destinations fail fast at New(). The
		// example disables it because godoc executes examples without
		// a live Loki receiver.
		DisableStartupVerification: true,
	}

	out, err := loki.New(cfg, nil)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		return
	}
	defer func() { _ = out.Close() }()

	fmt.Println(out.Name())
	fmt.Println(out.ReportsDelivery())
	// Output:
	// loki:localhost:3100
	// true
}
