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

// Example 16: Buffering and Backpressure
//
// Demonstrates the two-level buffering architecture:
//
//   - Level 1 (core buffer): a tiny buffer_size triggers ErrQueueFull
//     when events are produced faster than the drain goroutine can process.
//   - Level 2 (webhook buffer): an unreachable webhook endpoint fills
//     the per-output buffer, triggering silent drops with metrics.
//
// All non-stdout outputs have their own internal buffer and goroutine.
// The webhook output additionally batches events before HTTP delivery.
//
// Run:
//
//	go run .
package main

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/axonops/audit"
	"github.com/axonops/audit/outputconfig"
	_ "github.com/axonops/audit/outputs" // registers stdout, file, syslog, webhook, loki
)

//go:generate go run github.com/axonops/audit/cmd/audit-gen -input taxonomy.yaml -output audit_generated.go -package main

//go:embed taxonomy.yaml
var taxonomyYAML []byte

func main() {
	// Parse taxonomy.
	// Single-call facade: parse taxonomy, load outputs, create auditor.
	auditor, err := outputconfig.New(context.Background(), taxonomyYAML, "outputs.yaml")
	if err != nil {
		log.Fatalf("create auditor: %v", err)
	}

	// --- Level 1: Core Buffer Backpressure ---
	//
	// The core queue is set to 5 (outputs.yaml: auditor.queue_size: 5).
	// We emit 20 events in a tight loop. Some AuditEvent() calls will
	// find the channel full and return ErrQueueFull.
	fmt.Println("--- Level 1: Core Queue (queue_size: 5) ---")
	fmt.Println("Emitting 20 events in a tight loop...")

	var delivered, dropped int
	for i := range 20 {
		actor := fmt.Sprintf("user-%d", i)
		evt := NewUserCreateEvent(actor, "success")
		if auditErr := auditor.AuditEvent(evt); auditErr != nil {
			if errors.Is(auditErr, audit.ErrQueueFull) {
				dropped++
			} else {
				log.Printf("unexpected error: %v", auditErr)
			}
		} else {
			delivered++
		}
	}

	fmt.Printf("  Delivered: %d, Dropped (ErrQueueFull): %d\n", delivered, dropped)
	if dropped > 0 {
		fmt.Println("  → Core queue was full. In production, increase auditor.queue_size.")
	}

	// --- Level 2: Per-Output Buffer Drops ---
	//
	// The webhook output points at http://localhost:19999 — nothing is
	// listening. The webhook's batch goroutine will attempt to POST,
	// fail, retry once, then drop the batch. When the webhook's internal
	// buffer (buffer_size: 10) fills, subsequent events are dropped
	// silently with a rate-limited slog.Warn.
	//
	// The file output is unaffected — it has its own internal buffer
	// and writes successfully. Events dropped by the webhook are still
	// delivered to the file.
	fmt.Println("\n--- Level 2: Webhook Buffer (buffer_size: 10) ---")
	fmt.Println("The webhook points at an unreachable endpoint.")
	fmt.Println("Watch stderr for drop warnings from the webhook output.")
	fmt.Println("The file output (async, separate buffer) is unaffected.")

	// Give the drain goroutine time to process the first burst and
	// let the webhook's batch loop attempt delivery.
	time.Sleep(3 * time.Second)

	// --- Summary ---
	fmt.Println("\n--- Buffering Architecture Summary ---")
	fmt.Print(`
Two levels of buffering exist in the pipeline:

  Level 1: Core Intake Queue
    AuditEvent() → channel (auditor.queue_size) → drain goroutine
    Drop signal: ErrQueueFull returned to caller
    Tuning: increase auditor.queue_size (default 10,000)

  Level 2: Per-Output Buffer (all outputs except stdout)
    Drain goroutine → output channel (output buffer_size) → writeLoop/batchLoop
    Drop signal: OutputMetrics.RecordDrop() + slog.Warn
    Tuning: increase output buffer_size, decrease flush_interval

  Only stdout writes synchronously from the drain goroutine.
  All other outputs have independent async buffers.

See docs/async-delivery.md for the full architecture reference.
`)

	// Close flushes remaining events. The file output will have all
	// delivered events. The webhook will have dropped most of them.
	if closeErr := auditor.Close(); closeErr != nil {
		log.Printf("close: %v", closeErr)
	}

	fmt.Println("Check the audit file for delivered events:")
	fmt.Println("  cat audit-buffering-demo.log | head -5")
	fmt.Println("  cat audit-buffering-demo.log | wc -l")
	fmt.Println("  rm audit-buffering-demo.log  # clean up when done")
}
