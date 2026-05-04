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

//go:build linux

// Command file-enospc-runner is a hermetic test helper for the BDD
// scenario "File output records RecordError on ENOSPC" (#748).
//
// Strategy: the helper runs inside the privileged docker-compose
// container declared in tests/bdd/docker-compose.file-os.yml, which
// mounts a tmpfs of fixed size at /audit-test-tmpfs. The helper
// configures the audit file output to write to a path on that tmpfs
// and writes events until the tmpfs is full. Once the kernel returns
// ENOSPC, the file output's writeBatch error path fires
// om.RecordError, which we observe via a counting MockOutputMetrics.
//
// Markers (consumed by the BDD step):
//
//	stdout contains "ENOSPC_OBSERVED" + exit 0   — RecordError fired
//	any other outcome                            — exit non-zero
package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/axonops/audit"
	"github.com/axonops/audit/file"
)

const tmpfsPath = "/audit-test-tmpfs"

type errorCounter struct {
	audit.NoOpOutputMetrics
	mu     sync.Mutex
	errors int
}

func (e *errorCounter) RecordError() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.errors++
}

func (e *errorCounter) count() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.errors
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// Sanity: the tmpfs must be present (mounted by the harness).
	if info, err := os.Stat(tmpfsPath); err != nil {
		return fmt.Errorf("tmpfs path %q not found — was the file-os harness started? %w", tmpfsPath, err)
	} else if !info.IsDir() {
		return fmt.Errorf("tmpfs path %q is not a directory", tmpfsPath)
	}

	tax := &audit.Taxonomy{
		Version: 1,
		Categories: map[string]*audit.CategoryDef{
			"write": {Events: []string{"enospc_test"}},
		},
		Events: map[string]*audit.EventDef{
			"enospc_test": {
				Categories: []string{"write"},
				Required:   []string{"outcome"},
				Optional:   []string{"payload"},
			},
		},
	}

	logPath := tmpfsPath + "/audit.log"
	metrics := &errorCounter{}

	// MaxSizeMB at the floor (1) keeps the rotate writer in
	// per-file-size enforcement mode. The tmpfs (256 KiB) fills
	// well before the 1 MiB rotation threshold, so the failure
	// mode is "write returns ENOSPC", not "rotation".
	fileOut, err := file.New(&file.Config{
		Path:      logPath,
		MaxSizeMB: 1,
	}, file.WithOutputMetrics(metrics))
	if err != nil {
		return fmt.Errorf("file.New: %w", err)
	}

	auditor, err := audit.New(
		audit.WithTaxonomy(tax),
		audit.WithAppName("file-enospc-runner"),
		audit.WithHost("enospc-host"),
		audit.WithOutputs(fileOut),
	)
	if err != nil {
		return fmt.Errorf("audit.New: %w", err)
	}

	// Each event payload is large enough that ~256 of them fill
	// the 256 KiB tmpfs. The writeLoop batches and Writev's the
	// kernel buffer; ENOSPC fires from any single Writev when the
	// tmpfs has no remaining bytes.
	payload := strings.Repeat("X", 1024)
	for i := 0; i < 4096; i++ {
		_ = auditor.AuditEvent(audit.NewEvent("enospc_test", audit.Fields{
			"outcome": "success",
			"payload": payload,
		}))
	}

	// Poll for ENOSPC observation. The writeLoop drains async;
	// expect the failed Writev to land within a few hundred ms.
	pollCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for metrics.count() < 1 {
		select {
		case <-pollCtx.Done():
			return fmt.Errorf("no RecordError observed within 10s on tmpfs %q", tmpfsPath)
		case <-ticker.C:
		}
	}

	_ = auditor.Close()
	fmt.Println("ENOSPC_OBSERVED")
	return nil
}
