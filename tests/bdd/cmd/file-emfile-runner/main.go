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

// Command file-emfile-runner is a hermetic test helper invoked by the
// BDD scenario "File output records RecordError when fd limit is
// exhausted on rotation" (#748).
//
// Strategy: the file output's rotate.Writer opens the active log
// file LAZILY on first write (file/file.go writeLoop). So we
// (1) construct the auditor (no log fd yet),
// (2) exhaust file descriptors via dummy /dev/null opens,
// (3) Setrlimit(RLIMIT_NOFILE) at the current count so any new open hits EMFILE,
// (4) trigger an audit, which forces the writeLoop's first openNew,
// (5) observe RecordError firing on the OutputMetrics surface.
//
// The Go test runner cannot Setrlimit RLIMIT_NOFILE inline without
// affecting every subsequent test in the same process — the limit is
// per-process — so this binary forks the work and reports the outcome
// via stdout marker + exit code:
//
//	stdout contains "EMFILE_OBSERVED" + exit 0   — RecordError fired
//	any other outcome                            — exit non-zero
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/axonops/audit"
	"github.com/axonops/audit/file"
)

// errorCounter is a minimal [audit.OutputMetrics] implementation
// that counts RecordError calls. Embedding NoOpOutputMetrics
// satisfies the rest of the interface; only the methods we observe
// need overriding.
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
	tmp, err := os.MkdirTemp("", "audit-emfile-")
	if err != nil {
		return fmt.Errorf("mktmpdir: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmp) }()

	tax := &audit.Taxonomy{
		Version: 1,
		Categories: map[string]*audit.CategoryDef{
			"write": {Events: []string{"emfile_test"}},
		},
		Events: map[string]*audit.EventDef{
			"emfile_test": {
				Categories: []string{"write"},
				Required:   []string{"outcome"},
			},
		},
	}

	logPath := filepath.Join(tmp, "audit.log")
	metrics := &errorCounter{}

	fileOut, err := file.New(&file.Config{
		Path:      logPath,
		MaxSizeMB: 1,
	}, file.WithOutputMetrics(metrics))
	if err != nil {
		return fmt.Errorf("file.New: %w", err)
	}

	auditor, err := audit.New(
		audit.WithTaxonomy(tax),
		audit.WithAppName("file-emfile-runner"),
		audit.WithHost("emfile-host"),
		audit.WithOutputs(fileOut),
	)
	if err != nil {
		return fmt.Errorf("audit.New: %w", err)
	}

	// IMPORTANT: do NOT trigger any audit yet. The rotate.Writer
	// opens the active log file lazily on first Write — we want
	// that open to fail with EMFILE, which only happens if the fd
	// budget is exhausted BEFORE the first write.
	dummies, baseline, err := exhaustFDsAndCapLimit()
	if err != nil {
		return err
	}
	defer func() {
		for _, f := range dummies {
			_ = f.Close()
		}
	}()

	// Trigger the first audit. The writeLoop drains, attempts to
	// openNew (lazy) → fails with EMFILE → om.RecordError fires.
	if err := auditor.AuditEvent(audit.NewEvent("emfile_test", audit.Fields{
		"outcome": "success",
	})); err != nil {
		return fmt.Errorf("audit: %w", err)
	}

	// Poll for RecordError. The writeLoop drains async; we expect
	// the first failed open to land within the polling window. A
	// regression that never fires the metric exits with a clear
	// error rather than hanging.
	pollCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for metrics.count() < 1 {
		select {
		case <-pollCtx.Done():
			return fmt.Errorf("no RecordError observed within 5s; baseline=%d", baseline)
		case <-ticker.C:
		}
	}

	// Best-effort close. With RLIMIT_NOFILE at the cap, Close()
	// should still succeed because it only releases fds, never
	// allocates them.
	_ = auditor.Close()

	fmt.Println("EMFILE_OBSERVED")
	return nil
}

func countOpenFDs() (int, error) {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return 0, fmt.Errorf("read /proc/self/fd: %w", err)
	}
	return len(entries), nil
}

// exhaustFDsAndCapLimit opens dummy /dev/null fds to consume budget,
// then lowers RLIMIT_NOFILE below the live count so any new open
// fails with EMFILE. Existing fds remain valid (the kernel does not
// retroactively close on setrlimit). The dummy slice is returned so
// the caller can hold the fds open for the duration of the test.
func exhaustFDsAndCapLimit() ([]*os.File, int, error) {
	// The high count covers Go runtime fd churn (lazy epoll, GC
	// finalizers freeing existing files mid-test) so the count never
	// drops below our limit.
	const dummyCount = 256
	dummies := make([]*os.File, 0, dummyCount)
	for i := 0; i < dummyCount; i++ {
		f, openErr := os.OpenFile("/dev/null", os.O_RDONLY, 0)
		if openErr != nil {
			return nil, 0, fmt.Errorf("open /dev/null #%d: %w", i, openErr)
		}
		dummies = append(dummies, f)
	}

	baseline, err := countOpenFDs()
	if err != nil {
		return nil, 0, err
	}

	var rlim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rlim); err != nil {
		return nil, 0, fmt.Errorf("getrlimit: %w", err)
	}
	// Lower the cap 10 below baseline so even if the runtime drops a
	// few fds via finalizers, the limit stays below the live count.
	rlim.Cur = uint64(baseline - 10) //nolint:gosec // baseline is ReadDir count, large positive
	if rlim.Max > rlim.Cur {
		rlim.Max = rlim.Cur
	}
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rlim); err != nil {
		return nil, 0, fmt.Errorf("setrlimit: %w", err)
	}
	return dummies, baseline, nil
}
