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

package audit_test

// Split out of audit_test.go (#540).

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/axonops/audit"
	"github.com/axonops/audit/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Concurrent writes + Close race test
// ---------------------------------------------------------------------------

func TestLogger_ConcurrentWritesAndClose(t *testing.T) {
	t.Parallel()

	out := testhelper.NewMockOutput("test")
	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)

	// Start N goroutines writing, then Close concurrently.
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				_ = auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
					"outcome":  "failure",
					"actor_id": "bob",
				}))
			}
		}()
	}

	// Close while writes are in flight -- must not panic or race.
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = auditor.Close()
	}()

	wg.Wait()
}

func TestLogger_ThreeWayRace_AuditSetRouteClose(t *testing.T) {
	t.Parallel()
	out := testhelper.NewMockOutput("test")
	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(out),
	)
	require.NoError(t, err)

	var wg sync.WaitGroup

	// 50 goroutines auditing events.
	for i := range 50 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for range 10 {
				_ = auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
					"outcome": "success",
				}))
			}
		}(i)
	}

	// 10 goroutines toggling routes.
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 5 {
				_ = auditor.SetOutputRoute("test", &audit.EventRoute{
					IncludeCategories: []string{"write"},
				})
				_ = auditor.SetOutputRoute("test", &audit.EventRoute{})
			}
		}()
	}

	// 1 goroutine closing.
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = auditor.Close()
	}()

	wg.Wait()
	// Success = no panic, no race detector violation.
}

// ---------------------------------------------------------------------------
// Handle.AuditEvent after Close
// ---------------------------------------------------------------------------

func TestLogger_Handle_AuditAfterClose(t *testing.T) {
	t.Parallel()

	out := testhelper.NewMockOutput("test")
	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)

	h := auditor.MustHandle("auth_failure")
	require.NoError(t, auditor.Close())

	err = h.Audit(audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
	})
	assert.ErrorIs(t, err, audit.ErrClosed)
}

// ---------------------------------------------------------------------------
// Lifecycle tests
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Concurrency tests (run with -race)
// ---------------------------------------------------------------------------

func TestLogger_ConcurrentAudit(t *testing.T) {
	t.Parallel()

	out := testhelper.NewMockOutput("test")
	auditor := newTestAuditor(t, out)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
				"outcome":  "failure",
				"actor_id": "bob",
			}))
		}()
	}
	wg.Wait()

	// All 100 events should be delivered (buffer is 10k).
	require.True(t, out.WaitForEvents(100, 5*time.Second))
}

func TestLogger_ConcurrentFilterMutation(t *testing.T) {
	t.Parallel()

	out := testhelper.NewMockOutput("test")
	auditor := newTestAuditor(t, out)

	var wg sync.WaitGroup
	// Concurrent filter mutations + audit calls.
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = auditor.EnableCategory("read")
			_ = auditor.DisableCategory("read")
		}()
		go func() {
			defer wg.Done()
			_ = auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
				"outcome":  "failure",
				"actor_id": "bob",
			}))
		}()
	}
	wg.Wait()
}

func TestLogger_ConcurrentClose(t *testing.T) {
	t.Parallel()

	out := testhelper.NewMockOutput("test")
	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)

	var wg sync.WaitGroup
	var errCount atomic.Int32

	// Close from multiple goroutines — no panic, no race.
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := auditor.Close(); err != nil {
				errCount.Add(1)
			}
		}()
	}
	wg.Wait()
	assert.Equal(t, int32(0), errCount.Load(), "idempotent Close should not error")
}
