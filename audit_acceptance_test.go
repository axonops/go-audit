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
	"testing"
	"time"

	"github.com/axonops/audit"
	"github.com/axonops/audit/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Named tests for issue #455 acceptance criteria
// ---------------------------------------------------------------------------

// slowOutput is an output that adds artificial delay to each Write call.
type slowOutput struct { //nolint:govet // fieldalignment: readability preferred
	delay  time.Duration
	events [][]byte
	mu     sync.Mutex
	closed bool
}

func (s *slowOutput) Write(data []byte) error {
	time.Sleep(s.delay)
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make([]byte, len(data))
	copy(cp, data)
	s.events = append(s.events, cp)
	return nil
}

func (s *slowOutput) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

func (s *slowOutput) Name() string { return "slow" }

func TestDrainLoop_SlowOutput_DoesNotBlockOthers(t *testing.T) {
	// A slow output must not prevent a fast output from receiving events.
	slow := &slowOutput{delay: 100 * time.Millisecond}
	fast := testhelper.NewMockOutput("fast")

	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(slow, fast),
	)
	require.NoError(t, err)

	const n = 5
	for range n {
		require.NoError(t, auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
			"outcome": "success",
		})))
	}

	require.NoError(t, auditor.Close())

	assert.Equal(t, n, fast.EventCount(),
		"fast output must receive all %d events despite slow output", n)
}

func TestDrainLoop_AllOutputsAsync_NoSequentialBlocking(t *testing.T) {
	// Verify two async outputs both receive events.
	outA := testhelper.NewMockOutput("output-a")
	outB := testhelper.NewMockOutput("output-b")

	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(outA, outB),
	)
	require.NoError(t, err)

	const n = 3
	for range n {
		require.NoError(t, auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
			"outcome": "success",
		})))
	}

	require.NoError(t, auditor.Close())

	assert.Equal(t, n, outA.EventCount(),
		"output-a must receive all %d events", n)
	assert.Equal(t, n, outB.EventCount(),
		"output-b must receive all %d events", n)
}

func TestCoreMetrics_RecordSubmitted_CalledPerAuditEvent(t *testing.T) {
	out := testhelper.NewMockOutput("test")
	metrics := testhelper.NewMockMetrics()

	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
		audit.WithMetrics(metrics),
	)
	require.NoError(t, err)

	const n = 5
	for range n {
		require.NoError(t, auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
			"outcome": "success",
		})))
	}

	require.NoError(t, auditor.Close())

	assert.Equal(t, n, metrics.GetSubmitted(),
		"RecordSubmitted must be called once per AuditEvent call")
}

func TestCoreMetrics_RecordSubmitted_CalledBeforeFiltering(t *testing.T) {
	out := testhelper.NewMockOutput("test")
	metrics := testhelper.NewMockMetrics()

	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
		audit.WithMetrics(metrics),
	)
	require.NoError(t, err)

	// Disable "read" category so events in it are filtered.
	require.NoError(t, auditor.DisableCategory("read"))

	// Audit an event in the disabled category.
	require.NoError(t, auditor.AuditEvent(audit.NewEvent("user_get", audit.Fields{
		"outcome": "success",
	})))

	require.NoError(t, auditor.Close())

	// RecordSubmitted is called BEFORE filtering — so count is 1
	// even though the event was filtered and not delivered.
	assert.Equal(t, 1, metrics.GetSubmitted(),
		"RecordSubmitted must be called before filtering")
	assert.Equal(t, 0, out.EventCount(),
		"filtered event must not be delivered to output")
}

func TestCoreMetrics_RecordQueueDepth_SampledEveryNEvents(t *testing.T) {
	out := testhelper.NewMockOutput("test")
	metrics := testhelper.NewMockMetrics()

	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
		audit.WithMetrics(metrics),
	)
	require.NoError(t, err)

	// Audit 65 events — RecordQueueDepth is sampled every 64.
	const n = 65
	for range n {
		require.NoError(t, auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
			"outcome": "success",
		})))
	}

	require.NoError(t, auditor.Close())

	depths := metrics.GetQueueDepths()
	assert.NotEmpty(t, depths,
		"RecordQueueDepth must be called at least once after 65 events (sampled every 64)")
}
