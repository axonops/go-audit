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
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/audit"
	"github.com/axonops/audit/splunk"
)

// Supplementary tests covering low-leverage paths identified by the
// test-analyst as residual coverage gaps. Targets recordBufferFull
// (0%), WithMaxIdleConns (0%), and the audit.Metrics non-nil
// branches of recordSuccess (60%) / recordDrop (75%).

// fakeCoreMetrics implements audit.Metrics with simple counters so
// the splunk Output's recordSuccess / recordDrop inner-loop paths are
// exercised (the inner loops only run when o.metrics != nil; see
// splunk.go:556 / :567). Embeds audit.NoOpMetrics for forward-compat.
type fakeCoreMetrics struct {
	audit.NoOpMetrics
	deliveries atomic.Int64
	successes  atomic.Int64
	errors     atomic.Int64
}

func (m *fakeCoreMetrics) RecordDelivery(_ string, status audit.EventStatus) {
	m.deliveries.Add(1)
	switch status {
	case audit.EventSuccess:
		m.successes.Add(1)
	case audit.EventError:
		m.errors.Add(1)
	}
}

// TestOutput_RecordSuccess_CallsCoreMetricsRecordDelivery covers the
// `o.metrics != nil` branch of recordSuccess. With a real Metrics
// implementation we observe one delivery per event in the batch.
func TestOutput_RecordSuccess_CallsCoreMetricsRecordDelivery(t *testing.T) {
	srv, _ := newStub(t)
	cm := &fakeCoreMetrics{}
	cfg := validCfg(srv.URL)
	out, err := splunk.New(cfg, cm)
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte(`{"event_type":"a"}`)))
	require.NoError(t, out.Write([]byte(`{"event_type":"b"}`)))
	require.NoError(t, out.Close())

	assert.GreaterOrEqual(t, cm.successes.Load(), int64(2),
		"audit.Metrics.RecordDelivery(success) must fire per event delivered")
	assert.Zero(t, cm.errors.Load(), "no error deliveries expected on success path")
}

// TestOutput_RecordDrop_CallsCoreMetricsRecordDelivery covers the
// `o.metrics != nil` branch of recordDrop. We force every batch to
// drop by configuring MaxRetries=0 with a 5xx server.
func TestOutput_RecordDrop_CallsCoreMetricsRecordDelivery(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/services/collector/health" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"text":"HEC is healthy","code":17}`))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"text":"oh no","code":8}`))
	}))
	defer srv.Close()

	cm := &fakeCoreMetrics{}
	cfg := validCfg(srv.URL)
	cfg.MaxRetries = 0
	cfg.RetryBaseDelay = 5 * time.Millisecond
	cfg.RetryMaxDelay = 10 * time.Millisecond
	out, err := splunk.New(cfg, cm)
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte(`{"event_type":"x"}`)))
	require.NoError(t, out.Close())

	assert.GreaterOrEqual(t, cm.errors.Load(), int64(1),
		"audit.Metrics.RecordDelivery(error) must fire per event dropped")
}

// TestOutput_BufferFull_RecordsDropMetric covers recordBufferFull
// (0% before this test). Pattern: a slow server backs up flushes
// while writes continue at full speed; the BufferSize=100 channel
// fills and subsequent writes hit the `default` branch in Write.
func TestOutput_BufferFull_RecordsDropMetric(t *testing.T) {
	// /event handler sleeps long enough that the batch goroutine
	// blocks; /health returns immediately so construction succeeds.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/services/collector/health" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"text":"HEC is healthy","code":17}`))
			return
		}
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"text":"Success","code":0}`))
	}))
	defer srv.Close()

	rec := &recordingMetrics{}
	cfg := validCfg(srv.URL)
	cfg.BufferSize = 100 // MinBufferSize
	cfg.BatchSize = 1    // every event triggers a flush; the flush blocks
	out, err := splunk.New(cfg, nil, splunk.WithOutputMetrics(rec))
	require.NoError(t, err)
	defer func() { _ = out.Close() }()

	// Write enough events to overflow BufferSize while the batch
	// goroutine is blocked on the slow /event POST.
	for i := 0; i < 500; i++ {
		_ = out.Write([]byte(`{"event_type":"x"}`))
	}
	// The recordBufferFull path increments outputMetrics.RecordDrop.
	// We don't assert an exact count (it's race-dependent on when the
	// goroutine drains the first event before the buffer fills) — we
	// only assert that at least one buffer-full drop was recorded.
	assert.Eventually(t, func() bool {
		return rec.drops.Load() >= 1
	}, 1*time.Second, 10*time.Millisecond,
		"BufferSize=%d should not absorb 500 rapid writes against a 2s-blocked flush",
		cfg.BufferSize)
}

// TestWithMaxIdleConns covers the WithMaxIdleConns option (0% before
// this test). The option is honoured at transport construction; we
// verify the Output is constructed successfully with a non-default
// value and a sanity-bound zero value.
func TestWithMaxIdleConns(t *testing.T) {
	srv, _ := newStub(t)

	t.Run("explicit_value", func(t *testing.T) {
		out, err := splunk.New(validCfg(srv.URL), nil, splunk.WithMaxIdleConns(50))
		require.NoError(t, err)
		require.NoError(t, out.Close())
	})

	t.Run("zero_value_falls_back_to_default", func(t *testing.T) {
		// 0 should be treated as "use default" by the option resolver
		// (the underlying http.Transport.MaxIdleConns defaults to 100
		// when zero is passed in; the splunk option resolver applies
		// its own default).
		out, err := splunk.New(validCfg(srv.URL), nil, splunk.WithMaxIdleConns(0))
		require.NoError(t, err)
		require.NoError(t, out.Close())
	})
}
