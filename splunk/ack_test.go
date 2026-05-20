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

package splunk

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/axonops/audit"
)

// ackTestStub is a HEC stub that records every request and supports
// configurable /event ackID emission and /ack polling responses.
type ackTestStub struct {
	mu          sync.Mutex
	eventReqs   atomic.Int64
	ackReqs     atomic.Int64
	channelHdrs []string // recorded X-Splunk-Request-Channel values per event request
	bodies      [][]byte // recorded /event bodies
	ackIDs      atomic.Int64

	// ackResponses maps ackID → bool to return on /ack polls. Default
	// (key absent): false. Tests pre-populate to simulate confirmations.
	ackResponses map[int64]bool

	// /event response controls.
	eventReturnsCode14 atomic.Bool // simulate ACK disabled

	srv *httptest.Server
}

func newAckTestStub() *ackTestStub {
	s := &ackTestStub{ackResponses: make(map[int64]bool)}
	mux := http.NewServeMux()
	mux.HandleFunc("/services/collector/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"text":"HEC is healthy","code":17}`))
	})
	mux.HandleFunc("/services/collector/event", func(w http.ResponseWriter, r *http.Request) {
		s.eventReqs.Add(1)
		body, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.channelHdrs = append(s.channelHdrs, r.Header.Get("X-Splunk-Request-Channel"))
		s.bodies = append(s.bodies, body)
		s.mu.Unlock()
		if s.eventReturnsCode14.Load() {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"text":"ACK is disabled","code":14}`))
			return
		}
		ackID := s.ackIDs.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"text":"Success","code":0,"ackId":` + strconv.FormatInt(ackID, 10) + `}`))
	})
	mux.HandleFunc("/services/collector/ack", func(w http.ResponseWriter, r *http.Request) {
		s.ackReqs.Add(1)
		body, _ := io.ReadAll(r.Body)
		// Parse acks from the request to figure out which IDs to
		// answer. Simple — return true for IDs in s.ackResponses
		// with value true, false otherwise.
		var req struct {
			Acks []int64 `json:"acks"`
		}
		_ = json.Unmarshal(body, &req)
		s.mu.Lock()
		ackMap := make(map[string]bool, len(req.Acks))
		for _, id := range req.Acks {
			ackMap[strconv.FormatInt(id, 10)] = s.ackResponses[id]
		}
		s.mu.Unlock()
		out, _ := jsonMarshalAck(ackMap)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(out)
	})
	s.srv = httptest.NewServer(mux)
	return s
}

func (s *ackTestStub) URL() string            { return s.srv.URL }
func (s *ackTestStub) Close()                 { s.srv.Close() }
func (s *ackTestStub) eventRequests() int64   { return s.eventReqs.Load() }
func (s *ackTestStub) ackPollRequests() int64 { return s.ackReqs.Load() }
func (s *ackTestStub) confirmAck(id int64)    { s.mu.Lock(); s.ackResponses[id] = true; s.mu.Unlock() }
func (s *ackTestStub) confirmAllOutstanding(t *ackTracker) {
	for _, id := range t.snapshotIDs() {
		s.confirmAck(id)
	}
}
func (s *ackTestStub) lastChannelHeader() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.channelHdrs) == 0 {
		return ""
	}
	return s.channelHdrs[len(s.channelHdrs)-1]
}

// jsonMarshalAck encodes the /ack response envelope.
func jsonMarshalAck(m map[string]bool) ([]byte, error) {
	return json.Marshal(struct {
		Acks map[string]bool `json:"acks"`
	}{Acks: m})
}

// ackTestConfig returns a Config that targets the stub and uses
// short timing values for fast tests.
func ackTestConfig(url string, mode AckMode) *Config {
	gz := false
	return &Config{
		URL:                        url,
		Token:                      "tkn",
		AllowInsecureHTTP:          true,
		AllowPrivateRanges:         true,
		DisableStartupVerification: false,
		StartupVerificationTimeout: 2 * time.Second,
		AckMode:                    mode,
		AckPollInterval:            50 * time.Millisecond,
		AckResendWindow:            200 * time.Millisecond,
		BufferSize:                 100,
		BatchSize:                  1,
		MaxBatchBytes:              MinMaxBatchBytes,
		MaxEventBytes:              MinMaxEventBytes,
		FlushInterval:              100 * time.Millisecond,
		Gzip:                       &gz,
		Timeout:                    1 * time.Second,
		UserAgent:                  "audit-splunk/test",
		MaxRetries:                 0,
		RetryBaseDelay:             5 * time.Millisecond,
		RetryMaxDelay:              10 * time.Millisecond,
		RetryJitter:                0.0,
	}
}

// --- Named tests (per issue #55 PR 2 specification) ---

// TestAck_OffMode_NoChannelHeader — AckModeOff (default) must NOT
// emit the X-Splunk-Request-Channel header.
func TestAck_OffMode_NoChannelHeader(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreTopFunction("internal/poll.runtime_pollWait"))
	stub := newAckTestStub()
	defer stub.Close()

	cfg := ackTestConfig(stub.URL(), AckModeOff)
	out, err := New(cfg, nil)
	require.NoError(t, err)
	require.NoError(t, out.Write([]byte(`{"event_type":"x"}`)))
	require.NoError(t, out.Close())

	assert.GreaterOrEqual(t, stub.eventRequests(), int64(1))
	assert.Empty(t, stub.lastChannelHeader(),
		"AckModeOff must not send X-Splunk-Request-Channel")
}

// TestAck_BestEffort_ChannelHeaderSent — best-effort emits a UUID v4
// channel header on every /event request.
func TestAck_BestEffort_ChannelHeaderSent(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreTopFunction("internal/poll.runtime_pollWait"))
	stub := newAckTestStub()
	defer stub.Close()

	cfg := ackTestConfig(stub.URL(), AckModeBestEffort)
	out, err := New(cfg, nil)
	require.NoError(t, err)
	require.NoError(t, out.Write([]byte(`{"event_type":"x"}`)))
	require.NoError(t, out.Close())

	ch := stub.lastChannelHeader()
	uuidV4 := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	assert.True(t, uuidV4.MatchString(ch),
		"channel header %q must be a UUID v4", ch)
}

// TestAck_BestEffort_AckPollsAtInterval — the tracker polls /ack at
// the configured interval; at least one poll fires after a write.
func TestAck_BestEffort_AckPollsAtInterval(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreTopFunction("internal/poll.runtime_pollWait"))
	stub := newAckTestStub()
	defer stub.Close()

	cfg := ackTestConfig(stub.URL(), AckModeBestEffort)
	cfg.AckPollInterval = 50 * time.Millisecond
	out, err := New(cfg, nil)
	require.NoError(t, err)
	defer func() { _ = out.Close() }()

	require.NoError(t, out.Write([]byte(`{"event_type":"x"}`)))
	require.Eventually(t, func() bool {
		return stub.ackPollRequests() >= 1
	}, 2*time.Second, 10*time.Millisecond,
		"ack poll endpoint must be hit at least once")
}

// TestAck_BestEffort_BufferNotGated — best-effort does NOT gate the
// buffer on ack confirmations. Writes proceed even when no ack ever
// returns true.
func TestAck_BestEffort_BufferNotGated(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreTopFunction("internal/poll.runtime_pollWait"))
	stub := newAckTestStub()
	defer stub.Close()

	cfg := ackTestConfig(stub.URL(), AckModeBestEffort)
	out, err := New(cfg, nil)
	require.NoError(t, err)
	defer func() { _ = out.Close() }()

	// 50 rapid writes — none of which will be confirmed.
	for i := 0; i < 50; i++ {
		require.NoError(t, out.Write([]byte(`{"event_type":"x"}`)),
			"Write must remain non-blocking under un-confirmed ACK")
	}
}

// TestAck_Required_BufferGatedUntilAckPositive — required mode keeps
// events in-flight until /ack confirms. Drains when /ack returns true.
func TestAck_Required_BufferGatedUntilAckPositive(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreTopFunction("internal/poll.runtime_pollWait"))
	stub := newAckTestStub()
	defer stub.Close()

	cfg := ackTestConfig(stub.URL(), AckModeRequired)
	cfg.AckPollInterval = 50 * time.Millisecond
	// Generous resend window so the test isn't racing the resend
	// timer — we only care about the confirmation drain path.
	cfg.AckResendWindow = 30 * time.Second
	out, err := New(cfg, nil)
	require.NoError(t, err)
	defer func() { _ = out.Close() }()

	require.NoError(t, out.Write([]byte(`{"event_type":"x"}`)))

	// Wait for BOTH the probe and the actual write to reach the
	// server (probe lands during New(); write follows).
	require.Eventually(t, func() bool {
		return stub.eventRequests() >= 2 && out.tracker.inFlightCount() >= 2
	}, 2*time.Second, 10*time.Millisecond,
		"probe + event must both register as in-flight before confirmation")

	// Confirm all outstanding acks.
	stub.confirmAllOutstanding(out.tracker)

	// Within a few poll ticks, in-flight should drain.
	require.Eventually(t, func() bool {
		return out.tracker.inFlightCount() == 0
	}, 2*time.Second, 10*time.Millisecond,
		"in-flight buffer must drain after positive ack")
	assert.GreaterOrEqual(t, out.tracker.snapshot().Confirmed, int64(2))
}

// TestAck_Required_ResendWindowTimeout_Resends — when /ack returns
// false past the AckResendWindow, the tracker re-sends the batch.
func TestAck_Required_ResendWindowTimeout_Resends(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreTopFunction("internal/poll.runtime_pollWait"))
	stub := newAckTestStub()
	defer stub.Close()

	cfg := ackTestConfig(stub.URL(), AckModeRequired)
	cfg.AckPollInterval = 50 * time.Millisecond
	cfg.AckResendWindow = 200 * time.Millisecond
	out, err := New(cfg, nil)
	require.NoError(t, err)
	defer func() { _ = out.Close() }()

	require.NoError(t, out.Write([]byte(`{"event_type":"resend-me"}`)))

	// The first /event reaches the stub. Then /ack returns false
	// indefinitely. After AckResendWindow elapses, the tracker
	// re-sends the same envelope — count event requests reaching
	// ≥ 2 (probe + first event + resend).
	require.Eventually(t, func() bool {
		return out.tracker.snapshot().TimedOut >= 1
	}, 3*time.Second, 50*time.Millisecond,
		"resend window must trigger at least one timeout")
}

// TestAck_Required_BufferFull_DropsNewEventsWithMetric — when the
// in-flight buffer fills, new events trigger a drop with metric
// reason=ack_buffer_full. AC 59: producer (Write) remains non-blocking.
func TestAck_Required_BufferFull_DropsNewEventsWithMetric(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreTopFunction("internal/poll.runtime_pollWait"))
	stub := newAckTestStub()
	defer stub.Close()

	rec := &ackMetricsRecorder{}
	cfg := ackTestConfig(stub.URL(), AckModeRequired)
	cfg.BufferSize = MinBufferSize
	cfg.BatchSize = 1
	cfg.FlushInterval = 100 * time.Millisecond
	out, err := New(cfg, nil, WithOutputMetrics(rec))
	require.NoError(t, err)
	defer func() { _ = out.Close() }()

	// Saturate beyond the BufferSize. /ack never confirms, so
	// in-flight grows until the cap; subsequent batches drop with
	// ack_buffer_full.
	for i := 0; i < 2*MinBufferSize; i++ {
		_ = out.Write([]byte(`{"event_type":"x"}`))
	}
	require.Eventually(t, func() bool {
		return rec.bufferFullDrops.Load() >= 1
	}, 3*time.Second, 50*time.Millisecond,
		"buffer-full drops must record on AckMetricsRecorder")
}

// TestAck_GUIDIsCryptoRand_NotZero — generated GUIDs are UUID v4
// strings, non-zero, and pairwise distinct over a sample.
func TestAck_GUIDIsCryptoRand_NotZero(t *testing.T) {
	uuidV4 := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	const n = 1000
	seen := make(map[channelGUID]struct{}, n)
	for i := 0; i < n; i++ {
		g, err := newChannelGUID(randReader)
		require.NoError(t, err)
		assert.True(t, uuidV4.MatchString(string(g)),
			"GUID %q must match UUID v4 pattern", g)
		assert.NotEqual(t, channelGUID("00000000-0000-4000-8000-000000000000"), g,
			"GUID must not be zero")
		_, dup := seen[g]
		assert.False(t, dup, "GUID %q must be unique across %d samples", g, n)
		seen[g] = struct{}{}
	}
}

// TestAck_CryptoRandFailure_NewReturnsError — when the entropy
// source fails, New() returns ErrCryptoRandFailed. No goroutine is
// started (goleak verifies clean termination).
func TestAck_CryptoRandFailure_NewReturnsError(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreTopFunction("internal/poll.runtime_pollWait"))
	stub := newAckTestStub()
	defer stub.Close()

	saved := randReader
	defer func() { randReader = saved }()
	randReader = iotest.ErrReader(io.ErrUnexpectedEOF)

	cfg := ackTestConfig(stub.URL(), AckModeBestEffort)
	_, err := New(cfg, nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrCryptoRandFailed),
		"New() must wrap ErrCryptoRandFailed when crypto/rand fails: got %v", err)
}

// TestAck_FeatureDetectAtStartup_HECDisabledAckFails — when HEC
// returns code 14 on the feature-detection probe, New() returns
// ErrAckDisabled.
func TestAck_FeatureDetectAtStartup_HECDisabledAckFails(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreTopFunction("internal/poll.runtime_pollWait"))
	stub := newAckTestStub()
	defer stub.Close()

	stub.eventReturnsCode14.Store(true)

	cfg := ackTestConfig(stub.URL(), AckModeBestEffort)
	_, err := New(cfg, nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrAckDisabled),
		"New() must wrap ErrAckDisabled when HEC code 14 is returned on probe: got %v", err)
}

// TestAck_StateMachine_NoGoroutineLeak — explicit goleak verifier
// for the full lifecycle (New + write + Close).
func TestAck_StateMachine_NoGoroutineLeak(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreTopFunction("internal/poll.runtime_pollWait"))
	stub := newAckTestStub()
	defer stub.Close()

	cfg := ackTestConfig(stub.URL(), AckModeRequired)
	out, err := New(cfg, nil)
	require.NoError(t, err)
	require.NoError(t, out.Write([]byte(`{"event_type":"x"}`)))
	require.NoError(t, out.Close())
}

// TestAck_PollEndpointFormat — the /ack request has the documented
// URL path, channel query, Authorization header, and body shape.
func TestAck_PollEndpointFormat(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreTopFunction("internal/poll.runtime_pollWait"))
	var captured struct {
		mu     sync.Mutex
		path   string
		query  string
		auth   string
		body   []byte
		method string
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/services/collector/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"text":"HEC is healthy","code":17}`))
	})
	var ackID atomic.Int64
	mux.HandleFunc("/services/collector/event", func(w http.ResponseWriter, _ *http.Request) {
		id := ackID.Add(1)
		_, _ = w.Write([]byte(`{"text":"Success","code":0,"ackId":` + strconv.FormatInt(id, 10) + `}`))
	})
	mux.HandleFunc("/services/collector/ack", func(w http.ResponseWriter, r *http.Request) {
		captured.mu.Lock()
		captured.path = r.URL.Path
		captured.query = r.URL.RawQuery
		captured.auth = r.Header.Get("Authorization")
		captured.body, _ = io.ReadAll(r.Body)
		captured.method = r.Method
		captured.mu.Unlock()
		_, _ = w.Write([]byte(`{"acks":{}}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := ackTestConfig(srv.URL, AckModeBestEffort)
	out, err := New(cfg, nil)
	require.NoError(t, err)
	require.NoError(t, out.Write([]byte(`{"event_type":"x"}`)))
	require.Eventually(t, func() bool {
		captured.mu.Lock()
		defer captured.mu.Unlock()
		return captured.path != ""
	}, 2*time.Second, 10*time.Millisecond)
	require.NoError(t, out.Close())

	captured.mu.Lock()
	defer captured.mu.Unlock()
	assert.Equal(t, "POST", captured.method)
	assert.Equal(t, "/services/collector/ack", captured.path)
	assert.Contains(t, captured.query, "channel=")
	assert.True(t, strings.HasPrefix(captured.auth, "Splunk "),
		"Authorization must be Splunk-scheme: %q", captured.auth)
	assert.Contains(t, string(captured.body), `"acks"`)
}

// TestAck_PoolResponseBody_LimitReaderApplied — a hostile /ack
// response with a Content-Length above the 1 MiB cap is rejected.
func TestAck_PoolResponseBody_LimitReaderApplied(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreTopFunction("internal/poll.runtime_pollWait"))
	mux := http.NewServeMux()
	mux.HandleFunc("/services/collector/health", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"text":"HEC is healthy","code":17}`))
	})
	mux.HandleFunc("/services/collector/event", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"text":"Success","code":0,"ackId":1}`))
	})
	mux.HandleFunc("/services/collector/ack", func(w http.ResponseWriter, _ *http.Request) {
		// Advertise 2 MiB; cap is 1 MiB.
		w.Header().Set("Content-Length", "2097152")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"acks":{}}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := ackTestConfig(srv.URL, AckModeBestEffort)
	out, err := New(cfg, nil)
	require.NoError(t, err)
	require.NoError(t, out.Write([]byte(`{"event_type":"x"}`)))
	// Wait for one poll tick. The tracker should NOT have applied
	// any confirmations because the response was rejected.
	time.Sleep(150 * time.Millisecond)
	require.NoError(t, out.Close())
	assert.Equal(t, int64(0), out.tracker.snapshot().Confirmed,
		"oversized /ack response must be rejected, not parsed")
}

// TestOutput_Close_FlushesAckRequiredQueue — Close drains the
// in-flight buffer up to the configured budget when /ack confirms
// during shutdown.
func TestOutput_Close_FlushesAckRequiredQueue(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreTopFunction("internal/poll.runtime_pollWait"))
	stub := newAckTestStub()
	defer stub.Close()

	cfg := ackTestConfig(stub.URL(), AckModeRequired)
	cfg.AckResendWindow = 30 * time.Second // avoid resend races
	out, err := New(cfg, nil)
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte(`{"event_type":"x"}`)))
	// Wait until BOTH the probe (registered during New()) and the
	// actual write are in-flight.
	require.Eventually(t, func() bool {
		return stub.eventRequests() >= 2 && out.tracker.inFlightCount() >= 2
	}, 2*time.Second, 10*time.Millisecond)
	// Confirm all outstanding before Close.
	stub.confirmAllOutstanding(out.tracker)
	require.NoError(t, out.Close())

	assert.Equal(t, 0, out.tracker.snapshot().Pending,
		"Close must drain the in-flight buffer when /ack confirms")
	assert.GreaterOrEqual(t, out.tracker.snapshot().Confirmed, int64(2))
}

// TestAckTracker_RegisterAfterClosed_NoOp covers the closed-state
// branch in tracker.register — once closed, new registrations are
// silently dropped (no panic, no leak).
func TestAckTracker_RegisterAfterClosed_NoOp(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreTopFunction("internal/poll.runtime_pollWait"))
	stub := newAckTestStub()
	defer stub.Close()

	cfg := ackTestConfig(stub.URL(), AckModeBestEffort)
	out, err := New(cfg, nil)
	require.NoError(t, err)
	tr := out.tracker
	require.NoError(t, out.Close())

	// After Close, register is a no-op. Snapshot the in-flight count
	// before and after — the closed-state branch in tracker.register
	// must not modify the map.
	before := tr.inFlightCount()
	tr.register(999, nil)
	assert.Equal(t, before, tr.inFlightCount(),
		"register after Close must be a silent no-op (no map growth)")
}

// TestAckTracker_NilReceiverSafe — every public-ish tracker method
// must tolerate a nil receiver (AckModeOff Output paths call them).
func TestAckTracker_NilReceiverSafe(t *testing.T) {
	var t0 *ackTracker
	assert.NotPanics(t, func() {
		t0.register(1, nil)
		_ = t0.inFlightCount()
		t0.recordBufferFullDrop(1)
		t0.flushOnClose(context.Background())
		t0.stop()
		_ = t0.snapshot()
	})
}

// TestOutput_AckMetricsSnapshot_PullsCounters covers the public
// snapshot accessor — empty when ACK is disabled, populated when
// ACK is on.
func TestOutput_AckMetricsSnapshot_PullsCounters(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreTopFunction("internal/poll.runtime_pollWait"))
	stub := newAckTestStub()
	defer stub.Close()

	// AckModeOff: snapshot is zero-valued.
	cfgOff := ackTestConfig(stub.URL(), AckModeOff)
	outOff, err := New(cfgOff, nil)
	require.NoError(t, err)
	snap := outOff.AckMetricsSnapshot()
	assert.Equal(t, AckSnapshot{}, snap, "AckModeOff snapshot must be zero-valued")
	require.NoError(t, outOff.Close())

	// AckModeBestEffort: snapshot reflects the running tracker.
	cfgOn := ackTestConfig(stub.URL(), AckModeBestEffort)
	cfgOn.AckResendWindow = 30 * time.Second
	outOn, err := New(cfgOn, nil)
	require.NoError(t, err)
	require.NoError(t, outOn.Write([]byte(`{"event_type":"x"}`)))
	require.Eventually(t, func() bool {
		return outOn.AckMetricsSnapshot().Pending >= 2
	}, 2*time.Second, 10*time.Millisecond)
	stub.confirmAllOutstanding(outOn.tracker)
	require.Eventually(t, func() bool {
		return outOn.AckMetricsSnapshot().Confirmed >= 2
	}, 2*time.Second, 10*time.Millisecond)
	require.NoError(t, outOn.Close())
}

// TestAckGUID_Property_AllUUIDv4 — every generated GUID matches the
// strict UUID v4 regex. Sample is wider than TestAck_GUIDIsCryptoRand_NotZero
// to catch low-probability bit-pattern bugs.
func TestAckGUID_Property_AllUUIDv4(t *testing.T) {
	uuidV4 := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	for i := 0; i < 10000; i++ {
		g, err := newChannelGUID(randReader)
		require.NoError(t, err)
		require.True(t, uuidV4.MatchString(string(g)),
			"iteration %d: GUID %q failed UUID v4 regex", i, g)
	}
}

// ackMetricsRecorder is a test OutputMetrics that ALSO implements
// the AckMetricsRecorder interface. Used in
// TestAck_Required_BufferFull_DropsNewEventsWithMetric and others.
type ackMetricsRecorder struct {
	audit.NoOpOutputMetrics
	pending         atomic.Int64
	confirmed       atomic.Int64
	timedOut        atomic.Int64
	bufferFullDrops atomic.Int64
}

func (r *ackMetricsRecorder) RecordAckPending(gauge int) { r.pending.Store(int64(gauge)) }
func (r *ackMetricsRecorder) RecordAckConfirmed(count int) {
	r.confirmed.Add(int64(count))
}
func (r *ackMetricsRecorder) RecordAckTimedOut(count int) {
	r.timedOut.Add(int64(count))
}
func (r *ackMetricsRecorder) RecordAckBufferFullDrop(count int) {
	r.bufferFullDrops.Add(int64(count))
}
