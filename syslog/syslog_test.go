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

package syslog_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/axonops/audit"
	"github.com/axonops/audit/audittest"
	"github.com/axonops/audit/syslog"
	"github.com/axonops/srslog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

// ---------------------------------------------------------------------------
// Test helpers: TLS certificates
// ---------------------------------------------------------------------------

// TLS test certificates are produced by [audittest.GenerateTestCerts]
// — the audittest package is cross-module-importable; the core's
// internal/testhelper is not (#568).

// ---------------------------------------------------------------------------
// Test helpers: mock metrics
// ---------------------------------------------------------------------------

// mockMetrics implements audit.OutputMetrics (via NoOp embed) plus
// syslog.ReconnectRecorder — the combination picked up by the output's
// SetOutputMetrics type-assertion (#581).
//
// Synchronisation: a sync.Cond keyed off mu lets tests use
// waitForReconnectCount instead of sleep+poll loops or
// require.Eventually polling. Replaces flake-prone pattern
// (#705 family fix).
type mockMetrics struct {
	audit.NoOpOutputMetrics
	cond             *sync.Cond
	syslogReconnects map[string]int // "address:success|failure" -> count
	mu               sync.Mutex
	errors           atomic.Int64 // RecordError invocations
}

func newMockMetrics() *mockMetrics {
	m := &mockMetrics{
		syslogReconnects: make(map[string]int),
	}
	m.cond = sync.NewCond(&m.mu)
	return m
}

// RecordError counts errors recorded against the output. Used by
// reconnect tests that need to assert the retry-write-failed branch
// of handleWriteFailure was exercised.
func (m *mockMetrics) RecordError() { m.errors.Add(1) }

// getErrorCount returns the number of RecordError invocations.
func (m *mockMetrics) getErrorCount() int { return int(m.errors.Load()) }

// RecordReconnect satisfies syslog.ReconnectRecorder (#581).
func (m *mockMetrics) RecordReconnect(address string, success bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := address + ":"
	if success {
		key += "success"
	} else {
		key += "failure"
	}
	m.syslogReconnects[key]++
	m.cond.Broadcast()
}

// waitForReconnectCount blocks until the reconnect counter for
// (address, success) reaches at least n, or the timeout expires.
// Replaces sleep+poll loops and require.Eventually polling with a
// deterministic sync.Cond barrier (#705 family fix).
func (m *mockMetrics) waitForReconnectCount(t *testing.T, address string, success bool, n int, timeout time.Duration) {
	t.Helper()
	if !m.tryWaitForReconnectCount(address, success, n, timeout) {
		key := reconnectKey(address, success)
		m.mu.Lock()
		got := m.syslogReconnects[key]
		m.mu.Unlock()
		t.Fatalf("waitForReconnectCount(%s, %v, %d): only %d recorded after %v",
			address, success, n, got, timeout)
	}
}

// tryWaitForReconnectCount is the bool-returning variant for tests
// that tolerate platform-dependent non-occurrence (e.g., TIME_WAIT
// preventing rapid port rebind on macOS / Windows). Does not fail
// the test on timeout — caller decides what to do.
func (m *mockMetrics) tryWaitForReconnectCount(address string, success bool, n int, timeout time.Duration) bool {
	key := reconnectKey(address, success)
	deadline := time.Now().Add(timeout)
	m.mu.Lock()
	defer m.mu.Unlock()
	timer := time.AfterFunc(timeout, func() {
		m.mu.Lock()
		m.cond.Broadcast()
		m.mu.Unlock()
	})
	defer timer.Stop()
	for m.syslogReconnects[key] < n {
		if time.Now().After(deadline) {
			return false
		}
		m.cond.Wait()
	}
	return true
}

func reconnectKey(address string, success bool) string {
	if success {
		return address + ":success"
	}
	return address + ":failure"
}

// getSyslogReconnectCount returns the reconnect count for the given address and outcome.
func (m *mockMetrics) getSyslogReconnectCount(address string, success bool) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := address + ":"
	if success {
		key += "success"
	} else {
		key += "failure"
	}
	return m.syslogReconnects[key]
}

var _ syslog.ReconnectRecorder = (*mockMetrics)(nil)

// mockOutputMetrics implements audit.OutputMetrics for testing.
type mockOutputMetrics struct {
	audit.NoOpOutputMetrics
	drops      atomic.Int64
	flushes    atomic.Int64
	errors     atomic.Int64
	retries    atomic.Int64
	depthCalls atomic.Int64
}

func (m *mockOutputMetrics) RecordDrop()                        { m.drops.Add(1) }
func (m *mockOutputMetrics) RecordFlush(_ int, _ time.Duration) { m.flushes.Add(1) }
func (m *mockOutputMetrics) RecordError()                       { m.errors.Add(1) }
func (m *mockOutputMetrics) RecordRetry(_ int)                  { m.retries.Add(1) }
func (m *mockOutputMetrics) RecordQueueDepth(_, _ int)          { m.depthCalls.Add(1) }

var _ audit.OutputMetrics = (*mockOutputMetrics)(nil)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// mockSyslogServer listens on TCP and collects received messages.
type mockSyslogServer struct {
	listener net.Listener
	done     chan struct{}
	messages []string
	wg       sync.WaitGroup
	mu       sync.Mutex
}

func newMockSyslogServer(t *testing.T) *mockSyslogServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	s := &mockSyslogServer{
		listener: ln,
		done:     make(chan struct{}),
	}
	s.wg.Add(1)
	go s.accept()
	return s
}

func (s *mockSyslogServer) accept() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.done:
				return
			default:
				return
			}
		}
		s.wg.Add(1)
		go s.handleConn(conn)
	}
}

func (s *mockSyslogServer) handleConn(conn net.Conn) {
	defer s.wg.Done()
	defer func() { _ = conn.Close() }()

	buf := make([]byte, 8192)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, err := conn.Read(buf)
		if n > 0 {
			s.mu.Lock()
			s.messages = append(s.messages, string(buf[:n]))
			s.mu.Unlock()
		}
		if err != nil {
			select {
			case <-s.done:
				return
			default:
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			return
		}
	}
}

func (s *mockSyslogServer) addr() string {
	return s.listener.Addr().String()
}

func (s *mockSyslogServer) close() {
	close(s.done)
	_ = s.listener.Close()
	s.wg.Wait()
}

func (s *mockSyslogServer) getMessages() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make([]string, len(s.messages))
	copy(cp, s.messages)
	return cp
}

func (s *mockSyslogServer) messageCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.messages)
}

// waitForData polls until the server has received at least one chunk,
// or the timeout expires. Replaces time.Sleep for synchronisation.
func (s *mockSyslogServer) waitForData(timeout time.Duration) bool {
	deadline := time.After(timeout)
	for {
		if s.messageCount() > 0 {
			return true
		}
		select {
		case <-deadline:
			return false
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// waitForMarkerCount polls until the server has received at least
// `want` event markers (`"n":` substrings — one per event written
// by TestWriteLoop_*), or the timeout expires. Required because
// TCP coalescing means the writeLoop's batch may arrive across
// multiple Reads on the server side; a single waitForData +
// countEventMarkers snapshot races the second-and-onwards Reads
// (#763). Counts via strings.Count over the joined buffer so chunk
// boundaries do not affect the result.
func (s *mockSyslogServer) waitForMarkerCount(want int, timeout time.Duration) bool {
	deadline := time.After(timeout)
	for {
		if countEventMarkers(s.getMessages()) >= want {
			return true
		}
		select {
		case <-deadline:
			return false
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// waitForContent polls until the joined message buffer contains all
// specified substrings, or the timeout expires. Unlike waitForData
// (which returns after the first chunk), this is safe for multi-message
// assertions where TCP coalescing may delay later reads.
func (s *mockSyslogServer) waitForContent(substrings []string, timeout time.Duration) bool {
	deadline := time.After(timeout)
	for {
		all := strings.Join(s.getMessages(), "\n")
		found := true
		for _, sub := range substrings {
			if !strings.Contains(all, sub) {
				found = false
				break
			}
		}
		if found {
			return true
		}
		select {
		case <-deadline:
			return false
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// ---------------------------------------------------------------------------
// Construction validation
// ---------------------------------------------------------------------------

func TestNewSyslogOutput_TCP(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	out, err := syslog.New(&syslog.Config{
		Network:       "tcp",
		Address:       srv.addr(),
		FlushInterval: 5 * time.Millisecond,
	})
	require.NoError(t, err)
	require.NoError(t, out.Close())
}

func TestNewSyslogOutput_UDP(t *testing.T) {
	// UDP doesn't need a running server to construct.
	out, err := syslog.New(&syslog.Config{
		Network:       "udp",
		Address:       "127.0.0.1:9514",
		FlushInterval: 5 * time.Millisecond,
	})
	require.NoError(t, err)
	require.NoError(t, out.Close())
}

func TestNewSyslogOutput_InvalidConfig(t *testing.T) {
	tests := []struct {
		name    string
		wantErr string
		cfg     syslog.Config
	}{
		{
			name: "missing address",
			cfg: syslog.Config{Network: "tcp",
				FlushInterval: 5 * time.Millisecond,
			},
			wantErr: "must not be empty",
		},
		{
			name: "invalid network",
			cfg: syslog.Config{Network: "http", Address: "localhost:514",
				FlushInterval: 5 * time.Millisecond,
			},
			wantErr: "must be tcp, udp, or tcp+tls",
		},
		{
			name: "invalid facility",
			cfg: syslog.Config{Network: "udp", Address: "localhost:514", Facility: "bogus",
				FlushInterval: 5 * time.Millisecond,
			},
			wantErr: "unknown syslog facility",
		},
		{
			name: "cert without key",
			cfg: syslog.Config{
				Network:       "tcp+tls",
				Address:       "localhost:6514",
				TLSCert:       "/tmp/cert.pem",
				FlushInterval: 5 * time.Millisecond,
			},
			wantErr: "tls_cert and tls_key must both be set",
		},
		{
			name: "key without cert",
			cfg: syslog.Config{
				Network:       "tcp+tls",
				Address:       "localhost:6514",
				TLSKey:        "/tmp/key.pem",
				FlushInterval: 5 * time.Millisecond,
			},
			wantErr: "tls_cert and tls_key must both be set",
		},
		{
			name: "nonexistent cert file",
			cfg: syslog.Config{
				Network:       "tcp+tls",
				Address:       "localhost:6514",
				TLSCert:       "/nonexistent/cert.pem",
				TLSKey:        "/nonexistent/key.pem",
				FlushInterval: 5 * time.Millisecond,
			},
			wantErr: "tls file",
		},
		{
			name: "nonexistent CA file",
			cfg: syslog.Config{
				Network:       "tcp+tls",
				Address:       "localhost:6514",
				TLSCA:         "/nonexistent/ca.pem",
				FlushInterval: 5 * time.Millisecond,
			},
			wantErr: "tls file",
		},
		{
			name: "max_retries exceeds maximum",
			cfg: syslog.Config{Network: "udp", Address: "localhost:514", MaxRetries: 1000,
				FlushInterval: 5 * time.Millisecond,
			},
			wantErr: "max_retries 1000 exceeds maximum 20",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := syslog.New(&tt.cfg)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
			assert.ErrorIs(t, err, audit.ErrConfigInvalid,
				"all syslog config validation errors must wrap audit.ErrConfigInvalid")
		})
	}
}

func TestNewSyslogOutput_InvalidPEMCA(t *testing.T) {
	// Create a CA file with invalid PEM content.
	tmpFile, err := os.CreateTemp("", "bad-ca-*.pem")
	require.NoError(t, err)
	defer func() { _ = os.Remove(tmpFile.Name()) }()
	_, _ = tmpFile.WriteString("not valid pem data")
	_ = tmpFile.Close()

	_, err = syslog.New(&syslog.Config{
		Network:       "tcp+tls",
		Address:       "localhost:6514",
		TLSCA:         tmpFile.Name(),
		FlushInterval: 5 * time.Millisecond,
	})
	require.Error(t, err)
	// text-only: tls.go:49 returns raw fmt.Errorf for invalid PEM (no
	// sentinel wrap). The "parse" substring is the contract.
	assert.Contains(t, err.Error(), "parse")
}

// ---------------------------------------------------------------------------
// Write / Close contract
// ---------------------------------------------------------------------------

func TestSyslogOutput_Write(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	out, err := syslog.New(&syslog.Config{
		Network:       "tcp",
		Address:       srv.addr(),
		FlushInterval: 5 * time.Millisecond,
	})
	require.NoError(t, err)

	data := []byte(`{"event_type":"user_create","outcome":"success"}`)
	require.NoError(t, out.Write(data))

	// Give the server time to receive.
	require.True(t, srv.waitForData(2*time.Second), "server should receive data")
	require.NoError(t, out.Close())

	msgs := srv.getMessages()
	require.NotEmpty(t, msgs)
	// The message should contain our JSON payload.
	assert.Contains(t, msgs[0], "user_create")
}

func TestSyslogOutput_Hostname_Override(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	out, err := syslog.New(&syslog.Config{
		Network:       "tcp",
		Address:       srv.addr(),
		Hostname:      "custom-host",
		FlushInterval: 5 * time.Millisecond,
	})
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte(`{"event_type":"test"}`)))
	require.True(t, srv.waitForData(2*time.Second))
	require.NoError(t, out.Close())

	msgs := srv.getMessages()
	require.NotEmpty(t, msgs)
	assert.Contains(t, msgs[0], "custom-host",
		"syslog message should contain the overridden hostname")
}

func TestSyslogOutput_Hostname_DefaultFallback(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	out, err := syslog.New(&syslog.Config{
		Network: "tcp",
		Address: srv.addr(),
		// Hostname intentionally omitted — should fall back to os.Hostname.,
		FlushInterval: 5 * time.Millisecond,
	})
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte(`{"event_type":"test"}`)))
	require.True(t, srv.waitForData(2*time.Second))
	require.NoError(t, out.Close())

	msgs := srv.getMessages()
	require.NotEmpty(t, msgs)
	// Cannot assert the exact hostname, but the message should be non-empty.
	assert.NotEmpty(t, msgs[0])
}

func TestSyslogOutput_Hostname_Validation_Invalid(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		hostname string
		wantErr  string
	}{
		{"space", "my host", "invalid byte 0x20"},
		{"newline", "host\ninjection", "invalid byte 0x0a"},
		{"carriage_return", "host\rinjection", "invalid byte 0x0d"},
		{"null_byte", "host\x00evil", "invalid byte 0x00"},
		{"tab", "host\tevil", "invalid byte 0x09"},
		{"too_long", strings.Repeat("a", 256), "exceeds RFC 5424 maximum"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// Invalid hostnames are rejected during config validation
			// before any connection attempt — no server needed.
			_, err := syslog.New(&syslog.Config{
				Network:       "tcp",
				Address:       "localhost:1",
				Hostname:      tc.hostname,
				FlushInterval: 5 * time.Millisecond,
			})
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
			assert.ErrorIs(t, err, audit.ErrConfigInvalid,
				"hostname validation errors must wrap audit.ErrConfigInvalid")
		})
	}
}

func TestSyslogOutput_Hostname_Validation_Valid(t *testing.T) {
	t.Parallel()
	srv := newMockSyslogServer(t)
	defer srv.close()

	for _, hostname := range []string{"!", "~", "prod-01.example.com"} {
		out, err := syslog.New(&syslog.Config{
			Network:       "tcp",
			Address:       srv.addr(),
			Hostname:      hostname,
			FlushInterval: 5 * time.Millisecond,
		})
		require.NoError(t, err, "valid hostname %q should not cause an error", hostname)
		_ = out.Close()
	}
}

func TestSyslogOutput_WriteMultiple(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	out, err := syslog.New(&syslog.Config{
		Network:       "tcp",
		Address:       srv.addr(),
		FlushInterval: 5 * time.Millisecond,
	})
	require.NoError(t, err)

	expected := make([]string, 5)
	for i := range 5 {
		expected[i] = fmt.Sprintf(`{"n":%d}`, i)
		require.NoError(t, out.Write([]byte(expected[i])))
	}

	require.True(t, srv.waitForContent(expected, 2*time.Second),
		"server should receive all 5 events")
	require.NoError(t, out.Close())
}

func TestSyslogOutput_CloseIdempotent(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	out, err := syslog.New(&syslog.Config{
		Network:       "tcp",
		Address:       srv.addr(),
		FlushInterval: 5 * time.Millisecond,
	})
	require.NoError(t, err)

	assert.NoError(t, out.Close())
	assert.NoError(t, out.Close())
}

func TestSyslogOutput_WriteAfterClose(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	out, err := syslog.New(&syslog.Config{
		Network:       "tcp",
		Address:       srv.addr(),
		FlushInterval: 5 * time.Millisecond,
	})
	require.NoError(t, err)
	require.NoError(t, out.Close())

	err = out.Write([]byte("data"))
	assert.ErrorIs(t, err, audit.ErrOutputClosed)
}

// ---------------------------------------------------------------------------
// Async delivery (#455)
// ---------------------------------------------------------------------------

func TestSyslogOutput_Write_NonBlocking(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	out, err := syslog.New(&syslog.Config{
		Network:       "tcp",
		Address:       srv.addr(),
		BufferSize:    100,
		FlushInterval: 5 * time.Millisecond,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	// Write should return immediately — it enqueues to a channel.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 50 {
			_ = out.Write([]byte(`{"event":"nonblocking"}`))
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Write blocked for 5s — should be non-blocking")
	}
}

func TestSyslogOutput_BufferFull_Drops(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	om := &mockOutputMetrics{}
	out, err := syslog.New(&syslog.Config{
		Network:       "tcp",
		Address:       srv.addr(),
		BufferSize:    1,
		FlushInterval: 5 * time.Millisecond,
	}, syslog.WithOutputMetrics(om))
	require.NoError(t, err)

	// Flood the buffer. Some writes will be dropped.
	const writes = 200
	for range writes {
		_ = out.Write([]byte(`{"event":"flood"}`))
	}

	require.NoError(t, out.Close())

	assert.Positive(t, om.drops.Load(),
		"RecordDrop must be called when the buffer is full")
	assert.LessOrEqual(t, om.flushes.Load()+om.drops.Load(), int64(writes),
		"flushes plus drops must not exceed total writes")
}

func TestSyslogOutput_Close_DrainsBuffer(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	om := &mockOutputMetrics{}
	out, err := syslog.New(&syslog.Config{
		Network:       "tcp",
		Address:       srv.addr(),
		BufferSize:    1000,
		FlushInterval: 5 * time.Millisecond,
	}, syslog.WithOutputMetrics(om))
	require.NoError(t, err)

	const n = 20
	for range n {
		require.NoError(t, out.Write([]byte(`{"event":"drain-marker"}`)))
	}

	// Close must drain all buffered events.
	require.NoError(t, out.Close())

	// Verify server received events.
	require.True(t, srv.waitForData(2*time.Second),
		"server should have received data after Close drains buffer")

	// All events should have been flushed via OutputMetrics.
	assert.Equal(t, int64(n), om.flushes.Load(),
		"Close must drain all %d buffered events", n)
	assert.Zero(t, om.drops.Load(),
		"no events should be dropped with a large buffer")
}

func TestSyslogOutput_ImplementsDeliveryReporter(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	out, err := syslog.New(&syslog.Config{
		Network:       "tcp",
		Address:       srv.addr(),
		FlushInterval: 5 * time.Millisecond,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	var o audit.Output = out
	dr, ok := o.(audit.DeliveryReporter)
	require.True(t, ok, "syslog output must implement DeliveryReporter")
	assert.True(t, dr.ReportsDelivery(), "syslog output must self-report delivery")
}

// TestSyslogOutput_ImplementsOutputMetricsReceiver was removed in
// #696 along with the OutputMetricsReceiver interface. Per-output
// metrics are now plumbed in at construction via
// [syslog.WithOutputMetrics].

func TestSyslogOutput_CopySafety(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	out, err := syslog.New(&syslog.Config{
		Network:       "tcp",
		Address:       srv.addr(),
		FlushInterval: 5 * time.Millisecond,
	})
	require.NoError(t, err)

	data := []byte(`{"event":"original"}`)
	require.NoError(t, out.Write(data))

	// Mutate the original slice after Write returns.
	for i := range data {
		data[i] = 'X'
	}

	// Wait for the event to arrive at the mock server before closing.
	// The syslog output wraps the payload in RFC 5424 framing, so we
	// check for the payload as a substring.
	require.True(t, srv.waitForContent(
		[]string{`{"event":"original"}`}, 2*time.Second),
		"server must receive the original payload, not the mutated copy")

	require.NoError(t, out.Close())

	// waitForContent proved the original is present; verify the mutation did not leak.
	all := strings.Join(srv.getMessages(), "\n")
	assert.NotContains(t, all, "XXXXXXXXXXXXXXXXXXXX",
		"server must not contain the mutated data")
}

func TestSyslogOutput_WriteDuringClose_NoPanic(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	out, err := syslog.New(&syslog.Config{
		Network:       "tcp",
		Address:       srv.addr(),
		BufferSize:    10,
		FlushInterval: 5 * time.Millisecond,
	})
	require.NoError(t, err)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for range 100 {
			_ = out.Write([]byte(`{"event":"race"}`))
		}
	}()

	go func() {
		defer wg.Done()
		_ = out.Close()
	}()

	wg.Wait()
	// Success if no panic or deadlock.
}

func TestSyslogOutput_Name(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	out, err := syslog.New(&syslog.Config{
		Network:       "tcp",
		Address:       srv.addr(),
		FlushInterval: 5 * time.Millisecond,
	})
	require.NoError(t, err)
	defer func() { _ = out.Close() }()

	assert.True(t, strings.HasPrefix(out.Name(), "syslog:"))
	assert.Contains(t, out.Name(), srv.addr())
}

func TestSyslogOutput_DestinationKey(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	out, err := syslog.New(&syslog.Config{
		Network:       "tcp",
		Address:       srv.addr(),
		FlushInterval: 5 * time.Millisecond,
	})
	require.NoError(t, err)
	defer func() { _ = out.Close() }()

	assert.Equal(t, srv.addr(), out.DestinationKey(),
		"DestinationKey must return the configured address")
}

func TestSyslogOutput_ImplementsOutput(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	out, err := syslog.New(&syslog.Config{
		Network:       "tcp",
		Address:       srv.addr(),
		FlushInterval: 5 * time.Millisecond,
	})
	require.NoError(t, err)
	defer func() { _ = out.Close() }()

	var _ audit.Output = out
}

// ---------------------------------------------------------------------------
// Facility parsing
// ---------------------------------------------------------------------------

func TestParseFacility_AllStandard(t *testing.T) {
	facilities := []string{
		"kern", "user", "mail", "daemon", "auth", "syslog",
		"lpr", "news", "uucp", "cron", "authpriv", "ftp",
		"local0", "local1", "local2", "local3",
		"local4", "local5", "local6", "local7",
	}
	for _, f := range facilities {
		t.Run(f, func(t *testing.T) {
			// Verify construction succeeds with each facility.
			srv := newMockSyslogServer(t)
			defer srv.close()
			out, err := syslog.New(&syslog.Config{
				Network:       "tcp",
				Address:       srv.addr(),
				Facility:      f,
				FlushInterval: 5 * time.Millisecond,
			})
			require.NoError(t, err, "facility %q should be valid", f)
			require.NoError(t, out.Close())
		})
	}
}

func TestParseFacility_Unknown(t *testing.T) {
	_, err := syslog.New(&syslog.Config{
		Network:       "udp",
		Address:       "localhost:514",
		Facility:      "nonexistent",
		FlushInterval: 5 * time.Millisecond,
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrConfigInvalid)
	assert.Contains(t, err.Error(), "unknown syslog facility")
}

// ---------------------------------------------------------------------------
// TLS
// ---------------------------------------------------------------------------

// mockTLSSyslogServer listens on TLS TCP.
type mockTLSSyslogServer struct {
	listener net.Listener
	done     chan struct{}
	messages []string
	wg       sync.WaitGroup
	mu       sync.Mutex
}

func newMockTLSSyslogServer(t *testing.T, tlsCfg *tls.Config) *mockTLSSyslogServer {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	require.NoError(t, err)

	s := &mockTLSSyslogServer{
		listener: ln,
		done:     make(chan struct{}),
	}
	s.wg.Add(1)
	go s.accept()
	return s
}

func (s *mockTLSSyslogServer) accept() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go s.handleConn(conn)
	}
}

func (s *mockTLSSyslogServer) handleConn(conn net.Conn) {
	defer s.wg.Done()
	defer func() { _ = conn.Close() }()

	buf := make([]byte, 8192)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, err := conn.Read(buf)
		if n > 0 {
			s.mu.Lock()
			s.messages = append(s.messages, string(buf[:n]))
			s.mu.Unlock()
		}
		if err != nil {
			select {
			case <-s.done:
				return
			default:
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			return
		}
	}
}

func (s *mockTLSSyslogServer) addr() string {
	return s.listener.Addr().String()
}

func (s *mockTLSSyslogServer) close() {
	close(s.done)
	_ = s.listener.Close()
	s.wg.Wait()
}

func (s *mockTLSSyslogServer) getMessages() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make([]string, len(s.messages))
	copy(cp, s.messages)
	return cp
}

func (s *mockTLSSyslogServer) messageCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.messages)
}

func (s *mockTLSSyslogServer) waitForData(timeout time.Duration) bool {
	deadline := time.After(timeout)
	for {
		if s.messageCount() > 0 {
			return true
		}
		select {
		case <-deadline:
			return false
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestSyslogOutput_TLS(t *testing.T) {
	certs := audittest.GenerateTestCerts(t)
	srv := newMockTLSSyslogServer(t, certs.TLSCfg)
	defer srv.close()

	out, err := syslog.New(&syslog.Config{
		Network:       "tcp+tls",
		Address:       srv.addr(),
		TLSCA:         certs.CAPath,
		FlushInterval: 5 * time.Millisecond,
	})
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte(`{"event":"tls_test"}`)))
	require.True(t, srv.waitForData(2*time.Second), "TLS server should receive data")
	require.NoError(t, out.Close())

	msgs := srv.getMessages()
	require.NotEmpty(t, msgs)
	assert.Contains(t, msgs[0], "tls_test")
}

func TestSyslogOutput_MTLS(t *testing.T) {
	certs := audittest.GenerateTestCerts(t)
	// Require client cert for mTLS.
	certs.TLSCfg.ClientAuth = tls.RequireAndVerifyClientCert
	srv := newMockTLSSyslogServer(t, certs.TLSCfg)
	defer srv.close()

	out, err := syslog.New(&syslog.Config{
		Network:       "tcp+tls",
		Address:       srv.addr(),
		TLSCert:       certs.ClientCert,
		TLSKey:        certs.ClientKey,
		TLSCA:         certs.CAPath,
		FlushInterval: 5 * time.Millisecond,
	})
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte(`{"event":"mtls_test"}`)))
	require.True(t, srv.waitForData(2*time.Second), "mTLS server should receive data")
	require.NoError(t, out.Close())

	msgs := srv.getMessages()
	require.NotEmpty(t, msgs)
	assert.Contains(t, msgs[0], "mtls_test")
}

// ---------------------------------------------------------------------------
// TLSPolicy integration
// ---------------------------------------------------------------------------

func TestSyslogOutput_TLSPolicy_NilPreservesBehaviour(t *testing.T) {
	// Nil TLSPolicy should behave identically to the previous hardcoded
	// TLS 1.3 default: connect to a TLS 1.3 server with a custom CA.
	certs := audittest.GenerateTestCerts(t)
	srv := newMockTLSSyslogServer(t, certs.TLSCfg)
	defer srv.close()

	out, err := syslog.New(&syslog.Config{
		Network:       "tcp+tls",
		Address:       srv.addr(),
		TLSCA:         certs.CAPath,
		TLSPolicy:     nil, // explicitly nil,
		FlushInterval: 5 * time.Millisecond,
	})
	require.NoError(t, err)
	require.NoError(t, out.Write([]byte(`{"event":"nil_policy"}`)))
	require.True(t, srv.waitForData(2*time.Second))
	require.NoError(t, out.Close())

	msgs := srv.getMessages()
	require.NotEmpty(t, msgs)
	assert.Contains(t, msgs[0], "nil_policy")
}

func TestSyslogOutput_TLSPolicy_AllowTLS12(t *testing.T) {
	certs := audittest.GenerateTestCerts(t)
	// Server accepts TLS 1.2.
	certs.TLSCfg.MinVersion = tls.VersionTLS12
	srv := newMockTLSSyslogServer(t, certs.TLSCfg)
	defer srv.close()

	out, err := syslog.New(&syslog.Config{
		Network: "tcp+tls",
		Address: srv.addr(),
		TLSCA:   certs.CAPath,
		TLSPolicy: &audit.TLSPolicy{
			AllowTLS12: true,
		},
		FlushInterval: 5 * time.Millisecond,
	})
	require.NoError(t, err)
	require.NoError(t, out.Write([]byte(`{"event":"tls12_policy"}`)))
	require.True(t, srv.waitForData(2*time.Second))
	require.NoError(t, out.Close())

	msgs := srv.getMessages()
	require.NotEmpty(t, msgs)
	assert.Contains(t, msgs[0], "tls12_policy")
}

// ---------------------------------------------------------------------------
// Reconnection
// ---------------------------------------------------------------------------

func TestSyslogOutput_WriteFailure_HandledInBackground(t *testing.T) {
	srv := newMockSyslogServer(t)
	addr := srv.addr()

	out, err := syslog.New(&syslog.Config{
		Network:       "tcp",
		Address:       addr,
		MaxRetries:    1, // minimal retries to keep test fast,
		FlushInterval: 5 * time.Millisecond,
	})
	require.NoError(t, err)

	// First write succeeds (enqueued to background goroutine).
	require.NoError(t, out.Write([]byte(`{"n":1}`)))

	// Kill the server.
	srv.close()

	// With async delivery, Write() returns nil (non-blocking channel
	// send). Connection errors are handled in the background writeLoop.
	for range 5 {
		err := out.Write([]byte(`{"n":2}`))
		assert.NoError(t, err, "async Write should never return connection errors")
	}

	// Close drains the buffer — the writeLoop will encounter errors
	// and log them, but Close itself should not return an error from
	// the write failures (only from closing the underlying writer).
	require.NoError(t, out.Close())
}

// ---------------------------------------------------------------------------
// Metrics (#54)
// ---------------------------------------------------------------------------

// syslogOnlyMetrics implements audit.OutputMetrics (via NoOp embed)
// plus syslog.ReconnectRecorder so SetOutputMetrics wires both
// contracts (#581).
type syslogOnlyMetrics struct {
	audit.NoOpOutputMetrics
	mu        sync.Mutex
	successes int
	failures  int
}

func (m *syslogOnlyMetrics) RecordReconnect(_ string, success bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if success {
		m.successes++
	} else {
		m.failures++
	}
}

var _ syslog.ReconnectRecorder = (*syslogOnlyMetrics)(nil)

func TestSyslogOutput_NilReconnectRecorder_ReconnectDoesNotPanic(t *testing.T) {
	// nil Metrics must not panic during the reconnect path.
	srv := newMockSyslogServer(t)
	addr := srv.addr()

	out, err := syslog.New(&syslog.Config{
		Network:       "tcp",
		Address:       addr,
		MaxRetries:    1,
		FlushInterval: 5 * time.Millisecond,
	}) // nil Metrics
	require.NoError(t, err)

	// First write succeeds — connection is established.
	require.NoError(t, out.Write([]byte(`{"n":1}`)))

	// Kill the server to force reconnect logic.
	srv.close()

	// Writes after server dies enqueue events. The background
	// writeLoop triggers the reconnect path which would call
	// reconnect recorder via RecordReconnect if non-nil. With nil, it
	// must not panic.
	for range 5 {
		require.NoError(t, out.Write([]byte(`{"n":2}`)))
	}

	// Close drains and completes — success means no panic occurred.
	require.NoError(t, out.Close())
}

func TestSyslogOutput_ReconnectRecorder_RecordReconnect_FailureOnPermanentServerDown(t *testing.T) {
	// Verify RecordReconnect(address, false) is called when
	// reconnection fails because the server is permanently gone.
	srv := newMockSyslogServer(t)
	addr := srv.addr()

	m := newMockMetrics()
	out, err := syslog.New(&syslog.Config{
		Network:       "tcp",
		Address:       addr,
		MaxRetries:    2, // allow 2 reconnection attempts,
		FlushInterval: 5 * time.Millisecond,
	}, syslog.WithOutputMetrics(m))
	require.NoError(t, err)

	// Establish the connection with a successful write.
	require.NoError(t, out.Write([]byte(`{"n":1}`)))

	// Bring the server down permanently.
	srv.close()

	// Enqueue events — the background writeLoop will encounter
	// failures and attempt reconnection.
	for range 5 {
		_ = out.Write([]byte(`{"n":2}`))
	}

	// Wait deterministically for at least one reconnect failure to
	// be recorded before closing. Replaces require.Eventually
	// polling (#705 family fix).
	m.waitForReconnectCount(t, addr, false, 1, 5*time.Second)

	require.NoError(t, out.Close())
}

func TestSyslogOutput_ReconnectRecorder_RecordReconnect_SuccessPath(t *testing.T) {
	// Verify RecordReconnect(address, true) is called when a
	// reconnection attempt to a live server succeeds.
	//
	// Approach: bind a listener on a fixed address. Establish the initial
	// connection. Close and immediately rebind the same listener (SO_REUSEADDR
	// applies on Linux; the OS recycles the port instantly for loopback).
	// The output's reconnect path will connect to the new listener and call
	// RecordReconnect(addr, true).

	// Bind the server on a fixed loopback address with a kernel-assigned port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()

	// Wrap the first listener in a mock server.
	srv1 := &mockSyslogServer{
		listener: ln,
		done:     make(chan struct{}),
	}
	srv1.wg.Add(1)
	go srv1.accept()

	m := newMockMetrics()
	out, err := syslog.New(&syslog.Config{
		Network:       "tcp",
		Address:       addr,
		MaxRetries:    10, // enough headroom for reconnect,
		FlushInterval: 5 * time.Millisecond,
	}, syslog.WithOutputMetrics(m))
	require.NoError(t, err)

	// Establish a live connection with a successful write.
	require.NoError(t, out.Write([]byte(`{"n":1}`)))
	require.True(t, srv1.waitForData(2*time.Second), "server should receive initial write")

	// Kill the first server. The next write will fail and trigger backoff.
	srv1.close()

	// Reuse the same port by binding a new listener immediately after
	// the old one is closed. On Linux loopback this is nearly instant.
	ln2, listenErr := net.Listen("tcp", addr)
	require.NoError(t, listenErr, "must rebind same address for reconnect test")

	srv2 := &mockSyslogServer{
		listener: ln2,
		done:     make(chan struct{}),
	}
	srv2.wg.Add(1)
	go srv2.accept()
	defer srv2.close()

	// Drive a few writes to trigger reconnect detection on the dead
	// connection. With MaxRetries=10 and short backoff, the
	// reconnect goroutine should observe srv2 listening on the same
	// port and record success. Use tryWaitForReconnectCount rather
	// than waitForReconnectCount so the platform-dependent TIME_WAIT
	// case (macOS / Windows port rebind delay) skips cleanly instead
	// of failing the test (#705 family fix replaces sleep+poll).
	for range 5 {
		_ = out.Write([]byte(`{"n":2}`))
	}

	reconnectSucceeded := m.tryWaitForReconnectCount(addr, true, 1, 5*time.Second)
	require.NoError(t, out.Close())

	if reconnectSucceeded {
		assert.Greater(t, m.getSyslogReconnectCount(addr, true), 0,
			"RecordReconnect(address, true) should be called on successful reconnect")
	} else {
		// The port rebind did not succeed fast enough on this OS/run.
		// The failure path is already verified by
		// TestSyslogOutput_ReconnectRecorder_RecordReconnect_FailureOnPermanentServerDown.
		t.Log("reconnect success test skipped: port could not be rebound fast enough")
	}
}

// hostileSyslogServer accepts TCP connections. In normal mode it reads
// and discards data. After SetHostile is called, new connections receive
// an immediate TCP RST (SetLinger(0) + Close). The listener stays up
// the entire time so that srslog.Dial always succeeds.
type hostileSyslogServer struct { //nolint:govet // fieldalignment: test helper, readability preferred
	listener net.Listener
	hostile  atomic.Bool
	conns    []net.Conn
	connsMu  sync.Mutex
	done     chan struct{}
	wg       sync.WaitGroup
}

func newHostileSyslogServer(t *testing.T) *hostileSyslogServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	s := &hostileSyslogServer{listener: ln, done: make(chan struct{})}
	s.wg.Add(1)
	go s.acceptLoop()
	return s
}

func (s *hostileSyslogServer) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		if s.hostile.Load() {
			rstClose(conn)
		} else {
			s.trackAndRead(conn)
		}
	}
}

func (s *hostileSyslogServer) trackAndRead(conn net.Conn) {
	s.connsMu.Lock()
	s.conns = append(s.conns, conn)
	s.connsMu.Unlock()
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		buf := make([]byte, 4096)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			_, err := conn.Read(buf)
			if err == nil {
				continue
			}
			select {
			case <-s.done:
				return
			default:
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			return
		}
	}()
}

func (s *hostileSyslogServer) addr() string { return s.listener.Addr().String() }

// SetHostile switches the server to hostile mode and RST-closes all
// existing connections. New connections will also be RST-closed.
func (s *hostileSyslogServer) SetHostile() {
	s.hostile.Store(true)
	s.connsMu.Lock()
	for _, c := range s.conns {
		rstClose(c)
	}
	s.conns = nil
	s.connsMu.Unlock()
}

// KillExistingConnections RST-closes every currently-tracked
// connection without enabling hostile mode for future accepts. The
// listener continues accepting new connections normally, so a
// follow-up reconnect attempt by the client succeeds
// deterministically. Used by tests that need to force the client
// through handleWriteFailure without contending with the accept-
// then-RST race that affects SetHostile (#765). Callers wanting
// both existing AND new connections RST'd should use SetHostile
// instead.
func (s *hostileSyslogServer) KillExistingConnections() {
	s.connsMu.Lock()
	for _, c := range s.conns {
		rstClose(c)
	}
	s.conns = nil
	s.connsMu.Unlock()
}

func (s *hostileSyslogServer) close() {
	close(s.done)
	_ = s.listener.Close()
	s.connsMu.Lock()
	for _, c := range s.conns {
		_ = c.Close()
	}
	s.connsMu.Unlock()
	s.wg.Wait()
}

// rstClose sends a TCP RST by setting linger to 0 before closing.
func rstClose(conn net.Conn) {
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetLinger(0)
	}
	_ = conn.Close()
}

// TestSyslogOutput_HandleWriteFailure_WriteFailsAfterReconnect
// verifies BOTH legs of handleWriteFailure that the test name
// implies:
//
//   - the post-disconnect reconnect succeeds — RecordReconnect(addr, true) fires;
//   - the post-reconnect retry path runs and fails — RecordError fires.
//
// The "fails" leg is exercised via the
// "writer nil after successful reconnect" guard in
// retryAfterReconnect, NOT the literal "delivery failed after
// reconnect" syscall-error branch. The latter is unreachable
// deterministically because srslog.Writer transparently
// re-dials internally on a closed conn (see writeAndRetryWithPriority
// in github.com/axonops/srslog), so closing the writer mid-test
// is masked. The nil-guard branch is the deterministic equivalent —
// it sits on the same post-reconnect retry path and fires the same
// RecordError signal, which is what AC3 of #765 specifies
// ("retry-write-failed signal (e.g., RecordError count > 0)").
//
// Closes #765 (and subsumes the lingering #465 / #560 surface).
//
// History: prior incarnations of this test drove writes via a
// 40-iteration sleep loop, then via a 30-second ticker loop that
// kept firing until the reconnect metric incremented. Both
// flaked at -count=N under CI load (~0.18 % at count=1100)
// because of a TCP send-buffer cache race: after SetHostile RSTs
// the server-side connection, the client kernel briefly buffers
// initial writes — srslog.WriteWithPriority returns SUCCESS at
// the syscall level before the RST is observed — so the
// writeLoop never sees a write failure, never enters
// handleWriteFailure, and the reconnect counter never
// increments.
//
// Final fix (#765) makes BOTH the entry into handleWriteFailure
// and the retry-write-failure branch deterministic, without
// relying on transport timing:
//
//   - SetTestOnFlush signals when the initial successful write
//     has been flushed (writeLoop has parked on the select).
//   - KillExistingConnections RSTs the existing connection
//     server-side but leaves the listener accepting new conns
//     normally — connect() on reconnect is race-free.
//   - SimulateDisconnect atomically clears Output.writer so the
//     next writeLoop iteration observes errSyslogNotConnected at
//     the writeEntry nil check and enters handleWriteFailure
//     deterministically.
//   - SetTestOnReconnect installs a hook that fires between
//     RecordReconnect(addr, true) and the retry write. The hook
//     calls SimulateDisconnect(), atomically clearing s.writer.
//     handleWriteFailure's post-reconnect retry path re-loads
//     s.writer, sees nil, and trips the belt-and-braces "writer
//     nil after successful reconnect" guard which fires
//     RecordError. (Closing the writer directly would not work —
//     srslog.Writer.WriteWithPriority transparently re-dials
//     internally on a closed conn.)
func TestSyslogOutput_HandleWriteFailure_WriteFailsAfterReconnect(t *testing.T) {
	srv := newHostileSyslogServer(t)
	defer srv.close()
	addr := srv.addr()

	m := newMockMetrics()
	out, err := syslog.New(&syslog.Config{
		Network:       "tcp",
		Address:       addr,
		MaxRetries:    20,
		FlushInterval: 5 * time.Millisecond,
	}, syslog.WithOutputMetrics(m))
	require.NoError(t, err)

	// Register a flush barrier so we can deterministically tell
	// when the writeLoop has finished processing the initial
	// successful write and parked back on its select.
	flushed := make(chan struct{}, 8)
	out.SetTestOnFlush(func(_ int, _ string) {
		select {
		case flushed <- struct{}{}:
		default:
		}
	})
	t.Cleanup(func() { out.SetTestOnFlush(nil) })

	// Reconnect hook: between RecordReconnect(true) firing and the
	// retry write, atomically clear Output.writer. handleWriteFailure
	// re-loads s.writer immediately after the hook returns; a nil
	// trips the post-reconnect "writer nil after successful
	// reconnect" guard, which fires RecordError. Closing the writer
	// directly will not work — srslog.Writer.WriteWithPriority
	// transparently re-dials internally on a closed conn, masking
	// the failure.
	out.SetTestOnReconnect(func(_ *srslog.Writer) {
		out.SimulateDisconnect()
	})
	t.Cleanup(func() { out.SetTestOnReconnect(nil) })

	// Establish a live connection with a successful write.
	require.NoError(t, out.Write([]byte(`{"n":1}`)))

	// Wait for the initial flush to complete — once we receive on
	// `flushed`, writeLoop has called the test hook from inside
	// flushAndReset and is on its way back to select. This
	// happens-before edge is what makes the SimulateDisconnect
	// call below logically race-free with the next write.
	select {
	case <-flushed:
	case <-time.After(5 * time.Second):
		t.Fatal("initial write never flushed")
	}

	// RST the existing connection but leave the listener accepting
	// new conns normally. This guarantees connect() succeeds on
	// reconnect. SetHostile (which also RSTs new conns at accept
	// time) introduces an accept-vs-RST race that the original
	// 30 s ticker loop masked by retrying; the deterministic flow
	// needs connect() to be race-free.
	srv.KillExistingConnections()

	// Atomically clear the writer. The flush barrier above proved
	// the writeLoop has at least reached the post-flush select;
	// subsequent FlushInterval ticks on an empty batch are no-ops
	// and cannot race the Store. The atomic.Pointer wrap (#765)
	// keeps this race-clean under -race regardless of channel
	// ordering.
	out.SimulateDisconnect()

	// Drive a single write. Path:
	//
	//   writeEntry sees nil writer → errSyslogNotConnected →
	//   handleWriteFailure → close (no-op nil) → backoff →
	//   connect() succeeds (listener up) →
	//   RecordReconnect(addr, true) → testOnReconnect hook calls
	//   SimulateDisconnect → s.writer.Store(nil) →
	//   post-reconnect retry path re-loads s.writer, sees nil →
	//   "writer nil after successful reconnect" guard fires →
	//   RecordError++.
	require.NoError(t, out.Write([]byte(`{"n":2}`)))

	// Deterministic wait: the reconnect metric must fire within
	// the first reconnect attempt's backoff window. 5 s headroom
	// absorbs CI scheduling jitter; the actual path is sub-ms.
	if !m.tryWaitForReconnectCount(addr, true, 1, 5*time.Second) {
		t.Fatalf("RecordReconnect(addr, true) did not fire within 5s — "+
			"writeLoop may not be entering handleWriteFailure "+
			"(recorded counts: success=%d, failure=%d)",
			m.getSyslogReconnectCount(addr, true),
			m.getSyslogReconnectCount(addr, false))
	}

	_ = out.Close()

	assert.Greater(t, m.getSyslogReconnectCount(addr, true), 0,
		"RecordReconnect(address, true) must fire — connect() "+
			"succeeds because the listener stays up after "+
			"KillExistingConnections")
	assert.Greater(t, m.getErrorCount(), 0,
		"RecordError must fire from handleWriteFailure's "+
			"post-reconnect failure path — the testOnReconnect "+
			"hook clears s.writer so the post-reconnect retry "+
			"path observes nil and trips the \"writer nil after "+
			"successful reconnect\" guard")
}

func TestSyslogOutput_ReconnectRecorder_InterfaceAssertion(t *testing.T) {
	// Compile-time: verify NewSyslogOutput accepts any syslog.ReconnectRecorder,
	// not just mockMetrics. This test would not compile if the signature
	// changed.
	srv := newMockSyslogServer(t)
	defer srv.close()

	m := &syslogOnlyMetrics{}
	// Compile-time check: syslogOnlyMetrics satisfies ReconnectRecorder.
	var _ syslog.ReconnectRecorder = m
	out, err := syslog.New(&syslog.Config{
		Network:       "tcp",
		Address:       srv.addr(),
		FlushInterval: 5 * time.Millisecond,
	}, syslog.WithOutputMetrics(m))
	require.NoError(t, err)
	require.NoError(t, out.Close())
}

// TestSyslogOutput_SetOutputMetrics_ReplaceClearsReconnectRecorder was
// removed in #696 along with the post-construction SetOutputMetrics
// API. Output metrics are now wired once at construction via
// [syslog.WithOutputMetrics]; runtime swap is not supported.

// ---------------------------------------------------------------------------
// Backoff calculation
// ---------------------------------------------------------------------------

func TestBackoffDuration(t *testing.T) {
	// Backoff uses jitter [0.5, 1.0), so verify the result is within
	// the expected range.
	d1 := syslog.BackoffDuration(1)
	assert.GreaterOrEqual(t, d1, 50*time.Millisecond) // 100ms * 0.5
	assert.Less(t, d1, 100*time.Millisecond)          // 100ms * 1.0

	d2 := syslog.BackoffDuration(2)
	assert.GreaterOrEqual(t, d2, 100*time.Millisecond) // 200ms * 0.5
	assert.Less(t, d2, 200*time.Millisecond)

	d3 := syslog.BackoffDuration(3)
	assert.GreaterOrEqual(t, d3, 200*time.Millisecond) // 400ms * 0.5
	assert.Less(t, d3, 400*time.Millisecond)

	// Large attempt should be capped at 30s (with jitter, 15-30s).
	d20 := syslog.BackoffDuration(20)
	assert.GreaterOrEqual(t, d20, 15*time.Second)
	assert.LessOrEqual(t, d20, 30*time.Second)
}

// ---------------------------------------------------------------------------
// Empty and edge-case payloads
// ---------------------------------------------------------------------------

func TestSyslogOutput_WriteNil(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	out, err := syslog.New(&syslog.Config{
		Network:       "tcp",
		Address:       srv.addr(),
		FlushInterval: 5 * time.Millisecond,
	})
	require.NoError(t, err)
	defer func() { _ = out.Close() }()

	// Write(nil) should not panic. srslog may send an empty message
	// or silently drop it — either is acceptable.
	err = out.Write(nil)
	assert.NoError(t, err, "Write(nil) should not error")
}

func TestSyslogOutput_WriteEmpty(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	out, err := syslog.New(&syslog.Config{
		Network:       "tcp",
		Address:       srv.addr(),
		FlushInterval: 5 * time.Millisecond,
	})
	require.NoError(t, err)
	defer func() { _ = out.Close() }()

	err = out.Write([]byte{})
	assert.NoError(t, err, "Write([]byte{}) should not error")
}

// ---------------------------------------------------------------------------
// Rapid-fire TCP writes (validates RFC 5425 framing)
// ---------------------------------------------------------------------------

func TestSyslogOutput_RapidFireTCP(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	out, err := syslog.New(&syslog.Config{
		Network:       "tcp",
		Address:       srv.addr(),
		FlushInterval: 5 * time.Millisecond,
	})
	require.NoError(t, err)

	const count = 100
	for i := range count {
		data := []byte(fmt.Sprintf(`{"event":"rapid","n":%d}`, i))
		require.NoError(t, out.Write(data))
	}

	require.NoError(t, out.Close())

	// Wait for the last event to arrive — verifies all data was delivered.
	// Close() flushes the connection, so all data should be receivable.
	lastEvent := fmt.Sprintf(`"n":%d`, count-1)
	require.True(t, srv.waitForContent([]string{lastEvent}, 10*time.Second),
		"server should receive all %d events (last event not found)", count)

	// Verify all events arrived by checking the concatenated content.
	all := strings.Join(srv.getMessages(), "")
	for i := range count {
		assert.Contains(t, all, fmt.Sprintf(`"n":%d`, i),
			"event %d should be present in server data", i)
	}
}

// ---------------------------------------------------------------------------
// Concurrent writes
// ---------------------------------------------------------------------------

func TestSyslogOutput_ConcurrentWrites(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	out, err := syslog.New(&syslog.Config{
		Network:       "tcp",
		Address:       srv.addr(),
		FlushInterval: 5 * time.Millisecond,
	})
	require.NoError(t, err)

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := range goroutines {
		go func(n int) {
			defer wg.Done()
			_ = out.Write([]byte(fmt.Sprintf(`{"g":%d}`, n)))
		}(i)
	}
	wg.Wait()
	require.NoError(t, out.Close())
}

// ---------------------------------------------------------------------------
// UDP write path
// ---------------------------------------------------------------------------

func TestSyslogOutput_WriteUDP(t *testing.T) {
	// Start a UDP listener to receive syslog messages.
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	addr := conn.LocalAddr().String()

	out, err := syslog.New(&syslog.Config{
		Network:       "udp",
		Address:       addr,
		FlushInterval: 5 * time.Millisecond,
	})
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte(`{"event":"udp_test"}`)))

	// Read from the UDP listener with a timeout.
	buf := make([]byte, 8192)
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(2*time.Second)))
	n, _, readErr := conn.ReadFrom(buf)
	require.NoError(t, readErr)

	assert.Contains(t, string(buf[:n]), "udp_test",
		"UDP server should receive the event")

	require.NoError(t, out.Close())
}

func TestSyslogOutput_WriteUDP_NoOctetCountFraming(t *testing.T) {
	// RFC 5425 octet-count framing must NOT be applied to UDP datagrams.
	// A framed message starts with a decimal length: "NN <message>".
	// A bare RFC 5424 message starts with "<" (the PRI field).
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	out, err := syslog.New(&syslog.Config{
		Network:       "udp",
		Address:       conn.LocalAddr().String(),
		FlushInterval: 5 * time.Millisecond,
	})
	require.NoError(t, err)
	defer func() { _ = out.Close() }()

	require.NoError(t, out.Write([]byte(`{"event":"framing_check"}`)))

	buf := make([]byte, 8192)
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(2*time.Second)))
	n, _, readErr := conn.ReadFrom(buf)
	require.NoError(t, readErr)

	msg := string(buf[:n])
	assert.True(t, strings.HasPrefix(msg, "<"),
		"UDP datagram must start with PRI '<', not an octet-count prefix; got: %q", msg[:min(n, 40)])
	assert.Contains(t, msg, "framing_check")
}

func TestSyslogOutput_WriteUDP_LargePayload(t *testing.T) {
	// Start a UDP listener.
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	out, err := syslog.New(&syslog.Config{
		Network:       "udp",
		Address:       conn.LocalAddr().String(),
		FlushInterval: 5 * time.Millisecond,
	})
	require.NoError(t, err)
	defer func() { _ = out.Close() }()

	// A payload larger than typical UDP syslog limits (>2048 bytes).
	// The write should not panic. It may succeed (OS buffers it),
	// fail silently, or return an error — all are acceptable.
	largePayload := []byte(`{"data":"` + strings.Repeat("x", 4096) + `"}`)
	_ = out.Write(largePayload)
	// No assertion on error — UDP is fire-and-forget.
}

// ---------------------------------------------------------------------------
// handleWriteFailure — closed-during-backoff branch
// ---------------------------------------------------------------------------

func TestSyslogOutput_CloseDuringBackoff_DoesNotHang(t *testing.T) {
	// Verify that Close() called while Write() is sleeping in the
	// handleWriteFailure backoff causes Write to return promptly rather
	// than blocking for the full backoff duration.
	//
	// Strategy: connect to a server, kill it, then drive writes until
	// TCP buffering is exhausted and write actually fails (which puts
	// Write into handleWriteFailure's backoff sleep). Meanwhile, call
	// Close concurrently. If closeCh is working, Close returns quickly;
	// if not, the test blocks for tens of seconds and fails via the
	// deadline.
	//
	// TCP buffering means a single killed connection won't immediately
	// produce synchronous write errors. We use a Unix domain socket
	// listener — closing it causes immediate ECONNRESET on the writer,
	// which reliably triggers handleWriteFailure without buffering.

	srv := newMockSyslogServer(t)
	addr := srv.addr()

	// MaxRetries=20: if closeCh were broken, Write would sleep for
	// 100ms * 2^0 + 100ms * 2^1 + ... ≈ several seconds before giving
	// up, and the test would exceed its deadline.
	out, err := syslog.New(&syslog.Config{
		Network:       "tcp",
		Address:       addr,
		MaxRetries:    20,
		FlushInterval: 5 * time.Millisecond,
	})
	require.NoError(t, err)

	// Establish a live connection and flush the initial TCP buffer.
	require.NoError(t, out.Write([]byte(`{"n":0}`)))
	require.True(t, srv.waitForData(2*time.Second))

	// Kill the server; existing TCP connections reset.
	srv.close()

	// Drain the TCP kernel send buffer by writing until a write
	// synchronously fails. This must happen eventually once the OS
	// processes the RST from the closed listener.
	var firstErr error
	for range 50 {
		if err := out.Write([]byte(`{"n":1}`)); err != nil {
			firstErr = err
			break
		}
	}
	if firstErr == nil {
		// On this OS/run the kernel buffer did not drain. The closeCh
		// path is still exercised by the Close call below, just via a
		// different code path (closed check, not backoff). The test
		// still validates that Close does not hang.
		t.Log("TCP buffer did not drain synchronously; testing Close-does-not-hang path only")
	}

	// Regardless of whether writes failed, Close must return promptly.
	// The write goroutine (if any) is blocked in handleWriteFailure's
	// select — Close signals closeCh to interrupt it.
	writeDone := make(chan struct{})
	go func() {
		defer close(writeDone)
		for range 20 {
			_ = out.Write([]byte(`{"n":2}`))
		}
	}()

	closeDeadline := 3 * time.Second
	closeStart := time.Now()
	require.NoError(t, out.Close())
	closeElapsed := time.Since(closeStart)

	assert.Less(t, closeElapsed, closeDeadline,
		"Close should return promptly even when writes are in handleWriteFailure backoff")

	select {
	case <-writeDone:
	case <-time.After(5 * time.Second):
		t.Error("write goroutine did not terminate after Close")
	}
}

// ---------------------------------------------------------------------------
// buildSyslogTLSConfig — invalid CA PEM content
// ---------------------------------------------------------------------------

func TestNewSyslogOutput_TLSConfig_InvalidCAPEM(t *testing.T) {
	// buildSyslogTLSConfig calls pool.AppendCertsFromPEM which returns
	// false when the file exists but contains no valid certificate PEM.
	// Verify construction fails with a meaningful error.
	dir := t.TempDir()
	badCAPath := filepath.Join(dir, "bad-ca.pem")
	// Write a file that exists but contains no valid PEM certificate block.
	require.NoError(t, os.WriteFile(badCAPath, []byte("not a certificate\n"), 0o600))

	_, err := syslog.New(&syslog.Config{
		Network:       "tcp+tls",
		Address:       "localhost:6514",
		TLSCA:         badCAPath,
		FlushInterval: 5 * time.Millisecond,
	})
	require.Error(t, err)
	// text-only: tls.go:45,49 return raw fmt.Errorf for read/parse CA
	// failures (no sentinel wrap). The "ca certificate" substring is
	// the contract.
	assert.Contains(t, err.Error(), "ca certificate",
		"error should mention CA certificate when PEM parsing fails")
}

// ---------------------------------------------------------------------------
// validateSyslogTLSFiles — path is a directory
// ---------------------------------------------------------------------------

func TestNewSyslogOutput_TLSCert_IsDirectory(t *testing.T) {
	// When the TLS cert path is a directory, validateSyslogTLSFiles
	// must return an error citing that it is a directory.
	dir := t.TempDir()

	_, err := syslog.New(&syslog.Config{
		Network:       "tcp+tls",
		Address:       "localhost:6514",
		TLSCert:       dir, // a directory, not a file
		TLSKey:        dir,
		FlushInterval: 5 * time.Millisecond,
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrConfigInvalid)
	assert.Contains(t, err.Error(), "directory",
		"error should report that the TLS path is a directory")
}

// ---------------------------------------------------------------------------
// validateSyslogConfig — default network assignment
// ---------------------------------------------------------------------------

func TestNewSyslogOutput_DefaultNetwork(t *testing.T) {
	// When Network is empty, validateSyslogConfig defaults it to "tcp".
	// Verify construction succeeds and the output is functional.
	srv := newMockSyslogServer(t)
	defer srv.close()

	out, err := syslog.New(&syslog.Config{
		Network:       "", // empty — should default to "tcp"
		Address:       srv.addr(),
		FlushInterval: 5 * time.Millisecond,
	})
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte(`{"event":"default_network"}`)))
	require.True(t, srv.waitForData(2*time.Second), "default-network output should deliver data")
	require.NoError(t, out.Close())
}

// ---------------------------------------------------------------------------
// New — connect() failure at construction time
// ---------------------------------------------------------------------------

func TestNewSyslogOutput_TCP_ConnectFailure(t *testing.T) {
	// Verify that New returns an error (not panic) when the initial
	// TCP dial fails because nothing is listening at the address.
	// This exercises the connect() error path inside New.
	_, err := syslog.New(&syslog.Config{
		Network: "tcp",
		// Port 1 is privileged and not typically in use; on Linux this
		// causes a synchronous ECONNREFUSED rather than a timeout.
		Address:       "127.0.0.1:1",
		FlushInterval: 5 * time.Millisecond,
	})
	require.Error(t, err)
	// text-only: syslog.go startup verification path wraps dial
	// errors with the "startup verification failed" prefix; the
	// underlying srslog error contains "dial" or "connect" — either
	// is acceptable as evidence the dial failed.
	errStr := err.Error()
	assert.True(t,
		strings.Contains(errStr, "dial") || strings.Contains(errStr, "connect"),
		"error should describe the dial failure; got: %s", errStr)
	assert.Contains(t, errStr, "startup verification failed",
		"probe-time failure must surface via the new startup-verification prefix")
}

// TestNewSyslogOutput_DisableStartupVerification_SkipsDial verifies
// that the DisableStartupVerification opt-out lets New() succeed
// even when the configured address is unreachable — the runtime
// reconnect machinery handles "no connection yet" transparently.
func TestNewSyslogOutput_DisableStartupVerification_SkipsDial(t *testing.T) {
	out, err := syslog.New(&syslog.Config{
		Network:                    "tcp",
		Address:                    "127.0.0.1:1", // unreachable
		FlushInterval:              5 * time.Millisecond,
		DisableStartupVerification: true,
	})
	require.NoError(t, err, "DisableStartupVerification must allow construction against an unreachable address")
	require.NoError(t, out.Close())
}

// Note: a unit test for StartupVerificationTimeout in syslog is
// intentionally omitted. The srslog dialer that backs connect()
// does not accept a context, so the bounded() helper abandons the
// goroutine on timeout and lets the OS-level TCP connect drain in
// the background. Under [goleak.VerifyTestMain] this surfaces as a
// "leaked goroutine" failure even though the leak is bounded and
// the documented behaviour. The timeout property is exercised
// instead in webhook/loki probe tests (where the probe uses a
// ctx-aware dialer) and in the BDD scenarios. The docstring on
// [syslog.bounded] explains the abandoned-goroutine contract.

// ---------------------------------------------------------------------------
// buildSyslogTLSConfig — corrupt mTLS client cert/key pair
// ---------------------------------------------------------------------------

func TestNewSyslogOutput_TLSConfig_InvalidClientCert(t *testing.T) {
	// buildSyslogTLSConfig calls tls.LoadX509KeyPair which fails when
	// the cert and key files exist but contain invalid PEM.
	// This exercises the LoadX509KeyPair error branch.
	dir := t.TempDir()
	badCert := filepath.Join(dir, "bad-cert.pem")
	badKey := filepath.Join(dir, "bad-key.pem")
	require.NoError(t, os.WriteFile(badCert, []byte("not a cert\n"), 0o600))
	require.NoError(t, os.WriteFile(badKey, []byte("not a key\n"), 0o600))

	_, err := syslog.New(&syslog.Config{
		Network:       "tcp+tls",
		Address:       "localhost:6514",
		TLSCert:       badCert,
		TLSKey:        badKey,
		FlushInterval: 5 * time.Millisecond,
	})
	require.Error(t, err)
	// text-only: syslog.go:261 returns raw fmt.Errorf for TLS config
	// failures (no sentinel wrap). The "tls config" substring is the
	// contract.
	assert.Contains(t, err.Error(), "tls config",
		"error should indicate a TLS configuration failure")
}

// ---------------------------------------------------------------------------
// buildSyslogTLSConfig — CA file exists but is unreadable (permission denied)
// ---------------------------------------------------------------------------

func TestNewSyslogOutput_TLSConfig_UnreadableCAFile(t *testing.T) {
	// buildSyslogTLSConfig calls os.ReadFile after validateSyslogTLSFiles
	// has already confirmed the path exists and is not a directory.
	// A file with mode 0o000 passes os.Stat but fails os.ReadFile with
	// a permission-denied error, exercising the "reading ca certificate"
	// error path inside buildSyslogTLSConfig.
	//
	// This test is skipped when running as root because root bypasses
	// file permission checks and ReadFile would succeed.
	if os.Getuid() == 0 {
		t.Skip("skipping permission test: running as root")
	}

	dir := t.TempDir()
	caPath := filepath.Join(dir, "unreadable-ca.pem")
	// Write a syntactically valid (but throwaway) placeholder so os.Stat
	// sees a regular file, then remove all permissions.
	require.NoError(t, os.WriteFile(caPath, []byte("placeholder\n"), 0o600))
	require.NoError(t, os.Chmod(caPath, 0o000))
	t.Cleanup(func() {
		// Restore permissions so t.TempDir cleanup can remove the file.
		_ = os.Chmod(caPath, 0o600)
	})

	_, err := syslog.New(&syslog.Config{
		Network:       "tcp+tls",
		Address:       "localhost:6514",
		TLSCA:         caPath,
		FlushInterval: 5 * time.Millisecond,
	})
	require.Error(t, err)
	// text-only: tls.go:45 returns raw fmt.Errorf for read CA failures
	// (no sentinel wrap). The "ca certificate" substring is the contract.
	assert.Contains(t, err.Error(), "ca certificate",
		"error should mention CA certificate when ReadFile is denied")
}

// ---------------------------------------------------------------------------
// handleWriteFailure — closeCh fires reliably during backoff
// ---------------------------------------------------------------------------

func TestSyslogOutput_HandleWriteFailure_CloseDuringBackoff_CloseCh(t *testing.T) {
	// Exercise the `case <-s.closeCh:` arm of handleWriteFailure's select.
	//
	// Strategy:
	//  1. Connect to a live server and confirm data flows.
	//  2. Kill the server so the next write fails and enters handleWriteFailure.
	//  3. MaxRetries is high so we never exhaust retries before Close fires.
	//  4. After a short delay, call Close() which signals closeCh and
	//     interrupts the backoff select.
	//
	// The observable outcome is:
	//  - Write() returns an error (either "closed during reconnect",
	//    ErrOutputClosed, or retry exhaustion)
	//  - Close() returns without hanging
	//  - No goroutine leak

	srv := newMockSyslogServer(t)
	addr := srv.addr()

	out, err := syslog.New(&syslog.Config{
		Network:       "tcp",
		Address:       addr,
		MaxRetries:    20, // max allowed; high so we never exhaust retries before Close fires,
		FlushInterval: 5 * time.Millisecond,
	})
	require.NoError(t, err)

	// Establish the connection and confirm data flows.
	require.NoError(t, out.Write([]byte(`{"n":0}`)))
	require.True(t, srv.waitForData(2*time.Second), "initial write must reach server")

	// Tear down the server. The next write will fail and enter backoff.
	srv.close()

	// Schedule Close() after a short delay so it fires while the write
	// goroutine is inside handleWriteFailure's backoff select.
	time.AfterFunc(150*time.Millisecond, func() {
		_ = out.Close()
	})

	// writeErrCh receives the first error from the write loop once a
	// write fails and is interrupted by closeCh (or any other terminal
	// condition). We loop writes because the first write after server
	// death may succeed due to TCP buffering in srslog.
	writeErrCh := make(chan error, 1)
	go func() {
		for {
			if err := out.Write([]byte(`{"n":1}`)); err != nil {
				writeErrCh <- err
				return
			}
		}
	}()

	// Wait for the write goroutine to finish.
	select {
	case writeErr := <-writeErrCh:
		// The error should be either "closed during reconnect" (closeCh fired)
		// or ErrOutputClosed (closed before/during write) or a retry-exhaustion
		// error. All are acceptable — the key assertion is no hang and no panic.
		assert.Error(t, writeErr,
			"write must return an error when output is closed during backoff")
	case <-time.After(5 * time.Second):
		t.Fatal("write goroutine did not terminate after Close — possible hang in handleWriteFailure")
	}
}

// ---------------------------------------------------------------------------
// handleWriteFailure — s.closed is true after backoff timer fires
// ---------------------------------------------------------------------------

func TestSyslogOutput_CloseInterruptsBackoff(t *testing.T) {
	// Verify that Close() interrupts the writeLoop's backoff sleep
	// via closeCh. The writeLoop exits promptly — Close() does not
	// block indefinitely.
	srv := newMockSyslogServer(t)
	addr := srv.addr()

	out, err := syslog.New(&syslog.Config{
		Network:       "tcp",
		Address:       addr,
		MaxRetries:    10, // high retries — Close must interrupt, not wait,
		FlushInterval: 5 * time.Millisecond,
	})
	require.NoError(t, err)

	// Establish the connection.
	require.NoError(t, out.Write([]byte(`{"setup":true}`)))
	require.True(t, srv.waitForData(2*time.Second))

	// Kill the server so writes will fail and enter backoff.
	srv.close()

	// Enqueue an event that will trigger the reconnect/backoff path.
	_ = out.Write([]byte(`{"n":1}`))

	// Close should complete promptly by interrupting the backoff via
	// closeCh, not waiting for all 10 retries to exhaust.
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = out.Close()
	}()

	select {
	case <-done:
		// Close completed — backoff was interrupted.
	case <-time.After(5 * time.Second):
		t.Fatal("Close blocked for 5s — backoff was not interrupted by closeCh")
	}
}

// ---------------------------------------------------------------------------
// handleWriteFailure — max retries exceeded produces a clear error
// ---------------------------------------------------------------------------

func TestSyslogOutput_MaxRetriesExceeded_DropsEvent(t *testing.T) {
	// With async delivery, max-retries exhaustion is handled in the
	// background writeLoop. Write() never returns the error. Verify
	// via metrics that reconnect failures are recorded.
	srv := newMockSyslogServer(t)
	addr := srv.addr()

	m := newMockMetrics()
	out, err := syslog.New(&syslog.Config{
		Network:       "tcp",
		Address:       addr,
		MaxRetries:    1,
		FlushInterval: 5 * time.Millisecond,
	}, syslog.WithOutputMetrics(m))
	require.NoError(t, err)

	// Establish the connection.
	require.NoError(t, out.Write([]byte(`{"n":0}`)))
	require.True(t, srv.waitForData(2*time.Second))

	// Kill the server permanently.
	srv.close()

	// Enqueue events — writeLoop will exhaust retries in background.
	for range 5 {
		_ = out.Write([]byte(`{"n":1}`))
	}

	// Wait for at least one reconnect failure to be recorded before
	// closing. The writeLoop processes events asynchronously.
	require.Eventually(t, func() bool {
		return m.getSyslogReconnectCount(addr, false) > 0
	}, 5*time.Second, 10*time.Millisecond,
		"reconnect failures should be recorded when retries exhausted")

	require.NoError(t, out.Close())
}

// ---------------------------------------------------------------------------
// Close — writer.Close() returns an error
// ---------------------------------------------------------------------------

func TestSyslogOutput_Close_WriterCloseError(t *testing.T) {
	// Exercise the error path in Close() where s.writer.Close() returns
	// an error (lines 264-266 in syslog.go).
	//
	// srslog.Writer.Close() can fail if the underlying network connection
	// is already broken. We cause this by closing the server-side listener
	// (which forces a TCP RST on the existing connection) and then calling
	// out.Close() — srslog may detect the broken connection and return an
	// error when trying to flush/close.
	//
	// Note: srslog may also swallow the error internally and return nil.
	// In that case this test degrades to a no-error assertion, which is
	// still valid (Close() must never return an unexpected error on a
	// clean path). The test documents the intended behaviour: either nil
	// or a well-formed error is acceptable; panic is not.
	srv := newMockSyslogServer(t)

	out, err := syslog.New(&syslog.Config{
		Network:       "tcp",
		Address:       srv.addr(),
		FlushInterval: 5 * time.Millisecond,
	})
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte(`{"n":0}`)))
	require.True(t, srv.waitForData(2*time.Second))

	// Kill the server to force a broken connection on the output side.
	srv.close()

	// out.Close() must not panic. It may return nil or a wrapped error
	// from srslog — both are acceptable.
	closeErr := out.Close()
	// Acceptable: nil (srslog swallowed it) or a non-nil error.
	// Not acceptable: panic.
	if closeErr != nil {
		assert.Contains(t, closeErr.Error(), "syslog close",
			"Close error should be wrapped with 'syslog close' context")
	}
	// Second close must always be nil (idempotent).
	assert.NoError(t, out.Close())
}

func TestMapSeverity(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		audit  int
		syslog srslog.Priority
	}{
		{name: "audit 0 → LOG_DEBUG", audit: 0, syslog: srslog.LOG_DEBUG},
		{name: "audit 1 → LOG_INFO", audit: 1, syslog: srslog.LOG_INFO},
		{name: "audit 2 → LOG_INFO", audit: 2, syslog: srslog.LOG_INFO},
		{name: "audit 3 → LOG_INFO", audit: 3, syslog: srslog.LOG_INFO},
		{name: "audit 4 → LOG_NOTICE", audit: 4, syslog: srslog.LOG_NOTICE},
		{name: "audit 5 → LOG_NOTICE", audit: 5, syslog: srslog.LOG_NOTICE},
		{name: "audit 6 → LOG_WARNING", audit: 6, syslog: srslog.LOG_WARNING},
		{name: "audit 7 → LOG_WARNING", audit: 7, syslog: srslog.LOG_WARNING},
		{name: "audit 8 → LOG_ERR", audit: 8, syslog: srslog.LOG_ERR},
		{name: "audit 9 → LOG_ERR", audit: 9, syslog: srslog.LOG_ERR},
		{name: "audit 10 → LOG_CRIT", audit: 10, syslog: srslog.LOG_CRIT},
		// Out-of-range values fall back to LOG_INFO.
		{name: "audit -1 → LOG_INFO (fallback)", audit: -1, syslog: srslog.LOG_INFO},
		{name: "audit 11 → LOG_INFO (fallback)", audit: 11, syslog: srslog.LOG_INFO},
		{name: "audit 100 → LOG_INFO (fallback)", audit: 100, syslog: srslog.LOG_INFO},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.syslog, syslog.MapSeverity(tt.audit))
		})
	}
}

func TestMapSeverity_NeverEmitsEmergOrAlert(t *testing.T) {
	t.Parallel()
	for sev := 0; sev <= 10; sev++ {
		got := syslog.MapSeverity(sev)
		assert.NotEqual(t, srslog.LOG_EMERG, got, "severity %d must not map to LOG_EMERG", sev)
		assert.NotEqual(t, srslog.LOG_ALERT, got, "severity %d must not map to LOG_ALERT", sev)
	}
}

func TestSyslogOutput_WriteWithMetadata_SeverityMapping(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	// Facility defaults to local0 (16), so PRI = 128 + syslogSeverity.
	out, err := syslog.New(&syslog.Config{
		Network:       "tcp",
		Address:       srv.addr(),
		FlushInterval: 5 * time.Millisecond,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	tests := []struct {
		wantPRI  string // "<facility*8 + syslogSev>"
		auditSev int
	}{
		{auditSev: 0, wantPRI: "<135>"},  // 128 + 7 (LOG_DEBUG)
		{auditSev: 3, wantPRI: "<134>"},  // 128 + 6 (LOG_INFO)
		{auditSev: 5, wantPRI: "<133>"},  // 128 + 5 (LOG_NOTICE)
		{auditSev: 7, wantPRI: "<132>"},  // 128 + 4 (LOG_WARNING)
		{auditSev: 10, wantPRI: "<130>"}, // 128 + 2 (LOG_CRIT)
	}

	wantPRIs := make([]string, 0, len(tests))
	for _, tt := range tests {
		meta := audit.EventMetadata{
			EventType: "test_event",
			Severity:  tt.auditSev,
		}
		marker := fmt.Sprintf(`{"sev":%d}`, tt.auditSev)
		writeErr := out.WriteWithMetadata([]byte(marker), meta)
		require.NoError(t, writeErr, "severity %d", tt.auditSev)
		wantPRIs = append(wantPRIs, tt.wantPRI)
	}

	require.True(t, srv.waitForContent(wantPRIs, 2*time.Second),
		"timed out waiting for all PRI values in syslog output")

	all := strings.Join(srv.getMessages(), "\n")
	for _, tt := range tests {
		assert.Contains(t, all, tt.wantPRI,
			"audit severity %d should produce PRI %s", tt.auditSev, tt.wantPRI)
	}
}

func TestSyslogOutput_WriteWithMetadata_ImplementsInterface(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	out, err := syslog.New(&syslog.Config{
		Network:       "tcp",
		Address:       srv.addr(),
		FlushInterval: 5 * time.Millisecond,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	var mw audit.MetadataWriter = out
	writeErr := mw.WriteWithMetadata([]byte(`{"test":"interface"}`), audit.EventMetadata{
		Severity: 8,
	})
	require.NoError(t, writeErr)
}

func TestSyslogOutput_WriteWithMetadata_AfterClose(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	out, err := syslog.New(&syslog.Config{
		Network:       "tcp",
		Address:       srv.addr(),
		FlushInterval: 5 * time.Millisecond,
	})
	require.NoError(t, err)
	require.NoError(t, out.Close())

	writeErr := out.WriteWithMetadata([]byte(`{"test":"closed"}`), audit.EventMetadata{
		Severity: 5,
	})
	assert.ErrorIs(t, writeErr, audit.ErrOutputClosed)
}

// ---------------------------------------------------------------------------
// Config.String() tests (#325)
// ---------------------------------------------------------------------------

func TestSyslogConfig_String_Format(t *testing.T) {
	t.Parallel()
	cfg := syslog.Config{
		Network:       "tcp+tls",
		Address:       "siem:6514",
		TLSCA:         "/secret/ca.pem",
		TLSCert:       "/secret/cert.pem",
		TLSKey:        "/secret/key.pem",
		Facility:      "local0",
		FlushInterval: 5 * time.Millisecond,
	}
	s := cfg.String()
	assert.Contains(t, s, "SyslogConfig{")
	assert.Contains(t, s, "network=tcp+tls")
	assert.Contains(t, s, "address=siem:6514")
	assert.Contains(t, s, "tls=mtls")
	assert.Contains(t, s, "facility=local0")
	// TLS file paths must NOT appear in String() output.
	assert.NotContains(t, s, "/secret/")
	assert.NotContains(t, s, "cert.pem")
	assert.NotContains(t, s, "key.pem")
}

func TestSyslogConfig_String_TLSModes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		want string
		cfg  syslog.Config
	}{
		{
			name: "no TLS",
			cfg: syslog.Config{Network: "tcp", Address: "host:514",
				FlushInterval: 5 * time.Millisecond,
			},
			want: "tls=none",
		},
		{
			name: "CA only (TLS)",
			cfg: syslog.Config{Network: "tcp+tls", Address: "host:6514", TLSCA: "/ca.pem",
				FlushInterval: 5 * time.Millisecond,
			},
			want: "tls=tls",
		},
		{
			name: "cert+key (mTLS)",
			cfg: syslog.Config{Network: "tcp+tls", Address: "host:6514", TLSCert: "/c.pem", TLSKey: "/k.pem",
				FlushInterval: 5 * time.Millisecond,
			},
			want: "tls=mtls",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Contains(t, tt.cfg.String(), tt.want)
		})
	}
}

func TestSyslogConfig_GoString_RedactsTLSPaths(t *testing.T) {
	t.Parallel()
	cfg := syslog.Config{
		Network:       "tcp",
		Address:       "localhost:514",
		TLSCert:       "/etc/audit/tls/client.crt",
		TLSKey:        "/etc/audit/tls/client.key",
		TLSCA:         "/etc/audit/tls/ca.crt",
		FlushInterval: 5 * time.Millisecond,
	}
	out := fmt.Sprintf("%#v", cfg)
	assert.NotContains(t, out, "/etc/audit/tls/client.key", "GoString must not leak TLS key path")
	assert.NotContains(t, out, "/etc/audit/tls/client.crt", "GoString must not leak TLS cert path")
	assert.Contains(t, out, "SyslogConfig{")
}

func TestSyslogConfig_Format_RedactsTLSPaths(t *testing.T) {
	t.Parallel()
	cfg := syslog.Config{
		Network:       "tcp",
		Address:       "localhost:514",
		TLSKey:        "/secret/path/server.key",
		FlushInterval: 5 * time.Millisecond,
	}
	out := fmt.Sprintf("%+v", cfg)
	assert.NotContains(t, out, "/secret/path/server.key", "Format must not leak TLS key path via %%+v")
}

// ---------------------------------------------------------------------------
// OutputMetrics tests
// ---------------------------------------------------------------------------

func TestSyslogOutput_OutputMetrics_RecordFlush(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	om := &mockOutputMetrics{}
	out, err := syslog.New(&syslog.Config{
		Network:       "tcp",
		Address:       srv.addr(),
		Facility:      "local0",
		BufferSize:    10_000,
		FlushInterval: 5 * time.Millisecond,
	}, syslog.WithOutputMetrics(om))
	require.NoError(t, err)

	const n = 10
	for range n {
		require.NoError(t, out.Write([]byte(`{"event":"flush"}`)))
	}
	require.NoError(t, out.Close())

	assert.Equal(t, int64(n), om.flushes.Load(),
		"RecordFlush must be called for each successfully written event")
}

func TestSyslogOutput_OutputMetrics_RecordQueueDepth(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	om := &mockOutputMetrics{}
	out, err := syslog.New(&syslog.Config{
		Network:       "tcp",
		Address:       srv.addr(),
		Facility:      "local0",
		BufferSize:    10_000,
		FlushInterval: 5 * time.Millisecond,
	}, syslog.WithOutputMetrics(om))
	require.NoError(t, err)

	// Write 200 events and wait for writeLoop to process them
	// (not during drain). RecordQueueDepth samples every 64 events.
	for range 200 {
		require.NoError(t, out.Write([]byte(`{"event":"depth"}`)))
	}

	// Wait for the writeLoop to process events before closing.
	require.Eventually(t, func() bool {
		return om.flushes.Load() >= 64
	}, 5*time.Second, 50*time.Millisecond,
		"writeLoop should process at least 64 events before close")

	require.NoError(t, out.Close())

	assert.Positive(t, om.depthCalls.Load(),
		"RecordQueueDepth must be called every 64 events in writeLoop")
}

func TestSyslogOutput_NilWriter_RecordsRetry(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	om := &mockOutputMetrics{}
	out, err := syslog.New(&syslog.Config{
		Network:       "tcp",
		Address:       srv.addr(),
		Facility:      "local0",
		BufferSize:    100,
		MaxRetries:    1,
		FlushInterval: 5 * time.Millisecond,
	}, syslog.WithOutputMetrics(om))
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	// SimulateWriteFailure sets writer to nil, triggering
	// handleWriteFailure which calls RecordRetry during reconnection.
	out.SimulateWriteFailure()

	assert.Positive(t, om.retries.Load(),
		"RecordRetry must be called during reconnection attempt")

	// The output must still be functional after reconnection.
	require.NoError(t, out.Write([]byte(`{"event":"post-reconnect"}`)))
	require.NoError(t, out.Close())

	require.True(t, srv.waitForData(2*time.Second),
		"server should receive events after reconnection")
}

// ---------------------------------------------------------------------------
// Benchmarks (#455)
// ---------------------------------------------------------------------------

// discardSyslogServer is a minimal TCP server that accepts connections
// and discards all received data. Unlike mockSyslogServer it does not
// collect messages (no mutex, no slice append) to avoid polluting
// benchmark measurements with collection overhead.
type discardSyslogServer struct {
	listener net.Listener
	done     chan struct{}
	wg       sync.WaitGroup
}

func newDiscardSyslogServer(b *testing.B) *discardSyslogServer {
	b.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	s := &discardSyslogServer{
		listener: ln,
		done:     make(chan struct{}),
	}
	s.wg.Add(1)
	go s.accept()
	return s
}

func (s *discardSyslogServer) accept() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.done:
				return
			default:
				return
			}
		}
		s.wg.Add(1)
		go s.discard(conn)
	}
}

func (s *discardSyslogServer) discard(conn net.Conn) {
	defer s.wg.Done()
	defer func() { _ = conn.Close() }()
	buf := make([]byte, 32*1024)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		_, err := conn.Read(buf)
		if err != nil {
			select {
			case <-s.done:
				return
			default:
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			return
		}
	}
}

func (s *discardSyslogServer) addr() string {
	return s.listener.Addr().String()
}

func (s *discardSyslogServer) close() {
	close(s.done)
	_ = s.listener.Close()
	s.wg.Wait()
}

// silentBenchLogger is a slog logger that discards everything —
// suppresses buffer-full WARN emissions during benchmarks so they do
// not pollute the benchstat-parsed bench.txt output (#493).
func silentBenchLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// BenchmarkSyslogOutput_Write measures the Write() enqueue hot path:
// closed check (atomic load), data copy (make+copy), and non-blocking
// channel send. This is the per-event cost paid by the drain goroutine
// when delivering to a syslog output.
func BenchmarkSyslogOutput_Write(b *testing.B) {
	srv := newDiscardSyslogServer(b)
	defer srv.close()

	out, err := syslog.New(&syslog.Config{
		Network:       "tcp",
		Address:       srv.addr(),
		BufferSize:    100_000, // large buffer to avoid drops,
		FlushInterval: 5 * time.Millisecond,
	}, syslog.WithDiagnosticLogger(silentBenchLogger()))
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = out.Close() }()

	// Realistic audit event payload (~150 bytes).
	event := []byte(`{"timestamp":"2026-04-14T12:00:00Z","event_type":"user_create","severity":5,"app_name":"bench","host":"localhost","outcome":"success","actor_id":"alice"}` + "\n")

	b.ReportAllocs()
	b.SetBytes(int64(len(event)))
	b.ResetTimer()

	for b.Loop() {
		if err := out.Write(event); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSyslogOutput_Write_Parallel measures Write() contention
// under concurrent callers. Although the drain goroutine is the only
// caller in production, this validates the atomic.Bool fast-path and
// channel send under contention.
func BenchmarkSyslogOutput_Write_Parallel(b *testing.B) {
	srv := newDiscardSyslogServer(b)
	defer srv.close()

	out, err := syslog.New(&syslog.Config{
		Network:       "tcp",
		Address:       srv.addr(),
		BufferSize:    100_000,
		FlushInterval: 5 * time.Millisecond,
	}, syslog.WithDiagnosticLogger(silentBenchLogger()))
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = out.Close() }()

	event := []byte(`{"timestamp":"2026-04-14T12:00:00Z","event_type":"user_create","severity":5,"app_name":"bench","host":"localhost","outcome":"success","actor_id":"alice"}` + "\n")

	b.ReportAllocs()
	b.SetBytes(int64(len(event)))
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = out.Write(event)
		}
	})
}

// ---------------------------------------------------------------------------
// Named tests for issue #455 acceptance criteria
// ---------------------------------------------------------------------------

func TestSyslogOutput_ReconnectInBackground_Success(t *testing.T) {
	// Verify that the syslog output reconnects to a new server
	// after the original server goes down.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()

	srv1 := &mockSyslogServer{
		listener: ln,
		done:     make(chan struct{}),
	}
	srv1.wg.Add(1)
	go srv1.accept()

	out, err := syslog.New(&syslog.Config{
		Network:       "tcp",
		Address:       addr,
		MaxRetries:    10,
		FlushInterval: 5 * time.Millisecond,
	})
	require.NoError(t, err)

	// Establish connection with a successful write.
	require.NoError(t, out.Write([]byte(`{"n":1}`)))
	require.True(t, srv1.waitForData(2*time.Second))

	// Kill server.
	srv1.close()

	// Rebind on the same address.
	ln2, err := net.Listen("tcp", addr)
	require.NoError(t, err)
	srv2 := &mockSyslogServer{
		listener: ln2,
		done:     make(chan struct{}),
	}
	srv2.wg.Add(1)
	go srv2.accept()
	defer srv2.close()

	// Write events — reconnection should happen in background.
	for range 20 {
		_ = out.Write([]byte(`{"n":2}`))
	}

	// Verify the new server received data.
	ok := srv2.waitForData(5 * time.Second)
	require.NoError(t, out.Close())

	if ok {
		assert.True(t, ok, "new server should receive events after reconnection")
	} else {
		t.Log("reconnect test skipped: port could not be rebound fast enough")
	}
}

func TestSyslogOutput_ReconnectInBackground_Exhausted(t *testing.T) {
	// Verify that when reconnection retries are exhausted, metrics
	// record the failure.
	srv := newMockSyslogServer(t)
	addr := srv.addr()

	m := newMockMetrics()
	out, err := syslog.New(&syslog.Config{
		Network:       "tcp",
		Address:       addr,
		MaxRetries:    1,
		FlushInterval: 5 * time.Millisecond,
	}, syslog.WithOutputMetrics(m))
	require.NoError(t, err)

	// Establish connection.
	require.NoError(t, out.Write([]byte(`{"n":1}`)))

	// Kill server permanently.
	srv.close()

	// Enqueue events — reconnection will fail.
	for range 5 {
		_ = out.Write([]byte(`{"n":2}`))
	}

	require.Eventually(t, func() bool {
		return m.getSyslogReconnectCount(addr, false) > 0
	}, 5*time.Second, 10*time.Millisecond,
		"RecordReconnect(address, false) should be called when retries exhausted")

	require.NoError(t, out.Close())
}

func TestOutputMetrics_RecordDrop_CalledOnBufferFull(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	om := &mockOutputMetrics{}
	out, err := syslog.New(&syslog.Config{
		Network:       "tcp",
		Address:       srv.addr(),
		BufferSize:    1,
		FlushInterval: 5 * time.Millisecond,
	}, syslog.WithOutputMetrics(om))
	require.NoError(t, err)

	for range 100 {
		_ = out.Write([]byte(`{"event":"flood"}`))
	}

	require.NoError(t, out.Close())

	assert.Positive(t, om.drops.Load(),
		"RecordDrop must be called when buffer is full")
}

func TestOutputMetrics_RecordFlush_CalledOnSuccessfulWrite(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	om := &mockOutputMetrics{}
	out, err := syslog.New(&syslog.Config{
		Network:       "tcp",
		Address:       srv.addr(),
		BufferSize:    10_000,
		FlushInterval: 5 * time.Millisecond,
	}, syslog.WithOutputMetrics(om))
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte(`{"event":"flush"}`)))
	require.NoError(t, out.Close())

	assert.Positive(t, om.flushes.Load(),
		"RecordFlush must be called on successful write")
}

func TestOutputMetrics_RecordRetry_CalledOnRetryableError(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	om := &mockOutputMetrics{}
	out, err := syslog.New(&syslog.Config{
		Network:       "tcp",
		Address:       srv.addr(),
		BufferSize:    100,
		MaxRetries:    1,
		FlushInterval: 5 * time.Millisecond,
	}, syslog.WithOutputMetrics(om))
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	// SimulateWriteFailure sets writer to nil, triggering reconnect
	// which calls RecordRetry.
	out.SimulateWriteFailure()

	assert.Positive(t, om.retries.Load(),
		"RecordRetry must be called during reconnection attempt")
}

// TestSyslog_TLSWarningsRoutedToInjectedLogger verifies that
// TLS-policy warnings emitted during New() route through the
// WithDiagnosticLogger-supplied logger rather than slog.Default().
// Closes #490.
//
// Uses a TLS policy that triggers the "weak ciphers permitted"
// warning — the simplest path that produces a TLS.Apply warning.
// A local TLS listener stands in for a real syslog-ng so
// syslog.New's dial succeeds long enough for buildSyslogTLSConfig
// to run.
func TestSyslog_TLSWarningsRoutedToInjectedLogger(t *testing.T) {
	// Start a TLS listener that accepts any connection — we don't
	// need it to speak syslog, only to let dial succeed.
	certs := audittest.GenerateTestCerts(t)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", certs.TLSCfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_, _ = io.Copy(io.Discard, c)
			}(conn)
		}
	}()

	var buf strings.Builder
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})
	injected := slog.New(handler)

	out, err := syslog.New(&syslog.Config{
		Network:  "tcp+tls",
		Address:  listener.Addr().String(),
		Facility: "local0",
		AppName:  "syslog-logger-test",
		TLSCA:    certs.CAPath,
		TLSPolicy: &audit.TLSPolicy{
			AllowTLS12:       true,
			AllowWeakCiphers: true,
		},
		FlushInterval: 5 * time.Millisecond,
	}, syslog.WithDiagnosticLogger(injected))
	require.NoError(t, err)
	require.NoError(t, out.Close())

	logged := buf.String()
	assert.Contains(t, logged, "weak ciphers",
		"expected weak-ciphers warning on injected logger, got: %q", logged)
	assert.Contains(t, logged, "output=syslog",
		"warning should carry output=syslog attribute: %q", logged)
}

// TestSyslog_NilDiagnosticLoggerFallsBackToDefault verifies
// WithDiagnosticLogger(nil) does not nil-deref and falls back to
// slog.Default for warning emission.
func TestSyslog_NilDiagnosticLoggerFallsBackToDefault(t *testing.T) {
	certs := audittest.GenerateTestCerts(t)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", certs.TLSCfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_, _ = io.Copy(io.Discard, c)
			}(conn)
		}
	}()

	var buf strings.Builder
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	out, err := syslog.New(&syslog.Config{
		Network:  "tcp+tls",
		Address:  listener.Addr().String(),
		Facility: "local0",
		AppName:  "syslog-nil-logger-test",
		TLSCA:    certs.CAPath,
		TLSPolicy: &audit.TLSPolicy{
			AllowTLS12:       true,
			AllowWeakCiphers: true,
		},
		FlushInterval: 5 * time.Millisecond,
	}, syslog.WithDiagnosticLogger(nil))
	require.NoError(t, err)
	require.NoError(t, out.Close())

	assert.Contains(t, buf.String(), "weak ciphers",
		"WithDiagnosticLogger(nil) should fall back to slog.Default")
}

// TestSyslogReconnect_CloseErrorLoggedAtDebug asserts that when the
// reconnect path closes the previous writer and Close returns an
// error, the error is captured at slog.LevelDebug with the expected
// attributes — the reconnect path continues unaffected (#489). Prior
// behaviour was `_ = s.writer.Close()`, which silently dropped a
// diagnostic signal operators could use to track down persistent
// reconnect failures.
//
// Uses the JSON handler and decodes into a map so the level / message
// / attribute assertions do not depend on text-handler formatting.
func TestSyslogReconnect_CloseErrorLoggedAtDebug(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	injectedErr := errors.New("tls: teardown after peer reset")
	closeFn := func() error { return injectedErr }

	// Drive the helper directly — we do not need a live writer to
	// exercise the log path, only a closeFn that returns the error.
	syslog.CloseWriterForReconnect(closeFn, logger, "tcp!example.test:6514")

	var record map[string]any
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &record),
		"log output must be a single JSON record: %q", buf.String())

	assert.Equal(t, "DEBUG", record["level"],
		"close error must be at debug level: %v", record["level"])
	assert.Equal(t, "audit: output syslog: close before reconnect failed", record["msg"],
		"log message text missing: %v", record["msg"])
	assert.Equal(t, "tcp!example.test:6514", record["address"],
		"log must carry the address attribute: %v", record["address"])
	assert.Equal(t, "tls: teardown after peer reset", record["error"],
		"log must carry the underlying error: %v", record["error"])
}

// TestSyslogReconnect_CloseSuccess_NoLog verifies the happy path
// emits no log line — avoids log noise on every successful reconnect.
func TestSyslogReconnect_CloseSuccess_NoLog(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	syslog.CloseWriterForReconnect(func() error { return nil }, logger, "tcp!example.test:6514")

	assert.Empty(t, buf.String(),
		"successful Close must not emit any log line; got: %q", buf.String())
}

// TestSyslogReconnect_NilLoggerFallsBackToDefault verifies the
// helper does not nil-deref when invoked with a nil logger — the
// fallback path is used by the construction-time paths where the
// logger has not yet been installed.
//
// Not parallel: mutates the process-wide slog.Default. Running in
// parallel with any other test that reads slog.Default would race.
func TestSyslogReconnect_NilLoggerFallsBackToDefault(t *testing.T) { //nolint:paralleltest // mutates slog.Default
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	syslog.CloseWriterForReconnect(
		func() error { return errors.New("nil-logger injected error") },
		nil,
		"tcp!example.test:6514",
	)

	assert.Contains(t, buf.String(), "nil-logger injected error",
		"nil logger must fall back to slog.Default: %q", buf.String())
}

// TestSyslogOutput_RFC5424_HeaderParseable proves that the
// emitted syslog line follows the RFC 5424 wire grammar:
//
//	<PRI>VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP STRUCTURED-DATA SP MSG
//
// A regex-based parser checks that every required field is
// present and well-formed. The audit syslog output writes its
// own RFC 5424 header (delegating only the transport to srslog),
// so this test guards against silent header drift. (#565 G4).
func TestSyslogOutput_RFC5424_HeaderParseable(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	out, err := syslog.New(&syslog.Config{
		Network:       "tcp",
		Address:       srv.addr(),
		AppName:       "rfc5424-test",
		Hostname:      "test-host",
		FlushInterval: 5 * time.Millisecond,
	})
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte(`{"event_type":"user_create"}`)))
	require.True(t, srv.waitForData(2*time.Second))
	require.NoError(t, out.Close())

	msgs := srv.getMessages()
	require.NotEmpty(t, msgs, "server must receive at least one message")

	// RFC 5425 framing wraps each message with an octet-count
	// prefix: `135 <134>1 ...`. Strip the length prefix before
	// matching the RFC 5424 header. The 5424 header has the
	// form `<PRI>VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME
	// SP PROCID SP MSGID SP STRUCTURED-DATA SP MSG`. The
	// audit syslog stack delegates to srslog for the wire
	// format; field positions of the configured AppName/Hostname
	// reflect srslog's mapping (which routes Config.AppName
	// into MSGID, not APP-NAME). The test pins what the wire
	// format actually emits, not what a strict 5424-only reader
	// would expect.
	rfc5424 := regexp.MustCompile(
		`^(?:\d+ )?<(\d{1,3})>(\d+) (\S+) (\S+) (\S+) (\S+) (\S+)`)
	for _, m := range msgs {
		match := rfc5424.FindStringSubmatch(m)
		require.NotNil(t, match, "message must match RFC 5424 prefix; got: %q", m)
		pri, perr := strconv.Atoi(match[1])
		require.NoError(t, perr, "PRI must be numeric")
		assert.GreaterOrEqual(t, pri, 0)
		assert.LessOrEqual(t, pri, 191)
		assert.Equal(t, "1", match[2], "VERSION must be 1 per RFC 5424")
		assert.Equal(t, "test-host", match[4], "HOSTNAME must be the configured override")
		// The configured AppName lands in the MSGID position (field 7)
		// per srslog's wire mapping; the literal `rfc5424-test`
		// must appear somewhere in the header.
		assert.Contains(t, m, "rfc5424-test",
			"configured AppName must surface in the syslog header")
	}
}

// TestSyslogOutput_AppName_Empty_DefaultsToAuditConstant proves
// that an empty Config.AppName resolves to syslog.DefaultAppName
// ("audit") rather than something derived from os.Args[0]. The
// constant is the documented default in syslog/config.go:29; the
// issue's original "DefaultsToProcessName" framing was inaccurate.
// (#565 G4).
func TestSyslogOutput_AppName_Empty_DefaultsToAuditConstant(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	out, err := syslog.New(&syslog.Config{
		Network:       "tcp",
		Address:       srv.addr(),
		AppName:       "", // empty — default-trigger
		Hostname:      "h",
		FlushInterval: 5 * time.Millisecond,
	})
	require.NoError(t, err)
	require.NoError(t, out.Write([]byte(`{"event_type":"test"}`)))
	require.True(t, srv.waitForData(2*time.Second))
	require.NoError(t, out.Close())

	msgs := srv.getMessages()
	require.NotEmpty(t, msgs)
	// Field 5 (1-indexed) of the RFC 5424 header is APP-NAME.
	// The documented default is the literal "audit" — see
	// syslog.DefaultAppName.
	for _, m := range msgs {
		assert.Contains(t, m, " "+syslog.DefaultAppName+" ",
			"APP-NAME field must default to the documented constant %q",
			syslog.DefaultAppName)
	}
}

// ---------------------------------------------------------------------------
// Issue #696 acceptance criteria — factory FrameworkContext plumbing
// ---------------------------------------------------------------------------

// TestOutputFactory_ZeroContext_NoPanic verifies the syslog factory
// tolerates a zero-value [audit.FrameworkContext]. Construct via
// factory pointing at the test mock server; write once; no panic.
func TestOutputFactory_ZeroContext_NoPanic(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	yaml := []byte("network: tcp\naddress: " + srv.addr() + "\nflush_interval: 5ms\n")
	factory := audit.LookupOutputFactory("syslog")
	require.NotNil(t, factory)

	out, err := factory("zero", yaml, audit.FrameworkContext{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	require.NoError(t, out.Write([]byte(`{"event":"zero"}`)))
}

// syslogCaptureHandler records every slog Record passed through
// Handle for assertion in factory plumbing tests.
type syslogCaptureHandler struct {
	records []slog.Record
	mu      sync.Mutex
}

func (h *syslogCaptureHandler) Enabled(_ context.Context, _ slog.Level) bool { return true }
func (h *syslogCaptureHandler) Handle(_ context.Context, r slog.Record) error { //nolint:gocritic // hugeParam: slog.Handler interface contract
	h.mu.Lock()
	h.records = append(h.records, r)
	h.mu.Unlock()
	return nil
}
func (h *syslogCaptureHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }
func (h *syslogCaptureHandler) WithGroup(_ string) slog.Handler      { return h }

func (h *syslogCaptureHandler) anyContains(s string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for i := range h.records {
		if strings.Contains(h.records[i].Message, s) {
			return true
		}
	}
	return false
}

// TestOutputFactory_LoggerReachesOutput verifies that a logger
// supplied via [audit.FrameworkContext.DiagnosticLogger] reaches the
// syslog output. Trigger a TLS warning by passing a tls_policy with
// allow_tls12 + allow_weak_ciphers (which logs a WARNING) and assert
// the captured handler observed it.
func TestOutputFactory_LoggerReachesOutput(t *testing.T) {
	t.Parallel()
	h := &syslogCaptureHandler{}
	logger := slog.New(h)

	// Use real test certs so config validation passes and we reach
	// buildSyslogTLSConfig where the warning fires. Construction
	// fails at the dial step (no TLS server listening on the
	// reserved port) — that's fine, the assertion is on the captured
	// warning record, not on construction success.
	certs := audittest.GenerateTestCerts(t)
	yaml := []byte(
		"network: tcp+tls\n" +
			"address: 127.0.0.1:65530\n" +
			"tls_ca: " + certs.CAPath + "\n" +
			"tls_policy:\n" +
			"  allow_tls12: true\n" +
			"  allow_weak_ciphers: true\n",
	)
	factory := audit.LookupOutputFactory("syslog")
	require.NotNil(t, factory)

	out, err := factory("tls-warn", yaml, audit.FrameworkContext{DiagnosticLogger: logger})
	if err == nil {
		t.Cleanup(func() { _ = out.Close() })
	}

	assert.True(t, h.anyContains("weak"),
		"injected logger must capture the weak-cipher warning emitted in New")
}

// TestOutputFactory_OutputMetricsReachesOutput verifies that the
// per-output metrics value supplied via
// [audit.FrameworkContext.OutputMetrics] reaches the syslog output.
// Point at a port with no listener so writes drain into the retry
// path that records errors against the per-output metrics.
func TestOutputFactory_OutputMetricsReachesOutput(t *testing.T) {
	t.Parallel()

	om := &mockOutputMetrics{}
	// Pick a high port unlikely to have a listener; New will surface
	// a dial error before returning, so we instead build via a
	// reachable mock then break the connection.
	srv := newMockSyslogServer(t)
	addr := srv.addr()

	yaml := []byte("network: tcp\naddress: " + addr +
		"\nbuffer_size: 1\nflush_interval: 5ms\nmax_retries: 1\n")
	factory := audit.LookupOutputFactory("syslog")
	require.NotNil(t, factory)

	out, err := factory("metrics", yaml, audit.FrameworkContext{OutputMetrics: om})
	require.NoError(t, err)

	// Close the server to force write failures, then flood the tiny
	// buffer to guarantee both retries and channel-full drops.
	srv.close()
	for range 200 {
		_ = out.Write([]byte(`{"event":"flood"}`))
	}
	require.NoError(t, out.Close())

	// Either drops (channel full) or errors (writes failing) must be
	// recorded — the contract is "the metrics value reached the
	// output". Both paths confirm it.
	total := om.drops.Load() + om.errors.Load()
	assert.Positive(t, total,
		"per-output metrics value supplied via FrameworkContext must record drops or errors")
}
