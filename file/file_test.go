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

package file_test

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/axonops/audit"
	"github.com/axonops/audit/file"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

// mockOutputMetrics implements audit.OutputMetrics for testing.
// All fields use atomic counters — safe for concurrent use between
// the test goroutine and the output's writeLoop goroutine.
type mockOutputMetrics struct {
	audit.NoOpOutputMetrics
	drops      atomic.Int64
	flushes    atomic.Int64
	errors     atomic.Int64
	retries    atomic.Int64
	depthCalls atomic.Int64
}

func (m *mockOutputMetrics) RecordDrop() { m.drops.Add(1) }
func (m *mockOutputMetrics) RecordFlush(count int, _ time.Duration) {
	m.flushes.Add(int64(count))
}
func (m *mockOutputMetrics) RecordError()              { m.errors.Add(1) }
func (m *mockOutputMetrics) RecordRetry(_ int)         { m.retries.Add(1) }
func (m *mockOutputMetrics) RecordQueueDepth(_, _ int) { m.depthCalls.Add(1) }

var _ audit.OutputMetrics = (*mockOutputMetrics)(nil)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func TestFileOutput_Write(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	out, err := file.New(&file.Config{Path: path})
	require.NoError(t, err)

	data := []byte(`{"event_type":"test","outcome":"success"}` + "\n")
	require.NoError(t, out.Write(data))

	// Close flushes the async buffer and file writer.
	require.NoError(t, out.Close())

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, string(data), string(content))
}

func TestFileOutput_Write_NonBlocking(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	out, err := file.New(&file.Config{Path: path, BufferSize: 100})
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	// Write should return immediately — it enqueues to a channel.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 50 {
			_ = out.Write([]byte(`{"event":"test"}` + "\n"))
		}
	}()

	select {
	case <-done:
		// OK — writes completed without blocking.
	case <-time.After(5 * time.Second):
		t.Fatal("Write blocked for 5s — should be non-blocking")
	}
}

func TestFileOutput_BufferFull_Drops(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	om := &mockOutputMetrics{}
	// Tiny buffer to trigger drops.
	out, err := file.New(&file.Config{Path: path, BufferSize: 1}, file.WithOutputMetrics(om))
	require.NoError(t, err)

	// Flood the buffer. Some writes will succeed, some will be dropped.
	const writes = 200
	for range writes {
		_ = out.Write([]byte(`{"event":"flood"}` + "\n"))
	}

	require.NoError(t, out.Close())

	assert.Positive(t, om.drops.Load(),
		"RecordDrop must be called when the buffer is full")
	assert.LessOrEqual(t, om.flushes.Load()+om.drops.Load(), int64(writes),
		"flushes plus drops must not exceed total writes")
}

func TestFileOutput_Close_DrainsBuffer(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	out, err := file.New(&file.Config{Path: path, BufferSize: 1000})
	require.NoError(t, err)

	const n = 50
	for range n {
		require.NoError(t, out.Write([]byte(`{"event":"drain"}`+"\n")))
	}

	// Close must drain all buffered events before returning.
	require.NoError(t, out.Close())

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	assert.Equal(t, n, len(lines), "Close must drain all buffered events")
}

func TestFileOutput_Close(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	out, err := file.New(&file.Config{Path: path})
	require.NoError(t, err)
	assert.NoError(t, out.Close())
}

func TestFileOutput_CloseIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	out, err := file.New(&file.Config{Path: path})
	require.NoError(t, err)
	assert.NoError(t, out.Close())
	assert.NoError(t, out.Close())
}

func TestFileOutput_WriteAfterClose(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	out, err := file.New(&file.Config{Path: path})
	require.NoError(t, err)
	require.NoError(t, out.Close())

	err = out.Write([]byte("data\n"))
	assert.ErrorIs(t, err, audit.ErrOutputClosed)
}

func TestFileOutput_Name(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	out, err := file.New(&file.Config{Path: path})
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	// Normalise the expected path because the file output resolves
	// symlinks (e.g. /var → /private/var on macOS) and short-name
	// aliases (e.g. C:\Users\RUNNER~1 → C:\Users\runneradmin on
	// Windows) when computing the canonical Name. The directory
	// itself may exist before the file does, so resolve dir +
	// rejoin rather than EvalSymlinks on the full path.
	resolvedDir, err := filepath.EvalSymlinks(dir)
	require.NoError(t, err)
	expected := "file:" + filepath.Join(resolvedDir, "audit.log")
	assert.Equal(t, expected, out.Name())
}

func TestFileOutput_DefaultPermissions_0600(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not honoured on Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	out, err := file.New(&file.Config{Path: path})
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte("test\n")))
	// Close to flush async buffer to disk.
	require.NoError(t, out.Close())

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestFileOutput_GroupReadable_True_0640(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not honoured on Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	out, err := file.New(&file.Config{
		Path:          path,
		GroupReadable: true,
	})
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte("test\n")))
	require.NoError(t, out.Close())

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o640), info.Mode().Perm())
}

func TestFileOutput_DefaultConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	// All zero-value fields should get sensible defaults.
	out, err := file.New(&file.Config{Path: path})
	require.NoError(t, err)

	// Verify the output is functional.
	require.NoError(t, out.Write([]byte("test\n")))
	require.NoError(t, out.Close())

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "test\n", string(content))
}

func TestFileOutput_InvalidConfig(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name    string
		wantErr string
		cfg     file.Config
	}{
		{
			name:    "empty path",
			cfg:     file.Config{Path: ""},
			wantErr: "must not be empty",
		},
		{
			name:    "missing parent directory",
			cfg:     file.Config{Path: "/nonexistent/dir/audit.log"},
			wantErr: "parent directory",
		},
		{
			name: "MaxSizeMB exceeds limit",
			cfg: file.Config{
				Path:      filepath.Join(dir, "big.log"),
				MaxSizeMB: file.MaxSizeMB + 1,
			},
			wantErr: "max_size_mb",
		},
		{
			name: "MaxBackups exceeds limit",
			cfg: file.Config{
				Path:       filepath.Join(dir, "backups.log"),
				MaxBackups: file.MaxBackups + 1,
			},
			wantErr: "max_backups",
		},
		{
			name: "MaxAgeDays exceeds limit",
			cfg: file.Config{
				Path:       filepath.Join(dir, "age.log"),
				MaxAgeDays: file.MaxAgeDays + 1,
			},
			wantErr: "max_age_days",
		},
		{
			name: "BufferSize exceeds limit",
			cfg: file.Config{
				Path:       filepath.Join(dir, "buf.log"),
				BufferSize: file.MaxOutputBufferSize + 1,
			},
			wantErr: "buffer_size",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := file.New(&tt.cfg)
			require.Error(t, err)
			// text-only: mixed table — empty path, parent, permissions cases use bare fmt.Errorf in file.go;
			// only max_*/buffer_size cases wrap audit.ErrConfigInvalid (file.go:567+).
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestFileOutput_NegativeMaxSizeMB_DefaultsTo100(t *testing.T) {
	dir := t.TempDir()
	out, err := file.New(&file.Config{
		Path:      filepath.Join(dir, "neg.log"),
		MaxSizeMB: -1,
	})
	require.NoError(t, err, "negative MaxSizeMB should default, not error")
	_ = out.Close()
}

// TestFileOutput_ExistingFile_BroaderPerms covers ACs 7-11 of #436:
// the on-disk permissions of an existing audit log are validated
// against the configured target mode at construction time.
//
//	target = 0o600 (GroupReadable=false)
//	  existing 0o600 → accept (#8)
//	  existing 0o640 → reject (group-read not expected, #11)
//	  existing 0o644 → reject (broader than required, #7)
//
//	target = 0o640 (GroupReadable=true)
//	  existing 0o600 → accept (narrower than required is safe, #9)
//	  existing 0o640 → accept (#10)
//	  existing 0o644 → reject (other-read broader)
func TestFileOutput_ExistingFile_BroaderPerms(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not honoured on Windows")
	}
	cases := []struct {
		name          string
		existingPerm  os.FileMode
		groupReadable bool
		wantErr       bool
	}{
		{"target_0600_existing_0600", 0o600, false, false},
		{"target_0600_existing_0640_rejected", 0o640, false, true},
		{"target_0600_existing_0644_rejected", 0o644, false, true},
		{"target_0640_existing_0600", 0o600, true, false},
		{"target_0640_existing_0640", 0o640, true, false},
		{"target_0640_existing_0644_rejected", 0o644, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "audit.log")
			require.NoError(t, os.WriteFile(path, []byte("pre-existing\n"), tc.existingPerm))
			require.NoError(t, os.Chmod(path, tc.existingPerm)) // some umasks override WriteFile mode

			out, err := file.New(&file.Config{Path: path, GroupReadable: tc.groupReadable})
			if tc.wantErr {
				require.Error(t, err, "expected rejection for %v on target %v",
					tc.existingPerm, tc.groupReadable)
				assert.ErrorIs(t, err, audit.ErrConfigInvalid,
					"existing-perms rejection must wrap audit.ErrConfigInvalid")
				assert.Contains(t, err.Error(), "broader than required",
					"error message must explain the rejection cause")
			} else {
				require.NoError(t, err, "expected acceptance for %v on target %v",
					tc.existingPerm, tc.groupReadable)
				_ = out.Close()
			}
		})
	}
}

func TestFileOutput_MaxBoundaryValues_Accepted(t *testing.T) {
	dir := t.TempDir()
	out, err := file.New(&file.Config{
		Path:       filepath.Join(dir, "boundary.log"),
		MaxSizeMB:  file.MaxSizeMB,
		MaxBackups: file.MaxBackups,
		MaxAgeDays: file.MaxAgeDays,
		BufferSize: file.MaxOutputBufferSize,
	})
	require.NoError(t, err)
	require.NoError(t, out.Close())
}

func TestFileOutput_MaxExceeded_WrapsErrConfigInvalid(t *testing.T) {
	dir := t.TempDir()
	_, err := file.New(&file.Config{
		Path:      filepath.Join(dir, "test.log"),
		MaxSizeMB: file.MaxSizeMB + 1,
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrConfigInvalid)
}

func TestFileOutput_ImplementsOutput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	out, err := file.New(&file.Config{Path: path})
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	var _ audit.Output = out
}

func TestFileOutput_ImplementsDeliveryReporter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	out, err := file.New(&file.Config{Path: path})
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	// Type assertion through audit.Output interface.
	var o audit.Output = out
	dr, ok := o.(audit.DeliveryReporter)
	require.True(t, ok, "file output must implement DeliveryReporter")
	assert.True(t, dr.ReportsDelivery(), "file output must self-report delivery")
}

// TestFileOutput_ImplementsOutputMetricsReceiver was removed in #696
// along with the OutputMetricsReceiver interface. Per-output metrics
// are now plumbed in at construction via [file.WithOutputMetrics].

func TestFileOutput_MultipleWrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	out, err := file.New(&file.Config{Path: path})
	require.NoError(t, err)

	for i := range 10 {
		data := []byte(fmt.Sprintf(`{"n":%d}`+"\n", i))
		require.NoError(t, out.Write(data))
	}

	require.NoError(t, out.Close())

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	assert.Len(t, lines, 10)
}

func TestFileOutput_ConcurrentWriteClose(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	out, err := file.New(&file.Config{Path: path})
	require.NoError(t, err)

	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := range goroutines {
		go func(n int) {
			defer wg.Done()
			data := []byte(fmt.Sprintf(`{"n":%d}`+"\n", n))
			// Errors are expected after Close; just exercise the race detector.
			_ = out.Write(data)
		}(i)
	}

	// Close while writes are in-flight.
	assert.NoError(t, out.Close())
	wg.Wait()
}

func TestFileOutput_WriteDuringClose_NoPanic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	out, err := file.New(&file.Config{Path: path, BufferSize: 10})
	require.NoError(t, err)

	// Write events in goroutines while Close() is called concurrently.
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for range 100 {
			_ = out.Write([]byte(`{"event":"race"}` + "\n"))
		}
	}()

	go func() {
		defer wg.Done()
		_ = out.Close()
	}()

	wg.Wait()
	// Success if no panic or deadlock.
}

func TestFileOutput_CopySafety(t *testing.T) {
	// Verify that mutating the input []byte after Write() does not
	// corrupt the buffered data (formatCache reuse invariant).
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	out, err := file.New(&file.Config{Path: path})
	require.NoError(t, err)

	data := []byte(`{"event":"original"}` + "\n")
	require.NoError(t, out.Write(data))

	// Mutate the original slice after Write returns.
	for i := range data {
		data[i] = 'X'
	}

	require.NoError(t, out.Close())

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Contains(t, string(content), "original",
		"mutating input after Write must not corrupt buffered data")
}

func TestFileOutput_CompressFalse(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	compress := false
	out, err := file.New(&file.Config{
		Path:     path,
		Compress: &compress,
	})
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte("test\n")))
	require.NoError(t, out.Close())
}

// ---------------------------------------------------------------------------
// Metrics (#54)
// ---------------------------------------------------------------------------

// fileOnlyMetrics implements audit.OutputMetrics (via NoOp embed)
// plus file.RotationRecorder so the file output's WithOutputMetrics
// constructor wires both contracts via structural typing.
//
// rotated is an optional buffered channel that receives every
// rotated path. It enables tests to wait for rotation events
// deterministically rather than poll. Leave nil to disable.
type fileOnlyMetrics struct {
	audit.NoOpOutputMetrics
	rotated   chan string
	rotations []string // paths passed to RecordRotation
	mu        sync.Mutex
}

func (m *fileOnlyMetrics) RecordRotation(path string) {
	m.mu.Lock()
	m.rotations = append(m.rotations, path)
	m.mu.Unlock()
	if m.rotated != nil {
		select {
		case m.rotated <- path:
		default: // never block production
		}
	}
}

var (
	_ audit.OutputMetrics   = (*fileOnlyMetrics)(nil)
	_ file.RotationRecorder = (*fileOnlyMetrics)(nil)
)

func (m *fileOnlyMetrics) rotationCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.rotations)
}

func TestFileOutput_NilFileMetrics_RotationDoesNotPanic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	out, err := file.New(&file.Config{Path: path})
	require.NoError(t, err)

	for range 5 {
		require.NoError(t, out.Write([]byte(`{"event":"nil_metrics"}`+"\n")))
	}
	require.NoError(t, out.Close())
}

func TestFileOutput_FileMetrics_RecordRotation_CalledOnRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	m := &fileOnlyMetrics{}

	// MaxSizeMB=1 forces rotation after 1 MB of data.
	out, err := file.New(&file.Config{
		Path:      path,
		MaxSizeMB: 1,
	}, file.WithOutputMetrics(m))
	require.NoError(t, err)

	// Write 1 MB + 1 byte to cross the rotation threshold.
	payload := make([]byte, 1024*1024+1)
	for i := range payload {
		payload[i] = 'x'
	}
	require.NoError(t, out.Write(payload))
	// Close drains async buffer — rotation happens in background goroutine.
	require.NoError(t, out.Close())

	assert.Equal(t, 1, m.rotationCount(),
		"RecordRotation should be called once after crossing MaxSizeMB")

	m.mu.Lock()
	rotations := make([]string, len(m.rotations))
	copy(rotations, m.rotations)
	m.mu.Unlock()

	if assert.NotEmpty(t, rotations, "RecordRotation must have been called") {
		// Path comparison must account for the canonical-path
		// resolution the file output performs internally (see
		// TestFileOutput_Name for the macOS / Windows symlink
		// rationale).
		resolvedDir, evalErr := filepath.EvalSymlinks(dir)
		require.NoError(t, evalErr)
		expectedPath := filepath.Join(resolvedDir, "audit.log")
		assert.Equal(t, expectedPath, rotations[0],
			"RecordRotation should receive the active file path")
	}
}

func TestFileOutput_FileMetrics_MultipleRotations(t *testing.T) {
	// #760 fix: previously skipped because asserting "3 writes ⇒ 3
	// rotations" was timing-sensitive. The writeLoop coalesces
	// rapid writes into a single batched Writev which only
	// rotates once for an oversized batch (a real production
	// property worth pinning). The test now sequences each
	// write/rotate pair via the RotationRecorder channel so each
	// write is a separate batch, and asserts the per-write
	// rotation contract.
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	m := &fileOnlyMetrics{rotated: make(chan string, 4)}

	out, err := file.New(&file.Config{
		Path:       path,
		MaxSizeMB:  1,
		MaxBackups: 10,
	}, file.WithOutputMetrics(m))
	require.NoError(t, err)

	payload := make([]byte, 1024*1024+1)
	for i := range payload {
		payload[i] = byte('a' + (i % 26))
	}

	const rotations = 3
	resolvedDir, evalErr := filepath.EvalSymlinks(dir)
	require.NoError(t, evalErr)
	expectedPath := filepath.Join(resolvedDir, "audit.log")

	for i := range rotations {
		require.NoError(t, out.Write(payload))
		select {
		case got := <-m.rotated:
			assert.Equal(t, expectedPath, got,
				"RecordRotation should receive the active file path on rotation %d", i+1)
		case <-time.After(5 * time.Second):
			t.Fatalf("rotation %d/%d never recorded — possible writeLoop or rotation regression",
				i+1, rotations)
		}
	}
	require.NoError(t, out.Close())

	assert.Equal(t, rotations, m.rotationCount(),
		"exactly %d rotations should fire when each write is sequenced", rotations)
}

// TestFileOutput_RapidWrites_RotatesAtLeastOnce is the companion to
// TestFileOutput_FileMetrics_MultipleRotations. Whereas that test
// sequences each write and asserts one rotation per write, this one
// issues rapid writes back-to-back and asserts the writeLoop's
// coalescing behaviour does NOT silently drop rotations: when the
// total bytes written exceed MaxSize, at least one rotation must
// fire regardless of how aggressively the batches coalesce. Pins
// the durability contract called out in the MultipleRotations
// rewrite comment (#760 fix follow-up).
func TestFileOutput_RapidWrites_RotatesAtLeastOnce(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	m := &fileOnlyMetrics{}
	out, err := file.New(&file.Config{
		Path:       path,
		MaxSizeMB:  1,
		MaxBackups: 10,
	}, file.WithOutputMetrics(m))
	require.NoError(t, err)

	payload := make([]byte, 1024*1024+1)
	for i := range payload {
		payload[i] = 'x'
	}
	// 5 rapid writes — total ~5 MB, well above MaxSize=1 MB. Whether
	// these coalesce into one batch or several, rotation MUST fire
	// at least once because the active file would otherwise grow
	// without bound.
	for range 5 {
		require.NoError(t, out.Write(payload))
	}
	require.NoError(t, out.Close())

	assert.GreaterOrEqual(t, m.rotationCount(), 1,
		"rapid writes exceeding MaxSize must trigger at least one rotation regardless of batching")
}

func TestFileOutput_RotationRecorder_InterfaceAssertion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	m := &fileOnlyMetrics{}
	// Per #581/#696: RotationRecorder is detected via type assertion
	// inside [file.New] when the OutputMetrics implementation also
	// satisfies RotationRecorder. Pass the concrete *fileOnlyMetrics
	// so the same mock exercises both interfaces.
	out, err := file.New(&file.Config{Path: path}, file.WithOutputMetrics(m))
	require.NoError(t, err)
	require.NoError(t, out.Close())
}

// TestFileOutput_SetOutputMetrics_ReplaceClearsRotationRecorder was
// removed in #696 along with the post-construction SetOutputMetrics
// API. Output metrics are now wired once at construction via
// [file.WithOutputMetrics]; runtime swap is not supported.

func TestFileOutput_SymlinkRejected(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.log")
	link := filepath.Join(dir, "symlink.log")

	// Create a real file, then a symlink pointing to it.
	require.NoError(t, os.WriteFile(target, nil, 0o600))
	require.NoError(t, os.Symlink(target, link))

	// Construction succeeds — symlink check happens on first write
	// in the background goroutine.
	out, err := file.New(&file.Config{Path: link})
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte("test\n")))
	// Close drains the buffer. The symlink error is logged by the
	// diagnostic logger but is not returned to Write's caller (async
	// delivery path). Close itself must still succeed — the writer's
	// Close handles the already-rejected state cleanly.
	require.NoError(t, out.Close())

	// Behavioural assertion: if safeOpen correctly rejected the symlink,
	// the target file remains empty. If the library had followed the
	// symlink, the target would contain "test\n".
	info, statErr := os.Stat(target)
	require.NoError(t, statErr)
	require.Equal(t, int64(0), info.Size(),
		"symlink target should be empty — library must reject symlink writes")
}

func TestFileOutput_DestinationKey_EquivalentPaths(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name string
		path string
	}{
		{name: "absolute", path: filepath.Join(dir, "audit.log")},
		{name: "relative_dot", path: filepath.Join(dir, ".", "audit.log")},
		{name: "relative_dotdot", path: filepath.Join(dir, "sub", "..", "audit.log")},
	}

	// All paths should produce the same DestinationKey.
	var keys []string
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := file.New(&file.Config{Path: tt.path})
			require.NoError(t, err)
			t.Cleanup(func() { _ = out.Close() })

			key := out.DestinationKey()
			assert.NotEmpty(t, key)
			keys = append(keys, key)
		})
	}

	// All keys must be equal.
	for i := 1; i < len(keys); i++ {
		assert.Equal(t, keys[0], keys[i],
			"paths %q and %q should produce the same key", tests[0].path, tests[i].path)
	}
}

// ---------------------------------------------------------------------------
// OutputMetrics tests
// ---------------------------------------------------------------------------

func TestFileOutput_OutputMetrics_RecordFlush(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	om := &mockOutputMetrics{}
	out, err := file.New(&file.Config{Path: path, BufferSize: 10_000}, file.WithOutputMetrics(om))
	require.NoError(t, err)

	const n = 10
	for range n {
		require.NoError(t, out.Write([]byte(`{"event":"flush"}`+"\n")))
	}
	require.NoError(t, out.Close())

	assert.Equal(t, int64(n), om.flushes.Load(),
		"RecordFlush must be called for each successfully written event")
}

func TestFileOutput_OutputMetrics_RecordQueueDepth(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	om := &mockOutputMetrics{}
	out, err := file.New(&file.Config{Path: path, BufferSize: 10_000}, file.WithOutputMetrics(om))
	require.NoError(t, err)

	// 65 events guarantees writeCount hits 64 at least once.
	for range 65 {
		require.NoError(t, out.Write([]byte(`{"event":"depth"}`+"\n")))
	}
	require.NoError(t, out.Close())

	assert.Positive(t, om.depthCalls.Load(),
		"RecordQueueDepth must be called every 64 events in writeLoop")
}

func TestFileOutput_PanicRecovery_RecordsError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	om := &mockOutputMetrics{}
	out, err := file.New(&file.Config{Path: path, BufferSize: 100}, file.WithOutputMetrics(om))
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	// Simulate a panic inside writeEvent — the deferred recovery
	// catches it. Called synchronously, not through the channel.
	out.SimulatePanicOnNextWrite()

	assert.Equal(t, int64(1), om.errors.Load(),
		"RecordError must be called when writeEvent panics")

	// The output must still be functional after recovery.
	require.NoError(t, out.Write([]byte(`{"event":"post-panic"}`+"\n")))
	require.NoError(t, out.Close())

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Contains(t, string(content), "post-panic",
		"output must remain functional after panic recovery")
}

// ---------------------------------------------------------------------------
// Named tests for issue #455 acceptance criteria
// ---------------------------------------------------------------------------

func TestFileOutput_RotationInBackgroundGoroutine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	out, err := file.New(&file.Config{
		Path:       path,
		MaxSizeMB:  1,
		MaxBackups: 3,
	})
	require.NoError(t, err)

	// Write >1 MB to trigger rotation in the background writeLoop.
	payload := make([]byte, 1024*1024+1)
	for i := range payload {
		payload[i] = 'x'
	}
	require.NoError(t, out.Write(payload))

	// Close drains the async buffer — rotation happens in writeLoop.
	require.NoError(t, out.Close())

	// Verify backup file exists (rotation happened).
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)

	var backupCount int
	for _, e := range entries {
		if e.Name() != "audit.log" && strings.Contains(e.Name(), "audit") {
			backupCount++
		}
	}
	assert.Positive(t, backupCount,
		"rotation should produce at least one backup file")
}

func TestOutputMetrics_RecordError_CalledOnNonRetryableError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	om := &mockOutputMetrics{}
	out, err := file.New(&file.Config{Path: path, BufferSize: 100}, file.WithOutputMetrics(om))
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	// SimulatePanicOnNextWrite triggers a nil-pointer panic inside
	// writeEvent — the deferred recovery catches it and calls RecordError.
	out.SimulatePanicOnNextWrite()

	assert.Equal(t, int64(1), om.errors.Load(),
		"RecordError must be called on non-retryable error (panic recovery)")
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

// silentLogger is a slog logger that discards everything — suppresses
// buffer-full WARN emissions during benchmarks so they do not pollute
// the benchstat-parsed bench.txt output (#493).
func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func BenchmarkFileOutput_Write(b *testing.B) {
	dir := b.TempDir()
	path := filepath.Join(dir, "bench.log")

	out, err := file.New(&file.Config{Path: path, MaxSizeMB: 1024}, file.WithDiagnosticLogger(silentLogger()))
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = out.Close() }()

	event := []byte(`{"timestamp":"2026-04-14T12:00:00Z","event_type":"user_create","severity":5,"app_name":"bench","host":"localhost","outcome":"success","actor_id":"alice"}` + "\n")

	b.ResetTimer()
	b.SetBytes(int64(len(event)))
	for b.Loop() {
		if err := out.Write(event); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFileOutput_Write_Parallel(b *testing.B) {
	dir := b.TempDir()
	path := filepath.Join(dir, "bench.log")

	out, err := file.New(&file.Config{Path: path, MaxSizeMB: 1024, BufferSize: 10000}, file.WithDiagnosticLogger(silentLogger()))
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = out.Close() }()

	event := []byte(`{"timestamp":"2026-04-14T12:00:00Z","event_type":"user_create","severity":5,"app_name":"bench","host":"localhost","outcome":"success","actor_id":"alice"}` + "\n")

	b.ResetTimer()
	b.SetBytes(int64(len(event)))
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = out.Write(event)
		}
	})
}

// BenchmarkFileOutput_Write_WithRotation satisfies #504 AC #1
// (master tracker C-18) at the public file.Output API surface. The
// public file.Config.MaxSizeMB is integer megabytes (minimum 1), so
// at the 161 B event size rotation fires only every ~6500 writes —
// too coarse for per-rotation signal measurement. The fine-grained
// rotation-cost baseline lives in
// file/internal/rotate/writer_test.go::BenchmarkWriter_Write_WithRotation
// where MaxSize is byte-granular. This benchmark documents the
// public-API path under *some* rotation activity so regressions in
// the file.Output → rotate.Writer → Write → flush chain that only
// surface after a rotate have a baseline to regress against.
//
// The delta vs BenchmarkFileOutput_Write is dominated by the
// channel-send + bufio + diagnostic-logger path, not rotation
// (rotation contributes ~0.015 % of iterations). A regression in
// either path shows here; use BenchmarkWriter_Write_WithRotation to
// isolate rotation-specific regressions.
func BenchmarkFileOutput_Write_WithRotation(b *testing.B) {
	dir := b.TempDir()
	path := filepath.Join(dir, "bench.log")

	compressOff := false
	out, err := file.New(&file.Config{
		Path:       path,
		MaxSizeMB:  1, // public-API minimum; see godoc above
		MaxBackups: 2, // exercise the prune path without dir bloat
		Compress:   &compressOff,
	}, file.WithDiagnosticLogger(silentLogger()))
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = out.Close() }()

	event := []byte(`{"timestamp":"2026-04-14T12:00:00Z","event_type":"user_create","severity":5,"app_name":"bench","host":"localhost","outcome":"success","actor_id":"alice"}` + "\n")

	b.ReportAllocs()
	b.ResetTimer()
	b.SetBytes(int64(len(event)))
	for b.Loop() {
		if err := out.Write(event); err != nil {
			b.Fatal(err)
		}
	}
}

// TestFile_ConstructionWarningsRoutedToInjectedLogger verifies that
// (Construction-time permission warnings were removed in #436 along
// with the flexible Permissions string field; the only configurable
// modes are now 0o600 and 0o640, neither of which warrants a
// runtime warning. The injected-vs-default-logger contract for the
// WithDiagnosticLogger option remains exercised by the writeLoop's
// async-error path elsewhere in this file.)

// TestNew_NilConfig_ReturnsError verifies that [New] returns a
// non-nil error when passed a nil *Config (#580). The nil guard
// prevents a nil-pointer dereference in subsequent validation.
func TestNew_NilConfig_ReturnsError(t *testing.T) {
	t.Parallel()
	_, err := file.New(nil)
	require.Error(t, err)
	// text-only: file.go:212 returns raw fmt.Errorf without a sentinel wrap.
	assert.Contains(t, err.Error(), "config must not be nil")
}

// TestFileOutput_WriteToReadOnlyDirectory pins the contract that
// a file output configured to write into a read-only directory
// surfaces a permission error. Because the audit file output
// opens its log file lazily inside the writeLoop goroutine, the
// caller observes the failure via OutputMetrics.RecordError —
// not via the synchronous Write/Close return. The test sets up
// a fileOnlyMetrics with a RecordError counter and asserts at
// least one error was recorded.
//
// (#565 G3).
func TestFileOutput_WriteToReadOnlyDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod 0o555 to make a directory read-only is a no-op on Windows")
	}
	if os.Getuid() == 0 {
		t.Skip("running as root — chmod 0o555 is bypassed; cannot drive permission-denied")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	m := &errorCountingMetrics{}
	// Make the parent directory read-only AFTER constructing the
	// audit output but BEFORE the first write. New() only os.Stats
	// the parent (rotate/writer.go:resolveAndValidatePath); the
	// actual OpenFile happens inside the writeLoop on first write,
	// where chmod 0o555 forces EACCES.
	out, err := file.New(&file.Config{Path: path}, file.WithOutputMetrics(m))
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = os.Chmod(dir, 0o755)
	})
	require.NoError(t, os.Chmod(dir, 0o555))

	// Write should not block; the lazy file open inside the
	// writeLoop fails with EACCES and surfaces as an error metric.
	require.NoError(t, out.Write([]byte(`{"event":"perm_test"}`+"\n")))
	require.NoError(t, out.Close())

	assert.Greater(t, m.errorCount(), 0,
		"writing to a read-only directory must record at least one error")
}

// errorCountingMetrics is a minimal audit.OutputMetrics that
// counts RecordError invocations from the writeLoop goroutine.
// Used by the read-only-directory and large-payload tests above.
type errorCountingMetrics struct {
	audit.NoOpOutputMetrics
	mu     sync.Mutex
	errors int
}

func (m *errorCountingMetrics) RecordError() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.errors++
}

func (m *errorCountingMetrics) errorCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.errors
}

// TestFileOutput_Write_LargePayload pins the contract that a
// single 1 MiB event survives the full write+close cycle without
// truncation or corruption. Large single events are realistic
// for fan-out audits that aggregate dozens of fields. (#565 G3).
func TestFileOutput_Write_LargePayload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	out, err := file.New(&file.Config{Path: path, MaxSizeMB: 100})
	require.NoError(t, err)

	// Build a deterministic 1 MiB payload (printable ASCII so a
	// failure mode that re-encodes bytes shows up as a checksum
	// mismatch rather than a binary diff).
	payload := make([]byte, 1<<20)
	for i := range payload {
		payload[i] = byte('a' + (i % 26))
	}
	payload[len(payload)-1] = '\n'

	require.NoError(t, out.Write(payload))
	require.NoError(t, out.Close())

	content, readErr := os.ReadFile(path)
	require.NoError(t, readErr)
	require.Equal(t, len(payload), len(content),
		"file content length must match payload — no truncation")
	// Spot-check three windows so a partial-write regression
	// surfaces with a useful diff (full-buffer Equal would dump
	// 1 MiB on failure).
	assert.Equal(t, payload[:64], content[:64], "leading 64 bytes mismatch")
	assert.Equal(t, payload[len(payload)/2:len(payload)/2+64], content[len(payload)/2:len(payload)/2+64], "midstream bytes mismatch")
	assert.Equal(t, payload[len(payload)-64:], content[len(payload)-64:], "trailing 64 bytes mismatch")
}

// Note: TestFileOutput_Rotation_MetricsCallback (named in #565
// G3) is already covered by
// TestFileOutput_FileMetrics_RecordRotation_CalledOnRotation
// above (file_test.go:559). Not duplicated.

// ---------------------------------------------------------------------------
// Issue #696 acceptance criteria — factory FrameworkContext plumbing
// ---------------------------------------------------------------------------

// TestOutputFactory_ZeroContext_NoPanic verifies the file factory
// tolerates a zero-value [audit.FrameworkContext]. Construct via
// factory, write once, no panic.
func TestOutputFactory_ZeroContext_NoPanic(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "zero-ctx.log")
	yaml := []byte("path: " + path + "\n")

	factory := audit.LookupOutputFactory("file")
	require.NotNil(t, factory)

	out, err := factory("zero", yaml, audit.FrameworkContext{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	require.NoError(t, out.Write([]byte(`{"event":"zero"}`+"\n")))
}

// (TestOutputFactory_LoggerReachesOutput and the captureHandler that
// supported it were removed in #436. The previous form relied on a
// construction-time perm-mode warning that no longer exists; the
// injected-logger contract is exercised via the writeLoop's async
// error path tests in the BDD scenarios for file_output.feature.)

// TestOutputFactory_OutputMetricsReachesOutput verifies that the
// per-output metrics value supplied via
// [audit.FrameworkContext.OutputMetrics] reaches the file output and
// receives the buffer-full RecordDrop call.
func TestOutputFactory_OutputMetricsReachesOutput(t *testing.T) {
	t.Parallel()
	om := &mockOutputMetrics{}

	dir := t.TempDir()
	path := filepath.Join(dir, "metrics-reaches.log")
	yaml := []byte("path: " + path + "\nbuffer_size: 1\n")

	factory := audit.LookupOutputFactory("file")
	require.NotNil(t, factory)

	out, err := factory("metrics", yaml, audit.FrameworkContext{OutputMetrics: om})
	require.NoError(t, err)

	// Flood the tiny buffer to provoke at least one drop.
	for range 200 {
		_ = out.Write([]byte(`{"event":"flood"}` + "\n"))
	}
	require.NoError(t, out.Close())

	assert.Positive(t, om.drops.Load(),
		"per-output metrics value supplied via FrameworkContext must record drops")
}
