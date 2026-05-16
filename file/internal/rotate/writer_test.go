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

package rotate_test

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/axonops/audit/file/internal/rotate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// ---------------------------------------------------------------------------
// New — validation
// ---------------------------------------------------------------------------

func TestNew_Validation(t *testing.T) {
	t.Parallel()

	validDir := t.TempDir()

	tests := []struct {
		name     string
		filename string
		wantErr  string
		cfg      rotate.Config
	}{
		{
			name:     "empty path",
			filename: "",
			cfg:      rotate.Config{MaxSize: 100, Mode: 0o600},
			wantErr:  "filename must not be empty",
		},
		{
			name:     "missing parent directory",
			filename: filepath.Join(validDir, "no-such-dir", "audit.log"),
			cfg:      rotate.Config{MaxSize: 100, Mode: 0o600},
			wantErr:  "parent directory",
		},
		{
			name:     "zero MaxSize",
			filename: filepath.Join(validDir, "audit.log"),
			cfg:      rotate.Config{MaxSize: 0, Mode: 0o600},
			wantErr:  "MaxSize must be > 0",
		},
		{
			name:     "negative MaxSize",
			filename: filepath.Join(validDir, "audit.log"),
			cfg:      rotate.Config{MaxSize: -1, Mode: 0o600},
			wantErr:  "MaxSize must be > 0",
		},
		{
			name:     "zero Mode",
			filename: filepath.Join(validDir, "audit.log"),
			cfg:      rotate.Config{MaxSize: 100, Mode: 0},
			wantErr:  "Mode must be non-zero",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w, err := rotate.New(tc.filename, tc.cfg)
			assert.Nil(t, w)
			require.Error(t, err)
			// text-only: rotate package errors.New returns no audit sentinel (internal package).
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

func TestNew_SymlinkPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink tests unreliable on Windows CI")
	}
	t.Parallel()

	dir := t.TempDir()
	realFile := filepath.Join(dir, "real.log")
	require.NoError(t, os.WriteFile(realFile, []byte("x"), 0o600))

	link := filepath.Join(dir, "link.log")
	require.NoError(t, os.Symlink(realFile, link))

	w, err := rotate.New(link, rotate.Config{MaxSize: 100, Mode: 0o600})
	require.NoError(t, err, "New should succeed — symlink check is on Write, not New")

	_, err = w.Write([]byte("test"))
	assert.Error(t, err)
	// text-only: rotate package returns raw fmt.Errorf without an audit sentinel wrap (internal package).
	assert.Contains(t, err.Error(), "symlink")
	require.NoError(t, w.Close())
}

// ---------------------------------------------------------------------------
// Write — basic
// ---------------------------------------------------------------------------

func TestWriter_Write_CreatesFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not honoured on Windows")
	}
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	w, err := rotate.New(path, rotate.Config{MaxSize: 1024, Mode: 0o640})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, w.Close()) })

	// File must not exist after New.
	_, err = os.Stat(path)
	assert.True(t, os.IsNotExist(err), "file should not exist before first Write")

	n, err := w.Write([]byte("hello\n"))
	require.NoError(t, err)
	assert.Equal(t, 6, n)

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o640), info.Mode().Perm())
}

func TestWriter_Write_Appends(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	w, err := rotate.New(path, rotate.Config{MaxSize: 1024, Mode: 0o600})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, w.Close()) })

	_, err = w.Write([]byte("line1\n"))
	require.NoError(t, err)
	_, err = w.Write([]byte("line2\n"))
	require.NoError(t, err)

	// Sync flushes the bufio.Writer so file contents are visible.
	require.NoError(t, w.Sync())

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "line1\nline2\n", string(data))
}

// ---------------------------------------------------------------------------
// Write — rotation
// ---------------------------------------------------------------------------

func TestWriter_Write_RotatesOnSize(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	w, err := rotate.New(path, rotate.Config{MaxSize: 50, Mode: 0o600})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, w.Close()) })

	// Write enough to exceed MaxSize.
	payload := bytes.Repeat([]byte("A"), 30)
	_, err = w.Write(payload) // 30 bytes
	require.NoError(t, err)
	_, err = w.Write(payload) // 60 > 50 → rotate
	require.NoError(t, err)

	require.NoError(t, w.Sync())

	// Active file should contain only the last write.
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Len(t, data, 30)

	// There should be a backup file.
	backups := findBackups(t, dir, "audit-", ".log")
	assert.GreaterOrEqual(t, len(backups), 1)
}

func TestWriter_Write_OversizedPayload(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	w, err := rotate.New(path, rotate.Config{MaxSize: 50, Mode: 0o600})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, w.Close()) })

	// Single write > MaxSize should be accepted.
	big := bytes.Repeat([]byte("B"), 100)
	n, err := w.Write(big)
	require.NoError(t, err)
	assert.Equal(t, 100, n)

	// Next write should trigger rotation.
	_, err = w.Write([]byte("C"))
	require.NoError(t, err)

	require.NoError(t, w.Sync())

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "C", string(data))
}

func TestWriter_Write_BackupNaming(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	w, err := rotate.New(path, rotate.Config{MaxSize: 50, Mode: 0o600})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, w.Close()) })

	payload := bytes.Repeat([]byte("X"), 60)
	_, err = w.Write(payload)
	require.NoError(t, err)
	_, err = w.Write([]byte("Y"))
	require.NoError(t, err)

	backups := findBackups(t, dir, "audit-", ".log")
	require.NotEmpty(t, backups)

	// Backup name should match format: audit-YYYY-MM-DDThh-mm-ss.mmm[-N].log
	name := backups[0]
	ts := strings.TrimPrefix(name, "audit-")
	ts = strings.TrimSuffix(ts, ".log")
	// Strip optional collision counter suffix (e.g. "-1").
	if idx := strings.LastIndex(ts, "-"); idx > 0 {
		suffix := ts[idx+1:]
		allDigits := true
		for _, c := range suffix {
			if c < '0' || c > '9' {
				allDigits = false
				break
			}
		}
		if allDigits && suffix != "" {
			ts = ts[:idx]
		}
	}
	_, err = time.Parse("2006-01-02T15-04-05.000", ts)
	assert.NoError(t, err, "backup name %q should contain a valid timestamp", name)
}

// ---------------------------------------------------------------------------
// Write — permissions
// ---------------------------------------------------------------------------

func TestWriter_Write_AllFilesUseConfiguredMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not honoured on Windows")
	}
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	mode := os.FileMode(0o640)

	w, err := rotate.New(path, rotate.Config{MaxSize: 50, Mode: mode})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, w.Close()) })

	payload := bytes.Repeat([]byte("A"), 60)
	_, err = w.Write(payload)
	require.NoError(t, err)
	_, err = w.Write([]byte("B"))
	require.NoError(t, err)

	// Active file.
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, mode, info.Mode().Perm(), "active file permissions")

	// Backup.
	backups := findBackups(t, dir, "audit-", ".log")
	require.NotEmpty(t, backups)
	for _, b := range backups {
		bInfo, err := os.Stat(filepath.Join(dir, b))
		require.NoError(t, err)
		assert.Equal(t, mode, bInfo.Mode().Perm(), "backup %s permissions", b)
	}
}

func TestWriter_Write_ModeOnReopen(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not honoured on Windows")
	}
	// Verifies that openExistingOrNew uses configured mode, not hardcoded 0644.
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	mode := os.FileMode(0o600)

	// Create file with a different mode to simulate existing file.
	require.NoError(t, os.WriteFile(path, []byte("old"), 0o644))

	w, err := rotate.New(path, rotate.Config{MaxSize: 1024, Mode: mode})
	require.NoError(t, err)

	_, err = w.Write([]byte("new\n"))
	require.NoError(t, err)
	require.NoError(t, w.Close())

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, mode, info.Mode().Perm(), "should enforce configured mode, not 0644")
}

// ---------------------------------------------------------------------------
// Write — symlink rejection
// ---------------------------------------------------------------------------

func TestWriter_Write_SymlinkRejected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink tests unreliable on Windows CI")
	}
	t.Parallel()

	dir := t.TempDir()
	realFile := filepath.Join(dir, "real.log")
	require.NoError(t, os.WriteFile(realFile, []byte{}, 0o600))

	link := filepath.Join(dir, "link.log")
	require.NoError(t, os.Symlink(realFile, link))

	w, err := rotate.New(link, rotate.Config{MaxSize: 1024, Mode: 0o600})
	require.NoError(t, err)

	_, err = w.Write([]byte("test"))
	assert.Error(t, err)
	require.NoError(t, w.Close())
}

func TestWriter_Write_SymlinkCreatedBetweenRotations(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink tests unreliable on Windows CI")
	}
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	w, err := rotate.New(path, rotate.Config{MaxSize: 50, Mode: 0o600})
	require.NoError(t, err)
	t.Cleanup(func() { _ = w.Close() })

	// First write — creates the file normally.
	_, err = w.Write(bytes.Repeat([]byte("A"), 30))
	require.NoError(t, err)

	// Replace the file with a symlink (simulates an attacker).
	require.NoError(t, os.Remove(path))
	trap := filepath.Join(dir, "trap.log")
	require.NoError(t, os.WriteFile(trap, []byte{}, 0o600))
	require.NoError(t, os.Symlink(trap, path))

	// Next write should trigger rotation and hit the symlink check.
	_, err = w.Write(bytes.Repeat([]byte("B"), 30))
	assert.Error(t, err, "should reject symlink created between writes")
}

// ---------------------------------------------------------------------------
// Close
// ---------------------------------------------------------------------------

func TestWriter_Close_Idempotent(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	w, err := rotate.New(path, rotate.Config{MaxSize: 1024, Mode: 0o600})
	require.NoError(t, err)

	_, err = w.Write([]byte("test"))
	require.NoError(t, err)

	require.NoError(t, w.Close())
	require.NoError(t, w.Close(), "second close should not error")
}

func TestWriter_Close_WaitsForCompression(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	w, err := rotate.New(path, rotate.Config{
		MaxSize:  50,
		Mode:     0o600,
		Compress: true,
	})
	require.NoError(t, err)

	// Write enough to trigger rotation + compression.
	for i := range 5 {
		_, err = w.Write([]byte(fmt.Sprintf("event-%03d", i) + strings.Repeat("x", 50) + "\n"))
		require.NoError(t, err)
	}

	// Close must wait for compression to finish.
	require.NoError(t, w.Close())

	// After close, .gz files should exist.
	gzFiles := findBackups(t, dir, "audit-", ".log.gz")
	assert.NotEmpty(t, gzFiles, "compressed backups should exist after Close")
}

func TestWriter_Write_AfterClose(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	w, err := rotate.New(path, rotate.Config{MaxSize: 1024, Mode: 0o600})
	require.NoError(t, err)

	require.NoError(t, w.Close())

	_, err = w.Write([]byte("test"))
	assert.Error(t, err)
	assert.ErrorIs(t, err, os.ErrClosed)
}

// ---------------------------------------------------------------------------
// Retention
// ---------------------------------------------------------------------------

func TestWriter_Retention_MaxBackups(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	w, err := rotate.New(path, rotate.Config{
		MaxSize:    50,
		Mode:       0o600,
		MaxBackups: 2,
	})
	require.NoError(t, err)

	// Write enough to generate >2 backups.
	for i := range 5 {
		payload := fmt.Sprintf("event-%d-", i) + strings.Repeat("x", 50) + "\n"
		_, err = w.Write([]byte(payload))
		require.NoError(t, err)
	}
	require.NoError(t, w.Close())

	backups := findBackups(t, dir, "audit-", ".log")
	assert.LessOrEqual(t, len(backups), 2, "should retain at most MaxBackups backups")
}

func TestWriter_Retention_MaxAge(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	// Create fake old backups.
	old := time.Now().Add(-48 * time.Hour)
	oldName := fmt.Sprintf("audit-%s.log", old.Format("2006-01-02T15-04-05.000"))
	require.NoError(t, os.WriteFile(filepath.Join(dir, oldName), []byte("old"), 0o600))

	w, err := rotate.New(path, rotate.Config{
		MaxSize: 50,
		Mode:    0o600,
		MaxAge:  24 * time.Hour,
	})
	require.NoError(t, err)

	// Trigger a rotation to invoke the mill.
	payload := strings.Repeat("x", 60)
	_, err = w.Write([]byte(payload))
	require.NoError(t, err)
	_, err = w.Write([]byte("y"))
	require.NoError(t, err)

	require.NoError(t, w.Close())

	// Old backup should be removed.
	_, err = os.Stat(filepath.Join(dir, oldName))
	assert.True(t, os.IsNotExist(err), "old backup should have been removed by MaxAge")
}

// ---------------------------------------------------------------------------
// Compression
// ---------------------------------------------------------------------------

func TestWriter_Compression_CreatesGz(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	w, err := rotate.New(path, rotate.Config{
		MaxSize:  50,
		Mode:     0o600,
		Compress: true,
	})
	require.NoError(t, err)

	payload := strings.Repeat("x", 60) + "\n"
	_, err = w.Write([]byte(payload))
	require.NoError(t, err)
	_, err = w.Write([]byte("y\n"))
	require.NoError(t, err)

	require.NoError(t, w.Close())

	gzFiles := findBackups(t, dir, "audit-", ".log.gz")
	assert.NotEmpty(t, gzFiles, "should have compressed backup")

	// Verify the .gz file is valid gzip.
	for _, name := range gzFiles {
		f, err := os.Open(filepath.Join(dir, name))
		require.NoError(t, err)
		gr, err := gzip.NewReader(f)
		require.NoError(t, err)
		_, err = io.ReadAll(gr)
		assert.NoError(t, err, "gz file %s should be valid gzip", name)
		gr.Close() //nolint:errcheck // test cleanup — validity already verified by ReadAll
		f.Close()  //nolint:errcheck // test cleanup — read-only file
	}
}

func TestWriter_Compression_CorrectMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not honoured on Windows")
	}
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	mode := os.FileMode(0o640)

	w, err := rotate.New(path, rotate.Config{
		MaxSize:  50,
		Mode:     mode,
		Compress: true,
	})
	require.NoError(t, err)

	payload := strings.Repeat("x", 60) + "\n"
	_, err = w.Write([]byte(payload))
	require.NoError(t, err)
	_, err = w.Write([]byte("y\n"))
	require.NoError(t, err)

	require.NoError(t, w.Close())

	gzFiles := findBackups(t, dir, "audit-", ".log.gz")
	require.NotEmpty(t, gzFiles)

	for _, name := range gzFiles {
		info, err := os.Stat(filepath.Join(dir, name))
		require.NoError(t, err)
		assert.Equal(t, mode, info.Mode().Perm(), "gz file %s should have configured mode", name)
	}
}

func TestWriter_Compression_SourceRemoved(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows holds an exclusive file lock until the writer closes; the unlink-after-compress sequence is Linux/macOS-only")
	}
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	w, err := rotate.New(path, rotate.Config{
		MaxSize:  50,
		Mode:     0o600,
		Compress: true,
	})
	require.NoError(t, err)

	payload := strings.Repeat("x", 60) + "\n"
	_, err = w.Write([]byte(payload))
	require.NoError(t, err)
	_, err = w.Write([]byte("y\n"))
	require.NoError(t, err)

	require.NoError(t, w.Close())

	// Uncompressed backup should be removed.
	uncompressed := findBackups(t, dir, "audit-", ".log")
	assert.Empty(t, uncompressed, "uncompressed backups should be removed after compression")

	// Compressed backup should exist.
	gzFiles := findBackups(t, dir, "audit-", ".log.gz")
	assert.NotEmpty(t, gzFiles)
}

func TestWriter_Compression_Disabled(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	w, err := rotate.New(path, rotate.Config{
		MaxSize:  50,
		Mode:     0o600,
		Compress: false,
	})
	require.NoError(t, err)

	payload := strings.Repeat("x", 60) + "\n"
	_, err = w.Write([]byte(payload))
	require.NoError(t, err)
	_, err = w.Write([]byte("y\n"))
	require.NoError(t, err)

	require.NoError(t, w.Close())

	gzFiles := findBackups(t, dir, "audit-", ".log.gz")
	assert.Empty(t, gzFiles, "should not have compressed backups when Compress=false")
}

// ---------------------------------------------------------------------------
// Concurrency
// ---------------------------------------------------------------------------

func TestWriter_ConcurrentWrites(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	w, err := rotate.New(path, rotate.Config{MaxSize: 500, Mode: 0o600})
	require.NoError(t, err)

	const goroutines = 50
	const writes = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)
	errs := make(chan error, goroutines*writes)

	for i := range goroutines {
		go func(id int) {
			defer wg.Done()
			for j := range writes {
				msg := fmt.Sprintf("g%d-w%d\n", id, j)
				if _, err := w.Write([]byte(msg)); err != nil {
					errs <- err
				}
			}
		}(i)
	}

	wg.Wait()
	close(errs)
	require.NoError(t, w.Close())

	for err := range errs {
		t.Errorf("concurrent write error: %v", err)
	}
}

func TestWriter_ConcurrentWritesStress(t *testing.T) {
	// Stress test: 1000 goroutines writing concurrently with rotation
	// enabled. Verifies thread safety under heavy contention, no panics,
	// no data races (via -race), and no goroutine leaks.
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	w, err := rotate.New(path, rotate.Config{
		MaxSize:    1024, // 1KB — forces frequent rotation under load
		Mode:       0o600,
		MaxBackups: 10,
		Compress:   true,
	})
	require.NoError(t, err)

	const goroutines = 1000
	const writesPerGoroutine = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)

	var writeErrors atomic.Int64
	var totalWrites atomic.Int64

	for i := range goroutines {
		go func(id int) {
			defer wg.Done()
			for j := range writesPerGoroutine {
				msg := fmt.Sprintf(`{"goroutine":%d,"seq":%d,"ts":"%s"}`+"\n",
					id, j, time.Now().Format(time.RFC3339Nano))
				if _, writeErr := w.Write([]byte(msg)); writeErr != nil {
					writeErrors.Add(1)
					continue
				}
				totalWrites.Add(1)
			}
		}(i)
	}

	wg.Wait()

	// Close must complete cleanly — no panics, no hangs.
	require.NoError(t, w.Close())

	// All writes should succeed (no errors expected since we don't close early).
	assert.Equal(t, int64(0), writeErrors.Load(), "no write errors expected")
	assert.Equal(t, int64(goroutines*writesPerGoroutine), totalWrites.Load(),
		"all writes should succeed")

	// Verify files exist and active file is readable.
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.NotEmpty(t, data, "active file should contain data")

	// Verify backups were created (1000*50 writes at ~80 bytes each =
	// ~4MB, with 1KB MaxSize → many rotations).
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Greater(t, len(entries), 1, "rotation should have created backups")
}

func TestWriter_ConcurrentWriteAndClose(t *testing.T) {
	// Exercises the race between Write and Close — Close while 500
	// goroutines are writing. Some writes succeed, some get ErrClosed.
	// No panics, no races, no leaked goroutines.
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	w, err := rotate.New(path, rotate.Config{
		MaxSize: 512,
		Mode:    0o600,
	})
	require.NoError(t, err)

	const goroutines = 500
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := range goroutines {
		go func(id int) {
			defer wg.Done()
			for j := range 20 {
				msg := fmt.Sprintf("g%d-w%d\n", id, j)
				_, err := w.Write([]byte(msg))
				if err != nil {
					// After Close, writes return os.ErrClosed — that's expected.
					return
				}
			}
		}(i)
	}

	// Let some goroutines start writing, then close.
	require.NoError(t, w.Close())
	wg.Wait()

	// Double-close must be safe.
	require.NoError(t, w.Close())
}

// ---------------------------------------------------------------------------
// Lazy open / No MkdirAll
// ---------------------------------------------------------------------------

func TestWriter_LazyOpen(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	w, err := rotate.New(path, rotate.Config{MaxSize: 1024, Mode: 0o600})
	require.NoError(t, err)

	// File must NOT exist after New.
	_, err = os.Stat(path)
	assert.True(t, os.IsNotExist(err), "New should not create the file")

	require.NoError(t, w.Close())
}

func TestWriter_NoMkdirAll(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "missing", "dir", "audit.log")

	w, err := rotate.New(path, rotate.Config{MaxSize: 1024, Mode: 0o600})
	assert.Nil(t, w)
	assert.Error(t, err)
	// text-only: writer.go:399 returns raw fmt.Errorf without an audit sentinel wrap (internal package).
	assert.Contains(t, err.Error(), "parent directory")
}

// ---------------------------------------------------------------------------
// Sync
// ---------------------------------------------------------------------------

func TestWriter_Sync(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	w, err := rotate.New(path, rotate.Config{MaxSize: 1024, Mode: 0o600})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, w.Close()) })

	// Sync on unopened writer should be a no-op.
	require.NoError(t, w.Sync())

	_, err = w.Write([]byte("test\n"))
	require.NoError(t, err)

	// Sync on open writer should succeed.
	require.NoError(t, w.Sync())
}

// ---------------------------------------------------------------------------
// Write — visibility semantics
//
// #450 originally required per-write flush so every event was
// visible to readers without Sync/Close. #461 relaxed the
// default to deferred flush with a background timer and added
// SyncOnWrite to opt back in to the per-call flush contract.
// The tests below pin BOTH modes.
// ---------------------------------------------------------------------------

func TestWriter_Write_DataVisibleWithoutSync_SyncOnWriteTrue(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	w, err := rotate.New(path, rotate.Config{
		MaxSize:     1 << 20,
		Mode:        0o600,
		SyncOnWrite: true, // #450 contract
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, w.Close()) })

	event := []byte(`{"event_type":"auth.login","outcome":"success"}` + "\n")
	_, err = w.Write(event)
	require.NoError(t, err)

	// Data must be visible on disk WITHOUT calling Sync() or Close()
	// under the explicit SyncOnWrite=true contract.
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, string(event), string(data),
		"event must be visible on disk immediately after Write when SyncOnWrite=true (#450)")
}

func TestWriter_Write_MultipleEventsVisibleWithoutSync_SyncOnWriteTrue(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	w, err := rotate.New(path, rotate.Config{
		MaxSize:     1 << 20,
		Mode:        0o600,
		SyncOnWrite: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, w.Close()) })

	const count = 10
	for i := range count {
		event := []byte(fmt.Sprintf(`{"seq":%d}`+"\n", i))
		_, err = w.Write(event)
		require.NoError(t, err)
	}

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	assert.Len(t, lines, count,
		"all %d events must be visible on disk without Sync/Close when SyncOnWrite=true (#450)", count)
}

// TestWriter_Write_DeferredFlush_DefaultSyncOff pins the new
// default: writes accumulate in bufio until the background timer
// fires or Close drains. Immediately after Write, data is NOT
// yet visible to readers — but is after Sync() / Close() / timer.
func TestWriter_Write_DeferredFlush_DefaultSyncOff(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	// FlushInterval set large so the timer doesn't fire during
	// the test — we want to observe the "not yet visible" state.
	w, err := rotate.New(path, rotate.Config{
		MaxSize:       1 << 20,
		Mode:          0o600,
		FlushInterval: 10 * time.Second,
	})
	require.NoError(t, err)

	event := []byte(`{"event_type":"auth.login"}` + "\n")
	_, err = w.Write(event)
	require.NoError(t, err)

	// Data held in bufio; not yet on disk.
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Empty(t, data,
		"default SyncOnWrite=false must hold data in bufio; no disk visibility before Sync/Close/timer")

	// Sync explicitly drains.
	require.NoError(t, w.Sync())
	data, err = os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, string(event), string(data),
		"Sync must drain the pending bufio buffer to disk")

	require.NoError(t, w.Close())
}

// TestWriter_Write_BackgroundTimerFlushes pins the deferred-
// flush contract: bytes must become visible within ~FlushInterval
// without any Sync/Close call.
//
// Synchronisation uses the testOnFlush hook (#705 family fix);
// previously the test polled the file with 5 ms sleeps and a
// 500 ms deadline, which flaked under CI runner load.
func TestWriter_Write_BackgroundTimerFlushes(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	w, err := rotate.New(path, rotate.Config{
		MaxSize:       1 << 20,
		Mode:          0o600,
		FlushInterval: 10 * time.Millisecond, // fast for the test
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, w.Close()) })

	flushed := make(chan struct{}, 4)
	w.SetTestOnFlush(func() {
		select {
		case flushed <- struct{}{}:
		default:
		}
	})
	t.Cleanup(func() { w.SetTestOnFlush(nil) })

	event := []byte(`{"event_type":"timer.test"}` + "\n")
	_, err = w.Write(event)
	require.NoError(t, err)

	select {
	case <-flushed:
	case <-time.After(5 * time.Second):
		t.Fatal("testOnFlush hook never fired within 5 s — possible flushLoop regression")
	}

	data, rerr := os.ReadFile(path)
	require.NoError(t, rerr)
	assert.Equal(t, string(event), string(data),
		"bytes must be on disk after the background flush hook fires")
}

// TestWriter_Close_DrainsPendingBytes pins that Close always
// flushes pending bufio bytes regardless of SyncOnWrite.
func TestWriter_Close_DrainsPendingBytes(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	w, err := rotate.New(path, rotate.Config{
		MaxSize:       1 << 20,
		Mode:          0o600,
		FlushInterval: 10 * time.Second, // disable background timer for this test
	})
	require.NoError(t, err)

	event := []byte(`{"event_type":"close.test"}` + "\n")
	_, err = w.Write(event)
	require.NoError(t, err)

	require.NoError(t, w.Close())

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, string(event), string(data),
		"Close must drain pending bufio bytes to disk")
}

// ---------------------------------------------------------------------------
// Edge cases for coverage
// ---------------------------------------------------------------------------

func TestWriter_OpenExistingFile(t *testing.T) {
	// Exercises the openExistingOrNew path where the file exists and has capacity.
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	// Pre-create a small file.
	require.NoError(t, os.WriteFile(path, []byte("existing\n"), 0o600))

	w, err := rotate.New(path, rotate.Config{MaxSize: 1024, Mode: 0o600})
	require.NoError(t, err)

	_, err = w.Write([]byte("appended\n"))
	require.NoError(t, err)
	require.NoError(t, w.Close())

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Contains(t, string(data), "existing\n")
	assert.Contains(t, string(data), "appended\n")
}

func TestWriter_OpenExistingFile_AtCapacity(t *testing.T) {
	// Exercises the openExistingOrNew path where the file exists but is at capacity.
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	// Pre-create a file that is at capacity.
	require.NoError(t, os.WriteFile(path, bytes.Repeat([]byte("x"), 100), 0o600))

	w, err := rotate.New(path, rotate.Config{MaxSize: 100, Mode: 0o600})
	require.NoError(t, err)

	_, err = w.Write([]byte("new\n"))
	require.NoError(t, err)
	require.NoError(t, w.Close())

	// The old content should be in a backup, new content in the active file.
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "new\n", string(data))
}

func TestWriter_RotateCloseError(t *testing.T) {
	// Exercise the rotate → closeFile path by triggering multiple rotations.
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	w, err := rotate.New(path, rotate.Config{MaxSize: 50, Mode: 0o600})
	require.NoError(t, err)

	for i := range 4 {
		payload := fmt.Sprintf("event-%d-%s\n", i, strings.Repeat("x", 50))
		_, err = w.Write([]byte(payload))
		require.NoError(t, err)
	}
	require.NoError(t, w.Close())

	backups := findBackups(t, dir, "audit-", ".log")
	assert.GreaterOrEqual(t, len(backups), 1, "at least one backup from multiple rotations")
}

func TestWriter_CompressionWithRetention(t *testing.T) {
	// Exercise compression + MaxBackups together.
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	w, err := rotate.New(path, rotate.Config{
		MaxSize:    50,
		Mode:       0o600,
		Compress:   true,
		MaxBackups: 2,
	})
	require.NoError(t, err)

	for i := range 5 {
		payload := fmt.Sprintf("event-%d-%s\n", i, strings.Repeat("x", 50))
		_, err = w.Write([]byte(payload))
		require.NoError(t, err)
	}
	require.NoError(t, w.Close())

	// Should have at most 2 compressed backups.
	gzFiles := findBackups(t, dir, "audit-", ".log.gz")
	assert.LessOrEqual(t, len(gzFiles), 2)
}

func TestWriter_NonLogFilesIgnored(t *testing.T) {
	// Verify that unrelated files in the directory are not treated as backups.
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	// Create unrelated files that share the prefix.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "audit-notes.txt"), []byte("x"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "other.log"), []byte("x"), 0o600))

	w, err := rotate.New(path, rotate.Config{MaxSize: 50, Mode: 0o600, MaxBackups: 1})
	require.NoError(t, err)

	payload := strings.Repeat("x", 60)
	_, err = w.Write([]byte(payload))
	require.NoError(t, err)
	_, err = w.Write([]byte("y"))
	require.NoError(t, err)
	require.NoError(t, w.Close())

	// Unrelated files should still exist.
	_, err = os.Stat(filepath.Join(dir, "audit-notes.txt"))
	assert.NoError(t, err, "unrelated file should not be removed")
	_, err = os.Stat(filepath.Join(dir, "other.log"))
	assert.NoError(t, err, "unrelated file should not be removed")
}

// ---------------------------------------------------------------------------
// Lumberjack-inspired edge cases
// ---------------------------------------------------------------------------

func TestWriter_FilenameWithoutExtension(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "auditlog") // no extension

	w, err := rotate.New(path, rotate.Config{MaxSize: 50, Mode: 0o600})
	require.NoError(t, err)

	payload := strings.Repeat("x", 60) + "\n"
	_, err = w.Write([]byte(payload))
	require.NoError(t, err)
	_, err = w.Write([]byte("y\n"))
	require.NoError(t, err)
	require.NoError(t, w.Close())

	// Active file should exist.
	_, err = os.Stat(path)
	require.NoError(t, err)

	// Should have at least one backup.
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Greater(t, len(entries), 1, "should have created backup without extension")
}

func TestWriter_WriteBelowMaxSize_NoBackups(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	w, err := rotate.New(path, rotate.Config{MaxSize: 1024, Mode: 0o600})
	require.NoError(t, err)

	_, err = w.Write([]byte("small event\n"))
	require.NoError(t, err)
	_, err = w.Write([]byte("another small event\n"))
	require.NoError(t, err)
	require.NoError(t, w.Close())

	backups := findBackups(t, dir, "audit-", ".log")
	assert.Empty(t, backups, "no backups should be created when writes stay below MaxSize")
}

func TestWriter_BackupContentIntegrity(t *testing.T) {
	// Single-goroutine: total bytes in active + all backups = total written.
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	w, err := rotate.New(path, rotate.Config{MaxSize: 100, Mode: 0o600})
	require.NoError(t, err)

	totalWritten := 0
	for i := range 10 {
		payload := fmt.Sprintf("event-%02d-%s\n", i, strings.Repeat("x", 30))
		n, writeErr := w.Write([]byte(payload))
		require.NoError(t, writeErr)
		totalWritten += n
	}
	require.NoError(t, w.Close())

	// Sum bytes across active file + all backups.
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)

	totalOnDisk := 0
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		require.NoError(t, err)
		totalOnDisk += len(data)
	}

	assert.Equal(t, totalWritten, totalOnDisk, "no audit data should be lost during rotation")
}

func TestWriter_CompressionOnResume(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows file-locking semantics break the unlink-after-recompress sequence")
	}
	// Pre-create both .log and .log.gz (simulating crash during compression).
	// Verify no corruption after the writer runs.
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	ts := time.Now().Add(-time.Minute).Format("2006-01-02T15-04-05.000")
	backupLog := filepath.Join(dir, "audit-"+ts+".log")
	backupGz := backupLog + ".gz"

	require.NoError(t, os.WriteFile(backupLog, []byte("old data\n"), 0o600))
	require.NoError(t, os.WriteFile(backupGz, []byte("partial gz"), 0o600))

	w, err := rotate.New(path, rotate.Config{
		MaxSize:  50,
		Mode:     0o600,
		Compress: true,
	})
	require.NoError(t, err)

	// Trigger rotation to fire the mill.
	_, err = w.Write([]byte(strings.Repeat("x", 60) + "\n"))
	require.NoError(t, err)
	_, err = w.Write([]byte("y\n"))
	require.NoError(t, err)
	require.NoError(t, w.Close())

	// The pre-existing .log should have been re-compressed (overwriting the partial .gz).
	_, err = os.Stat(backupLog)
	assert.True(t, os.IsNotExist(err), "uncompressed backup should be removed after re-compression")

	_, err = os.Stat(backupGz)
	assert.NoError(t, err, "compressed backup should exist")
}

// ---------------------------------------------------------------------------
// OnRotate callback — black-box
// ---------------------------------------------------------------------------

func TestWriter_OnRotate_NilDoesNotPanic(t *testing.T) {
	// A nil OnRotate must not panic when rotation fires.
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	w, err := rotate.New(path, rotate.Config{
		MaxSize:  50,
		Mode:     0o600,
		OnRotate: nil, // explicit nil — the default
	})
	require.NoError(t, err)

	// Trigger rotation by writing past MaxSize.
	payload := bytes.Repeat([]byte("A"), 30)
	_, err = w.Write(payload) // 30 bytes
	require.NoError(t, err)

	// This write pushes total to 60 > 50, causing rotation.
	assert.NotPanics(t, func() {
		_, err = w.Write(payload)
		require.NoError(t, err)
	}, "nil OnRotate must not panic when rotation fires")

	require.NoError(t, w.Close())
}

func TestWriter_OnRotate_CalledOncePerRotation(t *testing.T) {
	// OnRotate must be called exactly once per rotation event, with
	// the path of the active file that was just rotated (not the backup path).
	//
	// MaxSize=100 bytes. Fill sequence:
	//   write1: 60 bytes → size=60  (no rotation)
	//   write2: 60 bytes → size would be 120 > 100 → rotation #1, size=60
	//   write3: 10 bytes → size=70  (no rotation)
	//   write4: 60 bytes → size would be 130 > 100 → rotation #2, size=60
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	var (
		mu           sync.Mutex
		rotatedPaths []string
	)
	onRotate := func(rotatedPath string) {
		mu.Lock()
		defer mu.Unlock()
		rotatedPaths = append(rotatedPaths, rotatedPath)
	}

	w, err := rotate.New(path, rotate.Config{
		MaxSize:  100,
		Mode:     0o600,
		OnRotate: onRotate,
	})
	require.NoError(t, err)

	big := bytes.Repeat([]byte("B"), 60)
	small := bytes.Repeat([]byte("S"), 10)

	_, err = w.Write(big) // 60 bytes — under limit
	require.NoError(t, err)
	_, err = w.Write(big) // 120 > 100 — rotation #1, then write 60 bytes
	require.NoError(t, err)
	_, err = w.Write(small) // 10 bytes — under limit
	require.NoError(t, err)
	_, err = w.Write(big) // 70+60 = 130 > 100 — rotation #2, then write 60 bytes
	require.NoError(t, err)

	require.NoError(t, w.Close())

	mu.Lock()
	count := len(rotatedPaths)
	paths := make([]string, count)
	copy(paths, rotatedPaths)
	mu.Unlock()

	assert.Equal(t, 2, count,
		"OnRotate should be called exactly once per rotation, got %d calls", count)

	for i, p := range paths {
		assert.Equal(t, path, p,
			"OnRotate call %d: got path %q, want %q (active file path)", i, p, path)
	}
}

func TestWriter_OnRotate_NotCalledOnNormalWrite(t *testing.T) {
	// OnRotate must not be called when no rotation occurs.
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	var called atomic.Int32
	w, err := rotate.New(path, rotate.Config{
		MaxSize: 10240, // 10 KB — writes below this do not rotate
		Mode:    0o600,
		OnRotate: func(_ string) {
			called.Add(1)
		},
	})
	require.NoError(t, err)

	for range 5 {
		_, err = w.Write([]byte("small event\n"))
		require.NoError(t, err)
	}
	require.NoError(t, w.Close())

	assert.Equal(t, int32(0), called.Load(),
		"OnRotate must not be called when no rotation occurs")
}

// ---------------------------------------------------------------------------
// OnError callback — black-box
// ---------------------------------------------------------------------------

func TestWriter_OnError_NilDoesNotPanic(t *testing.T) {
	// Verify that a nil OnError callback (the default) does not panic
	// when background errors occur.
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	w, err := rotate.New(path, rotate.Config{
		MaxSize: 50,
		Mode:    0o600,
	})
	require.NoError(t, err)

	for i := range 3 {
		_, err := fmt.Fprintf(w, "event-%d-%s\n", i, strings.Repeat("x", 50))
		require.NoError(t, err)
	}
	require.NoError(t, w.Close())
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func findBackups(t *testing.T, dir, prefix, suffix string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	var result []string
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, prefix) && strings.HasSuffix(name, suffix) {
			// Exclude .gz when looking for bare suffix (e.g. ".log" should not match ".log.gz")
			if !strings.HasSuffix(suffix, ".gz") && strings.HasSuffix(name, ".gz") {
				continue
			}
			result = append(result, name)
		}
	}
	return result
}

// ---------------------------------------------------------------------------
// Benchmarks for #461 — SyncOnWrite=true (old #450 behavior) vs
// SyncOnWrite=false (new default with background timer).
// ---------------------------------------------------------------------------

// benchWriter constructs a rotate.Writer in the given sync mode.
// Target: IOURING_BENCH_DIR env var (real disk) or /dev/shm (tmpfs)
// or t.TempDir (whatever $TMPDIR is). Same selection as iouring
// bench so results are comparable.
func benchWriter(b *testing.B, syncOnWrite bool) *rotate.Writer {
	b.Helper()
	dir := os.Getenv("IOURING_BENCH_DIR")
	if dir == "" {
		if _, err := os.Stat("/dev/shm"); err == nil {
			dir = "/dev/shm"
		} else {
			dir = b.TempDir()
		}
	}
	path := filepath.Join(dir, fmt.Sprintf("rotate-bench-%d-%t.log", os.Getpid(), syncOnWrite))
	w, err := rotate.New(path, rotate.Config{
		MaxSize:     1 << 30,
		Mode:        0o600,
		SyncOnWrite: syncOnWrite,
	})
	if err != nil {
		b.Fatal(err)
	}
	// Glob-remove the active file AND every rotated backup so
	// /dev/shm does not leak between bench runs. With MaxSize at
	// 1 GiB a long b.N can still trigger rotations; the previous
	// per-active-file Remove leaked rotated files. See #871.
	b.Cleanup(func() { cleanupBenchRotateFiles(w, path) })
	return w
}

// cleanupBenchRotateFiles closes the writer and removes the active
// file plus every rotated / compressed backup matching the same
// base name. Shared by benchWriter, BenchmarkWriter_Write_WithRotation,
// and the TestBenchWriter_Cleanup_* regression tests below so the
// production cleanup behaviour cannot drift from what the tests
// assert. Glob expression matches: <base>.log, <base>-<RFC3339>.log,
// <base>-<RFC3339>.log.gz. See ADR-free issue #871 and ADR 0007's
// pattern precedent for the same approach in BenchmarkMatchesRoute.
func cleanupBenchRotateFiles(w *rotate.Writer, path string) {
	_ = w.Close()
	globPrefix := strings.TrimSuffix(path, ".log") + "*"
	matches, _ := filepath.Glob(globPrefix)
	for _, m := range matches {
		_ = os.Remove(m)
	}
}

// BenchmarkWriter_Write_SyncOnWriteTrue measures the #450
// per-call flush path — flush every event, syscall every event.
func BenchmarkWriter_Write_SyncOnWriteTrue(b *testing.B) {
	w := benchWriter(b, true)
	event := []byte(`{"timestamp":"2026-04-14T12:00:00Z","event_type":"user_create","severity":5,"app_name":"bench","host":"localhost","outcome":"success","actor_id":"alice"}` + "\n")

	b.ReportAllocs()
	b.SetBytes(int64(len(event)))
	b.ResetTimer()
	for b.Loop() {
		if _, err := w.Write(event); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkWriter_Write_SyncOnWriteFalse measures the #461 deferred-
// flush path — bytes into bufio, background timer drains. Expected
// to beat the SyncOnWrite=true path by at least 10× per the #461 AC.
func BenchmarkWriter_Write_SyncOnWriteFalse(b *testing.B) {
	w := benchWriter(b, false)
	event := []byte(`{"timestamp":"2026-04-14T12:00:00Z","event_type":"user_create","severity":5,"app_name":"bench","host":"localhost","outcome":"success","actor_id":"alice"}` + "\n")

	b.ReportAllocs()
	b.SetBytes(int64(len(event)))
	b.ResetTimer()
	for b.Loop() {
		if _, err := w.Write(event); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkWriter_Write_WithRotation measures the steady-state cost
// of the Write path when rotation fires regularly (#504 AC #1,
// master tracker C-18). Pairs with BenchmarkWriter_Write_SyncOnWriteFalse
// — both write the same 161 B event; only the rotation trigger
// differs. The delta between the two captures the amortised rotation
// cost (rename + new file + prune).
//
// Placement rationale: the issue AC names the benchmark
// BenchmarkFileOutput_Write_WithRotation but the public
// file.Config.MaxSizeMB is integer megabytes (minimum 1 ≈ 6500
// writes per rotation = 0.015 % signal, below benchmark noise).
// rotate.Config.MaxSize is byte-granular and is where the rotation
// logic lives. At MaxSize=4 KiB with a 161 B event, rotation fires
// every ~25 writes — ~4 % signal, cleanly above the typical ±2 %
// variance. A companion BenchmarkFileOutput_Write_WithRotation in
// the public file_test.go satisfies the AC literal.
func BenchmarkWriter_Write_WithRotation(b *testing.B) {
	dir := os.Getenv("IOURING_BENCH_DIR")
	if dir == "" {
		if _, err := os.Stat("/dev/shm"); err == nil {
			dir = "/dev/shm"
		} else {
			dir = b.TempDir()
		}
	}
	path := filepath.Join(dir, fmt.Sprintf("rotate-bench-withrotation-%d.log", os.Getpid()))
	// MaxSize=4 KiB forces rotation every ~25 writes at 161 B/event.
	// MaxBackups=2 keeps the prune path warm without letting the
	// tmpfs / IOURING_BENCH_DIR directory balloon. Compress=false so
	// the measurement is rotation mechanics, not gzip CPU.
	w, err := rotate.New(path, rotate.Config{
		MaxSize:     4096,
		MaxBackups:  2,
		Compress:    false,
		Mode:        0o600,
		SyncOnWrite: false,
	})
	if err != nil {
		b.Fatal(err)
	}
	// Backups are named "<prefix>-<ts>.log" where <prefix> is the
	// base filename minus the extension. cleanupBenchRotateFiles
	// globs the prefix to match the active file plus every
	// rotated/compressed backup. Close already happens inside the
	// benchmark body before the safety-net check; the helper's
	// extra Close call is a documented no-op (idempotent).
	b.Cleanup(func() { cleanupBenchRotateFiles(w, path) })
	globPrefix := strings.TrimSuffix(path, ".log") + "*"

	event := []byte(`{"timestamp":"2026-04-14T12:00:00Z","event_type":"user_create","severity":5,"app_name":"bench","host":"localhost","outcome":"success","actor_id":"alice"}` + "\n")

	b.ReportAllocs()
	b.SetBytes(int64(len(event)))
	b.ResetTimer()
	for b.Loop() {
		if _, werr := w.Write(event); werr != nil {
			b.Fatal(werr)
		}
	}
	b.StopTimer()

	// Safety net: prove rotation actually fired. Without this, a
	// silent break in rotation logic would show as a free perf win.
	// Close flushes pending bytes and releases file handles before
	// the glob count.
	if cerr := w.Close(); cerr != nil {
		b.Fatalf("close: %v", cerr)
	}
	matches, gerr := filepath.Glob(globPrefix)
	if gerr != nil {
		b.Fatalf("glob: %v", gerr)
	}
	if len(matches) < 2 {
		b.Fatalf("expected rotation to fire; found only %d file(s) matching %q", len(matches), globPrefix)
	}
}

// ---------------------------------------------------------------------------
// Cleanup-helper regression test (#871) — covers the bench helper's
// glob-based cleanup, which previously leaked rotated backups into
// /dev/shm across runs.
// ---------------------------------------------------------------------------

// globPrefixOf returns the glob expression benchWriter uses to
// match the active file plus all rotated/compressed backups.
// Defined inline in tests so a test caller can count files via
// the same expression the production cleanup uses — keeping
// production cleanup and test assertions in lock-step.
func globPrefixOf(path string) string {
	return strings.TrimSuffix(path, ".log") + "*"
}

// driveWriterRotations creates a rotate.Writer with the given
// config, writes ~12.8 KiB of payload (50 writes × 256 B) to fire
// several rotations, and returns the writer (un-closed so the
// test can pass it to cleanupBenchRotateFiles which Closes it).
// Compress controls whether rotated backups become .log.gz.
func driveWriterRotations(t *testing.T, path string, compress bool, maxBackups int) *rotate.Writer {
	t.Helper()
	w, err := rotate.New(path, rotate.Config{
		MaxSize:     1024, // 1 KiB — rotates every ~4 writes of 256 B
		MaxBackups:  maxBackups,
		Compress:    compress,
		Mode:        0o600,
		SyncOnWrite: false,
	})
	require.NoError(t, err)

	event := bytes.Repeat([]byte("x"), 256)
	for range 50 {
		_, werr := w.Write(event)
		require.NoError(t, werr)
	}
	return w
}

// TestCleanupBenchRotateFiles_RotationsKeptUnbounded asserts that
// with MaxBackups=0 (unlimited) and enough writes to trigger several
// rotations, cleanupBenchRotateFiles removes the active file plus
// every rotated backup. Regression guard for #871 — the previous
// cleanup only removed the active file and leaked ~94 GB of backups
// into /dev/shm over a month of bench runs. Calls the same helper
// benchWriter uses so production cleanup and test cannot drift.
func TestCleanupBenchRotateFiles_RotationsKeptUnbounded(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "rotate-cleanup-test.log")
	w := driveWriterRotations(t, path, false, 0)
	// Snapshot file count BEFORE cleanup — must close first so
	// the rotate mill goroutine has drained.
	require.NoError(t, w.Sync())

	before, gerr := filepath.Glob(globPrefixOf(path))
	require.NoError(t, gerr)
	require.GreaterOrEqual(t, len(before), 2,
		"setup: expected at least 2 files (active + ≥1 backup), got %d: %v",
		len(before), before)

	// Exercise the actual production helper.
	cleanupBenchRotateFiles(w, path)

	after, _ := filepath.Glob(globPrefixOf(path))
	assert.Empty(t, after, "cleanup left files behind: %v", after)
}

// TestCleanupBenchRotateFiles_WithCompression asserts that the
// glob prefix matches compressed .log.gz backups as well as the
// active .log file. Verifies empirically that the production
// cleanup helper handles the compressed case.
func TestCleanupBenchRotateFiles_WithCompression(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "rotate-cleanup-compress-test.log")
	w := driveWriterRotations(t, path, true, 0)
	// Sync forces the bufio.Writer to flush so the count under
	// glob is stable; cleanupBenchRotateFiles will Close+drain.
	require.NoError(t, w.Sync())

	// Trigger Close indirectly via the helper to drain compression.
	cleanupBenchRotateFiles(w, path)

	after, _ := filepath.Glob(globPrefixOf(path))
	assert.Empty(t, after, "cleanup left files behind: %v", after)

	// Sanity: re-run the bench scenario without cleanup so we can
	// observe a .gz file existed pre-cleanup. Use a fresh path.
	path2 := filepath.Join(t.TempDir(), "rotate-cleanup-compress-test2.log")
	w2 := driveWriterRotations(t, path2, true, 0)
	require.NoError(t, w2.Close())
	pre, _ := filepath.Glob(globPrefixOf(path2))
	var sawGz bool
	for _, m := range pre {
		if strings.HasSuffix(m, ".gz") {
			sawGz = true
			break
		}
	}
	require.True(t, sawGz,
		"setup: expected at least one .log.gz backup pre-cleanup, got %v", pre)
}

// TestCleanupBenchRotateFiles_BoundedMaxBackups exercises the
// real BenchmarkWriter_Write_WithRotation configuration
// (MaxBackups=2) — the rotate mill goroutine prunes older backups
// before cleanup runs. cleanupBenchRotateFiles must still empty
// the directory of whatever survived the prune.
func TestCleanupBenchRotateFiles_BoundedMaxBackups(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "rotate-cleanup-bounded-test.log")
	w := driveWriterRotations(t, path, false, 2)
	// Sync so the bench's "Close drains mill" precondition matches.
	require.NoError(t, w.Sync())

	cleanupBenchRotateFiles(w, path)

	after, _ := filepath.Glob(globPrefixOf(path))
	assert.Empty(t, after, "cleanup left files behind: %v", after)
}

// TestCleanupBenchRotateFiles_IdempotentSecondCall asserts the
// helper is safe to invoke on a directory it has already emptied
// — no panic, no error, zero removals.
func TestCleanupBenchRotateFiles_IdempotentSecondCall(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "rotate-cleanup-idempotent-test.log")
	w := driveWriterRotations(t, path, false, 0)

	// First cleanup removes everything.
	cleanupBenchRotateFiles(w, path)
	matches, _ := filepath.Glob(globPrefixOf(path))
	require.Empty(t, matches, "first cleanup left files: %v", matches)

	// Second call on the same closed writer over an empty
	// directory must not panic or error. Writer.Close is
	// documented idempotent; filepath.Glob on a no-match prefix
	// returns nil; os.Remove on no files is a no-op.
	cleanupBenchRotateFiles(w, path)
	matches2, _ := filepath.Glob(globPrefixOf(path))
	assert.Empty(t, matches2, "second cleanup left files: %v", matches2)
}

// TestCleanupBenchRotateFiles_NoRotationsActiveOnly covers the
// degenerate case: a single write below the rotate threshold
// leaves only the active file. Cleanup must still remove it.
func TestCleanupBenchRotateFiles_NoRotationsActiveOnly(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "rotate-cleanup-active-only-test.log")
	w, err := rotate.New(path, rotate.Config{
		MaxSize:     1 << 30, // 1 GiB — single write will not rotate
		MaxBackups:  0,
		Mode:        0o600,
		SyncOnWrite: false,
	})
	require.NoError(t, err)
	_, err = w.Write([]byte("single line\n"))
	require.NoError(t, err)
	require.NoError(t, w.Sync())

	before, _ := filepath.Glob(globPrefixOf(path))
	require.Len(t, before, 1,
		"setup: expected exactly 1 file (active only), got %v", before)

	cleanupBenchRotateFiles(w, path)

	after, _ := filepath.Glob(globPrefixOf(path))
	assert.Empty(t, after, "cleanup left files behind: %v", after)
}
