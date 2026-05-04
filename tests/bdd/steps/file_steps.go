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

package steps

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cucumber/godog"

	"github.com/axonops/audit"
	"github.com/axonops/audit/file"
)

func registerFileSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	registerFileGivenSteps(ctx, tc)
	registerFileWhenSteps(ctx, tc)
	registerFileThenSteps(ctx, tc)
	registerFileFailureSteps(ctx, tc)
}

func registerFileGivenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^an auditor with file output at a temporary path$`, func() error {
		return createFileAuditor(tc, file.Config{})
	})
	ctx.Step(`^an auditor with file output with permissions "([^"]*)"$`, func(perms string) error {
		return createFileAuditor(tc, file.Config{Permissions: perms})
	})
	ctx.Step(`^an auditor with file output configured for (\d+) MB max size$`, func(mb int) error {
		return createFileAuditor(tc, file.Config{MaxSizeMB: mb})
	})
	ctx.Step(`^an auditor with file output configured for (\d+) MB max size with compression$`, func(mb int) error {
		compress := true
		return createFileAuditor(tc, file.Config{MaxSizeMB: mb, Compress: &compress})
	})
	ctx.Step(`^an auditor with file output configured for (\d+) MB max size without compression$`, func(mb int) error {
		compress := false
		return createFileAuditor(tc, file.Config{MaxSizeMB: mb, Compress: &compress})
	})
	ctx.Step(`^an auditor with file output configured for (\d+) MB max size and max backups (\d+)$`, func(mb, backups int) error {
		return createFileAuditor(tc, file.Config{MaxSizeMB: mb, MaxBackups: backups})
	})
	ctx.Step(`^at most (\d+) files should exist in the output directory$`, func(maxFiles int) error {
		if tc.Auditor != nil {
			_ = tc.Auditor.Close()
		}
		dir := tc.FileDir
		entries, err := os.ReadDir(dir)
		if err != nil {
			return fmt.Errorf("read dir: %w", err)
		}
		count := 0
		for _, e := range entries {
			if !e.IsDir() {
				count++
			}
		}
		if count > maxFiles {
			return fmt.Errorf("expected at most %d files, got %d", maxFiles, count)
		}
		return nil
	})

	ctx.Step(`^an auditor with file output configured for (\d+) MB max size with file metrics$`, func(mb int) error {
		tc.FileMetrics = &MockFileMetrics{}
		return createFileAuditorWithMetrics(tc, file.Config{MaxSizeMB: mb}, tc.FileMetrics)
	})
	ctx.Step(`^mock file metrics are configured$`, func() error {
		tc.FileMetrics = &MockFileMetrics{}
		return nil
	})
	ctx.Step(`^an auditor with file output at a temporary path and short drain timeout$`, func() error {
		return createFileAuditorWithExtraOpts(tc, file.Config{}, audit.WithShutdownTimeout(100*time.Millisecond))
	})
	ctx.Step(`^closing the auditor should complete within (\d+) seconds$`, func(maxSecs int) error {
		if tc.Auditor == nil {
			return fmt.Errorf("no auditor to close")
		}
		done := make(chan error, 1)
		go func() { done <- tc.Auditor.Close() }()
		select {
		case <-done:
			return nil
		case <-time.After(time.Duration(maxSecs) * time.Second):
			return fmt.Errorf("Close() did not return within %d seconds", maxSecs)
		}
	})
	ctx.Step(`^an auditor with no outputs$`, func() error { return createNoOutputAuditor(tc) })

}

func registerFileWhenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^I audit (\d+) events rapidly$`, func(n int) error { return auditNEvents(tc, n) })
	ctx.Step(`^I audit (\d+) events from (\d+) concurrent goroutines$`, func(total, goroutines int) error {
		return auditConcurrent(tc, total, goroutines)
	})
	ctx.Step(`^I write enough events to exceed (\d+) MB$`, func(mb int) error { return writeEventsExceeding(tc, mb) })
	ctx.Step(`^I write a single event to a file output configured with a symlink path$`,
		func() error { return writeToSymlinkFileOutput(tc) })
	ctx.Step(`^I try to create a file output with empty path$`, func() error { return tryFileOutputWithPath(tc, "") })
	ctx.Step(`^I try to create a file output with MaxSizeMB (\d+)$`, func(mb int) error {
		out, err := file.New(&file.Config{Path: "/tmp/test.log", MaxSizeMB: mb})
		if out != nil {
			tc.AddCleanup(func() { _ = out.Close() })
		}
		tc.LastErr = err
		return nil
	})
	ctx.Step(`^I try to create a file output at "([^"]*)"$`, func(path string) error { return tryFileOutputWithPath(tc, path) })
	ctx.Step(`^I try to create a file output with MaxBackups (\d+)$`, func(mb int) error {
		out, err := file.New(&file.Config{Path: "/tmp/test.log", MaxBackups: mb})
		if out != nil {
			tc.AddCleanup(func() { _ = out.Close() })
		}
		tc.LastErr = err
		return nil
	})
	ctx.Step(`^I try to create a file output with permissions "([^"]*)"$`, func(perms string) error {
		dir, dirErr := tc.EnsureFileDir()
		if dirErr != nil {
			return dirErr
		}
		out, err := file.New(&file.Config{Path: filepath.Join(dir, "test.log"), Permissions: perms})
		if out != nil {
			tc.AddCleanup(func() { _ = out.Close() })
		}
		tc.LastErr = err
		return nil
	})

}

func registerFileThenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	registerFileThenBasicSteps(ctx, tc)
	registerFileThenValidationSteps(ctx, tc)
}

func registerFileThenBasicSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^the file should contain exactly (\d+) events$`, func(n int) error { return assertFileEventCount(tc, "default", n) })
	ctx.Step(`^the file should contain an event with event_type "([^"]*)"$`, func(et string) error { return assertFileHasEventType(tc, et) })
	ctx.Step(`^every event in the file should be valid JSON$`, func() error { return assertFileAllValidJSON(tc) })
	ctx.Step(`^the file should contain events$`, func() error { return assertFileHasAnyEvents(tc) })
	ctx.Step(`^I close the auditor again$`, func() error { return closeLoggerAgain(tc) })
	ctx.Step(`^the second close should return no error$`, func() error { return assertLastErrNil(tc) })
	ctx.Step(`^the file should have permissions "([^"]*)"$`, func(perms string) error { return assertFilePermissions(tc, perms) })
	ctx.Step(`^I close the auditor from (\d+) goroutines concurrently$`, func(count int) error {
		var wg sync.WaitGroup
		for range count {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = tc.Auditor.Close()
			}()
		}
		wg.Wait()
		return nil
	})
	ctx.Step(`^no panic should have occurred$`, func() error {
		// If we got here, no panic occurred.
		return nil
	})

	ctx.Step(`^a backup file with a timestamp pattern should exist in the output directory$`, func() error {
		if tc.Auditor != nil {
			_ = tc.Auditor.Close()
		}
		entries, readErr := os.ReadDir(tc.FileDir)
		if readErr != nil {
			return fmt.Errorf("read dir: %w", readErr)
		}
		// Backup files have format: audit-YYYY-MM-DDTHH-MM-SS.SSS.log
		for _, e := range entries {
			name := e.Name()
			if name != "audit.log" && strings.Contains(name, "audit") && len(name) > 15 {
				return nil // Found a backup with timestamp
			}
		}
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		return fmt.Errorf("no backup file with timestamp found (files: %v)", names)
	})
}

func registerFileThenValidationSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^the file output construction should fail with error:$`, func(doc *godog.DocString) error {
		expected := strings.TrimSpace(doc.Content)
		if tc.LastErr == nil {
			return fmt.Errorf("expected error:\n  %q\ngot: nil", expected)
		}
		if tc.LastErr.Error() != expected {
			return fmt.Errorf("expected error:\n  %q\ngot:\n  %q", expected, tc.LastErr.Error())
		}
		return nil
	})
	ctx.Step(`^the file output construction should fail with an error$`, func() error {
		if tc.LastErr == nil {
			return fmt.Errorf("expected file output construction error, got nil")
		}
		return nil
	})
	ctx.Step(`^more than one file should exist in the output directory$`, func() error { return assertMultipleFilesInDir(tc) })
	ctx.Step(`^a \.gz backup file should exist in the output directory$`, func() error { return assertGzFileExists(tc) })
	ctx.Step(`^no \.gz files should exist in the output directory$`, func() error { return assertNoGzFiles(tc) })
	ctx.Step(`^the file event should have field "([^"]*)" present$`, func(field string) error { return assertFileEventFieldPresent(tc, field) })
	ctx.Step(`^the file metrics should have recorded at least (\d+) rotations?$`, func(n int) error { return assertFileRotationCount(tc, n) })
	ctx.Step(`^the symlink target file should remain empty$`, func() error { return assertSymlinkTargetEmpty(tc) })
}

// --- Extracted step implementations ---

func createNoOutputAuditor(tc *AuditTestContext) error {
	opts := []audit.Option{
		audit.WithTaxonomy(tc.Taxonomy),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
	}
	auditor, err := audit.New(opts...)
	if err != nil {
		tc.LastErr = err
		return nil //nolint:nilerr // scenario may assert on tc.LastErr
	}
	tc.Auditor = auditor
	tc.AddCleanup(func() { _ = auditor.Close() })
	return nil
}

func auditNEvents(tc *AuditTestContext, count int) error {
	for i := range count {
		fields := defaultRequiredFields(tc.Taxonomy, "user_create")
		fields["marker"] = fmt.Sprintf("rapid_%d", i)
		if err := tc.Auditor.AuditEvent(audit.NewEvent("user_create", fields)); err != nil {
			return fmt.Errorf("audit event %d: %w", i, err)
		}
	}
	return nil
}

func auditConcurrent(tc *AuditTestContext, total, goroutines int) error {
	perGoroutine := total / goroutines
	var wg sync.WaitGroup
	errCh := make(chan error, total)
	for g := range goroutines {
		wg.Add(1)
		go func(gID int) {
			defer wg.Done()
			for i := range perGoroutine {
				fields := defaultRequiredFields(tc.Taxonomy, "user_create")
				fields["marker"] = fmt.Sprintf("g%d_e%d", gID, i)
				if err := tc.Auditor.AuditEvent(audit.NewEvent("user_create", fields)); err != nil {
					errCh <- fmt.Errorf("goroutine %d event %d: %w", gID, i, err)
				}
			}
		}(g)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		return err
	}
	return nil
}

func writeEventsExceeding(tc *AuditTestContext, mb int) error {
	// Each event is roughly 200 bytes. Write enough to exceed target.
	// Tolerate ErrQueueFull — the drain goroutine may not keep up.
	targetBytes := mb * 1024 * 1024
	eventSize := 200
	count := (targetBytes / eventSize) + 100
	for i := range count {
		fields := defaultRequiredFields(tc.Taxonomy, "user_create")
		fields["marker"] = fmt.Sprintf("rot_%d_padding_data_for_size", i)
		err := tc.Auditor.AuditEvent(audit.NewEvent("user_create", fields))
		if err != nil && !errors.Is(err, audit.ErrQueueFull) {
			return fmt.Errorf("write event %d: %w", i, err)
		}
	}
	return nil
}

// writeToSymlinkFileOutput creates a real target file, a symlink pointing
// to it, then writes one event via a file.Output configured with the
// symlink path. file.Output.Write is async, so Close() drains the buffer
// and forces the actual write attempt, which is rejected by the rotate
// package's safeOpen (O_NOFOLLOW on Unix, Lstat on other platforms).
//
// Stashes the symlink-target path in tc for the assertSymlinkTargetEmpty
// Then step to verify the library did not write THROUGH the symlink.
func writeToSymlinkFileOutput(tc *AuditTestContext) error {
	dir, err := tc.EnsureFileDir()
	if err != nil {
		return err
	}
	realPath := filepath.Join(dir, "real.log")
	linkPath := filepath.Join(dir, "link.log")
	if writeErr := os.WriteFile(realPath, nil, 0o600); writeErr != nil {
		return fmt.Errorf("create real file: %w", writeErr)
	}
	if linkErr := os.Symlink(realPath, linkPath); linkErr != nil {
		return fmt.Errorf("create symlink: %w", linkErr)
	}
	tc.SymlinkTargetPath = realPath

	out, err := file.New(&file.Config{Path: linkPath})
	if err != nil {
		return fmt.Errorf("file.New unexpectedly failed at construction: %w", err)
	}
	if writeErr := out.Write([]byte(`{"test":"symlink"}` + "\n")); writeErr != nil {
		return fmt.Errorf("file.Output.Write unexpectedly returned error: %w", writeErr)
	}
	// Close drains the async write buffer, forcing the rejection to
	// happen before the Then step inspects the target file.
	if closeErr := out.Close(); closeErr != nil {
		return fmt.Errorf("file.Output.Close: %w", closeErr)
	}
	return nil
}

// assertSymlinkTargetEmpty verifies the symlink target file was not
// written to. If safeOpen's protection worked, the target stays at zero
// bytes; if the library followed the symlink, the target would contain
// the event payload.
func assertSymlinkTargetEmpty(tc *AuditTestContext) error {
	if tc.SymlinkTargetPath == "" {
		return fmt.Errorf("SymlinkTargetPath not set — did the When step run?")
	}
	info, err := os.Stat(tc.SymlinkTargetPath)
	if err != nil {
		return fmt.Errorf("stat symlink target %q: %w", tc.SymlinkTargetPath, err)
	}
	if info.Size() != 0 {
		return fmt.Errorf("symlink target %q has %d bytes — library followed the symlink (security regression)",
			tc.SymlinkTargetPath, info.Size())
	}
	return nil
}

func tryFileOutputWithPath(tc *AuditTestContext, path string) error {
	out, err := file.New(&file.Config{Path: path})
	if out != nil {
		tc.AddCleanup(func() { _ = out.Close() })
	}
	tc.LastErr = err
	return nil
}

func assertFileHasEventType(tc *AuditTestContext, eventType string) error {
	events, err := readFileEvents(tc, "default")
	if err != nil {
		return err
	}
	for _, e := range events {
		if e["event_type"] == eventType {
			return nil
		}
	}
	return fmt.Errorf("no event with event_type %q in file (%d events)", eventType, len(events))
}

func assertFileAllValidJSON(tc *AuditTestContext) error {
	events, err := readFileEvents(tc, "default")
	if err != nil {
		return err
	}
	if len(events) == 0 {
		return fmt.Errorf("file contains no events")
	}
	return nil
}

func assertFileHasAnyEvents(tc *AuditTestContext) error {
	events, err := readFileEvents(tc, "default")
	if err != nil {
		return err
	}
	if len(events) == 0 {
		return fmt.Errorf("file contains no events")
	}
	return nil
}

func closeLoggerAgain(tc *AuditTestContext) error {
	if tc.Auditor != nil {
		tc.LastErr = tc.Auditor.Close()
	}
	return nil
}

func assertLastErrNil(tc *AuditTestContext) error {
	if tc.LastErr != nil {
		return fmt.Errorf("expected no error, got: %w", tc.LastErr)
	}
	return nil
}

func assertFilePermissions(tc *AuditTestContext, expected string) error {
	if tc.Auditor != nil {
		_ = tc.Auditor.Close()
	}
	path := tc.FilePaths["default"]
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat file: %w", err)
	}
	got := fmt.Sprintf("%04o", info.Mode().Perm())
	if got != expected {
		return fmt.Errorf("expected permissions %s, got %s", expected, got)
	}
	return nil
}

func assertMultipleFilesInDir(tc *AuditTestContext) error {
	dir := tc.FileDir
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read dir: %w", err)
	}
	count := 0
	for _, e := range entries {
		if !e.IsDir() {
			count++
		}
	}
	if count <= 1 {
		return fmt.Errorf("expected more than 1 file in dir, got %d", count)
	}
	return nil
}

func assertGzFileExists(tc *AuditTestContext) error {
	dir := tc.FileDir
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read dir: %w", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".gz") {
			return nil
		}
	}
	return fmt.Errorf("no .gz file found in %s", dir)
}

func assertNoGzFiles(tc *AuditTestContext) error {
	dir := tc.FileDir
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read dir: %w", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".gz") {
			return fmt.Errorf("unexpected .gz file found: %s", e.Name())
		}
	}
	return nil
}

func assertFileEventFieldPresent(tc *AuditTestContext, field string) error {
	events, err := readFileEvents(tc, "default")
	if err != nil {
		return err
	}
	if len(events) == 0 {
		return fmt.Errorf("no events in file")
	}
	if _, ok := events[0][field]; !ok {
		return fmt.Errorf("field %q not present in file event", field)
	}
	return nil
}

func assertFileRotationCount(tc *AuditTestContext, minCount int) error {
	if tc.FileMetrics == nil {
		return fmt.Errorf("no file metrics configured")
	}
	tc.FileMetrics.mu.Lock()
	defer tc.FileMetrics.mu.Unlock()
	if tc.FileMetrics.rotations < minCount {
		return fmt.Errorf("expected at least %d rotations, got %d", minCount, tc.FileMetrics.rotations)
	}
	return nil
}

// --- Auditor construction helpers ---

func createFileAuditor(tc *AuditTestContext, fileCfg file.Config) error {
	return createFileAuditorImpl(tc, fileCfg, nil)
}

func createFileAuditorWithMetrics(tc *AuditTestContext, fileCfg file.Config, fileMetrics *MockFileMetrics) error {
	return createFileAuditorImpl(tc, fileCfg, fileMetrics)
}

func createFileAuditorWithExtraOpts(tc *AuditTestContext, fileCfg file.Config, extraOpts ...audit.Option) error {
	return createFileAuditorImpl(tc, fileCfg, nil, extraOpts...)
}

func createFileAuditorImpl(tc *AuditTestContext, fileCfg file.Config, fileMetrics *MockFileMetrics, extraOpts ...audit.Option) error {
	dir, err := tc.EnsureFileDir()
	if err != nil {
		return err
	}
	if fileCfg.Path == "" {
		fileCfg.Path = filepath.Join(dir, "audit.log")
	}
	tc.FilePaths["default"] = fileCfg.Path

	var fileOpts []file.Option
	if fileMetrics != nil {
		fileOpts = append(fileOpts, file.WithOutputMetrics(fileMetrics))
	}
	fileOut, err := file.New(&fileCfg, fileOpts...)
	if err != nil {
		tc.LastErr = err
		return nil //nolint:nilerr // scenario may assert on tc.LastErr
	}
	tc.AddCleanup(func() { _ = fileOut.Close() })

	opts := []audit.Option{
		audit.WithTaxonomy(tc.Taxonomy),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(fileOut),
	}
	if tc.MockMetrics != nil {
		opts = append(opts, audit.WithMetrics(tc.MockMetrics))
	}
	opts = append(opts, tc.Options...)
	opts = append(opts, extraOpts...)
	auditor, err := audit.New(opts...)
	if err != nil {
		tc.LastErr = err
		return nil //nolint:nilerr // scenario may assert on tc.LastErr
	}
	tc.Auditor = auditor
	tc.AddCleanup(func() { _ = auditor.Close() })
	return nil
}

// readFileEvents reads and parses JSON events from a named file output.
func readFileEvents(tc *AuditTestContext, name string) ([]map[string]any, error) {
	if tc.Auditor != nil {
		_ = tc.Auditor.Close()
	}
	path, ok := tc.FilePaths[name]
	if !ok {
		return nil, fmt.Errorf("no file output named %q", name)
	}
	data, err := os.ReadFile(path) //nolint:gosec // G304: test helper reads from controlled temp path
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read file %q: %w", path, err)
	}
	return parseJSONLines(data)
}

// assertFileEventCount reads and counts events in a named file output.
func assertFileEventCount(tc *AuditTestContext, name string, expected int) error {
	events, err := readFileEvents(tc, name)
	if err != nil {
		return err
	}
	if len(events) != expected {
		return fmt.Errorf("expected %d events in file %q, got %d", expected, name, len(events))
	}
	return nil
}

// --- Mock file metrics ---

// MockFileMetrics captures file rotation events plus async write
// errors so OS-level failure scenarios (#748) can assert on the same
// metric surface that production observability systems consume. It
// embeds [audit.NoOpOutputMetrics] to satisfy [audit.OutputMetrics]
// and additionally implements [file.RotationRecorder] so the file
// output can detect and call RecordRotation via structural typing.
type MockFileMetrics struct {
	audit.NoOpOutputMetrics
	mu        sync.Mutex
	rotations int
	errors    int
}

// RecordRotation satisfies [file.RotationRecorder].
func (m *MockFileMetrics) RecordRotation(_ string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rotations++
}

// RecordError shadows [audit.NoOpOutputMetrics.RecordError] so the
// embedded no-op default does not run; calls are counted for BDD
// assertion. The file output's writeLoop already calls om.RecordError
// on every async write failure (see file/file.go writeBatch), so the
// override is a pure observability extension — no production code
// change.
func (m *MockFileMetrics) RecordError() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.errors++
}

// ErrorCount returns the number of RecordError calls observed.
func (m *MockFileMetrics) ErrorCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.errors
}

// Rotations returns the number of RecordRotation calls observed.
func (m *MockFileMetrics) Rotations() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.rotations
}
