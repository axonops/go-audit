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
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/cucumber/godog"
)

// registerFileFailureSteps wires the OS-level failure-mode scenarios
// added in #748: ENOSPC (via privileged Docker tmpfs), EMFILE (via
// subprocess fork with low RLIMIT_NOFILE), and EACCES (via in-process
// chmod after rotation). The MockFileMetrics extension landing in
// the same PR (file_steps.go) records the async RecordError calls
// these scenarios assert on.
func registerFileFailureSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	registerEACCESSteps(ctx, tc)
	registerEMFILESteps(ctx, tc)
	registerENOSPCSteps(ctx, tc)
}

// --- Shared helpers ---

// pollMetricsCount waits up to deadline for `pred` to return true.
// Used by all three failure-mode scenarios — the writeLoop is async,
// so a synchronous "expect N errors right now" check would race the
// goroutine. Mirrors the existing audittest-style polling pattern.
func pollMetricsCount(deadline time.Duration, pred func() bool) error {
	const tick = 20 * time.Millisecond
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		if pred() {
			return nil
		}
		time.Sleep(tick)
	}
	return fmt.Errorf("metric condition not satisfied within %s", deadline)
}

// --- EACCES (perm-denied after rotation) ---
//
// The cleanest in-process pattern is rotation-observed-then-chmod:
//   1. Configure file output with small MaxSizeMB and MockFileMetrics.
//   2. Write enough events to trigger ONE rotation.
//   3. Poll until MockFileMetrics.Rotations() >= 1 — proves the
//      writeLoop has fully consumed the pre-chmod batch.
//   4. chmod the directory 0o555.
//   5. Write enough to trigger ANOTHER rotation. The rotate path
//      calls os.Rename (fails with EACCES on a 0o555 dir; the
//      directory's write bit is required to add/remove entries).
//   6. Poll until MockFileMetrics.ErrorCount() >= 1.
//   7. Cleanup: chmod the dir back to 0o755 so t.TempDir cleanup
//      succeeds.

func registerEACCESSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^the audit log directory is made read-only$`, func() error {
		if tc.FileDir == "" {
			return fmt.Errorf("no file directory captured — did the auditor get created?")
		}
		// Re-chmod on cleanup so t.TempDir can remove the directory.
		// 0o555 is the test contract (write bit removed → EACCES on
		// rotation) — explicitly NOT a production permission.
		tc.AddCleanup(func() { _ = os.Chmod(tc.FileDir, 0o755) }) //nolint:gosec // test cleanup, restores tmpdir for goroutine cleanup
		if err := os.Chmod(tc.FileDir, 0o555); err != nil {       //nolint:gosec // test contract: removing write bit forces EACCES
			return fmt.Errorf("chmod read-only: %w", err)
		}
		return nil
	})

	ctx.Step(`^I wait for at least (\d+) file rotation\(s\)$`, func(n int) error {
		if tc.FileMetrics == nil {
			return fmt.Errorf("mock file metrics not configured")
		}
		return pollMetricsCount(5*time.Second, func() bool {
			return tc.FileMetrics.Rotations() >= n
		})
	})

	ctx.Step(`^the file output should record at least (\d+) error\(s\)$`, func(n int) error {
		if tc.FileMetrics == nil {
			return fmt.Errorf("mock file metrics not configured")
		}
		// Allow up to 5 s for the writeLoop's failed rotation +
		// RecordError to land. The rotate path is async; immediate
		// inspection races the goroutine.
		if err := pollMetricsCount(5*time.Second, func() bool {
			return tc.FileMetrics.ErrorCount() >= n
		}); err != nil {
			return fmt.Errorf("expected >= %d errors; got %d: %w",
				n, tc.FileMetrics.ErrorCount(), err)
		}
		return nil
	})
}

// --- EMFILE (open-file-limit on rotation) ---
//
// The fd-limit scenario shells out to a small helper binary at
// tests/bdd/cmd/file-emfile-runner/main.go that:
//   1. Constructs an audit.Auditor with file output + MockFileMetrics
//      under a temp dir.
//   2. Writes a few events to force the writeLoop's first openNew
//      (active log file consumes 1 fd).
//   3. Reads /proc/self/fd to get the live count, then opens dummy
//      fds to /dev/null up to (limit - 1).
//   4. Calls syscall.Setrlimit(RLIMIT_NOFILE, baseline+1) so the
//      next openNew exceeds the cap by exactly 1.
//   5. Closes the active log file (rotate path: closes existing
//      fd) and writes a rotation-triggering payload. openNew now
//      hits EMFILE; om.RecordError fires.
//   6. Exit 0 if RecordError count >= 1, exit 1 otherwise.
//
// The BDD step builds the helper via `go run ./tests/bdd/cmd/...`
// to avoid a build artefact and to share the audit module via
// go.work resolution. RLIMIT_NOFILE testing is Linux-specific
// (/proc/self/fd path); the @linux tag scopes the scenario.

func registerEMFILESteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	_ = tc // unused — runner is hermetic, owns its own auditor + fs
	ctx.Step(`^I run the file-emfile subprocess$`, func() error {
		// Repo root is two levels up from tests/bdd/steps/.
		repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
		if err != nil {
			return fmt.Errorf("resolve repo root: %w", err)
		}
		cmd := exec.Command("go", "run", "./tests/bdd/cmd/file-emfile-runner")
		cmd.Dir = repoRoot
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("file-emfile runner failed: %w\noutput:\n%s", err, out)
		}
		if !strings.Contains(string(out), "EMFILE_OBSERVED") {
			return fmt.Errorf("file-emfile runner did not observe EMFILE; output:\n%s", out)
		}
		return nil
	})
}

// --- ENOSPC (disk full via privileged Docker + tmpfs) ---
//
// A standalone privileged docker-compose service (tests/bdd/
// docker-compose.file-os.yml) mounts a tmpfs of fixed size at
// /audit-test-tmpfs and idles via `sleep infinity`. The BDD step
// shells `docker compose exec` to run the file-failure-runner inside
// the container, which writes events to a path on the size-limited
// tmpfs. Once the tmpfs is full, writes return ENOSPC and the
// runner reports EMFILE_OBSERVED-style stdout markers + exit 0.
//
// The scenario is gated by `@linux @docker` Gherkin tags so it skips
// on non-Linux runners or environments without docker available.

func registerENOSPCSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	_ = tc
	ctx.Step(`^the file-os tmpfs container is up$`, func() error {
		// Sanity-check: the docker-compose service is reachable.
		// `make test-infra-file-os-up` is the prerequisite (mirrors
		// the test-infra-syslog-up pattern). The check fails fast
		// with a useful error if the harness wasn't started.
		out, err := exec.Command("docker", "ps", "--filter", "name=audit-file-os", "--format", "{{.Names}}").CombinedOutput()
		if err != nil {
			return fmt.Errorf("docker ps failed: %w (run `make test-infra-file-os-up`)", err)
		}
		if !strings.Contains(string(out), "audit-file-os") {
			return fmt.Errorf("audit-file-os container not running (run `make test-infra-file-os-up`)\ndocker ps output:\n%s", out)
		}
		return nil
	})

	ctx.Step(`^I run the ENOSPC test inside the file-os container$`, func() error {
		repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
		if err != nil {
			return fmt.Errorf("resolve repo root: %w", err)
		}
		// `go run` resolves the repo via the bind-mount /workspace
		// declared in docker-compose.file-os.yml.
		cmd := exec.Command("docker", "compose",
			"-f", "tests/bdd/docker-compose.file-os.yml",
			"exec", "-T", "audit-file-os",
			"go", "run", "./tests/bdd/cmd/file-enospc-runner")
		cmd.Dir = repoRoot
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("ENOSPC runner failed: %w\noutput:\n%s", err, out)
		}
		if !strings.Contains(string(out), "ENOSPC_OBSERVED") {
			return fmt.Errorf("ENOSPC runner did not observe ENOSPC; output:\n%s", out)
		}
		return nil
	})
}
