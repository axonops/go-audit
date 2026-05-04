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

//go:build unix

package file

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"github.com/axonops/audit"
)

// validateExistingFilePerms enforces that, when an audit log file
// already exists at path, its on-disk permissions and metadata cannot
// silently widen the configured target mode. Three classes of
// rejection (#436):
//
//  1. Special bits (setuid, setgid, sticky) — never legitimate on an
//     audit log; treat their presence as a tamper indicator.
//  2. Hardlink count > 1 — the audit data exists at a second path
//     under different ownership/perms and would survive a re-chmod
//     of the configured path.
//  3. Permissions broader than the target — `existing & ^target != 0`
//     means existing has at least one bit set that the target does
//     not. Narrower-or-equal is safe (a 0o600 file with
//     GroupReadable=true accepts; a 0o640 file with GroupReadable=
//     false rejects because the group-read bit is broader).
//
// Returns nil when the file does not exist (it will be created with
// the target mode by safeOpen) or when all three checks pass.
//
// Note on race window: between this Lstat and the writeLoop's first
// safeOpen, an attacker with write access could chmod the file
// broader. Acceptable per the threat model — write access defeats
// every audit-integrity guarantee — and safeOpen calls f.Chmod(target)
// on every open, narrowing the window. The startup check exists to
// fail-loud on misconfiguration, not to defend against an active
// attacker who already has chmod rights.
func validateExistingFilePerms(path string, target os.FileMode) error {
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil // file doesn't exist yet — will be created with target mode
		}
		// Other errors (permission denied on the parent dir, etc.)
		// fall through to the rotate writer's open path which will
		// produce its own error. We don't want to double-report.
		return nil
	}

	mode := info.Mode()

	// Symlinks are rejected downstream by safeStat/safeOpen via
	// O_NOFOLLOW. Don't double-report here — and a symlink's own
	// permissions are 0o777 by convention, which would falsely
	// trip the broader-than-target check below.
	if mode&os.ModeSymlink != 0 {
		return nil
	}

	// (1) Special bits never legitimate on an audit log.
	if mode&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return fmt.Errorf("audit: file output %q: existing file has setuid/setgid/sticky bits set (mode %v): %w",
			path, mode, audit.ErrConfigInvalid)
	}

	// (2) Hardlink count > 1 means the audit data exists under a
	// second path. Even if we narrow the configured path's perms,
	// the alternate path retains its own ownership and mode.
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Nlink > 1 {
		return fmt.Errorf("audit: file output %q: existing file has hardlink count %d (must be 1): %w",
			path, stat.Nlink, audit.ErrConfigInvalid)
	}

	// (3) Permissions broader than the target.
	perm := mode.Perm()
	if perm&^target != 0 {
		return fmt.Errorf("audit: file output %q: existing file permissions %04o are broader than required %04o: %w",
			path, perm, target, audit.ErrConfigInvalid)
	}
	return nil
}
