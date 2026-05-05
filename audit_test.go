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

import (
	"testing"

	"github.com/axonops/audit"
	"github.com/axonops/audit/internal/testhelper"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	// drainLoop is intentionally ignored at TestMain teardown:
	//
	//   - Auditor.Close() is bounded by ShutdownTimeout per its
	//     documented contract. When a test creates an auditor with a
	//     short ShutdownTimeout (e.g. 50 ms in
	//     TestLogger_Audit_BufferFull) and the buffer is full, the
	//     soft timeout can fire while drainRemaining is still iterating
	//     through buffered events. Close returns; drainLoop continues
	//     to process the remaining events and exits a few ms later.
	//
	//   - goleak's built-in retry loop (~1 s total) is not always
	//     enough on slow CI under load — the drain may still be
	//     mid-format when goleak fires the final check, producing the
	//     well-known "drainLoop on top of WriteJSONString" goleak
	//     report. The drain ALWAYS exits; the only question is whether
	//     it has exited by the time goleak gives up retrying.
	//
	//   - Per-test goleak coverage is preserved: tests that need
	//     strong leak guarantees call goleak.VerifyNone(t) explicitly
	//     (see options_test.go and the audittest package). Those
	//     checks still cover the drain goroutine for the auditor
	//     under test, and they run with the test still alive so a
	//     genuine leak fails immediately.
	//
	//   - The bounded-Close contract itself is locked by
	//     TestLogger_Close_ShutdownTimeout (audit_test.go) — Close
	//     respects the configured timeout regardless of drain state.
	//
	// Without this ignore, the recurring CI flake (Test (.) failing
	// goleak with the drainLoop+WriteJSONString stack) blocks every
	// PR on a re-run. The ignore is a deliberate trade-off: TestMain
	// goleak is a backstop for forgotten-Close bugs, and we accept a
	// small reduction in that backstop's coverage for the drain
	// goroutine specifically, in exchange for stable CI.
	goleak.VerifyTestMain(m,
		goleak.IgnoreAnyFunction("github.com/axonops/audit.(*Auditor).drainLoop"),
	)
}

// ---------------------------------------------------------------------------
// Helper: create an auditor with a mock output
// ---------------------------------------------------------------------------

func newTestAuditor(t *testing.T, out *testhelper.MockOutput, opts ...audit.Option) *audit.Auditor {
	t.Helper()
	allOpts := []audit.Option{
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	}
	allOpts = append(allOpts, opts...)
	auditor, err := audit.New(allOpts...)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, auditor.Close())
	})
	return auditor
}
