# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Breaking

- [`audit.EventRoute.IncludeCategories`](https://pkg.go.dev/github.com/axonops/audit#EventRoute)
  changes from `map[string]*SeverityRange` to
  `map[string]SeverityRange` (value type, not pointer). The
  canonical "no severity constraint for this category" value
  changes from `nil` (typed-nil pointer) to `SeverityRange{}`
  (zero-value struct). Inner fields `MinSeverity *int` and
  `MaxSeverity *int` remain as pointers (sentinel-nil = no
  bound). YAML configuration is unchanged. The library is
  pre-release; no back-compat shim. (#867 part 1)
- The [`audit.Formatter`](https://pkg.go.dev/github.com/axonops/audit#Formatter)
  interface gains a `ContentType() string` method. Built-in
  formatters implement it (`JSONFormatter` → `application/x-ndjson`,
  `CEFFormatter` → `text/plain`). Third-party `Formatter`
  implementations must add a one-line method returning the MIME
  type of the bytes they emit. The library is pre-release; no
  back-compat shim. (#463)

### Performance

- [`audit.MatchesRoute`](https://pkg.go.dev/github.com/axonops/audit#MatchesRoute)
  inline fast path for the common "include with 1-4 categories"
  routing pattern. Skips the `IncludeCategories` map hash / bucket
  lookup entirely in favour of a 4-element linear scan over an
  inline array populated at route-build time. Combined with a
  precomputed `routeMode` discriminator that replaces three
  `len()`-of-map scans per `MatchesRoute` call, this recovers
  ~80 % of the +112 % regression introduced by #193 (per-category
  severity) on the targeted benchmark:
  `BenchmarkMatchesRoute/include_categories` 6.80 ns → 4.0 ns
  (−41 % vs current main, +25 % vs the 2026-04-21 baseline at
  3.2 ns — see ADR 0007 for why the inline path doesn't fully
  match the original `[]string` linear-scan baseline).
  Three less-common benchmarks (`empty_route`,
  `exclude_categories`, `include_event_types`) regressed by
  0.8–3.8 ns due to the larger `EventRoute` struct footprint —
  accepted trade-off documented in
  [ADR 0007](docs/adr/0007-matchesroute-perf.md). (#867 part 2)

### Added

- New optional output interface
  [`audit.ContentTypeSetter`](https://pkg.go.dev/github.com/axonops/audit#ContentTypeSetter).
  The auditor invokes `SetContentType` on every output that
  implements it at construction time, passing the result of the
  output's effective formatter's `ContentType()`. HTTP outputs
  (webhook) use this to set the request Content-Type header
  correctly per formatter — previously hardcoded to
  `application/x-ndjson` even when the formatter was CEF. Loki
  does not implement this interface because its Content-Type is
  fixed at `application/json` for the Loki push API. (#463)
- 7 new BDD scenarios in `tests/bdd/features/webhook_batching.feature`
  validating the wire-level batched payload structure for both
  JSON and CEF formatters: NDJSON line count + parseability,
  per-event marker order, trailing-newline invariant, single- and
  multi-event CEF bodies with `CEF:0|` prefix, Content-Type
  assertions for JSON and CEF (including a negative assertion
  for the CEF→NDJSON Content-Type bug that this change fixes).
  (#463)

### Fixed

- Webhook output: when a `CEFFormatter` was configured, the
  request `Content-Type` header still claimed
  `application/x-ndjson`, lying to the receiver. The header now
  reflects the formatter's declared type (`text/plain` for CEF).
  Operators who need a different MIME type can still override via
  the output's `headers` configuration. (#463)
- Makefile `test-examples` target was a hard-coded list of 20
  example directories that drifted out of sync with `examples/`
  every time a new example was added (the issue body for #438
  cited "17 examples" when there were 20 — same drift bug).
  Now driven from the auto-discovered `EXAMPLE_MODULES` variable
  so future example additions need zero Makefile change. (#438)

### CI

- New workflow `.github/workflows/release-examples-verify.yml`
  fires on `release: published` (and `workflow_dispatch` for
  manual backfill). For each example under `examples/*`,
  copies it outside the workspace, bumps every
  `github.com/axonops/audit*` require to the published tag via
  `scripts/release/bump-example-deps.sh`, runs `go mod tidy +
  go build` and `go test` if any `*_test.go` files exist.
  Failures aggregated into one dedup'd GitHub issue per release
  tag — so a broken example surfaces immediately as a tracked
  bug rather than as a silent first-impression failure for the
  next consumer doing `go get`. Does NOT block the release;
  runs after publication. (#438)
- New `make verify-examples-published VERSION=v0.1.13` target
  reproduces the CI workflow locally for any published tag —
  same script, same flow, same exit code. Lets a maintainer
  smoke a release before tagging. (#438)
- Project toolchain adds `gotestsum` v1.13.0 for JUnit XML test
  reporting. Every per-module `make test-*` target now accepts a
  `JUNIT_REPORT_FILE=foo.xml` env var that writes a JUnit XML report
  alongside the existing coverage profile when set; with the env var
  unset, behaviour is unchanged. New `cmd/junit-report` tool
  (sibling to `cmd/bdd-report` from #439/#876) converts the JUnit
  XML to standalone HTML or GitHub-flavoured Markdown using the
  same visual style and the same context-aware GFM injection
  defences. The shared rendering helpers (`render.go`, `writer.go`)
  are byte-identical between the two tools, enforced by
  `make check-report-parity`. Cross-platform CI legs now install
  tools so the JUnit pipeline works on macOS and Windows runners
  via a `BINEXT` Makefile suffix that resolves to `.exe` on
  Windows. Local reproduction:
  `JUNIT_REPORT_FILE=/tmp/r.xml make test-core && go run ./cmd/junit-report -input /tmp/r.xml -suite core -format html > r.html`.
  CI workflow integration (artefact uploads + step summary) lands
  in a follow-up PR. (#877)
- BDD CI matrix now publishes per-suite HTML and Markdown report
  artefacts (`bdd-report-<suite>` HTML, `bdd-report-<suite>-md`
  Markdown) alongside the existing scenario-count artefact, and
  inlines a Markdown failure summary into the GitHub Actions step
  summary panel so reviewers see what broke without downloading
  anything. Each HTML report is a self-contained file: features
  grouped, scenarios collapsible via native `<details>`/`<summary>`,
  failed scenarios highlighted, step-level status + duration,
  error messages with `<pre>` formatting and HTML escaping. The
  Markdown variant targets GitHub-flavoured Markdown — inline
  HTML `<details>`/`<summary>` render natively on github.com and
  in step summaries. Generated from godog's cucumber JSON output
  by a new `cmd/bdd-report` tool — pure stdlib (`encoding/json`,
  `html/template`, hand-written Markdown renderer with separate
  GFM-aware escape for body context and HTML escape for `<summary>`
  context). The cucumber JSON is opt-in via the new `BDD_REPORT_FILE`
  env var; the existing pretty-printed CI log output is preserved.
  Local reproduction:
  `BDD_REPORT_FILE=/tmp/r.json make test-bdd-core && go run ./cmd/bdd-report -input /tmp/r.json -suite core -format markdown > r.md`.
  The step-summary path uses a separate `-only-failures` invocation
  that pre-truncates and emits a `> Download the bdd-report-<suite>-md
  artefact` footer when the GitHub Actions 1 MiB step-summary cap is
  hit (the full report is always available via the artefact download).
  (#439)

### Changed

- Core now depends on `github.com/axonops/syncmap v1.0.0` for the
  `filterState` lock-free category/event-type lookups, replacing the
  15-line inlined `syncMapBool` wrapper added in #588. The fork is
  AxonOps-controlled (Apache 2.0, signed releases, CI / CodeQL /
  Dependabot / SECURITY.md) so the supply-chain acceptance criteria
  tracked by #158 are self-imposed rather than requested upstream.
  Hot-path benchmark `BenchmarkFilterCheck` is unchanged within
  noise (16.74 ns → 16.72 ns, p=0.841). Upstream attribution is
  preserved in the fork's NOTICE.

## [0.1.13] - 2026-05-12

Mostly release-engineering and example-hygiene. No library API changes.

### Added

- Standalone `go.mod` for every example under `examples/` (#437).
  Examples 01-16, 18, 19 previously compiled only as part of the
  parent `audit` module via `go.work`; now each is its own Go
  module and gets transitive-dep updates via the nightly
  `dependency-update` workflow. The first release where this
  matters: example go.mods that require `audit v0.1.13` now
  build standalone with `GOWORK=off`, because v0.1.13's audit
  tarball excludes `examples/01-16/` (they have their own
  go.mod at this tag's SHA).
- New `make lint-examples` aggregate target that loops over
  every `examples/*/go.mod`. Replaces the single-purpose
  `make lint-capstone`; new examples with a `go.mod` are picked
  up automatically.

### Changed

- `scripts/release/update-deps.sh` loops over `examples/*/go.mod`
  rather than hardcoding `examples/17-capstone`. New examples
  with a `go.mod` are picked up automatically at release time.
- `.github/workflows/dependency-update.yml` MODULES list (5
  occurrences) extended with all 20 example directories.
- Go toolchain bumped to `1.26.3` for new stdlib vulnerabilities
  GO-2026-4971 + GO-2026-4918 (#832).
- Release workflow hardening discovered while cutting v0.1.12 —
  see #841 for the catalogue of follow-up PRs and tracking of
  proper App-signed commits.

### Fixed

- `outputconfig`: "unknown output type" error no longer embeds
  the user-supplied type name unquoted in the suggested per-output
  import path — found by `FuzzOutputConfigLoad` on a NUL byte
  (#833). Regression test added to
  `outputconfig/testdata/fuzz/FuzzOutputConfigLoad/`.

## [0.1.12] - 2026-05-07

> See [`docs/v1-changes.md`](docs/v1-changes.md) for a consolidated
> Before/After reference table of every public-API rename, YAML
> field rename, signature change, removal, and new error sentinel
> introduced during v1.0 work. Useful for anyone who experimented
> with a pre-v1.0 build informally — the per-issue entries below
> remain the authoritative source of rationale and behaviour notes.

### Breaking Changes

- **File output permissions restricted to `0o600` (default) or `0o640`
  (group-readable)** (#436). The flexible `Permissions string`
  Config field is removed; the YAML `permissions:` key is removed.
  Replaced by `Config.GroupReadable bool` (YAML: `group_readable:
  true`). Audit logs are not regular application logs — they contain
  compliance-critical data subject to SOX/HIPAA/GDPR
  tamper-resistance — and the prior `0–0o777` flexibility allowed a
  misconfig to publish audit data world-readable. Two modes are
  supported: `0o600` (owner only; the strictest default) and
  `0o640` (owner read/write + group read; for SIEM forwarders
  running as a separate user in the file's group). World-readable,
  world-writable, and group-writable modes are unsupported and
  reject at startup.

  At construction, [`file.New`] now also rejects an existing audit
  log at the configured path whose on-disk permissions are broader
  than the target mode, whose setuid/setgid/sticky bits are set, or
  whose hardlink count exceeds 1 — all are tamper indicators. Errors
  wrap [`audit.ErrConfigInvalid`].

  **Before**
  ```yaml
  outputs:
    audit_log:
      type: file
      config:
        path: /var/log/audit/events.log
        permissions: "0600"   # also accepted "0644", "0666", "0777" — silent compliance hazard
  ```

  **After**
  ```yaml
  outputs:
    audit_log:
      type: file
      config:
        path: /var/log/audit/events.log
        # Default 0o600 — no field needed.
  ```

  ```yaml
  outputs:
    siem_archive:
      type: file
      config:
        path: /var/log/audit/siem.log
        group_readable: true   # mode 0o640 for the SIEM forwarder
  ```

  **Migration**

  | Old YAML | New YAML |
  |---|---|
  | `permissions: "0600"` | _omit; default is 0o600_ |
  | `permissions: "0640"` | `group_readable: true` |
  | `permissions: "0644"` (or any broader) | unsupported — fix the deployment to `0o600` or `0o640` |

  Operators with existing audit logs at broader modes must `chmod` them
  before the next startup or the library will refuse to open them.
  `outputconfig.Load` produces an `unknown field "permissions"` decode
  error on the legacy key, naming the rejected field for the operator.

- **Collapse output setter interfaces into `audit.FrameworkContext`** (#696).
  The `OutputFactory` signature drops `coreMetrics` and `logger`
  positional parameters and gains all construction-time data via the
  unified context value. The optional setter interfaces
  (`FrameworkFieldReceiver`, `DiagnosticLoggerReceiver`,
  `OutputMetricsReceiver`) and the `Auditor.SetLogger` runtime swap
  API are removed.

  **Before**

  ```go
  type OutputFactory func(name string, rawConfig []byte,
      coreMetrics audit.Metrics, logger *slog.Logger,
      fctx audit.FrameworkContext) (audit.Output, error)

  // Output then implemented one or more of:
  //   SetFrameworkFields(appName, host, timezone string, pid int)
  //   SetDiagnosticLogger(l *slog.Logger)
  //   SetOutputMetrics(m audit.OutputMetrics)
  // and outputconfig/audit invoked them post-construction.
  ```

  **After**

  ```go
  type OutputFactory func(name string, rawConfig []byte,
      fctx audit.FrameworkContext) (audit.Output, error)

  // FrameworkContext now carries every construction-time value:
  //   AppName, Host, Timezone, PID
  //   DiagnosticLogger *slog.Logger
  //   OutputMetrics    audit.OutputMetrics
  //   CoreMetrics      audit.Metrics
  //
  // Outputs accept these via their own constructor (e.g.
  // file.New(cfg, file.WithOutputMetrics(m), file.WithDiagnosticLogger(l)))
  // and store them as immutable fields. There is no post-
  // construction setter and no atomic indirection on the hot path.
  ```

  **Migration**
  - Custom factories: drop the `coreMetrics, logger` parameters; read
    `fctx.CoreMetrics`, `fctx.DiagnosticLogger`, `fctx.OutputMetrics`,
    `fctx.AppName`, `fctx.Host`, `fctx.Timezone`, `fctx.PID` from the
    `FrameworkContext` instead. Apply nil defaults either at use site
    (`if l := fctx.DiagnosticLogger; l == nil { l = slog.Default() }`)
    or once at construction inside your `New` (e.g. inside the option
    resolution function). The built-in outputs use the latter pattern
    — both are valid; do NOT mutate `fctx` to backfill defaults.
  - Custom outputs: replace `SetFrameworkFields` /
    `SetDiagnosticLogger` / `SetOutputMetrics` methods with new
    `WithFrameworkContext` / `WithDiagnosticLogger` /
    `WithOutputMetrics` Options on your constructor, and store the
    resolved values as plain immutable fields.
  - Direct-Go consumers calling `Auditor.SetLogger(l)` after
    construction must rebuild the auditor to redirect diagnostics —
    `WithDiagnosticLogger` is the only entry point.

### Added

- **OS-level failure-mode BDD coverage for file output** (#748) — three new scenarios in `tests/bdd/features/file_output.feature` exercise the file output's `OutputMetrics.RecordError` surface against real filesystem failures: directory-becomes-read-only after one rotation (in-process via `chmod 0o555`), open-file-limit exhaustion on rotation (subprocess fork in `tests/bdd/cmd/file-emfile-runner` lowering `RLIMIT_NOFILE` below the live count), and disk-full / `ENOSPC` (privileged Docker harness `tests/bdd/docker-compose.file-os.yml` with a 256 KiB tmpfs; runner at `tests/bdd/cmd/file-enospc-runner`). The `MockFileMetrics` extension in `tests/bdd/steps/file_steps.go` adds `RecordError`/`ErrorCount`/`Rotations` accessors that scenarios poll on. New `make test-infra-file-os-up`/`-down` and `make test-bdd-file-os` targets bring up the privileged container and run the `@docker`-tagged scenario. No production-code change — the file output's `writeBatch` already calls `om.RecordError` on every async write failure (`file/file.go`); the PR makes those failures observable from BDD. `docs/output-configuration.md` "Tested file-output OS-level failure modes" table cross-references each scenario.

- **`make soak` — 12-hour pre-release soak benchmark** (#573 / Track F-52). New `tests/soak/` package contains `BenchmarkSoak_MixedOutputs`, gated by the `soak` build tag so it never runs under `go test ./...`. The driver wires file + in-process syslog (TCP) + httptest webhook outputs simultaneously, drives 8 producer goroutines at 5000 events/sec aggregate (`SOAK_RATE`), and samples `runtime.MemStats.HeapAlloc`, `runtime.NumGoroutine()`, GC counters, audit queue depth, and total events / drops every `SOAK_SAMPLE_INTERVAL` (default 1 minute) for `SOAK_DURATION` (default 12 hours). Output: `$SOAK_OUTPUT_DIR/soak-samples-*.csv` (per-sample state) and `soak-summary-*.json` (start / end / peak). End-of-run assertion guards heap and goroutine bounds at 2× start; `goleak.VerifyTestMain` catches leaked goroutines at process exit. `make soak-quick` runs a 1-minute smoke for harness verification before committing to a 12-hour run on the release-prep machine. `BENCHMARKS.md` gains a "Release Soak-Test Summary" section with a per-release template that maintainers populate from the JSON summary; `docs/releasing.md` pre-release checklist mandates the soak run before tagging. CI does NOT run the 12-hour soak — minute budgets and the lack of self-hosted runners make it impractical; the run is operator-owned.

- **Sigstore keyless OIDC signing for release artifacts** (#516) — every release now publishes `checksums.txt.sig` (signature) and `checksums.txt.pem` (short-lived Fulcio certificate bound to the GitHub Actions OIDC identity that produced the release) alongside the existing `checksums.txt`, build-provenance attestation, and binaries. The `signs:` block in `.goreleaser.yml` invokes `cosign sign-blob --yes --oidc-issuer=https://token.actions.githubusercontent.com` against `checksums.txt`; signing the checksum file rather than every binary keeps the signature surface minimal while protecting the cryptographic root of trust for every artifact in the release. The release and goreleaser workflows install a pinned `sigstore/cosign-installer` action before GoReleaser runs, and `actions/attest-build-provenance` now also covers the new `.sig`/`.pem` files. The cosign signature protects `checksums.txt` (and via `sha256sum -c` extends to every binary listed inside it); the existing build-provenance attestation independently proves each binary was built from a specific source commit by that workflow — verify both for a complete chain of custody. `docs/releasing.md` "Verify a Release with Cosign" gives the exact `cosign verify-blob` command (with anchored identity regex, OIDC issuer, and `--certificate-github-workflow-repository` defence-in-depth) plus a copy-paste GitHub Actions snippet for pre-deploy gating. `SECURITY.md` "Artifact Signing (Sigstore Keyless)" documents the supply-chain property and how it composes with the existing `gh attestation verify` flow.

- **`audit.LastDeliveryReporter` interface and `audit.Auditor.LastDeliveryAge(name string) time.Duration`** (#753) — per-output staleness signal so `/healthz` probes can detect a silently-failing async output (TCP half-open, retries exhausted) whose `Output.Write` keeps enqueuing while no batches reach the remote endpoint. Pure additive — outputs that don't implement `LastDeliveryReporter` cause `LastDeliveryAge` to return `0`, the same sentinel used for never-delivered. All five built-in outputs (stdout / file / syslog / webhook / loki) implement the interface; the timestamp updates on **actual delivery success** (post-flush for file, post-write-success for syslog, post-2xx for webhook/loki) and **stays frozen on failure** (retries exhausted, server unreachable, disk error). The `namedOutput` registry wrapper transparently delegates so `WrapOutput`-wrapped outputs behave identically. The wall-clock semantics (`time.Now().UnixNano()`) jump with system clock changes — the example default is 30 s; the practical minimum is 10 s to absorb sub-second NTP slews. Used in `examples/18-health-endpoint/main.go` to extend `/healthz` with the 30 s default `healthzStaleThreshold`. `docs/metrics-monitoring.md` "Health Endpoint" subsection documents the staleness pattern alongside queue saturation.

- **`syslog.Config.TLSHandshakeTimeout`** (#746) — bounds the total TCP dial + TLS handshake budget on every TLS connect (initial `New` and every reconnect). Default `10s` matches `http.DefaultTransport.TLSHandshakeTimeout`; valid range is `100ms–60s`; values outside the range cause `New` to wrap `audit.ErrConfigInvalid`. Without this bound a server that completes the TCP three-way handshake but never sends `ServerHello` would wedge `New` indefinitely. Closes the "stalled handshake — not exercised" gap in `docs/output-configuration.md`. The field is silently ignored on non-TLS networks (`tcp`, `udp`). The new exported constants `DefaultTLSHandshakeTimeout`, `MinTLSHandshakeTimeout`, and `MaxTLSHandshakeTimeout` document the bounds. New BDD scenario "Syslog New returns bounded under a stalled TLS handshake" in `tests/bdd/features/syslog_output.feature` locks the contract.

- `cmd/audit-validate` standalone CLI (#611) — pre-deploy validator for `outputs.yaml`. Closes the G-13 BLOCKER for consumers who want a CI gate on operator config before rollout. Runs the same `outputconfig.Load` pipeline the auditor uses at startup and exits with a distinct code per failure class: `0` valid, `1` parse, `2` schema/usage, `3` semantic. Reads either flag from stdin via `-` (`cat taxonomy.yaml | audit-validate -taxonomy - -outputs prod.yaml`); both as `-` rejected as a usage error.
  - **Offline-only in the default binary**: `ref+vault://...` / `ref+openbao://...` / `ref+file://...` / `ref+env://...` references are rejected as semantic errors (exit 3) because the release binary has no secret providers compiled in. Operators who need live secret resolution build a custom validator binary that blank-imports the appropriate `secrets/...` sub-modules.
  - `-resolve-secrets` is **reserved and rejected** by the default binary with a clear error (exit 2). Without provider blank-imports, accepting the flag would let unresolved literals pass an offline CI gate — a fail-open we explicitly avoid.
  - `-format text` (human-readable, default) / `-format json` (`{"valid":bool,"errors":[{"code","message"}]}`) / `-quiet` (exit-code-only) / `-version` (banner + exit 0). JSON shape is documented; stability is not guaranteed until v1.0.
  - Built and published as a stand-alone binary alongside `audit-gen` via GoReleaser; same `linux/darwin/windows × amd64/arm64` matrix. `main.version` is wired by `-ldflags -X` so `audit-validate -version` traces back to a specific build.
  - Shipped with `docs/validation.md` (CLI reference + pinned GitHub Actions snippet + comparison with `helm lint` / `terraform validate`); 20 unit tests at 94.6% coverage lock every exit-code arm.
  - **API decisions** (locked by api-ergonomics-reviewer pre-coding): standalone `cmd/audit-validate/` sub-module — not a sub-command on audit-gen — because the audience and inputs are different (DevOps vs developers; ops-owned outputs.yaml vs developer-owned taxonomy alone). Stdlib precedent: `gopls` / `goimports` / `stringer` / `vet` are separate small binaries. Long-form `-flag` style (matches `audit-gen`) over `--flag` (no `pflag` dep). `-` sentinel for stdin on either flag (gofmt / kubectl / jq precedent), both-stdin rejected (stdin can be read once).
- `secrets/file/` and `secrets/env/` provider sub-modules (#604) — fills the G-03 BLOCKER for K8s mounted-secret and plain-env consumers (~80% of deployments). Blank-import to register: `_ "github.com/axonops/audit/secrets/file"` / `_ "github.com/axonops/audit/secrets/env"`.
  - **`ref+file:///path/to/secret.txt`** — whole-file content as the secret value (single trailing newline trimmed).
  - **`ref+file:///path/to/secret.json#key.subkey`** — JSON file, dotted-fragment path into nested objects, scalar string leaves only.
  - **`ref+env://VAR_NAME`** — environment variable; POSIX `[A-Z_][A-Z0-9_]*` validation; `os.LookupEnv` distinguishes unset / empty (both are rejected).
  - Path validation enforced: absolute paths required, `..` segments rejected, NUL byte rejected, 1 MiB file size cap. Symlinks ARE followed (Kubernetes `..data` atomic-swap pattern requires it).
  - All errors REDACT the path / variable name — no substring of operator-controlled config appears in error messages (mirrors #486 ParseRef redaction).
  - Stateless providers; concurrent-safe by construction (no shared state). Both pass `-race` under 50-goroutine concurrency tests.
  - SECURITY.md updated: env vars are visible to same-UID processes via `/proc/PID/environ` (recommend file:// or vault for stronger isolation); operator is responsible for filesystem permissions on file-backed secrets.
  - Pre-coding api-ergonomics + security consults locked: support both whole-file and JSON-fragment forms; no caching layer (re-read per Resolve); no permission-mode enforcement (K8s 0644 dominant); reuse of `secrets.ParseRef` via new scheme-aware `validatePathForScheme` helper.
- `secrets.ParseRef` now dispatches path validation by scheme via `validatePathForScheme` (#604). The vault/openbao convention (no leading slash, mandatory `#key` fragment) remains the default; `file://` requires a leading slash and allows an optional fragment; `env://` forbids fragments. Existing vault/openbao references continue to parse with identical semantics.
- `audit.Auditor.SetLogger(l *slog.Logger)` and `audit.Auditor.Logger() *slog.Logger` (#601) — runtime diagnostic-logger swap. Consumers that rebuild their logging stack on config change can now call `SetLogger` to replace the audit library's diagnostic logger without restarting. The new logger is propagated atomically to every output that implements `DiagnosticLoggerReceiver` (built-in: file/syslog/webhook/loki, atomic.Pointer migration from #474). Safe to call concurrently with event emission.
  - **Nil-handling**: `SetLogger(nil)` substitutes `slog.Default()` — readers never see a nil pointer. Matches the existing `WithDiagnosticLogger(nil)` and per-output `SetDiagnosticLogger(nil)` semantics.
  - **Closed/disabled auditors**: SetLogger is a no-op success — pointer is updated, no panic, no error. Matches `slog.SetDefault` precedent.
  - **Implementation**: `Auditor.logger` migrated from `*slog.Logger` to `atomic.Pointer[slog.Logger]`; ~30 read sites updated to `Load()`. Hot-path impact: single relaxed atomic read on x86/arm64 — no measurable cost vs the plain pointer read it replaces.
  - **API decisions** locked by api-ergonomics-reviewer pre-coding: `SetLogger(l)` no return (slog.SetDefault precedent — returning previous invites racy compose-and-restore patterns); paired `Logger() *slog.Logger` getter (slog.Default precedent — pairs setter+getter for library composition); no new optional output interface (existing `DiagnosticLoggerReceiver` already covers the runtime swap unchanged).
- `audit.Auditor.AuditEventContext(ctx, evt) error` (#600) — ctx-aware variant of `AuditEvent`. Cancellation and deadlines are honoured at well-defined boundary points (top of validate path; before async enqueue; before sync deliver-fan-out begins) but NOT threaded into individual `Output.Write` calls or between outputs once fan-out starts. `database/sql.QueryContext` precedent — checks at boundaries, not mid-syscall. The legacy `AuditEvent(evt)` is now a `context.Background()` convenience wrapper.
- `audit.EventHandle.AuditContext(ctx, fields) error` and `audit.EventHandle.AuditEventContext(ctx, evt) error` (#600) — ctx parity on the handle path so consumers who have standardised on EventHandle don't have ctx silently dropped at the handle boundary.
- Ctx-cancelled drops emit a structured diagnostic-log warn line `"audit: event dropped due to context cancellation"` with `event_type` and `cause`; metric increment reuses `Metrics.RecordBufferDrop` per ADR 0005 (no Metrics-interface change). Operators distinguish caller-driven drops from queue-full drops via the slog message text.
- Performance: zero overhead when `ctx.Done() == nil` (Background or TODO). Benchmarks `BenchmarkAudit_AuditEventContext_Background` confirms parity with the legacy `BenchmarkAudit` baseline within 0.2% (437 ns/op vs 436 ns/op). Five additional benchmarks committed (HTTPRequestCtx / PreCancelled / Background_Parallel / Sync_Background / EventHandle_AuditContext_Background).
- API decisions locked by api-ergonomics-reviewer + performance-reviewer pre-coding consults: method name `AuditEventContext` (stdlib `…Context` suffix); ctx as first parameter (Go 1.7 idiom); all four entry points get ctx variants for symmetry; `Output.Write` is NOT changed; ctx-cancelled drops reuse `RecordBufferDrop` (Metrics interface stays at 9 methods per ADR 0005).
- Trace-correlation plumbing (e.g. `trace_id` framework field extracted from ctx) is **deferred to post-v1.0** as a follow-up issue. `slog.Handler.Handle(ctx, record)` precedent — accepts ctx but defines no correlation taxonomy. Consumers who need `trace_id` today read it from ctx in their `EventBuilder` or before calling `AuditEventContext`.
- Middleware now plumbs the request ctx through to `auditInternalDonatedFlagsCtx`, replacing the previous `Auditor.AuditEvent` call path (#600). End-to-end ctx propagation from HTTP handler to audit emit.
- `audit.Sanitizer` interface (#598) — privacy / compliance primitive for content scrubbing. `SanitizeField(key, value) any` runs once per field on every `Audit` / `AuditEvent` call; `SanitizePanic(val) any` runs on the middleware panic-recovery path before re-raise. Register one via `audit.WithSanitizer`; the same instance handles both paths. Sanitised values flow to BOTH the audit event AND the re-raise to outer panic handlers (Sentry, parent recovery middleware), so a single integration scrubs PII / secrets / internal error messages everywhere they could leak.
  - **NoopSanitizer** struct provided as embed-helper; consumers override only the method they care about (http.ResponseWriter adapter pattern).
  - **Failure modes**: SanitizeField panic → field replaced with `audit.SanitizerPanicSentinel` (`"[sanitizer_panic]"`) and key appended to framework field `sanitizer_failed_fields`. SanitizePanic panic → original value used in BOTH audit event AND re-raise (fail-open both paths) and framework field `sanitizer_failed=true` set on the event so SIEM tooling can alert.
  - **Diagnostic-log isolation**: when a Sanitizer panics, the diagnostic logger records ONLY the field key and the value's Go type; raw values are NEVER logged. Locked by hard BDD test that asserts a sentinel "SECRET-PII" string never appears in captured slog output.
  - **Concurrency contract**: implementations MUST be safe for concurrent use; documented godoc + race-detector unit + BDD test.
  - **Performance**: zero overhead when unset (single nil-check per event, hoisted out of the per-field loop). Benchmarks `BenchmarkAudit_NoSanitizer` (baseline) vs `BenchmarkAudit_NilSanitizer` (proves nil-check fast path matches baseline) committed alongside.
  - **API decisions** (locked by api-ergonomics-reviewer + security-reviewer): interface (not callbacks); two methods (not kind-dispatch enum); applies to ALL events (Scope A, not just middleware) — slog.Handler.Handle precedent; runs AFTER validation (avoids re-validation cost; type contract is documentation, not runtime check); single sanitise call per panic propagates same value to audit + re-raise.
  - Documented in new `docs/sanitizer.md` (interface contract, common patterns including drop-by-key / regex masking / hash-and-replace, threat-model section on timing side-channels).
- `audit.Event` interface enriched with three taxonomy-metadata methods (#597): `Description() string`, `Categories() []CategoryInfo`, `FieldInfoMap() map[string]FieldInfo`. Middleware and other consumers can introspect any `Event` they receive without a separate taxonomy reference.
  - **Mutation contract**: returned values are read-only; implementations may share cached state across calls. Callers MUST NOT mutate the slice / map / pointer fields. To consume mutably, copy first.
  - **NewEvent / NewEventKV are taxonomy-agnostic** and return zero values (`""`, `nil`, `nil`) for the new methods. For rich metadata, use generated builders or `Auditor.Handle`.
  - **API decisions** (locked by api-ergonomics-reviewer): Categories returns rich `[]CategoryInfo` — not AC-suggested `[]string` — to preserve severity (stdlib precedent: `slog.Record.Attrs`); interface map method named `FieldInfoMap()` not `FieldInfo()` to coexist with generated builders' typed `FieldInfo() <Event>Fields` struct method (stdlib precedent: `reflect.Type.Field` / `FieldByName`).
- `audit.EventHandle` gains parallel `Description()`, `Categories() []CategoryInfo`, `FieldInfoMap() map[string]FieldInfo` methods (#597). Resolved once at `Auditor.Handle` construction — zero per-call taxonomy lookup. EventHandle deliberately does NOT satisfy `Event` (it's a factory, not an instance — stdlib precedent: `reflect.Type` vs `reflect.Value`).
- `audit.ReservedFieldType` typed enum + `audit.ReservedStandardFieldType(name) (ReservedFieldType, bool)` accessor (#595 B-44). Reports the declared Go value type for each of the 31 reserved standard fields. Constants: `ReservedFieldString`, `ReservedFieldInt`, `ReservedFieldInt64`, `ReservedFieldFloat64`, `ReservedFieldBool`, `ReservedFieldTime`, `ReservedFieldDuration`. Backed by a private canonical map in `std_fields.go`; `ReservedStandardFieldNames()` now derives from the same source. Consumers building taxonomy linters, IDE plugins, or pre-`audit.New` config validators have a programmatic API for type metadata.
- `audit.ErrUnknownFieldType` sentinel error (#595 B-43). Returned by `Auditor.AuditEvent` in strict validation mode when a `Fields` value's Go type is outside the supported vocabulary (`string`, `int`/`int32`/`int64`, `float64`, `bool`, `time.Time`, `time.Duration`, `[]string`, `map[string]string`, `nil`). Discriminate via `errors.Is(err, audit.ErrUnknownFieldType)`. Always wrapped alongside `ErrValidation`. Warn and permissive modes coerce unsupported values via `fmt.Sprintf("%v", v)` instead of returning the error.
- `audit.MinSeverity` / `audit.MaxSeverity` constants (#593 B-27) replace the magic-number `0` / `10` range checks in `filter.go:validateSeverityRange`, `taxonomy.go:clampSeverity`, and `validate_taxonomy.go:checkSeverityRanges`. Godoc on each constant documents the inclusive CEF range semantic. Consumers may use these in their own severity validation to stay aligned with the library's contract.
- `audit.ErrTaxonomyRequired`, `audit.ErrAppNameRequired`, and `audit.ErrHostRequired` sentinel errors (#593 B-41) returned by `audit.New` when the corresponding `WithTaxonomy` / `WithAppName` / `WithHost` is unset (unless `WithDisabled` is also applied). Matches the `outputconfig.Load` YAML-path requirement so programmatic and declarative construction share identical invariants. Discriminate via `errors.Is(err, audit.ErrAppNameRequired)`.
- `audittest.Recorder.WaitForN(tb, n, timeout)` — blocks until at least `n` events have been recorded or the timeout elapses; returns `true` on success, `false` on timeout. Use in async-mode tests (`audittest.WithAsync`) or tests whose service emits from a goroutine. Poll interval is 10 ms, matching `testify/assert.Eventually`. The fast path returns immediately when the target is already reached. Synchronous auditors (the default for `New` / `NewQuick`) do not need `WaitForN` — events are recorded before `AuditEvent` returns; prefer `Count()` / `RequireEvents` there. Closes #566.
- `audittest.WithExcludeLabels(outputName, labels...)` — applies sensitivity-label exclusion to the test recorder, mirroring `audit.WithExcludeLabels` on a named output. Lets consumer tests assert that a compliance output does NOT receive `pii`- or `financial`-labelled fields. `outputName` MUST match the recorder's name (`"recorder"` by default, or whatever was passed to `NewNamedRecorder`) — a mismatch calls `tb.Fatalf` at construction. Multiple calls accumulate labels. Internally, `audittest.New` / `audittest.NewQuick` switch from `audit.WithOutputs(rec)` to `audit.WithNamedOutput(rec, audit.WithExcludeLabels(...))` when any `audittest.WithExcludeLabels` option is present; this is observable only when the option is used. Closes #566.

> **Deviations from #566 AC (accepted):** (1) `audittest.PermissiveTaxonomy()` NOT added — `audittest.QuickTaxonomy()` already exists and fills the same role; adding a second name violates the "one obvious way" principle. (2) `WithExcludedLabels` renamed to `WithExcludeLabels` to match core `audit.WithExcludeLabels` exactly (no "d"). (3) AC named `RecordedEvents.WaitForN` (a type name from the original issue draft that was never implemented in the codebase) — the actual type is `*audittest.Recorder`, so `WaitForN` is a method on `*Recorder`. All three deviations confirmed with api-ergonomics-reviewer.

### Changed

- **`audit.ParseTaxonomyYAML`**: removed the 1 MiB `MaxTaxonomyInputSize` cap (#646). Taxonomy YAML is developer-owned input — typically embedded at compile time via `embed.FS` — so the input-size limit was ceremony rather than defense. A YAML alias bomb amplifies regardless of input size, and `goccy/go-yaml` does not expose an alias-budget guard, so bounding bytes did not stop amplification. The exported `MaxTaxonomyInputSize` constant is removed; large enterprise taxonomies (10 MiB+ with tens of thousands of event types) now parse and validate successfully. The matching pre-validation cap in `cmd/audit-gen` is also removed for consistency. `outputconfig.MaxOutputConfigSize` (1 MiB) is intentionally retained — outputs YAML is ops-controlled and crosses a different trust boundary. Documented under the new "Size and Scale" subsection in `docs/taxonomy-validation.md`. Consumers relying on `audit.MaxTaxonomyInputSize` as a public symbol must remove that reference.

- **Release process**: unified single-tag flow (#513). The legacy three-tier dance (`tag-tier0` → `goreleaser` → `tag-tier1` → `tag-tier2` → `tag-tier3` → `verify` capstone-update) is replaced by one linear workflow: CI gate → `make api-check` (advisory until v1.0) → release PR (single commit pinning every inter-module dep) → branch-protection-respecting auto-merge → tag every published module at the merge SHA → GoReleaser → invariants check. All twelve module tags now point at the same SHA. Release commits go through a normal PR rather than direct push, signed by a dedicated `axonops-release-bot` GitHub App; the long-lived `RELEASE_TOKEN` PAT is retired (see Removed). New triggers: `workflow_dispatch` (primary) and `push: tags: v*` (recovery only — skips PR/tagging, runs goreleaser+verify+invariants idempotently). New Makefile targets: `make api-check` runs `gorelease` for every published module against its most recent tag (advisory pre-v1.0, blocking after — toggled via `inputs.api_check_blocking`); `make check-release-invariants VERSION=...` confirms every published `go.mod` references the released version; `make regen-release-docs` regenerates the module table in `docs/releasing.md` from the canonical `PUBLISH_MODULES` Makefile variable. Setup steps for the GitHub App (creation, permissions, secrets `RELEASE_APP_ID` / `RELEASE_APP_PRIVATE_KEY`, tag-protection allow-list, branch-protection bypass policy, key rotation, leak playbook) documented in `docs/releasing.md`. Also fixes a latent bash-parse bug in the existing `make publish-trigger` / `publish-verify` recipes that mishandled pipe characters in `PUBLISH_MODULES` entries.

- **Release artifacts**: SBOM publishing removed (#514). The library is the primary distribution artifact and library consumers use `go.mod` + the Go module proxy (`proxy.golang.org`) for their dependency manifest — strictly stronger than a published SBOM for a Go library. Auxiliary CLI binaries (`audit-gen`, `audit-validate`) are covered by GitHub build-provenance attestations (`gh attestation verify <artifact> --repo axonops/audit`). Operators wanting an SBOM of a downloaded binary can run `syft scan ./audit-gen` locally — the result is equivalent to what the project would have published. The `make sbom` target remains as a development convenience for inspecting the project's own dependency graph; it is not a release artifact. See [`docs/releasing.md` "Software Bill of Materials"](docs/releasing.md#software-bill-of-materials-sbom) for the full rationale.

- `cmd/audit-gen` now emits `FieldInfoMap() map[string]audit.FieldInfo` on every generated builder (#597). The data mirrors the typed `FieldInfo() <Event>Fields` struct and is emitted as a static map literal — zero runtime cost. All committed `audit_generated.go` files in `examples/` regenerated in the same commit.

- `audit.Fields` value-type validation locked for v1.0 (#595 B-43). The supported vocabulary is `string`, `int`/`int32`/`int64`, `float64`, `bool`, `time.Time`, `time.Duration`, `[]string`, `map[string]string`, and `nil` — see the `Fields` godoc and `docs/taxonomy-validation.md` for the full table. Unsupported values are rejected in strict mode (with the new `ErrUnknownFieldType` sentinel above) and coerced via `fmt.Sprintf("%v", v)` in warn (with a diagnostic-logger warning) and permissive modes. Pre-coding api-ergonomics consult locked the AC list because it matches the YAML `supportedCustomFieldTypes` vocabulary already declared in `taxonomy_yaml.go:218` — runtime contract == YAML schema. `cmd/audit-gen` `standardFieldGoTypes` map extended in lockstep: `start_time` and `end_time` now generate `time.Time` setters (previously `string`), matching the `ReservedFieldTime` declaration. Generated code that uses these setters now imports `"time"` automatically.

- `audit.Metrics` interface shape locked for v1.0 via [ADR 0005](docs/adr/0005-metrics-interface-shape.md) (#594). Kept the existing nine-method shape after api-ergonomics-reviewer rejected both the single-method `Record(MetricEvent)` tagged-union proposal (reintroduces untyped payload + adds a hot-path allocation) and the split `LifecycleMetrics` / `DeliveryMetrics` / `ValidationMetrics` composed-interface proposal (silent-compile footgun when consumers embed two of three no-op partial bases). Nine methods grouped by purpose matches stdlib precedent (`slog.Handler` ×4, `http.ResponseWriter` + optional extensions, `driver.Conn`/`Stmt`/`Rows` 4-6 each). Forward-compatibility policy: new metrics added in v1.x land as separate optional interfaces detected via type assertion on the `Metrics` value (same pattern as `DeliveryReporter` / `file.RotationRecorder` / `syslog.ReconnectRecorder`); consumers embedding `NoOpMetrics` automatically retain no-op implementations. Per-method Prometheus cardinality guidance added to godoc so consumers wiring label vectors see the label-space impact. Capstone Prometheus adapter rewritten using a `vec()` helper and `NoOpMetrics` embedding — the audit-side of `examples/17-capstone/metrics.go` is now 34 lines of significant code (struct + constructor + seven `Record*` methods), comfortably inside the 50-line AC target. New `TestNoOpMetrics_AllMethodsArePresent` locks the forward-compat embed pattern at test time.

- Small API-polish bundle #593:
  - **B-17** TLSPolicy zero-value docs & tests verified — no code change (already documented and tested at `tls_policy.go:19-39`; `TestTLSPolicy_Apply_NilReceiver_DefaultsTLS13` and `TestTLSPolicy_Apply_ZeroValue_DefaultsTLS13` already present).
  - **B-27** Exported `MinSeverity` / `MaxSeverity` severity-range constants; updated four magic-number call sites (`filter.go`, `taxonomy.go`, `validate_taxonomy.go`). See `### Added` above.
  - **B-29** `Auditor.Handle` godoc now documents that a disabled auditor yields a no-op `EventHandle` for any event type without taxonomy validation, matching `AuditEvent` on a disabled auditor. New `TestAuditorHandle_DisabledAuditor_ReturnsNoOpHandle` locks the contract.
  - **B-33** `secrets/openbao.Provider.Close` and `secrets/vault.Provider.Close` godoc now explicitly claims idempotency ("repeated calls are safe, return nil, and do not panic"). Behaviour already matches; new `TestOpenbaoClose_IsIdempotent` and `TestVaultClose_IsIdempotent` lock it.
  - **B-39** `audittest` internal helper rename: `newTestLogger` → `newTestAuditor` for symmetry with the rest of the `Logger` → `Auditor` migration (#586 et al.). Also `TestNewLogger` → `TestNew`. Unexported, no consumer impact.
  - **B-41** `audit.New` now requires `WithAppName` and `WithHost` (unless `WithDisabled`). See `### Added` above for sentinels and `### Breaking Changes` for migration.
  - **B-45** Option classification documented in `options.go` package comment and per-option godoc: Required options (`WithTaxonomy`, `WithFormatter`, `WithAppName`, `WithHost`, `WithTimezone`) reject nil/empty; Optional options (`WithMetrics`, `WithDiagnosticLogger`, `WithStandardFieldDefaults`) accept nil with a documented default. No runtime behaviour change — clarification of an already-mixed-but-sensible policy, following the `net/http.Client.Transport` vs `net/http.Server.Handler` pattern.

- Error-prefix convention unified across every module on the Go import-path pattern (#592). A CI grep check to enforce the convention is deferred to a follow-up issue. All modules now prefix errors with their dotted module path:
  - `audit:` (core — unchanged)
  - `audit/file:`, `audit/syslog:`, `audit/webhook:`, `audit/loki:` (previously `audit: <module> output:`)
  - `audit/outputconfig:` (new prefix via the restructured `ErrOutputConfigInvalid`)
  - `audit/secrets/vault:`, `audit/secrets/openbao:` (previously `vault:`, `openbao:` with no library prefix)
  
  `outputconfig.ErrOutputConfigInvalid` now wraps `audit.ErrConfigInvalid` so `errors.Is(err, audit.ErrConfigInvalid)` matches every configuration-validation failure — a single sentinel across outputs, config, and secrets (stdlib `fs.ErrNotExist` / `os.ErrNotExist` pattern). Consumers matching errors with `strings.Contains(err.Error(), "vault:")` must migrate to `errors.Is` / `errors.As` on sentinels (already forbidden by project style).

- Self-reporting output drop metrics are now consistent (#592). Webhook and Loki no longer call pipeline-level `Metrics.RecordDelivery(name, audit.EventError)` on **buffer drops** (oversized event or buffer full); those drops now surface only via `OutputMetrics.RecordDrop()`, matching file + syslog. Retry-exhaustion failures in webhook/loki (where delivery WAS attempted) still call `RecordDelivery(EventError)` — those are genuine delivery errors, not buffer drops. Consumers relying on `RecordDelivery` as a pre-delivery drop counter should use `OutputMetrics.RecordDrop` for that counter.

- `secrets.redactRef` drops its unused parameter (#592 B-35). The function was already returning a constant; the `_` parameter was dead. Internal helper — no consumer impact.

- `audit.CEFFormatter` small ergonomics bundle (#591):
  - `FieldMapping` now supports an **empty-string opt-out sentinel**: passing `{"actor_id": ""}` drops the default `actor_id → suser` mapping so the field is emitted with its raw audit name. Both `ViaDelete` (empty-string sentinel) and `SelfMap` (`{"actor_id": "actor_id"}`) opt-out patterns are now documented and exercised by named tests. Previously the only working opt-out was self-map; the empty-string form failed with a validation error and the "delete from DefaultCEFFieldMapping copy" pattern was documented but did not actually suppress defaults because the merge always re-seeded from them.
  - `SeverityFunc` godoc clarified to distinguish the clamp-on-override path (consumer-supplied func return values are clamped per event) from the fast path (taxonomy-derived severity is precomputed and clamped once at taxonomy registration — no per-event clamp). Behaviour unchanged.
  - `maxCEFHeaderField = 255` const now carries a multi-sentence rationale explaining that the ArcSight CEF spec does not define a per-field limit; 255 is a conservative operational ceiling derived from common SIEM header-parsing assumptions. Value unchanged.

- `audit.Formatter` godoc now declares that `Format` MUST be safe for concurrent use (#589). Previous godoc stated the method was called from a single goroutine, but the library's own `CEFFormatter` used `sync.Once` + `noCopy` for exactly the opposite reason — a shared formatter instance across multiple Auditors calls Format concurrently. The contract is updated to match the built-in implementation and the stdlib precedent (`log/slog.Handler`, `net/http.Handler`, `encoding/json.Marshaler`). Godoc on `JSONFormatter` + `CEFFormatter` adds a "Concurrency" section describing the `sync.Once` / `sync.Pool` pattern used internally. No behavioural change to the built-in formatters — the implementation has been concurrency-safe since inception. Consumer-side `Formatter` implementations that relied on the old single-goroutine wording must guard any mutable state (field caches, compiled templates) with `sync.Once` / `sync.RWMutex` / `sync/atomic`. A new `TestCEFFormatter_ConcurrentFormat` + `TestJSONFormatter_ConcurrentFormat` in `format_test.go` locks the contract at test time — run with `-race`, a future regression will fail loudly.

- All examples (`examples/02-code-generation` through `examples/17-capstone`) now blank-import the `outputs` convenience package in place of individual output-module imports (#585). README + `docs/output-configuration.md` now lead with `import _ "github.com/axonops/audit/outputs"` as the default registration path, with individual sub-module imports documented as a binary-size optimisation. No API change; consumers who already use either pattern are unaffected.

### Removed

- `RELEASE_TOKEN` repo secret (#513). The release workflow now uses the `axonops-release-bot` GitHub App for every write operation. After this PR merges, maintainers MUST delete the `RELEASE_TOKEN` PAT from **Settings → Secrets and variables → Actions** to complete the secret-rotation step. Until the secret is deleted, the rotation is not finished.

### Fixed

- `TestWriteLoop_BatchesOnCountThreshold`, `TestWriteLoop_BatchesOnByteThreshold`, `TestWriteLoop_FlushesOnTimerTimeout`, and `TestWriteLoop_FlushesPartialOnClose` no longer flake under heavy CI load (#763). Root cause: the writeLoop's `testOnFlush` hook fires when the batched `Writev` returns to the driver, but the mock syslog server's read loop may still be coalescing the framed messages into multiple Reads at that moment. The previous pattern (`waitForData` on first chunk, then a snapshot `countEventMarkers`) raced — under `-race -parallel=8 -count=500` the count assertion would intermittently see `9` instead of the expected `10`. Replaced with a new `mockSyslogServer.waitForMarkerCount(want int, timeout)` helper that polls the cumulative marker count via `strings.Count` over the joined buffer, immune to TCP read coalescing. Verified: 500 iterations under `-race -parallel=8` now complete clean.

- Framework-field protection table in `docs/sensitivity-labels.md`, `docs/cef-format.md`, `docs/json-format.md`, `examples/11-sensitivity-labels/README.md`, and `examples/13-standard-fields/README.md` misrepresented `app_name` and `host` (both REQUIRED at construction — `audit.New()` returns `ErrAppNameRequired` / `ErrHostRequired` if unset) and `timezone` (always populated; defaults to `time.Now().Location().String()` if `WithTimezone` is not provided) as `(when configured)`. A consumer following the docs would architect their SIEM ingestion / dashboards / alerting to handle missing values that never appear, OR would expect unconfigured `app_name`/`host` to silently flow through when in reality `audit.New()` refuses to start. The corrected tables document the exact contract enforced by `audit.New` and locked by the existing `TestNew_MissingAppName_ReturnsErrAppNameRequired`, `TestNew_MissingHost_ReturnsErrHostRequired`, `TestLogger_Timezone_AutoDetected`, and `TestTimezoneAlwaysPopulated` tests (#762).
- `ValidationError.Unwrap` and `SSRFBlockedError.Unwrap` now return a defensive copy of the wrapped-sentinel slice instead of a shared reference to the internal `[2]error` backing array (#590 part 1 of 2). Previously, a caller that retained and mutated the slice returned by `Unwrap` could corrupt subsequent `errors.Is` / `errors.As` dispatches on the same error value. The fix uses `slices.Clone` at the cost of a 16-byte allocation per `Unwrap` call — only invoked by `errors.Is` / `errors.As` on the consumer-side error-discrimination path, not the audit hot path. Also documents `ComputeHMAC`'s empty-payload / empty-salt / unknown-algorithm rejection behaviour in godoc (previously under-documented). Remaining #590 AC items (`RegisterOutputFactory` and `NewEventKV` error returns) split to PR-B.
- Syslog reconnect path no longer silently discards the `Close` error on the previous writer. The call previously read `_ = s.writer.Close()` with no comment and no log — a `Close` failure from a mid-handshake TLS teardown, TCP half-close, or unreachable remote produced no diagnostic signal, and operators had no way to link a persistent reconnect loop back to the underlying teardown error. The error is now logged at `slog.LevelDebug` with `address` and `error` attributes; the reconnect itself still proceeds (a fresh transport is about to be established by the subsequent `connect()`, so there is no recoverable action to take beyond observing the failure) (#489)
- Panic loudly at init if any hardcoded SSRF CIDR or IP literal fails to parse. Previously `cgnatBlock` / `deprecatedSiteLocalBlock` / `awsIPv6MetadataIP` init used `_, n, _ := net.ParseCIDR(...)` (or `net.ParseIP(...)` with no check); a source-level corruption or stdlib regression would have silently produced `nil`, and every subsequent SSRF check would have nil-deref panicked inside `Contains` / `Equal`. A new `mustParseCIDR` / `mustParseIP` wrapper panics with a clear `audit: SSRF init: failed to parse hardcoded CIDR ...` message at package load instead (#488)

### Breaking Changes

- Logger → Auditor rename across the entire API surface (#457). `audit.Logger` type → `audit.Auditor`; `audit.NewLogger(...)` → `audit.New(...)`; `outputconfig.NewLogger(...)` facade → `outputconfig.New(...)`; YAML top-level `logger:` section → `auditor:` (the old key is rejected as an unknown top-level field at load time); `audit.WithLogger(*slog.Logger)` → `audit.WithDiagnosticLogger(*slog.Logger)`; `audit.LoggerReceiver` interface → `audit.DiagnosticLoggerReceiver`; `audit.Logger.Audit(...)` → `audit.Auditor.AuditEvent(...)`; `audittest.NewLoggerQuick(...)` → `audittest.NewQuick(...)`. Receiver convention `l` → `a`. Migration is mechanical: a global find-and-replace covers the renames; the YAML key rename is a manual edit per `outputs.yaml`. Rationale: the library is an audit logger, not an application logger, and the `Logger` name collided pervasively with `slog.Logger` / consumer logging frameworks across grep, IDE auto-complete, and prose. Stdlib precedent: `database/sql.DB` not `Database`, `http.Client` not `HTTPClient`, OpenTelemetry `trace.Tracer` not `trace.Logger`. The full type / option / interface map is in [#457](https://github.com/axonops/audit/issues/457).

- `audit.Event` interface gains three required methods: `Description() string`, `Categories() []CategoryInfo`, `FieldInfoMap() map[string]FieldInfo` (#597). Custom `Event` implementations must add the three methods. Migration: copy the `basicEvent` zero-value pattern (return `""`, `nil`, `nil`) for taxonomy-agnostic events, or look up from your own taxonomy when you have one. All built-in implementations (basicEvent, generated builders, internal test mocks) updated. **AC corrections**: the issue text proposed `Categories() []string` and `FieldInfo() map[string]FieldInfo`; the implemented signatures are `Categories() []CategoryInfo` (preserves severity, no information loss) and `FieldInfoMap() map[string]FieldInfo` (renamed to avoid collision with generated builders' typed `FieldInfo()` method). Both decisions locked by api-ergonomics-reviewer.

- `audit.WithStandardFieldDefaults` signature changed from `map[string]string` to `map[string]any` (#595 B-44). Reserved fields with non-string declared types (`source_port`, `dest_port`, `file_size`: int; `start_time`, `end_time`: time.Time) now require values of the correct Go type; mismatches return an error wrapping `audit.ErrConfigInvalid` at `audit.New` time, before any event is processed. Migration:
  ```go
  // Before
  audit.WithStandardFieldDefaults(map[string]string{
      "actor_id":    "service-account",
      "source_port": "8080", // forced string even though port is logically int
  })

  // After
  audit.WithStandardFieldDefaults(map[string]any{
      "actor_id":    "service-account",
      "source_port": 8080, // typed correctly per ReservedStandardFieldType
  })
  ```
  YAML `standard_fields:` consumers via `outputconfig.Load` benefit automatically — YAML decoders produce typed values (`int` for YAML integers, `string` for strings), so an existing YAML with `source_port: 8080` (no quotes) starts validating correctly without YAML changes. YAML with `source_port: "8080"` (quoted, string) now fails fast with a clear error message.

- `audit.Metrics.RecordEvent` renamed to `RecordDelivery` (#594). The new name matches the method's actual role (per-output delivery outcome) and removes the semantic collision with `RecordSubmitted` in readers' heads. Migration is a one-line find-and-replace for every consumer of the interface:
  ```go
  // Before
  func (m *myMetrics) RecordEvent(output string, status audit.EventStatus) { ... }
  // After
  func (m *myMetrics) RecordDelivery(output string, status audit.EventStatus) { ... }
  ```
  All library-internal call sites, test mocks, and the capstone example are updated in lockstep.

- `audit.New` now rejects configurations that omit `WithAppName` or `WithHost` (#593 B-41), matching the existing `outputconfig.Load` YAML-path contract. Missing values yield `ErrAppNameRequired` / `ErrHostRequired`. Callers using `WithDisabled` remain free of the requirement. Migration:
  ```go
  // Before (silent empty app_name / host on programmatic path):
  auditor, err := audit.New(
      audit.WithTaxonomy(tax),
      audit.WithOutputs(out),
  )

  // After (required, compiler-friendly names):
  auditor, err := audit.New(
      audit.WithTaxonomy(tax),
      audit.WithAppName("my-service"),
      audit.WithHost(os.Hostname()),  // or a deterministic ID
      audit.WithOutputs(out),
  )
  ```
  `audittest.New` / `audittest.NewQuick` gain sensible test defaults (`"audittest"` / `"localhost"`) so existing tests continue to work without changes.

- `audit.Metrics.RecordDelivery` (renamed from `RecordEvent` by #594) now takes a typed `audit.EventStatus` instead of a raw `string` (#586). New exported type `type EventStatus string` with constants `audit.EventSuccess` (`"success"`) and `audit.EventError` (`"error"`). Prometheus / OpenTelemetry wire format is unchanged — `string(status)` is a zero-cost conversion that emits the identical label bytes that were previously hardcoded. Consumers implementing the `Metrics` interface (e.g. Prometheus adapter) must update the delivery-recording method signature. Test mocks migrated in lockstep: `audittest.MetricsRecorder.EventDeliveries` and `internal/testhelper.MockMetrics.GetEventCount` both now take `audit.EventStatus`. Pre-coding consult with api-ergonomics-reviewer locked the `string`-backed enum over `int`-backed for hot-path efficiency and wire-format stability. Migration:
  ```go
  // Before
  type myMetrics struct{ /* ... */ }
  func (m *myMetrics) RecordEvent(output, status string) {
      m.events.WithLabelValues(output, status).Inc()
  }

  // After (combined #586 typed status + #594 rename)
  func (m *myMetrics) RecordDelivery(output string, status audit.EventStatus) {
      m.events.WithLabelValues(output, string(status)).Inc()
  }
  ```
  Test assertions:
  ```go
  // Before
  assert.Equal(t, 1, metrics.EventDeliveries("out", "success"))
  // After
  assert.Equal(t, 1, metrics.EventDeliveries("out", audit.EventSuccess))
  ```

- HMAC configuration and wire format aligned for v1.0 API lock-in (#582). Three coordinated renames, detailed in [ADR-0004](docs/adr/0004-hmac-wire-field-naming.md):
  - **Go struct restructured**. `HMACConfig.SaltVersion string` + `HMACConfig.SaltValue []byte` → `HMACConfig.Salt HMACSalt` (new exported type `audit.HMACSalt{Version string, Value []byte}`). Matches the nested YAML shape so godoc and YAML read the same structure in both places. Go-precedent: `tls.Config` → `tls.Certificate` (domain-prefixed nested type).
  - **YAML key `hash` → `algorithm`**. `hmac.hash: HMAC-SHA-256` → `hmac.algorithm: HMAC-SHA-256`. The field holds an HMAC algorithm identifier, not a hash name; the Go API already called it `Algorithm`. No backward-compat alias — pre-v1.0, stale `hash:` configs fail loudly with a clear unknown-field error.
  - **Wire key JSON `_hmac_v` → `_hmac_version`**. CEF stays `_hmacVersion`. The pair `_hmac_version` / `_hmacVersion` matches the snake/camel symmetry already used for `event_category` / `eventCategory`. `_hmac_v` was the only abbreviated wire key and its `_v` suffix read ambiguously as version / value / verify. Position inside the HMAC-authenticated region is preserved — immediately preceding the `_hmac` digest, as locked by #473.
  
  Migration:
  ```go
  // Before
  cfg := audit.HMACConfig{
      Enabled:     true,
      SaltVersion: "2026-Q1",
      SaltValue:   salt,
      Algorithm:   "HMAC-SHA-256",
  }
  
  // After
  cfg := audit.HMACConfig{
      Enabled: true,
      Salt: audit.HMACSalt{
          Version: "2026-Q1",
          Value:   salt,
      },
      Algorithm: "HMAC-SHA-256",
  }
  ```
  ```yaml
  # Before
  hmac:
    enabled: true
    salt:
      version: "2026-Q1"
      value: "${HMAC_SALT}"
    hash: HMAC-SHA-256
  
  # After
  hmac:
    enabled: true
    salt:
      version: "2026-Q1"
      value: "${HMAC_SALT}"
    algorithm: HMAC-SHA-256
  ```
  External JSON verifiers: update the string constant from `_hmac_v` to `_hmac_version`. Continue to strip only `_hmac` (never `_hmac_version`) before recomputing the HMAC. CEF verifiers: no change.

- All four output sub-modules (`file`, `syslog`, `webhook`, `loki`) now expose the identical `NewFactory` signature (#581):
  ```go
  func NewFactory(factory audit.OutputMetricsFactory) audit.OutputFactory
  ```
  Previously `file` and `syslog` accepted a module-local `Metrics` interface; `webhook` and `loki` exposed no `NewFactory` at all. The library's unified `audit.OutputMetricsFactory` plumbing now covers all four. Passing `nil` opts out of per-output metrics. Direct-Go migration:
  ```go
  // Before (file, syslog only — webhook / loki had no exported NewFactory)
  audit.RegisterOutputFactory("file",   file.NewFactory(myFileMetrics))
  audit.RegisterOutputFactory("syslog", syslog.NewFactory(mySyslogMetrics))

  // After — identical signature across all four modules
  audit.RegisterOutputFactory("file",    file.NewFactory(myOutputMetricsFactory))
  audit.RegisterOutputFactory("syslog",  syslog.NewFactory(myOutputMetricsFactory))
  audit.RegisterOutputFactory("webhook", webhook.NewFactory(myOutputMetricsFactory))
  audit.RegisterOutputFactory("loki",    loki.NewFactory(myOutputMetricsFactory))
  ```

- `file.Metrics` renamed to `file.RotationRecorder` and `syslog.Metrics` renamed to `syslog.ReconnectRecorder`; their methods change from `RecordFileRotation(path)` / `RecordSyslogReconnect(address, success)` to `RecordRotation(path)` / `RecordReconnect(address, success)` (#581). The new names follow the Go stdlib `-er` convention for single-method extension interfaces layered on a base contract (`http.Flusher` / `http.Hijacker` on `http.ResponseWriter`, `sql/driver.Queryer` / `Execer` on `driver.Conn`). Both are detected automatically via type-assertion on the `audit.OutputMetrics` value supplied through `SetOutputMetrics` or the factory — no explicit registration required. Direct-Go migration: any type previously implementing `RecordFileRotation(path)` must rename the method to `RecordRotation(path)`; likewise `RecordSyslogReconnect(address, success)` becomes `RecordReconnect(address, success)`. BDD / audittest helpers and the internal `testhelper.MockMetrics` type are updated; consumer test mocks must rename to match. **AC deviation**: the original issue called for outright removal of `file.Metrics` + `syslog.Metrics`; api-ergonomics review locked the stdlib extension-interface precedent instead, because outright removal would drop the rotation and reconnect recording points entirely.

- `file.New` and `syslog.New` drop the positional `Metrics` parameter: construct without metrics, then call `out.SetOutputMetrics(m)` — matching the existing webhook / loki pattern (#581). Direct-Go migration:
  ```go
  // Before
  fileOut, _ := file.New(&cfg, myFileMetrics, opts...)
  syslogOut, _ := syslog.New(&cfg, mySyslogMetrics, opts...)

  // After
  fileOut, _ := file.New(&cfg, opts...)
  fileOut.SetOutputMetrics(myOutputMetrics) // may also implement file.RotationRecorder

  syslogOut, _ := syslog.New(&cfg, opts...)
  syslogOut.SetOutputMetrics(myOutputMetrics) // may also implement syslog.ReconnectRecorder
  ```
  See `docs/metrics-monitoring.md` for the unified-factory walkthrough.

- `audit.Config` struct and `audit.WithConfig` option removed — functional options are now the sole configuration mechanism for `audit.New` (#579). The dual-pattern exposed a bool-ambiguity footgun in the struct-merge (`OmitEmpty: false` indistinguishable from unset) that forced a dedicated `WithOmitEmpty()` to exist alongside the struct; this is an explicit admission the pattern was broken. Migration: replace `audit.WithConfig(audit.Config{QueueSize: 500})` with `audit.WithQueueSize(500)`; `audit.WithConfig(audit.Config{ShutdownTimeout: d})` with `audit.WithShutdownTimeout(d)`; etc. `audit.Config.version` is also removed — schema versioning lives in `outputconfig` YAML where it already did. Stdlib precedent: `log/slog` (`slog.New(handler)` + attribute-based options), `grpc.DialOption`, `redis.Options`, `mongo/options` — none expose parallel struct + functional-option surfaces. See [ADR-0003: Single Configuration Pattern](docs/adr/0003-config-pattern.md). `audittest.WithConfig(cfg audit.Config)` removed; migrate to `audittest.WithAuditOption(audit.WithQueueSize(n))`.
- `audit.go` `returnFieldsToPool` now drops `Fields` maps whose `len > 64` rather than returning them to `fieldsPool` (#579 B-26). Prevents a single giant event (e.g. one with hundreds of fields) from poisoning the pool for every subsequent caller. No API change; purely a pool-hygiene correctness fix matching the 64-KiB buffer cap pattern from #497.

- Generated typed-builder setters for custom (non-reserved) fields now use the Go type declared in the taxonomy YAML `type:` annotation — or `string` by default when no `type:` is given (#575). Before #575, every custom field emitted `Set<Name>(v any)` regardless of taxonomy, so `SetEmail(42)` compiled despite the README's "typos become compile errors" promise. Now `SetEmail(v string)` is typed and `SetEmail(42)` fails at compile time. Accepted `type:` vocabulary (matching `log/slog.Kind`): `string`, `int`, `int64`, `float64`, `bool`, `time` (→ `time.Time`), `duration` (→ `time.Duration`). Reserved standard fields (`actor_id`, `source_ip`, `dest_port`, etc.) always use the library-authoritative Go type and reject any per-taxonomy `type:` override. Migration: taxonomies whose existing custom fields carried non-string values must add `type:` annotations (e.g., `quota: {type: int}`); unannotated fields default to `string`, so most taxonomies work unchanged. Unknown `type:` values are rejected at taxonomy parse time with the valid-set listed in the error (matches the #447 YAML-error UX). All 16 example `audit_generated.go` files regenerated.
- `audit-gen` emits `auditIntPtr(n int) *int` instead of `intPtr(n int) *int` (#575, B-15). The previous unprefixed helper caused a redeclaration compile error when a consumer package defined its own `intPtr` (common in Go codebases). The prefixed form is generator-owned, eliminating the collision hazard. Consumer migration is automatic — regenerate the `audit_generated.go` file via `go generate`.
- `audit.EventDef` gains a new public field `FieldTypes map[string]string` exposing the parsed per-field Go type names (custom fields only; reserved fields stay in the library's standard-field table) (#575). Consumers inspecting taxonomies programmatically may read this map for diagnostics or custom code generation. Read-only after construction.
- `audit.Fields` returned from a generated builder's `Fields()` method is now documented as owned by the builder — callers MUST NOT mutate the returned map after handing the builder to `AuditEvent`, matching the `FieldsDonor` ownership contract (#575, B-16). Behaviour unchanged; the godoc contract is what's new.
- `audit-gen` accepts a new `-standard-setters=all|explicit` flag (#575, B-38). Default `all` preserves current behaviour (every builder gets every reserved-standard-field setter, ~31 per event). `explicit` emits setters only for reserved fields that appear in the event's taxonomy `fields:` map, trimming ~80 % of generator output for small schemas. Consumers whose event schemas reference only a handful of reserved fields per event can opt in via `go:generate` directives; existing consumers need no change.

- `outputconfig` public surface collapsed for v1.0 API lock-in (#577). The changes address three api-ergonomics findings bundled under B-03/B-37/B-40:
  - `outputconfig.LoadResult` removed. `outputconfig.Load` now returns `*outputconfig.Loaded` — an opaque type whose fields are unexported. Use method accessors: `Options()`, `Outputs()`, `OutputMetadata()`, `AppName()`, `Host()`, `Timezone()`, `StandardFields()`, `Close()`. Motivation: the old `LoadResult.Config` + `LoadResult.Options` fields both appeared prominently as "pass to `audit.New`"; passing both caused double-apply of queue size / shutdown timeout. The method-accessor shape removes the footgun. Stdlib precedent: `*sql.DB`, `*regexp.Regexp`, `*template.Template`.
  - `outputconfig.NamedOutput` demoted to unexported. Replaced by exported `outputconfig.OutputInfo` returned from `(*Loaded).OutputMetadata() []OutputInfo` — a diagnostic snapshot type separate from the internal pipeline struct. Stdlib precedent: `os.FileInfo`, `debug.Module`.
  - `outputconfig.New` signature split into two: the simple `New(ctx, taxonomyYAML, outputsConfigPath, opts ...audit.Option)` for the 80 % no-LoadOption case, and the advanced `NewWithLoad(ctx, taxonomyYAML, outputsConfigPath, loadOpts []LoadOption, opts ...audit.Option)` for consumers needing `WithSecretProvider`, `WithCoreMetrics`, `WithOutputMetrics`, etc. Stdlib precedent: `sql.Open`/`OpenDB`, `tls.Dial`/`DialWithDialer`, `exec.Command`/`CommandContext`. All 16 examples drop the `nil` 4th argument; capstone migrates to `NewWithLoad`.
  - `outputconfig/doc.go` usage snippets rewritten to match current signatures; runnable `ExampleLoad`, `ExampleNew`, `ExampleNewWithLoad` in `outputconfig/example_test.go` verify correctness at test time. Direct-Go call-site update for legacy `outputconfig.New(ctx, yaml, path, nil)` call is mechanical: drop the `nil`. For legacy `outputconfig.New(ctx, yaml, path, loadOpts, opts...)`, rename `New` → `NewWithLoad`. Access to parsed config fields previously on `LoadResult` is available via the matching method on `Loaded`. `(*Loaded).Close()` closes every output constructed by Load — use when the auditor construction fails and the outputs need cleanup.

- `audit.RegisterOutputFactory` now returns `error` instead of panicking on empty type name or nil factory (#590). The error wraps `audit.ErrValidation`. New companion `audit.MustRegisterOutputFactory(typeName, factory)` preserves the panic-on-programmer-error contract for init-time callers — mirrors `regexp.MustCompile`. All five built-in registrations (file / loki / stdout / syslog / webhook) migrated to `MustRegisterOutputFactory`. Custom factory authors who register via init() should migrate to `MustRegisterOutputFactory`; consumers who register dynamically should handle the returned error.
- `audit.NewEventKV(eventType, kv...) Event` → `NewEventKV(eventType, kv...) (Event, error)` (#590). The error wraps `audit.ErrValidation` on odd argument count or non-string key. New companion `audit.MustNewEventKV(eventType, kv...)` preserves the pre-#590 panic contract for literal-input call sites (tests, examples, package-level vars) — same pattern as `regexp.MustCompile` / `template.Must`. Migration: for dynamic input use `ev, err := audit.NewEventKV(...)`; for literal input use `audit.MustNewEventKV(...)`. CLAUDE.md rule "no panic escapes the package boundary" now holds for both functions; all examples and documentation updated to use the Must form.
- `file.New` now takes `*Config` instead of `Config` by value (#580). Matches the `syslog.New` / `webhook.New` / `loki.New` signatures and the idiomatic Go pattern for stateful constructors (`slog.NewJSONHandler(w, *HandlerOptions)`, `mongo.Connect(*ClientOptions)`, `redis.NewClient(*Options)`). `file.New` adds a `nil` check and a shallow defensive copy so caller-side mutation is prevented for value fields — same pattern webhook/loki use. **Caller-side constraint**: `file.Config.Compress` is `*bool`; mutating the bool via the pointer after `file.New` returns still affects the Output (shallow copy shares the pointer). Caller must treat `Compress` as immutable post-construction. Direct-Go call-site update is mechanical: `file.New(cfg, ...)` → `file.New(&cfg, ...)`.
- `stdout.go` dropped its `init()` auto-registration of the `"stdout"` factory (#578). Hidden global mutation at import time is now gone. Consumers who use YAML `type: stdout` MUST either blank-import `_ "github.com/axonops/audit/outputs"` (which registers stdout alongside file/syslog/webhook/loki) or call `audit.RegisterOutputFactory("stdout", audit.StdoutFactory())` explicitly. Direct-Go consumers calling `audit.NewStdoutOutput(...)` / the new `audit.NewStdout` / `audit.NewStderr` / `audit.NewWriter` constructors are unaffected.
- `audit.Stdout()` removed (#578). It panicked on error, violating the library rule that no panic escapes the package boundary. Non-panicking replacements: `audit.NewStdout()` (writes to os.Stdout), `audit.NewStderr()` (writes to os.Stderr), `audit.NewWriter(w io.Writer)` (writes to any `io.Writer`). All return `(*StdoutOutput, error)`. Migration: `audit.Stdout()` → `out, _ := audit.NewStdout()`.
- `audit.OutputFactory` type signature extended with a trailing `fctx audit.FrameworkContext` parameter (#583). The new `FrameworkContext` struct carries auditor-wide metadata (`AppName`, `Host`, `Timezone`, `PID`) into output constructors so they can reference cascade defaults without parsing YAML. Consumers who register custom factories via `audit.RegisterOutputFactory` must update the signature; all built-in factories (`stdout`, `file`, `syslog`, `webhook`, `loki`) have been updated. `outputconfig.Load` constructs the `FrameworkContext` from top-level `app_name:` + `host:` in outputs YAML and threads it through automatically.
- Documented the syslog APP-NAME cascade (#583): per-output `outputs.<name>.syslog.app_name` wins, otherwise top-level `app_name` cascades in, otherwise literal `"audit"`. The cascade was implemented in `outputconfig.injectSyslogGlobals` but was undocumented and operationally confusing (same YAML key name at two layers). See [APP-NAME Cascade in docs/syslog-output.md](docs/syslog-output.md#app-name-cascade).
- `loki.Config.Compress` Go field renamed to `loki.Config.Gzip` to align with the YAML key `gzip` (#584). YAML key unchanged — operator configs are unaffected. Programmatic consumers constructing `loki.Config` in Go must rename the field: `loki.Config{Compress: true}` becomes `loki.Config{Gzip: true}`. Rationale: Loki's server only accepts gzip (`Content-Encoding: gzip`), so the bool is algorithm-specific, not a generic toggle; naming the algorithm matches the Vector / Fluent Bit / promtail idiom. No aliases kept.
- Per-output `OutputOption` constructors renamed to follow the package's `WithX` convention (#576). `OutputRoute` → `WithRoute`, `OutputFormatter` → `WithOutputFormatter` (kept `Output` prefix because the auditor-level `WithFormatter` already exists), `OutputExcludeLabels` → `WithExcludeLabels`, `OutputHMAC` → `WithHMAC`. Call-site update is mechanical: `audit.WithNamedOutput(out, audit.OutputRoute(r), audit.OutputHMAC(h))` becomes `audit.WithNamedOutput(out, audit.WithRoute(r), audit.WithHMAC(h))`. No aliases kept.
- `New` signature changed from `New(Config, ...Option)` to `New(...Option)` — Config fields expressed as Options (#388)
- `Config.Version` unexported, `Config.Enabled` removed — use `WithDisabled()` (#388)
- `Fields` changed from type alias to defined type `type Fields map[string]any` with `Has()`, `String()`, `Int()` methods (#388)
- `EmitEventCategory` renamed to `SuppressEventCategory` (inverted semantics) (#388)
- `ParseTaxonomyYAML` returns `*Taxonomy` instead of `Taxonomy` (#389)
- `WithTaxonomy` accepts `*Taxonomy` with deep copy and mutation protection (#389)
- `outputconfig.Load` signature changed — `coreMetrics` moved to `WithCoreMetrics` LoadOption (#390)
- `WithStandardFieldDefaults` guard relaxed from error-on-second-call to last-wins (#390)
- `WithNamedOutput` replaced positional params with `...OutputOption` (#391)
- `WithOutputHMAC` removed — use `OutputHMAC` within `WithNamedOutput` (#391)
- `EventType` renamed to `EventHandle`, `Name()` renamed to `EventType()` (#402)
- Module renamed from `github.com/axonops/go-audit` to `github.com/axonops/audit` (#398)
- `audit-gen` generates typed parameters (string/int) instead of `any` for standard field setters and constructors (#394)
- HMAC wire-format: `_hmac_v` now appears BEFORE `_hmac` on the wire and is inside the HMAC-authenticated bytes. External verifiers must strip only the `_hmac` field from the received line (keeping `_hmac_v` in place) to recompute the HMAC. See [`docs/hmac-integrity.md`](docs/hmac-integrity.md#canonicalisation-rule-for-verifiers) for the full canonicalisation contract (#473)
- HMAC `SaltVersion` character set restricted to `[A-Za-z0-9._:-]` (length 1–64) at config-time validation — values containing spaces, control characters, CEF/JSON metacharacters, or other ambiguous bytes are rejected (#473)
- `OutputFactory` signature grew a `*slog.Logger` parameter: `func(name string, rawConfig []byte, coreMetrics Metrics, logger *slog.Logger) (Output, error)` — later extended again in #583 (see above). Custom factories must add the parameter (nil is valid; treated as `slog.Default`). The logger is plumbed from `outputconfig.WithDiagnosticLogger` / `audit.WithDiagnosticLogger` so construction-time warnings reach the consumer's handler (#490)
- Root-level `tls_policy:` removed from `outputconfig` YAML schema. TLS policy is now configured per-output (under `syslog:`, `webhook:`, `loki:`) and per-provider (under `vault:`, `openbao:`). Consumers with `tls_policy:` at the root get an explicit "unknown top-level key" error at startup and must move the block into each affected output/provider. Rationale: the previous inheritance model created a privilege-escalation surface where a permissive policy set for a legacy syslog target would silently downgrade the TLS posture of secret-provider connections that carry bootstrap credentials. See [`examples/15-tls-policy/outputs.yaml`](examples/15-tls-policy/outputs.yaml) and [`docs/output-configuration.md` — Per-Output TLS Policy](docs/output-configuration.md#per-output-tls-policy) for the new form (#476, #632)
- Async output `Output.Write` (`syslog`, `loki`, `webhook`) now returns a non-nil error wrapping `audit.ErrEventTooLarge` + `audit.ErrValidation` for events whose byte length exceeds the output's `MaxEventBytes` cap. Previously `Write` returned `nil` on buffer-full drops; the buffer-full contract is preserved, but the new oversized-event class returns an error so consumers inspecting the return value can discriminate via `errors.Is(err, audit.ErrEventTooLarge)`. Consumers ignoring `Write`'s return value remain unaffected. See the Security section below for full rationale (#688)

### Performance

- Webhook byte-threshold batching — `webhook.Config` adds `MaxBatchBytes` (default 1 MiB, range 1 KiB–10 MiB), matching the existing `loki.Config` and `syslog.Config` conventions. `batchLoop` now flushes when accumulated event bytes cross the threshold in addition to the existing count and timer triggers. Oversized single events flush alone — never dropped. YAML key: `max_batch_bytes`. Prevents unbounded HTTP POST body sizes when events are verbose (security events with stack context can be 10–100 KiB; at `BatchSize: 100` a batch could previously reach 1–10 MiB, head-of-line-blocking on slow endpoints). Validation wraps `audit.ErrConfigInvalid` for negative / out-of-range values. Closes #687.
- Batched syslog writes — `syslog.Config` adds `BatchSize` (default 100), `FlushInterval` (default 5 s), and `MaxBatchBytes` (default 1 MiB) fields, matching the conventions already established by `loki.Config` and `webhook.Config`. The `writeLoop` accumulates events and flushes on count threshold, byte threshold, timer timeout, or Close — instead of writing one event per srslog call. RFC 5425 octet-counting framing is preserved per message (each event remains an independently framed syslog message within a batch). Oversized single events flush alone — never dropped. YAML keys: `batch_size`, `flush_interval`, `max_batch_bytes`. **Behaviour change for existing consumers**: events may now wait up to `FlushInterval` (5 s default) before reaching the syslog server. Consumers needing synchronous per-event delivery should set `BatchSize: 1` or a small `FlushInterval` (e.g. `10ms`). Close still drains any pending batch before returning, bounded by the existing 10 s shutdown timeout. Follow-up issues filed: #687 (webhook `MaxBatchBytes` for cross-output consistency), #688 (per-event `MaxEventBytes` bound to defend against consumer-controlled memory pressure). (#599)
- Eliminate per-field allocations in the CEF formatter (#496). Primitive field values (`string`, `bool`, all int/uint widths, `float64`, `float32`, `time.Time`, `time.Duration`) now format directly into the pool-leased buffer via `strconv.Append*` into a 32-byte stack scratch, bypassing the `strconv.Format* → string → cefEscapeExtValue → string → WriteString` double-copy pattern. String values route through a new in-place `writeEscapedExtValueString` that performs CEF escaping while writing, without allocating an intermediate escaped string. Non-primitive fallback (the `default` branch for slices/maps/structs via `fmt.Sprintf("%v", val)`) is preserved unchanged — byte-for-byte output compatibility. `buf.Grow(768)` preflight added to `CEFFormatter.formatBuf` to amortise cold-pool growth across a realistic 20-field event. Result: `BenchmarkCEFFormatter_Format_LargeEvent` drops from 3 → 1 allocs/op (1196 → 1170 ns/op, 584 → 577 B/op); `BenchmarkCEFFormatter_Format` unchanged at 1 alloc/op. New benchmarks `BenchmarkCEFFormatter_Format_LargeEvent_Escaping` (metacharacter-heavy), `_Numeric` (10 numeric fields), and `_Parallel` (GOMAXPROCS) added for regression coverage. Byte-equivalence with the legacy path proven by rapid property tests (`TestWriteEscapedExtValueString_PropertyEqualsCEFEscape` — raw byte strings including invalid UTF-8 + adversarial seeds; `TestAppendFormatFieldValue_ByteEquivalentToLegacy` — table-driven across every supported primitive type).
- Eliminate per-event allocations in the drain pipeline via two coordinated changes shipped together (#497):
  - **`FieldsDonor` extension interface** — generated builders from `cmd/audit-gen` opt into a defensive-copy bypass via the unexported `donateFields()` sentinel method. The auditor takes ownership of the donor's `Fields` map (no per-event map clone), eliminating the dominant allocation on the slow path. `NewEvent` and consumer-defined `Event` types stay on the original defensive-copy path. Contract documented in [`docs/adr/0001-fields-ownership-contract.md`](docs/adr/0001-fields-ownership-contract.md).
  - **W2 zero-copy drain** — the formatter buffer leased from `jsonBufPool` / `cefBufPool` is now retained for the lifetime of `processEntry` (one event) and shared across every output and category pass. Per-output post-field assembly (`event_category`, `_hmac_v`, `_hmac`) writes into a pooled scratch buffer in place of the previous `make([]byte, n)` per-field copy. Sorted field-key slices are pooled. `Output.Write` godoc tightened: implementations MUST NOT retain `data` past the call (all first-party outputs already copy on enqueue). Pool returns enforce a 64 KiB capacity cap to bound memory under outlier events, and `clear()` the backing array as defence-in-depth against future read-past-len bugs.
  - Result: `BenchmarkAudit_RealisticFields` (10 fields, slow path) drops from 2 → 1 allocs/op and 670 → 320 B/op. `BenchmarkAudit_WithHMAC` drops from 2 → 1 allocs/op and 330 → 165 B/op (50 % reduction). Fan-out byte allocations halved across every variant. The donor fast path hits 0 allocs/op on the drain side end-to-end; the remaining caller-side allocations (builder `Fields{}` literal, `any`-boxing) are addressed by the v1.1 follow-on in #660. See [`BENCHMARKS.md`](BENCHMARKS.md) and [`docs/performance.md`](docs/performance.md) for the full table and the fast-path / slow-path ownership model.
- Eliminate per-event allocations in the Loki batch-build hot path. `BenchmarkLokiOutput_BatchBuild` for 100 events across 5 streams drops from **390 → 35 allocs/op** (91% reduction; ~0.35 allocs/event vs ~4 previously). Measured wall-clock falls 56% (78 µs → 35 µs); per-batch heap usage falls 95% (266 KiB → 12 KiB). New `BenchmarkLokiOutput_BatchBuild_HighCardinality` benchmarks the worst-case 100-distinct-streams pattern at 5 allocs/stream — the unavoidable floor without slab pooling. Optimisations: `streamKey` rewritten as `writeStreamKey` so the per-event lookup uses the Go compiler's `m[string(b)]` zero-alloc pattern; `sortedStreams` and `writeLabelsJSON` reuse pooled scratch slices on the Output struct; `frameworkFields.pidStr` pre-computed at `SetFrameworkFields` time; `strconv.AppendInt` writes into a fixed `[20]byte` scratch instead of `buf.AvailableBuffer()`. Behaviour unchanged — verified by existing BDD and three new unit tests (negative-pid, delimiter-collision, baseline-pid-zero). Closes #494
- New public `audit.WriteJSONBytes(buf, []byte)` mirrors `audit.WriteJSONString` for byte-slice input. Used by the Loki output to embed the pre-serialised event line as a JSON string value without the `string(b)` copy that was the single largest per-event allocation in the loki drain path. Verified byte-identical to `WriteJSONString` (and to `encoding/json.Marshal`) across 10k random inputs by quick-check. Closes #495

### Documentation

- Document the window-boundary counting semantics of `dropLimiter.record`. The lock-free two-atomic design (lastWarn + count) allows a drop's `count.Add(1)` that races with a winning goroutine's `count.Swap(0)` to be reported in the NEXT window rather than the one whose boundary just closed. Total drops across all windows are conserved; per-window counts are slightly smeared under concurrent bursts. Callers needing a monotonic SLA-grade drop total should use `OutputMetrics.RecordDrop` (pure `atomic.Add`, no windowing). Adds `TestDropLimiter_TotalConservedAcrossWindows` which proves conservation under 64 goroutines × 2000 records (#492)
- Document the required placement of `audit.Middleware` relative to panic-recovery middleware. `Middleware` MUST be placed OUTSIDE any panic-recovery middleware; reversing the order silently breaks the re-raise contract. `Middleware` godoc gained a new `# Placement` section with correct / wrong examples, `docs/http-middleware.md` gained a `Placement: Audit Must Wrap Panic Recovery` section with framework-specific examples (chi, Gin), and two BDD scenarios in `tests/bdd/features/http_middleware.feature` document the observable behaviour of both placements (#491)
- Add output-specific benchmark coverage for file rotation and outputconfig startup (#504, master tracker C-18 + C-19). Three components: (1) `BenchmarkWriter_Write_WithRotation` in `file/internal/rotate` sets `MaxSize: 4 KiB` + `MaxBackups: 2` + `Compress: false` so rotation fires every ~25 writes and the per-rotation cost is isolable from the write path (delta vs `BenchmarkWriter_Write_SyncOnWriteFalse` captures rename + new file + prune — ≈960 ns/write amortised, ≈24 µs per rotation event); a companion `BenchmarkFileOutput_Write_WithRotation` in the public `file` package uses `MaxSizeMB: 1` (the public API minimum) so rotation is dilute — catches regressions in the `file.Output → rotate.Writer → flush` chain that only surface after a rotate. Both include a post-loop `filepath.Glob` assertion that rotation actually fired, so a silent break in the rotation trigger fails the benchmark instead of reading as a free perf win. (2) `BenchmarkOutputConfigLoad` in a new `outputconfig/bench_test.go` baselines the full parse + envsubst + validate + factory dispatch path against a 4-output fixture (stdout + 3 file variants with routing, HMAC, envsubst, standard-field defaults) at ~485 µs/op, 1.23 MiB/op, ~8,171 allocs/op — a startup-only cost but a useful regression target for consumers reloading config dynamically. Outputs are closed outside the timer; a post-loop assertion verifies Load actually constructed all 4 outputs. (3) `BenchmarkLokiOutput_BatchBuild_HighCardinality` for the Loki 100-distinct-streams worst case already existed from #494 and is now cross-referenced in BENCHMARKS.md as fulfilling the Loki portion of #504's AC.
- Publish a side-by-side benchmark against `log/slog` + `slog.NewJSONHandler` to answer the adoption-critical "why not just use `slog`?" question with measured numbers. New `BenchmarkSlog_JSONHandler_BaselineComparison` in `bench_comparison_test.go` exercises 3-field and 10-field payloads on both sides, plus audit-only `WithHMAC` and `FanOut4` variants where `slog` has no equivalent. Both sides run synchronously (`audit.WithSynchronousDelivery` on the audit side; `slog.Logger.Info` is synchronous by construction), and each audit sub-benchmark asserts `NoopOutput.Writes() == b.N` at `b.StopTimer` so a silent drop cannot make the ns/op a lie. slog's fast path (`slog.LogAttrs` with pre-constructed `[]slog.Attr`) is represented alongside the ergonomic variadic form so the comparison uses slog's best number. Results published in [`BENCHMARKS.md` § Comparison against log/slog](BENCHMARKS.md#comparison-against-logslog) with prose covering taxonomy validation, framework fields, fan-out, HMAC, and sensitivity-label features that `slog` does not provide. Synchronous-call overhead is ~1.7–1.8 × slog at matched payload sizes — the price of the audit-library guarantees. Benchmarks committed to `bench-baseline.txt` (count=10) so `make bench-compare` tracks regressions; Go stdlib upgrades that change slog numbers are expected to require a rebaseline (#512)

### Security

- Cap per-event byte size at `Write()` entry across all three async outputs (syslog, loki, webhook) to defend against consumer-controlled memory pressure (#688). Each `Config` now has a `MaxEventBytes` field (default 1 MiB, range 1 KiB–10 MiB, YAML key `max_event_bytes`). Events whose byte length exceeds the cap are rejected with the new `audit.ErrEventTooLarge` sentinel wrapping `audit.ErrValidation`; `OutputMetrics.RecordDrop()` is called and the diagnostic logger records the reject. Without this cap, a 10 MiB event in the default 10 000-slot buffer could pin ~100 GiB of memory before backpressure triggers — and the pre-existing batching path concentrates the blast radius because an oversized event flushes alone while the preceding batch may still be held for retry. `Write()` now returns a non-nil error on oversized input where it previously returned nil for buffer-full drops — that buffer-full contract is preserved; the new reject path is specifically for the oversized class. Consumers can `errors.Is(err, audit.ErrEventTooLarge)` to discriminate.
- Drop `github.com/rgooding/go-syncmap` third-party dependency from the filter hot path. The 15-line generic wrapper over `sync.Map` is now inlined as `syncMapBool` in `filter.go`. Rationale: CLAUDE.md mandates minimal dependencies; a single-purpose type on the `isEnabled` path shouldn't carry supply-chain surface. No behavioural change; `BenchmarkAudit` and `BenchmarkAudit_Parallel` unchanged (~370 ns/op and ~62 ns/op, 1 alloc/op) (#588)
- HMAC now authenticates the `_hmac_v` salt version identifier. Previously `_hmac_v` was appended AFTER HMAC computation, leaving it outside the authenticated region. An in-transit attacker could flip the version from `v1` to `v2` to redirect a verifier's salt lookup without detection. `_hmac_v` is now inside the authenticated bytes; any modification invalidates the HMAC tag. Pre-v1.0 consumers using external verifiers that strip both `_hmac` and `_hmac_v` must update the verifier to strip only `_hmac` (#473)
- Document memory retention windows for credential-carrying fields. `HMACConfig.SaltValue`, `loki.Config.BearerToken`, `loki.BasicAuth.Password`, `webhook.Config.Headers`, and `loki.Config.TenantID` retain resolved plaintext for the auditor's lifetime; Go strings cannot be zeroed. The library best-effort zeroes provider `[]byte` token storage in `Provider.Close()` and drops HTTP header map entries after each request, but these are narrowings of the retention window, not zeroing guarantees. `outputconfig.Load()` now explicitly clears the short-lived resolver caches before return as defence-in-depth. Full model + operator rotation strategy: [`SECURITY.md` §Secrets and Memory Retention](SECURITY.md#secrets-and-memory-retention) and [`docs/secrets.md` §Memory Retention and Rotation Strategy](docs/secrets.md#memory-retention-and-rotation-strategy) (#479)
- Extend SSRF block list to cover AWS IMDSv2 over IPv6 (`fd00:ec2::254`) and deprecated IPv6 site-local range (`fec0::/10`, RFC 3879 — not classified by Go's `net.IP.IsPrivate`). IPv4-mapped IPv6 forms (`::ffff:a.b.c.d`) are now normalised to IPv4 before classification — a consumer cannot bypass the private-range or metadata block by bracketing an IPv4 address as an IPv6 literal. SSRF rejections now return the typed `*SSRFBlockedError` wrapping the new `ErrSSRFBlocked` sentinel, exposing a stable `Reason` string (`cloud_metadata`, `cgnat`, `link_local`, `multicast`, `loopback`, `private`, `deprecated_site_local`, `unspecified`) suitable for use as a Prometheus metric label. Azure IPv6 IMDS endpoint research tracked in #643 (#480)
- Add Go fuzz targets for the four untrusted-input parsers: `ParseTaxonomyYAML`, `outputconfig.Load`, `outputconfig.expandEnvString`, and `secrets.ParseRef`. Each target runs committed seed corpus on every PR (via standard `go test`) and is fuzzed for 5 minutes per target as a blocking release-gate step. Two real defects surfaced during the initial fuzz run and were fixed in the same PR: (a) `secrets.validatePath` now rejects C0/C1 control bytes and DEL (classic null-byte path-truncation vector), and (b) taxonomy + output-config parser error messages now sanitise control bytes out of embedded input echo (log-injection defence when a downstream logger prints the error). See [`CONTRIBUTING.md` — Fuzz Testing](CONTRIBUTING.md#fuzz-testing-481) (#481)
- `VerifyHMAC` now validates structural properties of the supplied HMAC value (non-empty, correct length for the algorithm's hash size, lowercase hex only) BEFORE reaching `hmac.Equal`. Malformed inputs return the new `ErrHMACMalformed` sentinel joined with `ErrValidation` so consumers can discriminate format errors from genuine verification failures. Uppercase hex is rejected deliberately — `ComputeHMAC` always emits lowercase, and accepting both would invite a "two valid encodings for one MAC" ambiguity. The constant-time compare happy path is unchanged; structural rejects are not timing-sensitive and are intentionally early returns (#483)
- Preserve string semantics through environment-variable substitution in `outputconfig`. Every YAML-marshaling re-serialisation in the output-config pipeline (`invokeFactory`, `buildRoute`, `buildHMACConfig`, `buildFormatter`, `unmarshalProviderConfig`) now routes through a new `safeMarshal` helper that wraps every string leaf in a YAML `DoubleQuoted` scalar. Without this, a post-expansion string value like `.inf`, `.NaN`, or (on older YAML 1.1 parsers) `on`/`off`/`yes`/`no` was re-emitted unquoted and the downstream factory read it as the wrong Go type — silently turning a string config value into a `float64(+Inf)` or `bool(true)` and breaking field-level contracts. Numbers, booleans, and nulls continue to round-trip at their parsed types; only string leaves are wrapped. Behaviour change is observable only in configs where env-expanded values would otherwise have coerced — existing configs using plain string values are unaffected (#487)
- Redact user-controlled substrings from every `secrets.ParseRef` and `secrets.Ref.Valid` error message. Previously the `invalid scheme %q` error echoed the caller-supplied scheme verbatim — a malformed reference such as `ref+LEAK-SCHEME://...` would surface `LEAK-SCHEME` in any log line that printed the error. A single user-controlled substring in a diagnostic log is a leakage vector (scheme, path, and key portions of a ref are all potentially sensitive in real deployments). The error message is now category-level only (`invalid scheme (redacted, must match [a-z][a-z0-9-]*)`); sentinel `ErrMalformedRef` still wraps the error, preserving `errors.Is` discrimination (#486)
- Enforce a 1-second minimum floor on the derived `http.Transport.ResponseHeaderTimeout` in the `webhook` and `loki` outputs. Previously the value was `Config.Timeout / 2`, which could become a sub-second figure (or even `0` for a misconfigured nanosecond-scale Timeout) unable to complete a real TLS handshake + server response. The overall `http.Client.Timeout` still enforces the caller-configured deadline unchanged; only the per-stage detection of a slow-to-respond server is now prevented from dropping below 1 second (#485)
- Cap the response-body drain to **4 KiB on any 3xx response** in the `webhook` and `loki` outputs. `net/http.Client.CheckRedirect` rejects standard redirects (301/302/303/307/308 with a `Location` header), but a non-redirect 3xx (for example `300 Multiple Choices`, `304 Not Modified`, or a redirect code without a `Location` header) still reaches our `defer`-based drain. Without this cap an attacker-controlled endpoint could force up to `maxResponseDrain` (1 MiB for webhook, 64 KiB for loki) of traffic per *request* — and with the maximum permitted `max_retries` of 20 that becomes 20 × per event. Non-redirect 3xx is treated as a non-retryable client error, so in practice only one drain occurs per event; the cap is still necessary because configuration or policy can change retry semantics, and retries do occur on 5xx where the larger body budget continues to apply. The previous 1 MiB / 64 KiB caps continue to apply to 2xx / 4xx / 5xx responses where the body may carry useful diagnostic information (#484)

## Pre-v1.0.0 Development History

The sections below predate the v1.0.0 release-prep reorganisation
above. They are retained verbatim for historical reference and to
preserve traceability of every change against its originating PR.
The v1.0.0 entries above are the authoritative summary for this
release; the items below describe the v0.x development path that led
here.

### Added

- `ErrValidation`, `ErrUnknownEventType`, `ErrMissingRequiredField`, `ErrUnknownField`, `ErrReservedFieldName` sentinels with `ValidationError` struct (#400, #473)
- `outputconfig.New()` facade for single-call logger creation (#392)
- `github.com/axonops/audit/outputs` convenience package — single blank import registers all output factories (#393)
- `Stdout()` convenience constructor, `NewEventKV()` slog-style event creation, `DevTaxonomy()` permissive development taxonomy (#395)
- `WithSynchronousDelivery()` for inline event processing — no drain goroutine, no Close-before-assert in tests (#403)
- `WithDiagnosticLogger(*slog.Logger)` for configurable library diagnostics (#397)
- `DiagnosticLoggerReceiver` interface — sub-module outputs receive the library's diagnostic logger (#397)
- `RecordedEvent.StringField()`, `IntField()`, `FloatField()` accessors with JSON float64 coercion (#397)
- `NoOpMetrics` base struct for composable Metrics implementations (#401)
- `WithFactory` LoadOption for per-call factory overrides (#399)
- `webhook.WithDiagnosticLogger`, `syslog.WithDiagnosticLogger`, `loki.WithDiagnosticLogger`, `file.WithDiagnosticLogger` functional options on each output module's `New()` — route construction-time TLS and permission warnings to a caller-supplied logger rather than `slog.Default` (#490)
- `outputconfig.WithDiagnosticLogger` LoadOption — threads the auditor's diagnostic logger through every output constructed by `outputconfig.Load`. Pair with `audit.WithDiagnosticLogger` on the `Auditor` for consistent routing of both construction-time and runtime warnings (#490)
- Runtime introspection methods: `QueueLen()`, `QueueCap()`, `OutputNames()`, `IsCategoryEnabled()`, `IsEventEnabled()`, `IsDisabled()`, `IsSynchronous()` (#404)
- `docs/writing-custom-outputs.md` — interface hierarchy and decision tree (#397)
- `docs/migrating-from-application-logging.md` — side-by-side coexistence guide (#397)

### Changed

- All 18 examples rewritten to use simplified API — net deletion of 285 lines (#396)
- Unknown output type error message now suggests both specific import and convenience package (#393)
- `audittest.NewQuick` defaults to synchronous delivery (#403)

- `default_formatter` YAML key removed — set `formatter:` on each output individually. Outputs without a `formatter:` block default to JSON. If you previously used `default_formatter: { type: json, timestamp: unix_ms }` or `default_formatter: { omit_empty: true }`, move those settings to each output's `formatter:` block or use `auditor: { omit_empty: true }` for the `omit_empty` case (#305)
- Progressive examples renumbered: outputs grouped together, 04-12 → 05-17 with gaps for new examples (#278)
- Progressive examples renumbered: new 03-standard-fields inserted, 03-11 → 04-12 (#237)
- Bare optional declaration of reserved standard fields now rejected by `ValidateTaxonomy` — use `required: true` or add labels (#237)
- CEF `event_category` extension key changed from `eventCategory` to `cat` (ArcSight `deviceEventCategory`) (#237)
- `Auditor.Audit(eventType, fields)` replaced by `Auditor.AuditEvent(Event)` (#205)
- Taxonomy YAML `required:` and `optional:` replaced by unified `fields:` map (#195)
- `Taxonomy.Categories` type changed from `map[string][]string` to `map[string]*CategoryDef` (#188)
- `EventDef.Category` (string) replaced by `EventDef.Categories` ([]string) — derived from categories map (#188)
- `category:` field removed from YAML event definitions (#188)
- `MatchesRoute` signature now requires a `severity int` parameter (#187)
- `Taxonomy.DefaultEnabled` field removed — all categories are enabled by default (#12)
- `InjectLifecycleEvents`, `EmitStartup`, and automatic shutdown event removed (#12)
- Buffer-full slog.Warn rate-limited to at most once per 10 seconds across core, webhook, and loki outputs. Drop count included in warning message. (#251)
- JSON post-serialisation append reduced from 6 to 1 allocs/op (#229)
- HMAC drain-loop: hash reuse via Reset() + pre-allocated buffers, 8 → 1 extra alloc per event (#230)
- SSRF dial control extracted from webhook/internal/ssrf to core audit package (#256)

## Foundation Releases

### Added

- `secrets.Provider` interface for resolving sensitive config values from external secret stores using `ref+SCHEME://PATH#KEY` syntax in YAML, with optional `BatchProvider` for path-level caching (#353).
- OpenBao secret provider (`go-audit/secrets/openbao`) — thin HTTP client, HTTPS-only, SSRF protection, redirect blocking, token zeroing on Close (#353).
- Vault secret provider (`go-audit/secrets/vault`) — KV v2 API support, HTTPS-only, SSRF protection, redirect blocking, token zeroing on Close (#353).
- Secret-resolution pipeline: env vars → ref resolution → safety-net scan for unresolved refs. HMAC `enabled` resolved first so remaining HMAC refs are skipped when HMAC is disabled. `WithSecretProvider` and `WithSecretTimeout` LoadOptions on `outputconfig.Load()` (#353).
- Secrets documentation: authentication guide, troubleshooting, error reference, plus 22 BDD scenarios + 6 real-container integration scenarios (OpenBao + Vault with dev-TLS) and Docker Compose for both providers (#353).
- **Grafana Loki output** (`go-audit/loki`) — stream labels, gzip compression, multi-tenancy, batched delivery with retry (#251)
  - Config: URL, BasicAuth/BearerToken, TenantID, static + dynamic labels, batching, compression
  - Stream labels: app_name, host, pid, event_type, event_category, severity (individually toggleable)
  - HTTP delivery: exponential backoff retry on 429/5xx, Retry-After support, SSRF protection
  - `FrameworkFieldReceiver` interface for outputs to receive app_name, host, pid
  - 11 integration tests against real Loki, 480+ BDD scenarios, 95% unit test coverage
  - HMAC integrity: end-to-end verification through Loki pipeline (7 BDD scenarios)
  - Multi-output fan-out with Loki: file+Loki, routing, HMAC consistency, failure isolation (7 BDD scenarios)
  - Docker TLS infrastructure: loki-tls (port 3101) and loki-mtls (port 3102) containers
- Syslog output severity mapped dynamically from audit event severity: audit 10→LOG_CRIT, 8-9→LOG_ERR, 6-7→LOG_WARNING, 4-5→LOG_NOTICE, 1-3→LOG_INFO, 0→LOG_DEBUG. Syslog output now implements `MetadataWriter` (#285)
- `MetadataWriter` optional interface for outputs that need structured per-event context (#250)
- `EventMetadata` value type: event type, severity, category, timestamp — zero-allocation, passed by value (#250)

- `WithAppName`, `WithHost`, `WithTimezone` options for logger-wide framework fields (#237)
- `FrameworkFieldSetter` interface for formatters to receive app_name, host, timezone, pid (#237)
- `pid` framework field auto-captured via `os.Getpid()` at construction (#237)
- JSON output: `app_name`, `host`, `timezone`, `pid` after `duration_ms`, before user fields (#237)
- CEF output: `deviceProcessName`, `dvchost`, `dtz`, `dvcpid` framework extensions (#237)
- `app_name`, `host`, `timezone` top-level keys in outputs YAML with env var support (#237)
- `standard_fields` YAML section for deployment-wide reserved field defaults (#237)
- Syslog `hostname` auto-injected from top-level `host` when not set per-output (#237)
- Code generation: setter methods and field constants for all 31 reserved standard fields on every builder (#237)
- `WithStandardFieldDefaults` option for deployment-wide reserved field defaults (#237)
- Syslog `hostname` config field overrides `os.Hostname()` in RFC 5424 header (#237)
- 31 reserved standard fields always accepted without taxonomy declaration (#237)
- Expanded default CEF field mapping from 7 to 28 ArcSight extension keys (#237)
- Per-output HMAC integrity verification with 6 NIST-approved algorithms (#216)
- `HMACConfig`, `ComputeHMAC`, `VerifyHMAC` for tamper detection and verification (#216)
- `_hmac` and `_hmac_v` reserved framework fields (#216)
- `event_category` framework field appended to serialised output (JSON and CEF) showing the delivery-specific category (#227)
- `emit_event_category` taxonomy config (under `categories:`) controls category emission; defaults to `true` (#227)
- `PostField` and `AppendPostFields` extensible post-serialisation append mechanism (#227)
- Reserved field name validation: `timestamp`, `event_type`, `severity`, `event_category` rejected as user-defined fields (#227)
- `audittest` package: in-memory `Recorder` and `MetricsRecorder`, `New`, `NewQuick`, `QuickTaxonomy`, `WithConfig`, `WithValidationMode` for consumer testing (#184)
- `Event` interface, `LabelInfo`, `FieldInfo`, `CategoryInfo` core types (#205)
- `NewEvent()` for dynamic event construction without code generation (#205)
- Per-event typed builders with required-field constructors and optional-field setters (#205)
- `audit-gen` generates typed event builders alongside existing constants (#205)
- Per-event `{Name}Fields` descriptor structs with `FieldInfo()` metadata accessor (#205)
- `Categories()` method on builders returning `[]audit.CategoryInfo` (#205)

- `SensitivityConfig` and `SensitivityLabel` for field-level sensitivity labels (#195)
- Three labeling mechanisms: explicit per-field annotation, global field name mapping, regex patterns (#195)
- Per-output `exclude_labels` strips labeled fields before delivery (#195)
- `WithNamedOutput` accepts variadic `excludeLabels` for output-level field stripping (#195)
- `audit-gen` generates `Label` constants when taxonomy has sensitivity labels (#195)
- Framework fields (timestamp, event_type, severity, duration_ms) protected from labeling (#195)

- `CategoryDef` struct with `Severity *int` for per-category CEF severity (#186)
- `EventDef.Severity *int` for per-event severity override; `EventDef.ResolvedSeverity()` returns resolved value (#186)
- `severity` framework field in JSON output, emitted after `event_type` (#186)
- CEF formatter uses taxonomy `Description` and `ResolvedSeverity()` when `DescriptionFunc`/`SeverityFunc` are nil (#186)
- Events can belong to multiple categories (#188)
- Uncategorised events (not in any category) are valid and always globally enabled (#188)
- `EventRoute.MinSeverity` and `EventRoute.MaxSeverity` for severity-based event routing (#187)
- `ValidateEventRoute` validates severity range (0-10) and min ≤ max (#187)
- Webhook `allow_insecure_http` and `allow_private_ranges` configurable via YAML (#181)
- Stdout factory rejects non-empty config blocks (#182)
- Eight progressive example applications in `examples/` (#163)
- YAML-based output configuration with registry pattern (`outputconfig` module) (#172)
- Output factory registry in core `audit` package: `OutputFactory`, `RegisterOutputFactory`, `LookupOutputFactory`, `RegisteredOutputTypes` (#172)
- Factory registration for file, syslog, and webhook outputs via `init()` and `NewFactory(metrics)` (#172)
- Environment variable substitution (`${VAR}`, `${VAR:-default}`) with post-parse expansion for YAML injection safety (#172)
- Per-output routing, formatter overrides, and `enabled` toggle in YAML config (#172)
- `audit-gen` CLI for generating type-safe audit event helpers from taxonomy YAML (#26)
- Taxonomy description field support (#161)
