# Contributing to audit

Thank you for your interest in contributing to audit. This document
covers the development setup, coding standards, and pull request process.

> **Deploying audit**, not contributing to it? See
> [docs/deployment.md](docs/deployment.md) for systemd, Kubernetes,
> Docker, capacity planning, and file-output parent-directory
> guidance.

## Development Setup

```bash
git clone https://github.com/axonops/audit.git
cd audit
make install-tools   # golangci-lint v2.1.6, govulncheck v1.1.4, goimports, goreleaser
make workspace       # creates go.work for IDE tooling (gitignored)
make check-static    # all 8 static-analysis guards in one shot
make check           # runs the full quality gate locally
```

> **First time?** Read
> [docs/development-workflow.md](docs/development-workflow.md) for
> the full multi-module workflow story — what `make workspace`
> does, why every sub-module has its own `go.mod`, how releases
> rewrite versions, and a troubleshooting section for the
> common failure modes (`unknown revision`, `go mod tidy`
> rewriting files, Docker build can't find module).

`make check-static` runs the same eight checks the CI hygiene job
runs (formatting, module tidiness, replace directives, orphaned
TODOs, InsecureSkipVerify production-code guard, example
cross-references, BDD strict-mode guard, benchmark-baseline
freshness) in a `||`-guarded loop, so every failure surfaces on
one push rather than aborting on the first. `make check`
incorporates `check-static` plus `vet-all`, `lint-all`,
`test-all`, `build-all`, `test-examples`, `verify`,
`release-check`, and `security`.

Requires **Go 1.26+**.

### Go Version Support

The library targets the Go release declared in `go.mod` (currently
`go 1.26+`). CI validates the build, vet, lint, and full test suite
against that single toolchain version on every PR.

The project's policy goal — pre-v1.0 — is to be compatible with the
Go release in `go.mod` AND the immediately preceding minor release,
mirroring the upstream Go release policy. A multi-version CI matrix
that enforces this is part of the v1.0 prep; until then, treat the
N-1 minor as best-effort.

**Lifecycle rules:**

- **Adding** support for a newer Go release is a non-breaking change
  and MAY land in any minor or patch release.
- **Dropping** support for a Go release is a **breaking change** from
  `v1.0` onward. It bumps the `go` directive in every module's
  `go.mod` and requires a `CHANGELOG.md` entry under `### Removed`.
  From `v1.0`, drops MUST land in a major-version release
  (e.g., `v1.x → v2.0`). While the library is pre-release (`v0.x`),
  Go-version drops MAY land in any `v0.x` minor release but MUST
  appear in `### Removed` in the CHANGELOG.
- A Go minor release receives security fixes until two newer minor
  releases have shipped — at that point it goes out of upstream
  support (see [Go release policy](https://go.dev/doc/devel/release)).
  The library will not retain a `go` directive pinned to an
  upstream-unsupported release.

Consumers tracking minor or patch releases never need to upgrade
their toolchain. Consumers tracking a major release upgrade (e.g.,
`v1` → `v2`) should expect the `go` directive to advance.

### Supported Platforms

The library is tested in CI on:

- `ubuntu-latest` (Linux x86_64) — primary CI target
- `macos-latest` (macOS arm64)
- `windows-latest` (Windows x86_64)

The cross-platform matrix covers the **core** and **file**
modules; remaining modules (syslog, webhook, loki, outputconfig,
secrets/*, cmd/*) are tested only on Linux because their
primary deployment target is Linux server-side. If you need
broader platform coverage for a specific output, please file
an issue — adding a runner is straightforward.

A small number of file-output tests (POSIX permission-mode
assertions, directory-readonly tests) skip on Windows because
the POSIX permission model does not translate. The skip
mechanism is grep-able: `runtime.GOOS == "windows"`. Coverage
for these paths remains via the Linux + macOS runs.

## Running Tests

```bash
make test              # unit tests for all modules
make test-integration  # integration tests (requires Docker)
make test-bdd          # BDD tests (requires Docker)
make check             # full quality gate (same checks as CI)
make sbom              # generate CycloneDX + SPDX SBOMs (requires syft)
make sbom-validate     # validate generated SBOMs
```

Individual modules can be tested separately: `make test-core`,
`make test-file`, `make test-syslog`, `make test-webhook`,
`make test-outputconfig`, `make test-audit-gen`.

This project does not use pre-commit hooks. Run `make check` before
committing to execute the full quality gate locally.

### Security invariants enforced statically

`make check` chains a set of static guards that reject
high-impact security misuse before it can land. The most
important is `make check-insecure-skip-verify`, which fails the
build if any production-code `.go` file sets
`InsecureSkipVerify: true`. CI's `Hygiene` job runs the same
guard. See [SECURITY.md](SECURITY.md#static-analysis-guards)
for the full list and the exemption mechanism.

### BDD Strict mode — non-negotiable

Every `godog.Options{}` block in every test file MUST include
`Strict: true`. Without it, scenarios whose step definitions are
missing pass silently — the BDD suite reports them as "undefined"
but the test still exits zero, and CI misses the regression.

This caused a months-long silent-failure window in `outputconfig`
BDD (issues #622 and #476). To prevent recurrence:

- `make check-bdd-strict` runs as part of `make check` and as a
  dedicated **Hygiene** step in CI, executed BEFORE the test
  matrix so a regression fails loudly and early.
- The check rejects three patterns: (1) any `godog.Options{}`
  block missing `Strict: true`; (2) any `Strict: false` anywhere
  in Go source; (3) any `--godog.strict=false` flag in a Makefile,
  shell script, or CI config.

**Under no circumstances may a PR be merged that disables Strict
mode, weakens the `check-bdd-strict` target, or removes the CI
step.** Attempts to bypass the check with `//nolint` comments,
build tags, or conditional shell expressions are a review-rejection
criterion independent of the underlying change's merits.

If you hit an undefined step, the fix is to define the step — not
to disable Strict. If you need to stage a scenario before its steps
exist, do not commit the scenario yet.

### Fuzz Testing (#481)

Four untrusted-input parsers have Go fuzz targets:

| Target | Fuzz function | Location |
|---|---|---|
| `audit.ParseTaxonomyYAML` | `FuzzParseTaxonomyYAML` | `taxonomy_yaml_fuzz_test.go` |
| `outputconfig.Load` | `FuzzOutputConfigLoad` | `outputconfig/outputconfig_fuzz_test.go` |
| `outputconfig.expandEnvString` | `FuzzExpandEnvString` | `outputconfig/envsubst_fuzz_test.go` |
| `secrets.ParseRef` | `FuzzParseRef` | `secrets/secrets_fuzz_test.go` |

**Regular PR CI** runs each fuzz function against its committed
seed corpus via `go test` — no `-fuzz` flag, just seeds as regular
sub-tests. Committed crashers live under `testdata/fuzz/FuzzXxx/`
and protect against regressions.

**Release workflow** runs `make fuzz-long` (default 5 minutes per
target) as a blocking gate — any crasher fails the release. Crash
inputs are uploaded as a workflow artifact for triage.

**Local fuzzing** — reproduce a seeded run quickly:
```bash
make fuzz-short                       # seeds only, < 1s
make fuzz-long                        # 60s per target
make fuzz-long FUZZ_TIME=10m          # 10 minutes per target
go test -fuzz=FuzzParseRef -fuzztime=30s ./secrets  # single target
```

If the fuzzer finds a crasher, it writes the reproducer to
`testdata/fuzz/FuzzXxx/<hash>`. Commit that file alongside the
fix — it becomes a permanent regression seed.

### Benchmarks and regression detection (#493)

The repo ships a committed baseline in `bench-baseline.txt` and a
human-readable summary in `BENCHMARKS.md`. The release workflow runs
`make bench-compare` as an advisory step (GitHub Actions runners are
too noisy for a hard threshold) and uploads the delta report as a
`bench-delta` artifact plus a summary in the GitHub Actions summary.

**Running benchmarks locally:**
```bash
make bench                      # run all modules → bench.txt (count=5)
make bench BENCH_COUNT=3        # faster, less statistical power
make bench-compare              # bench + benchstat vs bench-baseline.txt
make bench-save                 # bench and copy output to bench-baseline.txt
```

**Reading `make bench-compare` output.** benchstat produces a
two-column delta report (baseline vs current). A `+5.00%` under
`sec/op` means 5% slower; a `-2.00%` means 2% faster. The `p=...`
column reports statistical confidence (`p < 0.05` is the usual
threshold for a real delta). A blank column or `~` means the
confidence interval spans zero — run with a higher `BENCH_COUNT` to
get a clearer signal.

**When to refresh `bench-baseline.txt`:**

- A benchmark is renamed. `make bench-baseline-check` (part of
  `make check`) rejects a PR that introduces a stale name.
- A hot-path change lands that moves numbers meaningfully — say
  after a #494–#508 style performance issue.
- Before any milestone release (`docs/releasing.md` Pre-Release
  Checklist calls this out explicitly).

Refresh with `make bench-save` on consistent local hardware, update
`BENCHMARKS.md` with the new headline numbers, and commit both files
together in a `chore: refresh bench-baseline ...` commit.

### Running mutation tests (#571)

Mutation testing checks whether the test suite verifies behaviour or
merely traverses lines. `gremlins` applies mutation operators (boundary
inversions, conditional negations, arithmetic flips) to the source and
re-runs the tests; a surviving mutant reveals a test that doesn't
actually verify the contract for that branch.

We run mutation testing against six security-critical files in the root
package:

- `validate_fields.go` — runtime field validation
- `validate_taxonomy.go` — taxonomy structural validation
- `hmac.go` — HMAC computation and salt-version handling
- `filter.go` — event routing and severity range checks
- `format_cef.go` — CEF wire-format escaping
- `sensitivity.go` — sensitivity label resolution

**Targets:**
```bash
make mutation-test                 # all six files (~60 min total)
make mutation-test-hmac            # one file (~10 min)
make mutation-test-validate-fields
make mutation-test-validate-taxonomy
make mutation-test-filter
make mutation-test-format-cef
make mutation-test-sensitivity
```

Each target invokes `gremlins` once with `--exclude-files` set so that
exactly one file is mutated. Configuration lives in `.gremlins.yaml`
(thresholds, mutation operators); the Makefile chooses the file scope.
Threshold (efficacy ≥ 80%) is enforced via gremlins' exit code.

The current per-file baseline is recorded in `MUTATION_TESTING.md`
along with any equivalent-mutant exemptions. Refresh before any
milestone release.

**When a target fails.** gremlins prints `LIVED <operator> at
<file>:<line>:<col>` for each surviving mutant. Three responses, in
order of preference:

1. **Kill the mutant.** Add a test in the matching `*_test.go` whose
   assertion fails when the mutated branch flips. Test the contract
   bidirectionally — at-boundary AND just-past-boundary — so the
   symmetric mutant is also caught. Don't write a `TestKillMutantN`
   test; re-derive the case from the spec the mutated line implements.
2. **Document an equivalent mutant.** If the mutation produces
   functionally identical behaviour (e.g., a redundant defensive
   nil-check, an allocation-only difference), add an entry to
   `MUTATION_TESTING.md` with the file:line, mutant operator, and a
   one-or-two-sentence justification. If you can't articulate why it's
   equivalent in plain English in 30 seconds, it's not equivalent —
   you have a missing test.
3. **Lower the threshold (last resort).** Contributors MUST exhaust
   options 1 and 2 before considering this. Update `.gremlins.yaml`
   thresholds with a code comment explaining why the bar moved, and
   open a PR for explicit review. Rolling the threshold back is a
   non-trivial regression of test quality and MUST NOT be used to
   make a flaky run pass.

`make install-tools` installs the pinned gremlins version
(`scripts/tool-versions.txt`). For a local-only install, run
`make install-gremlins`.

#### Reading the CI workflow report (#524)

Mutation testing runs in CI in three modes (workflow files at
`.github/workflows/`):

- **Per PR** (`ci.yml`) — only the targets whose source or test file
  changed in the PR (or all six if `.gremlins.yaml` changed). Each
  matrix shard uploads an artefact named
  `mutation-test-report-<target>-<sha>` where `<target>` matches the
  make-target stem with underscores (e.g.
  `mutation-test-report-validate_fields-abc1234`); 7-day retention.
- **Weekly** (`mutation-test.yml`, Sundays 04:00 UTC) — full suite,
  uploads `mutation-test-report-all-<sha>`; 90-day retention. Also
  triggerable manually via `workflow_dispatch` with optional
  per-target scope (single-target dispatches upload
  `mutation-test-report-<target>-<sha>` instead).
- **On release tag** (`release.yml`, workflow_dispatch path only) —
  full suite as a release gate. The Actions artefact name is
  `mutation-test-report-release-<version>` (90-day retention); the
  same report is then attached to the published GitHub Release page
  as the asset `mutation-test-report.txt` (permanent on the release).

To download a CI artefact:

```bash
# List recent runs — note the RUN_ID in the first column
gh run list --workflow=mutation-test.yml --limit 5

# Resolve the SHA for that run, then download by exact artefact name
SHA=$(gh run view <RUN_ID> --json headSha --jq .headSha)
gh run download <RUN_ID> --name "mutation-test-report-all-${SHA}"
```

The artefact is the captured stdout of `make mutation-test`.
`` `LIVED <operator> at <file>:<line>:<col>` `` lines identify
surviving mutants; cross-reference each against `MUTATION_TESTING.md`
(repo root) to determine whether it's a genuine regression (kill it
with a new test) or matches an existing equivalent-mutant exemption.

To verify the workflow itself is detecting surviving mutants — e.g.
after a gremlins version bump or a `.gremlins.yaml` change — apply a
deliberately-weak assertion to one of the target files' tests
(`assert.NotNil(...)` instead of an exact comparison), trigger
`mutation-test.yml` via `workflow_dispatch`, and confirm the report
contains LIVED entries.

> **Warning:** the weak assertion MUST NOT be committed. `make check`
> does not detect weakened assertions — keep the change in a local
> `git stash` or a throwaway `git worktree`, and revert before
> opening a PR.

A `workflow_dispatch` run fired while the Sunday scheduled run is
still in flight waits for the scheduled run to finish before starting
(`cancel-in-progress: false`); expect up to ~3 hours before results
are available.

## Code Standards

The [Google Go Style Guide](https://google.github.io/styleguide/go/)
is the baseline. Key points:

- **External test packages** — use `package audit_test`, not `package audit`
- **Error wrapping** — `fmt.Errorf("audit: context: %w", err)` with `%w` as the final verb
- **Naming** — no stutter (`audit.Auditor` not `audit.AuditAuditor`), no `Get` prefix, acronyms in caps (`ID`, `URL`)
- **Godoc** — all exported symbols have comments starting with the symbol name
- **Coverage** — target 90%+; `goleak.VerifyNone(t)` on tests that start goroutines
- **No panics** — this is a library; no `log.Fatal`, `os.Exit`, or `panic` that escapes the package boundary

## Commit Conventions

Conventional commits are required:

```
feat: add webhook retry backoff (#42)
fix: prevent buffer overflow on slow outputs (#43)
test: add CEF formatter edge cases (#44)
docs: update syslog configuration reference (#45)
```

- **One logical change per commit**
- **Reference the issue number** in every commit message
- **Imperative mood** — "add feature" not "added feature"

## Pull Request Process

1. **File an issue first** for significant work — this avoids duplicated effort
2. **Branch from `main`** as `feature/<short-name>` or `fix/<short-name>`
3. **Write tests with the code** — if it is not tested, it is not done
4. **Run `make check`** — this runs the same checks as CI
5. **Open a PR** — keep the title under 70 characters; use the description for details
6. **CI must pass** — the `CI Pass` summary job gates all merges

Never commit directly to `main`.

## Branch and Commit Rules

The `main` branch has protection rules enforced by GitHub:

- **Signed commits required** — all commits must be GPG or SSH
  signed. See [GitHub's signing docs](https://docs.github.com/en/authentication/managing-commit-signature-verification)
  for setup instructions.
- **Linear history** — only squash or rebase merges are allowed.
  No merge commits.
- **No force pushes** — `git push --force` to `main` is blocked.
- **No branch deletion** — `main` cannot be deleted.
- **Status checks** — the `CI Pass` job must be green before merge.
  This aggregates all per-module build, lint, test, and security jobs.
- **Up-to-date branches** — your branch must be rebased on the
  latest `main` before merging.

Tags for every published module are protected — they cannot be
deleted or force-updated once created. The full pattern list is
in [docs/releasing.md](docs/releasing.md) under "Tag protection";
that file is the single source of truth, regenerated from the
canonical `PUBLISH_MODULES` list.

### Nightly dependency-update PR

A scheduled workflow
([`.github/workflows/dependency-update.yml`](.github/workflows/dependency-update.yml))
runs daily at 02:00 UTC and posts transitive Go dependency updates
to a single long-lived PR on the `chore/nightly-dep-update` branch.
The PR is updated **in place** — new commits are appended on each
iteration rather than force-pushed — so reviewer line comments stay
attached to their original commits and remain visible across runs.

Contributors MUST NOT push directly to `chore/nightly-dep-update`.
The workflow owns the branch exclusively; an external push will
either be overwritten on the next nightly run or cause the run to
fail with a non-fast-forward error.

The PR description is refreshed with the latest main-vs-current diff
on each run; if you have ticked any review checkboxes in the body,
they will be reset on the next iteration (each day's diff differs,
so the checklist warrants a fresh look). PR-level conversation
comments are never reset.

When the PR is **merged with branch deletion**, the next nightly run
starts a fresh cycle: it creates a new branch from `main` and opens a
new PR. When the PR is **closed without merging** (or merged without
branch deletion), the branch persists; the next nightly run appends
on top and opens a new PR pointing to the same branch. To force a
clean reset, delete the branch manually.

## CI Behaviour

The `CI` workflow (`.github/workflows/ci.yml`) detects whether a
PR touches code or only documentation. The detection lives in the
`changes` job near the top of the workflow and uses a `git diff`
pathspec exclusion list.

**Docs-only PRs skip the Go pipeline.** A PR whose diff touches
only the following paths runs `changes` + `hygiene` +
`validate-release` (≈2 minutes total) and skips the Go build,
lint, test, integration, BDD, security, and cross-platform jobs:

- `*.md` and `**/*.md` (every Markdown file at any depth)
- `docs/**`
- `LICENSE`, `NOTICE`
- `**/CHANGELOG*`, `**/CONTRIBUTING*` (with or without `.md`)
- `.github/ISSUE_TEMPLATE/**`
- `.claude/**` (defensive — the directory is gitignored, but the
  exclusion catches accidental commits)

`hygiene` and `validate-release` continue to run because they catch
real drift on docs-only PRs — for example,
`make regen-release-docs-check` (in `hygiene`) verifies the
auto-generated module table in `docs/releasing.md` is in sync with
the canonical `PUBLISH_MODULES` list.

**Mixed PRs run the full pipeline.** If the diff includes any
non-docs file, every CI job runs. There is no per-job opt-out for
mixed PRs.

**Branch protection** is satisfied by a single aggregate check:
`Test - CI Pass`. That job has `if: always()` and treats `skipped`
results as success, so a docs-only PR satisfies the gate without
any maintainer action.

**Workflow changes always run full CI.** Files under
`.github/workflows/**` are deliberately NOT excluded from the
detection list — a workflow change must exercise the full pipeline
before merging.

**Forcing full CI on a docs-only change.** If a docs change needs
the full pipeline (rare — e.g., regenerating a doc alongside an
embedded test that depends on it), bundle the doc change with the
code change in the same PR; mixed PRs run everything. Manually
re-running the workflow via `Actions → CI → Run workflow` also
forces full CI because the `workflow_dispatch` trigger sets
`code=true` unconditionally.

**Maintenance.** When adding a new docs-like path, edit the
pathspec in `.github/workflows/ci.yml` `changes` job (single source
of truth). When adding a new CI job, follow the maintenance note
above the `ci-pass` job: add the job name to its `needs:` list and
gate it on `if: needs.changes.outputs.code == 'true'` if it should
skip on docs-only PRs.

## Dependencies

Dependencies are kept minimal. The core library depends on
`github.com/goccy/go-yaml` (taxonomy parsing) and
`github.com/axonops/syncmap` (generic, type-safe wrapper around
`sync.Map` for the lock-free filter-state hot path). Output
modules carry their own dependencies — `github.com/axonops/srslog`
for syslog, etc.

Both runtime dependencies are AxonOps-controlled forks of
their upstream projects, which lets us self-impose the supply-chain
acceptance criteria (CI, CodeQL, Dependabot, SECURITY.md, signed
releases, CLA) that #158 originally tracked as upstream feature
requests. Upstream attribution lives in the forks' `NOTICE` files.

Before adding a new dependency, file an issue to discuss it. Forbidden
in core: Prometheus, OpenTelemetry, any logging framework, any config
file parser beyond what already exists.

## Multi-Module Development

Workspace setup, the `go.work` lifecycle, day-to-day inner-loop
commands, the release-flow implications, Docker / consumer
caveats, and the troubleshooting playbook are all in
[docs/development-workflow.md](docs/development-workflow.md).
Start there if `make check` produces resolution errors or if
`go.mod` files look stale on your branch.

## Project Layout

See [ARCHITECTURE.md](ARCHITECTURE.md) for the pipeline design, module
boundaries, and key source files.

## Release Process

Releases are cut by maintainers. Contributors do not create release tags.

The full release procedure — pre-release checklist, the unified single-tag
flow, the `axonops-audit-release-bot` GitHub App, the `api-check` gate, proxy
verification, and retraction policy — is documented in
[docs/releasing.md](docs/releasing.md). That file is the single source of
truth for the release contract.

Key points for contributors:

- Do not create release tags. Every published module's `v*` pattern is
  tag-protected; only the release-bot App can create them. The full list
  of protected patterns is in `docs/releasing.md`.
- Do not add `replace` directives to `go.mod` on any branch intended for
  merge — `make check-replace` enforces this in CI. Use the workspace
  (see [docs/development-workflow.md](docs/development-workflow.md))
  for local cross-module work instead.

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).

## Questions?

Open a [GitHub issue](https://github.com/axonops/audit/issues) —
there are no mailing lists or chat channels.
