[&larr; Back to README](../README.md)

# Releasing audit

- [How Go Module Publishing Works](#how-go-module-publishing-works)
- [For Maintainers: Cutting a Release](#for-maintainers-cutting-a-release)
- [For Maintainers: Verification Tools](#for-maintainers-verification-tools)
- [For Maintainers: CI Health](#for-maintainers-ci-health)
- [For Contributors](#for-contributors)
- [For Consumers](#for-consumers)

---

## How Go Module Publishing Works

### The Go Module Proxy

When a consumer runs `go get github.com/axonops/audit@v0.1.1`, the Go
toolchain contacts [proxy.golang.org](https://proxy.golang.org). The proxy
fetches and permanently caches the module source from GitHub at the exact
commit pointed to by that tag. The checksum is recorded in
[sum.golang.org](https://sum.golang.org) — a transparency log.

Two consequences follow directly from this:

- **A published tag is permanent.** Once a version is fetched through the
  proxy, it exists in the checksum database forever. Deleting or force-pushing
  a tag does not remove it from the proxy or the checksum log. Consumers who
  already fetched that version will get a checksum mismatch error if the tag
  is later changed. A tag that has been pushed MUST NOT be modified.

- **Publication is automatic.** There is no `go publish` command. Pushing a
  tag triggers indexing the next time any consumer (or the
  `publish-verify` workflow) requests that version. The proxy fetches from
  GitHub on demand.

[pkg.go.dev](https://pkg.go.dev) pulls its documentation from the same proxy.
It indexes asynchronously — expect up to 30 minutes after the first `go get`
before the documentation page appears.

### Multi-Module Tagging Scheme

This repository publishes twelve Go modules. Each module has its own `go.mod`,
and the Go toolchain identifies versions by tag with a path prefix for
sub-modules. The full list is generated from the canonical `PUBLISH_MODULES`
variable in `Makefile` — run `make regen-release-docs` after adding or
removing a module:

<!-- BEGIN PUBLISH_MODULES TABLE — do not edit; run `make regen-release-docs` to update -->

| Module | Path | Tag prefix |
|--------|------|------------|
| `(repo root)` | `github.com/axonops/audit` | `v*` |
| `file` | `github.com/axonops/audit/file` | `file/v*` |
| `syslog` | `github.com/axonops/audit/syslog` | `syslog/v*` |
| `webhook` | `github.com/axonops/audit/webhook` | `webhook/v*` |
| `loki` | `github.com/axonops/audit/loki` | `loki/v*` |
| `outputconfig` | `github.com/axonops/audit/outputconfig` | `outputconfig/v*` |
| `outputs` | `github.com/axonops/audit/outputs` | `outputs/v*` |
| `cmd/audit-gen` | `github.com/axonops/audit/cmd/audit-gen` | `cmd/audit-gen/v*` |
| `cmd/audit-validate` | `github.com/axonops/audit/cmd/audit-validate` | `cmd/audit-validate/v*` |
| `secrets` | `github.com/axonops/audit/secrets` | `secrets/v*` |
| `secrets/env` | `github.com/axonops/audit/secrets/env` | `secrets/env/v*` |
| `secrets/file` | `github.com/axonops/audit/secrets/file` | `secrets/file/v*` |
| `secrets/openbao` | `github.com/axonops/audit/secrets/openbao` | `secrets/openbao/v*` |
| `secrets/vault` | `github.com/axonops/audit/secrets/vault` | `secrets/vault/v*` |
<!-- END PUBLISH_MODULES TABLE -->

### Unified single-tag release flow

Background — under the legacy three-tier dance (retired #513) tags pointed
at three different commits on `main`, with separate `go.mod` updates pushed
between tiers. That layout produced version drift (e.g. `outputs` lagging at
v0.1.9 while everything else moved to v0.1.11) and made post-release
auditing harder than it needed to be.

The current flow tags **every published module at the same merge commit**.
The release workflow opens one PR that pins every inter-module `go.mod` in a
single commit, waits for branch-protection-respecting auto-merge, then
creates all twelve annotated tags pointing at that one merge SHA. The
post-release `make check-release-invariants VERSION=...` job verifies that
every published `go.mod` references the released version. Drift is
prevented structurally — there is no longer any commit window where modules
disagree on the release.

**Invariant: `SKIP_TIDY_CHECK` is honoured only on `release/*` branches.**
The release PR's commit pins every `go.mod` to a tag that does not yet
exist on origin — `tag-all` runs after the PR merges. As
[`scripts/release/update-deps.sh`][update-deps-sh] states inline:
"Tidy is intentionally NOT run — at this point in the release flow
VERSION is not yet a tag on origin, so tidy would fail to resolve."
CI's hygiene step in [`ci.yml`][ci-yml] sets `SKIP_TIDY_CHECK=1` for
branch names matching `release/*` so the same skip applies to the
release PR. The `invariants` job in [`release.yml`][release-yml] —
which runs after `tag-all` in the same workflow execution — re-runs
tidy and verifies correctness once the tag exists. Operators hitting
a tidy failure on a `release/*` branch should confirm
`SKIP_TIDY_CHECK=1` is being applied — the variable is intentionally
not set anywhere else in the codebase (`make
check-skip-tidy-check-scope` guards this). The
contributor-facing view of this invariant is documented in
[development-workflow.md](development-workflow.md#the-release-cycle).

[ci-yml]: ../.github/workflows/ci.yml
[release-yml]: ../.github/workflows/release.yml
[update-deps-sh]: ../scripts/release/update-deps.sh

### v0.x Stability Contract

This library is pre-release (`v0.x`). The Go module system treats v0 the same
as v1 for import paths — no `/v2` suffix is needed. However, v0.x releases
carry no API stability guarantee. Breaking changes MAY occur between minor
versions (`v0.1.x` → `v0.2.x`). Consumers MUST pin to a specific version:

```bash
go get github.com/axonops/audit@v0.1.1
```

The library will increment to v1.0.0 when the API is considered stable. At
that point the stability guarantees described in the
[Go module compatibility rules](https://go.dev/blog/module-compatibility) will
apply: no breaking changes within a major version.

### The "Never Modify a Published Tag" Rule

Once any published tag has been fetched through `proxy.golang.org` or recorded
in `sum.golang.org`, it is sealed. The constraint is absolute:

- Force-pushing a tag causes `go mod verify` to fail for every consumer who
  already fetched that version.
- Deleting a tag does not remove it from the proxy cache.
- Moving a tag to a different commit changes the source code the tag resolves
  to, which breaks the checksum verification for anyone who downloaded it.

If a release contains a serious bug, the correct response is:
1. Publish a new patch version with the fix.
2. Add a `retract` directive (see [Retracting a Bad Release](#retracting-a-bad-release)).

---

## Verify a Release with Cosign

Every release publishes two artifacts alongside the usual binaries
and `checksums.txt`:

- `checksums.txt.sig` — Sigstore-keyless signature of the checksum
  file.
- `checksums.txt.pem` — short-lived X.509 certificate issued by
  Fulcio, binding the signature to the GitHub Actions identity that
  produced this release.

The signing flow uses Sigstore [keyless OIDC] — there is no
long-lived private key. Each release identity is the workflow file
that produced it; the certificate's lifetime is ten minutes; the
signature is recorded in the public Rekor transparency log.

[keyless OIDC]: https://docs.sigstore.dev/cosign/signing/overview/

### Required tools

- [`cosign`](https://docs.sigstore.dev/cosign/installation/) ≥ v2.5
  — earlier versions do not support the
  `--certificate-github-workflow-repository` flag used below for
  defence-in-depth identity verification.

### Verify the checksum file

Download `checksums.txt`, `checksums.txt.sig`, and `checksums.txt.pem`
from the release page, then run:

```bash
cosign verify-blob \
  --certificate checksums.txt.pem \
  --signature checksums.txt.sig \
  --certificate-identity-regexp '^https://github\.com/axonops/audit/\.github/workflows/release\.yml@refs/tags/v.+$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-github-workflow-repository axonops/audit \
  checksums.txt
```

The regex is anchored on both ends with literal dots escaped — an
unanchored regex (`...v.*`) would also match a malicious identity
like `https://github.com/evil/axonops/audit/.github/workflows/release.yml@refs/tags/v9.9.9-pwn`
because `verify-blob` does substring/regex matching, not exact
equality. The trailing `v.+$` requires at least one character after
`v` so the regex cannot match a non-version path. The
`--certificate-github-workflow-repository` flag is defence-in-depth
— even if the regex anchors were bypassed, cosign rejects the
verification when the workflow's source repository does not match.

A successful run prints `Verified OK` and confirms three things:

1. The checksum file was signed by a workflow run on the
   `axonops/audit` repository (the anchored
   `--certificate-identity-regexp` matches the GitHub Actions OIDC
   subject and `--certificate-github-workflow-repository` matches
   the source repo).
2. The certificate was issued by Fulcio for a GHA OIDC token from
   `token.actions.githubusercontent.com`.
3. The signature is recorded in the Rekor public transparency log;
   this command queries Rekor as part of verification.

### Verify a binary against the verified checksum file

Once `checksums.txt` is verified, every binary listed inside it can
be authenticated by recomputing its hash:

```bash
sha256sum -c checksums.txt --ignore-missing
```

`--ignore-missing` lets you check a single binary without
downloading the rest. The `Verified OK` line from `cosign` plus an
`OK` line from `sha256sum` is the full chain of custody from
`axonops/audit`'s GitHub Actions run to the local file.

### Failure modes

- **`Verified OK` not printed.** The signature does not verify
  against the published certificate — consumers MUST NOT use the
  artifact. Possible causes: wrong file pair (downloading `.sig`
  from one release with `checksums.txt` from another), corrupted
  download, or active tampering. Re-download from
  `https://github.com/axonops/audit/releases` over HTTPS and retry.
- **Identity-regex mismatch.** The certificate identity does not
  match the anchored regex above. This is the strongest red flag
  — someone signed the release from a different repository or
  workflow file. Consumers MUST treat the artifact as untrusted
  and not use it.
- **`tlog entry not found`.** The release was signed but the
  signature is not present in the Rekor public transparency log.
  Real `axonops/audit` releases always record an entry; consumers
  SHOULD treat a missing tlog entry as suspicious and refuse to
  use the artifact.

### Automating verification in CI

The same `cosign verify-blob` command is suitable for a pre-deploy
gate in any CI system. Minimal GitHub Actions example:

```yaml
- name: Verify audit-gen release
  run: |
    set -euo pipefail
    VERSION=v1.0.0
    URL="https://github.com/axonops/audit/releases/download/${VERSION}"
    curl -fsSLO "${URL}/checksums.txt"
    curl -fsSLO "${URL}/checksums.txt.sig"
    curl -fsSLO "${URL}/checksums.txt.pem"
    curl -fsSLO "${URL}/audit-gen_${VERSION#v}_linux_amd64.tar.gz"

    cosign verify-blob \
      --certificate checksums.txt.pem \
      --signature checksums.txt.sig \
      --certificate-identity-regexp '^https://github\.com/axonops/audit/\.github/workflows/release\.yml@refs/tags/v.+$' \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com \
      --certificate-github-workflow-repository axonops/audit \
      checksums.txt

    sha256sum -c checksums.txt --ignore-missing
```

Pin `cosign` to a specific version via
`sigstore/cosign-installer@<sha>` in the workflow.

### Verifying the audit-gen container image (#610)

Each tagged release also publishes a multi-arch OCI image at
`ghcr.io/axonops/audit-gen` with three tags (`vX.Y.Z`, `vX.Y`,
`latest`). Image manifests are signed under the same Sigstore
keyless identity as `checksums.txt`:

```bash
cosign verify \
  --certificate-identity 'https://github.com/axonops/audit/.github/workflows/release.yml@refs/tags/v1.0.0' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  ghcr.io/axonops/audit-gen:v1.0.0
```

See [docs/code-generation.md § Container Image](code-generation.md#-container-image)
for usage and CI-pipeline guidance.

### Composition with build provenance

Every release also publishes a GitHub build-provenance attestation
(`gh attestation verify ...`). The two mechanisms protect different
properties:

- The **cosign signature** proves `checksums.txt` was signed by a
  workflow run on `axonops/audit` at the tagged ref. After
  verifying the checksum file, `sha256sum -c checksums.txt`
  extends that trust to every binary listed inside it.
- The **build-provenance attestation** proves a specific binary
  was built by that workflow from a specific source commit SHA,
  recorded in the Rekor transparency log.

Verify both for a complete supply-chain check from source commit
to local file.

---

## For Maintainers: Repository Protection Configuration

The repository's release contract depends on three layers of GitHub
configuration. Two of them — branch protection and tag protection —
are GitHub UI settings, not committed files. Maintainers MUST verify
these are configured before the v1.0.0 release, and on every
subsequent maintainer onboarding.

### CODEOWNERS (committed)

`.github/CODEOWNERS` declares review-required ownership for every
security-sensitive surface — `.github/workflows/`, `.goreleaser.yml`,
every `go.mod` / `go.sum`, `Makefile`, `scripts/release/`,
`scripts/tool-versions.txt`, `tests/release/`, `SECURITY.md`,
`docs/threat-model.md`, `docs/releasing.md`, `docs/deployment.md`,
and the cryptographic primitives (`hmac.go`, `ssrf*.go`,
`tls_policy.go`, `secrets/`). The release toolchain
(`scripts/release/`, `Makefile`, `tests/release/`,
`scripts/tool-versions.txt`) is included because every script there
runs under the release-bot's elevated token — a malicious edit could
exfiltrate the App's installation token. The catch-all `*` rule
assigns the maintainer team as default reviewer for every other path
so no PR merges without a maintainer's approval.

### Release-bot GitHub App

The release workflow uses a dedicated GitHub App identity — `axonops-audit-release-bot` —
instead of a personal access token (PAT). PAT compromise = full account takeover
across every org the human belongs to; App compromise is scoped to this single
repository plus the App's explicit permissions.

**Required permissions** (set during App creation):

| Permission | Scope | Why |
|---|---|---|
| Contents | Read & write | Push the release branch and the twelve module tags. |
| Pull requests | Read & write | Open the release PR, enable auto-merge. |
| Metadata | Read | Mandatory baseline for all Apps. |
| Workflows | **NOT granted** | Defends against an App-opened PR mutating `release.yml` itself. |

**Repository access**: only `axonops/audit`. Do not install the App org-wide.

**Repository secrets** (Settings → Secrets and variables → Actions → New
repository secret):
- `RELEASE_APP_ID` — the App's numeric ID (visible on the App settings page).
- `RELEASE_APP_PRIVATE_KEY` — the App's PEM-encoded private key.

**One-time UI setup** — order matters; some fields lock after the first
installation:

1. **Settings → Developer settings → GitHub Apps → New GitHub App** (on the
   organisation, not personal account).
2. **GitHub App name**: `axonops-audit-release-bot`.
3. **Homepage URL**: any URL — `https://github.com/axonops/audit` is fine.
4. **Webhook URL**: GitHub's form requires a non-empty URL even when webhooks
   are unused. Enter `https://github.com` and **uncheck Active**. The App will
   not receive webhook events; this field is purely a form requirement.
5. **Repository permissions**: set Contents, Pull requests, Metadata as in the
   table above. Leave everything else as **No access**. Do **not** grant
   Workflows write.
6. **Where can this GitHub App be installed?**: Only on this account.
7. Click **Create GitHub App**.
8. **Generate a private key** — click "Generate a private key" on the App page.
   The PEM file downloads once; store it immediately.
9. **Install the App** on the repository — go to the App's public page → Install
   App → select `axonops/audit` only. The App existing does not grant access;
   installation is a separate UI step (the most commonly missed one).
10. Store `RELEASE_APP_ID` and `RELEASE_APP_PRIVATE_KEY` as repository secrets.
11. Add the App identity to the tag-protection allow-list — see Tag protection
    section below.
12. Verify the App is **NOT** on the branch-protection bypass list — the whole
    point of the App is that release commits go through normal branch
    protection. See Branch protection section below.

**Smoke test** — once the secrets are in place, the next workflow run will
mint a token via `actions/create-github-app-token` and use it. To test
manually before the next release, run a workflow_dispatch on a no-op release
candidate (`v0.0.0-smoke`) and confirm the App identity opens the PR.

**Token rotation**: rotate the private key every 90 days (calendar reminder
on the maintainer team's shared calendar). Procedure: generate a new key in
the App settings, update `RELEASE_APP_PRIVATE_KEY`, then **delete the old
key** in the App settings. The App ID does not change.

**Leak playbook**: if `RELEASE_APP_PRIVATE_KEY` is suspected leaked:
1. Immediately revoke the key in the App settings page.
2. Generate a new key and update the repo secret.
3. Audit the org's installation-token usage in
   **Settings → Audit log** for the past 90 days, looking for unexpected
   `git_push`, `pull_request_create`, or `tag_create` events.
4. Review every tag created in that window; cross-check against the
   release-PR audit trail.

### Branch protection on `main`

Configure in **Settings → Branches → Add rule** (or **Edit** an
existing rule for `main`). Required settings:

| Setting | Value | Why |
|---|---|---|
| Branch name pattern | `main` | Protects the release branch. |
| Require a pull request before merging | ✓ | No direct commits. |
| Require approvals | ✓ — at least **1** approving review | Two-eyes review on every change. |
| Dismiss stale pull request approvals when new commits are pushed | ✓ | Reset reviews on rebase / amend. |
| Require review from Code Owners | ✓ | Enforces `.github/CODEOWNERS`. |
| Require status checks to pass before merging | ✓ | Block on CI. |
| Require branches to be up to date before merging | ✓ | Re-run CI on the merge target. |
| Required status check | `CI Pass` | Aggregate gate from `.github/workflows/ci.yml`. |
| Require conversation resolution before merging | ✓ | All review comments resolved. |
| Require signed commits | ✓ | Cryptographic provenance for every commit on `main`. |
| Require linear history | ✓ | Squash or rebase only — no merge commits. |
| Include administrators | ✓ | Maintainers cannot bypass. |
| Allow force pushes | ✗ (disabled) | Permanent history. |
| Allow deletions | ✗ (disabled) | `main` cannot be deleted. |
| Restrict who can push to matching branches | enabled, allowed actors empty | Closes the "PR-required, but anyone with write access can still push directly" loophole. The empty allow-list means even maintainers must go through a PR. |
| Allow specified actors to bypass required pull requests | empty | No bypass. The "Include administrators" toggle above already covers admin enforcement; this row makes it explicit that no individual / team / app is on a bypass list. |
| Lock branch | ✗ (disabled) | A locked branch refuses every write — only used during a freeze. Default off. |

For changes touching cryptographic primitives (`hmac.go`,
`tls_policy.go`, `secrets/`) GitHub does not currently support
per-path approval counts; the 1-approval floor above is the global
minimum. CODEOWNERS still routes the review to the maintainer team,
and reviewers SHOULD pull a second maintainer in for crypto changes
even though the gate does not enforce it.

After saving, push a small test PR (e.g. a typo fix) from a fork or
feature branch and verify the merge button is disabled until the
status check passes and an approving review is recorded.

### Tag protection — every release prefix

Configure in **Settings → Tags → New rule**. GitHub matches the
pattern against the FULL tag name (not the basename), so the core
module pattern `v*` does NOT cover sub-module tags like
`file/v1.0.0`. Add one rule per release prefix in the repository:

| Setting | Value | Covers |
|---|---|---|
| Tag name pattern | `v*` | Core module: `v1.0.0`, `v1.1.0-rc.1`, etc. |
| Tag name pattern | `file/v*` | `file` sub-module. |
| Tag name pattern | `syslog/v*` | `syslog` sub-module. |
| Tag name pattern | `webhook/v*` | `webhook` sub-module. |
| Tag name pattern | `loki/v*` | `loki` sub-module. |
| Tag name pattern | `outputconfig/v*` | `outputconfig` sub-module. |
| Tag name pattern | `outputs/v*` | `outputs` convenience-package sub-module. |
| Tag name pattern | `secrets/v*` | `secrets` parent sub-module. |
| Tag name pattern | `secrets/openbao/v*` | `secrets/openbao` provider sub-module. |
| Tag name pattern | `secrets/vault/v*` | `secrets/vault` provider sub-module. |
| Tag name pattern | `cmd/audit-gen/v*` | `audit-gen` CLI sub-module. |
| Tag name pattern | `cmd/audit-validate/v*` | `audit-validate` CLI sub-module. |
| Tag name pattern | `iouring/v*` | `iouring` sub-module — **not yet in `PUBLISH_MODULES`**; the rule reserves the namespace to prevent squatting before the module is first published. |

GitHub's tag-protection rule restricts tag creation to repository
maintainers. A pushed tag is the trigger for the release workflow
(GoReleaser, build-provenance attestation), so this rule is what
prevents an unauthorised actor from triggering a release pipeline.
**Without the per-sub-module entries, anyone with write access can
publish a sub-module release.**

**Allowed actors per rule**: under the unified release flow (#513), the
canonical creator of release tags is the `axonops-audit-release-bot` App.
Each rule's "Restrict who can create matching tags" allow-list MUST
include the App identity. Maintainers are intentionally **not** on
the standing allow-list for these patterns — see the rationale in
"Why the maintainer team is not on the tag-protection allow-list"
below.

Add a new rule whenever the repository gains another sub-module
that releases independently. Audit the live tag-protection set on
every maintainer onboarding (see verification snippet below).

#### Why the maintainer team is not on the tag-protection allow-list

A standing maintainer entry on the allow-list is a permanent bypass
capability: any maintainer could push a release tag at any time
without going through `release.yml`'s CI gate. Removing the standing
entry forces every release through the workflow.

**Emergency override** — when the App identity is unavailable (e.g.
private key revoked mid-incident, App suspended, GitHub-side outage)
a maintainer with admin permissions can:

1. Add their own user account to the relevant tag-protection allow-list
   in **Settings → Tags → edit rule**.
2. Push the required tag(s).
3. **Immediately remove themselves** from the allow-list.

The transient allow-list edits are recorded in
**Settings → Audit log** under `protected_tag.update`, providing a
post-incident audit trail. The "remove yourself" step is the
operator's responsibility — there is no automated revocation.

### Verification checklist (every release cycle)

```bash
# 1. CODEOWNERS file present and parseable.
test -f .github/CODEOWNERS && \
  gh api repos/:owner/:repo/codeowners/errors --jq '.errors | length' \
    | grep -qx 0 || echo "ERROR: CODEOWNERS has parse errors"

# 2. Branch protection enforces required checks.
gh api repos/:owner/:repo/branches/main/protection --jq '
  {
    require_signed: .required_signatures.enabled,
    require_linear: .required_linear_history.enabled,
    require_codeowner_review: .required_pull_request_reviews.require_code_owner_reviews,
    required_check: (.required_status_checks.contexts // []) | join(","),
    allow_force: .allow_force_pushes.enabled,
    allow_delete: .allow_deletions.enabled
  }'
# Expect: require_signed=true, require_linear=true,
# require_codeowner_review=true, required_check contains "CI Pass",
# allow_force=false, allow_delete=false.

# 3. Tag-protection rules — every release prefix.
gh api repos/:owner/:repo/tags/protection --jq '.[] | .pattern' | sort
# Expect (one per line):
#   cmd/audit-gen/v*
#   cmd/audit-validate/v*
#   file/v*
#   iouring/v*
#   loki/v*
#   outputconfig/v*
#   outputs/v*
#   secrets/openbao/v*
#   secrets/v*
#   secrets/vault/v*
#   syslog/v*
#   v*
#   webhook/v*
# A 404 / empty response means NO tag-protection rules exist —
# anyone with write access can publish a release. Configure the
# rules in Settings → Tags → New rule before promoting.
```

If any of the three checks reports an unexpected value, fix the
configuration in the UI before tagging the release.

---

## For Maintainers: Cutting a Release

### Release Workflow Overview

Two GitHub Actions workflows participate in releases. The primary workflow
runs end-to-end; the second is a manual fallback:

| Workflow | File | Trigger | Purpose |
|----------|------|---------|---------|
| **Release** | `release.yml` | Manual (workflow_dispatch) **or** push of a `v*` tag | Runs CI, opens release PR, waits for auto-merge, tags every module at the merge SHA, builds binaries via GoReleaser, verifies the proxy, runs the invariants check |
| **GoReleaser** | `goreleaser.yml` | Manual re-run only | Re-runs GoReleaser if the goreleaser job in `release.yml` failed |

The two triggers serve different purposes:

- **`workflow_dispatch`** is the **primary path**. The maintainer enters the
  version (e.g. `v0.1.12`) and starts the workflow. The workflow opens the
  release PR; the maintainer approves it (branch-protection requires a
  human review); auto-merge fires; the workflow tags every module at the
  merge SHA and runs GoReleaser.
- **`push: tags: v*`** is the **recovery path**. If the primary workflow
  failed after some tags had already been pushed (rare but possible —
  GitHub network blip during the tag loop), or if a maintainer pushed the
  core `v*` tag manually after an out-of-band fix, this trigger lets the
  workflow finish: it derives the merge SHA from the pushed tag, tags any
  remaining modules **idempotently** (skipping tags that already exist at
  the same SHA, aborting on SHA mismatch), and runs GoReleaser. It does
  NOT open a release PR. See "Release recovery playbook" below.

The `release.yml` workflow uses the `axonops-audit-release-bot` GitHub App for
every write operation; it does not consume a personal access token.

### `api-check` transition (advisory → blocking)

`make api-check` runs `gorelease` for every published module against the
module's most recent SemVer-sorted tag. Until the v1.0 release, the
release workflow runs `api-check` with `inputs.api_check_blocking=false`
(default), so a flagged incompatibility fails the step but does not stop
the release. This reflects the v0.x stability contract: breaking changes
are allowed.

After cutting v1.0, maintainers MUST flip `inputs.api_check_blocking` to
`true` for every subsequent release. From that point on, an incompatible
public-API change is a blocking failure — the only ways to release a
breaking change are to bump the major version (`/v2`) or to revert the
breakage. Document the date of the flip in the v1.0 changelog entry so
future maintainers know when the transition happened.

### Pre-Release Checklist

Complete every item before creating any tags. A partial or incorrect release
cannot be undone.

- [ ] CI is green on `main` — check the
      [CI workflow](https://github.com/axonops/audit/actions/workflows/ci.yml)
- [ ] `make check` passes locally with no errors or diffs
- [ ] No `replace` directives in any `go.mod` — `make check-replace` confirms this
- [ ] `make api-check` runs cleanly. Pre-v1.0 this is advisory — review any
      flagged incompatibilities and confirm they are intentional before
      releasing.
- [ ] All inter-module dependencies will reference the correct version after
      release. The release workflow updates them automatically from the
      release PR — no manual action needed pre-release. Post-release, the
      `invariants` job runs `make check-release-invariants VERSION=...` to
      confirm every published `go.mod` is at the released version.

- [ ] `CHANGELOG.md` updated — the `## [Unreleased]` section converted to
      `## [0.1.1] - 2026-01-01` (or the actual date)
- [ ] The version string is consistent across `CHANGELOG.md` and all tags you
      are about to create
- [ ] `go.sum` files are committed and up to date — `make tidy-check` passes
- [ ] `bench-baseline.txt` is fresh — regenerate it whenever a benchmark is
      renamed, a hot-path change lands, or before any milestone release.
      The release workflow runs `make bench-compare` as an advisory step
      (see "Benchmark regression report" in the GitHub Actions summary) —
      stale names silently break the column pairing and the report
      becomes uninformative. Regenerate with:

      ```bash
      # On consistent hardware — GitHub-hosted runners are too noisy.
      make bench-save
      git add bench-baseline.txt BENCHMARKS.md
      git commit -m "chore: refresh bench-baseline.txt ahead of vX.Y.Z"
      ```

      `make bench-baseline-check` (part of `make check`) rejects a PR
      that introduces a benchmark name to `bench-baseline.txt` that no
      longer exists in the source tree — catching renames at lint time.

- [ ] **Soak benchmark complete** (`make soak`). The 12-hour
      mixed-output soak (#573) is run on stable hardware before
      every release tag. After completion, paste start / end / peak
      values from `$SOAK_OUTPUT_DIR/soak-summary-*.json` into
      `BENCHMARKS.md` "Release Soak-Test Summary" under a new dated
      entry for the pending release. Do not tag if heap or
      goroutine count grows unboundedly, if `goleak` reports
      failures, or if `total_drops` is non-zero.

      ```bash
      # On the release-prep machine (no other load).
      make soak-quick                     # 1-min smoke first
      make soak                           # 12-hour run
      # paste summary into BENCHMARKS.md, commit, push
      ```

      See [`tests/soak/README.md`](../tests/soak/README.md) for
      result interpretation.

### Creating a Release

> **Warning:** Once tags are pushed, they are permanent. Complete the
> pre-release checklist before triggering the workflow.

Releases are created via the
[Release workflow](https://github.com/axonops/audit/actions/workflows/release.yml).
**Do not create tags manually** — the workflow runs the full CI pipeline,
opens the release PR, and only tags after the PR has merged through normal
branch protection.

1. Go to **Actions → Release → Run workflow**.
2. Enter the version string (e.g. `v0.1.12`).
3. Leave `api_check_blocking` at its default (`false`) until v1.0 is cut.
4. Click **Run workflow**.

The workflow then:

1. Validates the version format and confirms HEAD is on `main`.
2. Runs the full CI pipeline (same as a PR check — all tests, all modules)
   plus `fuzz-long`, advisory benchmark regression, and `api-check`.
3. Opens a release PR (branch `release/<version>`) containing one commit
   that pins every inter-module `go.mod` to the new version. Auto-merge
   is enabled.
4. **Waits for the PR to merge**. The PR must pass CI and any required
   approving reviews (typically one human approval per branch protection).
   The workflow polls the PR every ~30 seconds for up to 45 minutes.
5. After merge, checks out the merge commit and creates twelve annotated
   tags pointing at that one SHA: `v<version>`, `file/v<version>`,
   `syslog/v<version>`, etc.
6. Runs GoReleaser to build binaries, attest build provenance, and publish
   the GitHub Release.
7. Triggers proxy.golang.org indexing and runs the smoke test.
8. Runs `make check-release-invariants VERSION=v<version>` against the
   merge commit as the final post-release sanity gate.

**Approve the release PR promptly.** The maintainer who triggered the
workflow is expected to approve the auto-opened PR — auto-merge waits for
CI green AND any required approvals before merging. If 45 minutes pass
without merge the workflow fails; the PR may still auto-merge later, in
which case use the recovery path (push the `v*` tag manually to re-trigger
the goreleaser+verify+invariants jobs).

If you need to test the workflow without burning a real version number,
use a pre-release tag like `v0.1.12-rc.1`.

### Example: releasing v0.1.12

```bash
# 1. Pre-release checklist passes (CI green, CHANGELOG updated, etc.).

# 2. Trigger the workflow:
gh workflow run release.yml -f version=v0.1.12 -f api_check_blocking=false

# 3. The workflow opens a PR titled "release: v0.1.12" — review it:
gh pr list --head release/v0.1.12

# 4. Approve and let auto-merge fire:
gh pr review --approve <PR_NUMBER>

# 5. Watch the run:
gh run watch

# 6. After completion, verify:
gh release view v0.1.12
make check-release-invariants VERSION=v0.1.12
```

### After the Release

The `release.yml` workflow handles every step end-to-end. Monitor the run
for the final status (Actions → Release).

The post-release `invariants` job runs `make check-release-invariants
VERSION=$VERSION`, which scans every published `go.mod` and confirms that
every cross-reference to another published module is at the released
version. A green `invariants` job is the canonical "the release is sound"
signal.

Optionally verify locally:

```bash
make publish-verify VERSION=v0.1.12
make publish-smoke  VERSION=v0.1.12
```

### Release recovery playbook

The release workflow is designed so that every failure mode has a
copy-paste recovery. Tags that have already been pushed CANNOT be
deleted — but the workflow's idempotent `tag-all` step ensures that
re-runs do not corrupt existing tags.

#### Auto-merge blocked because no human has approved the PR yet

Approve the PR. Auto-merge fires on the next polling cycle (~30s). The
release workflow will pick up the merge and continue.

```bash
gh pr review --approve <PR_NUMBER>
```

#### `wait-for-pr-merge` timed out (45 min) but the PR is still open

The PR will eventually auto-merge once CI clears and approval is in
place. After it merges:

```bash
# 1. Find the merge commit:
MERGE_SHA=$(gh pr view <PR_NUMBER> --json mergeCommit -q '.mergeCommit.oid')

# 2. Push the core v* tag manually at the merge SHA. This triggers the
#    recovery path (push: tags: v*), which runs tag-all idempotently.
git fetch origin
git tag -a "v0.1.12" -m "Release v0.1.12" "$MERGE_SHA"
git push origin "v0.1.12"
```

The workflow run triggered by the tag-push will tag the remaining
eleven modules at the same SHA and continue with GoReleaser + verify +
invariants. Tags that already exist at the correct SHA are no-ops; tags
that exist at a DIFFERENT SHA cause the workflow to abort loudly (a
genuinely suspicious state that needs human investigation).

#### `tag-all` aborted after pushing some but not all twelve tags

Inspect what was pushed:

```bash
git fetch origin --tags
git ls-remote origin "*v0.1.12" | sort
# Compare against expected — every entry must reference the same SHA.
```

If the SHAs match, push the missing tags via the same recovery path:

```bash
# Use the merge commit SHA from the partial run:
git push origin v0.1.12  # or whichever tag is missing
```

The release.yml `push: tags: v*` trigger will fire and the workflow's
`tag-all` step will fill in the remaining tags at the same SHA. Do
**not** delete already-pushed tags; deletion does not unpublish the
version from `proxy.golang.org`, but does cause `go mod verify` failures
for any consumer who already fetched the deleted tag.

If SHAs do **not** match, stop and escalate — a tag at a wrong SHA is a
permanent contamination. The fix is to release a new patch version and
retract the bad one. See "Retracting a Bad Release" below.

#### GoReleaser failed but tags are pushed

Re-run GoReleaser manually via [Actions →
GoReleaser](https://github.com/axonops/audit/actions/workflows/goreleaser.yml)
on the `v*` tag ref. The standalone `goreleaser.yml` workflow exists for
exactly this case; it runs only the binary-build + attestation step
without touching tags.

#### App private key compromised mid-release

Stop the in-flight workflow run (Actions → run → Cancel workflow). Follow
the leak playbook in the "Release-bot GitHub App" section above. Do not
restart the release until the App key has been rotated. Already-pushed
tags are unaffected; resume from the recovery path with a freshly minted
token.

#### Tags pushed but the GitHub Release page has no binaries

The library is consumable via the Go module proxy as soon as
`tag-all` finishes — `go get github.com/axonops/audit@v0.1.13`
works without the GitHub Release page artifacts. But the
`goreleaser` job that produces `audit-gen` / `audit-validate`
binaries, `checksums.txt`, the Sigstore signature pair, and the
container image runs separately and can fail independently. The
v0.1.12 release hit this exact mode: a `goreleaser-action`
cosign-verification bug in the pinned v2.15.0 caused the
goreleaser job to fail every retry, leaving the tag published but
the GitHub Release page empty.

If the goreleaser job is still retryable (no code bug — just a
transient infra failure), see
[GoReleaser failed but tags are pushed](#goreleaser-failed-but-tags-are-pushed)
first; that's the canonical re-run path. If retries don't help
(e.g. the underlying tool version is broken on the tag's SHA),
pick one of the three options below:

1. **Cut the next patch version forward** (preferred). This is
   what v0.1.13 did. The failed-binary tag stays library-only;
   the next tag's release-page artifacts are the canonical
   distribution for binary consumers. This is the option v0.1.12
   was accepted under: v0.1.12 is library-only on purpose, and
   v0.1.13+ have full release-page artifacts. No retroactive
   binary backfill was performed.

2. **Manually backfill via a local goreleaser run**:

   ```bash
   # Check out the EXACT commit the tag points at
   VERSION=v0.1.12
   SHA=$(git rev-parse "$VERSION")
   git checkout "$SHA"

   # Build artifacts locally (no publish, no signing). GoReleaser
   # v2 uses --skip=<comma-list>; v1's --skip-publish / --skip-sign
   # flags are removed.
   goreleaser release --clean --skip=publish,sign

   # Upload to the existing GitHub Release page
   gh release upload "$VERSION" dist/audit-gen_*.tar.gz \
                                dist/audit-validate_*.tar.gz \
                                dist/checksums.txt
   ```

   This produces binaries identical to what the workflow would
   have, but without the Sigstore signature, the build-attestation
   provenance, or the container image. Acceptable for emergency
   backfill; not recommended for fresh releases.

3. **Accept as library-only**: do nothing on the release page;
   document in the project's release notes that binaries are not
   available for this version and consumers should use the next
   patch.

See the [`release-smoke`][release-smoke] workflow for pre-flight
checks (including the GoReleaser version-pin floor) that prevent
the v0.1.12 failure mode from recurring.

[release-smoke]: ../.github/workflows/release-smoke.yml

### Lessons learned (v0.1.12 incident)

Cutting v0.1.12 — the first real use of the unified release flow
(#513) — required eight fixes across seven PRs because the flow
had never been exercised end-to-end against a real tag. Grep this
section by the error string you see in CI to find the precedent.

See also [Example: releasing v0.1.12](#example-releasing-v0112)
for the trigger commands.

- **release.yml startup_failure (nested dependency-review)** →
  `ci.yml`'s `dependency-review` job declares `pull-requests:
  write`; the caller validated permissions before evaluating
  `if:` → grant `pull-requests: write` on the `ci` call (#832).
- **Go stdlib vulns GO-2026-4971 + GO-2026-4918** → go1.26.2
  vulnerable → bump GOTOOLCHAIN to go1.26.3 across every go.mod,
  the Makefile, and release.yml (#832, shipped together).
- **FuzzOutputConfigLoad: NUL byte in error string** → "unknown
  output type" error embedded user input unquoted → sanitise via
  `isValidImportPathSegment` + generic fallback (#833).
- **Bot rename release-bot → axonops-audit-release-bot** → org
  has multiple projects → rename App + all hardcoded references
  in release.yml, tag-all.sh, CONTRIBUTING, docs (#834).
- **`gh repo view --json autoMergeAllowed` invalid field** → JSON
  field name wrong on the `repo` resource → use
  `gh api /repos/$REPO --jq '.allow_auto_merge'` (#835).
- **update-deps.sh ran go mod tidy** → tag doesn't exist on
  origin until `tag-all` runs → skip tidy and strip stale
  go.sum entries; this is the `SKIP_TIDY_CHECK` invariant (#836).
- **CI tidy-check failed on the release PR** → ci.yml didn't
  honour the skip from #836 → add `SKIP_TIDY_CHECK` env on
  `release/*` branches in ci.yml's hygiene step (#838).
- **GoReleaser v2.15.0 cosign-verification bug** → ASN.1-encoded
  signature error on every retry → bump goreleaser-action pin to
  v2.15.4 (#840). v0.1.12's release-page binaries are
  permanently missing because the tag's workflow SHA still
  points at v2.15.0 (tags are immutable); v0.1.13+ ship from
  the fixed pin on main — see [Tags pushed but the GitHub
  Release page has no binaries](#tags-pushed-but-the-github-release-page-has-no-binaries).

### First Release: v0.1.1

The first release for this repository is `v0.1.1`. Version `v0.1.0` was
skipped because `loki/v0.1.0` was already sealed in the Go checksum database
before the loki module was ready to publish. Using `v0.1.1` as the first
coordinated release across all modules avoids a version mismatch where `loki`
appears to have a `v0.1.0` that predates the rest of the library.

No `retract` directive is required for `loki/v0.1.0` in the loki module's
`go.mod` because that version was never published with importable code — it
was sealed at a commit that did not contain the `loki` directory's current
code. If consumers report resolution issues with `loki/v0.1.0`, add:

```go
// loki/go.mod
retract v0.1.0 // sealed in sum DB before module was complete; use v0.1.1
```

### Retracting a Bad Release

If a published release contains a serious bug or security vulnerability,
publish a fix as a new version and add a `retract` directive. The retraction
MUST be in the module's `go.mod`, and the retraction itself MUST be released
as a new version for the Go toolchain to surface the warning to consumers.

Example — retracting `v0.1.1` from the core module after publishing `v0.1.2`:

```go
// go.mod
module github.com/axonops/audit

go 1.26.2

retract v0.1.1 // contains data loss bug in drain loop; use v0.1.2
```

The retraction comment is displayed by `go get` and `go list` when a consumer
has the retracted version. It MUST explain why the version was retracted and
what version to use instead.

Each affected module MUST have its own `retract` directive — retraction is
per-module, not repository-wide.

---

## For Maintainers: Verification Tools

### The Release Workflow

The [Release workflow](../.github/workflows/release.yml) handles the
entire release pipeline end-to-end. It is triggered via `workflow_dispatch`
(primary path) or `push: tags: v*` (recovery path). See "Release Workflow
Overview" above for the trigger semantics.

**What it does, in order (primary path):**

1. Validates the version format and confirms HEAD is on `main`.
2. Runs the full CI pipeline (every test, lint, security check) plus
   `fuzz-long`, advisory benchmark regression, and `make api-check`.
3. Opens a release PR pinning every inter-module `go.mod` to the new
   version in one commit; enables auto-merge.
4. Waits for the PR to merge (CI green + required approvals).
5. Creates twelve annotated tags at the merge commit SHA — every
   published module tagged at the same SHA.
6. Runs GoReleaser to build binaries and attest build provenance.
7. Triggers `proxy.golang.org` indexing for all modules.
8. Runs the smoke test (`go get` + compile in a fresh module).
9. Runs `make check-release-invariants VERSION=...` against the merge
   commit.

If any step fails, the workflow stops. Tags that were already pushed
cannot be undone — see [Release recovery playbook](#release-recovery-playbook)
and [Retracting a Bad Release](#retracting-a-bad-release).

### The release-smoke workflow

The [release-smoke workflow](../.github/workflows/release-smoke.yml)
is a validate-only pre-flight check for the release infrastructure.
It is triggered manually via `workflow_dispatch` and has zero side
effects — no tags, no branches, no commits, no PRs. Run it before
cutting a real release (or on a schedule, if drift becomes a
recurring problem) to surface any infrastructure regression.

**What it checks (each as a pass/fail row in the run summary):**

- `RELEASE_APP_ID` and `RELEASE_APP_PRIVATE_KEY` secrets are
  configured and the App token mints successfully.
- The App is installed on this specific repository (catches a
  misconfigured secret pointing at a different installation).
- The minted token has rate-limit budget remaining
  (`/rate_limit` core resource > 100).
- The repo has `allow_auto_merge: true` (catches the regression
  PR #835 fixed).
- The `main` branch has `required_signatures: enabled` (the whole
  reason for the GraphQL migration in #841 — releases must not
  silently disable this).
- The GoReleaser version pin is at or above v2.15.4 (the floor
  set by PR #840 to avoid the cosign-verification bug in v2.15.0
  that caused v0.1.12's missing binaries).
- Every script under `scripts/release/` parses cleanly via
  `bash -n`.
- `make print-publish-modules` returns a non-empty list.
- The tag-protection rule on `refs/tags/v*` is queryable (or
  absent on plain repos).

**When to run:**

```bash
gh workflow run release-smoke.yml
gh run watch
```

A green run means all the prerequisites the unified flow assumes
are in place. A red run names the failed check in the summary —
fix it before triggering a real release.

### Makefile Targets

These targets run locally for manual verification:

```bash
# Trigger proxy.golang.org indexing for a version
make publish-trigger VERSION=v0.1.1

# Verify proxy.golang.org and pkg.go.dev for a version
make publish-verify VERSION=v0.1.1

# Smoke test: go get + compile all modules for a version
make publish-smoke VERSION=v0.1.1
```

`publish-trigger` calls `go list -m` against `GOPROXY=https://proxy.golang.org`
for each module. This is the same operation that a consumer's first `go get`
performs — it forces the proxy to fetch and cache the module from GitHub.

`publish-verify` checks the `.info` endpoint on `proxy.golang.org` and the
HTTP status of `pkg.go.dev` for each module. It does not fail on a non-200
from `pkg.go.dev` — use it as a quick sanity check, not a gate.

`publish-smoke` creates a temporary module in `$(mktemp -d)`, installs the
published runtime modules at the specified version, compiles a program that
imports the runtime modules, and installs `audit-gen`. This is the closest
local equivalent to "does this release actually work for a consumer."
`cmd/audit-validate` is excluded from the smoke build because it has no
importable API — it is a standalone CLI with its own unit suite. The
release workflow's `verify` job covers `cmd/audit-validate` separately
via `go install`.

---

## For Maintainers: CI Health

CI is only useful if it reports real failures as failures. Defence in depth:
the test layer must fail loudly, AND every workflow step must propagate that
failure out of the shell pipeline into the job result.

### Job dependency graph

Post-#759 the CI workflow is structured for fail-fast and parallelism:

```
                   ┌─────────┐
                   │ changes │
                   └────┬────┘
                        │
       ┌────────────────┼────────────────┐
       ▼                ▼                ▼
  ┌──────────┐  ┌─────────────┐  ┌──────────────┐
  │ hygiene  │  │ validate-   │  │ dep-review   │
  │(8 checks)│  │  release    │  │  (PR only)   │
  └────┬─────┘  └─────────────┘  └──────────────┘
       │
       ├──────┬──────┬───────────┬──────────┬─────────┬─────────┬───────────────┐
       ▼      ▼      ▼           ▼          ▼         ▼         ▼               ▼
   ┌─────┐ ┌────┐ ┌─────────┐ ┌────────┐ ┌────────┐ ┌──────┐ ┌─────────┐ ┌──────────────┐
   │lint │ │test│ │integ-   │ │security│ │security│ │cross-│ │examples-│ │   (etc.)     │
   │     │ │x11 │ │ration   │ │  x13   │ │ verify │ │build │ │ build   │ └──────────────┘
   └─────┘ └─┬──┘ └─────────┘ └────────┘ └────────┘ └──────┘ └─────────┘
             │
             ├──────────────┐
             ▼              ▼
        ┌──────┐  ┌──────────────────┐
        │bdd x8│  │ test-cross-      │
        └──┬───┘  │ platform x4      │
           │      │ (mac + win)      │
           ▼      └──────────────────┘
     ┌────────────┐
     │ bdd-verify │
     └────────────┘

(All roll up into ci-pass, the single aggregate gate.)
```

Hygiene is the single fan-out point: all subsequent jobs gate on it.
Cross-platform tests and BDD gate on test (Linux unit suite must pass
before macOS/Windows shards or BDD shards consume runner-minutes).

The hygiene job runs `make check-static`, which aggregates eight static
guards (`fmt-check`, `tidy-check`, `check-todos`, `check-replace`,
`check-insecure-skip-verify`, `check-example-links`, `check-bdd-strict`,
`bench-baseline-check`) in a `||`-guarded loop so every failure
surfaces on a single push rather than aborting on the first. Developers
running `make check-static` locally see the same one-shot summary.

The CI setup ceremony (Go install, workspace init, optional tool
install) lives in `.github/actions/setup-audit/` as a composite
action — every job consumes it via `uses: ./.github/actions/setup-audit`.
The cache key hashes `scripts/tool-versions.txt` so version bumps are
the only thing that invalidate the cache.

### Security checks in CI

Three CI-time supply-chain controls run in this repository. Each plays
a distinct role; together they cover known-vuln detection, import
reachability, license policy, and update propagation. Removing any one
opens a coverage gap that the others do not fill.

| Tool | Where it runs | Trigger | What it blocks | Threshold |
|------|---------------|---------|----------------|-----------|
| `actions/dependency-review-action` (pinned to v4.9.0) | `dependency-review:` job in [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) | every pull request to `main` | a PR whose `go.mod`/`go.sum` diff introduces an advisory in the [GitHub Advisory Database](https://github.com/advisories) at or above the configured severity | `fail-on-severity: high` |
| `govulncheck` (run via `make security` / `make security-one MOD=...`) | `security:` matrix in [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) (one job per published module — root, `file`, `iouring`, `syslog`, `webhook`, `loki`, `outputconfig`, `outputs`, `cmd/audit-gen`, `cmd/audit-validate`, `secrets`, `secrets/env`, `secrets/file`, `secrets/openbao`, `secrets/vault`); the same target also runs in [`.github/workflows/security-scan.yml`](../.github/workflows/security-scan.yml) | every push and pull request that touches code; weekly cron at `0 6 * * 1`; manual dispatch | a build whose imported symbols reach a CVE in the [Go vulnerability database](https://pkg.go.dev/vuln/) | any vulnerability flagged by `govulncheck` (no severity gate) |
| Dependabot | [`.github/dependabot.yml`](../.github/dependabot.yml) | continuous (GitHub-managed) | nothing directly — opens version-bump and security-fix PRs against every module directory listed in the config | n/a (open-PR mechanism, not a gate) |

The split is intentional. `dependency-review` is the only PR-time
check against GHAS — a broader and often more current advisory feed
than the Go vulnerability database, and the only place we can enforce
`deny-licenses` or `deny-packages` if a license-policy or supply-chain
blocklist is added later. `govulncheck` is the only tool that performs
import-reachability analysis, so it surfaces "your code actually calls
into a vulnerable function" rather than "a vulnerable version is in
the graph". Dependabot is the only mechanism that opens update PRs.

If a PR is failing `Test - Dependency Review`, read the check
annotation for the GHSA ID and the affected module, then either bump
the dependency to a fixed version (Dependabot will usually open such a
PR independently within hours) or, if the advisory is a false positive
for our usage, allow it via `allow-ghsas:` on the action's `with:`
block — and document the rationale in the PR description.

A weekly run of `security-scan.yml` opens a tracking issue
automatically on every run where `make security` exits non-zero —
this includes CVEs that are already known but not yet resolved, so
expect duplicate issues until the underlying vulnerability is
fixed. Resolve them promptly: each one represents a CVE in code we
already ship, not a hypothetical "new dependency" risk.

### The pipefail bug class

GitHub Actions `run:` blocks execute bash without `set -o pipefail` by default.
When a step uses a pipeline like `make test | tee output.txt`, the pipeline's
exit status is `tee`'s (always 0), not `make`'s. A failing test suite can
therefore exit the step with status 0 and the job is marked `success` even
though the tests failed.

Issue #622 fixed this for the BDD step in `ci.yml`; the rule applies to every
workflow step that uses a pipeline. Every `run:` block that contains `|` must
either:

- Set `set -eo pipefail` at the top of the block, or
- Not use a pipeline.

### Proving the mechanism

The bug class is reproducible in five seconds without touching CI:

```bash
# Without pipefail: tee's zero exit masks false's non-zero exit.
$ bash -c 'false | tee /dev/null'; echo "outer exit: $?"
outer exit: 0

# With pipefail: false's exit propagates out of the subshell.
$ bash -c 'set -eo pipefail; false | tee /dev/null'; echo "outer exit: $?"
outer exit: 1
```

### Verifying CI is honest end-to-end

After any change to workflow steps that run tests, verify the gate is real:

1. Create a disposable branch, capturing the name once:

   ```bash
   BRANCH="verify/ci-pipefail-$(date +%Y%m%d-%H%M%S)"
   git checkout -b "$BRANCH"
   ```

2. Introduce a deliberate test failure — smallest recipe is to add an
   undefined step reference in a BDD feature file:

   ```gherkin
   # Append to any scenario in tests/bdd/features/core_audit.feature
   And an intentionally undefined canary step
   ```

3. Commit, push, and open a draft PR.
4. Confirm the relevant CI job (e.g. `BDD (core)`) reports `failure`. The
   check row in the PR UI shows a red `X`, not a green check.
5. Close the PR without merging and delete the branch:

   ```bash
   git push origin --delete "$BRANCH"
   git checkout main
   git branch -D "$BRANCH"
   ```

This verifies not just the pipefail mechanism but the entire chain from test
exit code through step status through job status through PR check status. Run
it when modifying any test-execution step in `.github/workflows/`.

### OpenSSF Scorecard

The OSSF Scorecard workflow (`.github/workflows/scorecard.yml`) runs weekly on
Monday at 08:00 UTC, on every push to `main`, and whenever a branch-protection
rule is created or modified. It scores the repository against the OpenSSF
supply-chain checks (Branch-Protection, Code-Review, SAST, Pinned-Dependencies,
Token-Permissions, Vulnerabilities, etc.).

Results are uploaded as SARIF to the GitHub **Security** tab and published to
the OpenSSF public dashboard at
<https://securityscorecards.dev/viewer/?uri=github.com/axonops/audit>. The
README badge links to that dashboard.

**If the score drops between runs:**

1. Open the latest workflow run, download the `scorecard-sarif` artifact, and
   read the per-check findings.
2. Cross-reference with the GitHub **Security** tab — each finding includes
   the file path and remediation guidance.
3. File a tracking issue (labels `security`, `ci/cd`) for any regression that
   is not a transient false positive.
4. Common drift causes: a new workflow added without
   `permissions: contents: read` at the top level; an action referenced by tag
   rather than full SHA; a dependency pin bumped to a vulnerable version
   (`govulncheck` will flag this independently in `security-scan.yml`).
5. The **Pinned-Dependencies** check is the one most often dragged down by
   GitHub-Actions updates that land as tag-pinned PRs from Dependabot — they
   should be edited to a full SHA before merge, matching the convention used
   throughout `.github/workflows/`.

A score drop on **Pinned-Dependencies** or **Vulnerabilities** MUST be
resolved before the next release — these checks measure supply-chain
integrity and CVE exposure directly. Drops on other checks
(Branch-Protection, Code-Review, SAST, Token-Permissions) SHOULD be
resolved within one release cycle. File a tracking issue (labels
`security`, `ci/cd`) for every unresolved regression before tagging.

---

## For Contributors

Contributors do not cut releases. This section explains how Go module
publishing works so that contributor actions (tags, `go.mod` changes) do not
accidentally interfere with the release process.

### How a Consumer Gets Your Code

When a consumer runs `go get github.com/axonops/audit@v0.1.1`:

1. The Go toolchain asks `proxy.golang.org` for the module at that version.
2. The proxy fetches the source from GitHub at the commit pointed to by the
   `v0.1.1` tag, if it has not already cached it.
3. The proxy records the module hash in `sum.golang.org`.
4. The source is extracted into the consumer's module cache.
5. The consumer's `go.sum` is updated with the verified hash.

The proxy caches the module permanently. If the tag is later deleted or moved,
consumers who already fetched it are unaffected — they get the same bytes
from the proxy cache. New consumers would get an error (tag not found on
GitHub), but the proxy cache would still serve the old bytes for existing
`go.sum` entries.

### What Contributors MUST NOT Do

- **Do not create release tags.** Every published module's `v*` pattern
  is tag-protected — see "Tag protection" above for the full list.
  Release tags are created exclusively by the `axonops-audit-release-bot`
  GitHub App via the `release.yml` workflow.
- **Do not add `replace` directives to `go.mod` on any branch intended for
  merge.** `replace` directives in published modules break consumer builds.
  `make check-replace` enforces this in CI.
- **Do not modify `go.mod` to point inter-module dependencies at local paths.**
  Use `make workspace` to create a `go.work` file for local development — it is
  gitignored and does not affect the published modules.

### Inter-Module Dependencies

Each sub-module depends on `github.com/axonops/audit` (the core module).
During development, `go.work` resolves these to your local checkout. In
published modules, the `go.mod` MUST reference a released version of the
core module — there is no `replace` directive in the committed `go.mod`.

Before a release, maintainers update each sub-module's `go.mod` to reference
the correct core version. Contributors do not need to manage this — just
ensure `make check` passes on your branch.

---

## For Consumers

### Installing Modules

Requires **Go 1.26.2+**.

Install only the modules you need. The core module provides the auditor,
taxonomy validation, formatters, stdout output, HTTP middleware, and the
`audittest` testing package. Output modules are separate to keep the core
dependency footprint minimal.

```bash
# Core (always required)
go get github.com/axonops/audit@v0.1.1

# Output modules — install only what you use
go get github.com/axonops/audit/file@v0.1.1         # file output with rotation
go get github.com/axonops/audit/syslog@v0.1.1       # RFC 5424 syslog (TCP/UDP/TLS/mTLS)
go get github.com/axonops/audit/webhook@v0.1.1      # batched HTTP webhook
go get github.com/axonops/audit/loki@v0.1.1         # Grafana Loki
go get github.com/axonops/audit/outputconfig@v0.1.1 # YAML-based output configuration

# Code generator (dev/build tooling, not a runtime dependency)
go get github.com/axonops/audit/cmd/audit-gen@v0.1.1
```

Each module is versioned independently. You MUST use the same version across
all modules you install — mixing versions (e.g. core at `v0.1.1` and syslog
at `v0.2.0`) is unsupported and may cause compile errors or unexpected
behaviour.

### Version Pinning

This library is pre-release (v0.x). The API MAY change between minor
versions. Pin to an exact version in your `go.mod`:

```bash
go get github.com/axonops/audit@v0.1.1
```

Do not use `@latest` in production `go.mod` files — a new minor release may
introduce breaking changes.

### Verifying Your Install

After installation, verify the checksums against the transparency log:

```bash
go mod verify
```

This confirms that the module source in your local cache has not been tampered
with. It checks against the hashes recorded in your `go.sum`, which were
verified against `sum.golang.org` when the module was first downloaded.

### Verifying Release Artifacts

Every release artifact has a GitHub
[build attestation](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations)
that cryptographically proves it was built by the audit CI pipeline.
Verify any downloaded artifact with:

```bash
gh attestation verify audit-gen_linux_amd64.tar.gz --repo axonops/audit
```

This confirms the artifact was built by GitHub Actions from the axonops/audit
repository at the tagged commit. No keys or additional tools are needed — the
`gh` CLI handles everything via GitHub's Sigstore-based transparency log.

### Software Bill of Materials (SBOM)

This project does **not** publish SBOMs as release artifacts. Rationale (#514):

- **For library consumers**: the canonical dependency manifest is `go.mod`,
  delivered alongside the library via the Go module proxy
  (`proxy.golang.org`). `go mod graph`, `go mod verify`, and the checksum
  database (`sum.golang.org`) provide stronger guarantees than a published
  SBOM would for a Go library.
- **For binary consumers** (operators downloading `audit-gen` or
  `audit-validate` from the GitHub Releases page): build provenance is
  attested per-artifact via GitHub build attestations (above). For an SBOM
  of the binary, scan it locally with [syft](https://github.com/anchore/syft):

  ```bash
  gh release download v0.1.1 --pattern 'audit-gen_*_linux_amd64.tar.gz' --repo axonops/audit
  tar -xzf audit-gen_*_linux_amd64.tar.gz
  syft scan ./audit-gen --output cyclonedx-json > audit-gen.cdx.json
  syft scan ./audit-gen --output spdx-json     > audit-gen.spdx.json
  ```

  syft will produce the same SBOM the project would have published, derived
  directly from the binary you're going to run.

For development convenience, `make sbom` produces a source-level SBOM in
both CycloneDX and SPDX formats inside `sbom/` — useful for inspecting
the project's own dependency graph but not a release artifact.

## Language-Neutral Schema Artifacts (#548)

Every tagged release publishes two extra release files describing the
audit event wire shape for non-Go consumers (SIEM rule authors,
Python/Java services, compliance teams):

- `audit-event.framework.schema.json` — JSON Schema (Draft 2020-12)
  for a single audit event JSON document. Framework-only — covers
  the always-present framework fields and the reserved standard
  fields that ship with the library, no taxonomy events.
- `audit-event.framework.cef.template` — CEF mapping documentation
  for the Common Event Format the library's `audit.CEFFormatter`
  emits. SIEM rule authors read it to align field-extraction rules.

Both are committed under `deploy/schemas/` and ride along with every
GitHub release. Download with:

```bash
gh release download v0.1.x \
  --pattern 'audit-event.framework.schema.json' \
  --pattern 'audit-event.framework.cef.template'
```

Consumers who want a schema covering their own taxonomy's custom
fields run `audit-gen -format json-schema -input my_taxonomy.yaml -output my-schema.json` themselves — see
[`docs/schema-artifacts.md`](schema-artifacts.md) for usage examples
(Python, Java, TypeScript validators; SIEM rule patterns).

The framework-only artifacts are regenerated on every change to the
framework field set, the reserved standard field list, or the CEF
mapping. The `make regen-schema-artifacts-check` CI guard rejects
stale artifacts on every PR.
