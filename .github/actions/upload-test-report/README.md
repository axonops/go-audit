# upload-test-report

Composite GitHub Action that generates HTML + GitHub-flavoured Markdown
test reports from cucumber JSON (godog) or JUnit XML (gotestsum),
uploads both as run artifacts, and inlines an only-failures Markdown
summary into the workflow's step summary panel.

Centralises the wiring introduced inline in the bdd job by #876
(per issue #439) so the same pattern applies to every test type —
unit, integration, cross-platform — without copy-paste across 20+
jobs. Issue #877.

## Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `format` | yes | — | `cucumber-json` (godog) or `junit-xml` (gotestsum) |
| `suite` | yes | — | Suite/module name shown in the report header and appended to artifact names |
| `input-path` | yes | — | Path to the cucumber JSON or JUnit XML input file |
| `artifact-prefix` | yes | — | Prefix; suite is appended (and `-md` for the Markdown artifact) |
| `retention-days` | no | `14` | Artifact retention |

## Outputs

| Output | Description |
|---|---|
| `html-artifact-name` | Name of the uploaded HTML artifact |
| `md-artifact-name` | Name of the uploaded Markdown artifact |

## Example — BDD job (cucumber JSON)

```yaml
- name: Generate + upload BDD report
  if: always()
  uses: ./.github/actions/upload-test-report
  with:
    format: cucumber-json
    suite: ${{ matrix.suite }}
    input-path: /tmp/bdd-report-${{ matrix.suite }}.json
    artifact-prefix: bdd-report
```

Produces `bdd-report-<suite>` (HTML) and `bdd-report-<suite>-md`
(Markdown).

## Example — Unit job (JUnit XML)

```yaml
- name: Generate + upload Unit test report
  if: always()
  uses: ./.github/actions/upload-test-report
  with:
    format: junit-xml
    suite: ${{ matrix.flag }}
    input-path: /tmp/junit-${{ matrix.flag }}.xml
    artifact-prefix: test-report-unit
```

Produces `test-report-unit-<flag>` and `test-report-unit-<flag>-md`.

## Behaviour notes

- **`if: always()` on every step** — reports surface on test failure
  (which is when they matter most).
- **Skip on empty/missing input** — when the test runner failed before
  producing output (infra container didn't start, panic in `TestMain`,
  etc.) the input file is missing or empty; in that case the action
  skips the report rather than failing the upload. The original test
  failure is the signal; double-failing the upload would obscure it.
- **Step summary** uses the report tool's `-only-failures` mode so the
  output fits inside GitHub's 1 MiB step-summary cap. The tool itself
  emits a truncation footer pointing at the full artifact if the cap
  is reached.
- **`if-no-files-found: warn`** on the upload steps preserves the
  skip-on-empty behaviour above.

## Security

Every `${{ inputs.X }}` reference in `action.yml` flows through a
step-level `env:` block before reaching a shell `run:` script.
**Never interpolate `${{ inputs.X }}` directly into a `run:` command**
— that re-introduces the GHA shell-injection class that #876 closed.
When adding new steps, follow the env-var indirection pattern.

The `actions/upload-artifact` action is SHA-pinned to v7.0.1; keep in
sync with every other reference in this repository so Dependabot
rotates all call sites together.
