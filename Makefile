.PHONY: test test-all test-core test-file test-syslog test-webhook test-loki test-outputconfig test-audit-gen test-audit-validate test-bdd-report test-junit-report \
       test-secrets test-secrets-env test-secrets-file test-secrets-openbao test-secrets-vault \
       test-integration test-integration-file test-integration-syslog test-integration-webhook test-integration-loki test-integration-core test-integration-secrets-openbao test-integration-secrets-vault \
       test-bdd test-bdd-core test-bdd-outputconfig test-bdd-file test-bdd-file-os test-bdd-syslog test-bdd-webhook test-bdd-loki test-bdd-fanout \
       test-bdd-verify \
       test-examples \
       lint lint-all lint-core lint-file lint-syslog lint-webhook lint-loki lint-outputconfig lint-audit-gen lint-audit-validate lint-bdd-report lint-junit-report lint-examples \
       lint-secrets lint-secrets-openbao lint-secrets-vault \
       check-report-parity \
       vet vet-all fmt fmt-check \
       build build-all bench bench-save bench-compare bench-baseline-check coverage \
       tidy tidy-check verify check-replace check-todos check-example-links check-bdd-strict check-insecure-skip-verify check-license-headers check-static \
       security release-check api-check check-release-invariants \
       regen-release-docs regen-release-docs-check \
       regen-schema-artifacts regen-schema-artifacts-check \
       print-publish-modules \
       check clean \
       install-tools install-benchstat install-govulncheck install-gremlins workspace generate-certs \
       mutation-test mutation-test-validate-fields mutation-test-validate-taxonomy \
       mutation-test-hmac mutation-test-filter mutation-test-format-cef mutation-test-sensitivity \
       test-infra-up test-infra-down test-infra-logs \
       test-infra-syslog-up test-infra-syslog-down \
       test-infra-file-os-up test-infra-file-os-down \
       test-infra-webhook-up test-infra-webhook-down \
       test-infra-loki-up test-infra-loki-down \
       test-infra-openbao-up test-infra-openbao-down \
       test-infra-vault-up test-infra-vault-down \
       test-bdd-secrets \
       sbom sbom-validate \
       stress-test

# --- Configuration ---

# Force bash with pipefail so recipe pipelines don't silently mask failures.
# Without this, `cmd | tee file` exits 0 even when `cmd` fails — the same
# bug class that hid BDD failures in CI before #622. Recipes that rely on
# `grep`'s non-zero-on-no-match (e.g. check-todos) must use `|| true`.
SHELL      := bash
.SHELLFLAGS := -e -o pipefail -c

MODULES           := . file iouring syslog webhook loki outputconfig outputs cmd/audit-gen cmd/audit-validate cmd/bdd-report cmd/junit-report secrets secrets/env secrets/file secrets/openbao secrets/vault
# EXAMPLE_MODULES is auto-discovered from any examples/*/go.mod so new
# examples are picked up without touching the Makefile. Sorted for
# deterministic workspace generation.
EXAMPLE_MODULES   := $(sort $(patsubst %/go.mod,%,$(wildcard examples/*/go.mod)))
WORKSPACE_MODULES := $(MODULES) $(EXAMPLE_MODULES)
GOBIN             := $(shell go env GOPATH)/bin
GO_TOOLCHAIN      := go1.26.3
# Windows go install appends .exe to executables; everything else is
# bare. Used when the recipe must invoke an installed tool by absolute
# path (cross-platform CI legs run under Git Bash).
BINEXT            := $(if $(filter Windows_NT,$(OS)),.exe,)

# Tool versions — pinned for supply chain safety, single source
# of truth for both this Makefile and the CI cache key. The CI
# cache (.github/actions/setup-audit/action.yml) keys on
# hashFiles('scripts/tool-versions.txt'), so updating that file
# automatically invalidates the cache.
include scripts/tool-versions.txt

# --- Tool management ---

install-tools:
	@echo "Installing tools with GOTOOLCHAIN=$(GO_TOOLCHAIN)..."
	GOTOOLCHAIN=$(GO_TOOLCHAIN) go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VER)
	GOTOOLCHAIN=$(GO_TOOLCHAIN) go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VER)
	GOTOOLCHAIN=$(GO_TOOLCHAIN) go install golang.org/x/tools/cmd/goimports@$(GOIMPORTS_VER)
	GOTOOLCHAIN=$(GO_TOOLCHAIN) go install github.com/goreleaser/goreleaser/v2@$(GORELEASER_VER)
	GOTOOLCHAIN=$(GO_TOOLCHAIN) go install golang.org/x/perf/cmd/benchstat@$(BENCHSTAT_VER)
	GOTOOLCHAIN=$(GO_TOOLCHAIN) go install golang.org/x/exp/cmd/gorelease@$(GORELEASE_VER)
	GOTOOLCHAIN=$(GO_TOOLCHAIN) go install github.com/go-gremlins/gremlins/cmd/gremlins@$(GREMLINS_VER)
	GOTOOLCHAIN=$(GO_TOOLCHAIN) go install gotest.tools/gotestsum@$(GOTESTSUM_VER)
	@echo "Tools installed to $(GOBIN)"

install-benchstat:
	@echo "Installing benchstat with GOTOOLCHAIN=$(GO_TOOLCHAIN)..."
	GOTOOLCHAIN=$(GO_TOOLCHAIN) go install golang.org/x/perf/cmd/benchstat@$(BENCHSTAT_VER)
	@echo "benchstat installed to $(GOBIN)"

install-gremlins:
	@echo "Installing gremlins with GOTOOLCHAIN=$(GO_TOOLCHAIN)..."
	GOTOOLCHAIN=$(GO_TOOLCHAIN) go install github.com/go-gremlins/gremlins/cmd/gremlins@$(GREMLINS_VER)
	@echo "gremlins installed to $(GOBIN)"

# --- Workspace ---

workspace:
	@rm -f go.work go.work.sum
	go work init $(WORKSPACE_MODULES)

# --- Per-module test targets ---
#
# Every test-<module> target honours JUNIT_REPORT_FILE: when set, the
# test run is driven by gotestsum and a JUnit XML report is written
# to that path alongside the existing coverage profile. With the env
# var unset, behaviour is exactly as before (plain `go test -v`).
#
# Local example (single module):
#   make install-tools                            # one-off: installs gotestsum
#   JUNIT_REPORT_FILE=/tmp/r.xml make test-core
#   go run ./cmd/junit-report -input /tmp/r.xml -suite core -format html > r.html
#
# The CI artefact wiring lands in a follow-up PR (#877 PR B).
#
# test-integration runs multiple `go test` invocations in one recipe
# (see lines below); its JUnit emission is intentionally NOT wired in
# this PR because a single JUNIT_REPORT_FILE would be overwritten by
# the last invocation. PR B will matrix-split it and wire per-leg.
define go_test_with_junit
	if [ -n "$$JUNIT_REPORT_FILE" ]; then \
	    $(GOBIN)/gotestsum$(BINEXT) --junitfile="$$JUNIT_REPORT_FILE" --format=testname -- $(1) $(2); \
	else \
	    go test -v $(1) $(2); \
	fi
endef

test-core:
	cd . && $(call go_test_with_junit,-race -count=1 -timeout=15m -coverprofile=coverage.out,$$(go list ./... | grep -v /tests/ | grep -v /internal/testhelper | grep -v /examples/))

test-file:
	cd file && $(call go_test_with_junit,-race -count=1 -coverprofile=coverage.out,./...)

test-syslog:
	cd syslog && $(call go_test_with_junit,-race -count=1 -coverprofile=coverage.out,./...)

test-webhook:
	cd webhook && $(call go_test_with_junit,-race -count=1 -coverprofile=coverage.out,./...)

test-loki:
	cd loki && $(call go_test_with_junit,-race -count=1 -coverprofile=coverage.out,./...)

test-outputconfig:
	cd outputconfig && $(call go_test_with_junit,-race -count=1 -coverprofile=coverage.out,$$(go list ./... | grep -v /tests/))

test-audit-gen:
	cd cmd/audit-gen && $(call go_test_with_junit,-race -count=1 -coverprofile=coverage.out,./...)

test-audit-validate:
	cd cmd/audit-validate && $(call go_test_with_junit,-race -count=1 -coverprofile=coverage.out,./...)

test-bdd-report:
	cd cmd/bdd-report && $(call go_test_with_junit,-race -count=1 -coverprofile=coverage.out,./...)

test-junit-report:
	cd cmd/junit-report && $(call go_test_with_junit,-race -count=1 -coverprofile=coverage.out,./...)

test-secrets:
	cd secrets && $(call go_test_with_junit,-race -count=1 -coverprofile=coverage.out,./...)

test-secrets-openbao:
	cd secrets/openbao && $(call go_test_with_junit,-race -count=1 -coverprofile=coverage.out,./...)

test-secrets-vault:
	cd secrets/vault && $(call go_test_with_junit,-race -count=1 -coverprofile=coverage.out,./...)

test-secrets-env:
	cd secrets/env && $(call go_test_with_junit,-race -count=1 -coverprofile=coverage.out,./...)

test-secrets-file:
	cd secrets/file && $(call go_test_with_junit,-race -count=1 -coverprofile=coverage.out,./...)

test-all: test-core test-file test-syslog test-webhook test-loki test-outputconfig test-audit-gen test-audit-validate test-bdd-report test-junit-report test-secrets test-secrets-env test-secrets-file test-secrets-openbao test-secrets-vault
test: test-all

# --- Stress targets (#705 family) ---
#
# stress-test runs the flake-prone tests N times under -race to
# catch synchronisation regressions early. Wired into a scheduled
# .github/workflows/stress-test.yml so the catch rate is high if
# anyone re-introduces a polling pattern.
#
# Override the iteration count on the command line:
#     make stress-test STRESS_COUNT=500

STRESS_COUNT ?= 100

stress-test: ## Run flake-prone tests STRESS_COUNT times under -race (default 100)
	cd syslog && go test -race -count=$(STRESS_COUNT) -run 'TestWriteLoop_|TestSyslogOutput_HandleWriteFailure_WriteFailsAfterReconnect|TestSyslogOutput_ReconnectRecorder_RecordReconnect_FailureOnPermanentServerDown' ./...
	cd file && go test -race -count=$(STRESS_COUNT) -run 'TestWriter_Write_BackgroundTimerFlushes|TestFileOutput_FileMetrics_MultipleRotations|TestFileOutput_FileMetrics_RecordRotation|TestFileOutput_RapidWrites_RotatesAtLeastOnce' ./...
	cd webhook && go test -race -count=$(STRESS_COUNT) -run 'TestWebhookOutput_DeliveryMetrics_SuccessOnHTTP200|TestWebhookOutput_TLS_WrongCA|TestMockMetrics_|TestMockOutputMetrics_' ./...
	go test -race -count=$(STRESS_COUNT) -run 'TestProcessEntry_ConcurrentSubmission_NoRace' .

# --- Soak benchmark (#573) ---
#
# `make soak` runs the long-running mixed-output workload that
# exercises the audit hot path for SOAK_DURATION (default 12h)
# before each release tag. Drives 4 outputs concurrently (file +
# in-process syslog mock + httptest webhook + drain to discard) at
# SOAK_RATE events/sec across SOAK_PRODUCERS goroutines, sampling
# runtime memory + goroutine count every SOAK_SAMPLE_INTERVAL.
#
# Output:
#   $(SOAK_OUTPUT_DIR)/soak-samples-<timestamp>.csv  per-sample state
#   $(SOAK_OUTPUT_DIR)/soak-summary-<timestamp>.json start/end/peak
#
# Maintainers paste the summary into BENCHMARKS.md "Release
# Soak-Test Summary" before tagging a release. See
# `docs/releasing.md` pre-release checklist for the full workflow.
#
# `make soak-quick` runs a 1-minute smoke test for harness
# verification (used by maintainers before kicking off the 12-hour
# run).
#
# Override variables on the command line:
#   make soak SOAK_DURATION=2h SOAK_RATE=10000

SOAK_DURATION ?= 12h
SOAK_PRODUCERS ?= 8
SOAK_RATE ?= 5000
SOAK_SAMPLE_INTERVAL ?= 1m
SOAK_OUTPUT_DIR ?= ./soak-output

soak: ## Run the 12-hour soak benchmark (overridable via SOAK_DURATION)
	@mkdir -p $(SOAK_OUTPUT_DIR)
	SOAK_DURATION=$(SOAK_DURATION) \
	SOAK_PRODUCERS=$(SOAK_PRODUCERS) \
	SOAK_RATE=$(SOAK_RATE) \
	SOAK_SAMPLE_INTERVAL=$(SOAK_SAMPLE_INTERVAL) \
	SOAK_OUTPUT_DIR=$(SOAK_OUTPUT_DIR) \
	go test -tags=soak -timeout=0 -count=1 -run='^$$' \
		-bench=BenchmarkSoak_MixedOutputs \
		-benchtime=$(SOAK_DURATION) \
		./tests/soak/...

soak-quick: ## Run a 1-minute soak smoke test (verifies harness)
	@$(MAKE) soak SOAK_DURATION=1m SOAK_SAMPLE_INTERVAL=10s

# --- Fuzz targets (#481) ---
#
# fuzz-short runs each Fuzz* function's SEED CORPUS only (no
# `-fuzz` flag means `go test` just executes the seeds as
# regular sub-tests). Fast (< 1s). Used by PR CI as a regression
# tripwire against committed seeds in testdata/fuzz/FuzzXxx/.
#
# fuzz-long invokes the fuzzer in discovery mode with
# `-fuzztime=${FUZZ_TIME}` per target (default 60s each). Used
# by the release workflow. Override on the command line for
# longer runs: `make fuzz-long FUZZ_TIME=10m`.

FUZZ_TIME ?= 60s

fuzz-short: ## Run fuzz seeds against every target (fast, PR-safe)
	go test -run='^Fuzz' -count=1 .
	cd outputconfig && go test -run='^Fuzz' -count=1 .
	cd secrets && go test -run='^Fuzz' -count=1 .

fuzz-long: ## Run each fuzz target for ${FUZZ_TIME} (default 60s). Release gate.
	go test -run='^$$' -fuzz='^FuzzParseTaxonomyYAML$$' -fuzztime=${FUZZ_TIME} .
	cd outputconfig && go test -run='^$$' -fuzz='^FuzzOutputConfigLoad$$' -fuzztime=${FUZZ_TIME} .
	cd outputconfig && go test -run='^$$' -fuzz='^FuzzExpandEnvString$$' -fuzztime=${FUZZ_TIME} .
	cd secrets && go test -run='^$$' -fuzz='^FuzzParseRef$$' -fuzztime=${FUZZ_TIME} .

# Integration tests (requires Docker: make test-infra-up first).
#
# Per-module integration targets honour JUNIT_REPORT_FILE via the
# go_test_with_junit macro (#877 PR A). CI runs each per-module
# target in its own matrix leg so the JUnit XML for each module is
# written to a distinct path; the meta `test-integration` target
# below preserves the local-dev one-command invocation. Do NOT
# parallelise (make -j test-integration) — the per-module docker
# stacks share infra ports.
test-integration-file:
	cd file && $(call go_test_with_junit,-race -count=1 -tags=integration,./tests/integration/...)

test-integration-syslog:
	cd syslog && $(call go_test_with_junit,-race -count=1 -tags=integration,./tests/integration/...)

test-integration-webhook:
	cd webhook && $(call go_test_with_junit,-race -count=1 -tags=integration,./tests/integration/...)

test-integration-loki:
	cd loki && $(call go_test_with_junit,-race -count=1 -tags=integration,./tests/integration/...)

test-integration-core:
	$(call go_test_with_junit,-race -count=1 -tags=integration,./tests/integration/...)

test-integration-secrets-openbao:
	cd secrets/openbao && $(call go_test_with_junit,-race -count=1 -tags=integration,./tests/integration/...)

test-integration-secrets-vault:
	cd secrets/vault && $(call go_test_with_junit,-race -count=1 -tags=integration,./tests/integration/...)

test-integration: test-integration-file test-integration-syslog \
                  test-integration-webhook test-integration-loki \
                  test-integration-core test-integration-secrets-openbao \
                  test-integration-secrets-vault

# BDD tests — all scenarios (requires Docker for syslog/webhook/loki scenarios)
test-bdd:
	go test -race -v -count=1 -tags=integration ./tests/bdd/...
	cd outputconfig && go test -race -v -count=1 ./tests/bdd/...

# BDD tests — per-tag runners for parallel CI execution.
# Core and file need no Docker. Others require specific infrastructure.
test-bdd-core:
	BDD_TAGS="@core && ~@docker" go test -race -v -count=1 -tags=integration ./tests/bdd/...

test-bdd-outputconfig:
	cd outputconfig && go test -race -v -count=1 ./tests/bdd/...

test-bdd-file:
	BDD_TAGS="@file && ~@docker" go test -race -v -count=1 -tags=integration ./tests/bdd/...

# OS-failure-mode scenarios for the file output (#748). Requires the
# file-os tmpfs container — see `test-infra-file-os-up`.
test-bdd-file-os:
	BDD_TAGS="@file && @docker" go test -race -v -count=1 -tags=integration ./tests/bdd/...

test-bdd-syslog:
	BDD_TAGS=@syslog go test -race -v -count=1 -tags=integration ./tests/bdd/...

test-bdd-webhook:
	BDD_TAGS="@webhook, @routing" go test -race -v -count=1 -tags=integration ./tests/bdd/...

test-bdd-loki:
	BDD_TAGS="@loki && ~@fanout" go test -race -v -count=1 -tags=integration ./tests/bdd/...

test-bdd-fanout:
	BDD_TAGS=@fanout go test -race -v -count=1 -tags=integration ./tests/bdd/...

test-bdd-secrets:
	cd outputconfig && go test -race -v -count=1 -tags=integration -run TestOutputConfigDockerFeatures ./tests/bdd/...

# BDD coverage verification — ensure every scenario is covered by at least one runner.
# This is a static check that evaluates tag expressions against feature files.
# Runs in CI after all BDD matrix entries complete, and locally before release.
test-bdd-verify:
	./scripts/verify-bdd-coverage.sh

# bdd-report builds the cucumber JSON → HTML/Markdown converter (#439).
# CI uses `go run ./cmd/bdd-report` directly; this target is for local
# builds. Pair with `BDD_REPORT_FILE=/tmp/r.json make test-bdd-core` to
# capture a report, then:
#   go run ./cmd/bdd-report -input /tmp/r.json -suite core -format html > r.html
#   go run ./cmd/bdd-report -input /tmp/r.json -suite core -format markdown > r.md
.PHONY: bdd-report
bdd-report:
	go build -o ./bin/bdd-report ./cmd/bdd-report

# Example compilation tests (no runtime — examples are documentation).
# Driven from EXAMPLE_MODULES (line 43) so new examples are picked up
# without touching the Makefile. The previous hard-coded list drifted
# behind reality — issue #438 cited "17 examples" when there were 20.
test-examples:
	@for dir in $(EXAMPLE_MODULES); do \
		echo "=== build $$dir ==="; \
		(cd $$dir && go build -o /dev/null .) || exit 1; \
	done

# print-example-modules emits EXAMPLE_MODULES one entry per line for
# shell-script consumption (.github/workflows/release-examples-verify.yml).
# Mirrors print-publish-modules.
.PHONY: print-example-modules
print-example-modules:
	@$(foreach e,$(EXAMPLE_MODULES),printf '%s\n' '$(e)';)

# verify-examples-published — local equivalent of
# .github/workflows/release-examples-verify.yml. Iterates every example,
# copies to a tmpdir, bumps every github.com/axonops/audit* require to
# VERSION via scripts/release/bump-example-deps.sh, runs go mod tidy +
# go build + (if tests exist) go test. Lets a maintainer reproduce the
# post-release CI gate against any published tag locally.
#
# Usage:
#   VERSION=v0.1.13 make verify-examples-published
.PHONY: verify-examples-published
verify-examples-published:
	@if [ -z "$(VERSION)" ]; then \
		echo "verify-examples-published: VERSION must be set (e.g. VERSION=v0.1.13)"; \
		exit 2; \
	fi
	@scripts_dir="$(CURDIR)/scripts/release"; \
	base=$$(mktemp -d -t verify-examples-XXXXXX); \
	trap 'rm -rf "$$base"' EXIT INT TERM; \
	failed=""; \
	for src in $(EXAMPLE_MODULES); do \
		echo "=== verify-published $$src @ $(VERSION) ==="; \
		dst="$$base/$$(basename $$src)"; \
		mkdir -p "$$dst"; \
		cp -r "$$src"/. "$$dst"/; \
		( \
			cd "$$dst" && \
			"$$scripts_dir/bump-example-deps.sh" "$$dst" "$(VERSION)" && \
			GOWORK=off go mod tidy && \
			GOWORK=off go build ./... && \
			GOWORK=off go test ./... \
		) || failed="$$failed $$src"; \
	done; \
	if [ -n "$$failed" ]; then \
		echo "verify-examples-published: FAILED for:$$failed"; \
		exit 1; \
	fi; \
	echo "verify-examples-published: all examples passed"

# --- Linting ---

lint-core:
	cd . && $(GOBIN)/golangci-lint run --timeout=5m --config $(CURDIR)/.golangci.yml ./...

lint-file:
	cd file && $(GOBIN)/golangci-lint run --timeout=5m --config $(CURDIR)/.golangci.yml ./...

lint-syslog:
	cd syslog && $(GOBIN)/golangci-lint run --timeout=5m --config $(CURDIR)/.golangci.yml ./...

lint-webhook:
	cd webhook && $(GOBIN)/golangci-lint run --timeout=5m --config $(CURDIR)/.golangci.yml ./...

lint-loki:
	cd loki && $(GOBIN)/golangci-lint run --timeout=5m --config $(CURDIR)/.golangci.yml ./...

lint-outputconfig:
	cd outputconfig && $(GOBIN)/golangci-lint run --timeout=5m --config $(CURDIR)/.golangci.yml ./...

lint-audit-gen:
	cd cmd/audit-gen && $(GOBIN)/golangci-lint run --timeout=5m --config $(CURDIR)/.golangci.yml ./...

lint-audit-validate:
	cd cmd/audit-validate && $(GOBIN)/golangci-lint run --timeout=5m --config $(CURDIR)/.golangci.yml ./...

lint-bdd-report:
	cd cmd/bdd-report && $(GOBIN)/golangci-lint run --timeout=5m --config $(CURDIR)/.golangci.yml ./...

lint-junit-report:
	cd cmd/junit-report && $(GOBIN)/golangci-lint run --timeout=5m --config $(CURDIR)/.golangci.yml ./...

lint-secrets:
	cd secrets && $(GOBIN)/golangci-lint run --timeout=5m --config $(CURDIR)/.golangci.yml ./...

lint-secrets-openbao:
	cd secrets/openbao && $(GOBIN)/golangci-lint run --timeout=5m --config $(CURDIR)/.golangci.yml ./...

lint-secrets-vault:
	cd secrets/vault && $(GOBIN)/golangci-lint run --timeout=5m --config $(CURDIR)/.golangci.yml ./...

# Lint every example with its own go.mod. EXAMPLE_MODULES is
# auto-discovered (see top of file). Replaces the single-example
# lint-capstone target so new examples are linted without further
# Makefile edits.
lint-examples:
	@for dir in $(EXAMPLE_MODULES); do \
		echo "=== lint $$dir ==="; \
		(cd $$dir && $(GOBIN)/golangci-lint run --timeout=5m --config $(CURDIR)/.golangci.yml ./...) || exit 1; \
	done

lint-all: lint-core lint-file lint-syslog lint-webhook lint-loki lint-outputconfig lint-audit-gen lint-audit-validate lint-bdd-report lint-junit-report lint-secrets lint-secrets-openbao lint-secrets-vault lint-examples
lint: lint-all

# --- Vet ---

vet-all:
	@for mod in $(MODULES); do \
		echo "=== vet $$mod ==="; \
		(cd $$mod && go vet ./...) || exit 1; \
	done
vet: vet-all

# --- Format ---

# gofmt ships with the Go toolchain — not installed to GOBIN.
fmt:
	gofmt -s -w .
	$(GOBIN)/goimports -w .

fmt-check:
	@echo "=== gofmt ==="
	@DIFF=$$(gofmt -s -l .); if [ -n "$$DIFF" ]; then echo "Files need gofmt -s:"; echo "$$DIFF"; exit 1; fi
	@echo "=== goimports ==="
	@DIFF=$$($(GOBIN)/goimports -l .); if [ -n "$$DIFF" ]; then echo "Files need goimports:"; echo "$$DIFF"; exit 1; fi

# --- Build ---

build-all:
	@for mod in $(MODULES); do \
		echo "=== build $$mod (linux/amd64) ==="; \
		(cd $$mod && GOOS=linux GOARCH=amd64 go build ./...) || exit 1; \
		echo "=== build $$mod (darwin/arm64) ==="; \
		(cd $$mod && GOOS=darwin GOARCH=arm64 go build ./...) || exit 1; \
		echo "=== build $$mod (windows/amd64) ==="; \
		(cd $$mod && GOOS=windows GOARCH=amd64 go build ./...) || exit 1; \
	done
build: build-all

# --- Benchmarks ---

BENCH_COUNT ?= 5

bench:
	@rm -f bench.txt
	@for mod in $(MODULES); do \
		echo "=== bench $$mod ===" >> bench.txt; \
		(cd $$mod && go test -bench=. -benchmem -count=$(BENCH_COUNT) -run='^$$' ./... >> $(CURDIR)/bench.txt) || exit 1; \
	done
	@echo "bench output written to bench.txt ($$(wc -l < bench.txt) lines)"

bench-save: bench
	cp bench.txt bench-baseline.txt
	@echo "Baseline saved to bench-baseline.txt"

bench-compare: bench
	@if [ -f bench-baseline.txt ]; then \
		$(GOBIN)/benchstat bench-baseline.txt bench.txt; \
	else \
		echo "No bench-baseline.txt found. Run 'make bench-save' first."; \
		exit 1; \
	fi

# bench-baseline-check fails if bench-baseline.txt references benchmark
# names that no longer exist in the source tree. Catches the class of
# bug that silently breaks benchstat on rename (#493). Run as part of
# make check to prevent stale names from landing on main.
bench-baseline-check:
	@if [ ! -f bench-baseline.txt ]; then \
		echo "bench-baseline.txt missing — run 'make bench-save' to create one."; \
		exit 1; \
	fi
	@bash scripts/bench-baseline-check.sh

# --- Mutation testing (#571) ---
#
# Mutation testing measures whether the test suite verifies behaviour or
# merely traverses lines. gremlins applies mutation operators (boundary
# inversions, conditional negations, arithmetic flips) to source code and
# reports which mutants survive — a survivor reveals a test that doesn't
# actually verify the contract for that branch.
#
# We mutation-test 6 security-critical files in the root pkg. Because
# gremlins operates per-package, per-file scoring requires a separate
# invocation per file with --exclude-files set to all OTHER package
# sources. Threshold (≥80% efficacy) is enforced via gremlins' exit code
# 10. See MUTATION_TESTING.md for the per-file baseline and exemptions.

# 6 mutation targets — mirrors AC#3 of #571.
MUTATION_TARGETS := validate_fields.go validate_taxonomy.go hmac.go filter.go format_cef.go sensitivity.go

# Worker count for gremlins. Default 2 to avoid resource-contention
# timeouts (every gremlins worker compiles + runs the full root-pkg
# test suite; on this codebase 4+ workers cause spurious TIMED OUT
# classifications). CI shards or beefier hardware can override:
# `make mutation-test-hmac GREMLINS_WORKERS=4`.
GREMLINS_WORKERS ?= 2

# Root-pkg non-test sources NOT in MUTATION_TARGETS — gremlins must not
# mutate these during a per-file run. Computed via recursive `=` (NOT
# `:=`) so $(wildcard *.go) re-evaluates per recipe call, auto-excluding
# any new root-pkg .go file a future contributor adds — keeping the
# baseline scope honest without requiring a Makefile edit.
MUTATION_OTHER_FILES = $(filter-out $(MUTATION_TARGETS),$(filter-out $(wildcard *_test.go),$(wildcard *.go)))

# Regex passed to --exclude-files: matches any file with a directory
# component. Combined with the per-file anchored excludes below it
# leaves exactly one root-pkg file in scope per invocation.
MUTATION_EXCLUDE_SUBDIRS := ^.+/.+

# Per-file recipe: mutate exactly $(1), exclude all other root-pkg
# sources (the 5 sibling targets + everything else) AND every file with
# a directory path component (every workspace sub-module). Gremlins
# prints its own structured output to stdout; on failure we append a
# remediation footer pointing at MUTATION_TESTING.md (precedent:
# check-todos / check-replace pattern).
#
# --coverpkg=github.com/axonops/audit scopes the coverage profile to the
# root package; without it, `go test ./...` would attempt to build
# coverage instrumentation for every example sub-package and race on the
# `covdata` tool build (Go cmd/covdata is built lazily into the build
# cache and parallel builds fail with "go: no such tool covdata"). The
# example packages contribute nothing to mutation testing of the 6
# target files.
#
# --workers caps gremlins parallelism. The default (auto = NumCPU)
# causes mutated test runs to time out under resource contention — each
# worker compiles + runs the full root-pkg test suite, so 8 workers on
# an 8-core box trigger spurious TIMED OUT classifications that mask
# LIVED mutants. GREMLINS_WORKERS=2 gives stable kills on this codebase
# at acceptable wall-clock cost (~10 minutes per file).
#
# --threshold-efficacy=80 / --threshold-mcover=80 are passed on the CLI
# in addition to the .gremlins.yaml settings: gremlins exit codes 10
# and 11 fire below these thresholds, so the recipe fails fast even if
# the YAML schema drifts in a future gremlins release.
#
# Excludes use Go regexp syntax with `^...$` anchors so file basenames
# don't accidentally match substring siblings (e.g., `hmac.go` would
# unanchored-match `hmac_anything.go`). The `$$` in the foreach below
# is a literal `$` regex anchor escaped for Make (NOT a Make variable).
define MUTATION_RECIPE
	@echo "=== mutation-test $(1) ==="
	@$(GOBIN)/gremlins unleash . \
		--coverpkg=github.com/axonops/audit \
		--workers=$(GREMLINS_WORKERS) \
		--threshold-efficacy=80 \
		--threshold-mcover=80 \
		--exclude-files='$(MUTATION_EXCLUDE_SUBDIRS)' \
		$(foreach f,$(filter-out $(1),$(MUTATION_TARGETS)),--exclude-files='^$(f)$$') \
		$(foreach f,$(MUTATION_OTHER_FILES),--exclude-files='^$(f)$$') \
		|| { \
			echo ""; \
			echo "FAILED: mutation efficacy below threshold for $(1)."; \
			echo "Next steps:"; \
			echo "  1. Kill the surviving mutant: add a test in the matching *_test.go that"; \
			echo "     fails when the mutated branch flips."; \
			echo "  2. OR document an equivalent mutant in MUTATION_TESTING.md (file:line,"; \
			echo "     operator, rationale)."; \
			echo "  3. OR justify lowering threshold in .gremlins.yaml (PR review required)."; \
			exit 1; \
		}
endef

mutation-test-validate-fields:
	$(call MUTATION_RECIPE,validate_fields.go)

mutation-test-validate-taxonomy:
	$(call MUTATION_RECIPE,validate_taxonomy.go)

mutation-test-hmac:
	$(call MUTATION_RECIPE,hmac.go)

mutation-test-filter:
	$(call MUTATION_RECIPE,filter.go)

mutation-test-format-cef:
	$(call MUTATION_RECIPE,format_cef.go)

mutation-test-sensitivity:
	$(call MUTATION_RECIPE,sensitivity.go)

mutation-test: mutation-test-validate-fields mutation-test-validate-taxonomy mutation-test-hmac mutation-test-filter mutation-test-format-cef mutation-test-sensitivity
	@echo "All mutation targets passed (efficacy ≥ threshold)."

# --- Coverage ---

coverage:
	@for mod in $(MODULES); do \
		echo "=== coverage $$mod ==="; \
		(cd $$mod && go test -race -coverprofile=coverage.out ./... && go tool cover -func=coverage.out | grep total) || exit 1; \
	done

# --- Module hygiene ---

tidy:
	@for mod in $(MODULES); do \
		echo "=== tidy $$mod ==="; \
		(cd $$mod && go mod tidy) || exit 1; \
	done

tidy-check:
	@if [ -n "$$SKIP_TIDY_CHECK" ]; then \
		echo "tidy-check: SKIP_TIDY_CHECK is set — skipping (release-branch flow)"; \
	else \
		for mod in $(MODULES); do \
			echo "=== tidy-check $$mod ==="; \
			(cd $$mod && \
			 cp go.mod go.mod.bak && (cp go.sum go.sum.bak 2>/dev/null; true) && \
			 go mod tidy && \
			 diff -q go.mod go.mod.bak > /dev/null 2>&1 && \
			 ([ ! -f go.sum.bak ] || diff -q go.sum go.sum.bak > /dev/null 2>&1) && \
			 rm -f go.mod.bak go.sum.bak || \
			 { echo "ERROR: go mod tidy produced changes in $$mod"; \
			   mv go.mod.bak go.mod 2>/dev/null; mv go.sum.bak go.sum 2>/dev/null; exit 1; }) || exit 1; \
		done; \
	fi

verify:
	@for mod in $(MODULES); do \
		echo "=== verify $$mod ==="; \
		(cd $$mod && go mod verify) || exit 1; \
	done

# Reject replace directives in all go.mod files
check-replace:
	@for mod in $(MODULES); do \
		if grep -q "^replace " "$$mod/go.mod" 2>/dev/null; then \
			echo "ERROR: $$mod/go.mod contains replace directive"; \
			exit 1; \
		fi; \
	done
	@echo "No replace directives found."

# Reject any production-code use of InsecureSkipVerify: true.
# The single biggest TLS footgun — must never appear outside
# *_test.go files. To exempt a legitimate test helper, append
# a trailing `// audit:allow-insecure-skip-verify` comment to
# the same line as the field assignment; the rule below
# filters those lines and the comment is grep-discoverable
# for review.
check-insecure-skip-verify:
	@OFFENDERS=$$({ \
		grep -rn -E 'InsecureSkipVerify[[:space:]]*:[[:space:]]*true' \
			--include='*.go' \
			--exclude='*_test.go' \
			. 2>/dev/null || true; \
	} | { grep -v 'audit:allow-insecure-skip-verify' || true; }); \
	if [ -n "$$OFFENDERS" ]; then \
		echo "ERROR: InsecureSkipVerify: true in production code:"; \
		echo "$$OFFENDERS"; \
		echo ""; \
		echo "TLS verification must never be disabled in production code."; \
		echo "If a test helper genuinely needs this, append a trailing"; \
		echo "// audit:allow-insecure-skip-verify comment on the same line."; \
		exit 1; \
	fi
	@echo "No InsecureSkipVerify: true in production code."

# Verify the shared report-rendering helpers (render.go, writer.go) are
# byte-identical between cmd/bdd-report and cmd/junit-report. The two
# tools render different input formats but share security-critical
# escape and writer code; drift between them creates a Markdown- or
# HTML-injection risk in one tool but not the other.
check-report-parity:
	@./scripts/check-report-parity.sh

# Enforce TODO comments must reference a GitHub issue: TODO(#NNN)
check-todos:
	@ORPHANED=$$({ grep -rn 'TODO' --include='*.go' || true; } | { grep -v 'TODO(#[0-9]' || true; } | { grep -v 'nolint' || true; } | { grep -v '_test.go.*TODO' || true; }); \
	if [ -n "$$ORPHANED" ]; then \
		echo "ERROR: orphaned TODO without issue reference:"; \
		echo "$$ORPHANED"; \
		exit 1; \
	fi

# Reject any *.go file that lacks the standard Apache 2.0 license
# header. Generated files (recognised by the standard
# `// Code generated ... DO NOT EDIT.` marker per `cmd/go` docs)
# are exempt. The header search window is the first 16 lines so
# that files starting with build constraints (`//go:build ...`)
# or a code-generation directive are still recognised. (#539)
check-license-headers:
	@MISSING=""; \
	while IFS= read -r f; do \
		if ! head -16 "$$f" | grep -qE 'Copyright.*AxonOps|Code generated.*DO NOT EDIT'; then \
			MISSING="$$MISSING $$f"; \
		fi; \
	done < <(find . -name '*.go' -not -path './.git/*' -not -path '*/.scratch/*' -not -path '*/vendor/*' -not -path '*/testdata/*'); \
	if [ -n "$$MISSING" ]; then \
		echo "ERROR: .go files missing the Apache 2.0 license header:"; \
		for f in $$MISSING; do echo "  $$f"; done; \
		exit 1; \
	fi
	@echo "All .go files have the standard license header."

# Reject broken numeric cross-references in example READMEs (e.g.
# `../05-file-output/` when `examples/04-formatters/` is the actual
# directory at index 05). Catches drift after example renumbering.
#
# Greps every `examples/*/README.md` for relative links of the form
# `../NN-slug` (with or without trailing slash, with or without
# `#anchor`) and verifies that `examples/NN-slug/` exists. Any
# pointer to a missing directory fails the target with the offending
# file:line and the bad target.
check-example-links:
	@FAILING=""; \
	for f in examples/*/README.md; do \
		LINKS=$$(grep -oE '\.\./[0-9][0-9]-[a-z][a-z0-9-]*' "$$f" | sort -u); \
		for link in $$LINKS; do \
			target=$$(echo "$$link" | sed -E 's#^\.\./##'); \
			if [ ! -d "examples/$$target" ]; then \
				LINENOS=$$(grep -nE "\.\./$$target([/#)]|$$)" "$$f" | cut -d: -f1 | tr '\n' ',' | sed 's/,$$//'); \
				FAILING="$$FAILING\n  $$f:$$LINENOS -> $$link (no examples/$$target/)"; \
			fi; \
		done; \
	done; \
	if [ -n "$$FAILING" ]; then \
		printf "ERROR: broken example README cross-references:%b\n" "$$FAILING"; \
		exit 1; \
	fi
	@echo "All example README cross-references resolve."

# Enforce godog runners use Strict mode so undefined steps fail the
# suite. This is the contract established by #622 — CI must NEVER
# silently pass a scenario whose step definition doesn't exist.
#
# Three checks — any one failing fails the target:
#  (1) Every file declaring `godog.Options{` must contain `Strict: true`
#      (exact string match, space-insensitive). `Strict: false` does
#      NOT satisfy the check. A commented-out `Strict` line does NOT
#      satisfy the check (grep ignores leading whitespace but not //).
#  (2) No file anywhere in the repo may contain `Strict: false` or
#      `Strict:false`. An explicit opt-out is rejected even if the same
#      file has `Strict: true` elsewhere — prevents tricks like a
#      runtime override.
#  (3) No Makefile target or shell script may pass `-godog.strict=false`
#      or `--godog.strict=false` as a CLI flag — prevents a silent
#      override at invocation time.
#
# This target runs in `make check` AND as a dedicated CI step before
# the test matrix so a regression fails loudly and early. Under NO
# circumstances may this target be removed, weakened, or bypassed.
# See memory feedback_bdd_strict_mode.md and issue #622.
check-bdd-strict:
	@FAILING=""; \
	for f in $$(grep -rln 'godog\.Options{' --include='*.go'); do \
		if ! grep -Eq '^[[:space:]]*Strict:[[:space:]]*true[[:space:]]*,' "$$f"; then \
			FAILING="$$FAILING $$f"; \
		fi; \
	done; \
	if [ -n "$$FAILING" ]; then \
		echo "ERROR (1/3): godog runners missing 'Strict: true' (undefined steps would silently pass):"; \
		for f in $$FAILING; do echo "  $$f"; done; \
		echo ""; \
		echo "Every godog.Options{} block MUST set 'Strict: true'. See #622."; \
		exit 1; \
	fi
	@EXPLICIT_FALSE=$$(grep -rnE 'Strict:[[:space:]]*false' --include='*.go' . 2>/dev/null || true); \
	if [ -n "$$EXPLICIT_FALSE" ]; then \
		echo "ERROR (2/3): explicit 'Strict: false' in Go source is forbidden. Found:"; \
		echo "$$EXPLICIT_FALSE"; \
		echo ""; \
		echo "BDD runners MUST fail on undefined steps. There is no legitimate"; \
		echo "reason to disable Strict. See #622 and memory feedback_bdd_strict_mode.md."; \
		exit 1; \
	fi
	@CLI_OVERRIDE=$$(grep -rnE '[-]{1,2}godog\.strict[= ]+false|[-]{1,2}godog-strict[= ]+false' --include='*.mk' --include='*.sh' --include='*.yml' --include='*.yaml' . 2>/dev/null || true); \
	if [ -n "$$CLI_OVERRIDE" ]; then \
		echo "ERROR (3/3): CLI-level godog strict override is forbidden. Found:"; \
		echo "$$CLI_OVERRIDE"; \
		echo ""; \
		echo "Makefile targets, scripts, and CI configs MUST NOT disable Strict"; \
		echo "via -godog.strict=false or similar flags. See #622."; \
		exit 1; \
	fi
	@echo "All godog runners use Strict mode (checks 1/3, 2/3, 3/3 passed)."

# Enforce that every file containing intentionally-duplicated logic
# carries a "// SYNC:" marker. Three pieces of logic are duplicated
# across published sub-modules because Go's internal/ package
# mechanism does not cross module boundaries — each output module is
# independently versioned and published, so cannot share unexported
# helpers with the others. See #542.
#
# Files in scope (12):
#   - dropLimiter (5 copies): droplimit.go and 4 sub-module copies.
#   - backoff/jitter (3 copies): syslog/reconnect.go,
#     webhook/http.go, loki/http.go.
#   - intPtrOrDefault (4 copies): file/, syslog/, webhook/, loki/
#     register.go.
#
# This target verifies marker PRESENCE only — it does NOT diff
# function bodies. Reviewers are expected to keep bodies in sync
# when any listed file changes; the SYNC marker is the trip-wire
# that prompts the cross-file diff during review.
check-sync-comments:
	@FAILING=""; \
	for f in droplimit.go \
	         file/droplimit.go webhook/droplimit.go \
	         syslog/droplimit.go loki/droplimit.go \
	         syslog/reconnect.go webhook/http.go loki/http.go \
	         file/register.go syslog/register.go \
	         webhook/register.go loki/register.go; do \
	  if ! grep -q '^// SYNC:' "$$f"; then \
	    FAILING="$$FAILING $$f"; \
	  fi; \
	done; \
	if [ -n "$$FAILING" ]; then \
	  echo "ERROR: file(s) missing required '// SYNC:' marker:"; \
	  for f in $$FAILING; do echo "  $$f"; done; \
	  echo ""; \
	  echo "Every file in the duplication-by-necessity list MUST carry a"; \
	  echo "'// SYNC:' comment listing its sibling copies. See #542 and"; \
	  echo "the existing SYNC comments in droplimit.go for the format."; \
	  exit 1; \
	fi
	@echo "All duplicated-logic files carry the required SYNC markers."

# --- Security ---

# security runs govulncheck serially over every module. Used by
# `make check` and by developers locally. CI fans this out across
# a GitHub Actions matrix for ~10x wall-time reduction (#522);
# see `security-one` below for the per-module target the matrix
# invokes.
security:
	@for mod in $(MODULES); do \
		echo "=== security $$mod ==="; \
		(cd $$mod && $(GOBIN)/govulncheck ./...) || exit 1; \
	done

# security-one runs govulncheck for a single module. Invoked from
# CI's matrix-parallelised Security Scan job (#522, master tracker
# D-15). Not intended for local use — `make security` covers the
# serial local workflow.
#
# Usage: make security-one MOD=<module-path>
#   e.g. make security-one MOD=.
#        make security-one MOD=secrets/vault
security-one:
	@if [ -z "$(MOD)" ]; then \
		echo "security-one: MOD is required (e.g. make security-one MOD=.)"; \
		exit 2; \
	fi
	@if [ ! -d "$(MOD)" ]; then \
		echo "security-one: MOD=$(MOD) does not exist"; \
		exit 2; \
	fi
	@echo "=== security $(MOD) ==="
	@cd $(MOD) && $(GOBIN)/govulncheck ./...

# --- Release ---

# release-check composes:
#   1. goreleaser config syntax check (.goreleaser.yml)
#   2. api-check — gorelease per published module against the
#      module's most recent SemVer-sorted tag. Advisory pre-v1.0
#      (inputs.api_check_blocking in release.yml controls the gate).
# Both run in `make check` via the composite target.
release-check: api-check
	$(GOBIN)/goreleaser check

# release-snapshot runs a local goreleaser snapshot dry-run that
# validates the entire release pipeline EXCEPT the `signs:` block
# and the GitHub publish step. Snapshot mode skips signing by
# design (cosign keyless requires real GHA OIDC; offline emulation
# is not supported). Maintainers SHOULD run this before tagging a
# release to catch build/archive/checksum errors locally; signing
# itself is verified at release time when `release.yml` runs the
# real GoReleaser invocation against the tag.
#
# The `signs:` YAML structure is independently validated by
# `goreleaser check` (already wired into `make release-check`).
release-snapshot:
	rm -rf dist
	$(GOBIN)/goreleaser release --snapshot --skip=publish --skip=sign --clean

# api-check runs gorelease for every published module, comparing
# the module's current public surface against its most recent
# release tag. gorelease exits non-zero on incompatible changes;
# the Makefile collects per-module failures and reports them all
# rather than aborting on the first.
#
# First-release case: a module with no prior tag is skipped (not a
# failure — gorelease has no base to compare against).
#
# GOFLAGS=-mod=readonly prevents api-check from mutating go.sum.
#
# Pipe-character note: PUBLISH_MODULES entries are pipe-delimited
# `dir|module|prefix`. We use $(foreach) + single-quoting so bash
# sees each entry as one quoted argument; an unquoted shell `for`
# would parse the pipes as control operators.
.PHONY: api-check
api-check:
	@if ! git diff --quiet HEAD -- 2>/dev/null || ! git diff --cached --quiet HEAD -- 2>/dev/null; then \
	  echo "api-check: working tree has uncommitted changes — skipping (gorelease requires a clean tree)."; \
	  echo "          run 'make api-check' on a clean checkout, or it will run automatically in CI."; \
	  exit 0; \
	fi; \
	FAILED=""; \
	for entry in $(foreach e,$(PUBLISH_MODULES),'$(e)'); do \
	  dir=$$(echo "$$entry" | cut -d'|' -f1); \
	  prefix=$$(echo "$$entry" | cut -d'|' -f3); \
	  base=$$(git tag --list "$${prefix}v[0-9]*" --sort=-version:refname | head -n1); \
	  if [ -z "$$base" ]; then \
	    echo "==> api-check $$dir (base=<none — skipping>)"; \
	    continue; \
	  fi; \
	  bare="$${base#$$prefix}"; \
	  echo "==> api-check $$dir (base=$$base, bare=$$bare)"; \
	  (cd "$$dir" && GOFLAGS=-mod=readonly $(GOBIN)/gorelease -base "$$bare" 2>&1) \
	    || FAILED="$$FAILED $$dir"; \
	done; \
	if [ -n "$$FAILED" ]; then \
	  echo ""; \
	  echo "api-check found incompatible changes in:$$FAILED"; \
	  echo "Advisory pre-v1.0; release.yml inputs.api_check_blocking controls blocking."; \
	  exit 1; \
	fi

# check-release-invariants verifies, for a given VERSION, that
# every go.mod across every published module references that
# exact version for every cross-reference to ANOTHER PUBLISHED
# module. Cross-references to unpublished local modules (e.g.
# iouring, secrets/env, secrets/file) are NOT checked — those
# are private modules used via pseudo-versions and are not
# subject to release tagging. Run post-release as a final sanity
# gate; CI invokes it from the invariants job in release.yml.
#
# Usage: make check-release-invariants VERSION=v0.1.12
.PHONY: check-release-invariants
check-release-invariants:
ifndef VERSION
	$(error VERSION is required, e.g. make check-release-invariants VERSION=v0.1.12)
endif
	@PUBLISHED=" $(foreach e,$(PUBLISH_MODULES),$(word 2,$(subst |, ,$(e)))) "; \
	FAILED=""; \
	for entry in $(foreach e,$(PUBLISH_MODULES),'$(e)'); do \
	  dir=$$(echo "$$entry" | cut -d'|' -f1); \
	  while read -r name ver; do \
	    case "$$PUBLISHED" in *" $$name "*) ;; *) continue;; esac; \
	    if [ "$$ver" != "$(VERSION)" ]; then \
	      echo "FAIL $$dir/go.mod: $$name @ $$ver (expected $(VERSION))"; \
	      FAILED="1"; \
	    fi; \
	  done < <(awk '/^require[[:space:]]/{print $$2, $$3} /^[[:space:]]+github\.com\/axonops\/audit/{print $$1, $$2}' "$$dir/go.mod" | grep -v '//' || true); \
	done; \
	if [ -n "$$FAILED" ]; then \
	  echo ""; \
	  echo "Release invariants failed — see above."; \
	  exit 1; \
	fi; \
	echo "All published go.mod files reference $(VERSION) for axonops/audit deps."

# print-publish-modules emits PUBLISH_MODULES one entry per line
# for shell-script consumption (scripts/release/*.sh). Format
# unchanged from the variable: dir|module_path|tag_prefix.
.PHONY: print-publish-modules
print-publish-modules:
	@$(foreach e,$(PUBLISH_MODULES),printf '%s\n' '$(e)';)

# regen-release-docs rewrites the auto-generated module table in
# docs/releasing.md from the canonical PUBLISH_MODULES list. Run
# this whenever a module is added to or removed from PUBLISH_MODULES.
.PHONY: regen-release-docs
regen-release-docs:
	@bash scripts/release/regen-docs.sh docs/releasing.md

# regen-release-docs-check verifies docs/releasing.md is in sync
# with PUBLISH_MODULES — runs the regenerator into a temp file
# and diffs against the live file. Wired into check-static so a
# stale module table fails CI.
.PHONY: regen-release-docs-check
regen-release-docs-check:
	@bash scripts/release/regen-docs.sh --check docs/releasing.md

# regen-schema-artifacts rewrites the framework-only language-neutral
# schema artifacts shipped with every release (#548). The artifacts
# are committed under deploy/schemas/ so consumers can fetch them
# from a release tag without running audit-gen themselves. Run this
# whenever the framework field set, reserved standard fields, or
# CEF mapping changes — and add the regenerated files to the same
# commit so the check target stays clean.
.PHONY: regen-schema-artifacts
regen-schema-artifacts:
	@mkdir -p deploy/schemas
	@go run ./cmd/audit-gen -format json-schema \
		-input internal/schemagen/framework_only_taxonomy.yaml \
		-output deploy/schemas/audit-event.framework.schema.json
	@go run ./cmd/audit-gen -format cef-template \
		-input internal/schemagen/framework_only_taxonomy.yaml \
		-output deploy/schemas/audit-event.framework.cef.template
	@echo "regenerated deploy/schemas/audit-event.framework.{schema.json,cef.template}"

# regen-schema-artifacts-check verifies deploy/schemas/* are in sync
# with the framework-only taxonomy and the current library state.
# Wired into check-static so stale artifacts fail CI.
.PHONY: regen-schema-artifacts-check
regen-schema-artifacts-check:
	@TMP=$$(mktemp -d); \
	go run ./cmd/audit-gen -format json-schema \
		-input internal/schemagen/framework_only_taxonomy.yaml \
		-output "$$TMP/audit-event.framework.schema.json" >/dev/null && \
	go run ./cmd/audit-gen -format cef-template \
		-input internal/schemagen/framework_only_taxonomy.yaml \
		-output "$$TMP/audit-event.framework.cef.template" >/dev/null && \
	if ! diff -q "$$TMP/audit-event.framework.schema.json" deploy/schemas/audit-event.framework.schema.json >/dev/null; then \
		echo "deploy/schemas/audit-event.framework.schema.json is stale; run 'make regen-schema-artifacts'"; \
		diff -u deploy/schemas/audit-event.framework.schema.json "$$TMP/audit-event.framework.schema.json" || true; \
		rm -rf "$$TMP"; exit 1; \
	fi; \
	if ! diff -q "$$TMP/audit-event.framework.cef.template" deploy/schemas/audit-event.framework.cef.template >/dev/null; then \
		echo "deploy/schemas/audit-event.framework.cef.template is stale; run 'make regen-schema-artifacts'"; \
		diff -u deploy/schemas/audit-event.framework.cef.template "$$TMP/audit-event.framework.cef.template" || true; \
		rm -rf "$$TMP"; exit 1; \
	fi; \
	rm -rf "$$TMP"

# Aggregate every static-analysis guard the CI hygiene job runs,
# in a single shell loop with `||`-guarded error collection so
# operators see every static failure on a single push (rather
# than aborting on the first). Mirrors the CI hygiene job's
# behaviour 1:1: the same checks, the same exit semantics.
check-static:
	@FAILED=""; \
	for target in fmt-check tidy-check check-todos check-replace \
	              check-insecure-skip-verify check-example-links \
	              check-bdd-strict check-sync-comments bench-baseline-check \
	              check-license-headers check-release-scripts \
	              check-skip-tidy-check-scope \
	              regen-release-docs-check regen-schema-artifacts-check; do \
	  echo "==> make $$target"; \
	  $(MAKE) "$$target" || FAILED="$$FAILED $$target"; \
	done; \
	if [ -n "$$FAILED" ]; then \
	  echo ""; \
	  echo "FAILED:$$FAILED"; \
	  exit 1; \
	fi; \
	echo ""; \
	echo "All static-analysis checks passed."

# Parse-check every release script with `bash -n` (#841). Catches
# syntax errors that would only surface at release time — the
# scripts run on a privileged App token and a broken script
# stalls the release flow.
check-release-scripts:
	@echo "==> check-release-scripts"
	@for f in scripts/release/*.sh; do \
	  bash -n "$$f" || { echo "PARSE ERROR in $$f" >&2; exit 1; }; \
	done
	@echo "OK: all scripts/release/*.sh parse cleanly"

# Guard the SKIP_TIDY_CHECK invariant (#841 docs/releasing.md): the
# variable is only honoured by the hygiene step in ci.yml when the
# branch matches `release/*`. If a future change introduces
# SKIP_TIDY_CHECK in any other context (a different workflow, a
# Makefile target, a script), the guard fires.
check-skip-tidy-check-scope:
	@echo "==> check-skip-tidy-check-scope"
	@MISUSE=$$(grep -rEl 'SKIP_TIDY_CHECK' \
	    --include='*.yml' --include='*.yaml' --include='*.sh' \
	    --include='Makefile' --include='*.go' --include='*.md' \
	    . 2>/dev/null \
	    | grep -v -E '^\./\.github/workflows/ci\.yml$$' \
	    | grep -v -E '^\./Makefile$$' \
	    | grep -v -E '^\./docs/releasing\.md$$' \
	    | grep -v -E '^\./docs/development-workflow\.md$$' \
	    || true); \
	if [ -n "$$MISUSE" ]; then \
	  echo "ERROR: SKIP_TIDY_CHECK referenced outside ci.yml / Makefile / docs:" >&2; \
	  echo "$$MISUSE" >&2; \
	  exit 1; \
	fi; \
	echo "OK: SKIP_TIDY_CHECK scope is contained to ci.yml"

# Install only govulncheck — used by the security matrix to
# avoid re-installing the full tool set 13 times across the
# per-module shards. Independent target so it can be invoked
# without dragging in golangci-lint, goimports, goreleaser,
# or benchstat.
install-govulncheck:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VER)

# --- Full local quality gate ---

check: vet-all lint-all test-all build-all test-examples verify check-static check-report-parity release-check security
	@echo ""
	@echo "All checks passed."

# --- Clean ---

clean:
	go clean -testcache
	@for mod in $(MODULES); do \
		rm -f $$mod/coverage.out $$mod/coverage.html; \
	done
	rm -f bench.txt

# --- SBOM generation ---

SBOM_DIR := sbom

sbom:
	@mkdir -p $(SBOM_DIR)
	@echo "=== Generating CycloneDX SBOM (all modules) ==="
	@syft dir:. --output cyclonedx-json --file $(SBOM_DIR)/audit_sbom.cdx.json
	@echo "=== Generating SPDX SBOM (all modules) ==="
	@syft dir:. --output spdx-json --file $(SBOM_DIR)/audit_sbom.spdx.json
	@echo "SBOMs generated in $(SBOM_DIR)/"

sbom-validate:
	@echo "=== Validating CycloneDX SBOM ==="
	@python3 -c "import json; json.load(open('$(SBOM_DIR)/audit_sbom.cdx.json')); print('CycloneDX: valid JSON')"
	@echo "=== Validating SPDX SBOM ==="
	@python3 -c "import json; json.load(open('$(SBOM_DIR)/audit_sbom.spdx.json')); print('SPDX: valid JSON')"

# --- Certificate generation ---

generate-certs:
	scripts/generate-test-certs.sh

# --- Test infrastructure (Docker) ---

COMPOSE_DIR := tests/bdd

test-infra-up:
	docker network create audit-test 2>/dev/null || true
	docker compose -f $(COMPOSE_DIR)/docker-compose.full.yml up -d --build --wait
	@echo "Test infrastructure is ready."

test-infra-down:
	docker compose -f $(COMPOSE_DIR)/docker-compose.full.yml down -v
	docker network rm audit-test 2>/dev/null || true

test-infra-logs:
	docker compose -f $(COMPOSE_DIR)/docker-compose.full.yml logs

# Per-service infrastructure targets for parallel CI runners.
# Each creates the shared network, starts only what it needs, and tears down cleanly.

test-infra-syslog-up:
	docker network create audit-test 2>/dev/null || true
	docker compose -f $(COMPOSE_DIR)/docker-compose.syslog.yml up -d --build --wait
	@echo "Syslog infrastructure is ready."

test-infra-syslog-down:
	docker compose -f $(COMPOSE_DIR)/docker-compose.syslog.yml down -v
	docker network rm audit-test 2>/dev/null || true

# File-output OS-failure-mode harness (#748). The container idles
# with a size-limited tmpfs at /audit-test-tmpfs. The
# test-bdd-file-os target shells the file-enospc-runner inside the
# container via `docker compose exec` to drive ENOSPC reproduction.
test-infra-file-os-up: workspace
	docker compose -f $(COMPOSE_DIR)/docker-compose.file-os.yml up -d --wait
	@echo "File-output OS-failure-mode infrastructure is ready."

test-infra-file-os-down:
	docker compose -f $(COMPOSE_DIR)/docker-compose.file-os.yml down -v

test-infra-webhook-up:
	docker network create audit-test 2>/dev/null || true
	docker compose -f $(COMPOSE_DIR)/docker-compose.webhook.yml up -d --build --wait
	@echo "Webhook infrastructure is ready."

test-infra-webhook-down:
	docker compose -f $(COMPOSE_DIR)/docker-compose.webhook.yml down -v
	docker network rm audit-test 2>/dev/null || true

test-infra-loki-up:
	docker network create audit-test 2>/dev/null || true
	docker compose -f $(COMPOSE_DIR)/docker-compose.loki.yml up -d --build --wait
	@echo "Loki infrastructure is ready."

test-infra-loki-down:
	docker compose -f $(COMPOSE_DIR)/docker-compose.loki.yml down -v
	docker network rm audit-test 2>/dev/null || true

test-infra-openbao-up:
	docker network create audit-test 2>/dev/null || true
	docker compose -f $(COMPOSE_DIR)/docker-compose.openbao.yml up -d --wait
	@echo "OpenBao infrastructure is ready."

test-infra-openbao-down:
	docker compose -f $(COMPOSE_DIR)/docker-compose.openbao.yml down -v
	docker network rm audit-test 2>/dev/null || true

test-infra-vault-up:
	docker network create audit-test 2>/dev/null || true
	docker compose -f $(COMPOSE_DIR)/docker-compose.vault.yml up -d --wait
	@echo "Vault infrastructure is ready."

test-infra-vault-down:
	docker compose -f $(COMPOSE_DIR)/docker-compose.vault.yml down -v
	docker network rm audit-test 2>/dev/null || true

# --- Publish verification (issue #29) ---

# Module definitions for publish targets: directory|module_path|tag_prefix
PUBLISH_MODULES := \
  .|github.com/axonops/audit| \
  file|github.com/axonops/audit/file|file/ \
  syslog|github.com/axonops/audit/syslog|syslog/ \
  webhook|github.com/axonops/audit/webhook|webhook/ \
  loki|github.com/axonops/audit/loki|loki/ \
  outputconfig|github.com/axonops/audit/outputconfig|outputconfig/ \
  outputs|github.com/axonops/audit/outputs|outputs/ \
  cmd/audit-gen|github.com/axonops/audit/cmd/audit-gen|cmd/audit-gen/ \
  cmd/audit-validate|github.com/axonops/audit/cmd/audit-validate|cmd/audit-validate/ \
  secrets|github.com/axonops/audit/secrets|secrets/ \
  secrets/env|github.com/axonops/audit/secrets/env|secrets/env/ \
  secrets/file|github.com/axonops/audit/secrets/file|secrets/file/ \
  secrets/openbao|github.com/axonops/audit/secrets/openbao|secrets/openbao/ \
  secrets/vault|github.com/axonops/audit/secrets/vault|secrets/vault/

.PHONY: publish-trigger publish-verify publish-smoke

publish-trigger: ## Trigger proxy.golang.org indexing for VERSION (e.g. make publish-trigger VERSION=v0.1.1)
ifndef VERSION
	$(error VERSION is required, e.g. make publish-trigger VERSION=v0.1.1)
endif
	@for entry in $(foreach e,$(PUBLISH_MODULES),'$(e)'); do \
		mod=$$(echo "$$entry" | cut -d'|' -f2); \
		echo "Indexing $$mod@$(VERSION) ..."; \
		GOPROXY=https://proxy.golang.org go list -m "$$mod@$(VERSION)"; \
		echo "  ✓ $$mod@$(VERSION)"; \
	done

publish-verify: ## Verify modules on proxy.golang.org and pkg.go.dev for VERSION
ifndef VERSION
	$(error VERSION is required, e.g. make publish-verify VERSION=v0.1.1)
endif
	@for entry in $(foreach e,$(PUBLISH_MODULES),'$(e)'); do \
		mod=$$(echo "$$entry" | cut -d'|' -f2); \
		proxy_path=$$(echo "$$mod" | tr '[:upper:]' '[:lower:]'); \
		echo "Verifying $$mod@$(VERSION) ..."; \
		curl -sS --fail "https://proxy.golang.org/$${proxy_path}/@v/$(VERSION).info" > /dev/null || \
			{ echo "  ✗ proxy.golang.org FAILED for $$mod"; exit 1; }; \
		echo "  ✓ proxy.golang.org"; \
		status=$$(curl -sS -o /dev/null -w "%{http_code}" "https://pkg.go.dev/$${mod}@$(VERSION)"); \
		if [ "$$status" = "200" ]; then echo "  ✓ pkg.go.dev"; else echo "  ⚠ pkg.go.dev HTTP $$status (may still be indexing)"; fi; \
	done

publish-smoke: ## Smoke test: go get + compile all modules for VERSION
ifndef VERSION
	$(error VERSION is required, e.g. make publish-smoke VERSION=v0.1.1)
endif
	@dir=$$(mktemp -d) && \
	trap 'rm -rf "$$dir"' EXIT && \
	cd "$$dir" && \
	go mod init smoketest && \
	echo "Installing modules ..." && \
	go get "github.com/axonops/audit@$(VERSION)" && \
	go get "github.com/axonops/audit/file@$(VERSION)" && \
	go get "github.com/axonops/audit/syslog@$(VERSION)" && \
	go get "github.com/axonops/audit/webhook@$(VERSION)" && \
	go get "github.com/axonops/audit/loki@$(VERSION)" && \
	go get "github.com/axonops/audit/outputconfig@$(VERSION)" && \
	go get "github.com/axonops/audit/outputs@$(VERSION)" && \
	go get "github.com/axonops/audit/cmd/audit-gen@$(VERSION)" && \
	go get "github.com/axonops/audit/secrets@$(VERSION)" && \
	go get "github.com/axonops/audit/secrets/openbao@$(VERSION)" && \
	go get "github.com/axonops/audit/secrets/vault@$(VERSION)" && \
	printf 'package main\n\nimport (\n\t_ "github.com/axonops/audit"\n\t_ "github.com/axonops/audit/file"\n\t_ "github.com/axonops/audit/syslog"\n\t_ "github.com/axonops/audit/webhook"\n\t_ "github.com/axonops/audit/loki"\n\t_ "github.com/axonops/audit/outputconfig"\n\t_ "github.com/axonops/audit/outputs"\n\t_ "github.com/axonops/audit/secrets"\n\t_ "github.com/axonops/audit/secrets/openbao"\n\t_ "github.com/axonops/audit/secrets/vault"\n)\n\nfunc main() {}\n' > main.go && \
	go build -o /dev/null . && \
	go install "github.com/axonops/audit/cmd/audit-gen@$(VERSION)" && \
	echo "✓ All modules compile successfully"
