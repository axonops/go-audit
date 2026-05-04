#!/usr/bin/env bash
# Copyright 2026 AxonOps Limited.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# verify-bdd-coverage.sh — Verify every BDD scenario is covered by at least
# one CI matrix runner.
#
# This script statically analyses feature files and evaluates each scenario
# against the tag expressions used by the CI BDD matrix runners. If any
# scenario is not matched by at least one runner, the script exits with
# code 1 and reports the orphaned scenarios.
#
# This is a quality gate: it runs in CI after all BDD matrix entries
# complete, and also locally via `make test-bdd-verify`.
#
# Usage:
#   ./scripts/verify-bdd-coverage.sh
#
# Exit codes:
#   0 — all scenarios covered
#   1 — orphaned scenarios found or parse error

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# --- Runner definitions ---
# Each runner has a name and a tag expression (using godog syntax).
# These MUST match the BDD_TAGS in the Makefile exactly.
#
# Godog tag expression syntax:
#   @tag           — scenario has tag
#   ~@tag          — scenario does NOT have tag (alias for "not")
#   &&             — AND
#   ,              — OR
#   "not", "and", "or" — also supported as keywords
#
# Format: "name|tag_expression"
MAIN_RUNNERS=(
    "core|@core && ~@docker"
    "file|@file && ~@docker"
    "file-os|@file && @docker"
    "syslog|@syslog"
    "webhook|@webhook, @routing"
    "loki|@loki && ~@fanout"
    "fanout|@fanout"
)

# The outputconfig suite runs all scenarios (no tag filter) in its own module.
# We only need to verify the main suite's tag coverage.
MAIN_FEATURES_DIR="$REPO_ROOT/tests/bdd/features"
OUTPUTCONFIG_FEATURES_DIR="$REPO_ROOT/outputconfig/tests/bdd/features"
MAKEFILE="$REPO_ROOT/Makefile"

# --- Cross-check: verify runner definitions match Makefile BDD_TAGS ---
# This catches the case where someone updates BDD_TAGS in the Makefile
# but forgets to update this script (or vice versa).
verify_runner_definitions() {
    local mismatch=0

    # Extract BDD_TAGS from Makefile (lines matching BDD_TAGS=... go test).
    # Format in Makefile: BDD_TAGS="expr" go test ... or BDD_TAGS=expr go test ...
    while IFS= read -r line; do
        # Extract the tag expression value.
        local tag_expr
        if [[ "$line" =~ BDD_TAGS=\"([^\"]+)\" ]]; then
            tag_expr="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ BDD_TAGS=([^[:space:]]+) ]]; then
            tag_expr="${BASH_REMATCH[1]}"
        else
            continue
        fi

        # Check this expression exists in our runner definitions.
        local found=false
        for runner_def in "${MAIN_RUNNERS[@]}"; do
            local runner_expr="${runner_def#*|}"
            if [ "$runner_expr" = "$tag_expr" ]; then
                found=true
                break
            fi
        done

        if [ "$found" = false ]; then
            echo "ERROR: Makefile BDD_TAGS=\"$tag_expr\" not found in verify-bdd-coverage.sh runner definitions" >&2
            mismatch=1
        fi
    done < <(grep 'BDD_TAGS=' "$MAKEFILE")

    # Also verify all script runner expressions exist in Makefile.
    for runner_def in "${MAIN_RUNNERS[@]}"; do
        local runner_name="${runner_def%%|*}"
        local runner_expr="${runner_def#*|}"
        if ! grep -qF "BDD_TAGS=\"$runner_expr\"" "$MAKEFILE" && ! grep -qF "BDD_TAGS=$runner_expr " "$MAKEFILE"; then
            echo "ERROR: Runner '$runner_name' expression \"$runner_expr\" not found in Makefile BDD_TAGS" >&2
            mismatch=1
        fi
    done

    return $mismatch
}

if ! verify_runner_definitions; then
    echo "" >&2
    echo "Runner definitions in this script are out of sync with the Makefile." >&2
    echo "Update MAIN_RUNNERS in scripts/verify-bdd-coverage.sh to match Makefile BDD_TAGS." >&2
    exit 1
fi

errors=0
orphaned_scenarios=()

# --- Tag expression evaluator ---
# Evaluates a godog tag expression against a set of tags.
# Returns 0 (true) if the expression matches, 1 (false) otherwise.
#
# Supports: @tag, ~@tag, &&, "," (OR), and, or, not
# Does NOT support parentheses (not used in our expressions).
evaluate_tags() {
    local expression="$1"
    shift
    local -a tags=("$@")

    # Empty expression matches everything.
    if [ -z "$expression" ]; then
        return 0
    fi

    # Check for comma-separated OR expressions first.
    # Godog treats commas as OR at the top level.
    if [[ "$expression" == *","* ]]; then
        IFS=',' read -ra or_parts <<< "$expression"
        for part in "${or_parts[@]}"; do
            part="$(echo "$part" | xargs)" # trim whitespace
            if evaluate_tags "$part" "${tags[@]}"; then
                return 0
            fi
        done
        return 1
    fi

    # Check for && (AND) expressions.
    if [[ "$expression" == *"&&"* ]]; then
        # Split on && — need to handle carefully.
        local remaining="$expression"
        while [[ "$remaining" == *"&&"* ]]; do
            local left="${remaining%%&&*}"
            remaining="${remaining#*&&}"
            left="$(echo "$left" | xargs)" # trim
            if ! evaluate_tags "$left" "${tags[@]}"; then
                return 1
            fi
        done
        remaining="$(echo "$remaining" | xargs)" # trim
        if ! evaluate_tags "$remaining" "${tags[@]}"; then
            return 1
        fi
        return 0
    fi

    # Single tag: @tag or ~@tag
    local expr
    expr="$(echo "$expression" | xargs)" # trim

    if [[ "$expr" == "~@"* ]]; then
        # Negation: ~@tag means NOT having this tag.
        local tag="${expr#\~}"
        for t in "${tags[@]}"; do
            if [ "$t" = "$tag" ]; then
                return 1 # has the tag, so negation fails
            fi
        done
        return 0
    elif [[ "$expr" == "@"* ]]; then
        # Positive: @tag means having this tag.
        for t in "${tags[@]}"; do
            if [ "$t" = "$expr" ]; then
                return 0
            fi
        done
        return 1
    else
        echo "ERROR: cannot parse tag expression element: '$expr'" >&2
        return 1
    fi
}

# --- Feature file parser ---
# Extracts scenarios with their effective tags (feature-level + scenario-level).
# Handles Scenario Outline expansion.
#
# Output format: one line per executable scenario:
#   file:line scenario_name tag1 tag2 ...
parse_feature_file() {
    local file="$1"
    local feature_tags=()
    local pending_scenario_tags=()
    local state="NONE"
    local outline_name=""
    local outline_tags=()
    local line_num=0
    local outline_line=0
    local outline_examples_data=()

    flush_outline() {
        # For each data row in the outline, emit a scenario entry.
        for row_idx in "${!outline_examples_data[@]}"; do
            echo "$file:$outline_line $outline_name (row $((row_idx + 1))) ${outline_tags[*]}"
        done
        outline_examples_data=()
    }

    while IFS= read -r line; do
        line_num=$((line_num + 1))
        local trimmed="${line#"${line%%[![:space:]]*}"}"

        # Skip empty lines and comments.
        [ -z "$trimmed" ] && continue
        [[ "$trimmed" == \#* ]] && continue

        # Tag lines: collect tags for the next element.
        if [[ "$trimmed" == @* ]]; then
            # Extract all @word tokens from the line.
            local tag_line_tags=()
            for word in $trimmed; do
                if [[ "$word" == @* ]]; then
                    tag_line_tags+=("$word")
                fi
            done

            if [ "$state" = "NONE" ] && [ ${#feature_tags[@]} -eq 0 ]; then
                # Could be feature-level or scenario-level.
                # We don't know yet — accumulate in pending.
                pending_scenario_tags+=("${tag_line_tags[@]}")
            else
                pending_scenario_tags+=("${tag_line_tags[@]}")
            fi
            continue
        fi

        if [[ "$trimmed" == "Feature:"* ]]; then
            # The pending tags are feature-level tags.
            feature_tags=("${pending_scenario_tags[@]}")
            pending_scenario_tags=()
            continue
        fi

        if [[ "$trimmed" == "Background:"* ]]; then
            pending_scenario_tags=()
            continue
        fi

        if [[ "$trimmed" == "Scenario:"* ]]; then
            # Flush any pending outline.
            if [ "$state" = "IN_EXAMPLES_DATA" ] || [ "$state" = "IN_OUTLINE" ]; then
                flush_outline
            fi

            local name="${trimmed#Scenario: }"
            local all_tags=("${feature_tags[@]}" "${pending_scenario_tags[@]}")
            echo "$file:$line_num $name ${all_tags[*]}"
            pending_scenario_tags=()
            state="NONE"
            continue
        fi

        if [[ "$trimmed" == "Scenario Outline:"* ]]; then
            # Flush any pending outline.
            if [ "$state" = "IN_EXAMPLES_DATA" ] || [ "$state" = "IN_OUTLINE" ]; then
                flush_outline
            fi

            outline_name="${trimmed#Scenario Outline: }"
            outline_tags=("${feature_tags[@]}" "${pending_scenario_tags[@]}")
            outline_line=$line_num
            outline_examples_data=()
            pending_scenario_tags=()
            state="IN_OUTLINE"
            continue
        fi

        if [[ "$trimmed" == "Examples:"* ]]; then
            state="IN_EXAMPLES_HEADER"
            continue
        fi

        case "$state" in
            IN_EXAMPLES_HEADER)
                if [[ "$trimmed" == "|"* ]]; then
                    state="IN_EXAMPLES_DATA"
                fi
                ;;
            IN_EXAMPLES_DATA)
                if [[ "$trimmed" == "|"* ]]; then
                    outline_examples_data+=("row")
                else
                    # End of table data — could be more Examples or end of Outline.
                    state="IN_OUTLINE"
                fi
                ;;
        esac
    done < "$file"

    # Flush at end of file.
    if [ "$state" = "IN_EXAMPLES_DATA" ] || [ "$state" = "IN_OUTLINE" ]; then
        flush_outline
    fi
}

# --- Main verification ---

echo "BDD Scenario Coverage Verification"
echo "==================================="
echo ""

# Parse all main suite feature files.
total_scenarios=0
covered_scenarios=0

while IFS= read -r scenario_line; do
    [ -z "$scenario_line" ] && continue
    total_scenarios=$((total_scenarios + 1))

    # Extract file:line, name, and tags.
    local_file_line="${scenario_line%% *}"
    local_rest="${scenario_line#* }"

    # Extract tags (all @-prefixed words).
    local_tags=()
    for word in $local_rest; do
        if [[ "$word" == @* ]]; then
            local_tags+=("$word")
        fi
    done

    # Check if at least one runner matches this scenario's tags.
    matched=false
    for runner_def in "${MAIN_RUNNERS[@]}"; do
        runner_name="${runner_def%%|*}"
        runner_expr="${runner_def#*|}"

        if evaluate_tags "$runner_expr" "${local_tags[@]}"; then
            matched=true
            break
        fi
    done

    if [ "$matched" = false ]; then
        errors=$((errors + 1))
        # Extract a readable name (everything that's not a tag).
        readable_name=""
        for word in $local_rest; do
            if [[ "$word" != @* ]] && [[ "$word" != "(row" ]] && [[ "$word" != *")" ]]; then
                readable_name="$readable_name $word"
            fi
        done
        readable_name="$(echo "$readable_name" | xargs)"
        orphaned_scenarios+=("$local_file_line: $readable_name [tags: ${local_tags[*]:-none}]")
    else
        covered_scenarios=$((covered_scenarios + 1))
    fi
done < <(for f in "$MAIN_FEATURES_DIR"/*.feature; do parse_feature_file "$f"; done)

# Outputconfig suite: all scenarios run without tag filter, so they are always covered.
outputconfig_count=0
if [ -d "$OUTPUTCONFIG_FEATURES_DIR" ]; then
    outputconfig_count=$("$SCRIPT_DIR/count-bdd-scenarios.sh" "$OUTPUTCONFIG_FEATURES_DIR")
fi

echo "Main suite scenarios:        $total_scenarios"
echo "Main suite covered:          $covered_scenarios"
echo "Main suite orphaned:         $errors"
echo "Outputconfig suite:          $outputconfig_count (always covered — no tag filter)"
echo "Total scenarios:             $((total_scenarios + outputconfig_count))"
echo ""

# Print runner coverage breakdown.
echo "Runner coverage breakdown:"
for runner_def in "${MAIN_RUNNERS[@]}"; do
    runner_name="${runner_def%%|*}"
    runner_expr="${runner_def#*|}"
    runner_count=0

    while IFS= read -r scenario_line; do
        [ -z "$scenario_line" ] && continue
        local_tags=()
        for word in $scenario_line; do
            if [[ "$word" == @* ]]; then
                local_tags+=("$word")
            fi
        done
        if evaluate_tags "$runner_expr" "${local_tags[@]}"; then
            runner_count=$((runner_count + 1))
        fi
    done < <(for f in "$MAIN_FEATURES_DIR"/*.feature; do parse_feature_file "$f"; done)

    printf "  %-12s %-30s %d scenarios\n" "$runner_name" "($runner_expr)" "$runner_count"
done
printf "  %-12s %-30s %d scenarios\n" "outputconfig" "(no filter)" "$outputconfig_count"
echo ""

if [ $errors -gt 0 ]; then
    echo "FAIL: $errors scenario(s) not covered by any runner:"
    for orphan in "${orphaned_scenarios[@]}"; do
        echo "  - $orphan"
    done
    echo ""
    echo "Fix: add an appropriate tag (@core, @file, @syslog, @webhook, @routing, @loki, @fanout)"
    echo "to the feature or scenario, ensuring it matches at least one CI runner's tag expression."
    exit 1
fi

echo "PASS: all $((total_scenarios + outputconfig_count)) scenarios covered."
exit 0
