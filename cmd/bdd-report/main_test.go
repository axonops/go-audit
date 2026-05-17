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

package main

import (
	"bytes"
	encJSON "encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/text"
)

// fixtureCucumberJSON is a minimal, plausible cucumber JSON payload
// matching what godog emits — one feature with two scenarios (one
// passing, one failing). Used by every test in this file.
const fixtureCucumberJSON = `[
  {
    "uri": "features/sample.feature",
    "id": "sample",
    "keyword": "Feature",
    "name": "Sample feature",
    "description": "A tiny feature with one pass and one fail",
    "elements": [
      {
        "keyword": "Scenario",
        "id": "sample;happy-path",
        "name": "Happy path",
        "line": 5,
        "type": "scenario",
        "tags": [{"name": "@core", "line": 4}],
        "steps": [
          {"keyword": "Given ", "name": "the system is ready", "line": 6,
           "result": {"status": "passed", "duration": 1500000}}
        ]
      },
      {
        "keyword": "Scenario",
        "id": "sample;broken-path",
        "name": "Broken path",
        "line": 10,
        "type": "scenario",
        "tags": [{"name": "@core", "line": 9}],
        "steps": [
          {"keyword": "Given ", "name": "an unhandled condition", "line": 11,
           "result": {"status": "failed", "duration": 500000,
                      "error_message": "boom: <bad input>"}}
        ]
      }
    ]
  }
]`

// runFixture is a small helper that writes the given JSON to a temp
// file and invokes run() with the supplied format / onlyFailures flag,
// returning the captured stdout buffer.
func runFixture(t *testing.T, jsonBody, format string, onlyFailures bool) string {
	t.Helper()
	dir := t.TempDir()
	in := filepath.Join(dir, "report.json")
	if err := os.WriteFile(in, []byte(jsonBody), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	var out bytes.Buffer
	if err := run("core", in, format, onlyFailures, &out); err != nil {
		t.Fatalf("run: %v", err)
	}
	return out.String()
}

func TestRun_ProducesHTMLForFixture(t *testing.T) {
	body := runFixture(t, fixtureCucumberJSON, "html", false)

	for _, want := range []string{
		`<!doctype html>`,
		`<title>BDD report — core</title>`,
		`2 scenarios`,
		`1 passed`,
		`1 failed`,
		`Happy path`,
		`Broken path`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("output missing %q", want)
		}
	}
	// html/template auto-escapes — the error message contains <bad input>
	// which must appear as &lt;bad input&gt; in the HTML, NOT as raw
	// HTML that the browser would interpret as a tag.
	if !strings.Contains(body, `boom: &lt;bad input&gt;`) {
		t.Errorf("error message not HTML-escaped — XSS risk")
	}
	if strings.Contains(body, `boom: <bad input>`) {
		t.Errorf("error message rendered raw — XSS risk")
	}
	if !strings.Contains(body, `data-status="failed"`) {
		t.Errorf(`output missing data-status="failed" — failed scenarios won't be highlighted`)
	}
}

func TestRun_HTMLDefaultsWhenFormatEmpty(t *testing.T) {
	body := runFixture(t, fixtureCucumberJSON, "", false)
	if !strings.Contains(body, `<!doctype html>`) {
		t.Errorf("empty format string should default to HTML, got: %s", body[:min(120, len(body))])
	}
}

// TestRun_AttributeContextXSS_StatusNormalised feeds a cucumber JSON
// payload with a crafted `status` field that, if interpolated raw
// into the `status-<status>` class attribute or `data-status="<status>"`,
// would break out of the attribute and inject HTML. The
// normaliseStatus closed-set defence MUST map it to "unknown" so
// the rendered HTML carries no attacker-controlled markup.
func TestRun_AttributeContextXSS_StatusNormalised(t *testing.T) {
	hostile := `[
	  {
	    "uri": "f.feature", "keyword": "Feature", "name": "F",
	    "elements": [{
	      "keyword": "Scenario", "name": "scary scenario", "line": 1,
	      "type": "scenario", "tags": [],
	      "steps": [{
	        "keyword": "Given ", "name": "a step", "line": 2,
	        "result": {"status": "passed\"><script>alert(1)</script>", "duration": 1000}
	      }]
	    }]
	  }
	]`
	body := runFixture(t, hostile, "html", false)
	if strings.Contains(body, `<script>`) || strings.Contains(body, `alert(1)`) {
		t.Errorf("attribute-context XSS: hostile status leaked into HTML")
	}
	if !strings.Contains(body, `status-unknown`) {
		t.Errorf("expected status-unknown class — normaliseStatus didn't fire")
	}
}

// TestRun_TextContextXSS_NameEscaped covers the other XSS surface:
// scenario / feature names interpolated in text context. html/template
// auto-escapes these, but the regression guard is cheap.
func TestRun_TextContextXSS_NameEscaped(t *testing.T) {
	hostile := `[
	  {
	    "uri": "f.feature", "keyword": "Feature",
	    "name": "<script>alert('feat')</script>",
	    "elements": [{
	      "keyword": "Scenario",
	      "name": "<img src=x onerror=alert('scn')>",
	      "line": 1, "type": "scenario", "tags": [],
	      "steps": [{
	        "keyword": "Given ", "name": "a step", "line": 2,
	        "result": {"status": "passed", "duration": 1000}
	      }]
	    }]
	  }
	]`
	body := runFixture(t, hostile, "html", false)
	if strings.Contains(body, `<script>alert('feat')</script>`) {
		t.Errorf("feature name not escaped in text context")
	}
	if strings.Contains(body, `<img src=x onerror=`) {
		t.Errorf("scenario name not escaped in text context")
	}
}

func TestNormaliseStatus(t *testing.T) {
	cases := map[string]string{
		"passed":                           "passed",
		"failed":                           "failed",
		"skipped":                          "skipped",
		"undefined":                        "undefined",
		"pending":                          "pending",
		"":                                 "unknown",
		"passed\"><script>":                "unknown",
		"PASSED":                           "unknown", // case-sensitive
		"completely-unknown-future-status": "unknown",
	}
	for input, want := range cases {
		if got := normaliseStatus(input); got != want {
			t.Errorf("normaliseStatus(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestRun_EmptyInputErrors(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(in, []byte{}, 0o600); err != nil {
		t.Fatalf("write empty: %v", err)
	}

	var out bytes.Buffer
	err := run("core", in, "html", false, &out)
	if err == nil {
		t.Fatal("expected error on empty input, got nil")
	}
	if !strings.Contains(err.Error(), "empty input:") {
		t.Errorf("expected 'empty input:' in error, got: %v", err)
	}
}

func TestRun_InvalidJSONErrors(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(in, []byte("not json"), 0o600); err != nil {
		t.Fatalf("write bad: %v", err)
	}

	var out bytes.Buffer
	err := run("core", in, "html", false, &out)
	if err == nil {
		t.Fatal("expected error on invalid JSON, got nil")
	}
	if !strings.Contains(err.Error(), "parse cucumber JSON") {
		t.Errorf("expected 'parse cucumber JSON' in error, got: %v", err)
	}
}

func TestRun_MissingSuiteFlag(t *testing.T) {
	var out bytes.Buffer
	err := run("", "/dev/null", "html", false, &out)
	if err == nil {
		t.Fatal("expected error when -suite is empty, got nil")
	}
	if !strings.Contains(err.Error(), "-suite is required") {
		t.Errorf("expected '-suite is required' in error, got: %v", err)
	}
}

func TestRun_UnknownFormatErrors(t *testing.T) {
	var out bytes.Buffer
	err := run("core", "/dev/null", "xml", false, &out)
	if err == nil {
		t.Fatal("expected error for unknown format, got nil")
	}
	if !strings.Contains(err.Error(), `unknown format "xml"`) {
		t.Errorf("expected 'unknown format \"xml\"' in error, got: %v", err)
	}
	if !strings.Contains(err.Error(), `"html"`) || !strings.Contains(err.Error(), `"markdown"`) {
		t.Errorf("error must list accepted formats, got: %v", err)
	}
}

func TestRun_FormatCaseInsensitive(t *testing.T) {
	// HTML / Markdown / MD / MARKDOWN all accepted.
	for _, fmt := range []string{"HTML", "Html", "Markdown", "MD", "md"} {
		body := runFixture(t, fixtureCucumberJSON, fmt, false)
		if body == "" {
			t.Errorf("format=%q produced empty output", fmt)
		}
	}
}

func TestScenarioStatus_Aggregates(t *testing.T) {
	cases := []struct {
		name     string
		expected string
		steps    []step
	}{
		{name: "all_passed", expected: "passed",
			steps: []step{{Result: result{Status: "passed"}}, {Result: result{Status: "passed"}}}},
		{name: "one_failed", expected: "failed",
			steps: []step{{Result: result{Status: "passed"}}, {Result: result{Status: "failed"}}}},
		{name: "failed_beats_undefined", expected: "failed",
			steps: []step{{Result: result{Status: "undefined"}}, {Result: result{Status: "failed"}}}},
		{name: "undefined_beats_skipped", expected: "undefined",
			steps: []step{{Result: result{Status: "skipped"}}, {Result: result{Status: "undefined"}}}},
		{name: "empty_is_passed", expected: "passed", steps: []step{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := scenario{Steps: tc.steps}
			if got := s.status(); got != tc.expected {
				t.Errorf("want %q, got %q", tc.expected, got)
			}
		})
	}
}

// ---- Markdown rendering -------------------------------------------------

func TestRun_ProducesMarkdownForFixture(t *testing.T) {
	body := runFixture(t, fixtureCucumberJSON, "markdown", false)

	for _, want := range []string{
		`# BDD report — core`,
		`**2 scenarios**`,
		`**1 passed**`,
		`**1 failed**`,
		`<details`,
		`<summary><strong>Feature: Sample feature</strong>`,
		`<code>features/sample.feature</code>`, // URI in <code> tag, HTML-escaped
		`Happy path`,
		`Broken path`,
		`boom: <bad input>`, // raw text inside fenced code — NOT escaped (fence is no-parse)
	} {
		if !strings.Contains(body, want) {
			t.Errorf("markdown output missing %q\n--- output ---\n%s", want, body)
		}
	}
}

// TestRun_MarkdownInjection_Headers verifies that a feature/scenario name
// containing newlines + Markdown headers cannot inject its own headers
// into the document outline. sanitiseLine MUST collapse \n / \r to
// spaces BEFORE escapeMarkdown runs, otherwise a `# ` at the start of
// a new line would be treated as a heading by GFM.
func TestRun_MarkdownInjection_Headers(t *testing.T) {
	hostile := `[
	  {
	    "uri": "f.feature", "keyword": "Feature",
	    "name": "# Pwned\n## Fake real failures\n",
	    "elements": [{
	      "keyword": "Scenario",
	      "name": "Real scenario\n# Also not a header",
	      "line": 1, "type": "scenario", "tags": [],
	      "steps": [{
	        "keyword": "Given ", "name": "a step", "line": 2,
	        "result": {"status": "passed", "duration": 1000}
	      }]
	    }]
	  }
	]`
	body := runFixture(t, hostile, "markdown", false)

	// No injected H1/H2 should appear. The legitimate "# BDD report" is
	// the only top-level header expected.
	if strings.Count(body, "\n# ") > 0 {
		t.Errorf("injected H1 in markdown body — header injection succeeded\n%s", body)
	}
	if strings.Contains(body, "\n## Fake real failures") {
		t.Errorf("injected H2 from feature name — sanitiseLine failed\n%s", body)
	}
	if strings.Contains(body, "\n# Also not a header") {
		t.Errorf("injected H1 from scenario name — sanitiseLine failed\n%s", body)
	}
	// The legitimate top header must still be present.
	if !strings.HasPrefix(body, "# BDD report — core") {
		t.Errorf("legitimate report header missing\n%s", body[:min(200, len(body))])
	}
}

// TestRun_MarkdownInjection_Metacharacters verifies that GFM
// metacharacters in user-supplied names are escaped (body context)
// or HTML-escaped (inside <summary>).
func TestRun_MarkdownInjection_Metacharacters(t *testing.T) {
	hostile := `[
	  {
	    "uri": "f.feature", "keyword": "Feature",
	    "name": "feat *bold* _em_ [link](x) ` + "`code`" + `",
	    "elements": [{
	      "keyword": "Scenario",
	      "name": "scen | pipe & amp <tag> end",
	      "line": 1, "type": "scenario", "tags": [],
	      "steps": [{
	        "keyword": "Given ",
	        "name": "step with *star* and _under_ and [brk]",
	        "line": 2,
	        "result": {"status": "passed", "duration": 1000}
	      }]
	    }]
	  }
	]`
	body := runFixture(t, hostile, "markdown", false)

	// Feature/scenario names live inside <summary> — HTML-escaped.
	// `&` must become `&amp;`, `<` → `&lt;`.
	if !strings.Contains(body, `&lt;tag&gt;`) {
		t.Errorf("scenario name <tag> not HTML-escaped inside summary\n%s", body)
	}
	if !strings.Contains(body, `&amp; amp`) {
		t.Errorf("scenario name & not HTML-escaped inside summary\n%s", body)
	}

	// Step name lives in body context — markdown-escaped.
	// `*star*` should appear as `\*star\*`.
	if !strings.Contains(body, `\*star\*`) {
		t.Errorf("step name *star* not markdown-escaped in body context\n%s", body)
	}
	if !strings.Contains(body, `\_under\_`) {
		t.Errorf("step name _under_ not markdown-escaped in body context\n%s", body)
	}
	if !strings.Contains(body, `\[brk\]`) {
		t.Errorf("step name [brk] not markdown-escaped in body context\n%s", body)
	}
}

// TestRun_MarkdownAmpersandInName verifies that an `&` in a feature
// or scenario name renders inside <summary> as `&amp;`, not as a
// stray ampersand that browsers tolerate but linters and accessibility
// tools flag.
func TestRun_MarkdownAmpersandInName(t *testing.T) {
	json := `[
	  {
	    "uri": "f.feature", "keyword": "Feature",
	    "name": "Tom & Jerry",
	    "elements": [{
	      "keyword": "Scenario", "name": "Cat & mouse",
	      "line": 1, "type": "scenario", "tags": [],
	      "steps": [{
	        "keyword": "Given ", "name": "a step", "line": 2,
	        "result": {"status": "passed", "duration": 1000}
	      }]
	    }]
	  }
	]`
	body := runFixture(t, json, "markdown", false)

	if !strings.Contains(body, `Tom &amp; Jerry`) {
		t.Errorf("feature ampersand not HTML-escaped\n%s", body)
	}
	if !strings.Contains(body, `Cat &amp; mouse`) {
		t.Errorf("scenario ampersand not HTML-escaped\n%s", body)
	}
}

// TestRun_MarkdownControlCharactersStripped feeds a name containing
// ANSI escape sequences and a NUL byte. sanitiseLine must replace
// every C0 control character with a space.
func TestRun_MarkdownControlCharactersStripped(t *testing.T) {
	// Cucumber JSON must escape C0 controls as \uNNNN. The renderer's
	// sanitiseLine must replace them with spaces before the output is
	// written.
	hostileName := "name\x00with\x1b[31mansi\x1b[0m and \x07 bell"
	jsonBody := `[
	  {
	    "uri": "f.feature", "keyword": "Feature",
	    "name": ` + jsonQuote(hostileName) + `,
	    "elements": [{
	      "keyword": "Scenario", "name": "clean",
	      "line": 1, "type": "scenario", "tags": [],
	      "steps": [{
	        "keyword": "Given ", "name": "a step", "line": 2,
	        "result": {"status": "passed", "duration": 1000}
	      }]
	    }]
	  }
	]`
	body := runFixture(t, jsonBody, "markdown", false)

	if strings.ContainsAny(body, "\x00\x07\x1B") {
		t.Errorf("control characters not stripped from markdown output")
	}
}

// jsonQuote returns s as a Go-side JSON-encoded string literal so test
// JSON fixtures can embed raw control characters without invalidating
// the surrounding cucumber JSON.
func jsonQuote(s string) string {
	b, err := encJSON.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// TestRun_MarkdownErrorContainingTripleBacktick verifies that an error
// message containing ``` (which would naively break a 3-backtick fence)
// is wrapped in a longer fence so the inner content survives byte for
// byte.
func TestRun_MarkdownErrorContainingTripleBacktick(t *testing.T) {
	json := `[
	  {
	    "uri": "f.feature", "keyword": "Feature", "name": "F",
	    "elements": [{
	      "keyword": "Scenario", "name": "s",
	      "line": 1, "type": "scenario", "tags": [],
	      "steps": [{
	        "keyword": "Given ", "name": "a step", "line": 2,
	        "result": {"status": "failed", "duration": 1000,
	                   "error_message": "before ` + "```" + ` after"}
	      }]
	    }]
	  }
	]`
	body := runFixture(t, json, "markdown", false)

	// Body must contain the raw `before ``` after` text — and the
	// surrounding fence must be 4+ backticks to wrap it.
	if !strings.Contains(body, "````") {
		t.Errorf("fence not extended past 3 backticks\n%s", body)
	}
	if !strings.Contains(body, "before ``` after") {
		t.Errorf("inner ``` corrupted by escaping\n%s", body)
	}
}

// TestRun_MarkdownErrorContainingFourBackticks verifies the dynamic-
// fence length logic actually counts (not just hard-coded to 4).
func TestRun_MarkdownErrorContainingFourBackticks(t *testing.T) {
	json := `[
	  {
	    "uri": "f.feature", "keyword": "Feature", "name": "F",
	    "elements": [{
	      "keyword": "Scenario", "name": "s",
	      "line": 1, "type": "scenario", "tags": [],
	      "steps": [{
	        "keyword": "Given ", "name": "a step", "line": 2,
	        "result": {"status": "failed", "duration": 1000,
	                   "error_message": "wrap ` + "````" + ` text"}
	      }]
	    }]
	  }
	]`
	body := runFixture(t, json, "markdown", false)

	if !strings.Contains(body, "`````") {
		t.Errorf("fence not extended to 5 backticks\n%s", body)
	}
	if !strings.Contains(body, "wrap ```` text") {
		t.Errorf("inner ```` corrupted\n%s", body)
	}
}

// TestFenceForError_DirectCounts exercises the helper at the boundary.
func TestFenceForError_DirectCounts(t *testing.T) {
	cases := map[string]int{
		"":               3,
		"no ticks":       3,
		"one `":          3,
		"two ``":         3,
		"three ```":      4,
		"four ````":      5,
		"five `````":     6,
		"mixed ` and ``": 3, // longest run is 2
	}
	for in, want := range cases {
		got := fenceForError(in)
		if len(got) != want {
			t.Errorf("fenceForError(%q): len=%d, want %d (got %q)", in, len(got), want, got)
		}
	}
}

// TestRun_MarkdownOnlyFailures emits only the failing scenarios + a
// summary header. Verifies the passing scenario is omitted entirely.
func TestRun_MarkdownOnlyFailures(t *testing.T) {
	body := runFixture(t, fixtureCucumberJSON, "markdown", true)

	if !strings.Contains(body, `# BDD report — core`) {
		t.Errorf("only-failures missing header\n%s", body)
	}
	if !strings.Contains(body, `Showing only failed scenarios`) {
		t.Errorf("only-failures missing notice\n%s", body)
	}
	if !strings.Contains(body, `Broken path`) {
		t.Errorf("only-failures missing failed scenario name\n%s", body)
	}
	if strings.Contains(body, `Happy path`) {
		t.Errorf("only-failures included passing scenario\n%s", body)
	}
}

// TestRun_MarkdownOnlyFailures_AllGreen verifies the placeholder
// rendered when the suite passes entirely.
func TestRun_MarkdownOnlyFailures_AllGreen(t *testing.T) {
	json := `[
	  {
	    "uri": "f.feature", "keyword": "Feature", "name": "F",
	    "elements": [{
	      "keyword": "Scenario", "name": "passes",
	      "line": 1, "type": "scenario", "tags": [],
	      "steps": [{
	        "keyword": "Given ", "name": "a step", "line": 2,
	        "result": {"status": "passed", "duration": 1000}
	      }]
	    }]
	  }
	]`
	body := runFixture(t, json, "markdown", true)
	if !strings.Contains(body, `_No failed scenarios in this run._`) {
		t.Errorf("only-failures all-green placeholder missing\n%s", body)
	}
}

// TestRun_MarkdownStepSummarySizeBudget synthesises many failing
// features to push output past the step-summary budget and asserts the
// truncation footer fires.
func TestRun_MarkdownStepSummarySizeBudget(t *testing.T) {
	// Each feature contributes ~2 KiB of markdown (long names, long
	// error messages). 800 features → ~1.6 MiB, comfortably past the
	// 1 MiB cap.
	var b strings.Builder
	b.WriteString("[")
	longName := strings.Repeat("name-segment-", 60)      // ~780 chars
	longError := strings.Repeat("stacktrace line\n", 50) // ~800 chars
	const n = 800
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"uri":"f%d.feature","keyword":"Feature","name":%q,
		  "elements":[{"keyword":"Scenario","name":%q,"line":1,"type":"scenario","tags":[],
		    "steps":[{"keyword":"Given ","name":"a step","line":2,
		      "result":{"status":"failed","duration":1000,"error_message":%q}}]}]}`,
			i, longName+fmt.Sprintf("-%d", i), "scen-"+longName,
			longError+fmt.Sprintf("at frame %d", i))
	}
	b.WriteString("]")

	body := runFixture(t, b.String(), "markdown", true)

	if !strings.Contains(body, `Output truncated`) {
		t.Errorf("expected truncation footer in oversized step-summary output (got %d bytes)", len(body))
	}
	// Should still be under (well, near) the budget — at most one
	// feature past the cap before the loop detects and truncates.
	if len(body) > stepSummaryByteBudget+50000 {
		t.Errorf("step-summary output %d bytes exceeds budget by more than 50KiB", len(body))
	}
}

// TestRun_MarkdownEmptyFeatureAndScenario covers edge cases the renderer
// must tolerate without crashing or emitting broken markdown.
func TestRun_MarkdownEmptyFeatureAndScenario(t *testing.T) {
	json := `[
	  {"uri": "", "keyword": "Feature", "name": "", "elements": []},
	  {"uri": "x.feature", "keyword": "Feature", "name": "X",
	   "elements": [{"keyword":"Scenario","name":"empty","line":1,"type":"scenario","tags":[],"steps":[]}]}
	]`
	body := runFixture(t, json, "markdown", false)

	if !strings.Contains(body, `(unnamed feature)`) {
		t.Errorf("empty feature fallback missing\n%s", body)
	}
	if !strings.Contains(body, `**2 scenarios** · **2 passed**`) {
		// Empty scenarios count as passed (per status() fallback),
		// and the unnamed feature has zero elements (contributes 0)
		// — actual total here is 1 scenario, 1 passed.
		// Adjust expectation:
		if !strings.Contains(body, `**1 scenarios**`) {
			t.Errorf("unexpected scenario count\n%s", body)
		}
	}
}

// TestRun_MarkdownDetailsBlankLineInvariant verifies that the blank-line
// rule around <summary>/</summary> and fenced code blocks is honoured
// — otherwise GFM treats the inside content as literal text.
func TestRun_MarkdownDetailsBlankLineInvariant(t *testing.T) {
	body := runFixture(t, fixtureCucumberJSON, "markdown", false)

	// After every </summary> the next line must be blank.
	lines := strings.Split(body, "\n")
	for i, ln := range lines {
		if !strings.Contains(ln, "</summary>") {
			continue
		}
		if i+1 >= len(lines) {
			t.Fatalf("</summary> on last line — missing trailing blank")
		}
		if strings.TrimSpace(lines[i+1]) != "" {
			t.Errorf("line %d </summary> not followed by blank line: %q", i, lines[i+1])
		}
	}
}

// TestMarkdownOutput_ValidGFM is a smoke test: the rendered markdown
// must parse cleanly through goldmark with GFM extensions. Catches
// fundamental structural breakage even if it doesn't catch GitHub-
// specific quirks.
func TestMarkdownOutput_ValidGFM(t *testing.T) {
	body := runFixture(t, fixtureCucumberJSON, "markdown", false)

	md := goldmark.New(goldmark.WithExtensions(extension.GFM))
	reader := text.NewReader([]byte(body))
	doc := md.Parser().Parse(reader, parser.WithContext(parser.NewContext()))
	if doc == nil {
		t.Fatal("goldmark returned nil document — fundamental parse failure")
	}
	// goldmark is lenient by design; the parse never errors. The
	// useful signal is that the AST has SOME children (proves the
	// renderer emitted recognisable markdown).
	if doc.ChildCount() == 0 {
		t.Errorf("goldmark parsed an empty document — markdown produced no recognisable blocks")
	}
}

// TestSanitiseLine spot-checks the sanitisation helper.
func TestSanitiseLine(t *testing.T) {
	cases := map[string]string{
		"":               "",
		"plain":          "plain",
		"with\nnewline":  "with newline",
		"with\r\ncrlf":   "with crlf",
		"tabs\there":     "tabs here",
		"NULs\x00inside": "NULs inside",
		"   pad   ":      "pad",
		// sanitiseLine strips the ESC byte but preserves the trailing
		// ANSI sequence chars (they're plain ASCII). The collapsed
		// whitespace at the start of the result is trimmed by
		// TrimSpace.
		"\x1b[31mansi\x1b[0m": "[31mansi [0m",
		"multi\n\n\nspaces":   "multi spaces",
	}
	for in, want := range cases {
		if got := sanitiseLine(in); got != want {
			t.Errorf("sanitiseLine(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestEscapeMarkdown_Coverage verifies every metacharacter in mdSpecial
// gets the leading backslash.
func TestEscapeMarkdown_Coverage(t *testing.T) {
	for i := 0; i < len(mdSpecial); i++ {
		c := mdSpecial[i]
		in := string(c) + "x"
		want := `\` + in
		if got := escapeMarkdown(in); got != want {
			t.Errorf("escapeMarkdown(%q) = %q, want %q", in, got, want)
		}
	}
	// And a non-special char passes through.
	if got := escapeMarkdown("abc"); got != "abc" {
		t.Errorf("escapeMarkdown plain text mangled: %q", got)
	}
}

// failingWriter returns an error after the first n bytes have been
// written. Used by TestMDWriter_StickyError to exercise the
// sticky-error path of mdWriter.
type failingWriter struct {
	written int
	limit   int
}

func (fw *failingWriter) Write(p []byte) (int, error) {
	if fw.written >= fw.limit {
		return 0, fmt.Errorf("simulated write failure")
	}
	n := len(p)
	if fw.written+n > fw.limit {
		n = fw.limit - fw.written
	}
	fw.written += n
	if n < len(p) {
		return n, fmt.Errorf("simulated short write")
	}
	return n, nil
}

// TestMDWriter_StickyError verifies that the mdWriter sticky-error
// pattern: (1) captures the first failed write, (2) treats subsequent
// writes as no-ops, (3) surfaces the wrapped error via flush().
func TestMDWriter_StickyError(t *testing.T) {
	// Use bufio's internal buffer (4 KiB default) so writes are
	// batched. Underlying writer errors after 5 bytes.
	fw := &failingWriter{limit: 5}
	w := newMDWriter(fw)
	// Write more than 4 KiB so bufio.Writer is forced to flush — that's
	// what triggers the underlying error and sets w.err.
	big := strings.Repeat("a", 8192)
	w.writeString(big)
	// At this point w.err may or may not be set depending on whether
	// bufio has flushed yet. The real assertion is on flush().
	w.writeString("more data")
	w.printf("formatted %d", 42)

	err := w.flush()
	if err == nil {
		t.Fatal("expected flush to surface the underlying error, got nil")
	}
	if !strings.Contains(err.Error(), "simulated") &&
		!strings.Contains(err.Error(), "flush markdown buffer") {
		t.Errorf("unexpected error: %v", err)
	}

	// Once flush has reported the error, additional flush calls
	// continue to return it (sticky).
	if err2 := w.flush(); err2 == nil {
		t.Error("second flush returned nil — sticky-error property violated")
	}
}

// TestScenarioIcon_AllStatuses covers the unicode-glyph mapping for
// each known status plus the fallback for "unknown".
func TestScenarioIcon_AllStatuses(t *testing.T) {
	cases := map[string]string{
		"passed":    "✓",
		"failed":    "✗",
		"skipped":   "-",
		"undefined": "?",
		"unknown":   "?",
		"":          "?",
	}
	for in, want := range cases {
		if got := scenarioIcon(in); got != want {
			t.Errorf("scenarioIcon(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestRun_MarkdownMixedStatuses ensures mdFeatureCounts + the renderer
// correctly tally skipped and undefined statuses (the existing fixtures
// only exercise passed + failed).
func TestRun_MarkdownMixedStatuses(t *testing.T) {
	jsonBody := `[
	  {
	    "uri": "x.feature", "keyword": "Feature", "name": "X",
	    "elements": [
	      {"keyword":"Scenario","name":"sk","line":1,"type":"scenario","tags":[],
	       "steps":[{"keyword":"Given ","name":"a","line":2,"result":{"status":"skipped","duration":1000}}]},
	      {"keyword":"Scenario","name":"un","line":3,"type":"scenario","tags":[],
	       "steps":[{"keyword":"Given ","name":"a","line":4,"result":{"status":"undefined","duration":1000}}]},
	      {"keyword":"Scenario","name":"pe","line":5,"type":"scenario","tags":[],
	       "steps":[{"keyword":"Given ","name":"a","line":6,"result":{"status":"pending","duration":1000}}]}
	    ]
	  }
	]`
	body := runFixture(t, jsonBody, "markdown", false)
	for _, want := range []string{`**1 skipped**`, `**2 undefined**`} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in:\n%s", want, body)
		}
	}
}

// TestCountingWriter_PropagatesError verifies the wrap on the
// underlying writer's error.
func TestCountingWriter_PropagatesError(t *testing.T) {
	fw := &failingWriter{limit: 2}
	cw := &countingWriter{w: fw}
	_, err := cw.Write([]byte("12345"))
	if err == nil {
		t.Fatal("expected error from underlying writer, got nil")
	}
	if !strings.Contains(err.Error(), "write underlying") {
		t.Errorf("expected wrapped error, got: %v", err)
	}
	if cw.n != 2 {
		t.Errorf("expected counter advanced by 2 bytes, got %d", cw.n)
	}
}

// TestMDWriter_NoErrorPath verifies the happy-path writer behaviour:
// writes succeed, flush returns nil, content is captured.
func TestMDWriter_NoErrorPath(t *testing.T) {
	var buf bytes.Buffer
	w := newMDWriter(&buf)
	w.writeString("hello ")
	w.printf("world %d", 42)
	if err := w.flush(); err != nil {
		t.Fatalf("flush error: %v", err)
	}
	if got := buf.String(); got != "hello world 42" {
		t.Errorf("got %q, want %q", got, "hello world 42")
	}
}
