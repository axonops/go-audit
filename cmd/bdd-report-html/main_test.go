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
	"os"
	"path/filepath"
	"strings"
	"testing"
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

func TestRun_ProducesHTMLForFixture(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "report.json")
	if err := os.WriteFile(in, []byte(fixtureCucumberJSON), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	var out bytes.Buffer
	if err := run("core", in, &out); err != nil {
		t.Fatalf("run: %v", err)
	}

	body := out.String()

	// Header + summary
	for _, want := range []string{
		`<!doctype html>`,
		`<title>BDD report — core</title>`,
		`2 scenarios`,
		`1 passed`,
		`1 failed`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("output missing %q", want)
		}
	}

	// Scenario names from fixture
	for _, want := range []string{`Happy path`, `Broken path`} {
		if !strings.Contains(body, want) {
			t.Errorf("output missing scenario name %q", want)
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

	// data-status used by the CSS to highlight failures
	if !strings.Contains(body, `data-status="failed"`) {
		t.Errorf(`output missing data-status="failed" — failed scenarios won't be highlighted`)
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
	dir := t.TempDir()
	in := filepath.Join(dir, "hostile.json")
	if err := os.WriteFile(in, []byte(hostile), 0o600); err != nil {
		t.Fatalf("write hostile fixture: %v", err)
	}

	var out bytes.Buffer
	if err := run("core", in, &out); err != nil {
		t.Fatalf("run: %v", err)
	}
	body := out.String()

	// The hostile status was either normalised to "unknown" OR
	// the angle bracket was HTML-escaped. Either way no raw
	// <script> tag must appear.
	if strings.Contains(body, `<script>`) || strings.Contains(body, `alert(1)`) {
		t.Errorf("attribute-context XSS: hostile status leaked into HTML")
	}
	// The class attribute should be `status-unknown`, not the
	// attacker-crafted variant.
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
	dir := t.TempDir()
	in := filepath.Join(dir, "names.json")
	if err := os.WriteFile(in, []byte(hostile), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	var out bytes.Buffer
	if err := run("core", in, &out); err != nil {
		t.Fatalf("run: %v", err)
	}
	body := out.String()

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
	err := run("core", in, &out)
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
	err := run("core", in, &out)
	if err == nil {
		t.Fatal("expected error on invalid JSON, got nil")
	}
	if !strings.Contains(err.Error(), "parse cucumber JSON") {
		t.Errorf("expected 'parse cucumber JSON' in error, got: %v", err)
	}
}

func TestRun_MissingSuiteFlag(t *testing.T) {
	var out bytes.Buffer
	err := run("", "/dev/null", &out)
	if err == nil {
		t.Fatal("expected error when -suite is empty, got nil")
	}
	if !strings.Contains(err.Error(), "-suite is required") {
		t.Errorf("expected '-suite is required' in error, got: %v", err)
	}
}

func TestScenarioStatus_Aggregates(t *testing.T) {
	cases := []struct {
		name     string
		steps    []step
		expected string
	}{
		{"all_passed", []step{{Result: result{Status: "passed"}}, {Result: result{Status: "passed"}}}, "passed"},
		{"one_failed", []step{{Result: result{Status: "passed"}}, {Result: result{Status: "failed"}}}, "failed"},
		{"failed_beats_undefined", []step{{Result: result{Status: "undefined"}}, {Result: result{Status: "failed"}}}, "failed"},
		{"undefined_beats_skipped", []step{{Result: result{Status: "skipped"}}, {Result: result{Status: "undefined"}}}, "undefined"},
		{"empty_is_passed", []step{}, "passed"},
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
