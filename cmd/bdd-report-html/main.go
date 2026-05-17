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

// Command bdd-report-html ingests a cucumber JSON report (as emitted
// by godog's "cucumber:<file>" format) and writes a standalone HTML
// report to stdout. Used by .github/workflows/ci.yml to publish a
// per-suite HTML artefact for each BDD matrix leg (#439).
//
// Usage:
//
//	bdd-report-html -suite <name> -input <cucumber.json> > report.html
//
// The output is self-contained: embedded CSS, no external assets, no
// JavaScript. Opens offline in any browser after artefact download.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

// Cucumber JSON schema as emitted by godog v0.15 cucumber formatter.
// Only the fields we render are bound; unknown fields are tolerated
// by encoding/json (no DisallowUnknownFields).
type feature struct {
	URI         string     `json:"uri"`
	ID          string     `json:"id"`
	Keyword     string     `json:"keyword"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Elements    []scenario `json:"elements"`
}

type scenario struct {
	Keyword     string `json:"keyword"`
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Line        int    `json:"line"`
	Type        string `json:"type"`
	Tags        []tag  `json:"tags"`
	Steps       []step `json:"steps"`
}

type tag struct {
	Name string `json:"name"`
	Line int    `json:"line"`
}

type step struct {
	Keyword string `json:"keyword"`
	Name    string `json:"name"`
	Line    int    `json:"line"`
	Result  result `json:"result"`
}

type result struct {
	Status   string `json:"status"`
	Duration int64  `json:"duration"`
	Error    string `json:"error_message,omitempty"`
}

// statusRank maps the known cucumber statuses to a severity rank
// (higher = worse). Used by scenario.status() to compute the
// scenario-level rollup.
var statusRank = map[string]int{
	"passed":    0,
	"skipped":   1,
	"undefined": 2,
	"pending":   2,
	"failed":    3,
}

// safeStatuses is the closed set of statuses safe to interpolate
// into HTML attributes (e.g. class names). Any value outside this
// set — including attacker-controlled JSON like
// `"status": "passed\"><script>"` — is mapped to "unknown" via
// normaliseStatus to prevent attribute-context XSS in the template.
var safeStatuses = map[string]bool{
	"passed":    true,
	"skipped":   true,
	"undefined": true,
	"pending":   true,
	"failed":    true,
}

// normaliseStatus returns the input if it's one of the known cucumber
// statuses, otherwise "unknown". Closed-set defence against
// attribute-context XSS via crafted JSON.
func normaliseStatus(raw string) string {
	if safeStatuses[raw] {
		return raw
	}
	return "unknown"
}

// status returns the worst step status for a scenario:
// failed > undefined > skipped > passed. Matches the convention
// used by cucumber-html-reporter and other consumers.
func (s scenario) status() string {
	worst := "passed"
	for _, st := range s.Steps {
		if statusRank[st.Result.Status] > statusRank[worst] {
			worst = st.Result.Status
		}
	}
	return worst
}

// durationNs sums every step's duration. Nanoseconds in cucumber JSON.
func (s scenario) durationNs() int64 {
	var total int64
	for _, st := range s.Steps {
		total += st.Result.Duration
	}
	return total
}

// summary is computed across all features and passed to the template.
type summary struct {
	Suite     string
	Features  []feature
	Counts    counts
	Total     int
	Generated string
}

type counts struct {
	Passed    int
	Failed    int
	Skipped   int
	Undefined int
}

func main() {
	var (
		suite   = flag.String("suite", "", "suite name shown in the report header (e.g. \"core\")")
		input   = flag.String("input", "", "path to the cucumber JSON file (default: stdin)")
		showVer = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVer {
		fmt.Println("bdd-report-html 1.0.0")
		return
	}

	if err := run(*suite, *input, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "bdd-report-html:", err)
		os.Exit(1)
	}
}

func run(suite, input string, out io.Writer) error {
	if suite == "" {
		return fmt.Errorf("-suite is required")
	}

	var reader io.Reader = os.Stdin
	if input != "" {
		f, err := os.Open(input) //nolint:gosec // input path comes from CI workflow controlled by maintainer
		if err != nil {
			return fmt.Errorf("open %q: %w", input, err)
		}
		defer func() { _ = f.Close() }()
		reader = f
	}

	data, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("read input: %w", err)
	}
	if len(data) == 0 {
		return fmt.Errorf("empty input: godog did not emit a cucumber report (bdd may have failed to start)")
	}

	var features []feature
	if err := json.Unmarshal(data, &features); err != nil {
		return fmt.Errorf("parse cucumber JSON: %w", err)
	}

	// Sort features by URI for deterministic output across runs.
	sort.Slice(features, func(i, j int) bool {
		return features[i].URI < features[j].URI
	})

	sum := summary{
		Suite:     suite,
		Features:  features,
		Generated: time.Now().UTC().Format(time.RFC3339),
	}
	for _, f := range features {
		for _, s := range f.Elements {
			sum.Total++
			switch s.status() {
			case "passed":
				sum.Counts.Passed++
			case "failed":
				sum.Counts.Failed++
			case "skipped":
				sum.Counts.Skipped++
			case "undefined", "pending":
				sum.Counts.Undefined++
			}
		}
	}

	tmpl := template.Must(template.New("report").Funcs(template.FuncMap{
		"durationMs": func(ns int64) string {
			d := time.Duration(ns)
			if d < time.Millisecond {
				return fmt.Sprintf("%d µs", d.Microseconds())
			}
			return fmt.Sprintf("%d ms", d.Milliseconds())
		},
		"scenarioStatus": func(s scenario) string { return normaliseStatus(s.status()) },
		"safeStatus":     normaliseStatus,
		"scenarioDuration": func(s scenario) string {
			return fmt.Sprintf("%d ms", time.Duration(s.durationNs()).Milliseconds())
		},
		"featureName": func(f feature) string {
			if f.Name != "" {
				return f.Name
			}
			// Fall back to the URI's basename without extension.
			base := f.URI
			if i := strings.LastIndex(base, "/"); i >= 0 {
				base = base[i+1:]
			}
			return strings.TrimSuffix(base, ".feature")
		},
		"featureCounts": func(f feature) counts {
			var c counts
			for _, s := range f.Elements {
				switch s.status() {
				case "passed":
					c.Passed++
				case "failed":
					c.Failed++
				case "skipped":
					c.Skipped++
				case "undefined", "pending":
					c.Undefined++
				}
			}
			return c
		},
		"hasFailure": func(s scenario) bool { return s.status() == "failed" },
	}).Parse(htmlTemplate))

	return tmpl.Execute(out, sum)
}

// htmlTemplate is the single-file HTML report. Embedded CSS only;
// no JavaScript, no external assets. Uses native <details>/<summary>
// for collapsible sections (browser-native, no JS needed).
const htmlTemplate = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>BDD report — {{ .Suite }}</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; max-width: 1100px; margin: 2em auto; padding: 0 1em; color: #1f2328; }
  h1 { border-bottom: 2px solid #d0d7de; padding-bottom: 0.3em; }
  .meta { color: #57606a; font-size: 0.9em; margin-bottom: 1.5em; }
  .summary { display: flex; gap: 1em; margin-bottom: 1.5em; flex-wrap: wrap; }
  .badge { padding: 0.5em 1em; border-radius: 6px; font-weight: 600; }
  .badge.total { background: #f6f8fa; color: #1f2328; }
  .badge.passed { background: #dafbe1; color: #1a7f37; }
  .badge.failed { background: #ffebe9; color: #cf222e; }
  .badge.skipped { background: #fff8c5; color: #9a6700; }
  .badge.undefined { background: #ddf4ff; color: #0969da; }
  details { border: 1px solid #d0d7de; border-radius: 6px; margin: 0.5em 0; background: #fff; }
  details summary { padding: 0.75em 1em; cursor: pointer; user-select: none; font-weight: 600; }
  details[data-status="failed"] > summary { background: #ffebe9; color: #cf222e; }
  details[data-status="passed"] > summary { background: #f6f8fa; }
  details[data-status="skipped"] > summary { background: #fff8c5; }
  details[data-status="undefined"] > summary { background: #ddf4ff; }
  details details { margin: 0.25em 1em 0.5em 1em; }
  details details summary { padding: 0.5em 1em; font-weight: 500; }
  .status-icon { display: inline-block; width: 1em; text-align: center; margin-right: 0.5em; }
  .status-passed { color: #1a7f37; }
  .status-failed { color: #cf222e; }
  .status-skipped { color: #9a6700; }
  .status-undefined { color: #0969da; }
  .steps { padding: 0 1em 0.75em 1em; margin: 0; list-style: none; }
  .step { padding: 0.25em 0; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.9em; }
  .step .keyword { color: #6e7781; font-weight: 600; }
  .step .duration { color: #6e7781; float: right; font-size: 0.85em; }
  .error { background: #ffebe9; border-left: 3px solid #cf222e; padding: 0.75em 1em; margin: 0.5em 1em; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.85em; white-space: pre-wrap; word-wrap: break-word; }
  .feature-counts { float: right; font-size: 0.85em; color: #57606a; font-weight: 400; }
  .feature-counts .c { padding: 0.1em 0.5em; border-radius: 3px; margin-left: 0.3em; }
  .feature-counts .c.passed { background: #dafbe1; color: #1a7f37; }
  .feature-counts .c.failed { background: #ffebe9; color: #cf222e; }
  .feature-counts .c.skipped { background: #fff8c5; color: #9a6700; }
  .feature-counts .c.undefined { background: #ddf4ff; color: #0969da; }
  code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; background: #f6f8fa; padding: 0.1em 0.3em; border-radius: 3px; font-size: 0.9em; }
</style>
</head>
<body>
<h1>BDD report — {{ .Suite }}</h1>
<div class="meta">Generated {{ .Generated }}</div>

<div class="summary">
  <div class="badge total">{{ .Total }} scenarios</div>
  <div class="badge passed">{{ .Counts.Passed }} passed</div>
  {{ if gt .Counts.Failed 0 }}<div class="badge failed">{{ .Counts.Failed }} failed</div>{{ end }}
  {{ if gt .Counts.Skipped 0 }}<div class="badge skipped">{{ .Counts.Skipped }} skipped</div>{{ end }}
  {{ if gt .Counts.Undefined 0 }}<div class="badge undefined">{{ .Counts.Undefined }} undefined</div>{{ end }}
</div>

{{ range .Features }}
{{ $c := featureCounts . }}
<details {{ if gt $c.Failed 0 }}open data-status="failed"{{ end }}>
  <summary>
    {{ featureName . }}
    <span class="feature-counts">
      {{ if gt $c.Passed 0 }}<span class="c passed">{{ $c.Passed }}P</span>{{ end }}
      {{ if gt $c.Failed 0 }}<span class="c failed">{{ $c.Failed }}F</span>{{ end }}
      {{ if gt $c.Skipped 0 }}<span class="c skipped">{{ $c.Skipped }}S</span>{{ end }}
      {{ if gt $c.Undefined 0 }}<span class="c undefined">{{ $c.Undefined }}U</span>{{ end }}
    </span>
  </summary>
  <div style="padding: 0.5em 1em;">
    <code>{{ .URI }}</code>
    {{ if .Description }}<p>{{ .Description }}</p>{{ end }}
  </div>

  {{ range .Elements }}
  {{ $st := scenarioStatus . }}
  <details {{ if eq $st "failed" }}open{{ end }} data-status="{{ $st }}">
    <summary>
      <span class="status-icon status-{{ $st }}">
        {{- if eq $st "passed" }}✓{{ else if eq $st "failed" }}✗{{ else if eq $st "skipped" }}-{{ else }}?{{ end -}}
      </span>
      {{ .Keyword }}: {{ .Name }}
      <span class="duration" style="float: right; color: #57606a; font-weight: 400; font-size: 0.85em;">{{ scenarioDuration . }}</span>
    </summary>
    <ul class="steps">
      {{ range .Steps }}
      {{ $sst := safeStatus .Result.Status }}
      <li class="step">
        <span class="status-icon status-{{ $sst }}">
          {{- if eq $sst "passed" }}✓{{ else if eq $sst "failed" }}✗{{ else if eq $sst "skipped" }}-{{ else }}?{{ end -}}
        </span>
        <span class="keyword">{{ .Keyword }}</span>{{ .Name }}
        <span class="duration">{{ durationMs .Result.Duration }}</span>
      </li>
      {{ if .Result.Error }}
      <li><div class="error">{{ .Result.Error }}</div></li>
      {{ end }}
      {{ end }}
    </ul>
  </details>
  {{ end }}
</details>
{{ end }}

</body>
</html>
`
