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

// Command junit-report ingests a JUnit XML report (as emitted by
// gotestsum's `--junitfile` flag) and writes a standalone HTML or
// GitHub-flavoured Markdown report to stdout. Sibling to cmd/bdd-report
// for the per-module test report use case (#877).
//
// Usage:
//
//	junit-report -suite <name> -input <junit.xml> [-format html|markdown] [-only-failures] > report.{html,md}
//
// The HTML output is self-contained: embedded CSS, no external assets,
// no JavaScript. The Markdown output targets GitHub-flavoured Markdown
// (GFM) — inline HTML <details>/<summary> render natively on
// github.com and the Actions step summary panel.
//
// The shared escape helpers and writer (render.go, writer.go) are
// byte-identical with cmd/bdd-report — `make check-report-parity`
// enforces this.
package main

import (
	"bytes"
	"encoding/xml"
	"flag"
	"fmt"
	"html/template"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

// JUnit XML schema bindings. JUnit has two valid root elements:
// <testsuites> wrapping one or more <testsuite> (what gotestsum emits)
// and bare <testsuite> as root (some older tools). loadJUnitXML peeks
// the root element and dispatches accordingly.

type testSuites struct {
	XMLName  xml.Name    `xml:"testsuites"`
	Name     string      `xml:"name,attr,omitempty"`
	Time     string      `xml:"time,attr,omitempty"`
	Suites   []testSuite `xml:"testsuite"`
	Tests    int         `xml:"tests,attr,omitempty"`
	Failures int         `xml:"failures,attr,omitempty"`
	Errors   int         `xml:"errors,attr,omitempty"`
	Skipped  int         `xml:"skipped,attr,omitempty"`
}

type testSuite struct {
	XMLName    xml.Name   `xml:"testsuite"`
	Name       string     `xml:"name,attr"`
	Time       string     `xml:"time,attr,omitempty"`
	Timestamp  string     `xml:"timestamp,attr,omitempty"`
	Cases      []testCase `xml:"testcase"`
	Tests      int        `xml:"tests,attr,omitempty"`
	Failures   int        `xml:"failures,attr,omitempty"`
	Errors     int        `xml:"errors,attr,omitempty"`
	SkippedNum int        `xml:"skipped,attr,omitempty"`
}

type testCase struct {
	Name      string         `xml:"name,attr"`
	ClassName string         `xml:"classname,attr,omitempty"`
	Time      string         `xml:"time,attr,omitempty"`
	Failure   *failureRecord `xml:"failure,omitempty"`
	Error     *failureRecord `xml:"error,omitempty"`
	Skipped   *skippedRecord `xml:"skipped,omitempty"`
	Stdout    string         `xml:"system-out,omitempty"`
	Stderr    string         `xml:"system-err,omitempty"`
}

type failureRecord struct {
	Message string `xml:"message,attr,omitempty"`
	Type    string `xml:"type,attr,omitempty"`
	Body    string `xml:",chardata"`
}

type skippedRecord struct {
	Message string `xml:"message,attr,omitempty"`
}

// status returns the worst status for a testcase. Order, worst first:
// errored > failed > skipped > passed. JUnit distinguishes <error>
// (e.g. panic, setup failure) from <failure> (assertion failure) —
// both are surfaced separately in the report; this rollup serves the
// suite-level severity computation.
func (tc *testCase) status() string {
	switch {
	case tc.Error != nil:
		return "errored"
	case tc.Failure != nil:
		return "failed"
	case tc.Skipped != nil:
		return "skipped"
	default:
		return "passed"
	}
}

// durationMs parses the JUnit time attribute (seconds, float) into
// milliseconds for display. Returns 0 if unparseable or negative —
// some CI tools emit negative times on clock skew.
func (tc *testCase) durationMs() int64 {
	return parseDurationSeconds(tc.Time)
}

func (ts *testSuite) durationMs() int64 {
	if ts.Time == "" {
		var total int64
		for i := range ts.Cases {
			total += ts.Cases[i].durationMs()
		}
		return total
	}
	return parseDurationSeconds(ts.Time)
}

// parseDurationSeconds parses a JUnit `time` attribute (decimal
// seconds) into milliseconds. Returns 0 on parse error or negative
// values; treats empty input as zero.
func parseDurationSeconds(s string) int64 {
	if s == "" {
		return 0
	}
	d, err := time.ParseDuration(s + "s")
	if err != nil || d < 0 {
		return 0
	}
	return d.Milliseconds()
}

// safeStatuses is the closed set of statuses safe to interpolate
// into HTML attributes (e.g. class names). Any value outside this
// set is mapped to "unknown" via normaliseStatus, preventing
// attribute-context XSS via attacker-crafted JUnit XML.
var safeStatuses = map[string]bool{
	"passed":  true,
	"skipped": true,
	"failed":  true,
	"errored": true,
}

func normaliseStatus(raw string) string {
	if safeStatuses[raw] {
		return raw
	}
	return "unknown"
}

// summary is the per-render aggregate passed to renderHTML/renderMarkdown.
type summary struct {
	Suite     string
	SchemaSrc string
	Generated string
	Suites    []testSuite
	Counts    counts
	Total     int
}

// headerName composes the report header. If -suite was provided and
// the schema also carries a source name and they differ, both are
// shown: "JUnit report — <suite> (<schemaSrc>)". Otherwise just
// `<suite>` (or `<schemaSrc>` if -suite is empty).
func (s *summary) headerName() string {
	suite := strings.TrimSpace(s.Suite)
	src := strings.TrimSpace(s.SchemaSrc)
	switch {
	case suite != "" && src != "" && suite != src:
		return suite + " (" + src + ")"
	case suite != "":
		return suite
	case src != "":
		return src
	default:
		return "(unnamed)"
	}
}

type counts struct {
	Passed  int
	Failed  int
	Errored int
	Skipped int
}

func (c counts) any() int { return c.Passed + c.Failed + c.Errored + c.Skipped }

func main() {
	var (
		suite        = flag.String("suite", "", "suite/module name shown in the report header (e.g. \"core\", \"webhook\")")
		input        = flag.String("input", "", "path to the JUnit XML file (default: stdin)")
		format       = flag.String("format", "html", "output format: html or markdown")
		onlyFailures = flag.Bool("only-failures", false,
			"markdown only: emit only failed scenarios (smaller output, suitable for $GITHUB_STEP_SUMMARY's 1 MiB cap)")
		showVer = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVer {
		fmt.Println("junit-report 1.0.0")
		return
	}

	if err := run(*suite, *input, *format, *onlyFailures, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "junit-report:", err)
		os.Exit(1)
	}
}

func run(suite, input, format string, onlyFailures bool, out io.Writer) error {
	if suite == "" {
		return fmt.Errorf("-suite is required")
	}
	normFormat, err := normaliseFormat(format)
	if err != nil {
		return err
	}

	root, err := loadJUnitXML(input)
	if err != nil {
		return err
	}

	sort.SliceStable(root.Suites, func(i, j int) bool {
		return root.Suites[i].Name < root.Suites[j].Name
	})

	sum := buildSummary(suite, root)

	if normFormat == "markdown" {
		return renderMarkdown(out, &sum, onlyFailures)
	}
	return renderHTML(out, &sum)
}

// normaliseFormat lowercases the requested format and maps accepted
// aliases. Returns an error for unknown formats with the allowed values
// listed.
func normaliseFormat(format string) (string, error) {
	switch strings.ToLower(format) {
	case "", "html":
		return "html", nil
	case "markdown", "md":
		return "markdown", nil
	default:
		return "", fmt.Errorf("unknown format %q: valid values are \"html\" or \"markdown\"", format)
	}
}

// loadJUnitXML reads the input path (or stdin when empty) and decodes
// the JUnit XML payload. Handles both <testsuites> (gotestsum / surefire
// modern) and bare <testsuite> (older tools) root elements.
func loadJUnitXML(input string) (*testSuites, error) {
	data, err := readJUnitInput(input)
	if err != nil {
		return nil, err
	}
	return parseJUnit(data)
}

// readJUnitInput opens the input path (or stdin) and returns its
// contents. Empty input is treated as a clear error.
func readJUnitInput(input string) ([]byte, error) {
	var reader io.Reader = os.Stdin
	if input != "" {
		f, err := os.Open(input) //nolint:gosec // input path comes from CI workflow controlled by maintainer
		if err != nil {
			return nil, fmt.Errorf("open %q: %w", input, err)
		}
		defer func() { _ = f.Close() }()
		reader = f
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("read input: %w", err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("empty input: gotestsum did not emit a JUnit report (test runner may have failed to start)")
	}
	return data, nil
}

// parseJUnit decodes a JUnit XML payload, accepting both wrapped
// <testsuites> and bare <testsuite> root elements. Skips ProcInst,
// CharData (whitespace), and Directive tokens until the first start
// element. encoding/xml has no DTD support so XXE is not possible
// here — no further hardening of the decoder is required.
func parseJUnit(data []byte) (*testSuites, error) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	for {
		tok, terr := dec.Token()
		if terr != nil {
			return nil, fmt.Errorf("parse junit XML: %w", terr)
		}
		start, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch start.Name.Local {
		case "testsuites":
			var ts testSuites
			if err := dec.DecodeElement(&ts, &start); err != nil {
				return nil, fmt.Errorf("decode testsuites: %w", err)
			}
			return &ts, nil
		case "testsuite":
			var s testSuite
			if err := dec.DecodeElement(&s, &start); err != nil {
				return nil, fmt.Errorf("decode testsuite: %w", err)
			}
			return &testSuites{Suites: []testSuite{s}}, nil
		default:
			return nil, fmt.Errorf("unexpected root element %q: expected \"testsuites\" or \"testsuite\"", start.Name.Local)
		}
	}
}

// buildSummary aggregates per-testcase status counts across suites.
func buildSummary(suite string, root *testSuites) summary {
	sum := summary{
		Suites:    root.Suites,
		Suite:     suite,
		SchemaSrc: root.Name,
		Generated: time.Now().UTC().Format(time.RFC3339),
	}
	for si := range root.Suites {
		for ci := range root.Suites[si].Cases {
			sum.Total++
			c := &root.Suites[si].Cases[ci]
			switch c.status() {
			case "passed":
				sum.Counts.Passed++
			case "failed":
				sum.Counts.Failed++
			case "errored":
				sum.Counts.Errored++
			case "skipped":
				sum.Counts.Skipped++
			}
		}
	}
	return sum
}

// suiteCounts returns the per-suite status rollup.
func suiteCounts(ts *testSuite) counts {
	var c counts
	for i := range ts.Cases {
		switch ts.Cases[i].status() {
		case "passed":
			c.Passed++
		case "failed":
			c.Failed++
		case "errored":
			c.Errored++
		case "skipped":
			c.Skipped++
		}
	}
	return c
}

// statusIcon returns the unicode glyph for a status. Distinct icons
// for failed vs errored so the visual diff matches the semantic
// distinction in the JUnit schema.
func statusIcon(st string) string {
	switch st {
	case "passed":
		return "✓"
	case "failed":
		return "✗"
	case "errored":
		return "⚠"
	case "skipped":
		return "-"
	default:
		return "?"
	}
}

// durationFmt formats a millisecond duration with ms or µs.
func durationFmt(ms int64) string {
	if ms < 1 {
		return "< 1 ms"
	}
	return fmt.Sprintf("%d ms", ms)
}

// htmlFuncs are the html/template helpers. Each takes a value-typed
// parameter because html/template invokes them with the iteration
// value, not an addressable pointer. Copy cost is irrelevant — the
// tool runs once per CI matrix leg.
func htmlFuncs() template.FuncMap {
	return template.FuncMap{
		"durationMs": durationFmt,
		"caseStatus": func(c testCase) string { return normaliseStatus(c.status()) },
		"safeStatus": normaliseStatus,
		"caseDuration": func(c testCase) string {
			return durationFmt(c.durationMs())
		},
		"suiteDuration": func(ts testSuite) string {
			return durationFmt(ts.durationMs())
		},
		"suiteCounts": func(ts testSuite) counts { return suiteCounts(&ts) },
		"suiteName": func(ts testSuite) string {
			if ts.Name != "" {
				return ts.Name
			}
			return "(unnamed suite)"
		},
		"caseLabel": func(c testCase) string {
			if c.Name == "" {
				return "(unnamed test)"
			}
			return c.Name
		},
		"failureBody": func(c testCase) string { return pickFailureBody(&c) },
		"hasBody":     func(c testCase) bool { return pickFailureBody(&c) != "" },
	}
}

func renderHTML(out io.Writer, sum *summary) error {
	tmpl := template.Must(template.New("report").Funcs(htmlFuncs()).Parse(htmlTemplate))
	if err := tmpl.Execute(out, sum); err != nil {
		return fmt.Errorf("render html: %w", err)
	}
	return nil
}

// renderMarkdown writes a GitHub-flavoured Markdown report. When
// onlyFailures is true the output is gated by stepSummaryByteBudget
// (defined in render.go): after each suite the running byte count is
// checked, and once the budget is exceeded a truncation footer is
// appended and the rest of the report is dropped. A single suite
// whose serialised form alone exceeds the cap will overshoot once
// (the footer still writes, but GitHub silently truncates the tail).
// Reviewers must download the full artefact in that edge case.
func renderMarkdown(out io.Writer, sum *summary, onlyFailures bool) error {
	var cw *countingWriter
	if onlyFailures {
		cw = &countingWriter{w: out}
		out = cw
	}
	w := newMDWriter(out)
	writeMarkdownHeader(w, sum, onlyFailures)

	emitted, err := writeMarkdownSuites(w, sum, cw, onlyFailures)
	if err != nil {
		return err
	}

	if onlyFailures && emitted == 0 {
		w.writeString("_No failed or errored tests in this run._\n")
	}
	if sum.Total == 0 {
		w.writeString("\n> _No tests were executed._\n")
	}
	return w.flush()
}

// writeMarkdownSuites iterates the suites in sum, writing each via
// writeMarkdownSuite. When cw is non-nil (only-failures mode), it
// flushes after each suite and emits the truncation footer once the
// running byte count exceeds stepSummaryByteBudget. Returns the
// number of suites actually written.
func writeMarkdownSuites(w *mdWriter, sum *summary, cw *countingWriter, onlyFailures bool) (int, error) {
	emitted := 0
	for i := range sum.Suites {
		ts := &sum.Suites[i]
		sc := suiteCounts(ts)
		if onlyFailures && sc.Failed == 0 && sc.Errored == 0 {
			continue
		}
		writeMarkdownSuite(w, ts, &sc, onlyFailures)
		emitted++

		if cw == nil {
			continue
		}
		if err := w.flush(); err != nil {
			return emitted, err
		}
		if cw.n > stepSummaryByteBudget {
			writeTruncationFooter(w, sum, emitted)
			return emitted, w.flush()
		}
	}
	return emitted, nil
}

func writeMarkdownHeader(w *mdWriter, sum *summary, onlyFailures bool) {
	hdr := escapeMarkdown(sanitiseLine(sum.headerName()))
	suiteCode := escapeHTMLAttr(sanitiseLine(sum.Suite))
	w.printf("# JUnit report — %s\n\n", hdr)
	w.printf("_Generated %s_\n\n", escapeMarkdown(sanitiseLine(sum.Generated)))

	if onlyFailures {
		w.writeString("_Showing only failed and errored tests. ")
		w.printf("Full report available as the <code>test-report-%s-md</code> artefact._\n\n", suiteCode)
	}

	w.printf("**%d tests** · **%d passed**", sum.Total, sum.Counts.Passed)
	if sum.Counts.Failed > 0 {
		w.printf(" · **%d failed**", sum.Counts.Failed)
	}
	if sum.Counts.Errored > 0 {
		w.printf(" · **%d errored**", sum.Counts.Errored)
	}
	if sum.Counts.Skipped > 0 {
		w.printf(" · **%d skipped**", sum.Counts.Skipped)
	}
	w.writeString("\n\n")
}

func writeMarkdownSuite(w *mdWriter, ts *testSuite, sc *counts, onlyFailures bool) {
	name := ts.Name
	if name == "" {
		name = "(unnamed suite)"
	}
	nameEsc := escapeHTMLAttr(sanitiseLine(name))

	openAttr := ""
	if sc.Failed > 0 || sc.Errored > 0 {
		openAttr = " open"
	}
	w.printf("<details%s>\n<summary><strong>Suite: %s</strong>", openAttr, nameEsc)
	if sc.any() > 0 {
		w.writeString(" — ")
		writeBadgeLine(w, sc)
	}
	w.writeString("</summary>\n\n")

	for i := range ts.Cases {
		c := &ts.Cases[i]
		st := normaliseStatus(c.status())
		if onlyFailures && st != "failed" && st != "errored" {
			continue
		}
		writeMarkdownCase(w, c, st)
	}

	w.writeString("</details>\n\n")
}

func writeBadgeLine(w *mdWriter, c *counts) {
	parts := make([]string, 0, 4)
	if c.Passed > 0 {
		parts = append(parts, fmt.Sprintf("%d✓", c.Passed))
	}
	if c.Failed > 0 {
		parts = append(parts, fmt.Sprintf("%d✗", c.Failed))
	}
	if c.Errored > 0 {
		parts = append(parts, fmt.Sprintf("%d⚠", c.Errored))
	}
	if c.Skipped > 0 {
		parts = append(parts, fmt.Sprintf("%d-", c.Skipped))
	}
	w.writeString(strings.Join(parts, " · "))
}

func writeMarkdownCase(w *mdWriter, c *testCase, st string) {
	name := c.Name
	if name == "" {
		name = "(unnamed test)"
	}
	nameEsc := escapeHTMLAttr(sanitiseLine(name))
	icon := statusIcon(st)
	dur := durationFmt(c.durationMs())

	openAttr := ""
	if st == "failed" || st == "errored" {
		openAttr = " open"
	}
	w.printf("<details%s>\n<summary>%s %s <em>(%s)</em></summary>\n\n", openAttr, icon, nameEsc, dur)

	if cls := escapeHTMLAttr(sanitiseLine(c.ClassName)); cls != "" {
		w.printf("<code>%s</code>\n\n", cls)
	}

	body := pickFailureBody(c)
	if body != "" {
		body = strings.ReplaceAll(body, "\r\n", "\n")
		body = strings.ReplaceAll(body, "\r", "\n")
		fence := fenceForError(body)
		w.writeString("\n")
		w.printf("%s\n%s\n%s\n\n", fence, body, fence)
	}

	w.writeString("</details>\n\n")
}

// pickFailureBody returns the most informative body for a testcase,
// preferring (in order): <failure> chardata/message, <error>
// chardata/message, <skipped> message, then system-err / system-out.
// The stdout/stderr fallback matters for panics and build failures
// where gotestsum emits the stack trace into <system-err> without a
// structured <failure> or <error> child.
func pickFailureBody(c *testCase) string {
	if body := failureRecordBody(c.Failure); body != "" {
		return body
	}
	if body := failureRecordBody(c.Error); body != "" {
		return body
	}
	if c.Skipped != nil && c.Skipped.Message != "" {
		return c.Skipped.Message
	}
	if c.Stderr != "" {
		return c.Stderr
	}
	return c.Stdout
}

// failureRecordBody prefers the chardata body over the message
// attribute; falls back to message when body is empty.
func failureRecordBody(r *failureRecord) string {
	if r == nil {
		return ""
	}
	if r.Body != "" {
		return r.Body
	}
	return r.Message
}

func writeTruncationFooter(w *mdWriter, sum *summary, emitted int) {
	w.printf(
		"\n> **Output truncated after %d suites (step summary 1 MiB cap).** "+
			"Download the <code>test-report-%s-md</code> artefact for the full report "+
			"(%d tests total).\n",
		emitted, escapeHTMLAttr(sanitiseLine(sum.Suite)), sum.Total)
}

// htmlTemplate is the single-file HTML report. Embedded CSS only;
// no JavaScript, no external assets. Uses native <details>/<summary>
// for collapsible sections.
const htmlTemplate = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>JUnit report — {{ .Suite }}</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; max-width: 1100px; margin: 2em auto; padding: 0 1em; color: #1f2328; }
  h1 { border-bottom: 2px solid #d0d7de; padding-bottom: 0.3em; }
  .meta { color: #57606a; font-size: 0.9em; margin-bottom: 1.5em; }
  .summary { display: flex; gap: 1em; margin-bottom: 1.5em; flex-wrap: wrap; }
  .badge { padding: 0.5em 1em; border-radius: 6px; font-weight: 600; }
  .badge.total { background: #f6f8fa; color: #1f2328; }
  .badge.passed { background: #dafbe1; color: #1a7f37; }
  .badge.failed { background: #ffebe9; color: #cf222e; }
  .badge.errored { background: #fff1e5; color: #b35900; }
  .badge.skipped { background: #fff8c5; color: #9a6700; }
  details { border: 1px solid #d0d7de; border-radius: 6px; margin: 0.5em 0; background: #fff; }
  details summary { padding: 0.75em 1em; cursor: pointer; user-select: none; font-weight: 600; }
  details[data-status="failed"] > summary { background: #ffebe9; color: #cf222e; }
  details[data-status="errored"] > summary { background: #fff1e5; color: #b35900; }
  details[data-status="passed"] > summary { background: #f6f8fa; }
  details[data-status="skipped"] > summary { background: #fff8c5; }
  details details { margin: 0.25em 1em 0.5em 1em; }
  details details summary { padding: 0.5em 1em; font-weight: 500; }
  .status-icon { display: inline-block; width: 1em; text-align: center; margin-right: 0.5em; }
  .status-passed { color: #1a7f37; }
  .status-failed { color: #cf222e; }
  .status-errored { color: #b35900; }
  .status-skipped { color: #9a6700; }
  .body { background: #ffebe9; border-left: 3px solid #cf222e; padding: 0.75em 1em; margin: 0.5em 1em; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.85em; white-space: pre-wrap; word-wrap: break-word; }
  details[data-status="errored"] .body { background: #fff1e5; border-left-color: #b35900; }
  details[data-status="skipped"] .body { background: #fff8c5; border-left-color: #9a6700; }
  .suite-counts { float: right; font-size: 0.85em; color: #57606a; font-weight: 400; }
  .suite-counts .c { padding: 0.1em 0.5em; border-radius: 3px; margin-left: 0.3em; }
  .suite-counts .c.passed { background: #dafbe1; color: #1a7f37; }
  .suite-counts .c.failed { background: #ffebe9; color: #cf222e; }
  .suite-counts .c.errored { background: #fff1e5; color: #b35900; }
  .suite-counts .c.skipped { background: #fff8c5; color: #9a6700; }
  code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; background: #f6f8fa; padding: 0.1em 0.3em; border-radius: 3px; font-size: 0.9em; }
</style>
</head>
<body>
<h1>JUnit report — {{ .Suite }}</h1>
<div class="meta">Generated {{ .Generated }}</div>

<div class="summary">
  <div class="badge total">{{ .Total }} tests</div>
  <div class="badge passed">{{ .Counts.Passed }} passed</div>
  {{ if gt .Counts.Failed 0 }}<div class="badge failed">{{ .Counts.Failed }} failed</div>{{ end }}
  {{ if gt .Counts.Errored 0 }}<div class="badge errored">{{ .Counts.Errored }} errored</div>{{ end }}
  {{ if gt .Counts.Skipped 0 }}<div class="badge skipped">{{ .Counts.Skipped }} skipped</div>{{ end }}
</div>

{{ if eq .Total 0 }}
<p><em>No tests were executed.</em></p>
{{ end }}

{{ range .Suites }}
{{ $c := suiteCounts . }}
<details {{ if or (gt $c.Failed 0) (gt $c.Errored 0) }}open data-status="failed"{{ end }}>
  <summary>
    {{ suiteName . }}
    <span class="suite-counts">
      {{ if gt $c.Passed 0 }}<span class="c passed">{{ $c.Passed }}P</span>{{ end }}
      {{ if gt $c.Failed 0 }}<span class="c failed">{{ $c.Failed }}F</span>{{ end }}
      {{ if gt $c.Errored 0 }}<span class="c errored">{{ $c.Errored }}E</span>{{ end }}
      {{ if gt $c.Skipped 0 }}<span class="c skipped">{{ $c.Skipped }}S</span>{{ end }}
      <span style="margin-left:0.5em">{{ suiteDuration . }}</span>
    </span>
  </summary>

  {{ range .Cases }}
  {{ $st := caseStatus . }}
  <details {{ if or (eq $st "failed") (eq $st "errored") }}open{{ end }} data-status="{{ $st }}">
    <summary>
      <span class="status-icon status-{{ $st }}">
        {{- if eq $st "passed" }}✓{{ else if eq $st "failed" }}✗{{ else if eq $st "errored" }}⚠{{ else if eq $st "skipped" }}-{{ else }}?{{ end -}}
      </span>
      {{ caseLabel . }}
      <span style="float: right; color: #57606a; font-weight: 400; font-size: 0.85em;">{{ caseDuration . }}</span>
    </summary>
    {{ if .ClassName }}<div style="padding: 0.5em 1em;"><code>{{ .ClassName }}</code></div>{{ end }}
    {{ if hasBody . }}
    <div class="body">{{ failureBody . }}</div>
    {{ end }}
  </details>
  {{ end }}
</details>
{{ end }}

</body>
</html>
`
