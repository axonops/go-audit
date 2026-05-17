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

// Command bdd-report ingests a cucumber JSON report (as emitted by
// godog's "cucumber:<file>" format) and writes a standalone HTML or
// GitHub-flavoured Markdown report to stdout. Used by
// .github/workflows/ci.yml to publish per-suite report artefacts for
// each BDD matrix leg, and to inline failure summaries into the
// GitHub Actions step summary panel (#439).
//
// Usage:
//
//	bdd-report -suite <name> -input <cucumber.json> [-format html|markdown] [-only-failures] > report.{html,md}
//
// The HTML output is self-contained: embedded CSS, no external assets,
// no JavaScript. The Markdown output targets GitHub-flavoured Markdown
// (GFM) — inline HTML <details>/<summary> render natively on
// github.com and the Actions step summary panel.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"html"
	"html/template"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

// Cucumber JSON schema as emitted by godog v0.15 cucumber formatter.
// Only the fields we render are bound; unknown fields are tolerated
// by encoding/json (no DisallowUnknownFields). Field order chosen so
// the pointer-sized members align together (govet fieldalignment).
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
	Type        string `json:"type"`
	Tags        []tag  `json:"tags"`
	Steps       []step `json:"steps"`
	Line        int    `json:"line"`
}

type tag struct {
	Name string `json:"name"`
	Line int    `json:"line"`
}

type step struct {
	Keyword string `json:"keyword"`
	Name    string `json:"name"`
	Result  result `json:"result"`
	Line    int    `json:"line"`
}

type result struct {
	Status   string `json:"status"`
	Error    string `json:"error_message,omitempty"`
	Duration int64  `json:"duration"`
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
func (s *scenario) status() string {
	worst := "passed"
	for i := range s.Steps {
		if statusRank[s.Steps[i].Result.Status] > statusRank[worst] {
			worst = s.Steps[i].Result.Status
		}
	}
	return worst
}

// durationNs sums every step's duration. Nanoseconds in cucumber JSON.
func (s *scenario) durationNs() int64 {
	var total int64
	for i := range s.Steps {
		total += s.Steps[i].Result.Duration
	}
	return total
}

// summary is computed across all features and passed to the template.
type summary struct {
	Suite     string
	Generated string
	Features  []feature
	Counts    counts
	Total     int
}

type counts struct {
	Passed    int
	Failed    int
	Skipped   int
	Undefined int
}

func main() {
	var (
		suite        = flag.String("suite", "", "suite name shown in the report header (e.g. \"core\")")
		input        = flag.String("input", "", "path to the cucumber JSON file (default: stdin)")
		format       = flag.String("format", "html", "output format: html or markdown")
		onlyFailures = flag.Bool("only-failures", false,
			"markdown only: emit only failed scenarios (smaller output, suitable for $GITHUB_STEP_SUMMARY's 1 MiB cap)")
		showVer = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVer {
		fmt.Println("bdd-report 1.0.0")
		return
	}

	if err := run(*suite, *input, *format, *onlyFailures, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "bdd-report:", err)
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

	features, err := loadCucumberJSON(input)
	if err != nil {
		return err
	}

	// Sort features by URI for deterministic output across runs.
	sort.Slice(features, func(i, j int) bool {
		return features[i].URI < features[j].URI
	})

	sum := buildSummary(suite, features)

	if normFormat == "markdown" {
		return renderMarkdown(out, &sum, onlyFailures)
	}
	return renderHTML(out, &sum)
}

// normaliseFormat lowercases the requested format and maps the
// accepted aliases. Returns an error for unknown formats with the
// allowed values listed.
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

// loadCucumberJSON reads the input path (or stdin when empty) and
// decodes the cucumber JSON payload.
func loadCucumberJSON(input string) ([]feature, error) {
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
		return nil, fmt.Errorf("empty input: godog did not emit a cucumber report (bdd may have failed to start)")
	}
	var features []feature
	if err := json.Unmarshal(data, &features); err != nil {
		return nil, fmt.Errorf("parse cucumber JSON: %w", err)
	}
	return features, nil
}

// buildSummary aggregates per-scenario status counts across features.
func buildSummary(suite string, features []feature) summary {
	sum := summary{
		Suite:     suite,
		Features:  features,
		Generated: time.Now().UTC().Format(time.RFC3339),
	}
	for fi := range features {
		for si := range features[fi].Elements {
			sum.Total++
			s := &features[fi].Elements[si]
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
	return sum
}

// htmlFuncs are the html/template helpers. Each takes a value-typed
// parameter because html/template invokes them with the iteration
// value, not an addressable pointer. Copy cost is irrelevant — the
// tool runs once per CI matrix leg.
func htmlFuncs() template.FuncMap {
	return template.FuncMap{
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
		"featureName": func(f feature) string { return mdFeatureName(&f) },
		"featureCounts": func(f feature) counts {
			return mdFeatureCounts(&f)
		},
		"hasFailure": func(s scenario) bool { return s.status() == "failed" },
	}
}

func renderHTML(out io.Writer, sum *summary) error {
	tmpl := template.Must(template.New("report").Funcs(htmlFuncs()).Parse(htmlTemplate))
	if err := tmpl.Execute(out, sum); err != nil {
		return fmt.Errorf("render html: %w", err)
	}
	return nil
}

// --- Markdown renderer -------------------------------------------------
//
// Built by hand (no text/template) because Markdown has no auto-escape
// equivalent of html/template. Every write of user-controlled text
// passes through either sanitiseLine + escapeMarkdown (body context)
// or sanitiseLine + escapeHTML (inside <summary>...</summary>).
//
// Two distinct escapers because the two contexts have different
// metacharacter sets and mixing them produces user-visible literal
// backslashes in the rendered output.

// stepSummaryByteBudget approximates the GitHub Actions step summary
// hard cap. Anything beyond 1 MiB is silently truncated by GitHub.
// We reserve a small margin so the truncation footer always fits.
const stepSummaryByteBudget = 1024*1024 - 4096

// mdSpecial lists the GFM metacharacters escaped by escapeMarkdown.
// `~` is included for strikethrough; `=` for setext underline at line
// start (escaped unconditionally for simplicity).
const mdSpecial = "\\`*_{}[]()#+-.!|<>~="

// sanitiseLine replaces CR/LF and C0 control characters in s with a
// single space, collapsing consecutive control characters into one
// space. Intra-name runs of real spaces are preserved. Applied before
// either escaper so newline-based injection (mid-summary header
// insertion, premature </details>, list-item smuggling) is impossible.
func sanitiseLine(s string) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s))
	prevSpace := false
	for _, r := range s {
		switch {
		case r == '\t', r == '\n', r == '\r', r < 0x20, r == 0x7F:
			if !prevSpace {
				b.WriteByte(' ')
				prevSpace = true
			}
		default:
			b.WriteRune(r)
			prevSpace = false
		}
	}
	return strings.TrimSpace(b.String())
}

// escapeMarkdown escapes every GFM metacharacter in s with a leading
// backslash. Assumes s has already passed through sanitiseLine (no
// CR/LF, no C0 controls).
func escapeMarkdown(s string) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s) + len(s)/4)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x80 && strings.IndexByte(mdSpecial, c) >= 0 {
			b.WriteByte('\\')
		}
		b.WriteByte(c)
	}
	return b.String()
}

// escapeHTMLAttr escapes the five HTML metacharacters. Used for content
// inside <summary>...</summary> where GFM treats the body as HTML.
func escapeHTMLAttr(s string) string {
	return html.EscapeString(s)
}

// fenceForError returns a backtick fence longer than any run of
// backticks in s. Minimum length is 3 — CommonMark's shortest fence.
// Required so a fenced code block whose body itself contains backticks
// closes at the right place.
func fenceForError(s string) string {
	longest, cur := 0, 0
	for i := 0; i < len(s); i++ {
		if s[i] == '`' {
			cur++
			if cur > longest {
				longest = cur
			}
		} else {
			cur = 0
		}
	}
	n := longest + 1
	if n < 3 {
		n = 3
	}
	return strings.Repeat("`", n)
}

// mdFeatureCounts mirrors the html-template featureCounts helper.
func mdFeatureCounts(f *feature) counts {
	var c counts
	for i := range f.Elements {
		switch f.Elements[i].status() {
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
}

// mdFeatureName falls back through name → URI basename → placeholder.
func mdFeatureName(f *feature) string {
	if name := strings.TrimSpace(f.Name); name != "" {
		return name
	}
	base := f.URI
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	base = strings.TrimSuffix(base, ".feature")
	if base == "" {
		return "(unnamed feature)"
	}
	return base
}

// scenarioIcon returns the unicode glyph for a scenario/step status.
func scenarioIcon(st string) string {
	switch st {
	case "passed":
		return "✓"
	case "failed":
		return "✗"
	case "skipped":
		return "-"
	default:
		return "?"
	}
}

// stepDuration formats a step duration in ms (or µs for sub-ms steps).
func stepDuration(ns int64) string {
	d := time.Duration(ns)
	if d < time.Millisecond {
		return fmt.Sprintf("%d µs", d.Microseconds())
	}
	return fmt.Sprintf("%d ms", d.Milliseconds())
}

// mdWriter wraps a bufio.Writer with a sticky error so renderer
// helpers don't have to handle io errors at every call site. The
// first failed write captures the error; subsequent writes are
// no-ops. Surfaced via the err() method (or Flush()).
type mdWriter struct {
	bw  *bufio.Writer
	err error
}

func newMDWriter(out io.Writer) *mdWriter {
	return &mdWriter{bw: bufio.NewWriter(out)}
}

func (w *mdWriter) printf(format string, args ...any) {
	if w.err != nil {
		return
	}
	_, w.err = fmt.Fprintf(w.bw, format, args...)
}

func (w *mdWriter) writeString(s string) {
	if w.err != nil {
		return
	}
	_, w.err = w.bw.WriteString(s)
}

func (w *mdWriter) flush() error {
	if w.err != nil {
		return w.err
	}
	if err := w.bw.Flush(); err != nil {
		return fmt.Errorf("flush markdown buffer: %w", err)
	}
	return nil
}

// renderMarkdown writes a GitHub-flavoured Markdown report. When
// onlyFailures is true the output is gated by stepSummaryByteBudget:
// after each feature the running byte count is checked, and once the
// budget is exceeded a truncation footer is appended and the rest of
// the report is dropped. The check fires AFTER each feature, so a
// single feature whose serialised form alone exceeds the cap will
// overshoot the budget once (the truncation footer still gets
// written, but GitHub silently truncates the tail). Reviewers must
// download the full report artefact in that edge case.
func renderMarkdown(out io.Writer, sum *summary, onlyFailures bool) error {
	// The step-summary budget only applies in -only-failures mode (the
	// CI step-summary path). The artefact path uses the full report
	// and has no GitHub-imposed byte cap.
	var cw *countingWriter
	if onlyFailures {
		cw = &countingWriter{w: out}
		out = cw
	}
	w := newMDWriter(out)
	writeMarkdownHeader(w, sum, onlyFailures)

	emitted := 0
	for i := range sum.Features {
		f := &sum.Features[i]
		fc := mdFeatureCounts(f)
		if onlyFailures && fc.Failed == 0 {
			continue
		}
		writeMarkdownFeature(w, f, &fc, onlyFailures)
		emitted++

		if cw != nil {
			// Flush so cw.n reflects everything written so far.
			if err := w.flush(); err != nil {
				return err
			}
			if cw.n > stepSummaryByteBudget {
				writeTruncationFooter(w, sum, emitted)
				return w.flush()
			}
		}
	}

	if onlyFailures && emitted == 0 {
		w.writeString("_No failed scenarios in this run._\n")
	}
	return w.flush()
}

func writeMarkdownHeader(w *mdWriter, sum *summary, onlyFailures bool) {
	suiteHdr := escapeMarkdown(sanitiseLine(sum.Suite))
	suiteCode := escapeHTMLAttr(sanitiseLine(sum.Suite))
	w.printf("# BDD report — %s\n\n", suiteHdr)
	w.printf("_Generated %s_\n\n", escapeMarkdown(sanitiseLine(sum.Generated)))

	if onlyFailures {
		w.writeString("_Showing only failed scenarios. ")
		w.printf("Full report available as the <code>bdd-report-%s-md</code> artefact._\n\n", suiteCode)
	}

	w.printf("**%d scenarios** · **%d passed**", sum.Total, sum.Counts.Passed)
	if sum.Counts.Failed > 0 {
		w.printf(" · **%d failed**", sum.Counts.Failed)
	}
	if sum.Counts.Skipped > 0 {
		w.printf(" · **%d skipped**", sum.Counts.Skipped)
	}
	if sum.Counts.Undefined > 0 {
		w.printf(" · **%d undefined**", sum.Counts.Undefined)
	}
	w.writeString("\n\n")
}

func writeMarkdownFeature(w *mdWriter, f *feature, fc *counts, onlyFailures bool) {
	name := escapeHTMLAttr(sanitiseLine(mdFeatureName(f)))
	// URI renders inside an HTML <code> element rather than a markdown
	// backtick span. Backtick spans cannot escape a literal backtick in
	// the content (a `\`` ends the span and shows the backslash); the
	// <code> element handles arbitrary text through escapeHTMLAttr.
	uri := escapeHTMLAttr(sanitiseLine(f.URI))

	openAttr := ""
	if fc.Failed > 0 {
		openAttr = " open"
	}
	w.printf("<details%s>\n<summary><strong>Feature: %s</strong>", openAttr, name)
	if fc.Passed+fc.Failed+fc.Skipped+fc.Undefined > 0 {
		w.writeString(" — ")
		writeBadgeLine(w, fc)
	}
	w.writeString("</summary>\n\n")

	if uri != "" {
		w.printf("<code>%s</code>\n\n", uri)
	}

	for i := range f.Elements {
		s := &f.Elements[i]
		st := normaliseStatus(s.status())
		if onlyFailures && st != "failed" {
			continue
		}
		writeMarkdownScenario(w, s, st)
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
	if c.Skipped > 0 {
		parts = append(parts, fmt.Sprintf("%d-", c.Skipped))
	}
	if c.Undefined > 0 {
		parts = append(parts, fmt.Sprintf("%d?", c.Undefined))
	}
	w.writeString(strings.Join(parts, " · "))
}

func writeMarkdownScenario(w *mdWriter, s *scenario, st string) {
	name := escapeHTMLAttr(sanitiseLine(s.Name))
	keyword := escapeHTMLAttr(sanitiseLine(s.Keyword))
	icon := scenarioIcon(st)
	duration := stepDuration(s.durationNs())

	openAttr := ""
	if st == "failed" {
		openAttr = " open"
	}
	// Inner <details>. Blank line between </summary> and any markdown
	// content below is required by GFM for the markdown to parse.
	w.printf("<details%s>\n<summary>%s %s: %s <em>(%s)</em></summary>\n\n",
		openAttr, icon, keyword, name, duration)

	for i := range s.Steps {
		writeMarkdownStep(w, &s.Steps[i])
	}

	w.writeString("</details>\n\n")
}

func writeMarkdownStep(w *mdWriter, st *step) {
	stat := normaliseStatus(st.Result.Status)
	icon := scenarioIcon(stat)
	keyword := escapeMarkdown(sanitiseLine(st.Keyword))
	name := escapeMarkdown(sanitiseLine(st.Name))
	duration := stepDuration(st.Result.Duration)

	w.printf("- %s **%s** %s _(%s)_\n", icon, keyword, name, duration)

	if st.Result.Error != "" {
		// Fenced code block. Blank lines around the fence are required
		// for it to be recognised as a block when surrounded by
		// <details>...</details>. Body is raw (no escape) — only the
		// fence length is adjusted to dodge embedded backtick runs.
		// Normalise CRLF → LF so the embedded text doesn't introduce
		// stray carriage returns.
		body := strings.ReplaceAll(st.Result.Error, "\r\n", "\n")
		body = strings.ReplaceAll(body, "\r", "\n")
		fence := fenceForError(body)
		w.writeString("\n")
		w.printf("%s\n%s\n%s\n\n", fence, body, fence)
	}
}

func writeTruncationFooter(w *mdWriter, sum *summary, emitted int) {
	w.printf(
		"\n> **Output truncated after %d features (step summary 1 MiB cap).** "+
			"Download the <code>bdd-report-%s-md</code> artefact for the full report "+
			"(%d scenarios total).\n",
		emitted, escapeHTMLAttr(sanitiseLine(sum.Suite)), sum.Total)
}

// countingWriter wraps an io.Writer to track total bytes written. Used
// by renderMarkdown's step-summary budget check.
type countingWriter struct {
	w io.Writer
	n int
}

func (cw *countingWriter) Write(p []byte) (int, error) {
	n, err := cw.w.Write(p)
	cw.n += n
	if err != nil {
		return n, fmt.Errorf("write underlying: %w", err)
	}
	return n, nil
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
