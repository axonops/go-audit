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

// fixtureJUnitXML is a minimal, plausible JUnit XML payload matching
// what gotestsum emits — one wrapped <testsuites> root, one suite,
// with one passing, one failing, one errored, one skipped test.
const fixtureJUnitXML = `<?xml version="1.0" encoding="UTF-8"?>
<testsuites tests="4" failures="1" errors="1" time="0.025">
  <testsuite tests="4" failures="1" errors="1" skipped="1" time="0.025"
             name="github.com/axonops/audit/sample"
             timestamp="2026-05-17T12:00:00Z">
    <testcase classname="github.com/axonops/audit/sample" name="TestHappyPath" time="0.001"></testcase>
    <testcase classname="github.com/axonops/audit/sample" name="TestBrokenPath" time="0.005">
      <failure message="want true, got false" type="">
boom: &lt;bad input&gt;
expected: true
actual:   false
      </failure>
    </testcase>
    <testcase classname="github.com/axonops/audit/sample" name="TestExploded" time="0.010">
      <error message="panic: index out of range" type="">
goroutine 1 [running]:
sample.foo()
        /src/sample/foo.go:42 +0x80
      </error>
    </testcase>
    <testcase classname="github.com/axonops/audit/sample" name="TestSkipped" time="0.000">
      <skipped message="awaiting feature flag"></skipped>
    </testcase>
  </testsuite>
</testsuites>`

// runFixture is a small helper that writes the given XML to a temp
// file and invokes run() with the supplied format / onlyFailures flag,
// returning the captured stdout buffer.
func runFixture(t *testing.T, xmlBody, format string, onlyFailures bool) string {
	t.Helper()
	dir := t.TempDir()
	in := filepath.Join(dir, "report.xml")
	if err := os.WriteFile(in, []byte(xmlBody), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	var out bytes.Buffer
	if err := run("core", in, format, onlyFailures, &out); err != nil {
		t.Fatalf("run: %v", err)
	}
	return out.String()
}

func TestRun_ProducesHTMLForFixture(t *testing.T) {
	body := runFixture(t, fixtureJUnitXML, "html", false)

	for _, want := range []string{
		`<!doctype html>`,
		`<title>JUnit report — core</title>`,
		`4 tests`,
		`1 passed`,
		`1 failed`,
		`1 errored`,
		`1 skipped`,
		`TestHappyPath`,
		`TestBrokenPath`,
		`TestExploded`,
		`TestSkipped`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("output missing %q", want)
		}
	}
	// html/template auto-escapes — the failure body should appear
	// rendered, NOT executed.
	if strings.Contains(body, `boom: <bad input>`) {
		t.Errorf("failure body rendered raw — XSS risk")
	}
	if !strings.Contains(body, `boom: &amp;lt;bad input&amp;gt;`) {
		// The XML uses &lt; entities; after XML decode those become
		// '<'/'>' in the Go string, then html/template re-escapes to
		// &lt; / &gt;. We assert the latter form.
		if !strings.Contains(body, `boom: &lt;bad input&gt;`) {
			t.Errorf("failure body not HTML-escaped")
		}
	}
	if !strings.Contains(body, `data-status="failed"`) {
		t.Errorf(`output missing data-status="failed" — failed tests won't be highlighted`)
	}
	if !strings.Contains(body, `data-status="errored"`) {
		t.Errorf(`output missing data-status="errored" — errored tests won't be highlighted`)
	}
}

func TestRun_HTMLDefaultsWhenFormatEmpty(t *testing.T) {
	body := runFixture(t, fixtureJUnitXML, "", false)
	if !strings.Contains(body, `<!doctype html>`) {
		t.Errorf("empty format string should default to HTML, got: %s", body[:min(120, len(body))])
	}
}

// TestRun_AttributeContextXSS_StatusNormalised confirms that any
// status string the renderer encounters other than the closed set
// resolves to "unknown", preventing attribute-context HTML injection.
// JUnit doesn't have a `status` attribute (status is implicit in the
// child element); the equivalent surface is when status() falls
// through to a synthetic value. Exercise directly.
func TestRun_AttributeContextXSS_StatusNormalised(t *testing.T) {
	for _, in := range []string{
		`passed"><script>alert(1)</script>`,
		"\n\n",
		"<>",
		"PASSED",
	} {
		if got := normaliseStatus(in); got != "unknown" {
			t.Errorf("normaliseStatus(%q) = %q, want \"unknown\"", in, got)
		}
	}
}

// TestRun_TextContextXSS_NameEscaped covers the testcase-name surface:
// crafted names interpolated in HTML text. html/template auto-escapes,
// but the regression guard is cheap.
func TestRun_TextContextXSS_NameEscaped(t *testing.T) {
	hostile := `<?xml version="1.0"?>
<testsuites>
  <testsuite name="&lt;script&gt;alert('s')&lt;/script&gt;">
    <testcase classname="x" name="&lt;img src=x onerror=alert('t')&gt;" time="0"></testcase>
  </testsuite>
</testsuites>`
	body := runFixture(t, hostile, "html", false)
	if strings.Contains(body, `<script>alert('s')</script>`) {
		t.Errorf("suite name not escaped in text context")
	}
	if strings.Contains(body, `<img src=x onerror=`) {
		t.Errorf("testcase name not escaped in text context")
	}
}

// TestRun_TextContextXSS_MessageEscaped covers JUnit-specific
// surfaces (<failure>.Body and <failure>.Message) for the HTML and
// Markdown paths.
func TestRun_TextContextXSS_MessageEscaped(t *testing.T) {
	hostile := `<?xml version="1.0"?>
<testsuites>
  <testsuite name="x">
    <testcase classname="x" name="t" time="0">
      <failure message="msg &lt;b&gt;X&lt;/b&gt;">
body &lt;script&gt;alert(1)&lt;/script&gt;
      </failure>
    </testcase>
  </testsuite>
</testsuites>`
	htmlOut := runFixture(t, hostile, "html", false)
	if strings.Contains(htmlOut, `body <script>alert(1)</script>`) {
		t.Errorf("HTML failure body not escaped")
	}
	if strings.Contains(htmlOut, `msg <b>X</b>`) {
		t.Errorf("HTML failure message not escaped")
	}

	mdOut := runFixture(t, hostile, "markdown", false)
	// In Markdown, failure body lives inside a fenced code block — the
	// fence is a no-parse region so the raw text appears, BUT it's
	// inside a code block which the browser renders as text, not HTML.
	// What we must NOT see is the script executing in any rendered
	// context — assert no raw <script> outside fenced code.
	if strings.Contains(mdOut, "\n<script>alert(1)") {
		t.Errorf("Markdown failure body leaked outside fenced code: %s", mdOut)
	}
}

func TestNormaliseStatus(t *testing.T) {
	cases := map[string]string{
		"passed":   "passed",
		"failed":   "failed",
		"errored":  "errored",
		"skipped":  "skipped",
		"":         "unknown",
		"PASSED":   "unknown",
		"<script>": "unknown",
	}
	for input, want := range cases {
		if got := normaliseStatus(input); got != want {
			t.Errorf("normaliseStatus(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestRun_EmptyInputErrors(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "empty.xml")
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

func TestRun_InvalidXMLErrors(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "bad.xml")
	if err := os.WriteFile(in, []byte("not xml"), 0o600); err != nil {
		t.Fatalf("write bad: %v", err)
	}
	var out bytes.Buffer
	err := run("core", in, "html", false, &out)
	if err == nil {
		t.Fatal("expected error on invalid XML, got nil")
	}
	if !strings.Contains(err.Error(), "parse junit XML") {
		t.Errorf("expected 'parse junit XML' in error, got: %v", err)
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
	for _, fmt := range []string{"HTML", "Html", "Markdown", "MD", "md"} {
		body := runFixture(t, fixtureJUnitXML, fmt, false)
		if body == "" {
			t.Errorf("format=%q produced empty output", fmt)
		}
	}
}

func TestRun_RootElement_UnexpectedErrors(t *testing.T) {
	wrong := `<?xml version="1.0"?><foo></foo>`
	dir := t.TempDir()
	in := filepath.Join(dir, "wrong.xml")
	if err := os.WriteFile(in, []byte(wrong), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	var out bytes.Buffer
	err := run("core", in, "html", false, &out)
	if err == nil {
		t.Fatal("expected error for unexpected root, got nil")
	}
	if !strings.Contains(err.Error(), "unexpected root element") {
		t.Errorf("error must explain root element problem, got: %v", err)
	}
}

// ---- Markdown rendering -------------------------------------------------

func TestRun_ProducesMarkdownForFixture(t *testing.T) {
	body := runFixture(t, fixtureJUnitXML, "markdown", false)

	for _, want := range []string{
		`# JUnit report — core`,
		`**4 tests**`,
		`**1 passed**`,
		`**1 failed**`,
		`**1 errored**`,
		`**1 skipped**`,
		`<details`,
		// Suite name lives inside <summary> — HTML escape, not Markdown,
		// so dots are not backslashed.
		`<summary><strong>Suite: github.com/axonops/audit/sample</strong>`,
		`TestHappyPath`,
		`TestBrokenPath`,
		`TestExploded`,
		`TestSkipped`,
		`<code>github.com/axonops/audit/sample</code>`, // classname in <code>
		// Failure body is the <failure> chardata, not the message attribute.
		`boom: <bad input>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("markdown output missing %q\n--- output ---\n%s", want, body)
		}
	}
}

func TestRun_MarkdownInjection_Headers(t *testing.T) {
	hostile := `<?xml version="1.0"?>
<testsuites>
  <testsuite name="# Pwned&#10;## Fake real failures">
    <testcase classname="x" name="Real test&#10;# Also not a header" time="0"></testcase>
  </testsuite>
</testsuites>`
	body := runFixture(t, hostile, "markdown", false)

	if strings.Count(body, "\n# ") > 0 {
		t.Errorf("injected H1 in markdown body\n%s", body)
	}
	if strings.Contains(body, "\n## Fake real failures") {
		t.Errorf("injected H2 from suite name\n%s", body)
	}
	if strings.Contains(body, "\n# Also not a header") {
		t.Errorf("injected H1 from testcase name\n%s", body)
	}
	if !strings.HasPrefix(body, "# JUnit report — core") {
		t.Errorf("legitimate header missing\n%s", body[:min(200, len(body))])
	}
}

func TestRun_MarkdownInjection_Metacharacters(t *testing.T) {
	// Build hostile XML with metacharacters that XML-escape cleanly.
	hostile := `<?xml version="1.0"?>
<testsuites>
  <testsuite name="suite *bold* _em_ [link] &lt;tag&gt; &amp; end">
    <testcase classname="cls *star*" name="test | pipe" time="0"></testcase>
  </testsuite>
</testsuites>`
	body := runFixture(t, hostile, "markdown", false)

	// Suite/test names live inside <summary> — HTML-escaped.
	if !strings.Contains(body, `&lt;tag&gt;`) {
		t.Errorf("suite name <tag> not HTML-escaped inside summary\n%s", body)
	}
	if !strings.Contains(body, `&amp; end`) {
		t.Errorf("suite name & not HTML-escaped inside summary\n%s", body)
	}
}

func TestRun_MarkdownAmpersandInName(t *testing.T) {
	xml := `<?xml version="1.0"?>
<testsuites>
  <testsuite name="Tom &amp; Jerry">
    <testcase classname="x" name="Cat &amp; mouse" time="0"></testcase>
  </testsuite>
</testsuites>`
	body := runFixture(t, xml, "markdown", false)
	if !strings.Contains(body, `Tom &amp; Jerry`) {
		t.Errorf("suite ampersand not HTML-escaped\n%s", body)
	}
	if !strings.Contains(body, `Cat &amp; mouse`) {
		t.Errorf("testcase ampersand not HTML-escaped\n%s", body)
	}
}

// Note: XML 1.0 rejects raw C0 control characters in any context, so
// the equivalent of cmd/bdd-report's TestRun_MarkdownControlCharactersStripped
// (which embeds control bytes via JSON \uNNNN escapes) is unreachable
// here — the XML parser would reject the input before sanitiseLine
// runs. Function-level coverage of the helper is in TestSanitiseLine
// below.

func TestRun_MarkdownErrorContainingTripleBacktick(t *testing.T) {
	xml := `<?xml version="1.0"?>
<testsuites>
  <testsuite name="s">
    <testcase classname="x" name="t" time="0">
      <failure message="m">before ` + "```" + ` after</failure>
    </testcase>
  </testsuite>
</testsuites>`
	body := runFixture(t, xml, "markdown", false)
	if !strings.Contains(body, "````") {
		t.Errorf("fence not extended past 3 backticks\n%s", body)
	}
	if !strings.Contains(body, "before ``` after") {
		t.Errorf("inner ``` corrupted by escaping\n%s", body)
	}
}

func TestRun_MarkdownErrorContainingFourBackticks(t *testing.T) {
	xml := `<?xml version="1.0"?>
<testsuites>
  <testsuite name="s">
    <testcase classname="x" name="t" time="0">
      <failure message="m">wrap ` + "````" + ` text</failure>
    </testcase>
  </testsuite>
</testsuites>`
	body := runFixture(t, xml, "markdown", false)
	if !strings.Contains(body, "`````") {
		t.Errorf("fence not extended to 5 backticks\n%s", body)
	}
	if !strings.Contains(body, "wrap ```` text") {
		t.Errorf("inner ```` corrupted\n%s", body)
	}
}

func TestFenceForError_DirectCounts(t *testing.T) {
	cases := map[string]int{
		"":           3,
		"no ticks":   3,
		"one `":      3,
		"two ``":     3,
		"three ```":  4,
		"four ````":  5,
		"five `````": 6,
		"mixed ` ``": 3,
	}
	for in, want := range cases {
		got := fenceForError(in)
		if len(got) != want {
			t.Errorf("fenceForError(%q): len=%d, want %d (got %q)", in, len(got), want, got)
		}
	}
}

func TestRun_MarkdownOnlyFailures(t *testing.T) {
	body := runFixture(t, fixtureJUnitXML, "markdown", true)

	for _, want := range []string{
		`# JUnit report — core`,
		`Showing only failed and errored tests`,
		`TestBrokenPath`,
		`TestExploded`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("only-failures missing %q\n%s", want, body)
		}
	}
	if strings.Contains(body, `TestHappyPath`) {
		t.Errorf("only-failures included passing test")
	}
	if strings.Contains(body, `TestSkipped`) {
		t.Errorf("only-failures included skipped test")
	}
}

func TestRun_MarkdownOnlyFailures_AllGreen(t *testing.T) {
	xml := `<?xml version="1.0"?>
<testsuites>
  <testsuite name="x">
    <testcase classname="x" name="passes" time="0"></testcase>
  </testsuite>
</testsuites>`
	body := runFixture(t, xml, "markdown", true)
	if !strings.Contains(body, `_No failed or errored tests in this run._`) {
		t.Errorf("only-failures all-green placeholder missing\n%s", body)
	}
}

// TestRun_MarkdownStepSummarySizeBudget synthesises many failing suites
// to push output past the step-summary budget and asserts the
// truncation footer fires.
func TestRun_MarkdownStepSummarySizeBudget(t *testing.T) {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0"?>`)
	b.WriteString("<testsuites>")
	longName := strings.Repeat("name-segment-", 60)
	longError := strings.Repeat("stacktrace line ", 50)
	const n = 800
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b,
			`<testsuite name="suite-%d-%s"><testcase classname="x" name="test-%s-%d" time="0">`+
				`<failure message="m">%s frame %d</failure></testcase></testsuite>`,
			i, longName, longName, i, longError, i)
	}
	b.WriteString("</testsuites>")

	body := runFixture(t, b.String(), "markdown", true)

	if !strings.Contains(body, `Output truncated`) {
		t.Errorf("expected truncation footer in oversized step-summary output (got %d bytes)", len(body))
	}
	if len(body) > stepSummaryByteBudget+50000 {
		t.Errorf("step-summary output %d bytes exceeds budget by more than 50KiB", len(body))
	}
}

// TestRun_MarkdownEmptySuiteAndTestcase: suite without testcases,
// testcase with no body, suite without name.
func TestRun_MarkdownEmptySuiteAndTestcase(t *testing.T) {
	xml := `<?xml version="1.0"?>
<testsuites>
  <testsuite name=""></testsuite>
  <testsuite name="x"><testcase classname="" name="" time="0"></testcase></testsuite>
</testsuites>`
	body := runFixture(t, xml, "markdown", false)

	if !strings.Contains(body, `(unnamed suite)`) {
		t.Errorf("empty suite fallback missing\n%s", body)
	}
	if !strings.Contains(body, `(unnamed test)`) {
		t.Errorf("empty testcase fallback missing\n%s", body)
	}
}

// TestRun_MarkdownNoTestsEmptyRender: zero tests => render with note,
// not error.
func TestRun_MarkdownNoTestsEmptyRender(t *testing.T) {
	xml := `<?xml version="1.0"?><testsuites></testsuites>`
	body := runFixture(t, xml, "markdown", false)
	if !strings.Contains(body, `No tests were executed`) {
		t.Errorf("zero-tests note missing\n%s", body)
	}
}

func TestRun_HTMLNoTestsEmptyRender(t *testing.T) {
	xml := `<?xml version="1.0"?><testsuites></testsuites>`
	body := runFixture(t, xml, "html", false)
	if !strings.Contains(body, `No tests were executed`) {
		t.Errorf("zero-tests note missing in HTML\n%s", body[:min(800, len(body))])
	}
}

// TestRun_MarkdownDetailsBlankLineInvariant verifies the blank-line
// rule around </summary> — required by GFM for markdown to parse
// inside <details>.
func TestRun_MarkdownDetailsBlankLineInvariant(t *testing.T) {
	body := runFixture(t, fixtureJUnitXML, "markdown", false)

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

// TestMarkdownOutput_ValidGFM is a smoke test: rendered markdown must
// parse cleanly through goldmark with GFM extensions.
func TestMarkdownOutput_ValidGFM(t *testing.T) {
	body := runFixture(t, fixtureJUnitXML, "markdown", false)

	md := goldmark.New(goldmark.WithExtensions(extension.GFM))
	reader := text.NewReader([]byte(body))
	doc := md.Parser().Parse(reader, parser.WithContext(parser.NewContext()))
	if doc == nil {
		t.Fatal("goldmark returned nil document — fundamental parse failure")
	}
	if doc.ChildCount() == 0 {
		t.Errorf("goldmark parsed an empty document — markdown produced no recognisable blocks")
	}
}

func TestSanitiseLine(t *testing.T) {
	cases := map[string]string{
		"":                    "",
		"plain":               "plain",
		"with\nnewline":       "with newline",
		"with\r\ncrlf":        "with crlf",
		"tabs\there":          "tabs here",
		"NULs\x00inside":      "NULs inside",
		"   pad   ":           "pad",
		"\x1b[31mansi\x1b[0m": "[31mansi [0m",
		"multi\n\n\nspaces":   "multi spaces",
	}
	for in, want := range cases {
		if got := sanitiseLine(in); got != want {
			t.Errorf("sanitiseLine(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEscapeMarkdown_Coverage(t *testing.T) {
	for i := 0; i < len(mdSpecial); i++ {
		c := mdSpecial[i]
		in := string(c) + "x"
		want := `\` + in
		if got := escapeMarkdown(in); got != want {
			t.Errorf("escapeMarkdown(%q) = %q, want %q", in, got, want)
		}
	}
	if got := escapeMarkdown("abc"); got != "abc" {
		t.Errorf("escapeMarkdown plain text mangled: %q", got)
	}
}

// ---- JUnit XML parsing -------------------------------------------------

// TestParseJUnit_MultiSuiteWrapper covers the wrapped <testsuites>
// root (gotestsum's format).
func TestParseJUnit_MultiSuiteWrapper(t *testing.T) {
	body := runFixture(t, fixtureJUnitXML, "html", false)
	if !strings.Contains(body, `4 tests`) {
		t.Errorf("multi-suite wrapper: count missing\n%s", body[:min(400, len(body))])
	}
}

// TestParseJUnit_SingleSuiteRoot covers a bare <testsuite> root.
func TestParseJUnit_SingleSuiteRoot(t *testing.T) {
	xml := `<?xml version="1.0"?>
<testsuite name="x" tests="1" failures="0">
  <testcase classname="x" name="solo" time="0"></testcase>
</testsuite>`
	body := runFixture(t, xml, "html", false)
	if !strings.Contains(body, `1 tests`) {
		t.Errorf("bare testsuite root not parsed\n%s", body[:min(400, len(body))])
	}
	if !strings.Contains(body, `solo`) {
		t.Errorf("testcase from bare suite not rendered\n%s", body[:min(400, len(body))])
	}
}

// TestParseJUnit_ErrorVsFailure verifies that <error> and <failure>
// produce distinct rendered states and counts.
func TestParseJUnit_ErrorVsFailure(t *testing.T) {
	body := runFixture(t, fixtureJUnitXML, "html", false)

	// Both badge counts must appear.
	if !strings.Contains(body, `1 failed</div>`) {
		t.Errorf("failed badge missing\n%s", body[:min(800, len(body))])
	}
	if !strings.Contains(body, `1 errored</div>`) {
		t.Errorf("errored badge missing\n%s", body[:min(800, len(body))])
	}
	// And distinct data-status attributes.
	if !strings.Contains(body, `data-status="failed"`) {
		t.Errorf("failed status attribute missing")
	}
	if !strings.Contains(body, `data-status="errored"`) {
		t.Errorf("errored status attribute missing")
	}
}

func TestParseJUnit_SkippedRender(t *testing.T) {
	body := runFixture(t, fixtureJUnitXML, "html", false)
	if !strings.Contains(body, `data-status="skipped"`) {
		t.Errorf("skipped status attribute missing")
	}
	if !strings.Contains(body, `awaiting feature flag`) {
		t.Errorf("skipped message missing")
	}
}

// failingWriter returns an error after the first n bytes have been
// written. Used by TestMDWriter_StickyError.
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

func TestMDWriter_StickyError(t *testing.T) {
	fw := &failingWriter{limit: 5}
	w := newMDWriter(fw)
	big := strings.Repeat("a", 8192)
	w.writeString(big)
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
	if err2 := w.flush(); err2 == nil {
		t.Error("second flush returned nil — sticky-error property violated")
	}
}

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

func TestStatusIcon_AllStatuses(t *testing.T) {
	cases := map[string]string{
		"passed":  "✓",
		"failed":  "✗",
		"errored": "⚠",
		"skipped": "-",
		"unknown": "?",
		"":        "?",
	}
	for in, want := range cases {
		if got := statusIcon(in); got != want {
			t.Errorf("statusIcon(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHeaderName_Composition(t *testing.T) {
	cases := []struct {
		name      string
		suite     string
		schemaSrc string
		want      string
	}{
		{"both_differ", "core", "github.com/x/y", "core (github.com/x/y)"},
		{"both_same", "core", "core", "core"},
		{"suite_only", "core", "", "core"},
		{"schema_only", "", "github.com/x/y", "github.com/x/y"},
		{"both_empty", "", "", "(unnamed)"},
		{"trim_whitespace", "  core  ", "  src  ", "core (src)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := summary{Suite: tc.suite, SchemaSrc: tc.schemaSrc}
			if got := s.headerName(); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestPickFailureBody_StderrFallback verifies that a testcase with no
// <failure>/<error>/<skipped> child but a populated <system-err>
// (e.g. a panic that killed a goroutine before t.Fatal could capture)
// surfaces the stderr text in the rendered body — this is the most
// diagnostic part of a panic-driven failure.
func TestPickFailureBody_StderrFallback(t *testing.T) {
	xml := `<?xml version="1.0"?>
<testsuites>
  <testsuite name="x">
    <testcase classname="x" name="paniced" time="0.001">
      <system-err>fatal: runtime error: invalid memory address
goroutine 1 [running]:
sample.foo(0x0)
        /src/sample/foo.go:42 +0x80</system-err>
    </testcase>
  </testsuite>
</testsuites>`
	body := runFixture(t, xml, "html", false)
	if !strings.Contains(body, `fatal: runtime error`) {
		t.Errorf("system-err fallback missing from HTML\n%s", body[:min(800, len(body))])
	}
	if !strings.Contains(body, `goroutine 1 [running]`) {
		t.Errorf("system-err stack trace missing\n%s", body[:min(800, len(body))])
	}

	mdBody := runFixture(t, xml, "markdown", false)
	if !strings.Contains(mdBody, `fatal: runtime error`) {
		t.Errorf("system-err fallback missing from Markdown\n%s", mdBody)
	}
}

// TestPickFailureBody_StdoutFallback verifies the stdout fallback when
// even system-err is empty.
func TestPickFailureBody_StdoutFallback(t *testing.T) {
	c := &testCase{Stdout: "stdout content"}
	if got := pickFailureBody(c); got != "stdout content" {
		t.Errorf("got %q, want %q", got, "stdout content")
	}
}

// TestParseDurationSeconds_NegativeAndInvalid verifies that
// pathological JUnit time values resolve to 0 ms instead of leaking
// into the rendered duration.
func TestParseDurationSeconds_NegativeAndInvalid(t *testing.T) {
	cases := map[string]int64{
		"":      0,
		"0":     0,
		"0.5":   500,
		"1.5":   1500,
		"-0.5":  0, // clock skew
		"-1":    0, // negative
		"NaN":   0, // unparseable
		"abc":   0, // garbage
		"1e308": 0, // scientific notation rejected by time.ParseDuration
	}
	for in, want := range cases {
		if got := parseDurationSeconds(in); got != want {
			t.Errorf("parseDurationSeconds(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestDurationFmt(t *testing.T) {
	cases := map[int64]string{
		0:    "< 1 ms",
		1:    "1 ms",
		42:   "42 ms",
		1500: "1500 ms",
	}
	for in, want := range cases {
		if got := durationFmt(in); got != want {
			t.Errorf("durationFmt(%d) = %q, want %q", in, got, want)
		}
	}
}
