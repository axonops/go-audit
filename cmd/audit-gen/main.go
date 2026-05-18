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

// Package comment lives in doc.go so pkg.go.dev surfaces it on the
// command's landing page.

package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/token"
	"io"
	"os"
	"path/filepath"

	"github.com/axonops/audit"
)

// Exit codes per specification.
const (
	exitSuccess     = 0
	exitInvalidArgs = 1
	exitYAMLError   = 2
	exitWriteError  = 3
)

// version is set by -ldflags at build time.
var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	cfg, code := parseFlags(args, stdout, stderr)
	if code >= 0 {
		return code
	}
	return execute(&cfg, stdout, stderr)
}

// cliConfig holds parsed CLI configuration.
type cliConfig struct {
	input, output, pkg, header string
	standardSetters            string // "all" | "explicit"
	format                     string // "go" | "json-schema" | "cef-template"
	types, fields, categories  bool
	labels, builders           bool
}

// Output formats supported by audit-gen.
const (
	formatGo          = "go"
	formatJSONSchema  = "json-schema"
	formatCEFTemplate = "cef-template"
)

// exitCodeContinue signals that parseFlags completed successfully
// and the caller should proceed with code generation (not exit).
const exitCodeContinue = -1

func parseFlags(args []string, stdout, stderr io.Writer) (cfg cliConfig, exitCode int) { //nolint:gocyclo,cyclop // CLI flag dispatch is naturally branchy; per-flag validations are independent
	fs := flag.NewFlagSet("audit-gen", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		input      = fs.String("input", "", "path to YAML taxonomy file (required)")
		output     = fs.String("output", "", "path to output Go file, or - for stdout (required)")
		pkg        = fs.String("package", "", "Go package name for generated file (required)")
		types      = fs.Bool("types", true, "generate event type constants")
		fields     = fs.Bool("fields", true, "generate field name constants")
		categories = fs.Bool("categories", true, "generate category constants")
		labels     = fs.Bool("labels", true, "generate sensitivity label constants")
		builders   = fs.Bool("builders", true, "generate typed event builder structs")
		header     = fs.String("header", "", "file header (default: auto-generated DO NOT EDIT comment)")
		showVer    = fs.Bool("version", false, "print version and exit")
		stdSetters = fs.String("standard-setters", "all",
			"reserved standard field setters: all (every builder gets every reserved setter) "+
				"| explicit (only taxonomy-declared reserved fields produce setters)")
		format = fs.String("format", formatGo,
			"output format: go (typed Go source for the package, default) "+
				"| json-schema (JSON Schema 2020-12 validator) "+
				"| cef-template (CEF mapping documentation)")
	)

	if err := fs.Parse(args); err != nil {
		return cliConfig{}, exitInvalidArgs
	}

	if *showVer {
		_, _ = fmt.Fprintf(stdout, "audit-gen %s\n", version)
		return cliConfig{}, exitSuccess
	}

	switch *format {
	case formatGo, formatJSONSchema, formatCEFTemplate:
		// valid
	default:
		_, _ = fmt.Fprintf(stderr, "audit-gen: -format=%q invalid (valid: go, json-schema, cef-template)\n", *format)
		return cliConfig{}, exitInvalidArgs
	}

	if *input == "" || *output == "" {
		_, _ = fmt.Fprintln(stderr, "audit-gen: -input and -output are required")
		fs.Usage()
		return cliConfig{}, exitInvalidArgs
	}

	// -package is only required for the Go output format. Schema and
	// CEF artifacts have no Go package binding.
	if *format == formatGo {
		if *pkg == "" {
			_, _ = fmt.Fprintln(stderr, "audit-gen: -package is required for -format=go")
			fs.Usage()
			return cliConfig{}, exitInvalidArgs
		}
		if !token.IsIdentifier(*pkg) {
			_, _ = fmt.Fprintf(stderr, "audit-gen: invalid package name %q\n", *pkg)
			return cliConfig{}, exitInvalidArgs
		}
	}

	if *stdSetters != "all" && *stdSetters != "explicit" {
		_, _ = fmt.Fprintf(stderr, "audit-gen: -standard-setters=%q invalid (valid: all, explicit)\n", *stdSetters)
		return cliConfig{}, exitInvalidArgs
	}

	return cliConfig{
		input: *input, output: *output, pkg: *pkg, header: *header,
		standardSetters: *stdSetters,
		format:          *format,
		types:           *types, fields: *fields, categories: *categories,
		labels: *labels, builders: *builders,
	}, exitCodeContinue
}

func execute(cfg *cliConfig, stdout, stderr io.Writer) int { //nolint:gocyclo,cyclop // format-dispatch + write paths are linear; refactoring to helpers obscures the flow
	// No input-size cap: taxonomy is developer-trusted at both
	// library and CLI boundaries (#646).
	data, err := os.ReadFile(cfg.input)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "audit-gen: read input: %v\n", err)
		return exitYAMLError
	}

	tax, err := audit.ParseTaxonomyYAML(data)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "audit-gen: parse taxonomy: %v\n", err)
		return exitYAMLError
	}

	var buf bytes.Buffer
	switch cfg.format {
	case formatGo:
		opts := generateOptions{
			Package:             cfg.pkg,
			Header:              cfg.header,
			InputFile:           filepath.Base(cfg.input),
			StandardSettersMode: cfg.standardSetters,
			Types:               cfg.types,
			Fields:              cfg.fields,
			Categories:          cfg.categories,
			Labels:              cfg.labels,
			Builders:            cfg.builders,
		}
		if cfg.header != "" {
			opts.InputFile = "" // custom header overrides auto-generated one
		}
		if err := generate(&buf, *tax, opts); err != nil {
			_, _ = fmt.Fprintf(stderr, "audit-gen: generate: %v\n", err)
			return exitWriteError
		}
	case formatJSONSchema:
		if err := generateJSONSchema(&buf, *tax); err != nil {
			_, _ = fmt.Fprintf(stderr, "audit-gen: generate json-schema: %v\n", err)
			return exitWriteError
		}
	case formatCEFTemplate:
		if err := generateCEFTemplate(&buf, *tax); err != nil {
			_, _ = fmt.Fprintf(stderr, "audit-gen: generate cef-template: %v\n", err)
			return exitWriteError
		}
	}

	if cfg.output == "-" {
		if _, err := stdout.Write(buf.Bytes()); err != nil {
			_, _ = fmt.Fprintf(stderr, "audit-gen: write stdout: %v\n", err)
			return exitWriteError
		}
		return exitSuccess
	}

	if err := writeFileAtomic(cfg.output, buf.Bytes()); err != nil {
		_, _ = fmt.Fprintf(stderr, "audit-gen: write output: %v\n", err)
		return exitWriteError
	}

	return exitSuccess
}

// writeFileAtomic writes data to a temp file in the same directory,
// then renames it to the target path. This prevents partial writes.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".audit-gen-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Chmod(tmpPath, 0o644); err != nil { //nolint:gosec // generated Go source files need standard 0644 permissions
		_ = os.Remove(tmpPath)
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename to %s: %w", path, err)
	}
	return nil
}
