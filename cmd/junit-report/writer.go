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

// This file is BYTE-IDENTICAL with cmd/junit-report/writer.go.
// `make check-report-parity` enforces this — change one, change both.

package main

import (
	"bufio"
	"fmt"
	"io"
)

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
