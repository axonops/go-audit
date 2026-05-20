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

package splunk

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// isTLSError returns true when err is a TLS-handshake or
// certificate-verification failure. These are non-retryable: a
// mis-configured cert chain won't fix itself on the next attempt;
// retrying just exhausts the budget without making progress.
func isTLSError(err error) bool {
	if err == nil {
		return false
	}
	var certErr *x509.UnknownAuthorityError
	if errors.As(err, &certErr) {
		return true
	}
	var hostErr *x509.HostnameError
	if errors.As(err, &hostErr) {
		return true
	}
	var invalidErr x509.CertificateInvalidError
	if errors.As(err, &invalidErr) {
		return true
	}
	var tlsErr *tls.RecordHeaderError
	if errors.As(err, &tlsErr) {
		return true
	}
	// String-match for "tls:" / "x509:" prefixes that don't match a
	// concrete type (e.g. some handshake errors). Used as a fallback
	// only.
	msg := err.Error()
	if strings.Contains(msg, "tls: ") || strings.Contains(msg, "x509: ") {
		return true
	}
	return false
}

// Response-body drain limits. /ack carries the largest expected body
// (an ackID map can contain hundreds of entries); /health and /event
// and /raw return small {"text":"...","code":N} envelopes.
const (
	maxResponseDrainEventOrRaw = 64 << 10 // 64 KiB
	maxResponseDrainHealth     = 64 << 10 // 64 KiB
	maxResponseDrainAck        = 1 << 20  // 1 MiB
	maxRedirectDrain           = 4 << 10  // 4 KiB
)

// checkResponseSize returns true when the server's advertised
// Content-Length is within the per-endpoint limit. A
// `Content-Length: -1` (unknown — typically chunked transfer
// encoding) returns true: the io.LimitReader at the body-read site
// is the load-bearing cap for chunked or unknown-length responses.
// This header check is a fast-fail short-circuit only — it lets
// the client reject a misbehaving server's oversize advertised
// body without allocating the buffer the server expects
// (security-reviewer HIGH-1).
//
// Reusable across endpoints with different limits (PR 2's /ack
// handling uses this with the 1 MiB limit).
func checkResponseSize(resp *http.Response, limit int64) bool {
	if resp == nil {
		return false
	}
	if resp.ContentLength < 0 {
		// Unknown / chunked — LimitReader bounds at the call site.
		return true
	}
	return resp.ContentLength <= limit
}

// Retry-After ceiling. HEC may send arbitrary values; cap to prevent
// server-controlled DoS.
const maxRetryAfter = 5 * time.Minute

// Backoff base + cap. 500ms base, 30s cap matches the issue body's
// `RetryBaseDelay`/`RetryMaxDelay` defaults.
const (
	backoffBase = 500 * time.Millisecond
	backoffMax  = 30 * time.Second
)

// drainAndClose drains up to drainCap bytes of resp.Body and then
// closes it. Tolerates a nil resp as defence-in-depth.
func drainAndClose(resp *http.Response, drainCap int64) {
	if resp == nil {
		return
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		drainCap = maxRedirectDrain
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, drainCap))
	_ = resp.Body.Close()
}

// errRedirectBlocked is returned by the HTTP client's CheckRedirect
// to reject all redirects, preventing SSRF via open redirects.
var errRedirectBlocked = errors.New("audit/splunk: redirects are not followed")

// doPost sends a single HTTP POST to the configured HEC URL. Returns
// (action, statusCode, hecCode, error). On success the action is
// [actionSuccess]; the response body has already been drained and
// closed before return.
func (o *Output) doPost(ctx context.Context, body []byte, compressed bool) (hecAction, int, int, error) {
	u := o.endpointURL
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return actionDrop, 0, 0, fmt.Errorf("audit/splunk: request: %w", err)
	}
	o.applyRequestHeaders(req, compressed)

	resp, err := o.client.Do(req)
	if err != nil {
		if errors.Is(err, errRedirectBlocked) {
			return actionDrop, 0, 0, fmt.Errorf("audit/splunk: redirect blocked: %w", err)
		}
		if ctx.Err() != nil {
			return actionRetry, 0, 0, fmt.Errorf("audit/splunk: cancelled: %w", ctx.Err())
		}
		// TLS handshake errors and cert validation failures are NOT
		// retryable — retrying against a misconfigured cert chain
		// will just exhaust the retry budget without progress (AC
		// 54). The errors.As probe finds a wrapped *tls.RecordHeaderError
		// or x509 verification failure.
		if isTLSError(err) {
			return actionDrop, 0, 0, fmt.Errorf("audit/splunk: TLS error (non-retryable): %w", err)
		}
		return actionRetry, 0, 0, fmt.Errorf("audit/splunk: request failed: %w", err)
	}

	// AC 70 — Content-Length fast-fail. Reject before allocating any
	// buffer when the server advertises a body larger than the cap.
	// Force `resp.Close = true` so the underlying TCP connection is
	// NOT returned to the idle pool — we don't trust this peer for
	// keep-alive after they lied about Content-Length
	// (security-reviewer HIGH-2).
	if !checkResponseSize(resp, maxResponseDrainEventOrRaw) {
		// resp.Close documents intent on the Response object; the
		// load-bearing mechanism that prevents pool reuse is closing
		// Body without draining — net/http's persistConn detects the
		// unread bytes and refuses to return the connection to the
		// idle pool (security-reviewer HIGH-2 / M1).
		resp.Close = true
		_ = resp.Body.Close()
		return actionDrop, resp.StatusCode, 0, fmt.Errorf(
			"audit/splunk: response Content-Length %d exceeds cap %d (non-retryable)",
			resp.ContentLength, int64(maxResponseDrainEventOrRaw))
	}

	// resp.Trailer (populated only after the body is fully consumed)
	// is deliberately not inspected — the drainAndClose path below
	// uses io.LimitReader + io.Discard which never populates trailers
	// into anywhere observable, so there's nothing to strip
	// (security-reviewer MEDIUM-2).
	defer drainAndClose(resp, maxResponseDrainEventOrRaw)

	// Read the response into a bounded buffer so we can parse the
	// HEC code envelope. Caps at 64 KiB.
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseDrainEventOrRaw))
	hecCode, _ := parseHECCode(bodyBytes)

	act := classify(resp.StatusCode, hecCode)
	if act == actionSuccess {
		return act, resp.StatusCode, hecCode, nil
	}
	if act == actionCapacityWarn {
		return act, resp.StatusCode, hecCode, nil
	}
	if act == actionRetry {
		o.retryHint = parseRetryAfter(resp.Header.Get("Retry-After"))
		return act, resp.StatusCode, hecCode, &hecError{
			HTTPStatus: resp.StatusCode,
			Code:       hecCode,
			Action:     act,
			Text:       sanitizeText(string(bodyBytes)),
		}
	}
	// actionStop / actionDrop / actionAckDisabled — non-retryable.
	return act, resp.StatusCode, hecCode, &hecError{
		HTTPStatus: resp.StatusCode,
		Code:       hecCode,
		Action:     act,
		Text:       sanitizeText(string(bodyBytes)),
	}
}

// applyRequestHeaders sets all HTTP headers on the request. Consumer
// headers are applied first; library-managed headers override them
// (defence in depth — config validation already blocks restricted
// header names).
func (o *Output) applyRequestHeaders(req *http.Request, compressed bool) {
	for k, v := range o.cfg.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", o.cfg.UserAgent)
	if compressed {
		req.Header.Set("Content-Encoding", "gzip")
	}
	// Auth — must never be overridable by consumer headers.
	req.Header.Set("Authorization", "Splunk "+o.cfg.Token)
}

// parseHECCode decodes a HEC response body and returns its `code`
// field. Returns 0 on parse failure. Bounded by the caller's
// io.LimitReader.
func parseHECCode(body []byte) (int, error) {
	if len(body) == 0 {
		return 0, nil
	}
	var resp hecResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		// Malformed JSON — return 0 and let classify() rely on the
		// HTTP status alone.
		return 0, err
	}
	return resp.Code, nil
}

// parseRetryAfter parses a Retry-After header value. Accepts
// delta-seconds (integer) and HTTP-date forms. Returns 0 if absent,
// unparseable, non-positive, or describing a past date. Caps the
// result at [maxRetryAfter] to prevent server-controlled DoS.
func parseRetryAfter(val string) time.Duration {
	if val == "" {
		return 0
	}
	// Delta-seconds form (the common case).
	if secs, err := strconv.Atoi(val); err == nil {
		if secs <= 0 {
			return 0
		}
		d := time.Duration(secs) * time.Second
		if d > maxRetryAfter {
			return maxRetryAfter
		}
		return d
	}
	// HTTP-date form: RFC 1123, RFC 850, ANSI C asctime.
	for _, layout := range []string{time.RFC1123, time.RFC850, time.ANSIC} {
		if t, err := time.Parse(layout, val); err == nil {
			d := time.Until(t)
			if d <= 0 {
				return 0
			}
			if d > maxRetryAfter {
				return maxRetryAfter
			}
			return d
		}
	}
	// Unparseable — fall back to backoff.
	return 0
}

// splunkBackoff returns a jittered exponential backoff duration:
// backoffBase * 2^attempt with [0.5, 1.0) jitter, capped at backoffMax.
//
// SYNC: matches the pattern at webhook/http.go and loki/http.go
// (different cap/base values). The helper is unexported and cannot
// be shared across Go modules. Keep in sync when refining (#542).
func splunkBackoff(attempt int) time.Duration {
	exp := float64(attempt)
	if exp > 20 {
		exp = 20
	}
	d := backoffBase * time.Duration(math.Pow(2, exp))
	if d > backoffMax {
		d = backoffMax
	}
	var b [1]byte
	if _, err := rand.Read(b[:]); err == nil {
		jitter := 0.5 + float64(b[0])/512.0 // [0.5, 1.0)
		d = time.Duration(float64(d) * jitter)
	}
	return d
}

// sanitizeText strips control characters from a HEC response text
// before it appears in a log line. Iterates BY BYTE (not by rune)
// so multi-byte UTF-8 sequences have every byte examined — a rune-
// iteration would skip past the trailing bytes of a multi-byte
// character, leaving them in the output. Caps the result at 256
// bytes to bound log line length.
func sanitizeText(s string) string {
	if len(s) > 256 {
		s = s[:256]
	}
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\t' || c == ' ' || (c >= 0x21 && c <= 0x7e) {
			b = append(b, c)
		} else {
			b = append(b, '?')
		}
	}
	return string(b)
}
