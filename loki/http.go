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

package loki

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/axonops/audit"
)

// sanitiseClientError returns a copy of err with any embedded
// [*url.Error] stripped of its URL — the URL is replaced with the
// sanitised scheme+host form to prevent path/query/fragment tokens
// (tenant IDs, bearer tokens) from leaking into diagnostic logs.
// Non-*url.Error values pass through unchanged.
//
// Mirror of webhook.sanitiseClientError — intentional duplication
// per #542 to keep sub-modules self-contained.
func sanitiseClientError(err error) error {
	var uerr *url.Error
	if !errors.As(err, &uerr) {
		return err
	}
	return &url.Error{
		Op:  uerr.Op,
		URL: sanitizeURLForLog(uerr.URL),
		Err: uerr.Err,
	}
}

// Backoff constants for retry logic. Hardcoded to match the webhook
// output pattern — MaxRetries is the user's control surface.
const (
	backoffBase = 100 * time.Millisecond
	backoffMax  = 5 * time.Second
)

// maxRetryAfter caps the server-provided Retry-After header to prevent
// a malicious server from forcing unbounded delay.
const maxRetryAfter = 30 * time.Second

// maxResponseBody limits the response body drained after each request,
// preventing a malicious server from forcing unbounded memory allocation.
const maxResponseBody = 64 << 10 // 64 KiB

// doPostWithRetry attempts HTTP POST with exponential backoff retry.
// On success, delivery metrics are recorded. On retries exhausted or
// non-retryable errors, drop metrics are recorded. This method is
// called from flush(), which runs in the single batchLoop goroutine.
// The body []byte comes from maybeCompress() and points into Output
// buffers that are safe to use because flush() is synchronous.
func (o *Output) doPostWithRetry(ctx context.Context, body []byte, batchSize int, compressed bool) {
	start := time.Now()
	logger := o.logger
	o.retryHint = 0 // clear stale hint from previous batch

	for attempt := range o.cfg.MaxRetries {
		if attempt > 0 {
			backoff := lokiBackoff(attempt)

			// Respect Retry-After from a 429 if it exceeds computed backoff.
			// retryHint is set by the previous doPost call.
			if o.retryHint > backoff {
				backoff = o.retryHint
			}
			o.retryHint = 0

			t := time.NewTimer(backoff)
			select {
			case <-t.C:
			case <-ctx.Done():
				t.Stop()
				o.recordDrop(batchSize)
				return
			}
		}

		retryable, _, err := o.doPost(ctx, body, compressed)
		if err == nil {
			o.recordSuccess(batchSize, time.Since(start))
			return
		}

		if !retryable {
			logger.Error("audit/loki: non-retryable error",
				"error", sanitiseClientError(err),
				"batch_size", batchSize)
			o.recordError()
			o.recordDrop(batchSize)
			return
		}

		o.recordRetry(attempt + 1)
		logger.Warn("audit/loki: retryable error",
			"attempt", attempt+1,
			"max_retries", o.cfg.MaxRetries,
			"error", sanitiseClientError(err))
	}

	// All retries exhausted.
	logger.Error("audit/loki: retries exhausted, dropping batch",
		"batch_size", batchSize,
		"max_retries", o.cfg.MaxRetries)
	o.recordDrop(batchSize)
}

// drainAndClose consumes up to a cap worth of the response body and
// closes it. The cap is tight on 3xx responses because CheckRedirect
// rejects redirects — the body is only useful for diagnostic logging
// and an attacker-controlled endpoint returning a 3xx with a large
// body would otherwise consume maxResponseBody per retry (#484).
// 2xx/4xx/5xx responses keep the larger 64 KiB budget because their
// bodies may carry useful diagnostic information. Tolerates a nil
// resp as defence-in-depth against future refactors that might
// register the defer before the client.Do error check.
func drainAndClose(resp *http.Response) {
	const (
		maxResponseDrain = maxResponseBody // 64 KiB on 2xx/4xx/5xx
		maxRedirectDrain = 4 << 10         // 4 KiB on 3xx
	)
	if resp == nil {
		return
	}
	drainCap := int64(maxResponseDrain)
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		drainCap = maxRedirectDrain
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, drainCap))
	_ = resp.Body.Close()
}

// doPost sends a single HTTP POST to the Loki push API. Returns
// (retryable, error). A nil error means success (2xx). Redirect
// rejections and 4xx (except 429) are non-retryable. 5xx, 429, and
// network errors are retryable.
func (o *Output) doPost(ctx context.Context, body []byte, compressed bool) (retryable bool, statusCode int, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return false, 0, fmt.Errorf("audit/loki: request: %w", err)
	}

	o.applyRequestHeaders(req, compressed)

	resp, err := o.client.Do(req)
	if err != nil {
		if errors.Is(err, errRedirectBlocked) {
			return false, 0, fmt.Errorf("audit/loki: redirect blocked: %w", err)
		}
		if ctx.Err() != nil {
			return false, 0, fmt.Errorf("audit/loki: cancelled: %w", ctx.Err())
		}
		return true, 0, fmt.Errorf("audit/loki: request failed: %w", err)
	}
	defer drainAndClose(resp)

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return false, resp.StatusCode, nil // success
	}

	if resp.StatusCode == 429 {
		o.retryHint = parseRetryAfter(resp.Header.Get("Retry-After"))
		return true, 429, fmt.Errorf("audit/loki: rate limited (429)")
	}

	if resp.StatusCode >= 500 {
		return true, resp.StatusCode, fmt.Errorf("audit/loki: server error %d", resp.StatusCode)
	}

	// 4xx (not 429), and any 3xx that bypassed redirect-follow
	// (no Location header, 300, 304, ...) — client error, not retryable.
	return false, resp.StatusCode, fmt.Errorf("audit/loki: client error %d", resp.StatusCode)
}

// applyRequestHeaders sets all HTTP headers on the request. Consumer
// headers are applied first; library-managed headers override them
// (defence in depth — config validation already blocks restricted
// header names).
func (o *Output) applyRequestHeaders(req *http.Request, compressed bool) {
	// Consumer headers first.
	for k, v := range o.cfg.Headers {
		req.Header.Set(k, v)
	}

	// Library-managed headers override — these are non-negotiable.
	req.Header.Set("Content-Type", "application/json")
	if compressed {
		req.Header.Set("Content-Encoding", "gzip")
	}

	// Auth — must never be overridable by consumer headers.
	if o.cfg.BasicAuth != nil {
		req.SetBasicAuth(o.cfg.BasicAuth.Username, o.cfg.BasicAuth.Password)
	} else if o.cfg.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+o.cfg.BearerToken)
	}

	if o.cfg.TenantID != "" {
		req.Header.Set("X-Scope-OrgID", o.cfg.TenantID)
	}
}

// recordSuccess records successful delivery metrics for a batch.
func (o *Output) recordSuccess(batchSize int, dur time.Duration) {
	// Record the wall-clock delivery timestamp for #753
	// LastDeliveryReporter. Updated AFTER the push API returns 2xx
	// so retry-exhausted batches leave the timestamp frozen.
	o.lastDeliveryNanos.Store(time.Now().UnixNano())
	o.outputMetrics.RecordFlush(batchSize, dur)
	if o.metrics != nil {
		name := o.Name()
		for range batchSize {
			o.metrics.RecordDelivery(name, audit.EventSuccess)
		}
	}
}

// recordDrop records dropped events in metrics.
func (o *Output) recordDrop(count int) {
	name := o.Name()
	for range count {
		o.outputMetrics.RecordDrop()
		if o.metrics != nil {
			o.metrics.RecordDelivery(name, audit.EventError)
		}
	}
}

// recordRetry records a retry attempt in output metrics.
func (o *Output) recordRetry(attempt int) {
	o.outputMetrics.RecordRetry(attempt)
}

// recordError records a non-retryable error in output metrics.
func (o *Output) recordError() {
	o.outputMetrics.RecordError()
}

// parseRetryAfter parses a Retry-After header value (delta-seconds
// only). Returns 0 if absent, unparseable, or non-positive. The
// result is capped at maxRetryAfter to prevent server-controlled DoS.
func parseRetryAfter(val string) time.Duration {
	if val == "" {
		return 0
	}
	secs, err := strconv.Atoi(val)
	if err != nil || secs <= 0 {
		return 0
	}
	d := time.Duration(secs) * time.Second
	if d > maxRetryAfter {
		return maxRetryAfter
	}
	return d
}

// lokiBackoff returns a jittered exponential backoff duration:
// 100ms * 2^attempt with [0.5, 1.0) jitter, capped at 5s.
//
// SYNC: identical to webhook/http.go (webhookBackoff, 5s cap).
// Similar to syslog/reconnect.go (backoffDuration, 30s cap,
// persistent TCP reconnection). The helper is unexported and
// cannot be shared across Go modules. Keep the three copies in
// sync when making changes (#542).
func lokiBackoff(attempt int) time.Duration {
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
