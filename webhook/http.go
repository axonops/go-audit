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

package webhook

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
	"time"

	"github.com/axonops/audit"
)

// sanitiseClientError returns a copy of err with any embedded
// [*url.Error] stripped of its URL — the URL is replaced with the
// sanitised scheme+host form to prevent path/query/fragment tokens
// (Slack, Datadog, Splunk) from leaking into diagnostic logs.
// Non-*url.Error values pass through unchanged.
//
// This is the transport-level counterpart of [Config.String]'s
// sanitisation: Config.String handles direct logging of the Config
// value; this handles indirect logging via errors returned from
// http.Client.Do.
func sanitiseClientError(err error) error {
	var uerr *url.Error
	if !errors.As(err, &uerr) {
		return err
	}
	// Reconstruct *url.Error with the URL replaced. Preserve Op and
	// the underlying Err so observability is unchanged.
	return &url.Error{
		Op:  uerr.Op,
		URL: sanitizeURLForLog(uerr.URL),
		Err: uerr.Err,
	}
}

// doPostWithRetry attempts HTTP POST with exponential backoff retry.
func (w *Output) doPostWithRetry(ctx context.Context, batch [][]byte) {
	start := time.Now()
	body := buildNDJSON(batch)
	logger := w.logger
	om := w.outputMetrics

	for attempt := range w.maxRetries {
		if attempt > 0 {
			backoff := webhookBackoff(attempt)
			timer := time.NewTimer(backoff)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				w.recordDrop(len(batch))
				return
			}
		}

		retryable, err := w.doPost(ctx, body)
		if err == nil {
			w.recordSuccess(len(batch), time.Since(start))
			return
		}

		if !retryable {
			logger.Error("audit: output webhook: non-retryable error",
				"error", sanitiseClientError(err),
				"batch_size", len(batch))
			om.RecordError()
			w.recordDrop(len(batch))
			return
		}

		logger.Warn("audit: output webhook: retrying",
			"attempt", attempt+1,
			"max_retries", w.maxRetries,
			"error", sanitiseClientError(err))
		om.RecordRetry(attempt + 1) // 1-indexed: attempt+1 = first retry
	}

	// All retries exhausted.
	logger.Error("audit: output webhook: retries exhausted, dropping batch",
		"batch_size", len(batch),
		"max_retries", w.maxRetries)
	om.RecordError()
	w.recordDrop(len(batch))
}

// drainAndClose consumes up to a cap worth of the response body and
// closes it. The cap is tight on 3xx responses because our
// CheckRedirect hook rejects redirects — the body is only useful for
// diagnostic logging and an attacker-controlled endpoint returning a
// 3xx with a large body would otherwise consume maxResponseDrain per
// retry (#484). 2xx/4xx/5xx responses keep the larger 1 MiB budget
// because their bodies may carry useful diagnostic information.
// Tolerates a nil resp as defence-in-depth against future refactors
// that might register the defer before the client.Do error check.
func drainAndClose(resp *http.Response) {
	const (
		maxResponseDrain = 1 << 20 // 1 MiB on 2xx/4xx/5xx
		maxRedirectDrain = 4 << 10 // 4 KiB on 3xx
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

// doPost sends a single HTTP POST. Returns (retryable, error).
// nil error means success (2xx). Redirect rejections and 4xx are
// non-retryable. 5xx, 429, and network errors are retryable.
func (w *Output) doPost(ctx context.Context, body []byte) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(body))
	if err != nil {
		return false, fmt.Errorf("audit/webhook: request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-ndjson")
	for k, v := range w.headers {
		req.Header.Set(k, v)
	}

	resp, err := w.client.Do(req)
	if err != nil {
		// Redirect rejection is non-retryable.
		if errors.Is(err, errRedirectBlocked) {
			return false, fmt.Errorf("audit/webhook: redirect blocked: %w", err)
		}
		// Context cancellation is non-retryable.
		if ctx.Err() != nil {
			return false, fmt.Errorf("audit/webhook: cancelled: %w", err)
		}
		// Network errors are retryable.
		return true, fmt.Errorf("audit/webhook: request failed: %w", err)
	}
	defer drainAndClose(resp)

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return false, nil // success
	}

	if resp.StatusCode == 429 || resp.StatusCode >= 500 {
		return true, fmt.Errorf("audit/webhook: server error %d", resp.StatusCode)
	}

	// 4xx (not 429), and any 3xx that bypassed redirect-follow
	// (no Location header, 300, 304, ...) — client error, not retryable.
	return false, fmt.Errorf("audit/webhook: client error %d", resp.StatusCode)
}

// recordSuccess records successful delivery metrics for a batch.
func (w *Output) recordSuccess(batchSize int, dur time.Duration) {
	// Record the wall-clock delivery timestamp for #753
	// LastDeliveryReporter. Updated AFTER an HTTP 2xx response
	// returns so retry-exhausted batches leave the timestamp frozen.
	w.lastDeliveryNanos.Store(time.Now().UnixNano())
	w.outputMetrics.RecordFlush(batchSize, dur)
	if w.metrics != nil {
		name := w.Name()
		for range batchSize {
			w.metrics.RecordDelivery(name, audit.EventSuccess)
		}
	}
}

// recordDrop records dropped events in metrics. Called when retries
// are exhausted or a non-retryable error occurs.
// RecordDrop is called per dropped event on OutputMetrics.
// RecordDelivery(name, audit.EventError) is called per dropped event on core Metrics.
func (w *Output) recordDrop(count int) {
	name := w.Name()
	for range count {
		w.outputMetrics.RecordDrop()
		if w.metrics != nil {
			w.metrics.RecordDelivery(name, audit.EventError)
		}
	}
}

// buildNDJSON concatenates event bytes as newline-delimited JSON.
// Events from the formatter already have a trailing newline.
func buildNDJSON(events [][]byte) []byte {
	var n int
	for _, e := range events {
		n += len(e)
		if len(e) == 0 || e[len(e)-1] != '\n' {
			n++ // need to add newline
		}
	}
	buf := make([]byte, 0, n)
	for _, e := range events {
		buf = append(buf, e...)
		if len(e) == 0 || e[len(e)-1] != '\n' {
			buf = append(buf, '\n')
		}
	}
	return buf
}

// webhookBackoff returns a jittered exponential backoff duration
// for webhook retry: 100ms * 2^attempt with [0.5, 1.0) jitter,
// capped at 5s.
//
// SYNC: similar implementations in syslog/reconnect.go
// (backoffDuration, 30s cap, persistent TCP reconnection) and
// loki/http.go (lokiBackoff, identical 5s cap, per-request HTTP).
// The helper is unexported and cannot be shared across Go modules.
// Keep the three copies in sync when making changes (#542).
func webhookBackoff(attempt int) time.Duration {
	const (
		base    = 100 * time.Millisecond
		maxBack = 5 * time.Second
	)
	exp := float64(attempt)
	if exp > 20 {
		exp = 20
	}
	d := base * time.Duration(math.Pow(2, exp))
	if d > maxBack {
		d = maxBack
	}
	var b [1]byte
	if _, err := rand.Read(b[:]); err == nil {
		jitter := 0.5 + float64(b[0])/512.0
		d = time.Duration(float64(d) * jitter)
	}
	return d
}
