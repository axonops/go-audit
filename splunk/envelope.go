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
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// wrapEvent produces a single HEC /event envelope for the given
// already-serialised event JSON. The envelope shape is:
//
//	{"event":<json>,"time":<epoch.ms>,"host":...,"source":...,"sourcetype":...,"index":...,"fields":{...}}
//
// `time` is epoch seconds with millisecond precision, extracted from
// the event's `timestamp` field; on extraction failure it falls back
// to `now`. `index` is omitted from the envelope when empty so HEC
// uses the token's default index. `fields` is populated only when
// [Config.IndexedFields] is non-empty AND the event JSON contains
// matching string fields.
//
// The encoded result is written to dst (reused buffer); dst's
// previous contents are NOT cleared — callers can call wrapEvent in
// sequence to build a concatenated batch.
//
// The function ASSUMES the input is valid JSON — the core formatter
// guarantees this contract, so we do NOT pay for a `json.Valid` scan
// here on the hot path (perf-reviewer HIGH-1).
//
// Returns (fellBack, err): `fellBack` is true when extractTime could
// not parse the event's `timestamp` field and used `now` instead.
// Callers aggregate this across a batch and emit a rate-limited
// diagnostic warning via the dropLimiter pattern (AC 23).
func wrapEvent(dst *bytes.Buffer, cfg *Config, eventJSON []byte, now time.Time) (bool, error) {
	// Probe the event once to extract timestamp + optionally indexed
	// fields. We allocate the probe struct only when IndexedFields is
	// configured; otherwise a narrow `Timestamp any` decode is enough
	// (perf-reviewer HIGH-3).
	timeVal, fellBackToNow := extractTimeWithFallbackFlag(eventJSON, now)
	var fields map[string]string
	if len(cfg.IndexedFields) > 0 {
		fields = extractIndexedFields(eventJSON, cfg.IndexedFields)
	}

	// Build the envelope with encoding/json.Marshal (not Encoder —
	// avoids a per-event Encoder struct alloc; perf-reviewer HIGH-2).
	// `event` is a RawMessage so the consumer's bytes pass through
	// without re-encoding.
	envelope := struct {
		Event      json.RawMessage   `json:"event"`
		Time       float64           `json:"time"`
		Host       string            `json:"host,omitempty"`
		Source     string            `json:"source,omitempty"`
		Sourcetype string            `json:"sourcetype,omitempty"`
		Index      string            `json:"index,omitempty"`
		Fields     map[string]string `json:"fields,omitempty"`
	}{
		Event:      eventJSON,
		Time:       timeVal,
		Host:       cfg.Host,
		Source:     cfg.Source,
		Sourcetype: cfg.Sourcetype,
		Index:      cfg.Index,
	}
	if fields != nil {
		envelope.Fields = fields
	}
	b, err := json.Marshal(envelope)
	if err != nil {
		return false, fmt.Errorf("audit/splunk: encode envelope: %w", err)
	}
	dst.Write(b)
	// One newline between concatenated envelopes — HEC tolerates
	// whitespace; consumers stream-decode by JSON object boundary, so
	// the newline is purely diagnostic (matches a `\n`-separated
	// concatenated JSON form readable with `jq -c .`).
	dst.WriteByte('\n')
	return fellBackToNow, nil
}

// extractTime decodes the event JSON enough to find a top-level
// `timestamp` field and convert it to epoch seconds with millisecond
// precision. Accepts RFC 3339 strings, RFC 3339Nano, and bare numbers
// (interpreted as epoch seconds or epoch milliseconds depending on
// magnitude). Returns `now` epoch on extraction failure — never
// panics, never returns zero. Sets `*fellBack` to true when the
// fallback path was taken so the caller can emit a one-time
// diagnostic warning (AC 23).
//
// Uses a narrow `Timestamp any` struct (not `map[string]any`) so the
// JSON parser short-circuits past every other field. The cost is one
// scan + one small-struct allocation per event.
func extractTime(eventJSON []byte, now time.Time) float64 {
	t, _ := extractTimeWithFallbackFlag(eventJSON, now)
	return t
}

// extractTimeWithFallbackFlag is the warn-aware variant. Returns
// `(epoch, fellBack)`; fellBack=true means the timestamp could not
// be parsed from the event JSON and `now` was substituted.
func extractTimeWithFallbackFlag(eventJSON []byte, now time.Time) (float64, bool) {
	var probe struct {
		Timestamp any `json:"timestamp"`
	}
	if err := json.Unmarshal(eventJSON, &probe); err == nil {
		switch v := probe.Timestamp.(type) {
		case string:
			for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.000Z07:00"} {
				if ts, err := time.Parse(layout, v); err == nil {
					return toEpochMillis(ts), false
				}
			}
		case float64:
			// Bare number — heuristically interpret > 1e12 as
			// milliseconds since the epoch, otherwise seconds.
			if v > 1e12 {
				return v / 1000.0, false
			}
			return v, false
		}
	}
	return toEpochMillis(now), true
}

// toEpochMillis returns epoch seconds with millisecond precision as a
// float — the format HEC documents for the envelope `time` field.
func toEpochMillis(t time.Time) float64 {
	return float64(t.UnixMilli()) / 1000.0
}

// extractIndexedFields decodes the event JSON and returns a flat
// string-only map containing only the named keys that appear at the
// top level with string values. Non-string values are silently
// skipped (HEC requires strings in the `fields` envelope object).
func extractIndexedFields(eventJSON []byte, names []string) map[string]string {
	var probe map[string]any
	if err := json.Unmarshal(eventJSON, &probe); err != nil {
		return nil
	}
	out := make(map[string]string, len(names))
	for _, name := range names {
		v, ok := probe[name]
		if !ok {
			continue
		}
		if s, isStr := v.(string); isStr {
			out[name] = s
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// rawEventLine returns the event JSON followed by a newline so the
// /raw endpoint receives one event per line (NDJSON). Used by the
// /raw batching path.
func rawEventLine(dst *bytes.Buffer, eventJSON []byte) {
	dst.Write(eventJSON)
	if len(eventJSON) == 0 || eventJSON[len(eventJSON)-1] != '\n' {
		dst.WriteByte('\n')
	}
}

// buildRawQueryParams returns the URL query-string used on the /raw
// endpoint to set per-batch metadata. Values are URL-encoded; empty
// values are omitted.
func buildRawQueryParams(cfg *Config) string {
	q := url.Values{}
	if cfg.Sourcetype != "" {
		q.Set("sourcetype", cfg.Sourcetype)
	}
	if cfg.Source != "" {
		q.Set("source", cfg.Source)
	}
	if cfg.Index != "" {
		q.Set("index", cfg.Index)
	}
	if cfg.Host != "" {
		q.Set("host", cfg.Host)
	}
	return q.Encode()
}

// joinRawURL returns the configured base URL with the /services/
// collector/raw path appended and query string from buildRawQueryParams
// attached. Preserves any existing path; preserves http vs https.
func joinRawURL(base string, cfg *Config) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/services/collector/raw"
	u.RawQuery = buildRawQueryParams(cfg)
	return u.String(), nil
}

// joinEventURL returns the configured base URL with the /services/
// collector/event path appended.
func joinEventURL(base string) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/services/collector/event"
	u.RawQuery = ""
	return u.String(), nil
}

// joinHealthURL returns the configured base URL with the /services/
// collector/health path appended.
func joinHealthURL(base string) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/services/collector/health"
	u.RawQuery = ""
	return u.String(), nil
}
