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
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractTime_FormatsTable(t *testing.T) {
	now := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)
	nowEpoch := toEpochMillis(now)

	tests := []struct {
		name  string
		input string
		want  float64
	}{
		{
			name:  "RFC3339Nano",
			input: `{"timestamp":"2026-05-20T10:00:00.123456789Z"}`,
			want:  toEpochMillis(time.Date(2026, 5, 20, 10, 0, 0, 123_000_000, time.UTC)),
		},
		{
			name:  "RFC3339 with ms precision",
			input: `{"timestamp":"2026-05-20T10:00:00.123Z"}`,
			want:  toEpochMillis(time.Date(2026, 5, 20, 10, 0, 0, 123_000_000, time.UTC)),
		},
		{
			name:  "RFC3339 without subseconds",
			input: `{"timestamp":"2026-05-20T10:00:00Z"}`,
			want:  toEpochMillis(time.Date(2026, 5, 20, 10, 0, 0, 0, time.UTC)),
		},
		{
			name:  "bare epoch seconds (float)",
			input: `{"timestamp":1779616800.123}`,
			want:  1779616800.123,
		},
		{
			name:  "bare epoch milliseconds (large int)",
			input: `{"timestamp":1779616800123}`,
			want:  1779616800.123,
		},
		{
			name:  "missing timestamp falls back to now",
			input: `{"event_type":"x"}`,
			want:  nowEpoch,
		},
		{
			name:  "garbage timestamp falls back to now",
			input: `{"timestamp":"not-a-date"}`,
			want:  nowEpoch,
		},
		{
			name:  "malformed JSON falls back to now",
			input: `{not-json`,
			want:  nowEpoch,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractTime([]byte(tc.input), now)
			assert.InDelta(t, tc.want, got, 0.001)
		})
	}
}

func TestExtractIndexedFields_StringOnly(t *testing.T) {
	event := []byte(`{"actor_id":"alice","port":8080,"flag":true,"target_id":"user-42","note":null}`)
	got := extractIndexedFields(event, []string{"actor_id", "port", "flag", "target_id", "missing", "note"})
	// Only string-valued top-level fields are extracted.
	want := map[string]string{
		"actor_id":  "alice",
		"target_id": "user-42",
	}
	assert.Equal(t, want, got)
}

func TestExtractIndexedFields_NoMatches_ReturnsNil(t *testing.T) {
	event := []byte(`{"event_type":"x"}`)
	got := extractIndexedFields(event, []string{"missing", "also_missing"})
	assert.Nil(t, got)
}

func TestExtractIndexedFields_MalformedJSON_ReturnsNil(t *testing.T) {
	got := extractIndexedFields([]byte(`{not-json`), []string{"x"})
	assert.Nil(t, got)
}

func TestWrapEvent_ProducesValidEnvelope(t *testing.T) {
	cfg := &Config{
		Host:       "inventory-01",
		Source:     "audit",
		Sourcetype: "axonops:audit",
		Index:      "audit_logs",
	}
	event := []byte(`{"timestamp":"2026-05-20T10:00:00.123Z","event_type":"user_login","actor_id":"alice"}`)
	var buf bytes.Buffer
	_, err := wrapEvent(&buf, cfg, event, time.Now())
	require.NoError(t, err)

	// Decode as a single JSON object.
	var env struct {
		Event      json.RawMessage `json:"event"`
		Time       float64         `json:"time"`
		Host       string          `json:"host"`
		Source     string          `json:"source"`
		Sourcetype string          `json:"sourcetype"`
		Index      string          `json:"index"`
	}
	dec := json.NewDecoder(&buf)
	require.NoError(t, dec.Decode(&env))
	assert.JSONEq(t, string(event), string(env.Event))
	assert.Equal(t, "inventory-01", env.Host)
	assert.Equal(t, "audit", env.Source)
	assert.Equal(t, "axonops:audit", env.Sourcetype)
	assert.Equal(t, "audit_logs", env.Index)
	expected := toEpochMillis(time.Date(2026, 5, 20, 10, 0, 0, 123_000_000, time.UTC))
	assert.InDelta(t, expected, env.Time, 0.001)
}

func TestWrapEvent_IndexedFieldsPopulated(t *testing.T) {
	cfg := &Config{
		Sourcetype:    "axonops:audit",
		IndexedFields: []string{"actor_id", "outcome"},
	}
	event := []byte(`{"actor_id":"alice","outcome":"success","timestamp":"2026-05-20T10:00:00Z"}`)
	var buf bytes.Buffer
	_, err := wrapEvent(&buf, cfg, event, time.Now())
	require.NoError(t, err)

	var env struct {
		Fields map[string]string `json:"fields"`
	}
	require.NoError(t, json.NewDecoder(&buf).Decode(&env))
	assert.Equal(t, "alice", env.Fields["actor_id"])
	assert.Equal(t, "success", env.Fields["outcome"])
}

func TestWrapEvent_ControlCharsInFieldValues_Escaped(t *testing.T) {
	cfg := &Config{Sourcetype: "axonops:audit"}
	// actor_id contains CR/LF/NUL — any of these surviving as raw
	// bytes in the output would be a log-injection primitive
	// (Splunk parsing a forged "FAKE" key in the envelope).
	event := []byte(`{"actor_id":"alice\r\nFAKE:value","timestamp":"2026-05-20T10:00:00Z"}`)
	var buf bytes.Buffer
	_, err := wrapEvent(&buf, cfg, event, time.Now())
	require.NoError(t, err)

	output := buf.String()
	// Raw CR/LF must not appear in the output bytes — encoding/json
	// escapes them. The escape sequence `\r\n` (4 bytes) appears
	// inside the event JSON instead.
	assert.NotContains(t, output, "\r\n")
	// The forged key text appears as a value of `actor_id`, not as
	// its own JSON key — stream-decoder confirms.
	var env struct {
		Event json.RawMessage `json:"event"`
	}
	require.NoError(t, json.NewDecoder(strings.NewReader(output)).Decode(&env))
	var inner map[string]any
	require.NoError(t, json.Unmarshal(env.Event, &inner))
	assert.Equal(t, "alice\r\nFAKE:value", inner["actor_id"])
	_, hasForgedKey := inner["FAKE"]
	assert.False(t, hasForgedKey, "FAKE key must NOT appear in decoded event — control-char injection blocked")
}

func TestWrapEvent_UnicodePreserved(t *testing.T) {
	cfg := &Config{Sourcetype: "axonops:audit"}
	event := []byte(`{"name":"日本語 emoji 🎉","arabic":"مرحبا"}`)
	var buf bytes.Buffer
	_, err := wrapEvent(&buf, cfg, event, time.Now())
	require.NoError(t, err)

	var env struct {
		Event json.RawMessage `json:"event"`
	}
	require.NoError(t, json.NewDecoder(&buf).Decode(&env))
	var inner map[string]any
	require.NoError(t, json.Unmarshal(env.Event, &inner))
	assert.Equal(t, "日本語 emoji 🎉", inner["name"])
	assert.Equal(t, "مرحبا", inner["arabic"])
}

func TestRawEventLine_AppendsNewline(t *testing.T) {
	var buf bytes.Buffer
	rawEventLine(&buf, []byte(`{"event":1}`))
	rawEventLine(&buf, []byte(`{"event":2}`))
	rawEventLine(&buf, []byte(`{"event":3}`+"\n")) // already has newline
	assert.Equal(t, "{\"event\":1}\n{\"event\":2}\n{\"event\":3}\n", buf.String())
}

func TestBuildRawQueryParams(t *testing.T) {
	cfg := &Config{
		Sourcetype: "axonops:audit",
		Source:     "my source", // intentional space — must be URL-encoded
		Index:      "audit_logs",
		Host:       "inventory-01",
	}
	q := buildRawQueryParams(cfg)
	parsed, err := url.ParseQuery(q)
	require.NoError(t, err)
	assert.Equal(t, "axonops:audit", parsed.Get("sourcetype"))
	assert.Equal(t, "my source", parsed.Get("source"))
	assert.Equal(t, "audit_logs", parsed.Get("index"))
	assert.Equal(t, "inventory-01", parsed.Get("host"))
	// URL-encoded form must contain '+' (space encoding) or '%20'.
	assert.Contains(t, q, "source=my+source")
}

func TestBuildRawQueryParams_EmptyFieldsOmitted(t *testing.T) {
	cfg := &Config{
		Sourcetype: "axonops:audit",
	}
	q := buildRawQueryParams(cfg)
	assert.Contains(t, q, "sourcetype=axonops%3Aaudit")
	assert.NotContains(t, q, "source=")
	assert.NotContains(t, q, "index=")
	assert.NotContains(t, q, "host=")
}

func TestJoinEventURL_StripsExistingPath(t *testing.T) {
	got, err := joinEventURL("https://splunk.example.com:8088/whatever?foo=bar")
	require.NoError(t, err)
	assert.Equal(t, "https://splunk.example.com:8088/whatever/services/collector/event", got)
}

func TestJoinHealthURL(t *testing.T) {
	got, err := joinHealthURL("https://splunk.example.com:8088")
	require.NoError(t, err)
	assert.Equal(t, "https://splunk.example.com:8088/services/collector/health", got)
}
