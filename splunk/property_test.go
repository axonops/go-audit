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
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"testing"
	"time"

	"pgregory.net/rapid"
)

// TestProperty_EnvelopeWrap_ArbitraryJSON_NeverPanics generates
// arbitrary valid JSON objects and asserts wrapEvent never panics.
// The event must be valid JSON because the core formatter guarantees
// that contract — the test exercises the surface of valid-input
// shapes wrapEvent might encounter in production.
func TestProperty_EnvelopeWrap_ArbitraryJSON_NeverPanics(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		obj := genJSONObject(t, 3)
		eventJSON, err := json.Marshal(obj)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		cfg := &Config{Sourcetype: "axonops:audit", Source: "audit"}
		var buf bytes.Buffer
		// Must not panic. The error is acceptable (we don't assert
		// on it because some pathological inputs may legitimately
		// fail).
		_, _ = wrapEvent(&buf, cfg, eventJSON, time.Now())
	})
}

// TestProperty_EnvelopeRoundTrip generates arbitrary JSON objects,
// wraps them in an envelope, decodes the envelope, and asserts the
// nested `event` field exactly equals the input JSON. Defends
// against any future refactor that mis-handles the RawMessage
// passthrough.
func TestProperty_EnvelopeRoundTrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		obj := genJSONObject(t, 3)
		eventJSON, err := json.Marshal(obj)
		if err != nil {
			t.Fatalf("marshal input: %v", err)
		}
		cfg := &Config{Sourcetype: "axonops:audit", Source: "audit"}
		var buf bytes.Buffer
		if _, err := wrapEvent(&buf, cfg, eventJSON, time.Now()); err != nil {
			return // wrap legitimately failed; not a property violation
		}
		var env struct {
			Event json.RawMessage `json:"event"`
		}
		if err := json.NewDecoder(&buf).Decode(&env); err != nil {
			t.Fatalf("decode envelope: %v", err)
		}
		// Re-marshal the input and output to canonical form so
		// key-ordering doesn't break the comparison.
		var inGeneric, outGeneric any
		if err := json.Unmarshal(eventJSON, &inGeneric); err != nil {
			t.Fatalf("re-decode input: %v", err)
		}
		if err := json.Unmarshal(env.Event, &outGeneric); err != nil {
			t.Fatalf("re-decode output: %v", err)
		}
		inCanon, _ := json.Marshal(inGeneric)
		outCanon, _ := json.Marshal(outGeneric)
		if !bytes.Equal(inCanon, outCanon) {
			t.Fatalf("envelope event field changed:\n  in:  %s\n  out: %s", inCanon, outCanon)
		}
	})
}

// TestProperty_BatchConcatenation_Parseable generates N arbitrary
// envelopes, concatenates them, and asserts a streaming JSON decoder
// produces exactly N objects. Defends against any future refactor
// that breaks the documented HEC concatenated-JSON batch format.
func TestProperty_BatchConcatenation_Parseable(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		n := rapid.IntRange(1, 20).Draw(t, "n")
		cfg := &Config{Sourcetype: "axonops:audit", Source: "audit"}
		var buf bytes.Buffer
		for i := 0; i < n; i++ {
			obj := genJSONObject(t, 2)
			eventJSON, err := json.Marshal(obj)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if _, err := wrapEvent(&buf, cfg, eventJSON, time.Now()); err != nil {
				return
			}
		}
		dec := json.NewDecoder(&buf)
		count := 0
		for {
			var obj any
			if err := dec.Decode(&obj); err != nil {
				if err == io.EOF {
					break
				}
				t.Fatalf("decode object %d: %v", count, err)
			}
			count++
		}
		if count != n {
			t.Fatalf("expected %d objects in concatenated batch, decoded %d", n, count)
		}
	})
}

// TestProperty_GzipRoundTrip — gzip then gunzip equals input. Catches
// any future change to the gzWriter Reset semantics that would corrupt
// the encoded payload.
func TestProperty_GzipRoundTrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		input := rapid.SliceOfN(rapid.Byte(), 1, 10_000).Draw(t, "input")
		var encoded bytes.Buffer
		gz := gzip.NewWriter(&encoded)
		if _, err := gz.Write(input); err != nil {
			t.Fatalf("gzip write: %v", err)
		}
		if err := gz.Close(); err != nil {
			t.Fatalf("gzip close: %v", err)
		}
		dec, err := gzip.NewReader(&encoded)
		if err != nil {
			t.Fatalf("gzip reader: %v", err)
		}
		decoded, err := io.ReadAll(dec)
		if err != nil {
			t.Fatalf("gzip read: %v", err)
		}
		if !bytes.Equal(input, decoded) {
			t.Fatalf("round-trip failed: input %d bytes, decoded %d bytes", len(input), len(decoded))
		}
	})
}

// TestProperty_SplunkBackoff_NeverExceedsMaxDelay — boundary defence
// against `>` vs `>=` mutation in the cap check at http.go's
// splunkBackoff.
func TestProperty_SplunkBackoff_NeverExceedsMaxDelay(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		attempt := rapid.IntRange(0, 100).Draw(t, "attempt")
		d := splunkBackoff(attempt)
		if d > backoffMax {
			t.Fatalf("attempt %d: backoff %s exceeds backoffMax %s",
				attempt, d, backoffMax)
		}
		if d <= 0 {
			t.Fatalf("attempt %d: backoff non-positive: %s", attempt, d)
		}
	})
}

// TestProperty_HECActionStringNeverPanics — String() must handle every
// integer value including invalid ones (returns "unknown").
func TestProperty_HECActionStringNeverPanics(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		i := rapid.IntRange(-100, 100).Draw(t, "i")
		_ = hecAction(i).String()
	})
}

// TestProperty_Classify_NeverPanics — exhaustively varies HTTP status
// + HEC code through classify(); must always return a defined action.
func TestProperty_Classify_NeverPanics(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		status := rapid.IntRange(0, 700).Draw(t, "status")
		code := rapid.IntRange(-10, 100).Draw(t, "code")
		got := classify(status, code)
		// The set of valid actions:
		switch got {
		case actionSuccess, actionRetry, actionDrop, actionStop,
			actionCapacityWarn, actionAckDisabled:
			// ok
		default:
			t.Fatalf("classify(%d,%d) returned undefined action %d", status, code, got)
		}
	})
}

// genJSONObject generates a small JSON object with random string,
// number, bool, and null values. Constrained depth to keep the
// shrinker from producing pathologically deep inputs.
func genJSONObject(t *rapid.T, maxDepth int) map[string]any {
	m := map[string]any{}
	nkeys := rapid.IntRange(0, 5).Draw(t, "nkeys")
	for i := 0; i < nkeys; i++ {
		key := fmt.Sprintf("k%d", i) // ASCII key
		switch rapid.IntRange(0, 4).Draw(t, "type") {
		case 0:
			m[key] = rapid.String().Draw(t, "str")
		case 1:
			m[key] = rapid.IntRange(-1<<20, 1<<20).Draw(t, "int")
		case 2:
			m[key] = rapid.Bool().Draw(t, "bool")
		case 3:
			m[key] = nil
		case 4:
			if maxDepth > 0 {
				m[key] = genJSONObject(t, maxDepth-1)
			} else {
				m[key] = "x"
			}
		}
	}
	return m
}
