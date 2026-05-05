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

package audit_test

// Split out of audit_test.go (#540).

import (
	"testing"
	"time"

	"github.com/axonops/audit"
	"github.com/axonops/audit/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// HMAC integrity (#216)
// ---------------------------------------------------------------------------

func TestHMAC_Enabled_JSON_FieldsPresent(t *testing.T) {
	t.Parallel()
	out := testhelper.NewMockOutput("test")
	tax := &audit.Taxonomy{
		Version: 1,

		Categories: map[string]*audit.CategoryDef{"security": {Events: []string{"auth_failure"}}},
		Events: map[string]*audit.EventDef{
			"auth_failure": {Required: []string{"outcome"}},
		},
	}

	auditor, err := audit.New(
		audit.WithTaxonomy(tax),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(out, audit.WithHMAC(&audit.HMACConfig{
			Enabled: true,
			Salt: audit.HMACSalt{
				Version: "v1",
				Value:   []byte("test-salt-sixteen-bytes!"),
			},
			Algorithm: "HMAC-SHA-256",
		})),
	)
	require.NoError(t, err)

	err = auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{"outcome": "failure"}))
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))
	require.NoError(t, auditor.Close())

	ev := out.GetEvent(0)
	assert.NotEmpty(t, ev["_hmac"], "HMAC should be present")
	assert.Equal(t, "v1", ev["_hmac_version"], "salt version should be present")
}

func TestHMAC_Disabled_NoFields(t *testing.T) {
	t.Parallel()
	out := testhelper.NewMockOutput("test")
	tax := &audit.Taxonomy{
		Version:    1,
		Categories: map[string]*audit.CategoryDef{"write": {Events: []string{"ev1"}}},
		Events:     map[string]*audit.EventDef{"ev1": {Required: []string{"outcome"}}},
	}

	auditor, err := audit.New(
		audit.WithTaxonomy(tax),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)

	err = auditor.AuditEvent(audit.NewEvent("ev1", audit.Fields{"outcome": "success"}))
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))
	require.NoError(t, auditor.Close())

	ev := out.GetEvent(0)
	_, hasHMAC := ev["_hmac"]
	assert.False(t, hasHMAC, "no HMAC when disabled")
}

func TestHMAC_SaltVersion_InOutput(t *testing.T) {
	t.Parallel()
	out := testhelper.NewMockOutput("test")
	tax := &audit.Taxonomy{
		Version:    1,
		Categories: map[string]*audit.CategoryDef{"write": {Events: []string{"ev1"}}},
		Events:     map[string]*audit.EventDef{"ev1": {Required: []string{"outcome"}}},
	}

	auditor, err := audit.New(
		audit.WithTaxonomy(tax),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(out, audit.WithHMAC(&audit.HMACConfig{
			Enabled: true,
			Salt: audit.HMACSalt{
				Version: "2026-Q1",
				Value:   []byte("version-test-salt-16b!"),
			},
			Algorithm: "HMAC-SHA-256",
		})),
	)
	require.NoError(t, err)

	err = auditor.AuditEvent(audit.NewEvent("ev1", audit.Fields{"outcome": "success"}))
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))
	require.NoError(t, auditor.Close())

	ev := out.GetEvent(0)
	assert.Equal(t, "2026-Q1", ev["_hmac_version"])
}

func TestHMAC_ReservedFieldNames(t *testing.T) {
	t.Parallel()
	for _, field := range []string{"_hmac", "_hmac_version"} {
		t.Run(field, func(t *testing.T) {
			t.Parallel()
			tax := &audit.Taxonomy{
				Version:    1,
				Categories: map[string]*audit.CategoryDef{"write": {Events: []string{"ev1"}}},
				Events: map[string]*audit.EventDef{
					"ev1": {Required: []string{field}},
				},
			}
			err := audit.ValidateTaxonomy(*tax)
			require.Error(t, err)
			assert.ErrorIs(t, err, audit.ErrTaxonomyInvalid)
			assert.Contains(t, err.Error(), "reserved framework field")
		})
	}
}

// TestHMAC_DifferentFieldStripping_DifferentHMAC verifies that the same
// event produces different HMACs on two outputs with different sensitivity
// label exclusions. Each output uses a different salt to prove HMAC config
// is applied independently per output (no shared singleton). Output "full"
// gets all fields; output "stripped" excludes PII fields. The HMAC is
// computed after stripping, so the digests must differ.
func TestHMAC_DifferentFieldStripping_DifferentHMAC(t *testing.T) {
	t.Parallel()

	const taxYAML = `
version: 1
categories:
  write:
    events:
      - user_create
sensitivity:
  labels:
    pii:
      description: "Personally identifiable information"
      fields: [email]
events:
  user_create:
    fields:
      outcome: {required: true}
      actor_id: {required: true}
      email:
        labels: [pii]
`
	tax, err := audit.ParseTaxonomyYAML([]byte(taxYAML))
	require.NoError(t, err)

	// Different salts per output — proves each output uses its own
	// HMAC config independently, not a shared singleton.
	fullHMACCfg := &audit.HMACConfig{
		Enabled: true,
		Salt: audit.HMACSalt{
			Version: "v1",
			Value:   []byte("full-output-salt-value!"),
		},
		Algorithm: "HMAC-SHA-256",
	}
	strippedHMACCfg := &audit.HMACConfig{
		Enabled: true,
		Salt: audit.HMACSalt{
			Version: "v2",
			Value:   []byte("stripped-output-salt!!"),
		},
		Algorithm: "HMAC-SHA-256",
	}

	fullOut := testhelper.NewMockOutput("full")
	strippedOut := testhelper.NewMockOutput("stripped")

	auditor, err := audit.New(
		audit.WithTaxonomy(tax),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		// "full" output: no label exclusions — gets all fields including email.
		audit.WithNamedOutput(fullOut, audit.WithHMAC(fullHMACCfg)),
		// "stripped" output: excludes PII — email is removed before HMAC.
		audit.WithNamedOutput(strippedOut, audit.WithExcludeLabels("pii"), audit.WithHMAC(strippedHMACCfg)),
	)
	require.NoError(t, err)

	err = auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"email":    "alice@example.com",
	}))
	require.NoError(t, err)

	require.True(t, fullOut.WaitForEvents(1, 2*time.Second))
	require.True(t, strippedOut.WaitForEvents(1, 2*time.Second))
	require.NoError(t, auditor.Close())

	fullEvent := fullOut.GetEvent(0)
	strippedEvent := strippedOut.GetEvent(0)

	// Both outputs should have HMAC fields.
	fullHMAC, ok := fullEvent["_hmac"].(string)
	require.True(t, ok, "full output should have _hmac")
	strippedHMAC, ok := strippedEvent["_hmac"].(string)
	require.True(t, ok, "stripped output should have _hmac")

	// The full output should contain the email field.
	assert.Equal(t, "alice@example.com", fullEvent["email"], "full output should have email")

	// The stripped output should NOT contain the email field.
	_, hasEmail := strippedEvent["email"]
	assert.False(t, hasEmail, "stripped output should not have email (PII excluded)")

	// Salt versions should reflect per-output config.
	assert.Equal(t, "v1", fullEvent["_hmac_version"], "full output should have salt version v1")
	assert.Equal(t, "v2", strippedEvent["_hmac_version"], "stripped output should have salt version v2")

	// The HMACs MUST be different because the payloads differ
	// (one has email, the other does not) AND the salts differ.
	assert.NotEqual(t, fullHMAC, strippedHMAC,
		"HMAC should differ between outputs with different field stripping and different salts")
}

// TestHMAC_EndToEnd_DrainLoopVerification verifies that the HMAC produced
// by the drain loop can be verified against the on-wire bytes. Emits a
// single event to an HMAC-enabled output, then reconstructs the
// authenticated payload by stripping only the `_hmac` field (leaving
// `_hmac_version` in place per issue #473), and confirms the HMAC verifies.
// This is the canonical real-world verifier pattern.
func TestHMAC_EndToEnd_DrainLoopVerification(t *testing.T) {
	t.Parallel()

	hmacOut := testhelper.NewMockOutput("with-hmac")
	salt := []byte("e2e-verification-salt-value!!")

	tax := &audit.Taxonomy{
		Version: 1,

		Categories: map[string]*audit.CategoryDef{"security": {Events: []string{"auth_failure"}}},
		Events: map[string]*audit.EventDef{
			"auth_failure": {Required: []string{"outcome", "actor_id"}},
		},
	}

	auditor, err := audit.New(
		audit.WithTaxonomy(tax),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(hmacOut, audit.WithHMAC(&audit.HMACConfig{
			Enabled: true,
			Salt: audit.HMACSalt{
				Version: "v1",
				Value:   salt,
			},
			Algorithm: "HMAC-SHA-256",
		})),
	)
	require.NoError(t, err)

	err = auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "eve",
	}))
	require.NoError(t, err)

	require.True(t, hmacOut.WaitForEvents(1, 2*time.Second))
	require.NoError(t, auditor.Close())

	// Extract the HMAC from the on-wire line.
	line := hmacOut.GetEvents()[0]
	hmacEvent := hmacOut.GetEvent(0)
	hmacHex, ok := hmacEvent["_hmac"].(string)
	require.True(t, ok, "HMAC output must contain _hmac field")
	require.NotEmpty(t, hmacHex)

	// Reconstruct the authenticated payload: strip ONLY `_hmac` from
	// the on-wire bytes, keeping `_hmac_version` in place because it is
	// inside the authenticated region (issue #473).
	canonical := stripHMACJSONField(line)

	verified, err := audit.VerifyHMAC(canonical, hmacHex, salt, "HMAC-SHA-256")
	require.NoError(t, err)
	assert.True(t, verified,
		"HMAC from drain loop must verify against the on-wire payload with only `_hmac` stripped")
}

// TestHMAC_EndToEnd_SensitivityExclusion_Verification verifies that HMAC
// computed after sensitivity label stripping can be verified against
// the stripped on-wire payload. The HMAC output has PII exclusion and
// HMAC enabled; a second output has the same PII exclusion but no HMAC
// — used only as a sanity check that stripping happened consistently.
// Verification uses the strip-only-`_hmac` canonicalisation rule from
// issue #473.
func TestHMAC_EndToEnd_SensitivityExclusion_Verification(t *testing.T) {
	t.Parallel()

	const taxYAML = `
version: 1
categories:
  emit_event_category: true
  write:
    events: [user_create]
sensitivity:
  labels:
    pii:
      description: "Personally identifiable information"
      fields: [email, phone]
events:
  user_create:
    fields:
      outcome: {required: true}
      actor_id: {required: true}
      email:
        labels: [pii]
      phone:
        labels: [pii]
`
	tax, err := audit.ParseTaxonomyYAML([]byte(taxYAML))
	require.NoError(t, err)

	salt := []byte("sensitivity-hmac-e2e-salt!!")

	hmacOut := testhelper.NewMockOutput("hmac-stripped")
	baseOut := testhelper.NewMockOutput("base-stripped")

	auditor, err := audit.New(
		audit.WithTaxonomy(tax),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		// Both outputs exclude PII. baseOut is a sanity check that
		// stripping happened; verification uses hmacOut's own bytes.
		audit.WithNamedOutput(hmacOut, audit.WithExcludeLabels("pii"), audit.WithHMAC(&audit.HMACConfig{
			Enabled: true,
			Salt: audit.HMACSalt{
				Version: "v1",
				Value:   salt,
			},
			Algorithm: "HMAC-SHA-256",
		})),
		audit.WithNamedOutput(baseOut, audit.WithExcludeLabels("pii")),
	)
	require.NoError(t, err)

	err = auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"email":    "alice@example.com",
		"phone":    "+1-555-0100",
	}))
	require.NoError(t, err)

	require.True(t, hmacOut.WaitForEvents(1, 2*time.Second))
	require.True(t, baseOut.WaitForEvents(1, 2*time.Second))
	require.NoError(t, auditor.Close())

	// Sanity: email and phone stripped from both outputs.
	hmacEvent := hmacOut.GetEvent(0)
	baseEvent := baseOut.GetEvent(0)
	for _, out := range []map[string]interface{}{hmacEvent, baseEvent} {
		_, hasEmail := out["email"]
		_, hasPhone := out["phone"]
		assert.False(t, hasEmail, "email should be stripped (PII)")
		assert.False(t, hasPhone, "phone should be stripped (PII)")
	}

	// Verify the HMAC against hmacOut's own bytes with only `_hmac`
	// stripped — _hmac_version remains because it is inside the authenticated
	// region per issue #473.
	hmacHex, ok := hmacEvent["_hmac"].(string)
	require.True(t, ok, "HMAC output must contain _hmac field")

	line := hmacOut.GetEvents()[0]
	canonical := stripHMACJSONField(line)
	verified, err := audit.VerifyHMAC(canonical, hmacHex, salt, "HMAC-SHA-256")
	require.NoError(t, err)
	assert.True(t, verified,
		"HMAC computed after PII stripping must verify against the stripped on-wire payload (minus _hmac)")
}
