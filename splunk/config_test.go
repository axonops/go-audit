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

package splunk_test

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/audit/splunk"
)

// validCfgForValidate returns a config that passes Validate(). Tests
// mutate one field at a time to assert each bound is enforced.
func validCfgForValidate() *splunk.Config {
	gz := true
	return &splunk.Config{
		URL:                "https://splunk.example.com:8088",
		Token:              "abc-def-ghi",
		AllowInsecureHTTP:  false,
		AllowPrivateRanges: false,
		BatchSize:          500,
		MaxBatchBytes:      819200,
		MaxEventBytes:      1024 * 1024,
		FlushInterval:      2 * time.Second,
		Timeout:            10 * time.Second,
		MaxRetries:         10,
		BufferSize:         10_000,
		Gzip:               &gz,
		UserAgent:          "audit-splunk/0.x",
	}
}

func TestValidate_HappyPath(t *testing.T) {
	cfg := validCfgForValidate()
	require.NoError(t, cfg.Validate())
}

func TestValidate_BoundsTable(t *testing.T) { //nolint:funlen // table-driven by design
	tests := []struct {
		name    string
		mutate  func(*splunk.Config)
		wantErr error // ErrConfigInvalid or ErrPR1NotImplemented
	}{
		{
			name:    "BatchSize below MinBatchSize",
			mutate:  func(c *splunk.Config) { c.BatchSize = -1 },
			wantErr: splunk.ErrConfigInvalid,
		},
		{
			name:    "BatchSize above MaxBatchSize",
			mutate:  func(c *splunk.Config) { c.BatchSize = splunk.MaxBatchSize + 1 },
			wantErr: splunk.ErrConfigInvalid,
		},
		{
			name:    "MaxBatchBytes below MinMaxBatchBytes",
			mutate:  func(c *splunk.Config) { c.MaxBatchBytes = 100 },
			wantErr: splunk.ErrConfigInvalid,
		},
		{
			name:    "MaxBatchBytes above MaxMaxBatchBytes",
			mutate:  func(c *splunk.Config) { c.MaxBatchBytes = splunk.MaxMaxBatchBytes + 1 },
			wantErr: splunk.ErrConfigInvalid,
		},
		{
			name:    "MaxEventBytes below MinMaxEventBytes",
			mutate:  func(c *splunk.Config) { c.MaxEventBytes = 100 },
			wantErr: splunk.ErrConfigInvalid,
		},
		{
			name:    "MaxEventBytes above MaxMaxEventBytes",
			mutate:  func(c *splunk.Config) { c.MaxEventBytes = splunk.MaxMaxEventBytes + 1 },
			wantErr: splunk.ErrConfigInvalid,
		},
		{
			name:    "FlushInterval below MinFlushInterval",
			mutate:  func(c *splunk.Config) { c.FlushInterval = 10 * time.Millisecond },
			wantErr: splunk.ErrConfigInvalid,
		},
		{
			name:    "FlushInterval above MaxFlushInterval",
			mutate:  func(c *splunk.Config) { c.FlushInterval = 10 * time.Minute },
			wantErr: splunk.ErrConfigInvalid,
		},
		{
			name:    "Timeout below MinTimeout",
			mutate:  func(c *splunk.Config) { c.Timeout = 10 * time.Millisecond },
			wantErr: splunk.ErrConfigInvalid,
		},
		{
			name:    "Timeout above MaxTimeout",
			mutate:  func(c *splunk.Config) { c.Timeout = 10 * time.Minute },
			wantErr: splunk.ErrConfigInvalid,
		},
		{
			name:    "MaxRetries below MinMaxRetries",
			mutate:  func(c *splunk.Config) { c.MaxRetries = -1 },
			wantErr: splunk.ErrConfigInvalid,
		},
		{
			name:    "MaxRetries above MaxMaxRetries",
			mutate:  func(c *splunk.Config) { c.MaxRetries = splunk.MaxMaxRetries + 1 },
			wantErr: splunk.ErrConfigInvalid,
		},
		{
			name:    "BufferSize below MinBufferSize",
			mutate:  func(c *splunk.Config) { c.BufferSize = 10 },
			wantErr: splunk.ErrConfigInvalid,
		},
		{
			name:    "BufferSize above MaxBufferSize",
			mutate:  func(c *splunk.Config) { c.BufferSize = splunk.MaxBufferSize + 1 },
			wantErr: splunk.ErrConfigInvalid,
		},
		{
			name:    "UserAgent with control character",
			mutate:  func(c *splunk.Config) { c.UserAgent = "audit-splunk/0.x\nfake" },
			wantErr: splunk.ErrConfigInvalid,
		},
		{
			name:    "UserAgent with semicolon (outside allowed charset)",
			mutate:  func(c *splunk.Config) { c.UserAgent = "audit-splunk/0.x; ext" },
			wantErr: splunk.ErrConfigInvalid,
		},
		{
			name: "Headers with CRLF in value",
			mutate: func(c *splunk.Config) {
				c.Headers = map[string]string{"X-Tenant": "foo\r\nFAKE: yes"}
			},
			wantErr: splunk.ErrConfigInvalid,
		},
		{
			name: "Headers with CRLF in key",
			mutate: func(c *splunk.Config) {
				c.Headers = map[string]string{"X-Bad\r\n": "ok"}
			},
			wantErr: splunk.ErrConfigInvalid,
		},
		{
			name: "Headers with reserved Authorization",
			mutate: func(c *splunk.Config) {
				c.Headers = map[string]string{"Authorization": "Splunk leaked"}
			},
			wantErr: splunk.ErrConfigInvalid,
		},
		{
			name: "Headers with reserved User-Agent",
			mutate: func(c *splunk.Config) {
				c.Headers = map[string]string{"User-Agent": "fake"}
			},
			wantErr: splunk.ErrConfigInvalid,
		},
		{
			name: "TLSCert without TLSKey",
			mutate: func(c *splunk.Config) {
				c.TLSCert = "/tmp/cert.pem"
			},
			wantErr: splunk.ErrConfigInvalid,
		},
		{
			name: "TLSKey without TLSCert",
			mutate: func(c *splunk.Config) {
				c.TLSKey = "/tmp/key.pem"
			},
			wantErr: splunk.ErrConfigInvalid,
		},
		{
			name: "URL with scheme ftp",
			mutate: func(c *splunk.Config) {
				c.URL = "ftp://splunk.example.com"
			},
			wantErr: splunk.ErrConfigInvalid,
		},
		{
			name: "URL malformed",
			mutate: func(c *splunk.Config) {
				c.URL = "://no-scheme"
			},
			wantErr: splunk.ErrConfigInvalid,
		},
		{
			name: "AckModeBestEffort rejected in PR 1",
			mutate: func(c *splunk.Config) {
				c.AckMode = splunk.AckModeBestEffort
			},
			wantErr: splunk.ErrPR1NotImplemented,
		},
		{
			name: "AckMode out of range",
			mutate: func(c *splunk.Config) {
				c.AckMode = splunk.AckMode(99)
			},
			wantErr: splunk.ErrConfigInvalid,
		},
		{
			name: "Endpoint out of range",
			mutate: func(c *splunk.Config) {
				c.Endpoint = splunk.Endpoint(99)
			},
			wantErr: splunk.ErrConfigInvalid,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validCfgForValidate()
			tc.mutate(cfg)
			err := cfg.Validate()
			require.Error(t, err)
			assert.ErrorIs(t, err, tc.wantErr)
		})
	}
}

// TestValidate_AppliesDefaults verifies that zero-valued fields are
// filled in before validation. The test specifically asserts that
// the well-known defaults appear on the returned Config — if a
// future change drops one of the applyDefaults branches the test
// catches it.
func TestValidate_AppliesDefaults(t *testing.T) {
	cfg := &splunk.Config{
		URL:   "https://splunk.example.com:8088",
		Token: "abc",
	}
	require.NoError(t, cfg.Validate())
	assert.Equal(t, splunk.DefaultBatchSize, cfg.BatchSize)
	assert.Equal(t, splunk.DefaultMaxBatchBytes, cfg.MaxBatchBytes)
	assert.Equal(t, splunk.DefaultMaxEventBytes, cfg.MaxEventBytes)
	assert.Equal(t, splunk.DefaultFlushInterval, cfg.FlushInterval)
	assert.Equal(t, splunk.DefaultTimeout, cfg.Timeout)
	assert.Equal(t, splunk.DefaultMaxRetries, cfg.MaxRetries)
	assert.Equal(t, splunk.DefaultBufferSize, cfg.BufferSize)
	require.NotNil(t, cfg.Gzip)
	assert.True(t, *cfg.Gzip, "Gzip default should be true")
}

func TestValidateCloudStack(t *testing.T) {
	tests := []struct {
		name    string
		stack   string
		wantErr bool
	}{
		{"acme-prod", "acme-prod", false},
		{"single char", "a", false},
		{"63 chars", strings.Repeat("a", 63), false},
		{"empty rejected", "", true},
		{"64 chars rejected", strings.Repeat("a", 64), true},
		{"with dot rejected", "acme.evil.com", true},
		{"with at sign rejected", "acme@evil", true},
		{"with slash rejected", "acme/path", true},
		{"with colon rejected", "acme:1234", true},
		{"with space rejected", "acme prod", true},
		{"with hash rejected", "acme#1", true},
		{"with backslash rejected", "acme\\bad", true},
		{"with newline rejected", "acme\n", true},
		{"with cyrillic homograph rejected", "аcme-prod", true}, // Cyrillic 'а'
		{"starting with hyphen rejected", "-acme", true},
		{"uppercase rejected", "ACME", true},
		{"plus sign rejected", "acme+prod", true},
		{"all digits accepted", "123", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := splunk.ValidateCloudStack(tc.stack)
			if tc.wantErr {
				require.Error(t, err)
				assert.ErrorIs(t, err, splunk.ErrConfigInvalid)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestConfig_SplunkCloud_ExpandsCorrectly verifies that a
// `splunkcloud://<stack>` URL is rewritten in-place by Validate() to
// the canonical Splunk Cloud HEC URL form.
func TestConfig_SplunkCloud_ExpandsCorrectly(t *testing.T) {
	cfg := validCfgForValidate()
	cfg.URL = "splunkcloud://acme-prod"
	require.NoError(t, cfg.Validate())
	assert.Equal(t, "https://http-inputs-acme-prod.splunkcloud.com:443", cfg.URL,
		"Validate() must rewrite the URL to the canonical Splunk Cloud HEC form")
}

// TestConfig_SplunkCloud_Idempotent verifies that calling Validate()
// twice on the same config is safe: the second call observes the
// already-rewritten https:// URL and takes the https branch.
func TestConfig_SplunkCloud_Idempotent(t *testing.T) {
	cfg := validCfgForValidate()
	cfg.URL = "splunkcloud://acme-prod"
	require.NoError(t, cfg.Validate())
	rewritten := cfg.URL
	require.NoError(t, cfg.Validate(), "second Validate() must succeed")
	assert.Equal(t, rewritten, cfg.URL,
		"second Validate() must not mutate the URL again")
}

// TestConfig_SplunkCloud_RejectsInvalidStackName drives the
// rejection list from the issue body's AC 17. Each entry must fail
// Validate() with ErrConfigInvalid.
func TestConfig_SplunkCloud_RejectsInvalidStackName(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{"dot in stack", "splunkcloud://acme-prod.evil.com"},
		{"at sign in stack", "splunkcloud://acme@evil.com"},
		{"path appended", "splunkcloud://acme/path"},
		{"port appended", "splunkcloud://acme:1234"},
		{"space in stack", "splunkcloud://acme prod"},
		{"cyrillic homograph", "splunkcloud://аcme-prod"}, // leading Cyrillic 'а'
		{"empty stack", "splunkcloud://"},
		{"64-char stack", "splunkcloud://" + strings.Repeat("a", 64)},
		{"query appended", "splunkcloud://acme?foo=bar"},
		{"fragment appended", "splunkcloud://acme#frag"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validCfgForValidate()
			cfg.URL = tc.url
			err := cfg.Validate()
			require.Error(t, err)
			assert.ErrorIs(t, err, splunk.ErrConfigInvalid)
		})
	}
}

// TestConfig_SplunkCloud_RejectionPrecedence pins which rejection
// fires first when a URL has BOTH a structural fault (path/port/
// query/fragment) AND a bad stack name. Structural errors fire
// first — they're more actionable for the operator. Code-reviewer
// follow-up: anchor the precedence so a future refactor that swaps
// the order is caught by this test, not by an angry user.
func TestConfig_SplunkCloud_RejectionPrecedence(t *testing.T) {
	t.Run("structural error fires before stack-name error", func(t *testing.T) {
		cfg := validCfgForValidate()
		cfg.URL = "splunkcloud://has.dot/and-path" // both bad
		err := cfg.Validate()
		require.Error(t, err)
		assert.ErrorContains(t, err, "must be the bare form",
			"structural rejection message should fire before stack-name rejection")
	})
	t.Run("stack-name error fires for content-only fault", func(t *testing.T) {
		cfg := validCfgForValidate()
		cfg.URL = "splunkcloud://HAS_UPPERCASE"
		err := cfg.Validate()
		require.Error(t, err)
		assert.ErrorContains(t, err, "splunkcloud stack name",
			"content rejection should mention stack name")
	})
}

// TestConfig_SplunkCloud_WithCustomTLSMaterial_Rejected verifies
// that `splunkcloud://` rejects ANY custom TLS material — TLSCert,
// TLSKey, or TLSCA. Splunk Cloud presents a public-CA-signed cert;
// silently dropping the operator's TLS settings would be a security
// surprise.
func TestConfig_SplunkCloud_WithCustomTLSMaterial_Rejected(t *testing.T) {
	t.Run("TLSCert set", func(t *testing.T) {
		cfg := validCfgForValidate()
		cfg.URL = "splunkcloud://acme-prod"
		cfg.TLSCert = "/path/to/client.crt"
		err := cfg.Validate()
		require.Error(t, err)
		assert.ErrorIs(t, err, splunk.ErrConfigInvalid)
		assert.Contains(t, err.Error(), "does not support custom TLS material")
	})
	t.Run("TLSKey set", func(t *testing.T) {
		cfg := validCfgForValidate()
		cfg.URL = "splunkcloud://acme-prod"
		cfg.TLSKey = "/path/to/client.key"
		err := cfg.Validate()
		require.Error(t, err)
		assert.ErrorIs(t, err, splunk.ErrConfigInvalid)
	})
	t.Run("TLSCA set", func(t *testing.T) {
		cfg := validCfgForValidate()
		cfg.URL = "splunkcloud://acme-prod"
		cfg.TLSCA = "/path/to/ca.crt"
		err := cfg.Validate()
		require.Error(t, err)
		assert.ErrorIs(t, err, splunk.ErrConfigInvalid)
	})
}
