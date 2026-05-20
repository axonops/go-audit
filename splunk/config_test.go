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
			name: "splunkcloud:// scheme rejected in PR 1",
			mutate: func(c *splunk.Config) {
				c.URL = "splunkcloud://acme-prod"
			},
			wantErr: splunk.ErrPR1NotImplemented,
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
