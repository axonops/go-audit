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

package loki_test

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/axonops/audit"
	"github.com/axonops/audit/loki"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// TestValidateConfig — exhaustive table-driven validation cases
// ---------------------------------------------------------------------------

func TestValidateConfig(t *testing.T) {
	t.Parallel()

	tests := []struct { //nolint:govet // fieldalignment: readability preferred
		name    string
		cfg     loki.Config
		wantErr string // substring that must appear in err.Error(); empty means no error expected
	}{
		// --- URL presence and form ----------------------------------------
		{
			name:    "empty URL rejected",
			cfg:     loki.Config{},
			wantErr: "url must not be empty",
		},
		{
			name:    "unparseable URL rejected",
			cfg:     loki.Config{URL: "://not-a-url"},
			wantErr: "invalid url",
		},
		{
			name:    "ftp scheme rejected",
			cfg:     loki.Config{URL: "ftp://logs.example.com/push"},
			wantErr: "scheme must be http or https",
		},
		{
			name:    "ws scheme rejected",
			cfg:     loki.Config{URL: "ws://logs.example.com/push"},
			wantErr: "scheme must be http or https",
		},

		// --- HTTP / HTTPS flag --------------------------------------------
		{
			name:    "http without AllowInsecureHTTP rejected",
			cfg:     loki.Config{URL: "http://loki.internal:3100/loki/api/v1/push"},
			wantErr: "must be https",
		},
		{
			name: "http with AllowInsecureHTTP accepted",
			cfg: loki.Config{
				URL:               "http://loki.internal:3100/loki/api/v1/push",
				AllowInsecureHTTP: true,
			},
		},
		{
			name: "https accepted without flag",
			cfg:  loki.Config{URL: "https://loki.example.com/loki/api/v1/push"},
		},

		// --- Credentials in URL -------------------------------------------
		{
			name:    "credentials embedded in URL rejected",
			cfg:     loki.Config{URL: "https://user:pass@loki.example.com/loki/api/v1/push"},
			wantErr: "url must not contain credentials",
		},
		{
			name:    "username-only in URL rejected",
			cfg:     loki.Config{URL: "https://user@loki.example.com/loki/api/v1/push"},
			wantErr: "url must not contain credentials",
		},

		// --- Auth mutual exclusivity --------------------------------------
		{
			name: "basic_auth and bearer_token mutually exclusive",
			cfg: loki.Config{
				URL:         "https://loki.example.com/loki/api/v1/push",
				BasicAuth:   &loki.BasicAuth{Username: "alice", Password: "secret"},
				BearerToken: "tok-abc123",
			},
			wantErr: "mutually exclusive",
		},
		{
			name: "basic_auth with empty username rejected",
			cfg: loki.Config{
				URL:       "https://loki.example.com/loki/api/v1/push",
				BasicAuth: &loki.BasicAuth{Username: "", Password: "secret"},
			},
			wantErr: "basic_auth.username must not be empty",
		},
		{
			name: "basic_auth alone accepted",
			cfg: loki.Config{
				URL:       "https://loki.example.com/loki/api/v1/push",
				BasicAuth: &loki.BasicAuth{Username: "alice", Password: "secret"},
			},
		},
		{
			name: "bearer_token alone accepted",
			cfg: loki.Config{
				URL:         "https://loki.example.com/loki/api/v1/push",
				BearerToken: "tok-abc123",
			},
		},

		// --- TLS cert/key pairing ----------------------------------------
		{
			name: "tls_cert without tls_key rejected",
			cfg: loki.Config{
				URL:     "https://loki.example.com/loki/api/v1/push",
				TLSCert: "/tmp/client.crt",
			},
			wantErr: "tls_cert and tls_key must both be set or both empty",
		},
		{
			name: "tls_key without tls_cert rejected",
			cfg: loki.Config{
				URL:    "https://loki.example.com/loki/api/v1/push",
				TLSKey: "/tmp/client.key",
			},
			wantErr: "tls_cert and tls_key must both be set or both empty",
		},
		{
			name: "tls_cert and tls_key both set accepted at validation stage",
			// Uses real temp files since validateLokiConfig now checks existence.
			cfg: func() loki.Config {
				dir := t.TempDir()
				certPath := filepath.Join(dir, "client.crt")
				keyPath := filepath.Join(dir, "client.key")
				_ = os.WriteFile(certPath, []byte("placeholder"), 0o600)
				_ = os.WriteFile(keyPath, []byte("placeholder"), 0o600)
				return loki.Config{
					URL:     "https://loki.example.com/loki/api/v1/push",
					TLSCert: certPath,
					TLSKey:  keyPath,
				}
			}(),
		},

		// --- TLS file validation (#325) -----------------------------------
		{
			name: "tls_cert is directory rejected",
			cfg: func() loki.Config {
				return loki.Config{
					URL:     "https://loki.example.com/loki/api/v1/push",
					TLSCert: t.TempDir(),
					TLSKey:  t.TempDir(),
				}
			}(),
			wantErr: "directory",
		},
		{
			name: "tls_ca is directory rejected",
			cfg: loki.Config{
				URL:   "https://loki.example.com/loki/api/v1/push",
				TLSCA: t.TempDir(),
			},
			wantErr: "directory",
		},
		{
			name: "nonexistent tls_cert rejected at validation",
			cfg: loki.Config{
				URL:     "https://loki.example.com/loki/api/v1/push",
				TLSCert: "/nonexistent/cert.pem",
				TLSKey:  "/nonexistent/key.pem",
			},
			wantErr: "tls file",
		},
		{
			name: "nonexistent tls_ca rejected at validation",
			cfg: loki.Config{
				URL:   "https://loki.example.com/loki/api/v1/push",
				TLSCA: "/nonexistent/ca.pem",
			},
			wantErr: "tls file",
		},

		// --- Static label name validation --------------------------------
		{
			name: "static label name with hyphen rejected",
			cfg: loki.Config{
				URL: "https://loki.example.com/loki/api/v1/push",
				Labels: loki.LabelConfig{
					Static: map[string]string{"my-label": "prod"},
				},
			},
			wantErr: "invalid",
		},
		{
			name: "static label name starting with digit rejected",
			cfg: loki.Config{
				URL: "https://loki.example.com/loki/api/v1/push",
				Labels: loki.LabelConfig{
					Static: map[string]string{"1bad": "prod"},
				},
			},
			wantErr: "invalid",
		},
		{
			name: "static label name with space rejected",
			cfg: loki.Config{
				URL: "https://loki.example.com/loki/api/v1/push",
				Labels: loki.LabelConfig{
					Static: map[string]string{"bad name": "prod"},
				},
			},
			wantErr: "invalid",
		},
		{
			name: "static label with empty value rejected",
			cfg: loki.Config{
				URL: "https://loki.example.com/loki/api/v1/push",
				Labels: loki.LabelConfig{
					Static: map[string]string{"environment": ""},
				},
			},
			wantErr: "empty value",
		},
		{
			name: "static label name with underscore prefix accepted",
			cfg: loki.Config{
				URL: "https://loki.example.com/loki/api/v1/push",
				Labels: loki.LabelConfig{
					Static: map[string]string{"_private": "value"},
				},
			},
		},
		{
			name: "static label name alphanumeric with underscores accepted",
			cfg: loki.Config{
				URL: "https://loki.example.com/loki/api/v1/push",
				Labels: loki.LabelConfig{
					Static: map[string]string{"env_name_2": "prod"},
				},
			},
		},

		// --- Batch size bounds -------------------------------------------
		{
			name: "batch_size below minimum rejected",
			cfg: loki.Config{
				URL:       "https://loki.example.com/loki/api/v1/push",
				BatchSize: -1, // non-zero so default is not applied
			},
			wantErr: "batch_size",
		},
		{
			name: "batch_size above maximum rejected",
			cfg: loki.Config{
				URL:       "https://loki.example.com/loki/api/v1/push",
				BatchSize: loki.MaxBatchSize + 1,
			},
			wantErr: "batch_size",
		},
		{
			name: "batch_size at maximum accepted",
			cfg: loki.Config{
				URL:       "https://loki.example.com/loki/api/v1/push",
				BatchSize: loki.MaxBatchSize,
			},
		},

		// --- MaxBatchBytes bounds ----------------------------------------
		{
			name: "max_batch_bytes below minimum rejected",
			cfg: loki.Config{
				URL:           "https://loki.example.com/loki/api/v1/push",
				MaxBatchBytes: loki.MinMaxBatchBytes - 1,
			},
			wantErr: "max_batch_bytes",
		},
		{
			name: "max_batch_bytes above maximum rejected",
			cfg: loki.Config{
				URL:           "https://loki.example.com/loki/api/v1/push",
				MaxBatchBytes: loki.MaxMaxBatchBytes + 1,
			},
			wantErr: "max_batch_bytes",
		},

		// --- FlushInterval bounds ----------------------------------------
		{
			name: "flush_interval below minimum rejected",
			cfg: loki.Config{
				URL:           "https://loki.example.com/loki/api/v1/push",
				FlushInterval: loki.MinFlushInterval - time.Millisecond,
			},
			wantErr: "flush_interval",
		},
		{
			name: "flush_interval above maximum rejected",
			cfg: loki.Config{
				URL:           "https://loki.example.com/loki/api/v1/push",
				FlushInterval: loki.MaxFlushInterval + time.Second,
			},
			wantErr: "flush_interval",
		},

		// --- Timeout bounds ----------------------------------------------
		{
			name: "timeout below minimum rejected",
			cfg: loki.Config{
				URL:     "https://loki.example.com/loki/api/v1/push",
				Timeout: loki.MinTimeout - time.Millisecond,
			},
			wantErr: "timeout",
		},
		{
			name: "timeout above maximum rejected",
			cfg: loki.Config{
				URL:     "https://loki.example.com/loki/api/v1/push",
				Timeout: loki.MaxTimeout + time.Second,
			},
			wantErr: "timeout",
		},

		// --- MaxRetries bounds -------------------------------------------
		// Note: MaxRetries == 0 triggers the default (3), so the minimum
		// effective value a caller can force is 1 by setting it explicitly.
		// Negative values are out of range.
		{
			name: "max_retries negative rejected",
			cfg: loki.Config{
				URL:        "https://loki.example.com/loki/api/v1/push",
				MaxRetries: -1,
			},
			wantErr: "max_retries",
		},
		{
			name: "max_retries above maximum rejected",
			cfg: loki.Config{
				URL:        "https://loki.example.com/loki/api/v1/push",
				MaxRetries: loki.MaxMaxRetries + 1,
			},
			wantErr: "max_retries",
		},
		{
			name: "max_retries at maximum accepted",
			cfg: loki.Config{
				URL:        "https://loki.example.com/loki/api/v1/push",
				MaxRetries: loki.MaxMaxRetries,
			},
		},

		// --- BufferSize bounds -------------------------------------------
		{
			name: "buffer_size below minimum rejected",
			cfg: loki.Config{
				URL:        "https://loki.example.com/loki/api/v1/push",
				BufferSize: loki.MinBufferSize - 1,
			},
			wantErr: "buffer_size",
		},
		{
			name: "buffer_size above maximum rejected",
			cfg: loki.Config{
				URL:        "https://loki.example.com/loki/api/v1/push",
				BufferSize: loki.MaxBufferSize + 1,
			},
			wantErr: "buffer_size",
		},
		{
			name: "buffer_size at maximum accepted",
			cfg: loki.Config{
				URL:        "https://loki.example.com/loki/api/v1/push",
				BufferSize: loki.MaxBufferSize,
			},
		},
		{
			name: "buffer_size at minimum accepted",
			cfg: loki.Config{
				URL:        "https://loki.example.com/loki/api/v1/push",
				BufferSize: loki.MinBufferSize,
			},
		},

		// --- Header CRLF injection ---------------------------------------
		{
			name: "CRLF in header name rejected",
			cfg: loki.Config{
				URL:     "https://loki.example.com/loki/api/v1/push",
				Headers: map[string]string{"X-Bad\r\nHeader": "value"},
			},
			wantErr: "CR/LF",
		},
		{
			name: "LF in header name rejected",
			cfg: loki.Config{
				URL:     "https://loki.example.com/loki/api/v1/push",
				Headers: map[string]string{"X-Bad\nHeader": "value"},
			},
			wantErr: "CR/LF",
		},
		{
			name: "CRLF in header value rejected",
			cfg: loki.Config{
				URL:     "https://loki.example.com/loki/api/v1/push",
				Headers: map[string]string{"X-Good-Name": "injected\r\nX-Extra: evil"},
			},
			wantErr: "CR/LF",
		},
		// --- Restricted header names ----------------------------------
		{
			name: "Authorization header rejected",
			cfg: loki.Config{
				URL:     "https://loki.example.com/loki/api/v1/push",
				Headers: map[string]string{"Authorization": "Bearer evil"},
			},
			wantErr: "managed by the library",
		},
		{
			name: "X-Scope-OrgID header rejected (case insensitive)",
			cfg: loki.Config{
				URL:     "https://loki.example.com/loki/api/v1/push",
				Headers: map[string]string{"x-scope-orgid": "attacker-tenant"},
			},
			wantErr: "managed by the library",
		},
		{
			name: "Content-Type header rejected",
			cfg: loki.Config{
				URL:     "https://loki.example.com/loki/api/v1/push",
				Headers: map[string]string{"Content-Type": "text/plain"},
			},
			wantErr: "managed by the library",
		},
		{
			name: "Host header rejected",
			cfg: loki.Config{
				URL:     "https://loki.example.com/loki/api/v1/push",
				Headers: map[string]string{"Host": "evil.com"},
			},
			wantErr: "managed by the library",
		},
		{
			name: "clean header accepted",
			cfg: loki.Config{
				URL:     "https://loki.example.com/loki/api/v1/push",
				Headers: map[string]string{"X-Tenant": "team-alpha"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Work on a copy so parallel subtests do not share the same struct.
			cfg := tt.cfg
			err := loki.ValidateLokiConfig(&cfg)

			if tt.wantErr == "" {
				require.NoError(t, err, "expected no error for %q", tt.name)
			} else {
				require.Error(t, err, "expected an error containing %q for %q", tt.wantErr, tt.name)
				assert.ErrorIs(t, err, audit.ErrConfigInvalid,
					"validation errors must wrap audit.ErrConfigInvalid")
				assert.Contains(t, err.Error(), tt.wantErr,
					"error message should contain %q, got: %q", tt.wantErr, err.Error())
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestValidateConfig_Defaults — zero-value fields receive documented defaults
// ---------------------------------------------------------------------------

func TestValidateConfig_Defaults(t *testing.T) {
	t.Parallel()

	// A minimal valid config: only URL is set, all numeric/duration fields
	// are their zero values. validateLokiConfig must fill them in.
	cfg := loki.Config{URL: "https://loki.example.com/loki/api/v1/push"}

	require.NoError(t, loki.ValidateLokiConfig(&cfg))

	assert.Equal(t, loki.DefaultBatchSize, cfg.BatchSize,
		"zero BatchSize should become loki.DefaultBatchSize")
	assert.Equal(t, loki.DefaultMaxBatchBytes, cfg.MaxBatchBytes,
		"zero MaxBatchBytes should become loki.DefaultMaxBatchBytes")
	assert.Equal(t, loki.DefaultFlushInterval, cfg.FlushInterval,
		"zero FlushInterval should become loki.DefaultFlushInterval")
	assert.Equal(t, loki.DefaultTimeout, cfg.Timeout,
		"zero Timeout should become loki.DefaultTimeout")
	assert.Equal(t, loki.DefaultMaxRetries, cfg.MaxRetries,
		"zero MaxRetries should become loki.DefaultMaxRetries")
	assert.Equal(t, loki.DefaultBufferSize, cfg.BufferSize,
		"zero BufferSize should become loki.DefaultBufferSize")
}

// ---------------------------------------------------------------------------
// TestValidateConfig_BoundaryValues — all fields at documented limits pass
// ---------------------------------------------------------------------------

func TestValidateConfig_BoundaryValues(t *testing.T) {
	t.Parallel()

	t.Run("all fields at maximum", func(t *testing.T) {
		t.Parallel()

		cfg := loki.Config{
			URL:           "https://loki.example.com/loki/api/v1/push",
			BatchSize:     loki.MaxBatchSize,
			MaxBatchBytes: loki.MaxMaxBatchBytes,
			FlushInterval: loki.MaxFlushInterval,
			Timeout:       loki.MaxTimeout,
			MaxRetries:    loki.MaxMaxRetries,
			BufferSize:    loki.MaxBufferSize,
		}
		require.NoError(t, loki.ValidateLokiConfig(&cfg),
			"all fields at documented maximum should be accepted")
	})

	t.Run("all fields at minimum", func(t *testing.T) {
		t.Parallel()

		cfg := loki.Config{
			URL:           "https://loki.example.com/loki/api/v1/push",
			BatchSize:     1, // minimum batch_size (zero triggers default)
			MaxBatchBytes: loki.MinMaxBatchBytes,
			FlushInterval: loki.MinFlushInterval,
			Timeout:       loki.MinTimeout,
			MaxRetries:    1, // zero triggers default; 1 is the minimum explicit value
			BufferSize:    loki.MinBufferSize,
		}
		require.NoError(t, loki.ValidateLokiConfig(&cfg),
			"all fields at documented minimum should be accepted")
	})

	t.Run("one above batch_size maximum rejected", func(t *testing.T) {
		t.Parallel()

		cfg := loki.Config{
			URL:       "https://loki.example.com/loki/api/v1/push",
			BatchSize: loki.MaxBatchSize + 1,
		}
		err := loki.ValidateLokiConfig(&cfg)
		require.Error(t, err)
		assert.ErrorIs(t, err, audit.ErrConfigInvalid)
		assert.Contains(t, err.Error(), "batch_size")
	})

	t.Run("one below max_batch_bytes minimum rejected", func(t *testing.T) {
		t.Parallel()

		cfg := loki.Config{
			URL:           "https://loki.example.com/loki/api/v1/push",
			MaxBatchBytes: loki.MinMaxBatchBytes - 1,
		}
		err := loki.ValidateLokiConfig(&cfg)
		require.Error(t, err)
		assert.ErrorIs(t, err, audit.ErrConfigInvalid)
		assert.Contains(t, err.Error(), "max_batch_bytes")
	})

	t.Run("one above buffer_size maximum rejected", func(t *testing.T) {
		t.Parallel()

		cfg := loki.Config{
			URL:        "https://loki.example.com/loki/api/v1/push",
			BufferSize: loki.MaxBufferSize + 1,
		}
		err := loki.ValidateLokiConfig(&cfg)
		require.Error(t, err)
		assert.ErrorIs(t, err, audit.ErrConfigInvalid)
		assert.Contains(t, err.Error(), "buffer_size")
	})
}

// ---------------------------------------------------------------------------
// TestConfigString_Redaction — String() must not expose credentials
// ---------------------------------------------------------------------------

func TestConfigString_Redaction(t *testing.T) {
	t.Parallel()

	t.Run("no auth shows none", func(t *testing.T) {
		t.Parallel()

		cfg := &loki.Config{URL: "https://loki.example.com/loki/api/v1/push", BatchSize: 50}
		s := cfg.String()

		// URL is sanitised to scheme+host — path/query/fragment dropped
		// to keep token placements (tenant in path, bearer in query)
		// out of debug logs. See TestLokiConfig_String_RedactsURLQueryAndFragment.
		assert.Contains(t, s, "https://loki.example.com",
			"String() must include the sanitised URL")
		assert.NotContains(t, s, "/loki/api/v1/push",
			"path must be stripped from sanitised URL")
		assert.Contains(t, s, "none",
			"String() must show auth=none when no credentials are set")
	})

	t.Run("basic auth hides both username and password", func(t *testing.T) {
		t.Parallel()

		const username = "alice"
		const password = "super-secret-pass"

		cfg := &loki.Config{
			URL:       "https://loki.example.com/loki/api/v1/push",
			BasicAuth: &loki.BasicAuth{Username: username, Password: password},
			BatchSize: 50,
		}
		s := cfg.String()

		assert.NotContains(t, s, username,
			"String() must NOT expose the basic auth username")
		assert.NotContains(t, s, password,
			"String() must NOT expose the basic auth password")
		assert.Contains(t, s, "basic_auth",
			"String() must indicate the auth type is basic_auth")
	})

	t.Run("bearer token hides token value", func(t *testing.T) {
		t.Parallel()

		const secret = "eyJhbGciOiJSUzI1NiJ9.super-secret-jwt-payload"

		cfg := &loki.Config{
			URL:         "https://loki.example.com/loki/api/v1/push",
			BearerToken: secret,
			BatchSize:   50,
		}
		s := cfg.String()

		assert.NotContains(t, s, secret,
			"String() must NOT expose the bearer token value")
		assert.True(t, strings.Contains(s, "bearer_token"),
			"String() must indicate the auth type is bearer_token")
	})

	t.Run("Format prevents credential leak via %+v", func(t *testing.T) {
		t.Parallel()

		const password = "format-leak-secret"
		cfg := &loki.Config{
			URL:       "https://loki.example.com/loki/api/v1/push",
			BasicAuth: &loki.BasicAuth{Username: "user", Password: password},
		}
		s := fmt.Sprintf("%+v", cfg)
		assert.NotContains(t, s, password,
			"%%+v must NOT expose credentials; Format() should intercept all verbs")
	})

	t.Run("Format prevents credential leak via %#v", func(t *testing.T) {
		t.Parallel()

		const token = "gosstring-leak-token"
		cfg := &loki.Config{
			URL:         "https://loki.example.com/loki/api/v1/push",
			BearerToken: token,
		}
		s := fmt.Sprintf("%#v", cfg)
		assert.NotContains(t, s, token,
			"%%#v must NOT expose credentials; Format() should intercept")
	})

	t.Run("BasicAuth String redacts credentials", func(t *testing.T) {
		t.Parallel()

		ba := loki.BasicAuth{Username: "alice", Password: "secret-password"}
		s := ba.String()
		assert.NotContains(t, s, "alice",
			"BasicAuth String must not expose username")
		assert.NotContains(t, s, "secret-password",
			"BasicAuth String must not expose password")
		assert.Contains(t, s, "REDACTED")
	})

	t.Run("value Config format does not leak BearerToken", func(t *testing.T) {
		t.Parallel()

		cfg := loki.Config{
			URL:         "https://loki.example.com/push",
			BearerToken: "value-format-leak-token",
		}
		// cfg is a value, not &cfg — value receiver must still intercept.
		s := fmt.Sprintf("%+v", cfg)
		assert.NotContains(t, s, "value-format-leak-token",
			"%%+v on Config value must NOT expose BearerToken")
	})

	t.Run("BasicAuth GoString redacts credentials", func(t *testing.T) {
		t.Parallel()

		ba := loki.BasicAuth{Username: "alice", Password: "secret-password"}
		s := fmt.Sprintf("%#v", ba)
		assert.NotContains(t, s, "alice",
			"BasicAuth GoString must not expose username")
		assert.NotContains(t, s, "secret-password",
			"BasicAuth GoString must not expose password")
		assert.Contains(t, s, "REDACTED")
	})
}

// ---------------------------------------------------------------------------
// TestBuildLokiTLSConfig — TLS configuration building
// ---------------------------------------------------------------------------

func TestBuildLokiTLSConfig(t *testing.T) {
	t.Parallel()

	t.Run("nil TLSPolicy defaults to TLS 1.3", func(t *testing.T) {
		t.Parallel()

		cfg := &loki.Config{URL: "https://loki.example.com/push"}
		tlsCfg, warnings, err := loki.BuildLokiTLSConfig(cfg)
		require.NoError(t, err)
		assert.Empty(t, warnings)
		assert.Equal(t, uint16(tls.VersionTLS13), tlsCfg.MinVersion,
			"default TLS config must require TLS 1.3")
		assert.Empty(t, tlsCfg.Certificates)
		assert.Nil(t, tlsCfg.RootCAs)
	})

	t.Run("TLSPolicy applies overrides", func(t *testing.T) {
		t.Parallel()

		cfg := &loki.Config{
			URL:       "https://loki.example.com/push",
			TLSPolicy: &audit.TLSPolicy{AllowTLS12: true},
		}
		tlsCfg, _, err := loki.BuildLokiTLSConfig(cfg)
		require.NoError(t, err)
		assert.Equal(t, uint16(tls.VersionTLS12), tlsCfg.MinVersion,
			"AllowTLS12 should set minimum to TLS 1.2")
	})

	t.Run("invalid cert path returns error", func(t *testing.T) {
		t.Parallel()

		cfg := &loki.Config{
			URL:     "https://loki.example.com/push",
			TLSCert: "/nonexistent/client.crt",
			TLSKey:  "/nonexistent/client.key",
		}
		_, _, err := loki.BuildLokiTLSConfig(cfg)
		require.Error(t, err)
		// text-only: config.go:549 returns raw fmt.Errorf without an audit sentinel wrap.
		assert.Contains(t, err.Error(), "load client certificate")
	})

	t.Run("invalid CA path returns error", func(t *testing.T) {
		t.Parallel()

		cfg := &loki.Config{
			URL:   "https://loki.example.com/push",
			TLSCA: "/nonexistent/ca.pem",
		}
		_, _, err := loki.BuildLokiTLSConfig(cfg)
		require.Error(t, err)
		// text-only: config.go:557 returns raw fmt.Errorf without an audit sentinel wrap.
		assert.Contains(t, err.Error(), "read ca certificate")
	})

	t.Run("invalid CA PEM returns error", func(t *testing.T) {
		t.Parallel()

		// Write a temporary file that is not valid PEM.
		dir := t.TempDir()
		caFile := filepath.Join(dir, "bad-ca.pem")
		require.NoError(t, os.WriteFile(caFile, []byte("not-pem-data"), 0o600))

		cfg := &loki.Config{
			URL:   "https://loki.example.com/push",
			TLSCA: caFile,
		}
		_, _, err := loki.BuildLokiTLSConfig(cfg)
		require.Error(t, err)
		// text-only: config.go:561 returns raw fmt.Errorf without an audit sentinel wrap.
		assert.Contains(t, err.Error(), "no valid pem blocks")
	})
}

// TestLokiConfig_String_RedactsURLQueryAndFragment verifies that
// common Loki token placements — tenant IDs in path, bearer tokens
// or tenant_id query strings, URL fragments — are dropped by
// Config.String(). Closes #475 AC #2.
func TestLokiConfig_String_RedactsURLQueryAndFragment(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		url        string
		mustAppear string
		mustNot    []string
	}{
		{
			name: "tenant_id query and auth query",
			url:  "https://loki.example.com/loki/api/v1/push?tenant_id=leak-tenant&auth_key=leak-auth-XYZ",
			mustNot: []string{
				"leak-tenant", "leak-auth-XYZ",
				"tenant_id", "auth_key",
			},
			// NOTE: "auth=" appears in the output as the auth-type
			// marker ("auth=none"), so we cannot assert its absence
			// — that's a legitimate part of the String format.
			mustAppear: "https://loki.example.com",
		},
		{
			name:       "tenant in path",
			url:        "https://loki.example.com/tenants/LEAK-TENANT/push",
			mustNot:    []string{"LEAK-TENANT", "/tenants", "/push"},
			mustAppear: "https://loki.example.com",
		},
		{
			name:       "fragment",
			url:        "https://loki.example.com/push#session=LEAK-FRAG",
			mustNot:    []string{"LEAK-FRAG", "session=", "#"},
			mustAppear: "https://loki.example.com",
		},
		{
			name:       "invalid URL falls back to placeholder",
			url:        "::://not-a-url",
			mustNot:    []string{"not-a-url"},
			mustAppear: "<invalid-url>",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := loki.Config{URL: tt.url}
			s := cfg.String()
			for _, forbidden := range tt.mustNot {
				assert.NotContains(t, s, forbidden,
					"String() leaked %q from URL %q", forbidden, tt.url)
			}
			assert.Contains(t, s, tt.mustAppear,
				"String() must include the sanitised form")
		})
	}
}

// TestLokiSanitiseClientError_RedactsURLInUrlError verifies that an
// *url.Error from http.Client.Do has its URL stripped to scheme+host
// before being logged. Closes #475 H1.
func TestLokiSanitiseClientError_RedactsURLInUrlError(t *testing.T) {
	t.Parallel()
	in := &url.Error{
		Op:  "Post",
		URL: "https://loki.example.com/tenants/LEAK-TENANT/push?token=LEAK",
		Err: fmt.Errorf("connection refused"),
	}
	out := loki.SanitiseClientError(in)
	msg := out.Error()
	assert.Contains(t, msg, "Post")
	assert.Contains(t, msg, "connection refused")
	assert.Contains(t, msg, "https://loki.example.com")
	assert.NotContains(t, msg, "LEAK-TENANT")
	assert.NotContains(t, msg, "LEAK", "query-string token must be stripped")
	assert.NotContains(t, msg, "/tenants", "path must be stripped")
}

// TestLokiSanitiseClientError_PassesThroughNonUrlErrors verifies that
// plain errors not wrapping *url.Error are unchanged.
func TestLokiSanitiseClientError_PassesThroughNonUrlErrors(t *testing.T) {
	t.Parallel()
	plain := fmt.Errorf("plain error, no URL")
	got := loki.SanitiseClientError(plain)
	assert.Equal(t, plain, got)
}

// TestLoki_ConstructionWarningsRoutedToInjectedLogger verifies that
// TLS-policy warnings emitted during New() route through the
// WithDiagnosticLogger-supplied logger rather than slog.Default().
// Closes #490.
func TestLoki_ConstructionWarningsRoutedToInjectedLogger(t *testing.T) {
	var buf strings.Builder
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})
	injected := slog.New(handler)

	out, err := loki.New(&loki.Config{
		URL:                        "https://loki.example.com/loki/api/v1/push",
		TLSPolicy:                  &audit.TLSPolicy{AllowTLS12: true, AllowWeakCiphers: true},
		AllowPrivateRanges:         true,
		BatchSize:                  1,
		FlushInterval:              100 * time.Millisecond,
		Timeout:                    1 * time.Second,
		BufferSize:                 1000,
		DisableStartupVerification: true,
	}, nil, loki.WithDiagnosticLogger(injected))
	require.NoError(t, err)
	require.NoError(t, out.Close())

	logged := buf.String()
	assert.Contains(t, logged, "weak ciphers",
		"expected weak-ciphers warning on injected logger, got: %q", logged)
	assert.Contains(t, logged, "output=loki",
		"warning should carry output=loki attribute: %q", logged)
}

// TestLoki_NilDiagnosticLoggerFallsBackToDefault verifies
// WithDiagnosticLogger(nil) does not nil-deref and falls back to
// slog.Default for warning emission.
func TestLoki_NilDiagnosticLoggerFallsBackToDefault(t *testing.T) {
	var buf strings.Builder
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	out, err := loki.New(&loki.Config{
		URL:                        "https://loki.example.com/loki/api/v1/push",
		TLSPolicy:                  &audit.TLSPolicy{AllowTLS12: true, AllowWeakCiphers: true},
		AllowPrivateRanges:         true,
		BatchSize:                  1,
		FlushInterval:              100 * time.Millisecond,
		Timeout:                    1 * time.Second,
		BufferSize:                 1000,
		DisableStartupVerification: true,
	}, nil, loki.WithDiagnosticLogger(nil))
	require.NoError(t, err)
	require.NoError(t, out.Close())

	assert.Contains(t, buf.String(), "weak ciphers",
		"WithDiagnosticLogger(nil) should fall back to slog.Default")
}
