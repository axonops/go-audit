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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/axonops/audit"
)

// Default values for [Config] fields.
const (
	// DefaultBatchSize is the default maximum events per batch.
	DefaultBatchSize = 100

	// DefaultFlushInterval is the default maximum time between
	// batch flushes.
	DefaultFlushInterval = 5 * time.Second

	// DefaultTimeout is the default HTTP request timeout.
	DefaultTimeout = 10 * time.Second

	// DefaultMaxRetries is the default retry count for 5xx/429.
	DefaultMaxRetries = 3

	// DefaultBufferSize is the default internal buffer capacity.
	DefaultBufferSize = 10_000

	// MaxBatchSize is the upper bound for BatchSize.
	MaxBatchSize = 10_000

	// MaxBufferSize is the upper bound for BufferSize.
	MaxBufferSize = 1_000_000

	// MaxMaxRetries is the upper bound for MaxRetries.
	MaxMaxRetries = 20

	// DefaultMaxBatchBytes is the default maximum accumulated batch
	// payload size in bytes before a flush is triggered. 1 MiB
	// matches [loki.DefaultMaxBatchBytes] and [syslog.DefaultMaxBatchBytes].
	// Events exceeding this threshold alone trigger an immediate
	// flush (the event is sent in its own HTTP POST; it is never
	// dropped).
	DefaultMaxBatchBytes = 1 << 20 // 1 MiB

	// MinMaxBatchBytes is the lower bound for MaxBatchBytes.
	MinMaxBatchBytes = 1 << 10 // 1 KiB

	// MaxMaxBatchBytes is the upper bound for MaxBatchBytes. Matches
	// the range accepted by Loki and syslog; real-world endpoints
	// typically reject request bodies larger than a few MiB anyway.
	MaxMaxBatchBytes = 10 << 20 // 10 MiB

	// DefaultMaxEventBytes is the default per-event size cap at
	// [Output.Write] entry (#688). Events with payload byte length
	// exceeding this are rejected with [audit.ErrEventTooLarge].
	// 1 MiB matches loki and syslog.
	DefaultMaxEventBytes = 1 << 20 // 1 MiB

	// MinMaxEventBytes is the lower bound for MaxEventBytes.
	MinMaxEventBytes = 1 << 10 // 1 KiB

	// MaxMaxEventBytes is the upper bound for MaxEventBytes.
	MaxMaxEventBytes = 10 << 20 // 10 MiB
)

// Config holds configuration for [Output].
type Config struct { //nolint:govet // fieldalignment: pointer field TLSPolicy extends scan region by 8 bytes; readability preferred
	// URL is the HTTP endpoint to POST batched events to.
	// REQUIRED. MUST be https:// unless [AllowInsecureHTTP] is true.
	URL string

	// Headers are custom HTTP headers added to every request.
	// Common use: "Authorization: Bearer <token>" or
	// "Authorization: Splunk <token>".
	//
	// Header NAMES whose lower-case form contains any of "auth",
	// "key", "secret", or "token" have their VALUES replaced with
	// "[REDACTED]" in [Config.String], [Config.GoString], and
	// [Config.Format] output — a defence-in-depth safety net against
	// `fmt.Sprintf("%+v", cfg)` and `slog.Debug("cfg", cfg)` leakage.
	// Header names themselves are NOT redacted — they appear in full
	// so that operators can identify which headers are configured.
	//
	// Header names must not contain CRLF. Values are sent verbatim in
	// the HTTP request regardless of redaction in debug output.
	Headers map[string]string

	// TLSCA is the path to a custom CA certificate for the webhook
	// endpoint. When empty, the system root CA pool is used.
	TLSCA string

	// TLSCert is the path to a client certificate for mTLS.
	// Both TLSCert and TLSKey must be set for client authentication.
	TLSCert string

	// TLSKey is the path to the client private key for mTLS.
	// Both TLSCert and TLSKey must be set for client authentication.
	TLSKey string

	// TLSPolicy controls TLS version and cipher suite policy. When nil,
	// the default policy (TLS 1.3 only) is used. See [audit.TLSPolicy] for
	// details on enabling TLS 1.2 fallback.
	TLSPolicy *audit.TLSPolicy

	// FlushInterval is the maximum time between batch flushes.
	// The timer resets after every flush (batch-size or timer
	// triggered). Zero defaults to [DefaultFlushInterval] (5s).
	FlushInterval time.Duration

	// Timeout is the HTTP request timeout covering the full
	// request/response lifecycle including body read.
	// Zero defaults to [DefaultTimeout] (10s).
	//
	// The transport-level [http.Transport.ResponseHeaderTimeout] is
	// derived as `max(Timeout/2, 1*time.Second)` — the 1-second floor
	// prevents a misconfigured short Timeout (for example 1 ms) from
	// producing a per-stage timeout too small to complete a real TLS
	// handshake and server response (#485).
	Timeout time.Duration

	// BatchSize is the maximum events per HTTP request.
	// Zero defaults to [DefaultBatchSize] (100).
	// Values above [MaxBatchSize] (10,000) are rejected.
	BatchSize int

	// MaxBatchBytes is the maximum accumulated payload size (sum of
	// event byte lengths) in a single batch. When the threshold is
	// reached, the batch flushes immediately regardless of
	// [Config.BatchSize]. Zero defaults to [DefaultMaxBatchBytes]
	// (1 MiB). Values below [MinMaxBatchBytes] (1 KiB) or above
	// [MaxMaxBatchBytes] (10 MiB) cause [New] to return an error
	// wrapping [audit.ErrConfigInvalid].
	//
	// A single event exceeding MaxBatchBytes is flushed alone — it
	// is never dropped. Matches the conventions established by
	// [loki.Config.MaxBatchBytes] and
	// [github.com/axonops/audit/syslog.Config.MaxBatchBytes].
	MaxBatchBytes int

	// MaxEventBytes is the maximum byte length accepted by
	// [Output.Write] for a single event. Events exceeding this cap
	// are rejected with [audit.ErrEventTooLarge] wrapping
	// [audit.ErrValidation] and [audit.OutputMetrics.RecordDrop] is
	// called. Zero defaults to [DefaultMaxEventBytes] (1 MiB).
	// Values below [MinMaxEventBytes] (1 KiB) or above
	// [MaxMaxEventBytes] (10 MiB) cause [New] to return an error
	// wrapping [audit.ErrConfigInvalid]. Introduced by #688 as a
	// defence against consumer-controlled memory pressure.
	MaxEventBytes int

	// BufferSize is the internal async buffer capacity. When full,
	// new events are dropped and [audit.OutputMetrics.RecordDrop] is called.
	// Zero defaults to [DefaultBufferSize] (10,000).
	// Values above [MaxBufferSize] (1,000,000) are rejected.
	BufferSize int

	// MaxRetries is the retry count for 5xx and 429 responses.
	// Zero defaults to [DefaultMaxRetries] (3).
	// Values above [MaxMaxRetries] (20) are rejected.
	MaxRetries int

	// AllowInsecureHTTP permits http:// URLs. Default: false.
	// MUST NOT be set to true in production. Plaintext HTTP exposes
	// credentials in request headers (including Authorization tokens)
	// to network observers. Use only for local development and testing.
	AllowInsecureHTTP bool

	// AllowPrivateRanges disables SSRF protection for private and
	// loopback IP ranges. Default: false. Enable for webhooks on
	// private networks. Cloud metadata (169.254.169.254) remains
	// blocked regardless.
	AllowPrivateRanges bool

	// DisableStartupVerification skips the construction-time
	// connectivity probe. When false (zero value), [New] performs a
	// TCP dial and — for https URLs — a TLS handshake before
	// returning, so misconfigured or unreachable destinations fail
	// fast at application start-up rather than surfacing as silent
	// event loss on the first flush.
	//
	// Set to true for sidecar deployments where the destination may
	// not yet be ready when the application calls [New], or for
	// short-lived CLI tools that must start regardless of receiver
	// availability.
	//
	// YAML: verify_on_startup (positive form; default true, set
	// false to disable).
	DisableStartupVerification bool

	// StartupVerificationTimeout bounds the construction-time
	// connectivity probe. Zero defaults to
	// [DefaultStartupVerificationTimeout] (5s). The probe budget
	// covers the TCP dial and — for https URLs — the TLS handshake
	// under a single [context.Context]. Operators on slow WAN paths
	// can raise this; CI/local development is fine with the default.
	//
	// Ignored when DisableStartupVerification is true.
	StartupVerificationTimeout time.Duration
}

// String returns a human-readable representation of the config with
// credentials redacted. This prevents credential leakage when configs
// are accidentally logged via %v or %+v.
//
// URL is sanitised to scheme+host only — path, query, and fragment are
// dropped (common token placements: Slack /services/.../<TOKEN>,
// Datadog ?dd-api-key=, Splunk HEC ?token=). Header values for names
// matching the credential-name rule described on [Config.Headers] are
// replaced with [REDACTED]. Network traffic itself is unaffected;
// this is a debug-log safety net, not the primary defence.
func (c Config) String() string {
	return fmt.Sprintf("WebhookConfig{url=%q, headers=%s, batch_size=%d, timeout=%s}",
		sanitizeURLForLog(c.URL), redactHeaders(c.Headers), c.BatchSize, c.Timeout)
}

// GoString returns the same redacted representation as [Config.String].
// This prevents credential leakage when configs are formatted via %#v.
func (c Config) GoString() string { return c.String() } //nolint:gocritic // hugeParam: value receiver required by fmt.GoStringer

// Format writes the redacted representation to the formatter.
// This prevents credential leakage via %+v and all other format verbs.
func (c Config) Format(f fmt.State, _ rune) { _, _ = fmt.Fprint(f, c.String()) } //nolint:gocritic // hugeParam: value receiver required by fmt.Formatter

// sanitizeURLForLog returns the scheme+host portion of a URL, dropping
// path, query, and fragment. Used in Config.String / TLS warning log
// sites to keep secrets (tokens in path, query-string API keys) out
// of diagnostic output.
//
// Returns "<invalid-url>" when raw cannot be parsed, so
// [Config.String] remains safe to call on unvalidated configs.
//
// Duplicated in loki/config.go — intentional per #542.
func sanitizeURLForLog(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "<invalid-url>"
	}
	return u.Scheme + "://" + u.Host
}

// credentialHeaderPatterns is the case-insensitive substring set used
// by [redactHeaders] to decide whether a header value is sensitive.
// The set is deliberately broad — over-redaction is cheap, a missed
// credential is the whole reason the mechanism exists. Patterns:
//
//   - auth       — Authorization, X-Auth-Token, WWW-Authenticate
//   - key        — X-API-Key, X-Public-Key, Api-Key
//   - secret     — X-Shared-Secret
//   - token      — Bearer tokens, CSRF-Token
//   - cookie     — Cookie, Set-Cookie (session tokens)
//   - password   — basic-auth legacy carriers
//   - credential — X-Credential, X-Credentials
//   - signature  — GitHub X-Hub-Signature, HMAC request signing
//   - hmac       — X-Hmac, Hmac-Request
//   - session    — X-Session-Id, Session-Id
var credentialHeaderPatterns = []string{
	"auth",
	"key",
	"secret",
	"token",
	"cookie",
	"password",
	"credential",
	"signature",
	"hmac",
	"session",
}

// redactHeaders returns a deterministic map-style string
// representation of hdrs with credential values replaced by
// [REDACTED]. Keys are sorted so output is byte-stable across calls.
// Empty or nil maps return "map[]".
func redactHeaders(hdrs map[string]string) string {
	if len(hdrs) == 0 {
		return "map[]"
	}
	names := make([]string, 0, len(hdrs))
	for name := range hdrs {
		names = append(names, name)
	}
	sort.Strings(names)

	var b strings.Builder
	b.WriteString("map[")
	for i, name := range names {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(name)
		b.WriteByte(':')
		if isCredentialHeader(name) {
			b.WriteString("[REDACTED]")
		} else {
			b.WriteString(hdrs[name])
		}
	}
	b.WriteByte(']')
	return b.String()
}

// isCredentialHeader reports whether a header name's lower-case form
// contains any of the [credentialHeaderPatterns].
func isCredentialHeader(name string) bool {
	lower := strings.ToLower(name)
	for _, p := range credentialHeaderPatterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

// validateWebhookConfig checks the config for correctness, applying
// defaults where needed.
func validateWebhookConfig(cfg *Config) error {
	if cfg.URL == "" {
		return fmt.Errorf("%w: webhook url must not be empty", audit.ErrConfigInvalid)
	}

	u, err := url.Parse(cfg.URL)
	if err != nil {
		return fmt.Errorf("%w: webhook url invalid: %w", audit.ErrConfigInvalid, err)
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%w: webhook url scheme must be http or https (got %q)", audit.ErrConfigInvalid, u.Scheme)
	}

	if !cfg.AllowInsecureHTTP && u.Scheme != "https" {
		return fmt.Errorf("%w: webhook url must be https (got %q); set AllowInsecureHTTP for testing", audit.ErrConfigInvalid, u.Scheme)
	}

	// Reject URLs with embedded credentials — they would leak in logs.
	if u.User != nil {
		return fmt.Errorf("%w: webhook url must not contain credentials; use Headers for auth", audit.ErrConfigInvalid)
	}

	if err := validateWebhookHeaders(cfg.Headers); err != nil {
		return err
	}

	if err := validateWebhookTLSFiles(cfg); err != nil {
		return err
	}

	applyWebhookDefaults(cfg)
	return validateWebhookLimits(cfg)
}

// validateWebhookTLSFiles checks TLS cert/key pairing and file existence.
func validateWebhookTLSFiles(cfg *Config) error {
	if (cfg.TLSCert != "") != (cfg.TLSKey != "") {
		return fmt.Errorf("%w: webhook tls_cert and tls_key must both be set or both empty", audit.ErrConfigInvalid)
	}
	for _, path := range []string{cfg.TLSCert, cfg.TLSKey, cfg.TLSCA} {
		if path != "" {
			fi, err := os.Stat(path)
			if err != nil {
				return fmt.Errorf("%w: webhook tls file %q: %w", audit.ErrConfigInvalid, path, err)
			}
			if fi.IsDir() {
				return fmt.Errorf("%w: webhook tls file %q is a directory", audit.ErrConfigInvalid, path)
			}
		}
	}
	return nil
}

// validateWebhookHeaders checks header names and values for CRLF injection.
func validateWebhookHeaders(headers map[string]string) error {
	for k, v := range headers {
		if strings.ContainsAny(k, "\r\n") {
			return fmt.Errorf("%w: webhook header name %q contains invalid characters", audit.ErrConfigInvalid, k)
		}
		if strings.ContainsAny(v, "\r\n") {
			return fmt.Errorf("%w: webhook header value for %q contains invalid characters", audit.ErrConfigInvalid, k)
		}
	}
	return nil
}

// applyWebhookDefaults fills zero-valued fields with documented defaults.
// For the programmatic API, zero means "not set". Negative values from
// the YAML path (sentinel for explicit zero) pass through to validation.
func applyWebhookDefaults(cfg *Config) {
	if cfg.BatchSize == 0 {
		cfg.BatchSize = DefaultBatchSize
	}
	if cfg.FlushInterval == 0 {
		cfg.FlushInterval = DefaultFlushInterval
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.MaxRetries == 0 {
		cfg.MaxRetries = DefaultMaxRetries
	}
	if cfg.BufferSize == 0 {
		cfg.BufferSize = DefaultBufferSize
	}
	if cfg.MaxBatchBytes == 0 {
		cfg.MaxBatchBytes = DefaultMaxBatchBytes
	}
	if cfg.MaxEventBytes == 0 {
		cfg.MaxEventBytes = DefaultMaxEventBytes
	}
}

// validateWebhookLimits checks bounds on numeric fields. Linear
// guard sequence — each if maps 1-1 to a documented Config field
// constraint. Extracting per-field helpers would hide the pattern.
//
//nolint:gocyclo,cyclop // linear guard sequence; see comment above.
func validateWebhookLimits(cfg *Config) error {
	if cfg.BatchSize < 1 {
		return fmt.Errorf("%w: webhook batch_size must be at least 1 (got %d)",
			audit.ErrConfigInvalid, cfg.BatchSize)
	}
	if cfg.MaxRetries < 1 {
		return fmt.Errorf("%w: webhook max_retries must be at least 1 (got %d); this is the total number of delivery attempts",
			audit.ErrConfigInvalid, cfg.MaxRetries)
	}
	if cfg.BufferSize < 1 {
		return fmt.Errorf("%w: webhook buffer_size must be at least 1 (got %d)",
			audit.ErrConfigInvalid, cfg.BufferSize)
	}
	if cfg.BatchSize > MaxBatchSize {
		return fmt.Errorf("%w: webhook batch_size %d exceeds maximum %d",
			audit.ErrConfigInvalid, cfg.BatchSize, MaxBatchSize)
	}
	if cfg.BufferSize > MaxBufferSize {
		return fmt.Errorf("%w: webhook buffer_size %d exceeds maximum %d",
			audit.ErrConfigInvalid, cfg.BufferSize, MaxBufferSize)
	}
	if cfg.MaxRetries > MaxMaxRetries {
		return fmt.Errorf("%w: webhook max_retries %d exceeds maximum %d",
			audit.ErrConfigInvalid, cfg.MaxRetries, MaxMaxRetries)
	}
	if cfg.FlushInterval < 0 {
		return fmt.Errorf("%w: webhook flush_interval must not be negative (got %v)",
			audit.ErrConfigInvalid, cfg.FlushInterval)
	}
	if cfg.MaxBatchBytes < MinMaxBatchBytes {
		return fmt.Errorf("%w: webhook max_batch_bytes %d below minimum %d",
			audit.ErrConfigInvalid, cfg.MaxBatchBytes, MinMaxBatchBytes)
	}
	if cfg.MaxBatchBytes > MaxMaxBatchBytes {
		return fmt.Errorf("%w: webhook max_batch_bytes %d exceeds maximum %d",
			audit.ErrConfigInvalid, cfg.MaxBatchBytes, MaxMaxBatchBytes)
	}
	if cfg.MaxEventBytes < MinMaxEventBytes {
		return fmt.Errorf("%w: webhook max_event_bytes %d below minimum %d",
			audit.ErrConfigInvalid, cfg.MaxEventBytes, MinMaxEventBytes)
	}
	if cfg.MaxEventBytes > MaxMaxEventBytes {
		return fmt.Errorf("%w: webhook max_event_bytes %d exceeds maximum %d",
			audit.ErrConfigInvalid, cfg.MaxEventBytes, MaxMaxEventBytes)
	}
	if cfg.Timeout < 0 {
		return fmt.Errorf("%w: webhook timeout must not be negative (got %v)",
			audit.ErrConfigInvalid, cfg.Timeout)
	}
	return nil
}

// buildWebhookTLSConfig creates a TLS configuration for webhook
// connections using the [audit.TLSPolicy] from the config (defaulting to
// TLS 1.3 only when nil). InsecureSkipVerify is never set.
//
// Warnings emitted by [audit.TLSPolicy.Apply] are routed through the
// given logger (pass [slog.Default] for caller-default behaviour).
func buildWebhookTLSConfig(cfg *Config, logger *slog.Logger) (*tls.Config, error) {
	tlsCfg, warnings := cfg.TLSPolicy.Apply(nil)
	for _, w := range warnings {
		// Log only scheme+host to avoid leaking query-parameter tokens.
		logger.Warn(w, "output", "webhook", "url", sanitizeURLForLog(cfg.URL))
	}

	if cfg.TLSCert != "" && cfg.TLSKey != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
		if err != nil {
			return nil, fmt.Errorf("audit/webhook: tls: load client certificate: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	if cfg.TLSCA != "" {
		caCert, err := os.ReadFile(cfg.TLSCA)
		if err != nil {
			return nil, fmt.Errorf("audit/webhook: tls: read ca certificate: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("audit/webhook: tls: parse ca certificate: invalid pem block")
		}
		tlsCfg.RootCAs = pool
	}

	return tlsCfg, nil
}
