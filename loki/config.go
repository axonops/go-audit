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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/axonops/audit"
)

// Default values for [Config] fields.
const (
	// DefaultBatchSize is the default maximum events per push request.
	DefaultBatchSize = 100

	// DefaultMaxBatchBytes is the default maximum uncompressed push
	// payload size in bytes (1 MiB).
	DefaultMaxBatchBytes = 1 << 20

	// DefaultFlushInterval is the default maximum time between push
	// requests when the batch has not yet reached [DefaultBatchSize].
	DefaultFlushInterval = 5 * time.Second

	// DefaultTimeout is the default HTTP request timeout.
	DefaultTimeout = 10 * time.Second

	// DefaultMaxRetries is the default retry count for 429/5xx.
	DefaultMaxRetries = 3

	// DefaultBufferSize is the default internal event buffer capacity.
	DefaultBufferSize = 10_000

	// DefaultMaxEventBytes is the default per-event size cap at
	// [Output.Write] entry (#688). Events whose payload byte length
	// exceeds this are rejected with [audit.ErrEventTooLarge]. 1 MiB
	// matches the cap used by syslog and webhook.
	DefaultMaxEventBytes = 1 << 20 // 1 MiB
)

// Upper bounds for [Config] fields.
const (
	// MaxBatchSize is the upper bound for [Config.BatchSize].
	MaxBatchSize = 10_000

	// MaxMaxBatchBytes is the upper bound for [Config.MaxBatchBytes] (10 MiB).
	MaxMaxBatchBytes = 10 << 20

	// MaxFlushInterval is the upper bound for [Config.FlushInterval].
	MaxFlushInterval = 5 * time.Minute

	// MaxTimeout is the upper bound for [Config.Timeout].
	MaxTimeout = 5 * time.Minute

	// MaxMaxRetries is the upper bound for [Config.MaxRetries].
	MaxMaxRetries = 20

	// MaxBufferSize is the upper bound for [Config.BufferSize].
	MaxBufferSize = 1_000_000

	// MaxMaxEventBytes is the upper bound for [Config.MaxEventBytes] (10 MiB).
	MaxMaxEventBytes = 10 << 20
)

// Lower bounds for [Config] fields.
const (
	// MinMaxBatchBytes is the lower bound for [Config.MaxBatchBytes] (1 KiB).
	MinMaxBatchBytes = 1024

	// MinFlushInterval is the lower bound for [Config.FlushInterval].
	MinFlushInterval = 100 * time.Millisecond

	// MinTimeout is the lower bound for [Config.Timeout].
	MinTimeout = 1 * time.Second

	// MinBufferSize is the lower bound for [Config.BufferSize].
	MinBufferSize = 100

	// MinMaxEventBytes is the lower bound for [Config.MaxEventBytes] (1 KiB).
	MinMaxEventBytes = 1 << 10
)

// validLabelName matches Loki's label name requirement.
var validLabelName = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// BasicAuth holds HTTP basic authentication credentials for Loki push
// requests. Mutually exclusive with [Config.BearerToken]. The library
// redacts credentials in all log output and string representations.
type BasicAuth struct {
	// Username is the HTTP basic auth username. REQUIRED when BasicAuth
	// is non-nil; an empty value causes [New] to return an error.
	Username string

	// Password is the HTTP basic auth password. MAY be empty when the
	// Loki endpoint accepts username-only authentication.
	Password string
}

// LabelConfig controls which fields become Loki stream labels.
type LabelConfig struct {
	// Static labels are constant across all events from this output.
	// Keys must match [a-zA-Z_][a-zA-Z0-9_]* (Loki requirement).
	Static map[string]string

	// Dynamic controls which per-event fields become labels.
	// Zero value means all dynamic labels are included.
	Dynamic DynamicLabels
}

// DynamicLabels toggles which per-event fields become Loki stream
// labels. All fields default to included (zero value = include).
// Set Exclude* to true to remove a field from labels.
//
// Cardinality is the primary tuning concern: each unique
// label-value combination across all included fields creates a
// distinct Loki stream. Including high-cardinality fields (like
// PID, which changes on every process restart) can quickly exhaust
// Loki's per-tenant stream limits. The default-included list has
// been chosen so that typical multi-host, multi-app deployments
// stay within Loki's recommended ceiling of <100k active streams
// per tenant. Tighten by excluding fields that contribute the most
// unique values.
type DynamicLabels struct {
	// ExcludeAppName drops the `app_name` label. Cardinality impact:
	// equal to the number of distinct applications writing to the
	// same Loki tenant. Usually low (<20). Exclude only if you index
	// by app_name through a different mechanism.
	ExcludeAppName bool

	// ExcludeHost drops the `host` label. Cardinality impact: equal
	// to the number of distinct hosts. Significant in fleet-style
	// deployments (hundreds to thousands of hosts) — consider
	// excluding and storing host as a JSON field instead.
	ExcludeHost bool

	// ExcludeTimezone drops the `timezone` label. Cardinality impact:
	// negligible (typically 1 — the deployment's timezone). Safe to
	// keep included.
	ExcludeTimezone bool

	// ExcludePID drops the `pid` label. Cardinality impact: HIGH —
	// every process restart creates a new label value, and labels
	// are never garbage-collected for the active retention window.
	// Strongly recommend excluding in production unless PID is
	// genuinely needed for stream filtering.
	ExcludePID bool

	// ExcludeEventType drops the `event_type` label. Cardinality
	// impact: equal to the size of the taxonomy (number of distinct
	// event types). Usually moderate (10-200). Useful for stream
	// filtering by event type — exclude only if your alerting paths
	// query JSON fields instead.
	ExcludeEventType bool

	// ExcludeEventCategory drops the `event_category` label.
	// Cardinality impact: low (typically 5-20 categories). Useful
	// for routing by category in alerts.
	ExcludeEventCategory bool

	// ExcludeSeverity drops the `severity` label. Cardinality impact:
	// at most 11 (severity 0-10). Almost always safe to keep
	// included; primary use is severity-based alert routing.
	ExcludeSeverity bool
}

// Config holds configuration for the Loki [Output].
type Config struct { //nolint:govet // fieldalignment: readability preferred
	// URL is the full Loki push API endpoint, including path.
	// Example: "https://loki:3100/loki/api/v1/push"
	// REQUIRED; must be https unless AllowInsecureHTTP is true.
	URL string

	// BasicAuth configures HTTP basic authentication. Mutually
	// exclusive with BearerToken.
	BasicAuth *BasicAuth

	// BearerToken sets the Authorization: Bearer header. Mutually
	// exclusive with BasicAuth.
	BearerToken string

	// TenantID sets the X-Scope-OrgID header for Loki multi-tenancy.
	TenantID string

	// Headers are additional HTTP headers sent with every push request.
	Headers map[string]string

	// Labels controls stream label configuration.
	Labels LabelConfig

	// TLSCA is the path to a PEM-encoded CA certificate used to verify
	// the Loki server certificate. When empty, the system root CA pool
	// is used. Use this field when Loki is configured with a private or
	// self-signed CA.
	TLSCA string

	// TLSCert is the path to a PEM-encoded client certificate for mTLS
	// authentication. MUST be set together with [Config.TLSKey]; setting
	// one without the other causes [New] to return an error.
	TLSCert string

	// TLSKey is the path to the PEM-encoded private key for the client
	// certificate. MUST be set together with [Config.TLSCert]; setting
	// one without the other causes [New] to return an error.
	TLSKey string

	// TLSPolicy controls the TLS version and cipher suite policy applied
	// to all Loki connections. When nil, the default policy (TLS 1.3
	// only) is used. See [audit.TLSPolicy] for details on enabling TLS
	// 1.2 fallback.
	TLSPolicy *audit.TLSPolicy

	// BatchSize is the maximum events per push request.
	// Zero defaults to [DefaultBatchSize] (100).
	// Values above [MaxBatchSize] (10,000) are rejected.
	BatchSize int

	// MaxBatchBytes is the maximum uncompressed payload size per push
	// request. Zero defaults to [DefaultMaxBatchBytes] (1 MiB).
	// Valid range: [MinMaxBatchBytes] (1 KiB) to [MaxMaxBatchBytes] (10 MiB).
	MaxBatchBytes int

	// MaxEventBytes is the maximum byte length accepted by
	// [Output.Write] and [Output.WriteWithMetadata] for a single
	// event. Events exceeding this cap are rejected with
	// [audit.ErrEventTooLarge] wrapping [audit.ErrValidation] and
	// [audit.OutputMetrics.RecordDrop] is called. Zero defaults to
	// [DefaultMaxEventBytes] (1 MiB). Values below
	// [MinMaxEventBytes] (1 KiB) or above [MaxMaxEventBytes]
	// (10 MiB) cause [New] to return an error wrapping
	// [audit.ErrConfigInvalid]. Introduced by #688 as a defence
	// against consumer-controlled memory pressure.
	MaxEventBytes int

	// FlushInterval is the maximum time between push requests when the
	// batch has not yet reached BatchSize. The timer resets after
	// every flush. Zero defaults to [DefaultFlushInterval] (5s).
	FlushInterval time.Duration

	// BufferSize is the internal async event buffer capacity. When full,
	// new events are dropped. Zero defaults to [DefaultBufferSize]
	// (10,000).
	BufferSize int

	// Timeout is the HTTP request timeout covering the full push
	// request/response lifecycle. Zero defaults to [DefaultTimeout]
	// (10s). Validation enforces [MinTimeout] (1s) and [MaxTimeout]
	// (5m).
	//
	// The transport-level [http.Transport.ResponseHeaderTimeout] is
	// derived as `max(Timeout/2, 1*time.Second)` — the 1-second floor
	// prevents a short Timeout (at the lower bound of 1s, half would
	// otherwise be 500 ms) from producing a per-stage timeout too
	// small to complete a real TLS handshake and server response
	// (#485).
	Timeout time.Duration

	// MaxRetries is the retry count for 429 and 5xx responses.
	// Zero defaults to [DefaultMaxRetries] (3).
	MaxRetries int

	// Gzip enables gzip compression of push requests (the only
	// compression algorithm Loki accepts). The YAML key is
	// `gzip`. The YAML factory defaults to true when the key is
	// omitted; the Go zero value is false for programmatic
	// construction.
	Gzip bool

	// AllowInsecureHTTP permits http:// URLs. MUST NOT be true in
	// production.
	AllowInsecureHTTP bool

	// AllowPrivateRanges permits connections to RFC 1918 private
	// addresses. Intended for testing and private deployments.
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

// String returns a safe representation of the config without credentials.
// Value receiver ensures both Config and *Config are protected.
//
// URL is sanitised to scheme+host only — path, query, and fragment are
// dropped. Common Loki token placements include tenant IDs in the path
// (`/tenants/<TENANT>/push`) and bearer tokens in query strings —
// stripping everything beyond the host keeps these out of debug logs.
// Network traffic itself is unaffected; this is a debug-log safety net.
func (c Config) String() string {
	auth := "none"
	if c.BasicAuth != nil {
		auth = "basic_auth"
	} else if c.BearerToken != "" {
		auth = "bearer_token"
	}
	return fmt.Sprintf("LokiConfig{url=%q, auth=%s, gzip=%t, batch_size=%d}",
		sanitizeURLForLog(c.URL), auth, c.Gzip, c.BatchSize)
}

// sanitizeURLForLog returns the scheme+host portion of a URL, dropping
// path, query, and fragment. Used in [Config.String] and the TLS
// warning log site to keep secrets (bearer tokens in query strings,
// tenant IDs in path segments) out of diagnostic output.
//
// Returns "<invalid-url>" when raw cannot be parsed, so
// [Config.String] remains safe to call on unvalidated configs.
//
// Duplicated in webhook/config.go — intentional per #542.
func sanitizeURLForLog(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "<invalid-url>"
	}
	return u.Scheme + "://" + u.Host
}

// Format implements [fmt.Formatter] to prevent credential leakage via
// all format verbs including %+v and %#v. Value receiver ensures both
// Config and *Config are protected.
func (c Config) Format(f fmt.State, _ rune) { //nolint:gocritic // hugeParam: value receiver required to intercept fmt verbs on Config values
	_, _ = fmt.Fprint(f, c.String())
}

// String returns a redacted representation to prevent credential leakage.
func (ba BasicAuth) String() string { return "BasicAuth{REDACTED}" }

// GoString implements [fmt.GoStringer] to prevent credential leakage via %#v.
func (ba BasicAuth) GoString() string { return "BasicAuth{REDACTED}" }

// validateLokiConfig validates the config and applies defaults.
// It modifies cfg in place (applying defaults) and returns an error
// if any field is invalid.
func validateLokiConfig(cfg *Config) error {
	if err := validateLokiURL(cfg); err != nil {
		return err
	}

	if cfg.BasicAuth != nil && cfg.BearerToken != "" {
		return fmt.Errorf("%w: loki: basic_auth and bearer_token are mutually exclusive", audit.ErrConfigInvalid)
	}

	if cfg.BasicAuth != nil && cfg.BasicAuth.Username == "" {
		return fmt.Errorf("%w: loki: basic_auth.username must not be empty", audit.ErrConfigInvalid)
	}

	if err := validateLokiTLSFiles(cfg); err != nil {
		return err
	}

	if err := validateStaticLabels(cfg.Labels.Static); err != nil {
		return err
	}

	applyLokiDefaults(cfg)

	if err := validateLokiBounds(cfg); err != nil {
		return err
	}

	return validateHeaders(cfg.Headers)
}

// validateLokiTLSFiles checks TLS cert/key pairing and file existence.
func validateLokiTLSFiles(cfg *Config) error {
	if (cfg.TLSCert != "") != (cfg.TLSKey != "") {
		return fmt.Errorf("%w: loki: tls_cert and tls_key must both be set or both empty", audit.ErrConfigInvalid)
	}
	for _, path := range []string{cfg.TLSCert, cfg.TLSKey, cfg.TLSCA} {
		if path != "" {
			fi, err := os.Stat(path)
			if err != nil {
				return fmt.Errorf("%w: loki: tls file %q: %w", audit.ErrConfigInvalid, path, err)
			}
			if fi.IsDir() {
				return fmt.Errorf("%w: loki: tls file %q is a directory", audit.ErrConfigInvalid, path)
			}
		}
	}
	return nil
}

// validateLokiURL checks the URL field for presence, scheme, and credentials.
func validateLokiURL(cfg *Config) error {
	if cfg.URL == "" {
		return fmt.Errorf("%w: loki: url must not be empty", audit.ErrConfigInvalid)
	}

	u, err := url.Parse(cfg.URL)
	if err != nil {
		return fmt.Errorf("%w: loki: invalid url: %w", audit.ErrConfigInvalid, err)
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%w: loki: url scheme must be http or https, got %q", audit.ErrConfigInvalid, u.Scheme)
	}

	if u.Scheme == "http" && !cfg.AllowInsecureHTTP {
		return fmt.Errorf("%w: loki: url must be https (got %q); set allow_insecure_http for testing", audit.ErrConfigInvalid, u.Scheme)
	}

	if u.User != nil {
		return fmt.Errorf("%w: loki: url must not contain credentials; use basic_auth for authentication", audit.ErrConfigInvalid)
	}

	return nil
}

// validateStaticLabels checks that all static label names match the Loki
// label name pattern and have non-empty values without control characters.
func validateStaticLabels(labels map[string]string) error {
	for name, val := range labels {
		if !validLabelName.MatchString(name) {
			return fmt.Errorf("%w: loki: static label name %q is invalid: must match [a-zA-Z_][a-zA-Z0-9_]*", audit.ErrConfigInvalid, name)
		}
		if val == "" {
			return fmt.Errorf("%w: loki: static label %q has empty value", audit.ErrConfigInvalid, name)
		}
		if containsControlChar(val) {
			return fmt.Errorf("%w: loki: static label %q value contains control characters", audit.ErrConfigInvalid, name)
		}
	}
	return nil
}

// containsControlChar reports whether s contains any ASCII control
// character (bytes 0x00-0x1F).
func containsControlChar(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 {
			return true
		}
	}
	return false
}

// applyLokiDefaults fills zero-value fields with documented defaults.
// For the programmatic API, zero means "not set". Negative values from
// the YAML path (sentinel for explicit zero) pass through to validation.
func applyLokiDefaults(cfg *Config) {
	if cfg.BatchSize == 0 {
		cfg.BatchSize = DefaultBatchSize
	}
	if cfg.MaxBatchBytes == 0 {
		cfg.MaxBatchBytes = DefaultMaxBatchBytes
	}
	if cfg.MaxEventBytes == 0 {
		cfg.MaxEventBytes = DefaultMaxEventBytes
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
}

// validateLokiBounds checks that all numeric/duration fields are within
// documented bounds. Must be called after applyLokiDefaults.
func validateLokiBounds(cfg *Config) error {
	if err := checkIntBound("batch_size", cfg.BatchSize, 1, MaxBatchSize); err != nil {
		return err
	}
	if err := checkIntBound("max_batch_bytes", cfg.MaxBatchBytes, MinMaxBatchBytes, MaxMaxBatchBytes); err != nil {
		return err
	}
	if err := checkIntBound("max_event_bytes", cfg.MaxEventBytes, MinMaxEventBytes, MaxMaxEventBytes); err != nil {
		return err
	}
	if err := checkDurBound("flush_interval", cfg.FlushInterval, MinFlushInterval, MaxFlushInterval); err != nil {
		return err
	}
	if err := checkDurBound("timeout", cfg.Timeout, MinTimeout, MaxTimeout); err != nil {
		return err
	}
	if err := checkIntBound("max_retries", cfg.MaxRetries, 1, MaxMaxRetries); err != nil {
		return err
	}
	return checkIntBound("buffer_size", cfg.BufferSize, MinBufferSize, MaxBufferSize)
}

func checkIntBound(name string, val, lo, hi int) error {
	if val < lo || val > hi {
		return fmt.Errorf("%w: loki: %s %d out of range [%d, %d]", audit.ErrConfigInvalid, name, val, lo, hi)
	}
	return nil
}

func checkDurBound(name string, val, lo, hi time.Duration) error {
	if val < lo || val > hi {
		return fmt.Errorf("%w: loki: %s %s out of range [%s, %s]", audit.ErrConfigInvalid, name, val, lo, hi)
	}
	return nil
}

// restrictedHeaders are header names managed by the library. Consumers
// must use the dedicated Config fields (BasicAuth, BearerToken, TenantID)
// instead of setting these via the Headers map.
var restrictedHeaders = map[string]struct{}{
	"authorization":    {},
	"x-scope-orgid":    {},
	"content-type":     {},
	"content-encoding": {},
	"host":             {},
}

// validateHeaders checks for CRLF injection and restricted header names.
func validateHeaders(headers map[string]string) error {
	for k, v := range headers {
		if strings.ContainsAny(k, "\r\n") || strings.ContainsAny(v, "\r\n") {
			return fmt.Errorf("%w: loki: header %q contains CR/LF", audit.ErrConfigInvalid, k)
		}
		if _, blocked := restrictedHeaders[strings.ToLower(k)]; blocked {
			return fmt.Errorf("%w: loki: header %q is managed by the library; use the dedicated config field", audit.ErrConfigInvalid, k)
		}
	}
	return nil
}

// buildLokiTLSConfig creates a TLS configuration from the Loki config.
// Warnings from TLS policy application are returned for the caller to log.
func buildLokiTLSConfig(cfg *Config) (*tls.Config, []string, error) {
	// Apply handles nil TLSPolicy (defaults to TLS 1.3 only),
	// consistent with webhook and syslog builders.
	tlsCfg, warnings := cfg.TLSPolicy.Apply(nil)

	if cfg.TLSCert != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
		if err != nil {
			return nil, nil, fmt.Errorf("audit/loki: load client certificate: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	if cfg.TLSCA != "" {
		caPEM, err := os.ReadFile(cfg.TLSCA)
		if err != nil {
			return nil, nil, fmt.Errorf("audit/loki: read ca certificate: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, nil, fmt.Errorf("audit/loki: ca certificate contains no valid pem blocks")
		}
		tlsCfg.RootCAs = pool
	}

	return tlsCfg, warnings, nil
}
