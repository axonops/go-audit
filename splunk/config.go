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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/axonops/audit"
)

// Default values for Config fields. These align with the Splunk HEC
// research findings (issue #55 pre-implementation comment):
//   - 800 KiB batch byte cap leaves 200 KiB headroom under the 1 MB
//     stock HEC max_content_length, so over-cap drops never reach the
//     server (HTTP 413).
//   - gzip ON by default — 6-12× compression ratio on audit-shaped
//     JSON; the CPU cost is dominated by network savings.
//   - 10 events/request typical at scale, but 500 events/request
//     covers bulk-friendly HEC ingest with payload-byte-cap as the
//     dominant limiter.
//   - 10s HTTP timeout matches the OpenTelemetry splunkhecexporter
//     default; matches loki/webhook.
//   - 10 retries matches the syslog precedent for audit-grade
//     persistence; the buffer absorbs longer outages.
const (
	DefaultBatchSize                  = 500
	DefaultMaxBatchBytes              = 819200  // 800 KiB (1 MB stock cap with safety margin)
	DefaultMaxEventBytes              = 1 << 20 // 1 MiB
	DefaultFlushInterval              = 2 * time.Second
	DefaultTimeout                    = 10 * time.Second
	DefaultMaxRetries                 = 10
	DefaultBufferSize                 = 10_000
	DefaultRetryBaseDelay             = 500 * time.Millisecond
	DefaultRetryMaxDelay              = 30 * time.Second
	DefaultRetryJitter                = 0.2 // ±20%
	DefaultAckPollInterval            = 10 * time.Second
	DefaultAckResendWindow            = 5 * time.Minute
	DefaultStartupVerificationTimeout = 5 * time.Second
	defaultSourcetype                 = "audit:event"
	defaultSource                     = "audit"
	defaultIdleConnTimeout            = 90 * time.Second
)

// Bounds on numeric Config values. Set as constants so unit tests and
// godoc can reference them.
const (
	MinBatchSize     = 1
	MaxBatchSize     = 10_000
	MinMaxBatchBytes = 1024             // 1 KiB
	MaxMaxBatchBytes = 1024 * 1024      // 1 MiB (Splunk Cloud hard cap)
	MinMaxEventBytes = 1024             // 1 KiB
	MaxMaxEventBytes = 10 * 1024 * 1024 // 10 MiB
	MinFlushInterval = 100 * time.Millisecond
	MaxFlushInterval = 5 * time.Minute
	MinTimeout       = 1 * time.Second
	MaxTimeout       = 5 * time.Minute
	MinMaxRetries    = 0
	MaxMaxRetries    = 100
	MinBufferSize    = 100
	MaxBufferSize    = 1_000_000
)

// Endpoint is a typed enum selecting which HEC endpoint the output
// posts to.
type Endpoint int

const (
	// EndpointEvent (default) — POST /services/collector/event. Each
	// event is wrapped in a `{"event":..., "time":...}` envelope with
	// per-event metadata (sourcetype, source, index, host) and
	// optional indexed fields via the `fields` envelope object.
	EndpointEvent Endpoint = iota

	// EndpointRaw — POST /services/collector/raw. Events sent as
	// newline-delimited bodies; metadata travels in query string. No
	// envelope wrapping. Indexed `fields` extraction is not supported.
	EndpointRaw
)

// String returns the metric-label and YAML form of the endpoint.
func (e Endpoint) String() string {
	switch e {
	case EndpointEvent:
		return "event"
	case EndpointRaw:
		return "raw"
	default:
		return "unknown"
	}
}

// UnmarshalYAML decodes an [Endpoint] from the YAML strings "event"
// or "raw" (case-insensitive). Empty string defaults to "event".
// Unknown strings return [ErrConfigInvalid].
func (e *Endpoint) UnmarshalYAML(unmarshal func(any) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "event":
		*e = EndpointEvent
	case "raw":
		*e = EndpointRaw
	default:
		return fmt.Errorf("%w: endpoint must be \"event\" or \"raw\", got %q", ErrConfigInvalid, s)
	}
	return nil
}

// MarshalYAML returns the canonical YAML string form.
func (e Endpoint) MarshalYAML() (any, error) {
	return e.String(), nil
}

// AckMode selects indexer-acknowledgement behaviour. See
// [About HEC Indexer Acknowledgment](https://help.splunk.com/en/splunk-enterprise/get-started/get-data-in/10.0/get-data-with-http-event-collector/about-http-event-collector-indexer-acknowledgment)
// for the protocol details. Only [AckModeOff] is implemented in PR 1;
// non-Off values produce [ErrPR1NotImplemented] from [New].
type AckMode int

const (
	// AckModeOff (default) — no `X-Splunk-Request-Channel` header,
	// no polling. HTTP 200 is the only durability signal.
	AckModeOff AckMode = iota

	// AckModeBestEffort — channel GUID generated, ack polled, results
	// exposed as metrics; buffer progress NOT gated.
	AckModeBestEffort

	// AckModeRequired — events stay in the buffer until ack returns
	// positive; on `AckResendWindow` timeout the events re-send.
	// Compliance-grade durability.
	AckModeRequired
)

// String returns the metric-label and YAML form of the ack mode.
func (a AckMode) String() string {
	switch a {
	case AckModeOff:
		return "off"
	case AckModeBestEffort:
		return "best_effort"
	case AckModeRequired:
		return "required"
	default:
		return "unknown"
	}
}

// UnmarshalYAML decodes an [AckMode] from the strings "off",
// "best_effort", or "required" (case-insensitive). Empty string
// defaults to "off". Unknown strings return [ErrConfigInvalid].
func (a *AckMode) UnmarshalYAML(unmarshal func(any) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "off":
		*a = AckModeOff
	case "best_effort":
		*a = AckModeBestEffort
	case "required":
		*a = AckModeRequired
	default:
		return fmt.Errorf("%w: ack_mode must be \"off\", \"best_effort\", or \"required\", got %q", ErrConfigInvalid, s)
	}
	return nil
}

// MarshalYAML returns the canonical YAML string form.
func (a AckMode) MarshalYAML() (any, error) {
	return a.String(), nil
}

// Config configures a Splunk HEC [Output]. See the package doc for
// usage patterns. Field names match the YAML keys via snake_case
// conversion in the outputconfig factory (e.g. `BatchSize` ↔
// `batch_size`).
type Config struct { //nolint:govet // fieldalignment: readability preferred (grouped by concern)
	// ============ Required ============

	// URL is the HEC endpoint. Two accepted forms:
	//   "https://splunk.example.com:8088"           - Splunk Enterprise / self-managed
	//   "splunkcloud://acme-prod"                   - Splunk Cloud stack shortcut
	//
	// The `splunkcloud://<stack>` form is expanded at config validation
	// to `https://http-inputs-<stack>.splunkcloud.com:443`. The stack
	// name MUST match `^[a-z0-9][a-z0-9-]{0,62}$`. The shortcut form
	// rejects any non-empty path, port, query, fragment, or opaque
	// component (use the full `https://` form for non-standard cases),
	// and rejects [Config.TLSCert] / [Config.TLSKey] (Splunk Cloud HEC
	// does not support mTLS — use a self-managed HTTPS proxy with
	// mTLS termination if mTLS is required).
	URL string

	// Token is the HEC token (opaque string). Required. Validated to
	// reject CR/LF/NUL (header injection) and prefixes "Splunk " /
	// "Bearer " (foot-gun where the consumer accidentally included the
	// scheme prefix in the secret).
	Token string

	// ============ Endpoint and metadata ============

	Endpoint Endpoint

	Sourcetype string // default: "audit:event"
	Source     string // default: "audit"
	Index      string // empty = HEC token's default index
	Host       string // default: os.Hostname()

	// IndexedFields enumerates field names whose values are copied
	// from the event JSON into the HEC envelope `fields` object for
	// index-time extraction. String values only. Ignored on /raw.
	IndexedFields []string

	// ============ Batching and event size ============

	BatchSize     int
	MaxBatchBytes int
	MaxEventBytes int
	FlushInterval time.Duration

	// ============ Compression and HTTP ============

	// Gzip is a *bool so the YAML decoder can distinguish "unset"
	// (use default true) from "explicitly false".
	Gzip *bool

	// UserAgent header value. Default
	// "audit-splunk/<library-version>". MUST match
	// ^[A-Za-z0-9._/-]+$ — validated at New() time to prevent
	// header injection.
	UserAgent string

	Timeout time.Duration

	// Headers are additional HTTP headers sent on every request.
	// Header values are validated for CRLF; credential-shaped values
	// are redacted in Config.String().
	Headers map[string]string

	// ============ Retry ============

	MaxRetries     int
	RetryBaseDelay time.Duration
	RetryMaxDelay  time.Duration
	RetryJitter    float64

	// ============ Buffer ============

	BufferSize int

	// ============ Indexer acknowledgement (PR 2) ============

	AckMode         AckMode
	AckPollInterval time.Duration
	AckResendWindow time.Duration

	// ============ TLS and network safety ============

	TLSPolicy          *audit.TLSPolicy
	TLSCA              string
	TLSCert            string
	TLSKey             string
	AllowInsecureHTTP  bool
	AllowPrivateRanges bool

	// ============ Health and lifecycle ============

	DisableStartupVerification bool
	StartupVerificationTimeout time.Duration

	// ============ Routing ============

	EventRoute audit.EventRoute
}

// applyDefaults fills in zero-valued fields with their package
// defaults. Mutates the receiver. Called by [Validate] and [New].
func (c *Config) applyDefaults() {
	if c.BatchSize == 0 {
		c.BatchSize = DefaultBatchSize
	}
	if c.MaxBatchBytes == 0 {
		c.MaxBatchBytes = DefaultMaxBatchBytes
	}
	if c.MaxEventBytes == 0 {
		c.MaxEventBytes = DefaultMaxEventBytes
	}
	if c.FlushInterval == 0 {
		c.FlushInterval = DefaultFlushInterval
	}
	if c.Timeout == 0 {
		c.Timeout = DefaultTimeout
	}
	if c.MaxRetries == 0 {
		c.MaxRetries = DefaultMaxRetries
	}
	if c.RetryBaseDelay == 0 {
		c.RetryBaseDelay = DefaultRetryBaseDelay
	}
	if c.RetryMaxDelay == 0 {
		c.RetryMaxDelay = DefaultRetryMaxDelay
	}
	if c.RetryJitter == 0 {
		c.RetryJitter = DefaultRetryJitter
	}
	if c.BufferSize == 0 {
		c.BufferSize = DefaultBufferSize
	}
	if c.Gzip == nil {
		t := true
		c.Gzip = &t
	}
	if c.UserAgent == "" {
		c.UserAgent = "audit-splunk/" + libraryVersion()
	}
	if c.Sourcetype == "" {
		c.Sourcetype = defaultSourcetype
	}
	if c.Source == "" {
		c.Source = defaultSource
	}
	if c.Host == "" {
		host, err := os.Hostname()
		if err == nil {
			c.Host = host
		}
	}
	if c.StartupVerificationTimeout == 0 {
		c.StartupVerificationTimeout = DefaultStartupVerificationTimeout
	}
	if c.AckMode != AckModeOff {
		if c.AckPollInterval == 0 {
			c.AckPollInterval = DefaultAckPollInterval
		}
		if c.AckResendWindow == 0 {
			c.AckResendWindow = DefaultAckResendWindow
		}
	}
}

// validUserAgent matches RFC 7230 visible-ASCII tokens with a small
// allow-list. Header-injection defence.
var validUserAgent = regexp.MustCompile(`^[A-Za-z0-9._/ -]+$`)

// validCloudStack matches a Splunk Cloud stack name per AWS
// stack-naming rules: ≤63 chars, lowercase alphanumeric + hyphen,
// starts alphanumeric. Defends against host-smuggling
// (acme-prod.evil.com etc).
var validCloudStack = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// Validate checks the configuration for usable values, applies
// defaults to unset fields, and returns the first violation as a
// wrapped [ErrConfigInvalid]. Idempotent. Mutates the receiver to
// apply defaults.
func (c *Config) Validate() error { //nolint:cyclop,gocyclo,funlen,gocognit // long-but-flat validation; clarity > decomposition
	if c == nil {
		return fmt.Errorf("%w: nil config", ErrConfigInvalid)
	}
	c.applyDefaults()

	// --- URL ---
	if c.URL == "" {
		return fmt.Errorf("%w: URL is required", ErrConfigInvalid)
	}
	u, err := url.Parse(c.URL)
	if err != nil {
		return fmt.Errorf("%w: URL parse: %v", ErrConfigInvalid, err)
	}
	if u.User != nil {
		return fmt.Errorf("%w: URL must not contain user-info credentials", ErrConfigInvalid)
	}
	switch u.Scheme {
	case "splunkcloud":
		// Expand to canonical Splunk Cloud HEC URL. The stack name
		// lives in the host component (URL form
		// `splunkcloud://<stack>`). Reject any non-empty path / port
		// / query / fragment / opaque (e.g., `splunkcloud:foo` with
		// no double-slash sets u.Opaque) — they make no sense for
		// the shortcut form and a typo is more likely than intent.
		if u.Opaque != "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Port() != "" {
			return fmt.Errorf("%w: splunkcloud:// URL must be the bare form splunkcloud://<stack> with no path, port, query, or fragment", ErrConfigInvalid)
		}
		if err := ValidateCloudStack(u.Host); err != nil {
			return err
		}
		// Splunk Cloud HEC presents a public-CA-signed cert and does
		// NOT support custom TLS material (mTLS client cert/key or
		// custom CA bundle). Reject the ambiguous config rather than
		// silently dropping the operator's settings — somebody who
		// configured TLS material expects it to be used.
		if c.TLSCert != "" || c.TLSKey != "" || c.TLSCA != "" {
			return fmt.Errorf("%w: splunkcloud:// does not support custom TLS material (TLSCert/TLSKey/TLSCA); target https:// to a self-managed proxy with mTLS termination if required", ErrConfigInvalid)
		}
		// Rewrite to the canonical form. Idempotent: a re-Validate()
		// observes https:// and takes the https branch directly.
		c.URL = "https://http-inputs-" + u.Host + ".splunkcloud.com:443"
	case "https":
		// ok
	case "http":
		if !c.AllowInsecureHTTP {
			return fmt.Errorf("%w: URL scheme http is rejected unless AllowInsecureHTTP=true", ErrConfigInvalid)
		}
	default:
		return fmt.Errorf("%w: URL scheme must be https (or http with AllowInsecureHTTP=true); got %q", ErrConfigInvalid, u.Scheme)
	}

	// --- Token ---
	if c.Token == "" {
		return fmt.Errorf("%w: Token is required", ErrConfigInvalid)
	}
	lowerToken := strings.ToLower(c.Token)
	if strings.HasPrefix(lowerToken, "splunk ") {
		return fmt.Errorf("%w: Token must not start with %q (scheme prefix is added automatically)", ErrConfigInvalid, "Splunk ")
	}
	if strings.HasPrefix(lowerToken, "bearer ") {
		return fmt.Errorf("%w: Token must not start with %q (HEC uses the Splunk scheme, not Bearer)", ErrConfigInvalid, "Bearer ")
	}
	for i, r := range c.Token {
		// RFC 7230 visible-ASCII (0x21-0x7E) plus HTAB (0x09) and
		// SPACE (0x20). Reject CR/LF/NUL and control chars.
		if r == '\t' || r == ' ' || (r >= 0x21 && r <= 0x7e) {
			continue
		}
		return fmt.Errorf("%w: Token contains invalid character at position %d (only ASCII visible characters and HTAB allowed)", ErrConfigInvalid, i)
	}

	// --- Endpoint range ---
	if c.Endpoint < EndpointEvent || c.Endpoint > EndpointRaw {
		return fmt.Errorf("%w: Endpoint value %d out of range (must be EndpointEvent or EndpointRaw)", ErrConfigInvalid, c.Endpoint)
	}

	// --- AckMode range + PR 1 limit ---
	if c.AckMode < AckModeOff || c.AckMode > AckModeRequired {
		return fmt.Errorf("%w: AckMode value %d out of range (must be AckModeOff, AckModeBestEffort, or AckModeRequired)", ErrConfigInvalid, c.AckMode)
	}
	if c.AckMode != AckModeOff {
		return fmt.Errorf("%w: AckMode=%s ships in PR 2; use AckModeOff in PR 1", ErrPR1NotImplemented, c.AckMode)
	}

	// --- Numeric bounds ---
	if c.BatchSize < MinBatchSize || c.BatchSize > MaxBatchSize {
		return fmt.Errorf("%w: BatchSize=%d out of range [%d,%d]", ErrConfigInvalid, c.BatchSize, MinBatchSize, MaxBatchSize)
	}
	if c.MaxBatchBytes < MinMaxBatchBytes || c.MaxBatchBytes > MaxMaxBatchBytes {
		return fmt.Errorf("%w: MaxBatchBytes=%d out of range [%d,%d]", ErrConfigInvalid, c.MaxBatchBytes, MinMaxBatchBytes, MaxMaxBatchBytes)
	}
	if c.MaxEventBytes < MinMaxEventBytes || c.MaxEventBytes > MaxMaxEventBytes {
		return fmt.Errorf("%w: MaxEventBytes=%d out of range [%d,%d]", ErrConfigInvalid, c.MaxEventBytes, MinMaxEventBytes, MaxMaxEventBytes)
	}
	if c.FlushInterval < MinFlushInterval || c.FlushInterval > MaxFlushInterval {
		return fmt.Errorf("%w: FlushInterval=%s out of range [%s,%s]", ErrConfigInvalid, c.FlushInterval, MinFlushInterval, MaxFlushInterval)
	}
	if c.Timeout < MinTimeout || c.Timeout > MaxTimeout {
		return fmt.Errorf("%w: Timeout=%s out of range [%s,%s]", ErrConfigInvalid, c.Timeout, MinTimeout, MaxTimeout)
	}
	if c.MaxRetries < MinMaxRetries || c.MaxRetries > MaxMaxRetries {
		return fmt.Errorf("%w: MaxRetries=%d out of range [%d,%d]", ErrConfigInvalid, c.MaxRetries, MinMaxRetries, MaxMaxRetries)
	}
	if c.BufferSize < MinBufferSize || c.BufferSize > MaxBufferSize {
		return fmt.Errorf("%w: BufferSize=%d out of range [%d,%d]", ErrConfigInvalid, c.BufferSize, MinBufferSize, MaxBufferSize)
	}

	// --- User-Agent ---
	if !validUserAgent.MatchString(c.UserAgent) {
		return fmt.Errorf("%w: UserAgent contains characters outside [A-Za-z0-9._/ -]", ErrConfigInvalid)
	}

	// --- Headers ---
	for k, v := range c.Headers {
		if strings.ContainsAny(k, "\r\n\x00") || strings.ContainsAny(v, "\r\n\x00") {
			return fmt.Errorf("%w: Headers[%q] contains CR/LF/NUL", ErrConfigInvalid, k)
		}
		lower := strings.ToLower(k)
		if lower == "authorization" || lower == "x-splunk-request-channel" || lower == "content-encoding" || lower == "content-type" || lower == "user-agent" {
			return fmt.Errorf("%w: Headers[%q] is reserved by the Splunk output", ErrConfigInvalid, k)
		}
	}

	// --- TLS cert paths ---
	if c.TLSCA != "" {
		clean := filepath.Clean(c.TLSCA)
		if clean != c.TLSCA {
			c.TLSCA = clean
		}
	}
	if c.TLSCert != "" {
		clean := filepath.Clean(c.TLSCert)
		if clean != c.TLSCert {
			c.TLSCert = clean
		}
	}
	if c.TLSKey != "" {
		clean := filepath.Clean(c.TLSKey)
		if clean != c.TLSKey {
			c.TLSKey = clean
		}
	}
	if (c.TLSCert == "") != (c.TLSKey == "") {
		return fmt.Errorf("%w: TLSCert and TLSKey must be set together (mTLS requires both)", ErrConfigInvalid)
	}

	return nil
}

// ValidateCloudStack returns nil when `stack` matches the Splunk
// Cloud stack-name shape (`^[a-z0-9][a-z0-9-]{0,62}$`). Used by PR 2's
// `splunkcloud://<stack>` URL scheme handler; exposed now so PR 1
// can test the regex independently. Defends against host smuggling.
func ValidateCloudStack(stack string) error {
	if !validCloudStack.MatchString(stack) {
		return fmt.Errorf("%w: splunkcloud stack name %q does not match %s", ErrConfigInvalid, stack, validCloudStack.String())
	}
	return nil
}

// String returns a one-line, log-safe representation of the Config.
// The token is REDACTED; URL is sanitised to scheme+host. Implements
// [fmt.Stringer]. Matches the webhook precedent for log-safe Config
// repr.
func (c Config) String() string {
	gzip := "<default>"
	if c.Gzip != nil {
		if *c.Gzip {
			gzip = "true"
		} else {
			gzip = "false"
		}
	}
	return fmt.Sprintf("SplunkConfig{url=%q, endpoint=%s, sourcetype=%q, index=%q, gzip=%s, batch_size=%d, max_batch_bytes=%d, ack_mode=%s, token=REDACTED}",
		sanitizeURLForLog(c.URL),
		c.Endpoint,
		c.Sourcetype,
		c.Index,
		gzip,
		c.BatchSize,
		c.MaxBatchBytes,
		c.AckMode,
	)
}

// GoString is the verbose-formatter form (%#v); also redacts.
func (c Config) GoString() string {
	return c.String()
}

// Format implements [fmt.Formatter] so both %v and %+v produce the
// redacted form. Without this, fmt's default reflection-based
// formatter would print every field including the token.
func (c Config) Format(f fmt.State, _ rune) {
	_, _ = fmt.Fprint(f, c.String())
}

// sanitizeURLForLog parses the input URL and returns scheme://host.
// Strips any path, query, fragment, and user-info. If the URL fails
// to parse, returns "<invalid-url>" — never the original string.
func sanitizeURLForLog(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" {
		return "<invalid-url>"
	}
	return u.Scheme + "://" + u.Host
}

// buildTLSConfig produces a [*tls.Config] from the Config's TLS
// fields. Mirrors loki/config.go:565-593 (`buildLokiTLSConfig`).
// Returns the config, any warnings from the TLS policy application
// (e.g. weak ciphers allowed), and an error if cert/key/CA cannot
// be loaded.
func buildTLSConfig(c *Config) (*tls.Config, []string, error) {
	tlsCfg, warnings := c.TLSPolicy.Apply(nil)
	if c.TLSCert != "" && c.TLSKey != "" {
		cert, err := tls.LoadX509KeyPair(c.TLSCert, c.TLSKey)
		if err != nil {
			return nil, warnings, fmt.Errorf("audit/splunk: load client cert/key: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	if c.TLSCA != "" {
		caPEM, err := os.ReadFile(c.TLSCA)
		if err != nil {
			return nil, warnings, fmt.Errorf("audit/splunk: read CA bundle: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, warnings, fmt.Errorf("audit/splunk: CA bundle at %q contained no valid PEM certificates", c.TLSCA)
		}
		tlsCfg.RootCAs = pool
	}
	return tlsCfg, warnings, nil
}
