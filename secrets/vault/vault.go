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

package vault

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/axonops/audit"
	"github.com/axonops/audit/secrets"
)

// maxResponseSize is the maximum response body size accepted from the
// Vault server. Prevents memory exhaustion from a compromised server.
const maxResponseSize = 1 << 20 // 1 MiB

// errRedirectBlocked is returned by the redirect policy.
var errRedirectBlocked = errors.New("audit/secrets/vault: redirects are blocked")

// Config holds connection parameters for a HashiCorp Vault provider.
type Config struct { //nolint:govet // readability over alignment
	// Address is the Vault server URL. Required. Must use HTTPS.
	// Typically sourced from the VAULT_ADDR environment variable.
	Address string

	// Token is the authentication token. Required.
	// Typically sourced from the VAULT_TOKEN environment variable.
	Token string

	// Namespace is the Vault namespace prefix. Optional.
	// Set via X-Vault-Namespace header on every request.
	Namespace string

	// TLSCA is the path to a custom CA certificate PEM file for
	// verifying the Vault server's TLS certificate.
	TLSCA string

	// TLSCert is the path to a client certificate for mTLS
	// authentication.
	TLSCert string

	// TLSKey is the path to the client private key for mTLS
	// authentication.
	TLSKey string

	// TLSPolicy controls TLS version and cipher suite selection.
	// Nil defaults to TLS 1.3 only.
	TLSPolicy *audit.TLSPolicy

	// AllowPrivateRanges permits connections to RFC 1918 private
	// addresses and loopback. Required for local development where
	// Vault runs on 127.0.0.1. Cloud metadata endpoints remain
	// blocked. Default: false.
	AllowPrivateRanges bool

	// AllowInsecureHTTP permits http:// URLs. Default: false.
	// MUST NOT be set to true in production. Plaintext HTTP exposes
	// the authentication token to network observers. Use only for
	// local development with Docker Compose where Vault runs
	// on the internal Docker network.
	AllowInsecureHTTP bool
}

// String returns a credential-free representation of the config,
// suitable for debug logging via %v or %+v. Token is never printed;
// Address path/query/fragment are stripped; presence of TLS client
// cert and namespace is surfaced without the values (#475).
func (c Config) String() string {
	tokenState := "unset"
	if c.Token != "" {
		tokenState = "[REDACTED]"
	}
	namespaceState := "unset"
	if c.Namespace != "" {
		namespaceState = "set"
	}
	tlsMode := "none"
	if c.TLSCert != "" {
		tlsMode = "mtls"
	} else if c.TLSCA != "" {
		tlsMode = "tls"
	}
	return fmt.Sprintf("vault.Config{address=%q, token=%s, namespace=%s, tls=%s}",
		sanitizeAddressForLog(c.Address), tokenState, namespaceState, tlsMode)
}

// GoString returns the same redacted representation as [Config.String].
// Prevents credential leakage when a Config is formatted via %#v.
func (c Config) GoString() string { return c.String() } //nolint:gocritic // hugeParam: value receiver required by fmt.GoStringer

// Format writes the redacted representation to the formatter.
// Prevents credential leakage via %+v and all other format verbs.
func (c Config) Format(f fmt.State, _ rune) { //nolint:gocritic // hugeParam: value receiver required by fmt.Formatter
	_, _ = fmt.Fprint(f, c.String())
}

// sanitizeAddressForLog returns the scheme+host portion of the
// configured Address URL, dropping path/query/fragment. Returns
// "<invalid-url>" for unparseable input.
func sanitizeAddressForLog(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "<invalid-url>"
	}
	return u.Scheme + "://" + u.Host
}

// Provider resolves secret references from a HashiCorp Vault KV v2
// engine. Construction validates the address and builds an SSRF-safe
// HTTP client but performs no network I/O. The first [Resolve] call
// initiates the connection.
type Provider struct { //nolint:govet // readability over alignment
	client *http.Client
	addr   string // full base URL
	host   string // host:port for String() output
	token  []byte // stored as bytes for zeroing in Close()
	ns     string // X-Vault-Namespace header; empty = no namespace
}

// New creates a HashiCorp Vault provider from the given configuration.
// Validates the address (HTTPS required unless [Config.AllowInsecureHTTP]
// is set), builds the TLS config and HTTP client, but performs no
// network I/O.
//
// Error messages do not echo caller-supplied substrings (the
// configured address, scheme, or token); the audit/secrets/vault
// logger category surfaces the failure class without leakage. Set
// log-level debug on that category if a deployment-time root cause
// is needed (#651).
func New(cfg *Config) (*Provider, error) { //nolint:gocyclo,cyclop // linear validation pipeline
	// Validate address.
	if cfg.Address == "" {
		return nil, fmt.Errorf("%w: audit/secrets/vault: address is required", audit.ErrConfigInvalid)
	}
	u, err := url.Parse(cfg.Address)
	if err != nil {
		// Do not wrap url.Error — stdlib embeds the full input
		// address in its error string. The address is operator-
		// controlled config, not a ref's path/key, but logging it
		// in error chains still constitutes a leakage vector. See
		// #651 + the sentinel-injection test in vault_test.go.
		return nil, fmt.Errorf("%w: audit/secrets/vault: address is not a valid URL", audit.ErrConfigInvalid)
	}
	if u.Scheme != "https" && !cfg.AllowInsecureHTTP {
		return nil, fmt.Errorf("%w: audit/secrets/vault: address must use https; set AllowInsecureHTTP for local development", audit.ErrConfigInvalid)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("%w: audit/secrets/vault: address has empty host", audit.ErrConfigInvalid)
	}
	if u.User != nil {
		return nil, fmt.Errorf("%w: audit/secrets/vault: address must not contain embedded credentials", audit.ErrConfigInvalid)
	}

	// Normalise: strip trailing slash to prevent double-slash in URLs.
	addr := strings.TrimRight(cfg.Address, "/")

	// Validate token.
	if cfg.Token == "" {
		return nil, fmt.Errorf("%w: audit/secrets/vault: token is required", audit.ErrConfigInvalid)
	}

	// Build TLS config (skip when using plain HTTP for development).
	var tlsCfg *tls.Config
	if u.Scheme == "https" {
		tlsCfg, err = buildTLSConfig(cfg)
		if err != nil {
			return nil, err
		}
	}

	// Build SSRF dial control.
	var ssrfOpts []audit.SSRFOption
	if cfg.AllowPrivateRanges {
		ssrfOpts = append(ssrfOpts, audit.AllowPrivateRanges())
	}

	// Build HTTP client.
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: 30 * time.Second,
			Control: audit.NewSSRFDialControl(ssrfOpts...),
		}).DialContext,
		TLSClientConfig:       tlsCfg,
		DisableKeepAlives:     true,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
	}
	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errRedirectBlocked
		},
	}

	return &Provider{
		client: client,
		addr:   addr,
		host:   u.Host,
		token:  []byte(cfg.Token),
		ns:     cfg.Namespace,
	}, nil
}

// NewWithHTTPClient creates a Vault provider using the provided HTTP
// client instead of building one from the Config's TLS settings.
// This is primarily for testing with [net/http/httptest] servers.
// The Config.Address and Config.Token are still validated.
func NewWithHTTPClient(cfg *Config, client *http.Client) (*Provider, error) {
	if cfg == nil {
		return nil, fmt.Errorf("%w: audit/secrets/vault: config must not be nil", audit.ErrConfigInvalid)
	}
	if client == nil {
		return nil, fmt.Errorf("%w: audit/secrets/vault: http client must not be nil", audit.ErrConfigInvalid)
	}
	if cfg.Address == "" {
		return nil, fmt.Errorf("%w: audit/secrets/vault: address is required", audit.ErrConfigInvalid)
	}
	u, err := url.Parse(cfg.Address)
	if err != nil {
		return nil, fmt.Errorf("%w: audit/secrets/vault: invalid address: %w", audit.ErrConfigInvalid, err)
	}
	if u.Scheme != "https" && !cfg.AllowInsecureHTTP {
		return nil, fmt.Errorf("%w: audit/secrets/vault: address must use https (got %q); set AllowInsecureHTTP for local development", audit.ErrConfigInvalid, u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("%w: audit/secrets/vault: address has empty host", audit.ErrConfigInvalid)
	}
	if u.User != nil {
		return nil, fmt.Errorf("%w: audit/secrets/vault: address must not contain embedded credentials", audit.ErrConfigInvalid)
	}
	if cfg.Token == "" {
		return nil, fmt.Errorf("%w: audit/secrets/vault: token is required", audit.ErrConfigInvalid)
	}
	return &Provider{
		client: client,
		addr:   strings.TrimRight(cfg.Address, "/"),
		host:   u.Host,
		token:  []byte(cfg.Token),
		ns:     cfg.Namespace,
	}, nil
}

// Scheme returns "vault".
func (p *Provider) Scheme() string { return "vault" }

// Compile-time check that Provider implements BatchProvider.
var _ secrets.BatchProvider = (*Provider)(nil)

// Resolve fetches a single secret value for the given reference.
func (p *Provider) Resolve(ctx context.Context, ref secrets.Ref) (string, error) {
	if err := ref.Valid(); err != nil {
		return "", fmt.Errorf("audit/secrets/vault: %w", err)
	}
	allKeys, err := p.fetchPath(ctx, ref.Path)
	if err != nil {
		return "", err
	}
	val, ok := allKeys[ref.Key]
	if !ok {
		return "", fmt.Errorf("%w: requested key not found in secret", secrets.ErrSecretNotFound)
	}
	return val, nil
}

// ResolvePath fetches all key-value pairs at the given path from the
// Vault KV v2 engine. Implements [secrets.BatchProvider] for
// path-level caching.
func (p *Provider) ResolvePath(ctx context.Context, path string) (map[string]string, error) {
	if err := secrets.ValidatePath(path); err != nil {
		return nil, fmt.Errorf("audit/secrets/vault: %w", err)
	}
	return p.fetchPath(ctx, path)
}

// fetchPath does the HTTP GET to /v1/{path} and returns all string
// key-value pairs from the KV v2 response.
func (p *Provider) fetchPath(ctx context.Context, path string) (map[string]string, error) { //nolint:gocyclo,cyclop // linear HTTP pipeline
	reqURL := p.addr + "/v1/" + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, http.NoBody)
	if err != nil {
		// Strip stdlib error to prevent vault path leakage.
		return nil, fmt.Errorf("%w: failed to build HTTP request", secrets.ErrSecretResolveFailed)
	}
	// Setting these headers converts p.token ([]byte) into an
	// immutable Go string via string(p.token). Close() zeroes the
	// underlying byte slice, but the string copy cannot be zeroed.
	// We Delete the header entries after Do returns to drop the
	// request-object reference — a best-effort narrowing of the
	// retention window, since the string values persist until GC.
	// See SECURITY.md §Secrets and Memory Retention (#479).
	req.Header.Set("X-Vault-Token", string(p.token))
	if p.ns != "" {
		req.Header.Set("X-Vault-Namespace", p.ns)
	}
	defer func() {
		// Drop the map-held references after the request completes.
		// The string values already copied into the header map
		// cannot be zeroed; GC reclaims them once req itself is
		// unreachable. Best-effort defence-in-depth per #479.
		req.Header.Del("X-Vault-Token")
		req.Header.Del("X-Vault-Namespace")
	}()

	// Execute request. Strip *url.Error wrapper to prevent vault
	// path leakage — url.Error.Error() embeds the full request URL.
	resp, err := p.client.Do(req)
	if err != nil {
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			return nil, fmt.Errorf("%w: %w", secrets.ErrSecretResolveFailed, urlErr.Err)
		}
		return nil, fmt.Errorf("%w: %w", secrets.ErrSecretResolveFailed, err)
	}
	defer func() {
		// Drain and close body. Small limit sufficient since
		// keep-alives are disabled (hygiene only).
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		// success — parse below
	case http.StatusNotFound:
		return nil, fmt.Errorf("%w: path returned 404", secrets.ErrSecretNotFound)
	case http.StatusForbidden:
		return nil, fmt.Errorf("%w: authentication failed (403)", secrets.ErrSecretResolveFailed)
	default:
		return nil, fmt.Errorf("%w: unexpected status %d", secrets.ErrSecretResolveFailed, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize+1))
	if err != nil {
		return nil, fmt.Errorf("%w: read response: %w", secrets.ErrSecretResolveFailed, err)
	}
	if len(body) > maxResponseSize {
		return nil, fmt.Errorf("%w: response exceeds %d bytes", secrets.ErrSecretResolveFailed, maxResponseSize)
	}

	var kvResp kvResponse
	if err := json.Unmarshal(body, &kvResp); err != nil {
		return nil, fmt.Errorf("%w: parse response: %w", secrets.ErrSecretResolveFailed, err)
	}

	if kvResp.Data == nil || kvResp.Data.Data == nil {
		return nil, fmt.Errorf("%w: response has no data", secrets.ErrSecretNotFound)
	}

	// Convert map[string]any to map[string]string, rejecting non-string values.
	result := make(map[string]string, len(kvResp.Data.Data))
	for k, v := range kvResp.Data.Data {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("%w: secret contains a non-string value", secrets.ErrSecretResolveFailed)
		}
		result[k] = s
	}
	return result, nil
}

// Close releases resources held by the provider and zeroes the
// authentication token from memory (best-effort; Go GC may retain
// copies).
//
// Close is idempotent: repeated calls are safe, return nil, and do
// not panic. Token zeroing on an already-zero slice is a no-op, and
// [http.Client.CloseIdleConnections] is safe to invoke multiple
// times per the stdlib contract. Calls to [Provider.Resolve] after
// Close will fail with a connection error.
func (p *Provider) Close() error {
	for i := range p.token {
		p.token[i] = 0
	}
	p.client.CloseIdleConnections()
	return nil
}

// String returns a safe representation with the token redacted.
func (p *Provider) String() string {
	return fmt.Sprintf("vault{host: %s, token: [REDACTED]}", p.host)
}

// GoString implements [fmt.GoStringer] to prevent token leakage via %#v.
func (p *Provider) GoString() string { return p.String() }

// Format implements [fmt.Formatter] to prevent token leakage via %+v.
func (p *Provider) Format(f fmt.State, _ rune) {
	_, _ = fmt.Fprint(f, p.String())
}

// kvResponse is the KV v2 response structure.
type kvResponse struct {
	Data *kvData `json:"data"`
}

type kvData struct {
	Data map[string]any `json:"data"`
}

// buildTLSConfig creates a TLS configuration from the provider config.
func buildTLSConfig(cfg *Config) (*tls.Config, error) {
	tlsCfg, _ := cfg.TLSPolicy.Apply(nil)

	if cfg.TLSCert != "" && cfg.TLSKey != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
		if err != nil {
			return nil, fmt.Errorf("%w: audit/secrets/vault: load client certificate: %w", audit.ErrConfigInvalid, err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	} else if cfg.TLSCert != "" || cfg.TLSKey != "" {
		return nil, fmt.Errorf("%w: audit/secrets/vault: tls_cert and tls_key must both be set or both empty", audit.ErrConfigInvalid)
	}

	if cfg.TLSCA != "" {
		caCert, err := os.ReadFile(cfg.TLSCA)
		if err != nil {
			return nil, fmt.Errorf("%w: audit/secrets/vault: read ca certificate: %w", audit.ErrConfigInvalid, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("%w: audit/secrets/vault: parse ca certificate: invalid PEM", audit.ErrConfigInvalid)
		}
		tlsCfg.RootCAs = pool
	}

	return tlsCfg, nil
}
