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
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/axonops/audit"
)

// DefaultStartupVerificationTimeout is the time budget for the
// construction-time connectivity probe when
// [Config.StartupVerificationTimeout] is zero. Five seconds is
// generous for any healthy network while keeping `New()` bounded for
// CI/local development. Operators with slow WAN paths can raise the
// timeout via YAML (`verify_on_startup_timeout: 30s`) or by setting
// the Config field directly.
const DefaultStartupVerificationTimeout = 5 * time.Second

// probeEndpoint performs a construction-time connectivity check
// against rawURL. Behaviour:
//
//   - Parses rawURL and extracts host:port (default 80 for http, 443
//     for https).
//   - Dials TCP through an [audit.NewSSRFDialControl]-gated dialer so
//     the probe rejects exactly the destinations the runtime
//     transport would reject (loopback, RFC 1918, cloud metadata,
//     etc.) — subject to cfg.AllowPrivateRanges.
//   - For https URLs, performs a TLS handshake against a clone of
//     tlsCfg with [tls.Config.ServerName] derived from the URL host
//     (mirrors the syslog boundedTLSDialer pattern). Without the
//     clone the runtime's pinned-roots policy can silently diverge
//     from the probe's verification path.
//   - Closes the connection unconditionally before returning.
//
// The probe budget covers the TCP dial and TLS handshake under a
// single [context.Context] derived from
// [context.WithTimeout]([context.Background](), probeTimeout). A
// caller-supplied parent context is not required — probe latency is
// a property of the output configuration, not the caller.
//
// Errors are wrapped with the package-qualified message
// "audit/loki: startup verification …" and include the sanitised
// URL (scheme://host) but never the path, query, or fragment — the
// same redaction discipline applied by [Config.String].
//
// SYNC: structurally identical to webhook/probe.go — duplicated per
// the cross-module no-share rule documented in #542. Keep both copies
// in sync.
func probeEndpoint(rawURL string, tlsCfg *tls.Config, cfg *Config) error {
	host, addr, scheme, err := parseProbeURL(rawURL)
	if err != nil {
		return err
	}

	timeout := cfg.StartupVerificationTimeout
	if timeout <= 0 {
		timeout = DefaultStartupVerificationTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	dialer := &net.Dialer{
		Timeout: timeout,
		Control: audit.NewSSRFDialControl(ssrfOptsFromConfig(cfg)...),
	}
	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("audit/loki: startup verification failed for %s: %w (set verify_on_startup: false to skip)",
			sanitizeURLForLog(rawURL), err)
	}

	if scheme == "https" {
		return probeTLSHandshake(ctx, rawConn, tlsCfg, host, rawURL)
	}
	_ = rawConn.Close()
	return nil
}

// parseProbeURL extracts host, host:port, and scheme from rawURL,
// applying scheme-default ports (80/443) when the URL omits the port.
func parseProbeURL(rawURL string) (host, addr, scheme string, err error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", "", "", fmt.Errorf("audit/loki: startup verification: parse url: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return "", "", "", fmt.Errorf("audit/loki: startup verification: url missing scheme or host")
	}
	host = u.Hostname()
	port := u.Port()
	if port == "" {
		switch u.Scheme {
		case "https":
			port = "443"
		case "http":
			port = "80"
		default:
			return "", "", "", fmt.Errorf("audit/loki: startup verification: unsupported scheme %q", u.Scheme)
		}
	}
	return host, net.JoinHostPort(host, port), u.Scheme, nil
}

// probeTLSHandshake performs the TLS handshake on rawConn using a
// clone of tlsCfg with ServerName derived from host. Closes rawConn
// on any failure path; on success closes the TLS layer (which
// closes rawConn too).
func probeTLSHandshake(ctx context.Context, rawConn net.Conn, tlsCfg *tls.Config, host, rawURL string) error {
	probeTLS := tlsCfg.Clone()
	if probeTLS.ServerName == "" {
		probeTLS.ServerName = host
	}
	tlsConn := tls.Client(rawConn, probeTLS)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = rawConn.Close()
		return fmt.Errorf("audit/loki: startup verification failed for %s: tls handshake: %w (set verify_on_startup: false to skip)",
			sanitizeURLForLog(rawURL), err)
	}
	_ = tlsConn.Close()
	return nil
}

// ssrfOptsFromConfig builds the SSRF option set applied to BOTH the
// runtime transport dialer and the construction-time probe dialer.
// Single source of truth — any divergence between the two would be
// a regression. Currently a one-knob mapping; extending the policy
// means updating exactly this helper.
func ssrfOptsFromConfig(cfg *Config) []audit.SSRFOption {
	var opts []audit.SSRFOption
	if cfg.AllowPrivateRanges {
		opts = append(opts, audit.AllowPrivateRanges())
	}
	return opts
}
