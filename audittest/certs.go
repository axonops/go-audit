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

package audittest

// TLS test helpers shared across the core module and every sub-module
// (file/syslog/webhook/loki/secrets). Sub-modules cannot import the
// core's internal/testhelper package because Go's internal/ mechanism
// is module-scoped, but they CAN import this package (audittest is a
// public sibling of audit, not internal). #568.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestCerts holds paths to test TLS certificates and a server TLS config
// produced by [GenerateTestCerts]. All files are written under
// [testing.TB.TempDir] so they are cleaned up automatically when the
// test exits.
type TestCerts struct {
	// TLSCfg is a server-side [tls.Config] with the server certificate
	// loaded, ClientCAs set to a pool containing the CA cert, and
	// ClientAuth set to [tls.VerifyClientCertIfGiven].
	TLSCfg *tls.Config

	// CAPath is the PEM-encoded self-signed CA certificate.
	CAPath string

	// CertPath is the PEM-encoded server certificate (CN=localhost,
	// SANs include localhost + 127.0.0.1).
	CertPath string

	// KeyPath is the PEM-encoded server private key (ECDSA P-256).
	KeyPath string

	// ClientCert is the PEM-encoded client certificate
	// (CN=test-client, ExtKeyUsageClientAuth).
	ClientCert string

	// ClientKey is the PEM-encoded client private key (ECDSA P-256).
	ClientKey string
}

// GenerateTestCerts creates a self-signed CA plus server and client
// certificates for testing TLS. All files are written to
// [testing.TB.TempDir] and removed when the test exits. ECDSA P-256
// keys, one-hour expiry. The returned [tls.Config] is ready to use
// with [net.Listen]'s tls wrapper for a server that wants to verify
// optional client certs against the same CA.
func GenerateTestCerts(tb testing.TB) *TestCerts {
	tb.Helper()
	dir := tb.TempDir()

	// CA key and cert.
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(tb, err)

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(tb, err)
	caCert, err := x509.ParseCertificate(caCertDER)
	require.NoError(tb, err)

	caPath := filepath.Join(dir, "ca.pem")
	WritePEM(tb, caPath, "CERTIFICATE", caCertDER)

	// Server key and cert.
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(tb, err)

	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	serverCertDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	require.NoError(tb, err)

	certPath := filepath.Join(dir, "server-cert.pem")
	keyPath := filepath.Join(dir, "server-key.pem")
	WritePEM(tb, certPath, "CERTIFICATE", serverCertDER)
	WriteKeyPEM(tb, keyPath, serverKey)

	// Client key and cert.
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(tb, err)

	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "test-client"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientCertDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, &clientKey.PublicKey, caKey)
	require.NoError(tb, err)

	clientCertPath := filepath.Join(dir, "client-cert.pem")
	clientKeyPath := filepath.Join(dir, "client-key.pem")
	WritePEM(tb, clientCertPath, "CERTIFICATE", clientCertDER)
	WriteKeyPEM(tb, clientKeyPath, clientKey)

	// Server TLS config.
	serverTLSCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	require.NoError(tb, err)

	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	return &TestCerts{
		CAPath:     caPath,
		CertPath:   certPath,
		KeyPath:    keyPath,
		ClientCert: clientCertPath,
		ClientKey:  clientKeyPath,
		TLSCfg: &tls.Config{
			Certificates: []tls.Certificate{serverTLSCert},
			ClientCAs:    caPool,
			ClientAuth:   tls.VerifyClientCertIfGiven,
			MinVersion:   tls.VersionTLS13,
		},
	}
}

// BadCerts holds a CA plus two server certificates with deliberate
// defects, used by negative-path TLS tests (#552). Both server
// certs are signed by the same runtime CA, so a client trusting
// CAPath fails for the installed defect — expired NotAfter or
// CN/SAN mismatch — rather than "unknown authority". A separate
// implementation in tests/bdd/steps/tls_negative_steps.go uses a
// different shape (in-memory tls.Config rather than file paths)
// and may be reconciled with this struct in a future PR.
type BadCerts struct {
	// CAPath is the self-signed CA that signed both bad-cert pairs.
	CAPath string

	// ExpiredCertPath / ExpiredKeyPath: NotAfter set in the past,
	// SANs include localhost + 127.0.0.1.
	ExpiredCertPath string
	ExpiredKeyPath  string

	// CNMismatchCertPath / CNMismatchKeyPath: NotAfter valid but
	// SANs only include "elsewhere.example.com" (CN/SAN does not
	// match a client connecting to 127.0.0.1 or localhost).
	CNMismatchCertPath string
	CNMismatchKeyPath  string
}

// GenerateBadCerts produces a fresh CA and two server certificates
// (one expired, one with CN/SAN mismatch) under [testing.TB.TempDir].
// ECDSA P-256. The two server cert pairs are independently usable
// in TLS server configs that need to be rejected by a client that
// trusts CAPath.
//
//   - Expired: NotAfter set one hour in the past; DNSNames
//     "localhost" + IPAddresses 127.0.0.1.
//   - CN-mismatch: NotAfter valid; DNSNames "elsewhere.example.com".
//
// Use [ExpiredCert] / [CNMismatchCert] for a single-cert convenience
// when only one defect is needed.
func GenerateBadCerts(tb testing.TB) *BadCerts {
	tb.Helper()
	dir := tb.TempDir()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(tb, err)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "Bad-Cert Test CA"},
		NotBefore:             time.Now().Add(-2 * time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(tb, err)
	caCert, err := x509.ParseCertificate(caCertDER)
	require.NoError(tb, err)
	caPath := filepath.Join(dir, "ca.pem")
	WritePEM(tb, caPath, "CERTIFICATE", caCertDER)

	expiredCertPath, expiredKeyPath := writeBadServerCert(tb, dir, "expired",
		caCert, caKey,
		&x509.Certificate{
			SerialNumber: big.NewInt(101),
			Subject:      pkix.Name{CommonName: "localhost"},
			NotBefore:    time.Now().Add(-2 * time.Hour),
			NotAfter:     time.Now().Add(-1 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			DNSNames:     []string{"localhost"},
			IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		})

	cnMismatchCertPath, cnMismatchKeyPath := writeBadServerCert(tb, dir, "cn-mismatch",
		caCert, caKey,
		&x509.Certificate{
			SerialNumber: big.NewInt(102),
			Subject:      pkix.Name{CommonName: "elsewhere.example.com"},
			NotBefore:    time.Now().Add(-1 * time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			DNSNames:     []string{"elsewhere.example.com"},
		})

	return &BadCerts{
		CAPath:             caPath,
		ExpiredCertPath:    expiredCertPath,
		ExpiredKeyPath:     expiredKeyPath,
		CNMismatchCertPath: cnMismatchCertPath,
		CNMismatchKeyPath:  cnMismatchKeyPath,
	}
}

// ExpiredCert is a convenience wrapper that returns just the
// expired-NotAfter cert pair (plus its CA path). Equivalent to
// (BadCerts.ExpiredCertPath, .ExpiredKeyPath, .CAPath) from
// [GenerateBadCerts].
func ExpiredCert(tb testing.TB) (certPath, keyPath, caPath string) {
	tb.Helper()
	bc := GenerateBadCerts(tb)
	return bc.ExpiredCertPath, bc.ExpiredKeyPath, bc.CAPath
}

// CNMismatchCert is the matching convenience wrapper for the
// CN/SAN-mismatch cert pair. Returns
// (BadCerts.CNMismatchCertPath, .CNMismatchKeyPath, .CAPath).
func CNMismatchCert(tb testing.TB) (certPath, keyPath, caPath string) {
	tb.Helper()
	bc := GenerateBadCerts(tb)
	return bc.CNMismatchCertPath, bc.CNMismatchKeyPath, bc.CAPath
}

// writeBadServerCert is a sequential helper used by
// GenerateBadCerts to keep the per-defect template list readable.
func writeBadServerCert(tb testing.TB, dir, name string, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, template *x509.Certificate) (certPath, keyPath string) {
	tb.Helper()
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(tb, err)
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &leafKey.PublicKey, caKey)
	require.NoError(tb, err)
	certPath = filepath.Join(dir, name+"-cert.pem")
	keyPath = filepath.Join(dir, name+"-key.pem")
	WritePEM(tb, certPath, "CERTIFICATE", der)
	WriteKeyPEM(tb, keyPath, leafKey)
	return certPath, keyPath
}

// WritePEM writes a PEM-encoded block to the given path. Exposed so
// callers that need to assemble bespoke cert bundles can reuse the
// PEM-marshalling boilerplate.
func WritePEM(tb testing.TB, path, blockType string, data []byte) {
	tb.Helper()
	// path is constructed by the helper from t.TempDir() + a fixed
	// filename; not user-controlled. Test-only helper.
	f, err := os.Create(path) //nolint:gosec // G304: test-only path under t.TempDir()
	require.NoError(tb, err)
	defer func() { _ = f.Close() }()
	require.NoError(tb, pem.Encode(f, &pem.Block{Type: blockType, Bytes: data}))
}

// WriteKeyPEM writes an ECDSA private key as PEM to the given path.
func WriteKeyPEM(tb testing.TB, path string, key *ecdsa.PrivateKey) {
	tb.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	require.NoError(tb, err)
	WritePEM(tb, path, "EC PRIVATE KEY", der)
}
