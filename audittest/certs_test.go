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

package audittest_test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/audit/audittest"
)

// TestGenerateTestCerts_AllPathsExist verifies that every path in
// *TestCerts points at a non-empty PEM file and that the server cert
// + key parse and pair up.
func TestGenerateTestCerts_AllPathsExist(t *testing.T) {
	t.Parallel()
	c := audittest.GenerateTestCerts(t)

	for name, path := range map[string]string{
		"CA":          c.CAPath,
		"server cert": c.CertPath,
		"server key":  c.KeyPath,
		"client cert": c.ClientCert,
		"client key":  c.ClientKey,
	} {
		info, err := os.Stat(path)
		require.NoError(t, err, "%s should exist", name)
		assert.Greater(t, info.Size(), int64(0), "%s should be non-empty", name)
	}

	_, err := tls.LoadX509KeyPair(c.CertPath, c.KeyPath)
	require.NoError(t, err)
	require.NotNil(t, c.TLSCfg)
}

// TestGenerateBadCerts_ExpiredAndCNMismatch verifies the two bad
// pairs carry their documented defects.
func TestGenerateBadCerts_ExpiredAndCNMismatch(t *testing.T) {
	t.Parallel()
	bc := audittest.GenerateBadCerts(t)

	expired := loadFirstCertPEM(t, bc.ExpiredCertPath)
	assert.True(t, expired.NotAfter.Before(time.Now()),
		"expired cert NotAfter %v should be in the past", expired.NotAfter)

	cnMismatch := loadFirstCertPEM(t, bc.CNMismatchCertPath)
	assert.True(t, cnMismatch.NotAfter.After(time.Now()),
		"cn-mismatch cert NotAfter %v should be in the future", cnMismatch.NotAfter)
	assert.NotContains(t, cnMismatch.DNSNames, "localhost",
		"cn-mismatch cert SANs should not include localhost")
	assert.Contains(t, cnMismatch.DNSNames, "elsewhere.example.com",
		"cn-mismatch cert SANs should include the elsewhere domain")
}

// TestExpiredCert_ConvenienceWrapper checks the (cert, key, ca)
// three-string return shape.
func TestExpiredCert_ConvenienceWrapper(t *testing.T) {
	t.Parallel()
	certPath, keyPath, caPath := audittest.ExpiredCert(t)
	for _, p := range []string{certPath, keyPath, caPath} {
		_, err := os.Stat(p)
		require.NoError(t, err)
	}
}

// TestCNMismatchCert_ConvenienceWrapper checks the (cert, key, ca)
// three-string return shape.
func TestCNMismatchCert_ConvenienceWrapper(t *testing.T) {
	t.Parallel()
	certPath, keyPath, caPath := audittest.CNMismatchCert(t)
	for _, p := range []string{certPath, keyPath, caPath} {
		_, err := os.Stat(p)
		require.NoError(t, err)
	}
}

// loadFirstCertPEM reads a PEM file, decodes the first CERTIFICATE
// block, and parses it into an *x509.Certificate.
func loadFirstCertPEM(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	// path is constructed by audittest from t.TempDir() — not user input.
	pemBytes, err := os.ReadFile(path)
	require.NoError(t, err)
	for {
		block, rest := pem.Decode(pemBytes)
		if block == nil {
			t.Fatalf("no CERTIFICATE block in %s", path)
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			require.NoError(t, err)
			return cert
		}
		pemBytes = rest
	}
}
