// Copyright 2026 Google LLC
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

package proxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func createTestCA(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour * 24),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})

	tmpDir := t.TempDir()
	certPath = filepath.Join(tmpDir, "ca.crt")
	keyPath = filepath.Join(tmpDir, "ca.key")

	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		t.Fatalf("failed to write ca.crt: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatalf("failed to write ca.key: %v", err)
	}

	return certPath, keyPath
}

func TestCertSigner(t *testing.T) {
	caCertPath, caKeyPath := createTestCA(t)

	signer, err := NewCertSigner(caCertPath, caKeyPath)
	if err != nil {
		t.Fatalf("NewCertSigner failed: %v", err)
	}

	info := &tls.ClientHelloInfo{
		ServerName: "api.example.com",
	}
	cert1, err := signer.GetCertificate(info)
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}
	if cert1 == nil {
		t.Fatal("expected non-nil cert")
	}

	// Repeated call with the same host name (even with case or trailing dot variations) reuses the cached certificate.
	infoVariant := &tls.ClientHelloInfo{
		ServerName: "API.EXAMPLE.COM.",
	}
	cert2, err := signer.GetCertificate(infoVariant)
	if err != nil {
		t.Fatalf("GetCertificate on variant failed: %v", err)
	}
	if cert1 != cert2 {
		t.Error("expected cert1 and cert2 to be the exact same cached certificate pointer")
	}

	// Requesting a different host signs a new certificate.
	infoDifferent := &tls.ClientHelloInfo{
		ServerName: "other.example.com",
	}
	cert3, err := signer.GetCertificate(infoDifferent)
	if err != nil {
		t.Fatalf("GetCertificate on different host failed: %v", err)
	}
	if cert3 == cert1 {
		t.Error("expected different certificate for different host")
	}
}

func TestCertSigner_CacheLimitAndEviction(t *testing.T) {
	caCertPath, caKeyPath := createTestCA(t)

	signer, err := NewCertSigner(caCertPath, caKeyPath)
	if err != nil {
		t.Fatalf("NewCertSigner failed: %v", err)
	}

	signer.maxCerts = 3

	hosts := []string{
		"host1.example.com",
		"host2.example.com",
		"host3.example.com",
		"host4.example.com",
		"host5.example.com",
	}

	for _, h := range hosts {
		info := &tls.ClientHelloInfo{ServerName: h}
		cert, err := signer.GetCertificate(info)
		if err != nil {
			t.Fatalf("GetCertificate(%q) failed: %v", h, err)
		}
		if cert == nil {
			t.Fatalf("expected non-nil cert for %q", h)
		}
	}

	signer.mu.Lock()
	count := len(signer.certs)
	_, hasHost1 := signer.certs["host1.example.com"]
	_, hasHost2 := signer.certs["host2.example.com"]
	_, hasHost3 := signer.certs["host3.example.com"]
	_, hasHost4 := signer.certs["host4.example.com"]
	_, hasHost5 := signer.certs["host5.example.com"]
	signer.mu.Unlock()

	if count > 3 {
		t.Errorf("cache size %d exceeded maximum limit %d", count, signer.maxCerts)
	}
	if count != 3 {
		t.Errorf("expected cache size 3, got %d", count)
	}

	if hasHost1 || hasHost2 {
		t.Errorf("expected host1 and host2 to be evicted, got hasHost1=%v, hasHost2=%v", hasHost1, hasHost2)
	}
	if !hasHost3 || !hasHost4 || !hasHost5 {
		t.Errorf("expected host3, host4, host5 to remain in cache; got %v, %v, %v", hasHost3, hasHost4, hasHost5)
	}
}
