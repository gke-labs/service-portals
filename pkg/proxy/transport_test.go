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
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gke-labs/service-portals/pkg/cache"
)

func TestCachingTransport(t *testing.T) {
	// Create a mock cache
	memCache := cache.NewInMemoryCache(0)

	// Create a mock upstream server
	callCount := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("hello"))
	}))
	defer ts.Close()

	transport := NewCachingTransport(memCache, http.DefaultTransport, 1*time.Minute)

	// First request (GET) - should miss cache and call upstream
	req, _ := http.NewRequest("GET", ts.URL, nil)
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if callCount != 1 {
		t.Errorf("Expected call count 1, got %d", callCount)
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello" {
		t.Errorf("Expected body 'hello', got '%s'", body)
	}

	// Second request (GET) - should hit cache and NOT call upstream
	resp2, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()

	if callCount != 1 {
		t.Errorf("Expected call count 1 (cached), got %d", callCount)
	}

	body2, _ := io.ReadAll(resp2.Body)
	if string(body2) != "hello" {
		t.Errorf("Expected body 'hello', got '%s'", body2)
	}

	// Third request (POST) - should NOT cache and call upstream
	req3, _ := http.NewRequest("POST", ts.URL, bytes.NewReader([]byte("data")))
	resp3, err := transport.RoundTrip(req3)
	if err != nil {
		t.Fatal(err)
	}
	defer resp3.Body.Close()

	if callCount != 2 {
		t.Errorf("Expected call count 2, got %d", callCount)
	}
}

func generateTestCA(t *testing.T, cn string) ([]byte, *rsa.PrivateKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return pemBytes, priv
}

func generateSignedCert(t *testing.T, caPEM []byte, caPriv *rsa.PrivateKey, hosts []string) tls.Certificate {
	t.Helper()
	block, _ := pem.Decode(caPEM)
	if block == nil {
		t.Fatal("failed to decode CA PEM")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("x509.ParseCertificate: %v", err)
	}

	serverPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: hosts[0]},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, &tmpl, caCert, &serverPriv.PublicKey, caPriv)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{serverDER},
		PrivateKey:  serverPriv,
	}
}

func TestNewUpstreamTransport(t *testing.T) {
	ca1PEM, _ := generateTestCA(t, "Private Upstream CA 1")

	t.Run("empty path returns default transport without error", func(t *testing.T) {
		tr, err := NewUpstreamTransport("")
		if err != nil {
			t.Fatalf("expected nil error, got: %v", err)
		}
		if tr != http.DefaultTransport {
			t.Errorf("expected http.DefaultTransport, got: %v", tr)
		}
	})

	t.Run("empty directory returns default transport without error", func(t *testing.T) {
		emptyDir := t.TempDir()
		tr, err := NewUpstreamTransport(emptyDir)
		if err != nil {
			t.Fatalf("expected nil error, got: %v", err)
		}
		if tr != http.DefaultTransport {
			t.Errorf("expected http.DefaultTransport, got: %v", tr)
		}
	})

	t.Run("directory with hidden files only returns default transport without error", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "..data"), []byte("something"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(dir, "..2026_11_19"), 0755); err != nil {
			t.Fatal(err)
		}
		tr, err := NewUpstreamTransport(dir)
		if err != nil {
			t.Fatalf("expected nil error, got: %v", err)
		}
		if tr != http.DefaultTransport {
			t.Errorf("expected http.DefaultTransport, got: %v", tr)
		}
	})

	t.Run("non-existent directory returns error", func(t *testing.T) {
		_, err := NewUpstreamTransport(filepath.Join(t.TempDir(), "nonexistent"))
		if err == nil {
			t.Fatal("expected error for non-existent path, got nil")
		}
	})

	t.Run("directory containing unparseable file returns error", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "valid.crt"), ca1PEM, 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "invalid.crt"), []byte("bogus"), 0644); err != nil {
			t.Fatal(err)
		}
		_, err := NewUpstreamTransport(dir)
		if err == nil {
			t.Fatal("expected error for directory with invalid cert file, got nil")
		}
	})
}

func TestNewUpstreamTransport_TLSVerification(t *testing.T) {
	caPEM, caPriv := generateTestCA(t, "Test Upstream Private CA")
	serverCert := generateSignedCert(t, caPEM, caPriv, []string{"127.0.0.1"})

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("secure upstream response"))
	}))
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
	}
	server.StartTLS()
	defer server.Close()

	caDir := t.TempDir()
	caFile := filepath.Join(caDir, "tls.crt")
	if err := os.WriteFile(caFile, caPEM, 0644); err != nil {
		t.Fatal(err)
	}

	// 1. Without the custom CA (default transport), connection to self-signed upstream fails TLS verification
	defaultTransport, err := NewUpstreamTransport("")
	if err != nil {
		t.Fatalf("NewUpstreamTransport(\"\") failed: %v", err)
	}
	clientWithoutCA := &http.Client{Transport: defaultTransport}
	_, err = clientWithoutCA.Get(server.URL)
	if err == nil {
		t.Fatal("expected TLS verification error with default transport, but request succeeded")
	}

	// 2. With the custom CA, connection succeeds and verifies TLS
	customTransport, err := NewUpstreamTransport(caDir)
	if err != nil {
		t.Fatalf("NewUpstreamTransport(%q) failed: %v", caDir, err)
	}
	clientWithCA := &http.Client{Transport: customTransport}
	resp, err := clientWithCA.Get(server.URL)
	if err != nil {
		t.Fatalf("expected request with custom CA to succeed, got: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "secure upstream response" {
		t.Errorf("expected 'secure upstream response', got %q", string(body))
	}
}
