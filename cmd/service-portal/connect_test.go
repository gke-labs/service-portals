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

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestConnectHonorsHost(t *testing.T) {
	// 1. Setup a mock target backend
	targetBackend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Backend", "target")
		if r.Header.Get("Authorization") != "" {
			w.Header().Set("X-Auth", "true")
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("target"))
	}))
	defer targetBackend.Close()
	targetURL, _ := url.Parse(targetBackend.URL)

	// 2. Setup a mock other backend
	otherBackend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Backend", "other")
		if r.Header.Get("Authorization") != "" {
			w.Header().Set("X-Auth", "true")
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("other"))
	}))
	defer otherBackend.Close()
	otherURL, _ := url.Parse(otherBackend.URL)

	// 3. Setup CA for MITM
	tmpDir, err := os.MkdirTemp("", "mitm-test")
	if err != nil {
		t.Fatalf("Failed to create tmp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	caCertPath := filepath.Join(tmpDir, "ca.crt")
	caKeyPath := filepath.Join(tmpDir, "ca.key")
	generateCA(t, caCertPath, caKeyPath)

	// 4. Create the proxy
	proxy := newProxy(targetURL, "secret-token", "Authorization")
	// Use a custom transport to handle http/https backends correctly in tests
	proxy.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	mitm, err := newMITMHandler(proxy, caCertPath, caKeyPath)
	if err != nil {
		t.Fatalf("Failed to create mitm handler: %v", err)
	}

	proxyServer := httptest.NewServer(mitm)
	defer proxyServer.Close()

	proxyURL, _ := url.Parse(proxyServer.URL)

	// 5. Test request to target host via CONNECT
	t.Run("TargetHost", func(t *testing.T) {
		client := &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyURL(proxyURL),
				TLSClientConfig: &tls.Config{
					RootCAs: x509.NewCertPool(),
				},
			},
		}
		// Trust the MITM CA
		caCert, _ := os.ReadFile(caCertPath)
		client.Transport.(*http.Transport).TLSClientConfig.RootCAs.AppendCertsFromPEM(caCert)

		reqURL := fmt.Sprintf("https://%s/", targetURL.Host)
		resp, err := client.Get(reqURL)
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close()

		if resp.Header.Get("X-Backend") != "target" {
			t.Errorf("Expected X-Backend: target, got %s", resp.Header.Get("X-Backend"))
		}
		if resp.Header.Get("X-Auth") != "true" {
			t.Errorf("Expected X-Auth: true, got %s", resp.Header.Get("X-Auth"))
		}
	})

	// 6. Test request to OTHER host via CONNECT
	t.Run("OtherHost", func(t *testing.T) {
		client := &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyURL(proxyURL),
				TLSClientConfig: &tls.Config{
					RootCAs: x509.NewCertPool(),
				},
			},
		}
		// Trust the MITM CA
		caCert, _ := os.ReadFile(caCertPath)
		client.Transport.(*http.Transport).TLSClientConfig.RootCAs.AppendCertsFromPEM(caCert)

		reqURL := fmt.Sprintf("https://%s/", otherURL.Host)
		resp, err := client.Get(reqURL)
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close()

		// EXPECTED BEHAVIOR after fix:
		// backend should be "other"
		// auth should be empty
		backend := resp.Header.Get("X-Backend")
		if backend != "other" {
			t.Errorf("Expected X-Backend: other, got %s", backend)
		}
		if resp.Header.Get("X-Auth") != "" {
			t.Errorf("Expected no X-Auth for other host, got %s", resp.Header.Get("X-Auth"))
		}
	})
}

func generateCA(t *testing.T, certPath, keyPath string) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"MITM Test"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	certOut, _ := os.Create(certPath)
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()

	keyOut, _ := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	keyBytes, _ := x509.MarshalPKCS8PrivateKey(priv)
	pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	keyOut.Close()
}
