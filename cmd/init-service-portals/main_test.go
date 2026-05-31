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
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateCA(t *testing.T) {
	tmpDirCert, err := os.MkdirTemp("", "init-service-portals-cert-*")
	if err != nil {
		t.Fatalf("Failed to create temp cert dir: %v", err)
	}
	defer os.RemoveAll(tmpDirCert)

	tmpDirKey, err := os.MkdirTemp("", "init-service-portals-key-*")
	if err != nil {
		t.Fatalf("Failed to create temp key dir: %v", err)
	}
	defer os.RemoveAll(tmpDirKey)

	if err := generateCA(tmpDirCert, tmpDirKey, -1, -1); err != nil {
		t.Fatalf("generateCA failed: %v", err)
	}

	publicCertPath := filepath.Join(tmpDirCert, "tls.crt")
	privateCertPath := filepath.Join(tmpDirKey, "tls.crt")
	privateKeyPath := filepath.Join(tmpDirKey, "tls.key")

	if _, err := os.Stat(publicCertPath); os.IsNotExist(err) {
		t.Errorf("Expected public tls.crt to exist, but it does not")
	}

	if _, err := os.Stat(privateCertPath); os.IsNotExist(err) {
		t.Errorf("Expected private tls.crt to exist, but it does not")
	}

	if _, err := os.Stat(privateKeyPath); os.IsNotExist(err) {
		t.Errorf("Expected private tls.key to exist, but it does not")
	}

	certBytes, err := os.ReadFile(publicCertPath)
	if err != nil {
		t.Fatalf("Failed to read generated certificate: %v", err)
	}

	block, _ := pem.Decode(certBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("Failed to decode PEM certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse generated x509 certificate: %v", err)
	}

	if !cert.IsCA {
		t.Errorf("Expected generated certificate to be a CA, but IsCA is false")
	}

	if cert.Subject.CommonName != "Service Portal Root CA" {
		t.Errorf("Expected Subject CommonName to be 'Service Portal Root CA', got %q", cert.Subject.CommonName)
	}
}
