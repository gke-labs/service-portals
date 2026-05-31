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
	tmpDir, err := os.MkdirTemp("", "init-service-portals-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	if err := generateCA(tmpDir); err != nil {
		t.Fatalf("generateCA failed: %v", err)
	}

	certPath := filepath.Join(tmpDir, "tls.crt")
	keyPath := filepath.Join(tmpDir, "tls.key")

	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Errorf("Expected tls.crt to exist, but it does not")
	}

	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Errorf("Expected tls.key to exist, but it does not")
	}

	certBytes, err := os.ReadFile(certPath)
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
