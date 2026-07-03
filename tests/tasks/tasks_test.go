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

package tasks

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestCreateTestCertificates(t *testing.T) {
	// Find repo root
	cmd := exec.Command("git", "rev-parse", "--show-toplevel")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("Failed to find git root: %v", err)
	}
	repoRoot := filepath.Clean(filepath.ToSlash(string(out)))
	// Normalize newline
	repoRoot = filepath.Clean(filepath.ToSlash(string(out)))
	for len(repoRoot) > 0 && (repoRoot[len(repoRoot)-1] == '\n' || repoRoot[len(repoRoot)-1] == '\r') {
		repoRoot = repoRoot[:len(repoRoot)-1]
	}

	scriptPath := filepath.Join(repoRoot, "dev", "tasks", "create-test-certificates")

	// Create a temp directory for the certificates
	tmpDir, err := os.MkdirTemp("", "test-certs-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Run the script: ./dev/tasks/create-test-certificates <tmpDir> <domains...>
	runCmd := exec.Command(scriptPath, tmpDir, "localhost", "127.0.0.1", "test.backend")
	if combined, err := runCmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to run create-test-certificates script: %v\nOutput: %s", err, string(combined))
	}

	// Define expected files
	expectedFiles := []string{
		filepath.Join(tmpDir, "ca.key"),
		filepath.Join(tmpDir, "ca.crt"),
		filepath.Join(tmpDir, "tls.key"),
		filepath.Join(tmpDir, "tls.crt"),
		filepath.Join(tmpDir, "ca", "tls.key"),
		filepath.Join(tmpDir, "ca", "tls.crt"),
		filepath.Join(tmpDir, "signed", "tls.key"),
		filepath.Join(tmpDir, "signed", "tls.crt"),
	}

	for _, path := range expectedFiles {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Errorf("Expected file to exist: %s", path)
		}
	}

	// Parse the CA certificate
	caBytes, err := os.ReadFile(filepath.Join(tmpDir, "ca.crt"))
	if err != nil {
		t.Fatalf("Failed to read CA certificate: %v", err)
	}
	block, _ := pem.Decode(caBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("Failed to decode PEM CA certificate")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse CA certificate: %v", err)
	}
	if !caCert.IsCA {
		t.Errorf("Expected CA certificate to have IsCA = true")
	}

	// Parse the signed certificate
	signedBytes, err := os.ReadFile(filepath.Join(tmpDir, "tls.crt"))
	if err != nil {
		t.Fatalf("Failed to read signed certificate: %v", err)
	}
	block, _ = pem.Decode(signedBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("Failed to decode PEM signed certificate")
	}
	signedCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse signed certificate: %v", err)
	}
	if signedCert.IsCA {
		t.Errorf("Expected signed certificate to have IsCA = false")
	}

	// Check SANs
	foundLocalhost := false
	foundIP := false
	foundTestBackend := false
	for _, dns := range signedCert.DNSNames {
		if dns == "localhost" {
			foundLocalhost = true
		}
		if dns == "test.backend" {
			foundTestBackend = true
		}
	}
	for _, ip := range signedCert.IPAddresses {
		if ip.String() == "127.0.0.1" {
			foundIP = true
		}
	}

	if !foundLocalhost {
		t.Errorf("Expected DNS SAN 'localhost' in signed certificate, got: %v", signedCert.DNSNames)
	}
	if !foundTestBackend {
		t.Errorf("Expected DNS SAN 'test.backend' in signed certificate, got: %v", signedCert.DNSNames)
	}
	if !foundIP {
		t.Errorf("Expected IP SAN '127.0.0.1' in signed certificate, got: %v", signedCert.IPAddresses)
	}
}
