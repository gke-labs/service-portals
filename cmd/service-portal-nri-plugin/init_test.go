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
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestInitNode(t *testing.T) {
	tmpDir := t.TempDir()
	socketDir, caDir := filepath.Join(tmpDir, "socket"), filepath.Join(tmpDir, "ca")
	cfg := nodeInitConfig{caDir: caDir, socketDir: socketDir, proxyUID: os.Getuid(), proxyGID: os.Getgid()}

	if err := initNode(cfg); err != nil {
		t.Fatalf("initNode failed: %v", err)
	}

	if sInfo, err := os.Stat(socketDir); err != nil || sInfo.Mode().Perm() != 0750 {
		t.Fatalf("expected socketDir mode 0750, got err=%v", err)
	}

	certPath, keyPath := filepath.Join(caDir, "tls.crt"), filepath.Join(caDir, "tls.key")
	certBytes, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("failed to read cert: %v", err)
	}
	block, _ := pem.Decode(certBytes)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !cert.IsCA || cert.Subject.CommonName != "Service Portal Root CA" {
		t.Fatalf("invalid CA cert: err=%v, isCA=%v, cn=%q", err, cert.IsCA, cert.Subject.CommonName)
	}

	if kInfo, err := os.Stat(keyPath); err != nil || kInfo.Mode().Perm() != 0600 {
		t.Fatalf("expected tls.key mode 0600, got err=%v", err)
	}

	// Idempotency: second run must not overwrite existing CA
	if err := initNode(cfg); err != nil {
		t.Fatalf("second initNode failed: %v", err)
	}
	newCertBytes, _ := os.ReadFile(certPath)
	if !bytes.Equal(certBytes, newCertBytes) {
		t.Errorf("CA cert was regenerated on second run")
	}
}
