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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

func main() {
	certDir := flag.String("cert-dir", "/etc/service-portal/ca", "Directory to write the public CA cert")
	keyDir := flag.String("key-dir", "/etc/service-portal/ca-private", "Directory to write the CA cert and key")
	flag.Parse()

	if err := generateCA(*certDir, *keyDir); err != nil {
		fmt.Fprintf(os.Stderr, "Error generating CA: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Successfully generated CA certificate and key.")
}

func generateCA(certDir, keyDir string) error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Service Portal Dynamic CA"},
			CommonName:   "Service Portal Root CA",
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365 * 10), // 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("failed to create CA certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	keyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})

	// 1. Write the public certificate to certDir
	if certDir != "" {
		if err := os.MkdirAll(certDir, 0755); err != nil {
			return fmt.Errorf("failed to create cert directory: %w", err)
		}
		certPath := filepath.Join(certDir, "tls.crt")
		if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
			return fmt.Errorf("failed to write public tls.crt: %w", err)
		}
		if os.Getuid() == 0 {
			_ = os.Chown(certPath, 1337, 1337)
		}
	}

	// 2. Write both the certificate and key to keyDir
	if keyDir != "" {
		if err := os.MkdirAll(keyDir, 0700); err != nil {
			return fmt.Errorf("failed to create key directory: %w", err)
		}
		certPath := filepath.Join(keyDir, "tls.crt")
		keyPath := filepath.Join(keyDir, "tls.key")

		if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
			return fmt.Errorf("failed to write private tls.crt: %w", err)
		}
		if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
			return fmt.Errorf("failed to write tls.key: %w", err)
		}

		if os.Getuid() == 0 {
			if err := os.Chown(certPath, 1337, 1337); err != nil {
				return fmt.Errorf("failed to chown private tls.crt: %w", err)
			}
			if err := os.Chown(keyPath, 1337, 1337); err != nil {
				return fmt.Errorf("failed to chown tls.key: %w", err)
			}
		}
	}

	return nil
}
