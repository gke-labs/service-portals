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

type nodeInitConfig struct {
	caDir     string
	socketDir string
	proxyUID  int
	proxyGID  int
}

func initNode(cfg nodeInitConfig) error {
	if cfg.socketDir != "" {
		if err := os.MkdirAll(cfg.socketDir, 0750); err != nil {
			return fmt.Errorf("failed to create socket dir %q: %w", cfg.socketDir, err)
		}
		if err := os.Chmod(cfg.socketDir, 0750); err != nil {
			return fmt.Errorf("failed to chmod socket dir %q: %w", cfg.socketDir, err)
		}
		if cfg.proxyUID >= 0 && cfg.proxyGID >= 0 {
			if err := os.Chown(cfg.socketDir, cfg.proxyUID, cfg.proxyGID); err != nil {
				return fmt.Errorf("failed to chown socket dir %q: %w", cfg.socketDir, err)
			}
		}
	}
	if cfg.caDir != "" {
		certPath, keyPath := filepath.Join(cfg.caDir, "tls.crt"), filepath.Join(cfg.caDir, "tls.key")
		_, cErr := os.Stat(certPath)
		_, kErr := os.Stat(keyPath)
		if os.IsNotExist(cErr) || os.IsNotExist(kErr) {
			if err := os.MkdirAll(cfg.caDir, 0755); err != nil {
				return fmt.Errorf("failed to create ca dir %q: %w", cfg.caDir, err)
			}
			certPEM, keyPEM, err := generateNodeCACertKey()
			if err != nil {
				return err
			}
			if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
				return fmt.Errorf("failed to write CA cert: %w", err)
			}
			if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
				return fmt.Errorf("failed to write CA key: %w", err)
			}
		}
		if cfg.proxyUID >= 0 && cfg.proxyGID >= 0 {
			if err := os.Chown(cfg.caDir, cfg.proxyUID, cfg.proxyGID); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("failed to chown ca dir %q: %w", cfg.caDir, err)
			}
			if err := os.Chown(keyPath, cfg.proxyUID, cfg.proxyGID); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("failed to chown ca key %q: %w", keyPath, err)
			}
		}
	}
	return nil
}

func generateNodeCACertKey() ([]byte, []byte, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial: %w", err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{Organization: []string{"Service Portal Dynamic CA"}, CommonName: "Service Portal Root CA"},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}
	keyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}), nil
}

func runInitCommand(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	var cfg nodeInitConfig
	fs.StringVar(&cfg.caDir, "ca-dir", "/etc/service-portal/ca", "Directory for node CA certificate and key")
	fs.StringVar(&cfg.socketDir, "socket-dir", "/run/service-portal", "Directory for shared unix domain sockets")
	fs.IntVar(&cfg.proxyUID, "proxy-uid", 65532, "Proxy UID to chown socket dir and private key")
	fs.IntVar(&cfg.proxyGID, "proxy-gid", 65532, "Proxy GID to chown socket dir and private key")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "error parsing flags: %v\n", err)
		os.Exit(1)
	}
	if err := initNode(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "init failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Node initialization complete.")
}
