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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// CertSigner dynamically signs and caches TLS certificates for hosts using a CA key pair.
type CertSigner struct {
	caCert *x509.Certificate
	caKey  crypto.PrivateKey

	certs map[string]*tls.Certificate
	mu    sync.RWMutex
}

// NewCertSigner loads a CA certificate and private key from disk and returns a CertSigner.
func NewCertSigner(caCertPath, caKeyPath string) (*CertSigner, error) {
	certPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA cert: %w", err)
	}
	keyPEM, err := os.ReadFile(caKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA key: %w", err)
	}

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to load CA key pair: %w", err)
	}

	caCert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	return &CertSigner{
		caCert: caCert,
		caKey:  tlsCert.PrivateKey,
		certs:  make(map[string]*tls.Certificate),
	}, nil
}

// GetCertificate returns a certificate for the host requested in info.ServerName,
// signing and caching a new certificate with the CA if one does not already exist.
func (s *CertSigner) GetCertificate(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
	host := info.ServerName
	if host == "" {
		host = "localhost"
	}
	host = HostWithoutPort(host)
	return s.getCert(host)
}

func (s *CertSigner) getCert(host string) (*tls.Certificate, error) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))

	s.mu.RLock()
	cert, ok := s.certs[host]
	s.mu.RUnlock()
	if ok {
		return cert, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if cert, ok := s.certs[host]; ok {
		return cert, nil
	}

	cert, err := s.signCert(host)
	if err != nil {
		return nil, err
	}
	s.certs[host] = cert
	return cert, nil
}

func (s *CertSigner) signCert(host string) (*tls.Certificate, error) {
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour * 24 * 365),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, s.caCert, &priv.PublicKey, s.caKey)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}
