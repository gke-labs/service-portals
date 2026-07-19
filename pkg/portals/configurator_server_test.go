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

package portals

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/gke-labs/service-portals/pkg/portals/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func getFreePort(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find free port: %v", err)
	}
	defer l.Close()
	_, port, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		t.Fatalf("failed to parse port: %v", err)
	}
	return port
}

func generateTestCertificates(t *testing.T) (caPEM, certPEM, keyPEM []byte) {
	// Generate CA
	caPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	caTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(1 * time.Hour),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caPriv.PublicKey, caPriv)
	if err != nil {
		t.Fatalf("failed to create CA certificate: %v", err)
	}

	caPEMBuf := new(bytes.Buffer)
	pem.Encode(caPEMBuf, &pem.Block{Type: "CERTIFICATE", Bytes: caBytes})
	caPEM = caPEMBuf.Bytes()

	// Generate Server/Client Certificate
	certPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate cert private key: %v", err)
	}

	certTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Test Cert"},
		},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:    []string{"localhost"},
		NotBefore:   time.Now().Add(-1 * time.Hour),
		NotAfter:    time.Now().Add(1 * time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &certTemplate, &caTemplate, &certPriv.PublicKey, caPriv)
	if err != nil {
		t.Fatalf("failed to create signed certificate: %v", err)
	}

	certPEMBuf := new(bytes.Buffer)
	pem.Encode(certPEMBuf, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	certPEM = certPEMBuf.Bytes()

	keyPEMBuf := new(bytes.Buffer)
	pem.Encode(keyPEMBuf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(certPriv)})
	keyPEM = keyPEMBuf.Bytes()

	return caPEM, certPEM, keyPEM
}

func TestDynamicReconfigurationAndPolicy(t *testing.T) {
	// 1. Generate mTLS certs
	caPEM, certPEM, keyPEM := generateTestCertificates(t)

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.crt")
	certFile := filepath.Join(tmpDir, "tls.crt")
	keyFile := filepath.Join(tmpDir, "tls.key")

	if err := os.WriteFile(caFile, caPEM, 0600); err != nil {
		t.Fatalf("failed to write CA: %v", err)
	}
	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		t.Fatalf("failed to write cert: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatalf("failed to write key: %v", err)
	}

	// 2. Setup mock target backend
	backendCalled := false
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendCalled = true
		if r.Header.Get("Authorization") != "Bearer secret-token-123" {
			t.Errorf("expected Auth token secret-token-123, got %s", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("backend-response-ok"))
	}))
	defer backend.Close()

	// 3. Set environment variables
	httpPort := getFreePort(t)
	httpsPort := getFreePort(t)
	grpcPort := getFreePort(t)

	os.Setenv("PORT", httpPort)
	os.Setenv("HTTPS_PORT", httpsPort)
	os.Setenv("GRPC_PORT", grpcPort)
	os.Setenv("TARGET_URL", backend.URL)

	os.Setenv("GRPC_TLS_CERT_PATH", certFile)
	os.Setenv("GRPC_TLS_KEY_PATH", keyFile)
	os.Setenv("GRPC_CLIENT_CA_PATH", caFile)

	defer func() {
		os.Unsetenv("PORT")
		os.Unsetenv("HTTPS_PORT")
		os.Unsetenv("GRPC_PORT")
		os.Unsetenv("TARGET_URL")
		os.Unsetenv("GRPC_TLS_CERT_PATH")
		os.Unsetenv("GRPC_TLS_KEY_PATH")
		os.Unsetenv("GRPC_CLIENT_CA_PATH")
	}()

	// 4. Run server
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errChan := make(chan error, 1)
	go func() {
		errChan <- Run(ctx, Config{})
	}()

	// Give servers a brief moment to start up
	time.Sleep(100 * time.Millisecond)

	// 5. Connect to gRPC server using mTLS
	clientCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("failed to load client key pair: %v", err)
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(caPEM) {
		t.Fatalf("failed to append CA certificate to pool")
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      certPool,
		ServerName:   "localhost",
	}

	creds := credentials.NewTLS(tlsConfig)
	conn, err := grpc.Dial(fmt.Sprintf("127.0.0.1:%s", grpcPort), grpc.WithTransportCredentials(creds))
	if err != nil {
		t.Fatalf("failed to dial gRPC: %v", err)
	}
	defer conn.Close()

	client := pb.NewSidecarReconfiguratorClient(conn)

	// Test case A: Set & Get Security Policy
	policyReq := &pb.SetSecurityPolicyRequest{
		Policy: &pb.SecurityPolicy{
			BlockExec:     true,
			AllowedImages: []string{"gcr.io/test/image1", "gcr.io/test/image2"},
		},
	}
	policyResp, err := client.SetSecurityPolicy(context.Background(), policyReq)
	if err != nil {
		t.Fatalf("failed to set security policy: %v", err)
	}
	if !policyResp.Success {
		t.Errorf("set security policy not successful: %s", policyResp.Message)
	}

	getPolicyResp, err := client.GetSecurityPolicy(context.Background(), &pb.GetSecurityPolicyRequest{})
	if err != nil {
		t.Fatalf("failed to get security policy: %v", err)
	}
	if getPolicyResp.Policy == nil {
		t.Fatal("expected policy to be non-nil")
	}
	if !getPolicyResp.Policy.BlockExec {
		t.Errorf("expected BlockExec to be true")
	}
	if len(getPolicyResp.Policy.AllowedImages) != 2 || getPolicyResp.Policy.AllowedImages[0] != "gcr.io/test/image1" {
		t.Errorf("expected allowed images, got: %v", getPolicyResp.Policy.AllowedImages)
	}

	// Test case B: Update and List Rules
	updateReq := &pb.UpdateRulesRequest{
		Rules: []*pb.PortalRule{
			{
				ApiVersion: "portals.gke.io/v1alpha1",
				Kind:       "PortalRule",
				Metadata: &pb.Metadata{
					Name: "dynamic-rule-1",
				},
				Spec: &pb.RuleSpec{
					Host:       "dynamic-host.portal",
					RewriteUrl: backend.URL,
					AuthToken:  "secret-token-123",
					AuthHeader: "Authorization",
				},
			},
		},
	}
	updateResp, err := client.UpdateRules(context.Background(), updateReq)
	if err != nil {
		t.Fatalf("failed to update rules: %v", err)
	}
	if !updateResp.Success {
		t.Errorf("update rules not successful: %s", updateResp.Message)
	}

	listResp, err := client.ListRules(context.Background(), &pb.ListRulesRequest{})
	if err != nil {
		t.Fatalf("failed to list rules: %v", err)
	}
	if len(listResp.Rules) != 1 {
		t.Errorf("expected 1 rule, got %d", len(listResp.Rules))
	} else {
		rule := listResp.Rules[0]
		if rule.Metadata.Name != "dynamic-rule-1" || rule.Spec.Host != "dynamic-host.portal" {
			t.Errorf("unexpected rule values: %+v", rule)
		}
	}

	// 6. Test routing through the HTTP proxy using the newly dynamic rule
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%s/", httpPort), nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Host = "dynamic-host.portal"

	hc := &http.Client{Timeout: 2 * time.Second}
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatalf("failed to execute request to proxy: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status OK, got %d", resp.StatusCode)
	}
	if !backendCalled {
		t.Errorf("expected backend to be called via dynamic rule routing")
	}

	// 7. Verify that connecting WITHOUT client cert fails (authn/authz enforcement)
	insecureTLS := &tls.Config{
		RootCAs:            certPool,
		InsecureSkipVerify: true,
	}
	insecureCreds := credentials.NewTLS(insecureTLS)
	badConn, err := grpc.Dial(fmt.Sprintf("127.0.0.1:%s", grpcPort), grpc.WithTransportCredentials(insecureCreds))
	if err == nil {
		defer badConn.Close()
		badClient := pb.NewSidecarReconfiguratorClient(badConn)
		_, err = badClient.ListRules(context.Background(), &pb.ListRulesRequest{})
		if err == nil {
			t.Errorf("expected call to fail without valid client cert, but it succeeded")
		}
	}

	// 8. Shut down and clean up
	cancel()
	select {
	case err := <-errChan:
		if err != nil {
			t.Logf("Server shutdown with error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Errorf("timeout waiting for server shutdown")
	}
}
