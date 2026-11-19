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

package client_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gke-labs/service-portals/pkg/client"
	portalsv1 "github.com/gke-labs/service-portals/pkg/portals/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func generateTestCertificate(t *testing.T, ip net.IP) (certPEM, keyPEM []byte) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: ip.String()},
		IPAddresses:  []net.IP{ip},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	privateKeyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateKeyDER})
	return certPEM, keyPEM
}

type fakeServer struct {
	portalsv1.UnimplementedPodBindServiceServer
	mu          sync.Mutex
	validTokens map[string]bool
	lastToken   string
	bindCount   int
	injectCount int
	bindResp    *portalsv1.BindResponse
	injectResp  *portalsv1.InjectSecretsResponse
}

func (s *fakeServer) authenticate(ctx context.Context) error {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "missing metadata")
	}
	auth := md.Get("authorization")
	if len(auth) == 0 {
		return status.Error(codes.Unauthenticated, "missing authorization header")
	}
	raw := auth[0]
	s.lastToken = raw
	if !strings.HasPrefix(raw, "Bearer ") {
		return status.Error(codes.Unauthenticated, "malformed authorization header")
	}
	token := strings.TrimPrefix(raw, "Bearer ")
	if !s.validTokens[token] {
		return status.Error(codes.Unauthenticated, "unrecognized token")
	}
	return nil
}

func (s *fakeServer) Bind(ctx context.Context, req *portalsv1.PodPolicy) (*portalsv1.BindResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bindCount++
	if err := s.authenticate(ctx); err != nil {
		return nil, err
	}
	return s.bindResp, nil
}

func (s *fakeServer) InjectSecrets(ctx context.Context, req *portalsv1.PodSecrets) (*portalsv1.InjectSecretsResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.injectCount++
	if err := s.authenticate(ctx); err != nil {
		return nil, err
	}
	return s.injectResp, nil
}

func setupTestServer(t *testing.T) (*fakeServer, string, string, string) {
	t.Helper()
	ip := net.ParseIP("127.0.0.1")
	certPEM, keyPEM := generateTestCertificate(t, ip)
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("tls.X509KeyPair: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	srv := &fakeServer{
		validTokens: make(map[string]bool),
	}
	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewServerTLSFromCert(&tlsCert)))
	portalsv1.RegisterPodBindServiceServer(grpcServer, srv)

	go func() {
		_ = grpcServer.Serve(listener)
	}()
	t.Cleanup(func() { grpcServer.Stop() })

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.crt")
	if err := os.WriteFile(caFile, certPEM, 0600); err != nil {
		t.Fatalf("writing CA file: %v", err)
	}

	tokenFile := filepath.Join(tmpDir, "token")
	if err := os.WriteFile(tokenFile, []byte("initial-token"), 0600); err != nil {
		t.Fatalf("writing token file: %v", err)
	}
	srv.validTokens["initial-token"] = true

	return srv, listener.Addr().String(), caFile, tokenFile
}

func TestClient_Accepted(t *testing.T) {
	srv, addr, caFile, tokenFile := setupTestServer(t)

	c, err := client.New(client.Options{
		ControllerAddr: addr,
		CAFile:         caFile,
		TokenFile:      tokenFile,
	})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	defer c.Close()

	const podUID = "pod-1234"
	policy := &portalsv1.EgressPolicy{
		Rules: []*portalsv1.EgressRule{
			{Https: &portalsv1.HttpsRule{Hostnames: []string{"example.com"}}},
		},
	}

	// 1. Accepted Bind without secrets
	srv.mu.Lock()
	srv.bindResp = &portalsv1.BindResponse{
		PodUid: podUID,
		Bound:  true,
		Status: portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_ACCEPTED,
	}
	srv.mu.Unlock()

	if err := c.Bind(t.Context(), podUID, policy, nil); err != nil {
		t.Fatalf("expected nil error on accepted bind without secrets, got: %v", err)
	}
	if srv.lastToken != "Bearer initial-token" {
		t.Errorf("server received token %q, want 'Bearer initial-token'", srv.lastToken)
	}

	// 2. Accepted Bind with companion secrets:
	// The policy push returns PENDING (expected because secrets are needed),
	// followed by InjectSecrets which returns ACCEPTED.
	srv.mu.Lock()
	srv.bindResp = &portalsv1.BindResponse{
		PodUid:         podUID,
		Status:         portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_PENDING,
		MissingSecrets: []string{"github-token"},
	}
	srv.injectResp = &portalsv1.InjectSecretsResponse{
		PodUid: podUID,
		Status: portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_ACCEPTED,
	}
	srv.mu.Unlock()

	secrets := map[string][]byte{"github-token": []byte("ephemeral-token")}
	if err := c.Bind(t.Context(), podUID, policy, secrets); err != nil {
		t.Fatalf("expected nil error on accepted bind with secrets, got: %v", err)
	}
}

func TestClient_PendingWithMissingSecrets(t *testing.T) {
	srv, addr, caFile, tokenFile := setupTestServer(t)

	c, err := client.New(client.Options{
		ControllerAddr: addr,
		CAFile:         caFile,
		TokenFile:      tokenFile,
	})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	defer c.Close()

	const podUID = "pod-pending"
	policy := &portalsv1.EgressPolicy{}

	// Case A: Policy push returns PENDING and no secrets are provided.
	// This is the final answer, so it returns StatusError.
	srv.mu.Lock()
	srv.bindResp = &portalsv1.BindResponse{
		PodUid:         podUID,
		Status:         portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_PENDING,
		MissingSecrets: []string{"secret-a", "secret-b"},
	}
	srv.mu.Unlock()

	err = c.Bind(t.Context(), podUID, policy, nil)
	if err == nil {
		t.Fatal("expected error on pending bind without secrets, got nil")
	}

	var statusErr *client.StatusError
	if !errors.As(err, &statusErr) {
		t.Fatalf("expected *client.StatusError, got %T: %v", err, err)
	}
	if statusErr.Operation != "bind" {
		t.Errorf("Operation = %q, want 'bind'", statusErr.Operation)
	}
	if statusErr.Status != portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_PENDING {
		t.Errorf("Status = %v, want PENDING", statusErr.Status)
	}
	if want := []string{"secret-a", "secret-b"}; !slices.Equal(statusErr.MissingSecrets, want) {
		t.Errorf("MissingSecrets = %v, want %v", statusErr.MissingSecrets, want)
	}
	if !strings.Contains(err.Error(), "missing secrets: secret-a, secret-b") {
		t.Errorf("expected missing secrets in error message: %v", err)
	}

	// Case B: Secrets are provided, policy returns PENDING, but final InjectSecrets also returns PENDING
	srv.mu.Lock()
	srv.bindResp = &portalsv1.BindResponse{
		PodUid:         podUID,
		Status:         portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_PENDING,
		MissingSecrets: []string{"secret-a", "secret-b"},
	}
	srv.injectResp = &portalsv1.InjectSecretsResponse{
		PodUid:         podUID,
		Status:         portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_PENDING,
		MissingSecrets: []string{"secret-b"},
	}
	srv.mu.Unlock()

	const secretValue = "super-secret-value-do-not-leak"
	secrets := map[string][]byte{"secret-a": []byte(secretValue)}
	err = c.Bind(t.Context(), podUID, policy, secrets)
	if err == nil {
		t.Fatal("expected error on pending inject secrets, got nil")
	}
	if !errors.As(err, &statusErr) {
		t.Fatalf("expected *client.StatusError, got %T: %v", err, err)
	}
	if statusErr.Operation != "inject secrets" {
		t.Errorf("Operation = %q, want 'inject secrets'", statusErr.Operation)
	}
	if statusErr.Status != portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_PENDING {
		t.Errorf("Status = %v, want PENDING", statusErr.Status)
	}
	if want := []string{"secret-b"}; !slices.Equal(statusErr.MissingSecrets, want) {
		t.Errorf("MissingSecrets = %v, want %v", statusErr.MissingSecrets, want)
	}
	// Verify secret values never appear in the error or String()
	if strings.Contains(err.Error(), secretValue) {
		t.Fatalf("secret value leaked into error message: %v", err)
	}
}

func TestClient_Refused(t *testing.T) {
	srv, addr, caFile, tokenFile := setupTestServer(t)

	c, err := client.New(client.Options{
		ControllerAddr: addr,
		CAFile:         caFile,
		TokenFile:      tokenFile,
	})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	defer c.Close()

	const podUID = "pod-refused"
	policy := &portalsv1.EgressPolicy{}
	secrets := map[string][]byte{"tok": []byte("confidential-secret-payload")}

	// Case A: Policy push refused by node agent.
	// InjectSecrets must not be called when policy is refused.
	srv.mu.Lock()
	srv.injectCount = 0
	srv.bindResp = &portalsv1.BindResponse{
		PodUid:        podUID,
		Status:        portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_REFUSED,
		RefusalReason: "pod not found on node",
	}
	srv.mu.Unlock()

	err = c.Bind(t.Context(), podUID, policy, secrets)
	if err == nil {
		t.Fatal("expected error on refused bind, got nil")
	}

	var statusErr *client.StatusError
	if !errors.As(err, &statusErr) {
		t.Fatalf("expected *client.StatusError, got %T: %v", err, err)
	}
	if statusErr.Operation != "bind" {
		t.Errorf("Operation = %q, want 'bind'", statusErr.Operation)
	}
	if statusErr.Status != portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_REFUSED {
		t.Errorf("Status = %v, want REFUSED", statusErr.Status)
	}
	if statusErr.RefusalReason != "pod not found on node" {
		t.Errorf("RefusalReason = %q, want 'pod not found on node'", statusErr.RefusalReason)
	}
	if !strings.Contains(err.Error(), "pod not found on node") {
		t.Errorf("expected refusal reason in error message: %v", err)
	}
	if srv.injectCount != 0 {
		t.Errorf("expected 0 InjectSecrets calls when bind is refused, got %d", srv.injectCount)
	}

	// Case B: Secrets injection refused by node agent.
	srv.mu.Lock()
	srv.bindResp = &portalsv1.BindResponse{
		PodUid:         podUID,
		Status:         portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_PENDING,
		MissingSecrets: []string{"tok"},
	}
	srv.injectResp = &portalsv1.InjectSecretsResponse{
		PodUid:        podUID,
		Status:        portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_REFUSED,
		RefusalReason: "binding store disk full",
	}
	srv.mu.Unlock()

	const secretValue = "confidential-secret-payload"
	err = c.Bind(t.Context(), podUID, policy, map[string][]byte{"tok": []byte(secretValue)})
	if err == nil {
		t.Fatal("expected error on refused inject secrets, got nil")
	}
	if !errors.As(err, &statusErr) {
		t.Fatalf("expected *client.StatusError, got %T: %v", err, err)
	}
	if statusErr.Operation != "inject secrets" {
		t.Errorf("Operation = %q, want 'inject secrets'", statusErr.Operation)
	}
	if statusErr.RefusalReason != "binding store disk full" {
		t.Errorf("RefusalReason = %q, want 'binding store disk full'", statusErr.RefusalReason)
	}
	if strings.Contains(err.Error(), secretValue) {
		t.Fatalf("secret value leaked into error message: %v", err)
	}
}

func TestClient_UnauthenticatedCall(t *testing.T) {
	_, addr, caFile, tokenFile := setupTestServer(t)

	// Overwrite token file with an invalid token not recognized by the server
	if err := os.WriteFile(tokenFile, []byte("unauthorized-token"), 0600); err != nil {
		t.Fatalf("writing unauthorized token: %v", err)
	}

	c, err := client.New(client.Options{
		ControllerAddr: addr,
		CAFile:         caFile,
		TokenFile:      tokenFile,
	})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	defer c.Close()

	err = c.Bind(t.Context(), "pod-1", &portalsv1.EgressPolicy{}, nil)
	if err == nil {
		t.Fatal("expected unauthenticated error, got nil")
	}
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected codes.Unauthenticated, got: %v (code %v)", err, status.Code(err))
	}
}

func TestClient_RotatedToken(t *testing.T) {
	srv, addr, caFile, tokenFile := setupTestServer(t)

	srv.mu.Lock()
	srv.validTokens["token-v1"] = true
	srv.validTokens["token-v2"] = true
	srv.bindResp = &portalsv1.BindResponse{
		Status: portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_ACCEPTED,
	}
	srv.mu.Unlock()

	// Initial token: token-v1
	if err := os.WriteFile(tokenFile, []byte("token-v1"), 0600); err != nil {
		t.Fatalf("writing token-v1: %v", err)
	}

	c, err := client.New(client.Options{
		ControllerAddr: addr,
		CAFile:         caFile,
		TokenFile:      tokenFile,
	})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	defer c.Close()

	// 1. Call with token-v1
	if err := c.Bind(t.Context(), "pod-1", &portalsv1.EgressPolicy{}, nil); err != nil {
		t.Fatalf("bind with token-v1 failed: %v", err)
	}
	if srv.lastToken != "Bearer token-v1" {
		t.Errorf("server received %q, want 'Bearer token-v1'", srv.lastToken)
	}

	// 2. Rotate token on disk to token-v2 and revoke token-v1 on the server
	if err := os.WriteFile(tokenFile, []byte("token-v2\n"), 0600); err != nil {
		t.Fatalf("writing token-v2: %v", err)
	}
	srv.mu.Lock()
	delete(srv.validTokens, "token-v1")
	srv.mu.Unlock()

	// 3. Make another call with the SAME client instance; it must read the rotated token
	if err := c.Bind(t.Context(), "pod-1", &portalsv1.EgressPolicy{}, nil); err != nil {
		t.Fatalf("bind with rotated token-v2 failed: %v", err)
	}
	if srv.lastToken != "Bearer token-v2" {
		t.Errorf("server received %q, want 'Bearer token-v2'", srv.lastToken)
	}
}

func TestClient_OptionsValidation(t *testing.T) {
	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.crt")
	tokenFile := filepath.Join(tmpDir, "token")
	_ = os.WriteFile(caFile, []byte("cert"), 0600)
	_ = os.WriteFile(tokenFile, []byte("token"), 0600)

	tests := []struct {
		name    string
		opts    client.Options
		wantErr string
	}{
		{
			name:    "missing controller address",
			opts:    client.Options{CAFile: caFile, TokenFile: tokenFile},
			wantErr: "controller address is required",
		},
		{
			name:    "missing CA file",
			opts:    client.Options{ControllerAddr: "localhost:8443", TokenFile: tokenFile},
			wantErr: "CA file is required",
		},
		{
			name:    "missing token file",
			opts:    client.Options{ControllerAddr: "localhost:8443", CAFile: caFile},
			wantErr: "token file is required",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := client.New(tc.opts)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("client.New() error = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}

func TestClient_WrongCA(t *testing.T) {
	_, addr, _, tokenFile := setupTestServer(t)

	ip := net.ParseIP("127.0.0.1")
	wrongCertPEM, _ := generateTestCertificate(t, ip)
	wrongCAFile := filepath.Join(t.TempDir(), "wrong-ca.crt")
	if err := os.WriteFile(wrongCAFile, wrongCertPEM, 0600); err != nil {
		t.Fatalf("writing wrong CA file: %v", err)
	}

	c, err := client.New(client.Options{
		ControllerAddr: addr,
		CAFile:         wrongCAFile,
		TokenFile:      tokenFile,
	})
	if err != nil {
		t.Fatalf("client.New with wrong CA: %v", err)
	}
	defer c.Close()

	err = c.Bind(t.Context(), "pod-1", &portalsv1.EgressPolicy{}, nil)
	if err == nil {
		t.Fatal("expected TLS handshake error with wrong CA, got nil")
	}
}
