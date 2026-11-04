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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	portalsv1 "github.com/gke-labs/service-portals/pkg/portals/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

type testCerts struct {
	caCert     *x509.Certificate
	caKey      *ecdsa.PrivateKey
	caPEM      []byte
	serverCert tls.Certificate
	serverPEM  []byte
	serverKey  []byte
}

func generateTestPKI(t *testing.T) *testCerts {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Dedicated Bind CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("failed to parse CA cert: %v", err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	// Server cert for 127.0.0.1 and localhost
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate server key: %v", err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create server cert: %v", err)
	}
	serverCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER})
	serverKeyDER, err := x509.MarshalECPrivateKey(serverKey)
	if err != nil {
		t.Fatalf("failed to marshal server key: %v", err)
	}
	serverKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: serverKeyDER})
	serverTLS, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		t.Fatalf("failed to parse server keypair: %v", err)
	}

	return &testCerts{
		caCert:     caCert,
		caKey:      caKey,
		caPEM:      caPEM,
		serverCert: serverTLS,
		serverPEM:  serverCertPEM,
		serverKey:  serverKeyPEM,
	}
}

func (tc *testCerts) newClientCert(t *testing.T, commonName string, sans ...string) tls.Certificate {
	t.Helper()
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate client key: %v", err)
	}
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: commonName},
		DNSNames:     sans,
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, tc.caCert, &clientKey.PublicKey, tc.caKey)
	if err != nil {
		t.Fatalf("failed to create client cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER})
	keyDER, err := x509.MarshalECPrivateKey(clientKey)
	if err != nil {
		t.Fatalf("failed to marshal client key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("failed to parse client keypair: %v", err)
	}
	return tlsCert
}

func startTestGRPCServer(t *testing.T, pm *PodMap, allowedCallers []string, tc *testCerts) (string, func()) {
	t.Helper()
	clientCAPool := x509.NewCertPool()
	clientCAPool.AppendCertsFromPEM(tc.caPEM)

	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{tc.serverCert},
		ClientCAs:    clientCAPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on tcp: %v", err)
	}

	srv, err := NewGRPCServer(pm, allowedCallers, serverTLS)
	if err != nil {
		_ = listener.Close()
		t.Fatalf("failed to create grpc server: %v", err)
	}

	go func() {
		_ = srv.Serve(listener)
	}()

	cleanup := func() {
		srv.Stop()
		_ = listener.Close()
	}

	return listener.Addr().String(), cleanup
}

func dialTestGRPC(t *testing.T, addr string, serverCAPEM []byte, clientCert *tls.Certificate) (*grpc.ClientConn, portalsv1.PodBindServiceClient) {
	t.Helper()
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(serverCAPEM)

	tlsCfg := &tls.Config{
		RootCAs:    caPool,
		ServerName: "localhost",
	}
	if clientCert != nil {
		tlsCfg.Certificates = []tls.Certificate{*clientCert}
	}

	conn, err := grpc.NewClient(
		addr,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
	)
	if err != nil {
		t.Fatalf("failed to dial grpc server %s: %v", addr, err)
	}

	return conn, portalsv1.NewPodBindServiceClient(conn)
}

func TestPodBindServer_AllowedCaller(t *testing.T) {
	tc := generateTestPKI(t)
	pm := NewPodMap()
	addr, stop := startTestGRPCServer(t, pm, []string{"sandbox-controller", "claim-controller"}, tc)
	defer stop()

	clientCert := tc.newClientCert(t, "sandbox-controller")
	conn, client := dialTestGRPC(t, addr, tc.caPEM, &clientCert)
	defer func() { _ = conn.Close() }()

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	// 1. Get before bind on unknown pod returns NotFound
	_, err := client.Get(ctx, &portalsv1.GetRequest{PodUid: "pod-123"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("expected NotFound before bind, got: %v", err)
	}

	// 2. Bind pod-123
	bindResp, err := client.Bind(ctx, &portalsv1.BindRequest{
		PodUid:   "pod-123",
		Identity: "alice",
		Policy:   "backend,github",
	})
	if err != nil {
		t.Fatalf("bind failed: %v", err)
	}
	if !bindResp.GetBound() || bindResp.GetPodUid() != "pod-123" {
		t.Fatalf("unexpected bind response: %+v", bindResp)
	}

	// 3. Get after bind returns bound status and policy
	getResp, err := client.Get(ctx, &portalsv1.GetRequest{PodUid: "pod-123"})
	if err != nil {
		t.Fatalf("get failed: %v", err)
	}
	if !getResp.GetBound() || getResp.GetIdentity() != "alice" || getResp.GetPolicy() != "backend,github" {
		t.Fatalf("unexpected get response: %+v", getResp)
	}

	// 4. Verify podmap state
	pod, ok := pm.GetPodByUID("pod-123")
	if !ok || !pod.Bound || pod.Identity != "alice" {
		t.Fatalf("unexpected podmap state: %+v, ok=%v", pod, ok)
	}
	if !pm.IsRuleAllowed(pod, "github", "api.github.com") {
		t.Errorf("expected rule to be allowed after bind")
	}

	// 5. Unbind pod-123
	unbindResp, err := client.Unbind(ctx, &portalsv1.UnbindRequest{PodUid: "pod-123"})
	if err != nil {
		t.Fatalf("unbind failed: %v", err)
	}
	if unbindResp.GetBound() {
		t.Fatalf("expected bound to be false after unbind")
	}

	// 6. Verify podmap state after unbind
	pod, ok = pm.GetPodByUID("pod-123")
	if !ok || pod.Bound || pod.Identity != "" {
		t.Fatalf("unexpected podmap state after unbind: %+v", pod)
	}
	if pm.IsRuleAllowed(pod, "github", "api.github.com") {
		t.Errorf("expected rule to be denied after unbind")
	}
}

func TestPodBindServer_UnauthorizedCaller(t *testing.T) {
	tc := generateTestPKI(t)
	pm := NewPodMap()
	addr, stop := startTestGRPCServer(t, pm, []string{"sandbox-controller"}, tc)
	defer stop()

	// Client cert signed by CA, but identity is "unknown-caller" (not in allowlist)
	unauthCert := tc.newClientCert(t, "unknown-caller")
	conn, client := dialTestGRPC(t, addr, tc.caPEM, &unauthCert)
	defer func() { _ = conn.Close() }()

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	_, err := client.Bind(ctx, &portalsv1.BindRequest{
		PodUid:   "pod-rogue",
		Identity: "attacker",
		Policy:   "*",
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied for unauthorized caller, got: %v", err)
	}

	// Pod must not be created or bound
	if _, ok := pm.GetPodByUID("pod-rogue"); ok {
		t.Fatalf("pod must not exist after unauthorized bind call")
	}
}

func TestPodBindServer_UntrustedCA(t *testing.T) {
	trustedTC := generateTestPKI(t)
	untrustedTC := generateTestPKI(t)

	pm := NewPodMap()
	addr, stop := startTestGRPCServer(t, pm, []string{"sandbox-controller"}, trustedTC)
	defer stop()

	// Client cert signed by untrusted CA
	untrustedClientCert := untrustedTC.newClientCert(t, "sandbox-controller")
	conn, client := dialTestGRPC(t, addr, trustedTC.caPEM, &untrustedClientCert)
	defer func() { _ = conn.Close() }()

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	_, err := client.Bind(ctx, &portalsv1.BindRequest{
		PodUid:   "pod-bad-ca",
		Identity: "alice",
		Policy:   "*",
	})
	if err == nil {
		t.Fatalf("expected error connecting with untrusted CA client cert, got nil")
	}
}

func TestPodBindServer_NoClientCert(t *testing.T) {
	tc := generateTestPKI(t)
	pm := NewPodMap()
	addr, stop := startTestGRPCServer(t, pm, []string{"sandbox-controller"}, tc)
	defer stop()

	// Connect without client certificate
	conn, client := dialTestGRPC(t, addr, tc.caPEM, nil)
	defer func() { _ = conn.Close() }()

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	_, err := client.Bind(ctx, &portalsv1.BindRequest{
		PodUid:   "pod-no-cert",
		Identity: "alice",
		Policy:   "*",
	})
	if err == nil {
		t.Fatalf("expected error connecting without client cert, got nil")
	}
}

func TestPodBindServer_WildcardAllowlist(t *testing.T) {
	tc := generateTestPKI(t)
	pm := NewPodMap()
	addr, stop := startTestGRPCServer(t, pm, []string{"*"}, tc)
	defer stop()

	clientCert := tc.newClientCert(t, "custom-controller-id")
	conn, client := dialTestGRPC(t, addr, tc.caPEM, &clientCert)
	defer func() { _ = conn.Close() }()

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	resp, err := client.Bind(ctx, &portalsv1.BindRequest{
		PodUid:   "wildcard-pod",
		Identity: "bob",
		Policy:   "backend",
	})
	if err != nil {
		t.Fatalf("bind failed with wildcard allowlist: %v", err)
	}
	if !resp.GetBound() {
		t.Fatalf("expected bound true")
	}
}

func TestPodBindServer_Validation(t *testing.T) {
	tc := generateTestPKI(t)
	pm := NewPodMap()
	addr, stop := startTestGRPCServer(t, pm, []string{"sandbox-controller"}, tc)
	defer stop()

	clientCert := tc.newClientCert(t, "sandbox-controller")
	conn, client := dialTestGRPC(t, addr, tc.caPEM, &clientCert)
	defer func() { _ = conn.Close() }()

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	// Empty pod UID in Bind
	_, err := client.Bind(ctx, &portalsv1.BindRequest{})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument for empty pod_uid in Bind, got: %v", err)
	}

	// Empty pod UID in Unbind
	_, err = client.Unbind(ctx, &portalsv1.UnbindRequest{})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument for empty pod_uid in Unbind, got: %v", err)
	}

	// Empty pod UID in Get
	_, err = client.Get(ctx, &portalsv1.GetRequest{})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument for empty pod_uid in Get, got: %v", err)
	}

	// Unbind non-existent pod
	_, err = client.Unbind(ctx, &portalsv1.UnbindRequest{PodUid: "non-existent"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("expected NotFound for non-existent pod in Unbind, got: %v", err)
	}
}

func TestLoadServerMTLSConfig(t *testing.T) {
	tc := generateTestPKI(t)
	tmpDir := t.TempDir()

	certPath := filepath.Join(tmpDir, "server.crt")
	keyPath := filepath.Join(tmpDir, "server.key")
	caPath := filepath.Join(tmpDir, "ca.crt")

	if err := os.WriteFile(certPath, tc.serverPEM, 0600); err != nil {
		t.Fatalf("failed to write server cert: %v", err)
	}
	if err := os.WriteFile(keyPath, tc.serverKey, 0600); err != nil {
		t.Fatalf("failed to write server key: %v", err)
	}
	if err := os.WriteFile(caPath, tc.caPEM, 0600); err != nil {
		t.Fatalf("failed to write CA cert: %v", err)
	}

	cfg, err := LoadServerMTLSConfig(certPath, keyPath, caPath)
	if err != nil {
		t.Fatalf("LoadServerMTLSConfig failed: %v", err)
	}
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("expected ClientAuth RequireAndVerifyClientCert, got: %v", cfg.ClientAuth)
	}
	if cfg.ClientCAs == nil {
		t.Errorf("expected non-nil ClientCAs")
	}
	if len(cfg.Certificates) != 1 {
		t.Errorf("expected 1 certificate, got: %d", len(cfg.Certificates))
	}
}
