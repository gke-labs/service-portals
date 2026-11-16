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
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	portalsv1 "github.com/gke-labs/service-portals/pkg/portals/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

type fakeControllerServer struct {
	portalsv1.UnimplementedNodeStreamServiceServer
	mu         sync.Mutex
	tokens     []string
	declCh     chan []string
	answerCh   chan *portalsv1.PushAnswer
	pushCh     chan *portalsv1.ControllerPush
	dropStream chan struct{}
}

func newFakeControllerServer() *fakeControllerServer {
	return &fakeControllerServer{
		declCh:     make(chan []string, 10),
		answerCh:   make(chan *portalsv1.PushAnswer, 10),
		pushCh:     make(chan *portalsv1.ControllerPush, 10),
		dropStream: make(chan struct{}, 1),
	}
}

func (s *fakeControllerServer) Stream(stream portalsv1.NodeStreamService_StreamServer) error {
	md, ok := metadata.FromIncomingContext(stream.Context())
	if ok {
		auth := md.Get("authorization")
		if len(auth) > 0 {
			tok := strings.TrimPrefix(auth[0], "Bearer ")
			s.mu.Lock()
			s.tokens = append(s.tokens, tok)
			s.mu.Unlock()
		}
	}

	recvErr := make(chan error, 1)
	go func() {
		for {
			msg, err := stream.Recv()
			if err != nil {
				recvErr <- err
				return
			}
			switch payload := msg.GetPayload().(type) {
			case *portalsv1.NodeMessage_Declaration:
				s.declCh <- payload.Declaration.GetPodUids()
			case *portalsv1.NodeMessage_Answer:
				s.answerCh <- payload.Answer
			}
		}
	}()

	for {
		select {
		case <-s.dropStream:
			return nil
		case <-stream.Context().Done():
			return stream.Context().Err()
		case err := <-recvErr:
			return err
		case push := <-s.pushCh:
			if err := stream.Send(&portalsv1.ControllerMessage{
				Payload: &portalsv1.ControllerMessage_Push{Push: push},
			}); err != nil {
				return err
			}
		}
	}
}

func generateTestCertificates(t *testing.T) (caCertPath, serverCertPath, serverKeyPath string) {
	t.Helper()
	caPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating CA key: %v", err)
	}

	caTemplate := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Controller Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caPriv.PublicKey, caPriv)
	if err != nil {
		t.Fatalf("creating CA cert: %v", err)
	}

	serverPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating server key: %v", err)
	}

	serverTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.IPv6loopback},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	serverDER, err := x509.CreateCertificate(rand.Reader, &serverTemplate, &caTemplate, &serverPriv.PublicKey, caPriv)
	if err != nil {
		t.Fatalf("creating server cert: %v", err)
	}

	tmpDir := t.TempDir()
	caCertPath = filepath.Join(tmpDir, "ca.crt")
	serverCertPath = filepath.Join(tmpDir, "server.crt")
	serverKeyPath = filepath.Join(tmpDir, "server.key")

	if err := os.WriteFile(caCertPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0600); err != nil {
		t.Fatalf("writing CA cert: %v", err)
	}
	if err := os.WriteFile(serverCertPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}), 0600); err != nil {
		t.Fatalf("writing server cert: %v", err)
	}
	serverKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverPriv)})
	if err := os.WriteFile(serverKeyPath, serverKeyPEM, 0600); err != nil {
		t.Fatalf("writing server key: %v", err)
	}

	return caCertPath, serverCertPath, serverKeyPath
}

func TestControllerClient_LifecycleAndAcceptance(t *testing.T) {
	caCertPath, serverCertPath, serverKeyPath := generateTestCertificates(t)

	serverCert, err := tls.LoadX509KeyPair(serverCertPath, serverKeyPath)
	if err != nil {
		t.Fatalf("loading server key pair: %v", err)
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening on TCP: %v", err)
	}
	defer l.Close()

	fakeController := newFakeControllerServer()
	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewServerTLSFromCert(&serverCert)))
	portalsv1.RegisterNodeStreamServiceServer(grpcServer, fakeController)
	go func() {
		_ = grpcServer.Serve(l)
	}()
	defer grpcServer.Stop()

	tmpDir := t.TempDir()
	tokenPath := filepath.Join(tmpDir, "token")
	if err := os.WriteFile(tokenPath, []byte("token-initial-v1"), 0600); err != nil {
		t.Fatalf("writing token: %v", err)
	}

	pm := NewPodMap()
	pm.AddOrUpdatePod(&PodInfo{UID: "pod-1", IPs: []string{"10.0.0.1"}})

	store, err := portalsv1.NewBindingStore("")
	if err != nil {
		t.Fatalf("failed to create BindingStore: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	go runControllerClient(ctx, controllerClientConfig{
		addr:       l.Addr().String(),
		tokenPath:  tokenPath,
		caCertPath: caCertPath,
		pm:         pm,
		store:      store,
	})

	// 1. On connect the node declares its pods
	select {
	case decl := <-fakeController.declCh:
		if len(decl) != 1 || decl[0] != "pod-1" {
			t.Fatalf("expected pod declaration [pod-1], got %v", decl)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for pod declaration on connect")
	}

	fakeController.mu.Lock()
	if len(fakeController.tokens) == 0 || fakeController.tokens[0] != "token-initial-v1" {
		t.Fatalf("expected token-initial-v1, got %v", fakeController.tokens)
	}
	fakeController.mu.Unlock()

	// 2. Pod added and removed restates full pod list
	pm.AddOrUpdatePod(&PodInfo{UID: "pod-2", IPs: []string{"10.0.0.2"}})
	select {
	case decl := <-fakeController.declCh:
		if len(decl) != 2 || decl[0] != "pod-1" || decl[1] != "pod-2" {
			t.Fatalf("expected restated pods [pod-1 pod-2], got %v", decl)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for pod-2 add restatement")
	}

	pm.RemovePod("pod-2")
	select {
	case decl := <-fakeController.declCh:
		if len(decl) != 1 || decl[0] != "pod-1" {
			t.Fatalf("expected restated pods [pod-1], got %v", decl)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for pod-2 remove restatement")
	}

	// 3. Push policy naming secrets -> pending with missing secrets
	policyWithSecrets := &portalsv1.EgressPolicy{
		Rules: []*portalsv1.EgressRule{
			{
				Https: &portalsv1.HttpsRule{
					Hostnames: []string{"api.github.com"},
					Effects: &portalsv1.HttpRuleEffects{
						ReplaceHeaders: []*portalsv1.CredentialHeader{
							{Header: "Authorization", CredentialUri: "secret://token-1"},
							{Header: "X-Api-Key", CredentialUri: "secret://token-2"},
						},
					},
				},
			},
		},
	}
	fakeController.pushCh <- &portalsv1.ControllerPush{
		PushId: "push-1",
		Action: &portalsv1.ControllerPush_Policy{
			Policy: &portalsv1.PodPolicy{PodUid: "pod-1", Policy: policyWithSecrets},
		},
	}

	select {
	case ans := <-fakeController.answerCh:
		if ans.PushId != "push-1" || ans.PodUid != "pod-1" {
			t.Fatalf("unexpected answer: %+v", ans)
		}
		if ans.Status != portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_PENDING {
			t.Fatalf("expected PENDING, got %v", ans.Status)
		}
		if len(ans.MissingSecrets) != 2 || ans.MissingSecrets[0] != "token-1" || ans.MissingSecrets[1] != "token-2" {
			t.Fatalf("expected missing [token-1 token-2], got %v", ans.MissingSecrets)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for push-1 answer")
	}

	// Verify policy is resolvable from BindingStore
	if pol := store.Policy("pod-1"); pol == nil {
		t.Fatal("policy not resolvable from BindingStore")
	}

	// Push first secret -> still pending
	fakeController.pushCh <- &portalsv1.ControllerPush{
		PushId: "push-2",
		Action: &portalsv1.ControllerPush_Secrets{
			Secrets: &portalsv1.PodSecrets{
				PodUid:  "pod-1",
				Secrets: map[string][]byte{"token-1": []byte("sec-1")},
			},
		},
	}
	select {
	case ans := <-fakeController.answerCh:
		if ans.Status != portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_PENDING {
			t.Fatalf("expected PENDING, got %v", ans.Status)
		}
		if len(ans.MissingSecrets) != 1 || ans.MissingSecrets[0] != "token-2" {
			t.Fatalf("expected missing [token-2], got %v", ans.MissingSecrets)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for push-2 answer")
	}

	// Push full set of secrets -> accepted once last named secret arrives
	fakeController.pushCh <- &portalsv1.ControllerPush{
		PushId: "push-3",
		Action: &portalsv1.ControllerPush_Secrets{
			Secrets: &portalsv1.PodSecrets{
				PodUid:  "pod-1",
				Secrets: map[string][]byte{"token-1": []byte("sec-1"), "token-2": []byte("sec-2")},
			},
		},
	}
	select {
	case ans := <-fakeController.answerCh:
		if ans.Status != portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_ACCEPTED {
			t.Fatalf("expected ACCEPTED, got %v", ans.Status)
		}
		if len(ans.MissingSecrets) != 0 {
			t.Fatalf("expected no missing secrets, got %v", ans.MissingSecrets)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for push-3 answer")
	}

	// Verify secrets are resolvable from BindingStore
	s1, ok1 := store.ResolveSecret("pod-1", "token-1")
	s2, ok2 := store.ResolveSecret("pod-1", "token-2")
	if !ok1 || string(s1.Bytes()) != "sec-1" || !ok2 || string(s2.Bytes()) != "sec-2" {
		t.Fatal("secrets not properly resolved from BindingStore")
	}

	// 4. Policy that names no secrets is accepted on its own
	pm.AddOrUpdatePod(&PodInfo{UID: "pod-no-sec", IPs: []string{"10.0.0.3"}})
	select {
	case <-fakeController.declCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for pod-no-sec update")
	}

	noSecPolicy := &portalsv1.EgressPolicy{
		Rules: []*portalsv1.EgressRule{
			{Https: &portalsv1.HttpsRule{Hostnames: []string{"example.com"}}},
		},
	}
	fakeController.pushCh <- &portalsv1.ControllerPush{
		PushId: "push-4",
		Action: &portalsv1.ControllerPush_Policy{
			Policy: &portalsv1.PodPolicy{PodUid: "pod-no-sec", Policy: noSecPolicy},
		},
	}
	select {
	case ans := <-fakeController.answerCh:
		if ans.Status != portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_ACCEPTED {
			t.Fatalf("expected ACCEPTED for policy naming no secrets, got %v", ans.Status)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for push-4 answer")
	}

	// 5. Invalid policy is refused with validation message and nothing is stored
	invalidPolicy := &portalsv1.EgressPolicy{
		Rules: []*portalsv1.EgressRule{
			{
				Https: &portalsv1.HttpsRule{
					Hostnames: []string{"api.github.com"},
				},
			},
			{
				Https: &portalsv1.HttpsRule{
					Hostnames: []string{"api.github.com"},
				},
			},
		},
	}
	fakeController.pushCh <- &portalsv1.ControllerPush{
		PushId: "push-5",
		Action: &portalsv1.ControllerPush_Policy{
			Policy: &portalsv1.PodPolicy{PodUid: "pod-1", Policy: invalidPolicy},
		},
	}
	select {
	case ans := <-fakeController.answerCh:
		if ans.Status != portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_REFUSED {
			t.Fatalf("expected REFUSED for invalid policy, got %v", ans.Status)
		}
		if ans.RefusalReason == "" {
			t.Fatal("expected refusal reason with validation message")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for push-5 answer")
	}

	// 6. Push for pod not on node is refused
	fakeController.pushCh <- &portalsv1.ControllerPush{
		PushId: "push-6",
		Action: &portalsv1.ControllerPush_Policy{
			Policy: &portalsv1.PodPolicy{PodUid: "pod-not-on-node", Policy: noSecPolicy},
		},
	}
	select {
	case ans := <-fakeController.answerCh:
		if ans.Status != portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_REFUSED {
			t.Fatalf("expected REFUSED for pod not on node, got %v", ans.Status)
		}
		if !strings.Contains(ans.RefusalReason, "not found on node") {
			t.Fatalf("expected refusal reason to mention 'not found on node', got %q", ans.RefusalReason)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for push-6 answer")
	}
	if pol := store.Policy("pod-not-on-node"); pol != nil {
		t.Fatal("expected nothing stored for pod not on node")
	}

	// 7. Unbind removes the binding
	fakeController.pushCh <- &portalsv1.ControllerPush{
		PushId: "push-7",
		Action: &portalsv1.ControllerPush_Unbind{
			Unbind: &portalsv1.UnbindRequest{PodUid: "pod-1"},
		},
	}
	select {
	case ans := <-fakeController.answerCh:
		if ans.Status != portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_ACCEPTED {
			t.Fatalf("expected ACCEPTED for unbind, got %v", ans.Status)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for push-7 answer")
	}
	if pol := store.Policy("pod-1"); pol != nil {
		t.Fatal("expected policy to be removed after unbind")
	}

	// 8. Stream drops -> reconnects, restates pods, token file re-read, bindings still enforce
	// First, rotate token file
	if err := os.WriteFile(tokenPath, []byte("token-rotated-v2"), 0600); err != nil {
		t.Fatalf("updating token file: %v", err)
	}

	// Trigger drop stream
	fakeController.dropStream <- struct{}{}

	// Verify while reconnecting, existing bindings still enforce (pod-no-sec still in store)
	if pol := store.Policy("pod-no-sec"); pol == nil {
		t.Fatal("expected existing binding for pod-no-sec to remain enforced after stream drop")
	}

	// Wait for reconnected stream declaration
	select {
	case decl := <-fakeController.declCh:
		// Should restate current pods (pod-1 and pod-no-sec)
		if len(decl) != 2 || decl[0] != "pod-1" || decl[1] != "pod-no-sec" {
			t.Fatalf("expected restated pods [pod-1 pod-no-sec], got %v", decl)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for restated pod declaration after reconnect")
	}

	// Verify token was re-read on reconnect
	fakeController.mu.Lock()
	lastToken := fakeController.tokens[len(fakeController.tokens)-1]
	fakeController.mu.Unlock()
	if lastToken != "token-rotated-v2" {
		t.Fatalf("expected re-read token 'token-rotated-v2', got %q", lastToken)
	}
}

func TestControllerClient_TLSVerificationFailure(t *testing.T) {
	_, serverCertPath, serverKeyPath := generateTestCertificates(t)
	untrustedCACertPath, _, _ := generateTestCertificates(t)

	serverCert, err := tls.LoadX509KeyPair(serverCertPath, serverKeyPath)
	if err != nil {
		t.Fatalf("loading server key pair: %v", err)
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening on TCP: %v", err)
	}
	defer l.Close()

	fakeController := newFakeControllerServer()
	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewServerTLSFromCert(&serverCert)))
	portalsv1.RegisterNodeStreamServiceServer(grpcServer, fakeController)
	go func() {
		_ = grpcServer.Serve(l)
	}()
	defer grpcServer.Stop()

	tmpDir := t.TempDir()
	tokenPath := filepath.Join(tmpDir, "token")
	if err := os.WriteFile(tokenPath, []byte("tok"), 0600); err != nil {
		t.Fatalf("writing token: %v", err)
	}

	pm := NewPodMap()
	store, err := portalsv1.NewBindingStore("")
	if err != nil {
		t.Fatalf("failed to create BindingStore: %v", err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
	defer cancel()

	// Dial with untrusted CA -> must not successfully declare pods
	go runControllerClient(ctx, controllerClientConfig{
		addr:       l.Addr().String(),
		tokenPath:  tokenPath,
		caCertPath: untrustedCACertPath,
		pm:         pm,
		store:      store,
	})

	select {
	case <-fakeController.declCh:
		t.Fatal("controller client should have failed TLS verification against untrusted CA")
	case <-ctx.Done():
		// Expected: failed to verify TLS against untrusted CA
	}
}

func TestControllerClient_ServerRunWiring(t *testing.T) {
	caCertPath, serverCertPath, serverKeyPath := generateTestCertificates(t)

	serverCert, err := tls.LoadX509KeyPair(serverCertPath, serverKeyPath)
	if err != nil {
		t.Fatalf("loading server key pair: %v", err)
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening on TCP: %v", err)
	}
	defer l.Close()

	fakeController := newFakeControllerServer()
	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewServerTLSFromCert(&serverCert)))
	portalsv1.RegisterNodeStreamServiceServer(grpcServer, fakeController)
	go func() {
		_ = grpcServer.Serve(l)
	}()
	defer grpcServer.Stop()

	tmpDir := t.TempDir()
	tokenPath := filepath.Join(tmpDir, "token")
	if err := os.WriteFile(tokenPath, []byte("run-token"), 0600); err != nil {
		t.Fatalf("writing token: %v", err)
	}

	pm := NewPodMap()
	pm.AddOrUpdatePod(&PodInfo{UID: "pod-wired", IPs: []string{"10.0.0.10"}})

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	t.Setenv("ADMIN_ADDR", filepath.Join(tmpDir, "admin.sock"))
	t.Setenv("CONTROLLER_ADDR", l.Addr().String())
	t.Setenv("CONTROLLER_TOKEN_PATH", tokenPath)
	t.Setenv("CONTROLLER_CA_CERT_PATH", caCertPath)

	config := Config{
		PodMap:         pm,
		BindSocketPath: filepath.Join(tmpDir, "bind.sock"),
	}

	runErr := make(chan error, 1)
	go func() {
		runErr <- Run(ctx, config)
	}()

	select {
	case decl := <-fakeController.declCh:
		if len(decl) != 1 || decl[0] != "pod-wired" {
			t.Fatalf("expected [pod-wired], got %v", decl)
		}
	case err := <-runErr:
		t.Fatalf("Run exited unexpectedly: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for controller declaration from Run")
	}

	cancel()
	<-runErr
}

func TestRun_ControllerConfigValidation(t *testing.T) {
	caCertPath, _, _ := generateTestCertificates(t)
	tmpDir := t.TempDir()
	tokenPath := filepath.Join(tmpDir, "token")
	if err := os.WriteFile(tokenPath, []byte("valid-token"), 0600); err != nil {
		t.Fatalf("writing token: %v", err)
	}

	tests := []struct {
		name           string
		controllerAddr string
		caCertPath     string
		tokenPath      string
		wantErrSub     string
	}{
		{
			name:           "missing CA cert path",
			controllerAddr: "127.0.0.1:9999",
			caCertPath:     "",
			tokenPath:      tokenPath,
			wantErrSub:     "CONTROLLER_CA_CERT_PATH is required",
		},
		{
			name:           "unreadable CA cert",
			controllerAddr: "127.0.0.1:9999",
			caCertPath:     filepath.Join(tmpDir, "nonexistent-ca.crt"),
			tokenPath:      tokenPath,
			wantErrSub:     "failed to load controller CA cert",
		},
		{
			name:           "missing token path",
			controllerAddr: "127.0.0.1:9999",
			caCertPath:     caCertPath,
			tokenPath:      "",
			wantErrSub:     "CONTROLLER_TOKEN_PATH is required",
		},
		{
			name:           "unreadable token path",
			controllerAddr: "127.0.0.1:9999",
			caCertPath:     caCertPath,
			tokenPath:      filepath.Join(tmpDir, "nonexistent-token"),
			wantErrSub:     "failed to read controller token file",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("ADMIN_ADDR", filepath.Join(t.TempDir(), "admin.sock"))
			t.Setenv("CONTROLLER_ADDR", tc.controllerAddr)
			t.Setenv("CONTROLLER_CA_CERT_PATH", tc.caCertPath)
			t.Setenv("CONTROLLER_TOKEN_PATH", tc.tokenPath)

			config := Config{
				PodMap:         NewPodMap(),
				BindSocketPath: filepath.Join(t.TempDir(), "bind.sock"),
			}
			err := Run(t.Context(), config)
			if err == nil {
				t.Fatal("expected Run to fail validation, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantErrSub) {
				t.Fatalf("expected error containing %q, got %v", tc.wantErrSub, err)
			}
		})
	}
}
