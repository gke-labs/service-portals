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
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
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
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
)

const (
	testAudience            = "https://controller.service-portals"
	testNodeAgentAccount    = "system:serviceaccount:service-portals:portal-node-agent"
	testClientAccount       = "system:serviceaccount:default:sandbox-controller"
	testUnauthorizedAccount = "system:serviceaccount:default:unauthorized-client"
)

func generateTestCertAndKey(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey failed: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.IPv6loopback},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("x509.CreateCertificate failed: %v", err)
	}

	dir := t.TempDir()
	certFile = filepath.Join(dir, "server.crt")
	keyFile = filepath.Join(dir, "server.key")

	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatalf("writing certFile failed: %v", err)
	}
	keyDER := x509.MarshalPKCS1PrivateKey(priv)
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatalf("writing keyFile failed: %v", err)
	}
	return certFile, keyFile
}

func makeJWT(sub string, exp time.Time) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payloadBytes, _ := json.Marshal(map[string]any{
		"sub": sub,
		"exp": exp.Unix(),
	})
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	return fmt.Sprintf("%s.%s.signature", header, payload)
}

func newTestPod(namespace, name string, uid types.UID, nodeName string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
			UID:       uid,
		},
		Spec: corev1.PodSpec{
			NodeName: nodeName,
		},
	}
}

func TestWiredController(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	certFile, keyFile := generateTestCertAndKey(t)
	fakeClient := fake.NewClientset()

	nodeAgentToken := makeJWT(testNodeAgentAccount, time.Now().Add(time.Hour))
	clientToken := makeJWT(testClientAccount, time.Now().Add(time.Hour))
	unauthorizedClientToken := makeJWT(testUnauthorizedAccount, time.Now().Add(time.Hour))

	fakeClient.Fake.PrependReactor("create", "tokenreviews", func(action clienttesting.Action) (bool, runtime.Object, error) {
		createAction := action.(clienttesting.CreateAction)
		tr := createAction.GetObject().(*authenticationv1.TokenReview)
		switch tr.Spec.Token {
		case nodeAgentToken:
			tr.Status = authenticationv1.TokenReviewStatus{
				Authenticated: true,
				Audiences:     []string{testAudience},
				User: authenticationv1.UserInfo{
					Username: testNodeAgentAccount,
					Extra: map[string]authenticationv1.ExtraValue{
						"authentication.kubernetes.io/node-name": []string{"node-test-1"},
					},
				},
			}
		case clientToken:
			tr.Status = authenticationv1.TokenReviewStatus{
				Authenticated: true,
				Audiences:     []string{testAudience},
				User: authenticationv1.UserInfo{
					Username: testClientAccount,
				},
			}
		case unauthorizedClientToken:
			tr.Status = authenticationv1.TokenReviewStatus{
				Authenticated: true,
				Audiences:     []string{testAudience},
				User: authenticationv1.UserInfo{
					Username: testUnauthorizedAccount,
				},
			}
		default:
			tr.Status = authenticationv1.TokenReviewStatus{
				Authenticated: false,
			}
		}
		return true, tr, nil
	})

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening on local port: %v", err)
	}

	cfg := Config{
		TLSCertFile:      certFile,
		TLSKeyFile:       keyFile,
		Audience:         testAudience,
		NodeAgentAccount: testNodeAgentAccount,
		ClientAllowlist:  []string{testClientAccount},
		PushTimeout:      200 * time.Millisecond,
	}

	serverErrCh := make(chan error, 1)
	go func() {
		serverErrCh <- run(ctx, cfg, fakeClient, lis)
	}()

	// Verify TLS 1.3 is enforced: TLS 1.2 client handshake fails.
	tls12Conn, err := tls.Dial("tcp", lis.Addr().String(), &tls.Config{
		MaxVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
	})
	if err == nil {
		_ = tls12Conn.Close()
		t.Fatal("expected TLS 1.2 handshake to fail because MinVersion is TLS 1.3")
	}

	// Dial the wired controller over TLS
	tlsCreds := credentials.NewTLS(&tls.Config{InsecureSkipVerify: true})
	conn, err := grpc.Dial(lis.Addr().String(), grpc.WithTransportCredentials(tlsCreds))
	if err != nil {
		t.Fatalf("dialing server over TLS: %v", err)
	}
	defer conn.Close()

	nodeStreamClient := portalsv1.NewNodeStreamServiceClient(conn)
	bindClient := portalsv1.NewPodBindServiceClient(conn)

	// 1. Connect fake node agent
	nodeCtx, cancelNode := context.WithCancel(ctx)
	defer cancelNode()
	nodeCtx = metadata.NewOutgoingContext(nodeCtx, metadata.Pairs("authorization", "Bearer "+nodeAgentToken))
	stream, err := nodeStreamClient.Stream(nodeCtx)
	if err != nil {
		t.Fatalf("opening node stream: %v", err)
	}

	// Send initial declaration with pod-1
	if err := stream.Send(&portalsv1.NodeMessage{
		Payload: &portalsv1.NodeMessage_Declaration{
			Declaration: &portalsv1.PodDeclaration{
				PodUids: []string{"pod-1"},
			},
		},
	}); err != nil {
		t.Fatalf("sending declaration: %v", err)
	}

	// Fake node agent answering loop
	go func() {
		for {
			msg, err := stream.Recv()
			if err != nil {
				return
			}
			push := msg.GetPush()
			if push == nil {
				continue
			}
			var uid string
			switch a := push.GetAction().(type) {
			case *portalsv1.ControllerPush_Policy:
				uid = a.Policy.GetPodUid()
			case *portalsv1.ControllerPush_Secrets:
				uid = a.Secrets.GetPodUid()
			case *portalsv1.ControllerPush_Unbind:
				uid = a.Unbind.GetPodUid()
			}
			_ = stream.Send(&portalsv1.NodeMessage{
				Payload: &portalsv1.NodeMessage_Answer{
					Answer: &portalsv1.PushAnswer{
						PushId: push.GetPushId(),
						PodUid: uid,
						Status: portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_ACCEPTED,
					},
				},
			})
		}
	}()

	// Create pod-1 scheduled on node-test-1 in the fake API
	if _, err := fakeClient.CoreV1().Pods("default").Create(ctx, newTestPod("default", "pod-1", types.UID("pod-1"), "node-test-1"), metav1.CreateOptions{}); err != nil {
		t.Fatalf("creating pod-1 in fake API: %v", err)
	}

	// Wait briefly for informer cache sync
	time.Sleep(100 * time.Millisecond)

	clientCtx := metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", "Bearer "+clientToken))

	// Requirement 1: a client's Bind with wait for a pod on that node returns the node's accepted answer
	bindResp, err := bindClient.Bind(clientCtx, &portalsv1.PodPolicy{
		PodUid: "pod-1",
		Policy: &portalsv1.EgressPolicy{},
		Wait:   true,
	})
	if err != nil {
		t.Fatalf("Bind pod-1 failed: %v", err)
	}
	if bindResp.GetStatus() != portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_ACCEPTED || !bindResp.GetBound() {
		t.Fatalf("expected accepted and bound=true, got status=%v, bound=%v", bindResp.GetStatus(), bindResp.GetBound())
	}

	// Requirement 2: the same call from a client not on the allowlist is refused
	unauthCtx := metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", "Bearer "+unauthorizedClientToken))
	_, err = bindClient.Bind(unauthCtx, &portalsv1.PodPolicy{
		PodUid: "pod-1",
		Policy: &portalsv1.EgressPolicy{},
		Wait:   true,
	})
	if err == nil {
		t.Fatal("expected unauthorized client to be refused, got nil")
	}
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", status.Code(err))
	}

	// Requirement 3: a push for a pod that is scheduled after the call is delivered once the resolver sees it
	// Node agent announces it has pod-2
	if err := stream.Send(&portalsv1.NodeMessage{
		Payload: &portalsv1.NodeMessage_Update{
			Update: &portalsv1.PodUpdate{
				AddedPodUids: []string{"pod-2"},
			},
		},
	}); err != nil {
		t.Fatalf("declaring pod-2 on node: %v", err)
	}

	// Push for pod-2 before pod-2 exists in Kubernetes (held in pending)
	bindDone := make(chan error, 1)
	var heldBindResp *portalsv1.BindResponse
	go func() {
		var bErr error
		heldBindResp, bErr = bindClient.Bind(clientCtx, &portalsv1.PodPolicy{
			PodUid: "pod-2",
			Policy: &portalsv1.EgressPolicy{},
			Wait:   true,
		})
		bindDone <- bErr
	}()

	// Verify push is held
	select {
	case err := <-bindDone:
		t.Fatalf("push returned prematurely before scheduling: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	// Now schedule pod-2 in the fake Kubernetes client
	if _, err := fakeClient.CoreV1().Pods("default").Create(ctx, newTestPod("default", "pod-2", types.UID("pod-2"), "node-test-1"), metav1.CreateOptions{}); err != nil {
		t.Fatalf("scheduling pod-2: %v", err)
	}

	// The held push should now be delivered and accepted
	select {
	case err := <-bindDone:
		if err != nil {
			t.Fatalf("held Bind failed: %v", err)
		}
		if heldBindResp.GetStatus() != portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_ACCEPTED {
			t.Fatalf("expected ACCEPTED for scheduled pod-2, got %v", heldBindResp.GetStatus())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for held push to be delivered once scheduled")
	}

	// Requirement 4: a wait that runs out is DeadlineExceeded
	_, err = bindClient.Bind(clientCtx, &portalsv1.PodPolicy{
		PodUid: "pod-never-scheduled",
		Policy: &portalsv1.EgressPolicy{},
		Wait:   true,
	})
	if err == nil {
		t.Fatal("expected timeout error for unscheduled pod, got nil")
	}
	if status.Code(err) != codes.DeadlineExceeded {
		t.Fatalf("expected codes.DeadlineExceeded, got %v: %v", status.Code(err), err)
	}

	// Cancel context to stop server
	cancel()
	select {
	case err := <-serverErrCh:
		if err != nil {
			t.Fatalf("server returned error on shutdown: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for server to stop")
	}
}

// Requirement 5: starting without a certificate fails
func TestStartingWithoutCertificateFails(t *testing.T) {
	ctx := t.Context()
	fakeClient := fake.NewClientset()

	// Missing certificate configuration
	err := run(ctx, Config{
		TLSCertFile:      "",
		TLSKeyFile:       "",
		Audience:         testAudience,
		NodeAgentAccount: testNodeAgentAccount,
	}, fakeClient, nil)
	if err == nil {
		t.Fatal("expected error starting without certificate files, got nil")
	}

	// Non-existent certificate files
	err = run(ctx, Config{
		TLSCertFile:      "/tmp/nonexistent-cert.crt",
		TLSKeyFile:       "/tmp/nonexistent-key.key",
		Audience:         testAudience,
		NodeAgentAccount: testNodeAgentAccount,
	}, fakeClient, nil)
	if err == nil {
		t.Fatal("expected error starting with non-existent certificate files, got nil")
	}
}

func TestFailClosedAtStartup(t *testing.T) {
	ctx := t.Context()
	certFile, keyFile := generateTestCertAndKey(t)
	fakeClient := fake.NewClientset()

	// Missing audience
	err := run(ctx, Config{
		TLSCertFile:      certFile,
		TLSKeyFile:       keyFile,
		Audience:         "",
		NodeAgentAccount: testNodeAgentAccount,
	}, fakeClient, nil)
	if err == nil {
		t.Fatal("expected error for missing audience, got nil")
	}

	// Missing node agent account
	err = run(ctx, Config{
		TLSCertFile:      certFile,
		TLSKeyFile:       keyFile,
		Audience:         testAudience,
		NodeAgentAccount: "",
	}, fakeClient, nil)
	if err == nil {
		t.Fatal("expected error for missing node agent account, got nil")
	}

	// No access to Kubernetes API
	errClient := fake.NewClientset()
	errClient.Fake.PrependReactor("list", "pods", func(action clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, fmt.Errorf("apiserver unreachable")
	})
	err = run(ctx, Config{
		TLSCertFile:      certFile,
		TLSKeyFile:       keyFile,
		Audience:         testAudience,
		NodeAgentAccount: testNodeAgentAccount,
	}, errClient, nil)
	if err == nil {
		t.Fatal("expected error when Kubernetes API is inaccessible, got nil")
	}
}

func TestParseFlags(t *testing.T) {
	args := []string{
		"-listen-address", ":9443",
		"-tls-cert-file", "/etc/certs/tls.crt",
		"-tls-key-file", "/etc/certs/tls.key",
		"-audience", "my-audience",
		"-node-agent-account", "sa-node-agent",
		"-client-allowlist", "client-1, client-2",
		"-kubeconfig", "/etc/kubeconfig",
		"-push-timeout", "30s",
	}

	cfg, err := parseFlags(args)
	if err != nil {
		t.Fatalf("parseFlags failed: %v", err)
	}

	if cfg.ListenAddr != ":9443" {
		t.Errorf("expected :9443, got %s", cfg.ListenAddr)
	}
	if cfg.TLSCertFile != "/etc/certs/tls.crt" {
		t.Errorf("expected /etc/certs/tls.crt, got %s", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "/etc/certs/tls.key" {
		t.Errorf("expected /etc/certs/tls.key, got %s", cfg.TLSKeyFile)
	}
	if cfg.Audience != "my-audience" {
		t.Errorf("expected my-audience, got %s", cfg.Audience)
	}
	if cfg.NodeAgentAccount != "sa-node-agent" {
		t.Errorf("expected sa-node-agent, got %s", cfg.NodeAgentAccount)
	}
	if len(cfg.ClientAllowlist) != 2 || cfg.ClientAllowlist[0] != "client-1" || cfg.ClientAllowlist[1] != "client-2" {
		t.Errorf("expected [client-1, client-2], got %v", cfg.ClientAllowlist)
	}
	if cfg.Kubeconfig != "/etc/kubeconfig" {
		t.Errorf("expected /etc/kubeconfig, got %s", cfg.Kubeconfig)
	}
	if cfg.PushTimeout != 30*time.Second {
		t.Errorf("expected 30s, got %v", cfg.PushTimeout)
	}
}
