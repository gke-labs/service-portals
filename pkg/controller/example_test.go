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

package controller_test

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
	"strings"
	"testing"
	"time"

	"github.com/gke-labs/service-portals/pkg/client"
	"github.com/gke-labs/service-portals/pkg/controller"
	portalsv1 "github.com/gke-labs/service-portals/pkg/portals/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// BindAndReleaseSandbox demonstrates the recommended pattern for a sandbox controller
// configuring egress policy and credentials for a sandbox pod via the Service Portal Controller client.
//
// Flow:
//  1. Construct a client from the controller address, CA certificate, and projected token file.
//  2. Call Bind with the pod UID, egress policy, and companion secrets. Bind executes the complete
//     sequence synchronously and returns success only when the node agent accepts all configurations.
//  3. Release the sandbox only when Bind succeeds.
func BindAndReleaseSandbox(
	ctx context.Context,
	controllerAddr string,
	caCertPath string,
	tokenPath string,
	podUID string,
	policy *portalsv1.EgressPolicy,
	secrets map[string][]byte,
	releaseSandbox func(),
) error {
	c, err := client.New(client.Options{
		ControllerAddr: controllerAddr,
		CAFile:         caCertPath,
		TokenFile:      tokenPath,
	})
	if err != nil {
		return err
	}
	defer c.Close()

	if err := c.Bind(ctx, podUID, policy, secrets); err != nil {
		return err
	}

	if releaseSandbox != nil {
		releaseSandbox()
	}
	return nil
}

// ExamplePodBindServiceClient provides a compilable godoc example illustrating how
// a sandbox controller binds policy and secrets before releasing a sandbox pod.
func ExamplePodBindServiceClient() {
	// Example has no *testing.T in reach.
	ctx := context.Background()
	controllerAddr := "service-portal-controller.service-portal-system.svc:8443"
	caCertPath := "/etc/service-portal/ca/tls.crt"
	tokenPath := "/var/run/secrets/tokens/service-portal-token"
	podUID := "12345678-1234-1234-1234-123456789abc"

	// Define egress policy:
	// - HTTPS access to public APIs with no credentials (TLS is intercepted at the proxy).
	// - Swapping Authorization header from a named secret for GitHub API.
	policy := &portalsv1.EgressPolicy{
		Rules: []*portalsv1.EgressRule{
			{
				Https: &portalsv1.HttpsRule{
					Hostnames: []string{"api.anthropic.com", "crates.io"},
				},
			},
			{
				Https: &portalsv1.HttpsRule{
					Hostnames: []string{"api.github.com"},
					Effects: &portalsv1.HttpRuleEffects{
						ReplaceHeaders: []*portalsv1.CredentialHeader{
							{
								Header:        "Authorization",
								Prefix:        "Bearer ",
								CredentialUri: "secret://github-token",
							},
						},
					},
				},
			},
		},
	}

	secrets := map[string][]byte{
		"github-token": []byte("example-ephemeral-token-for-sandbox"),
	}

	releaseSandbox := func() {
		// Start or unpause the sandbox container.
	}

	_ = BindAndReleaseSandbox(ctx, controllerAddr, caCertPath, tokenPath, podUID, policy, secrets, releaseSandbox)
}

// fakeExampleCore simulates the controller core routing for testing BindAndReleaseSandbox.
type fakeExampleCore struct {
	podUID string
}

func (f *fakeExampleCore) Push(ctx context.Context, push *portalsv1.ControllerPush, wait bool) (*portalsv1.PushAnswer, error) {
	switch a := push.GetAction().(type) {
	case *portalsv1.ControllerPush_Policy:
		if a.Policy.GetPodUid() != f.podUID {
			return &portalsv1.PushAnswer{
				PushId:        push.GetPushId(),
				PodUid:        a.Policy.GetPodUid(),
				Status:        portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_REFUSED,
				RefusalReason: "pod not found on node",
			}, nil
		}
		// If policy has secret effects, it is pending until secrets arrive
		hasSecrets := false
		for _, r := range a.Policy.GetPolicy().GetRules() {
			if r.GetHttps() != nil && r.GetHttps().GetEffects() != nil && len(r.GetHttps().GetEffects().GetReplaceHeaders()) > 0 {
				hasSecrets = true
			}
		}
		if hasSecrets {
			return &portalsv1.PushAnswer{
				PushId:         push.GetPushId(),
				PodUid:         f.podUID,
				Status:         portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_PENDING,
				MissingSecrets: []string{"github-token"},
			}, nil
		}
		return &portalsv1.PushAnswer{
			PushId: push.GetPushId(),
			PodUid: f.podUID,
			Status: portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_ACCEPTED,
		}, nil

	case *portalsv1.ControllerPush_Secrets:
		if a.Secrets.GetPodUid() != f.podUID {
			return &portalsv1.PushAnswer{
				PushId:        push.GetPushId(),
				PodUid:        a.Secrets.GetPodUid(),
				Status:        portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_REFUSED,
				RefusalReason: "pod not found on node",
			}, nil
		}
		if _, ok := a.Secrets.GetSecrets()["github-token"]; !ok {
			return &portalsv1.PushAnswer{
				PushId:         push.GetPushId(),
				PodUid:         f.podUID,
				Status:         portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_PENDING,
				MissingSecrets: []string{"github-token"},
			}, nil
		}
		return &portalsv1.PushAnswer{
			PushId: push.GetPushId(),
			PodUid: f.podUID,
			Status: portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_ACCEPTED,
		}, nil
	}
	return nil, errors.New("unexpected push")
}

type fakeExampleTokenReviews struct {
	expectedToken string
	allowedSA     string
	audience      string
}

func (f *fakeExampleTokenReviews) Create(ctx context.Context, tr *authenticationv1.TokenReview, opts metav1.CreateOptions) (*authenticationv1.TokenReview, error) {
	if tr.Spec.Token == f.expectedToken {
		return &authenticationv1.TokenReview{
			Status: authenticationv1.TokenReviewStatus{
				Authenticated: true,
				Audiences:     []string{f.audience},
				User: authenticationv1.UserInfo{
					Username: f.allowedSA,
				},
			},
		}, nil
	}
	return &authenticationv1.TokenReview{
		Status: authenticationv1.TokenReviewStatus{
			Authenticated: false,
		},
	}, nil
}

func TestBindAndReleaseSandbox(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	// 1. Generate ephemeral self-signed TLS cert and key for localhost testing
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "tls.crt")
	keyPath := filepath.Join(tmpDir, "tls.key")
	tokenPath := filepath.Join(tmpDir, "token")

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	certFile, err := os.Create(certPath)
	if err != nil {
		t.Fatalf("creating cert file: %v", err)
	}
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatalf("encoding cert: %v", err)
	}
	certFile.Close()

	privDer, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	keyFile, err := os.Create(keyPath)
	if err != nil {
		t.Fatalf("creating key file: %v", err)
	}
	if err := pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privDer}); err != nil {
		t.Fatalf("encoding key: %v", err)
	}
	keyFile.Close()

	const (
		testAudience = "https://controller.service-portals"
		clientSA     = "system:serviceaccount:default:sandbox-controller"
		clientToken  = "valid-client-token"
		podUID       = "test-pod-uid-1234"
	)

	if err := os.WriteFile(tokenPath, []byte(clientToken), 0600); err != nil {
		t.Fatalf("writing token file: %v", err)
	}

	// 2. Start controller with TLS
	tlsCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadX509KeyPair: %v", err)
	}

	auth, err := controller.NewAuthenticator(controller.AuthenticatorConfig{
		Audience:        testAudience,
		ClientAllowlist: []string{clientSA},
		TokenReviews: &fakeExampleTokenReviews{
			expectedToken: clientToken,
			allowedSA:     clientSA,
			audience:      testAudience,
		},
	})
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}

	core := &fakeExampleCore{podUID: podUID}
	ctrl, err := controller.NewController(auth, core)
	if err != nil {
		t.Fatalf("NewController: %v", err)
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer lis.Close()

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS13,
	}
	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
	portalsv1.RegisterPodBindServiceServer(grpcServer, ctrl)

	go func() {
		_ = grpcServer.Serve(lis)
	}()
	defer grpcServer.Stop()

	// 3. Test successful Bind and InjectSecrets with acceptance
	policyWithSecrets := &portalsv1.EgressPolicy{
		Rules: []*portalsv1.EgressRule{
			{
				Https: &portalsv1.HttpsRule{
					Hostnames: []string{"api.github.com"},
					Effects: &portalsv1.HttpRuleEffects{
						ReplaceHeaders: []*portalsv1.CredentialHeader{
							{
								Header:        "Authorization",
								Prefix:        "Bearer ",
								CredentialUri: "secret://github-token",
							},
						},
					},
				},
			},
		},
	}
	secrets := map[string][]byte{
		"github-token": []byte("test-ephemeral-secret-token"),
	}

	released := false
	releaseFn := func() {
		released = true
	}

	err = BindAndReleaseSandbox(ctx, lis.Addr().String(), certPath, tokenPath, podUID, policyWithSecrets, secrets, releaseFn)
	if err != nil {
		t.Fatalf("BindAndReleaseSandbox failed: %v", err)
	}
	if !released {
		t.Fatal("expected sandbox to be released upon acceptance")
	}

	// 4. Test refusal for unknown pod UID
	err = BindAndReleaseSandbox(ctx, lis.Addr().String(), certPath, tokenPath, "unknown-pod", policyWithSecrets, secrets, releaseFn)
	if err == nil {
		t.Fatal("expected error for unknown pod, got nil")
	}
	if !strings.Contains(err.Error(), "refused") {
		t.Fatalf("expected refusal error, got: %v", err)
	}
}
