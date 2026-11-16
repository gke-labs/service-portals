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

package controller

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	portalsv1 "github.com/gke-labs/service-portals/pkg/portals/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"
)

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (n int, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type fakeTokenReviews struct {
	mu       sync.Mutex
	reviewFn func(ctx context.Context, tr *authenticationv1.TokenReview) (*authenticationv1.TokenReview, error)
	calls    int
}

func (f *fakeTokenReviews) Create(ctx context.Context, tr *authenticationv1.TokenReview, opts metav1.CreateOptions) (*authenticationv1.TokenReview, error) {
	f.mu.Lock()
	f.calls++
	fn := f.reviewFn
	f.mu.Unlock()
	if fn != nil {
		return fn(ctx, tr)
	}
	return nil, errors.New("unimplemented")
}

func (f *fakeTokenReviews) CallCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func makeJWT(exp time.Time) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payloadBytes, _ := json.Marshal(map[string]any{
		"exp": exp.Unix(),
		"sub": "system:serviceaccount:default:test",
	})
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	return fmt.Sprintf("%s.%s.signature", header, payload)
}

func incomingCtx(token string) context.Context {
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+token))
}

const (
	testAudience   = "https://controller.service-portals"
	testNodeAgent  = "system:serviceaccount:service-portals:portal-node-agent"
	testClientSA   = "system:serviceaccount:default:sandbox-controller"
	otherClientSA  = "system:serviceaccount:default:unauthorized-client"
	otherNodeAgent = "system:serviceaccount:service-portals:other-agent"
)

func TestNodeAgentToken_Success(t *testing.T) {
	fake := &fakeTokenReviews{
		reviewFn: func(ctx context.Context, tr *authenticationv1.TokenReview) (*authenticationv1.TokenReview, error) {
			return &authenticationv1.TokenReview{
				Status: authenticationv1.TokenReviewStatus{
					Authenticated: true,
					Audiences:     []string{testAudience},
					User: authenticationv1.UserInfo{
						Username: testNodeAgent,
						Extra: map[string]authenticationv1.ExtraValue{
							extraNodeName: []string{"node-test-1"},
						},
					},
				},
			}, nil
		},
	}

	auth, err := NewAuthenticator(AuthenticatorConfig{
		Audience:         testAudience,
		NodeAgentAccount: testNodeAgent,
		TokenReviews:     fake,
	})
	if err != nil {
		t.Fatalf("NewAuthenticator failed: %v", err)
	}

	ctx := incomingCtx("valid-node-token")
	nodeName, expiresAt, err := auth.AuthorizeNodeAgent(ctx)
	if err != nil {
		t.Fatalf("AuthorizeNodeAgent failed: %v", err)
	}
	if nodeName != "node-test-1" {
		t.Fatalf("nodeName = %q, want %q", nodeName, "node-test-1")
	}
	if expiresAt.IsZero() {
		t.Fatal("expiresAt is zero, want non-zero expiration")
	}
}

func TestNodeAgentToken_ReturnedExpiry(t *testing.T) {
	fake := &fakeTokenReviews{
		reviewFn: func(ctx context.Context, tr *authenticationv1.TokenReview) (*authenticationv1.TokenReview, error) {
			return &authenticationv1.TokenReview{
				Status: authenticationv1.TokenReviewStatus{
					Authenticated: true,
					Audiences:     []string{testAudience},
					User: authenticationv1.UserInfo{
						Username: testNodeAgent,
						Extra: map[string]authenticationv1.ExtraValue{
							extraNodeName: []string{"node-test-1"},
						},
					},
				},
			}, nil
		},
	}

	startTime := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	auth, err := NewAuthenticator(AuthenticatorConfig{
		Audience:         testAudience,
		NodeAgentAccount: testNodeAgent,
		TokenReviews:     fake,
		CacheTTL:         10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("NewAuthenticator failed: %v", err)
	}
	auth.now = func() time.Time { return startTime }

	// 1. Token that outlives CacheTTL (expires in 1 hour; CacheTTL is 10 minutes):
	// returns the token's own expiry so streams are not prematurely cut.
	tokenExpLong := startTime.Add(1 * time.Hour)
	jwtTokenLong := makeJWT(tokenExpLong)

	nodeName, exp, err := auth.AuthorizeNodeAgent(incomingCtx(jwtTokenLong))
	if err != nil {
		t.Fatalf("AuthorizeNodeAgent failed: %v", err)
	}
	if nodeName != "node-test-1" {
		t.Fatalf("nodeName = %q, want %q", nodeName, "node-test-1")
	}
	if !exp.Equal(tokenExpLong) {
		t.Fatalf("exp = %v, want token expiration %v", exp, tokenExpLong)
	}

	// 2. Token that expires earlier than CacheTTL (in 3 minutes):
	// returns the token's own expiry.
	tokenExpShort := startTime.Add(3 * time.Minute)
	jwtTokenShort := makeJWT(tokenExpShort)

	nodeNameShort, expShort, err := auth.AuthorizeNodeAgent(incomingCtx(jwtTokenShort))
	if err != nil {
		t.Fatalf("AuthorizeNodeAgent failed: %v", err)
	}
	if nodeNameShort != "node-test-1" {
		t.Fatalf("nodeName = %q, want %q", nodeNameShort, "node-test-1")
	}
	if !expShort.Equal(tokenExpShort) {
		t.Fatalf("expShort = %v, want token expiration %v", expShort, tokenExpShort)
	}

	// 3. Token without readable exp claim: falls back to now + CacheTTL.
	nodeNameFallback, expFallback, err := auth.AuthorizeNodeAgent(incomingCtx("raw-token-without-exp"))
	if err != nil {
		t.Fatalf("AuthorizeNodeAgent failed: %v", err)
	}
	if nodeNameFallback != "node-test-1" {
		t.Fatalf("nodeName = %q, want %q", nodeNameFallback, "node-test-1")
	}
	wantFallbackExp := startTime.Add(10 * time.Minute)
	if !expFallback.Equal(wantFallbackExp) {
		t.Fatalf("expFallback = %v, want cache expiration %v", expFallback, wantFallbackExp)
	}
}

func TestNodeAgentToken_NoNodeNameRefused(t *testing.T) {
	fake := &fakeTokenReviews{
		reviewFn: func(ctx context.Context, tr *authenticationv1.TokenReview) (*authenticationv1.TokenReview, error) {
			return &authenticationv1.TokenReview{
				Status: authenticationv1.TokenReviewStatus{
					Authenticated: true,
					Audiences:     []string{testAudience},
					User: authenticationv1.UserInfo{
						Username: testNodeAgent,
					},
				},
			}, nil
		},
	}

	auth, err := NewAuthenticator(AuthenticatorConfig{
		Audience:         testAudience,
		NodeAgentAccount: testNodeAgent,
		TokenReviews:     fake,
	})
	if err != nil {
		t.Fatalf("NewAuthenticator failed: %v", err)
	}

	ctx := incomingCtx("token-without-node")
	_, _, err = auth.AuthorizeNodeAgent(ctx)
	if err == nil {
		t.Fatal("AuthorizeNodeAgent succeeded, want refusal")
	}
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied", status.Code(err))
	}
}

func TestNodeAgentToken_WrongAccountRefused(t *testing.T) {
	fake := &fakeTokenReviews{
		reviewFn: func(ctx context.Context, tr *authenticationv1.TokenReview) (*authenticationv1.TokenReview, error) {
			return &authenticationv1.TokenReview{
				Status: authenticationv1.TokenReviewStatus{
					Authenticated: true,
					Audiences:     []string{testAudience},
					User: authenticationv1.UserInfo{
						Username: otherNodeAgent,
						Extra: map[string]authenticationv1.ExtraValue{
							extraNodeName: []string{"node-test-1"},
						},
					},
				},
			}, nil
		},
	}

	auth, err := NewAuthenticator(AuthenticatorConfig{
		Audience:         testAudience,
		NodeAgentAccount: testNodeAgent,
		TokenReviews:     fake,
	})
	if err != nil {
		t.Fatalf("NewAuthenticator failed: %v", err)
	}

	ctx := incomingCtx("wrong-account-token")
	_, _, err = auth.AuthorizeNodeAgent(ctx)
	if err == nil {
		t.Fatal("AuthorizeNodeAgent succeeded, want refusal")
	}
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied", status.Code(err))
	}
}

func TestWrongAudienceRefused(t *testing.T) {
	fake := &fakeTokenReviews{
		reviewFn: func(ctx context.Context, tr *authenticationv1.TokenReview) (*authenticationv1.TokenReview, error) {
			return &authenticationv1.TokenReview{
				Status: authenticationv1.TokenReviewStatus{
					Authenticated: true,
					Audiences:     []string{"https://kubernetes.default.svc"},
					User: authenticationv1.UserInfo{
						Username: testNodeAgent,
						Extra: map[string]authenticationv1.ExtraValue{
							extraNodeName: []string{"node-test-1"},
						},
					},
				},
			}, nil
		},
	}

	auth, err := NewAuthenticator(AuthenticatorConfig{
		Audience:         testAudience,
		NodeAgentAccount: testNodeAgent,
		TokenReviews:     fake,
	})
	if err != nil {
		t.Fatalf("NewAuthenticator failed: %v", err)
	}

	ctx := incomingCtx("wrong-audience-token")
	_, _, err = auth.AuthorizeNodeAgent(ctx)
	if err == nil {
		t.Fatal("AuthorizeNodeAgent succeeded, want refusal")
	}
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code = %v, want Unauthenticated", status.Code(err))
	}
}

func TestClientAllowlist_AcceptedAndRefused(t *testing.T) {
	fake := &fakeTokenReviews{
		reviewFn: func(ctx context.Context, tr *authenticationv1.TokenReview) (*authenticationv1.TokenReview, error) {
			username := testClientSA
			if tr.Spec.Token == "unauthorized-token" {
				username = otherClientSA
			}
			return &authenticationv1.TokenReview{
				Status: authenticationv1.TokenReviewStatus{
					Authenticated: true,
					Audiences:     []string{testAudience},
					User: authenticationv1.UserInfo{
						Username: username,
					},
				},
			}, nil
		},
	}

	auth, err := NewAuthenticator(AuthenticatorConfig{
		Audience:        testAudience,
		ClientAllowlist: []string{testClientSA},
		TokenReviews:    fake,
	})
	if err != nil {
		t.Fatalf("NewAuthenticator failed: %v", err)
	}

	// 1. Allowlisted client is accepted
	ctxAllowed := incomingCtx("allowed-token")
	sa, err := auth.AuthorizeClient(ctxAllowed)
	if err != nil {
		t.Fatalf("AuthorizeClient failed: %v", err)
	}
	if sa != testClientSA {
		t.Fatalf("sa = %q, want %q", sa, testClientSA)
	}

	// 2. Client not on allowlist is refused with PermissionDenied
	ctxDenied := incomingCtx("unauthorized-token")
	_, err = auth.AuthorizeClient(ctxDenied)
	if err == nil {
		t.Fatal("AuthorizeClient succeeded for unauthorized client, want refusal")
	}
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied", status.Code(err))
	}
}

func TestNoToken_Unauthenticated(t *testing.T) {
	fake := &fakeTokenReviews{}
	auth, err := NewAuthenticator(AuthenticatorConfig{
		Audience:         testAudience,
		NodeAgentAccount: testNodeAgent,
		ClientAllowlist:  []string{testClientSA},
		TokenReviews:     fake,
	})
	if err != nil {
		t.Fatalf("NewAuthenticator failed: %v", err)
	}

	// Context with no metadata
	ctx := context.Background()

	if _, _, err := auth.AuthorizeNodeAgent(ctx); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("AuthorizeNodeAgent code = %v, want Unauthenticated", status.Code(err))
	}

	if _, err := auth.AuthorizeClient(ctx); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("AuthorizeClient code = %v, want Unauthenticated", status.Code(err))
	}

	if _, err := auth.Authenticate(ctx); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("Authenticate code = %v, want Unauthenticated", status.Code(err))
	}
}

func TestEmptyAllowlistRefusesEveryone(t *testing.T) {
	fake := &fakeTokenReviews{
		reviewFn: func(ctx context.Context, tr *authenticationv1.TokenReview) (*authenticationv1.TokenReview, error) {
			return &authenticationv1.TokenReview{
				Status: authenticationv1.TokenReviewStatus{
					Authenticated: true,
					Audiences:     []string{testAudience},
					User: authenticationv1.UserInfo{
						Username: testClientSA,
					},
				},
			}, nil
		},
	}

	auth, err := NewAuthenticator(AuthenticatorConfig{
		Audience:        testAudience,
		ClientAllowlist: []string{},
		TokenReviews:    fake,
	})
	if err != nil {
		t.Fatalf("NewAuthenticator failed: %v", err)
	}

	ctx := incomingCtx("any-valid-token")
	_, err = auth.AuthorizeClient(ctx)
	if err == nil {
		t.Fatal("AuthorizeClient succeeded with empty allowlist, want refusal")
	}
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied", status.Code(err))
	}
}

func TestTokenReviewError_Refuses(t *testing.T) {
	// API call error
	fakeErr := &fakeTokenReviews{
		reviewFn: func(ctx context.Context, tr *authenticationv1.TokenReview) (*authenticationv1.TokenReview, error) {
			return nil, errors.New("apiserver unreachable")
		},
	}

	auth1, err := NewAuthenticator(AuthenticatorConfig{
		Audience:         testAudience,
		NodeAgentAccount: testNodeAgent,
		TokenReviews:     fakeErr,
	})
	if err != nil {
		t.Fatalf("NewAuthenticator failed: %v", err)
	}

	ctx := incomingCtx("test-token")
	_, _, err = auth1.AuthorizeNodeAgent(ctx)
	if err == nil {
		t.Fatal("AuthorizeNodeAgent succeeded on API error, want refusal")
	}
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code = %v, want Unauthenticated", status.Code(err))
	}
	if msg := status.Convert(err).Message(); msg != "unauthenticated" {
		t.Fatalf("expected fixed error message 'unauthenticated', got %q", msg)
	}

	// Status.Error in review
	fakeStatusErr := &fakeTokenReviews{
		reviewFn: func(ctx context.Context, tr *authenticationv1.TokenReview) (*authenticationv1.TokenReview, error) {
			return &authenticationv1.TokenReview{
				Status: authenticationv1.TokenReviewStatus{
					Error: "token expired",
				},
			}, nil
		},
	}

	auth2, err := NewAuthenticator(AuthenticatorConfig{
		Audience:         testAudience,
		NodeAgentAccount: testNodeAgent,
		TokenReviews:     fakeStatusErr,
	})
	if err != nil {
		t.Fatalf("NewAuthenticator failed: %v", err)
	}

	_, _, err = auth2.AuthorizeNodeAgent(ctx)
	if err == nil {
		t.Fatal("AuthorizeNodeAgent succeeded on review status error, want refusal")
	}
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code = %v, want Unauthenticated", status.Code(err))
	}
	if msg := status.Convert(err).Message(); msg != "unauthenticated" {
		t.Fatalf("expected fixed error message 'unauthenticated', got %q", msg)
	}
}

func TestNoTokenInLogs(t *testing.T) {
	logBuf := &syncBuffer{}
	klog.LogToStderr(false)
	klog.SetOutput(logBuf)
	defer func() {
		klog.LogToStderr(true)
	}()

	secretToken := "secret-jwt-token-abcdef123456"

	fake := &fakeTokenReviews{
		reviewFn: func(ctx context.Context, tr *authenticationv1.TokenReview) (*authenticationv1.TokenReview, error) {
			return &authenticationv1.TokenReview{
				Status: authenticationv1.TokenReviewStatus{
					Authenticated: true,
					Audiences:     []string{"wrong-audience"},
					User: authenticationv1.UserInfo{
						Username: otherClientSA,
					},
				},
			}, nil
		},
	}

	auth, err := NewAuthenticator(AuthenticatorConfig{
		Audience:        testAudience,
		ClientAllowlist: []string{testClientSA},
		TokenReviews:    fake,
	})
	if err != nil {
		t.Fatalf("NewAuthenticator failed: %v", err)
	}

	ctx := incomingCtx(secretToken)
	_, _ = auth.AuthorizeClient(ctx)

	// Also trigger missing token refusal
	_, _ = auth.AuthorizeClient(context.Background())

	klog.Flush()
	logs := logBuf.String()

	if strings.Contains(logs, secretToken) {
		t.Fatalf("log contains secret token! Log output: %s", logs)
	}

	// Refusal must log the service account where known
	if !strings.Contains(logs, otherClientSA) {
		t.Errorf("log does not contain known service account %q. Log output: %s", otherClientSA, logs)
	}
}

func TestCache_ExpiresNoLaterThanToken(t *testing.T) {
	fake := &fakeTokenReviews{
		reviewFn: func(ctx context.Context, tr *authenticationv1.TokenReview) (*authenticationv1.TokenReview, error) {
			return &authenticationv1.TokenReview{
				Status: authenticationv1.TokenReviewStatus{
					Authenticated: true,
					Audiences:     []string{testAudience},
					User: authenticationv1.UserInfo{
						Username: testClientSA,
					},
				},
			}, nil
		},
	}

	currentTime := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	timeMu := sync.Mutex{}
	nowFn := func() time.Time {
		timeMu.Lock()
		defer timeMu.Unlock()
		return currentTime
	}

	// Token expires in 10 minutes.
	tokenExp := currentTime.Add(10 * time.Minute)
	tokenWithExp := makeJWT(tokenExp)

	auth, err := NewAuthenticator(AuthenticatorConfig{
		Audience:        testAudience,
		ClientAllowlist: []string{testClientSA},
		TokenReviews:    fake,
		CacheTTL:        1 * time.Hour, // CacheTTL is longer than token expiration
	})
	if err != nil {
		t.Fatalf("NewAuthenticator failed: %v", err)
	}
	auth.now = nowFn

	ctx := incomingCtx(tokenWithExp)

	// Call 1: makes API call
	if _, err := auth.AuthorizeClient(ctx); err != nil {
		t.Fatalf("call 1 failed: %v", err)
	}
	if calls := fake.CallCount(); calls != 1 {
		t.Fatalf("expected 1 call, got %d", calls)
	}

	// Call 2: after 5 minutes (before token expiration), served from cache
	timeMu.Lock()
	currentTime = currentTime.Add(5 * time.Minute)
	timeMu.Unlock()

	if _, err := auth.AuthorizeClient(ctx); err != nil {
		t.Fatalf("call 2 failed: %v", err)
	}
	if calls := fake.CallCount(); calls != 1 {
		t.Fatalf("expected call to be cached, got %d calls", calls)
	}

	// Advance time past token expiration (11 minutes from start)
	timeMu.Lock()
	currentTime = currentTime.Add(6 * time.Minute)
	timeMu.Unlock()

	// Call 3: token expired, cache expired, makes new API call
	if _, err := auth.AuthorizeClient(ctx); err != nil {
		t.Fatalf("call 3 failed: %v", err)
	}
	if calls := fake.CallCount(); calls != 2 {
		t.Fatalf("expected cache to expire with token, got %d calls", calls)
	}
}

func TestConcurrency_Race(t *testing.T) {
	fake := &fakeTokenReviews{
		reviewFn: func(ctx context.Context, tr *authenticationv1.TokenReview) (*authenticationv1.TokenReview, error) {
			isNode := strings.Contains(tr.Spec.Token, "node")
			username := testClientSA
			extra := map[string]authenticationv1.ExtraValue{}
			if isNode {
				username = testNodeAgent
				extra[extraNodeName] = []string{"test-node"}
			}
			return &authenticationv1.TokenReview{
				Status: authenticationv1.TokenReviewStatus{
					Authenticated: true,
					Audiences:     []string{testAudience},
					User: authenticationv1.UserInfo{
						Username: username,
						Extra:    extra,
					},
				},
			}, nil
		},
	}

	auth, err := NewAuthenticator(AuthenticatorConfig{
		Audience:         testAudience,
		NodeAgentAccount: testNodeAgent,
		ClientAllowlist:  []string{testClientSA},
		TokenReviews:     fake,
		CacheTTL:         100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewAuthenticator failed: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			var token string
			if id%2 == 0 {
				token = fmt.Sprintf("node-token-%d", id%5)
				ctx := incomingCtx(token)
				_, _, _ = auth.AuthorizeNodeAgent(ctx)
			} else {
				token = fmt.Sprintf("client-token-%d", id%5)
				ctx := incomingCtx(token)
				_, _ = auth.AuthorizeClient(ctx)
			}
		}(i)
	}
	wg.Wait()
}

type fakeBindServer struct {
	portalsv1.UnimplementedPodBindServiceServer
}

func (s *fakeBindServer) Bind(ctx context.Context, in *portalsv1.PodPolicy) (*portalsv1.BindResponse, error) {
	return &portalsv1.BindResponse{}, nil
}

func TestGRPCIntegration_MethodLogged(t *testing.T) {
	logBuf := &syncBuffer{}
	klog.LogToStderr(false)
	klog.SetOutput(logBuf)
	defer func() {
		klog.LogToStderr(true)
	}()

	fake := &fakeTokenReviews{
		reviewFn: func(ctx context.Context, tr *authenticationv1.TokenReview) (*authenticationv1.TokenReview, error) {
			return &authenticationv1.TokenReview{
				Status: authenticationv1.TokenReviewStatus{
					Authenticated: true,
					Audiences:     []string{testAudience},
					User: authenticationv1.UserInfo{
						Username: otherClientSA,
					},
				},
			}, nil
		},
	}

	auth, err := NewAuthenticator(AuthenticatorConfig{
		Audience:        testAudience,
		ClientAllowlist: []string{testClientSA},
		TokenReviews:    fake,
	})
	if err != nil {
		t.Fatalf("NewAuthenticator failed: %v", err)
	}

	lis := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer(
		grpc.UnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
			if _, err := auth.AuthorizeClient(ctx); err != nil {
				return nil, err
			}
			return handler(ctx, req)
		}),
	)

	portalsv1.RegisterPodBindServiceServer(server, &fakeBindServer{})

	go func() {
		_ = server.Serve(lis)
	}()
	defer server.Stop()

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, s string) (net.Conn, error) {
			return lis.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("failed to dial bufnet: %v", err)
	}
	defer conn.Close()

	client := portalsv1.NewPodBindServiceClient(conn)
	ctx := metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer client-token")
	_, err = client.Bind(ctx, &portalsv1.PodPolicy{PodUid: "test-pod-uid"})
	if err == nil {
		t.Fatal("expected invoke to fail, but succeeded")
	}
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied", status.Code(err))
	}

	klog.Flush()
	logs := logBuf.String()
	const expectedMethod = "/portals.v1.PodBindService/Bind"
	if !strings.Contains(logs, expectedMethod) {
		t.Errorf("expected log to contain method %q, got: %s", expectedMethod, logs)
	}
	if !strings.Contains(logs, otherClientSA) {
		t.Errorf("expected log to contain service account %q, got: %s", otherClientSA, logs)
	}
}
