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
	"context"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"

	portalsv1 "github.com/gke-labs/service-portals/pkg/portals/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	authenticationv1 "k8s.io/api/authentication/v1"
	"k8s.io/klog/v2"
)

type fakeCore struct {
	mu     sync.Mutex
	pushes []*portalsv1.ControllerPush
	waits  []bool
	pushFn func(ctx context.Context, push *portalsv1.ControllerPush, wait bool) (*portalsv1.PushAnswer, error)
}

func (f *fakeCore) Push(ctx context.Context, push *portalsv1.ControllerPush, wait bool) (*portalsv1.PushAnswer, error) {
	f.mu.Lock()
	f.pushes = append(f.pushes, push)
	f.waits = append(f.waits, wait)
	fn := f.pushFn
	f.mu.Unlock()
	if fn != nil {
		return fn(ctx, push, wait)
	}
	return &portalsv1.PushAnswer{
		PodUid: podUIDFromPush(push),
		Status: portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_PENDING,
	}, nil
}

func (f *fakeCore) PushCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.pushes)
}

func (f *fakeCore) LastPush() (*portalsv1.ControllerPush, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.pushes) == 0 {
		return nil, false
	}
	return f.pushes[len(f.pushes)-1], f.waits[len(f.waits)-1]
}

func podUIDFromPush(p *portalsv1.ControllerPush) string {
	switch a := p.GetAction().(type) {
	case *portalsv1.ControllerPush_Policy:
		return a.Policy.GetPodUid()
	case *portalsv1.ControllerPush_Secrets:
		return a.Secrets.GetPodUid()
	case *portalsv1.ControllerPush_Unbind:
		return a.Unbind.GetPodUid()
	}
	return ""
}

type testEnv struct {
	core   *fakeCore
	auth   *Authenticator
	fakeTR *fakeTokenReviews
	client portalsv1.PodBindServiceClient
	stop   func()
}

func newTestEnv(t *testing.T) *testEnv {
	fakeTR := &fakeTokenReviews{
		reviewFn: func(ctx context.Context, tr *authenticationv1.TokenReview) (*authenticationv1.TokenReview, error) {
			sa := testClientSA
			if tr.Spec.Token == "unauthorized-token" {
				sa = otherClientSA
			}
			return &authenticationv1.TokenReview{
				Status: authenticationv1.TokenReviewStatus{
					Authenticated: true,
					Audiences:     []string{testAudience},
					User: authenticationv1.UserInfo{
						Username: sa,
					},
				},
			}, nil
		},
	}

	auth, err := NewAuthenticator(AuthenticatorConfig{
		Audience:        testAudience,
		ClientAllowlist: []string{testClientSA},
		TokenReviews:    fakeTR,
	})
	if err != nil {
		t.Fatalf("NewAuthenticator failed: %v", err)
	}

	core := &fakeCore{}
	ctrl, err := NewController(auth, core)
	if err != nil {
		t.Fatalf("NewController failed: %v", err)
	}

	lis := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	portalsv1.RegisterPodBindServiceServer(server, ctrl)

	go func() {
		_ = server.Serve(lis)
	}()

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, s string) (net.Conn, error) {
			return lis.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("failed to dial bufnet: %v", err)
	}

	client := portalsv1.NewPodBindServiceClient(conn)

	stop := func() {
		_ = conn.Close()
		server.Stop()
		_ = lis.Close()
	}

	return &testEnv{
		core:   core,
		auth:   auth,
		fakeTR: fakeTR,
		client: client,
		stop:   stop,
	}
}

func clientCtx(t *testing.T, token string) context.Context {
	return metadata.AppendToOutgoingContext(t.Context(), "authorization", "Bearer "+token)
}

func validTestPolicy() *portalsv1.EgressPolicy {
	return &portalsv1.EgressPolicy{
		Rules: []*portalsv1.EgressRule{
			{
				Https: &portalsv1.HttpsRule{
					Hostnames: []string{"api.example.com"},
					Ports: &portalsv1.Ports{
						Numbers: []int32{443},
					},
				},
			},
		},
	}
}

func TestNewController_NilValidation(t *testing.T) {
	fakeTR := &fakeTokenReviews{}
	auth, err := NewAuthenticator(AuthenticatorConfig{
		Audience:     testAudience,
		TokenReviews: fakeTR,
	})
	if err != nil {
		t.Fatalf("NewAuthenticator failed: %v", err)
	}
	core := &fakeCore{}

	if _, err := NewController(nil, core); err == nil {
		t.Error("NewController(nil, core) succeeded, want error")
	}
	if _, err := NewController(auth, nil); err == nil {
		t.Error("NewController(auth, nil) succeeded, want error")
	}
}

func TestController_Bind_WaitAccepted(t *testing.T) {
	env := newTestEnv(t)
	defer env.stop()

	env.core.pushFn = func(ctx context.Context, push *portalsv1.ControllerPush, wait bool) (*portalsv1.PushAnswer, error) {
		if !wait {
			t.Errorf("wait = false, want true")
		}
		return &portalsv1.PushAnswer{
			PodUid: push.GetPolicy().GetPodUid(),
			Status: portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_ACCEPTED,
		}, nil
	}

	resp, err := env.client.Bind(clientCtx(t, "allowed-token"), &portalsv1.PodPolicy{
		PodUid:   "pod-123",
		Identity: "user@example.com",
		Policy:   validTestPolicy(),
		Wait:     true,
	})
	if err != nil {
		t.Fatalf("Bind failed: %v", err)
	}
	if resp.GetPodUid() != "pod-123" {
		t.Errorf("pod_uid = %q, want %q", resp.GetPodUid(), "pod-123")
	}
	if resp.GetStatus() != portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_ACCEPTED {
		t.Errorf("status = %v, want ACCEPTANCE_STATUS_ACCEPTED", resp.GetStatus())
	}
	if !resp.GetBound() {
		t.Errorf("bound = false, want true")
	}
	if env.core.PushCount() != 1 {
		t.Errorf("push count = %d, want 1", env.core.PushCount())
	}
}

func TestController_Bind_WaitPending_MissingSecrets(t *testing.T) {
	env := newTestEnv(t)
	defer env.stop()

	wantMissing := []string{"github-token", "openai-api-key"}
	env.core.pushFn = func(ctx context.Context, push *portalsv1.ControllerPush, wait bool) (*portalsv1.PushAnswer, error) {
		if !wait {
			t.Errorf("wait = false, want true")
		}
		return &portalsv1.PushAnswer{
			PodUid:         push.GetPolicy().GetPodUid(),
			Status:         portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_PENDING,
			MissingSecrets: wantMissing,
		}, nil
	}

	resp, err := env.client.Bind(clientCtx(t, "allowed-token"), &portalsv1.PodPolicy{
		PodUid:   "pod-123",
		Identity: "user@example.com",
		Policy:   validTestPolicy(),
		Wait:     true,
	})
	if err != nil {
		t.Fatalf("Bind failed: %v", err)
	}
	if resp.GetPodUid() != "pod-123" {
		t.Errorf("pod_uid = %q, want %q", resp.GetPodUid(), "pod-123")
	}
	if resp.GetStatus() != portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_PENDING {
		t.Errorf("status = %v, want ACCEPTANCE_STATUS_PENDING", resp.GetStatus())
	}
	if !resp.GetBound() {
		t.Errorf("bound = false, want true")
	}
	if !slices.Equal(resp.GetMissingSecrets(), wantMissing) {
		t.Errorf("missing_secrets = %v, want %v", resp.GetMissingSecrets(), wantMissing)
	}
}

func TestController_InjectSecrets_WaitPending_MissingSecrets(t *testing.T) {
	env := newTestEnv(t)
	defer env.stop()

	wantMissing := []string{"openai-api-key"}
	env.core.pushFn = func(ctx context.Context, push *portalsv1.ControllerPush, wait bool) (*portalsv1.PushAnswer, error) {
		if !wait {
			t.Errorf("wait = false, want true")
		}
		return &portalsv1.PushAnswer{
			PodUid:         push.GetSecrets().GetPodUid(),
			Status:         portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_PENDING,
			MissingSecrets: wantMissing,
		}, nil
	}

	resp, err := env.client.InjectSecrets(clientCtx(t, "allowed-token"), &portalsv1.PodSecrets{
		PodUid:  "pod-123",
		Secrets: map[string][]byte{"github-token": []byte("token-value")},
		Wait:    true,
	})
	if err != nil {
		t.Fatalf("InjectSecrets failed: %v", err)
	}
	if resp.GetPodUid() != "pod-123" {
		t.Errorf("pod_uid = %q, want %q", resp.GetPodUid(), "pod-123")
	}
	if resp.GetStatus() != portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_PENDING {
		t.Errorf("status = %v, want ACCEPTANCE_STATUS_PENDING", resp.GetStatus())
	}
	if !slices.Equal(resp.GetMissingSecrets(), wantMissing) {
		t.Errorf("missing_secrets = %v, want %v", resp.GetMissingSecrets(), wantMissing)
	}
}

func TestController_Bind_NoWaitPending(t *testing.T) {
	env := newTestEnv(t)
	defer env.stop()

	env.core.pushFn = func(ctx context.Context, push *portalsv1.ControllerPush, wait bool) (*portalsv1.PushAnswer, error) {
		if wait {
			t.Errorf("wait = true, want false")
		}
		return &portalsv1.PushAnswer{
			PodUid: push.GetPolicy().GetPodUid(),
			Status: portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_PENDING,
		}, nil
	}

	resp, err := env.client.Bind(clientCtx(t, "allowed-token"), &portalsv1.PodPolicy{
		PodUid:   "pod-123",
		Identity: "user@example.com",
		Policy:   validTestPolicy(),
		Wait:     false,
	})
	if err != nil {
		t.Fatalf("Bind failed: %v", err)
	}
	if resp.GetPodUid() != "pod-123" {
		t.Errorf("pod_uid = %q, want %q", resp.GetPodUid(), "pod-123")
	}
	if resp.GetStatus() != portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_PENDING {
		t.Errorf("status = %v, want ACCEPTANCE_STATUS_PENDING", resp.GetStatus())
	}
	if resp.GetBound() {
		t.Errorf("bound = true, want false")
	}
	if env.core.PushCount() != 1 {
		t.Errorf("push count = %d, want 1", env.core.PushCount())
	}
	_, wait := env.core.LastPush()
	if wait {
		t.Errorf("core wait = true, want false")
	}
}

func TestController_Bind_Refused(t *testing.T) {
	env := newTestEnv(t)
	defer env.stop()

	const refusalReason = "conflicting policy already bound on node"
	env.core.pushFn = func(ctx context.Context, push *portalsv1.ControllerPush, wait bool) (*portalsv1.PushAnswer, error) {
		return &portalsv1.PushAnswer{
			PodUid:        push.GetPolicy().GetPodUid(),
			Status:        portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_REFUSED,
			RefusalReason: refusalReason,
		}, nil
	}

	resp, err := env.client.Bind(clientCtx(t, "allowed-token"), &portalsv1.PodPolicy{
		PodUid:   "pod-123",
		Identity: "user@example.com",
		Policy:   validTestPolicy(),
		Wait:     true,
	})
	if err != nil {
		t.Fatalf("Bind failed: %v", err)
	}
	if resp.GetStatus() != portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_REFUSED {
		t.Errorf("status = %v, want ACCEPTANCE_STATUS_REFUSED", resp.GetStatus())
	}
	if resp.GetRefusalReason() != refusalReason {
		t.Errorf("refusal_reason = %q, want %q", resp.GetRefusalReason(), refusalReason)
	}
	if resp.GetBound() {
		t.Errorf("bound = true, want false")
	}
}

func TestController_Bind_DeadlineExceeded(t *testing.T) {
	env := newTestEnv(t)
	defer env.stop()

	env.core.pushFn = func(ctx context.Context, push *portalsv1.ControllerPush, wait bool) (*portalsv1.PushAnswer, error) {
		return nil, context.DeadlineExceeded
	}

	_, err := env.client.Bind(clientCtx(t, "allowed-token"), &portalsv1.PodPolicy{
		PodUid: "pod-123",
		Policy: validTestPolicy(),
		Wait:   true,
	})
	if err == nil {
		t.Fatal("Bind succeeded, want DeadlineExceeded error")
	}
	if status.Code(err) != codes.DeadlineExceeded {
		t.Fatalf("code = %v, want DeadlineExceeded", status.Code(err))
	}
}

func TestController_UnlistedClientRefused(t *testing.T) {
	env := newTestEnv(t)
	defer env.stop()

	_, err := env.client.Bind(clientCtx(t, "unauthorized-token"), &portalsv1.PodPolicy{
		PodUid: "pod-123",
		Policy: validTestPolicy(),
		Wait:   true,
	})
	if err == nil {
		t.Fatal("Bind succeeded for unauthorized client, want error")
	}
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied", status.Code(err))
	}
	if env.core.PushCount() != 0 {
		t.Fatalf("push count = %d, want 0 (nothing pushed)", env.core.PushCount())
	}
}

func TestController_NoTokenUnauthenticated(t *testing.T) {
	env := newTestEnv(t)
	defer env.stop()

	_, err := env.client.Bind(t.Context(), &portalsv1.PodPolicy{
		PodUid: "pod-123",
		Policy: validTestPolicy(),
		Wait:   true,
	})
	if err == nil {
		t.Fatal("Bind succeeded with no token, want error")
	}
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code = %v, want Unauthenticated", status.Code(err))
	}
	if env.core.PushCount() != 0 {
		t.Fatalf("push count = %d, want 0 (nothing pushed)", env.core.PushCount())
	}
}

func TestController_Bind_InvalidPolicy(t *testing.T) {
	env := newTestEnv(t)
	defer env.stop()

	// 1. Empty pod UID
	_, err := env.client.Bind(clientCtx(t, "allowed-token"), &portalsv1.PodPolicy{
		PodUid: "",
		Policy: validTestPolicy(),
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("empty pod_uid code = %v, want InvalidArgument", status.Code(err))
	}
	if env.core.PushCount() != 0 {
		t.Fatalf("push count = %d, want 0", env.core.PushCount())
	}

	// 2. Nil policy
	_, err = env.client.Bind(clientCtx(t, "allowed-token"), &portalsv1.PodPolicy{
		PodUid: "pod-123",
		Policy: nil,
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("nil policy code = %v, want InvalidArgument", status.Code(err))
	}
	if env.core.PushCount() != 0 {
		t.Fatalf("push count = %d, want 0", env.core.PushCount())
	}

	// 3. Invalid rule (empty hostnames)
	invalidPolicy := &portalsv1.EgressPolicy{
		Rules: []*portalsv1.EgressRule{
			{
				Https: &portalsv1.HttpsRule{
					Hostnames: []string{},
				},
			},
		},
	}
	_, err = env.client.Bind(clientCtx(t, "allowed-token"), &portalsv1.PodPolicy{
		PodUid: "pod-123",
		Policy: invalidPolicy,
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("invalid policy code = %v, want InvalidArgument", status.Code(err))
	}
	if env.core.PushCount() != 0 {
		t.Fatalf("push count = %d, want 0", env.core.PushCount())
	}
}

func TestController_InjectSecrets_Routing(t *testing.T) {
	env := newTestEnv(t)
	defer env.stop()

	secrets := map[string][]byte{
		"token": []byte("test-secret-value"),
	}

	// 1. With wait -> returns accepted answer
	env.core.pushFn = func(ctx context.Context, push *portalsv1.ControllerPush, wait bool) (*portalsv1.PushAnswer, error) {
		if !wait {
			t.Errorf("wait = false, want true")
		}
		return &portalsv1.PushAnswer{
			PodUid: push.GetSecrets().GetPodUid(),
			Status: portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_ACCEPTED,
		}, nil
	}

	resp, err := env.client.InjectSecrets(clientCtx(t, "allowed-token"), &portalsv1.PodSecrets{
		PodUid:  "pod-123",
		Secrets: secrets,
		Wait:    true,
	})
	if err != nil {
		t.Fatalf("InjectSecrets failed: %v", err)
	}
	if resp.GetPodUid() != "pod-123" {
		t.Errorf("pod_uid = %q, want %q", resp.GetPodUid(), "pod-123")
	}
	if resp.GetStatus() != portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_ACCEPTED {
		t.Errorf("status = %v, want ACCEPTANCE_STATUS_ACCEPTED", resp.GetStatus())
	}

	// 2. Without wait -> returns pending immediately and push was submitted
	env.core.pushFn = func(ctx context.Context, push *portalsv1.ControllerPush, wait bool) (*portalsv1.PushAnswer, error) {
		if wait {
			t.Errorf("wait = true, want false")
		}
		return &portalsv1.PushAnswer{
			PodUid: push.GetSecrets().GetPodUid(),
			Status: portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_PENDING,
		}, nil
	}

	resp, err = env.client.InjectSecrets(clientCtx(t, "allowed-token"), &portalsv1.PodSecrets{
		PodUid:  "pod-123",
		Secrets: secrets,
		Wait:    false,
	})
	if err != nil {
		t.Fatalf("InjectSecrets without wait failed: %v", err)
	}
	if resp.GetStatus() != portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_PENDING {
		t.Errorf("status = %v, want ACCEPTANCE_STATUS_PENDING", resp.GetStatus())
	}
	_, lastWait := env.core.LastPush()
	if lastWait {
		t.Errorf("lastWait = true, want false")
	}

	// 3. Refusal from node
	const refusalReason = "secret rejected by node"
	env.core.pushFn = func(ctx context.Context, push *portalsv1.ControllerPush, wait bool) (*portalsv1.PushAnswer, error) {
		return &portalsv1.PushAnswer{
			PodUid:        push.GetSecrets().GetPodUid(),
			Status:        portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_REFUSED,
			RefusalReason: refusalReason,
		}, nil
	}
	resp, err = env.client.InjectSecrets(clientCtx(t, "allowed-token"), &portalsv1.PodSecrets{
		PodUid:  "pod-123",
		Secrets: secrets,
		Wait:    true,
	})
	if err != nil {
		t.Fatalf("InjectSecrets with refusal failed: %v", err)
	}
	if resp.GetStatus() != portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_REFUSED {
		t.Errorf("status = %v, want REFUSED", resp.GetStatus())
	}
	if resp.GetRefusalReason() != refusalReason {
		t.Errorf("refusal_reason = %q, want %q", resp.GetRefusalReason(), refusalReason)
	}

	// 4. Wait runs out -> DeadlineExceeded
	env.core.pushFn = func(ctx context.Context, push *portalsv1.ControllerPush, wait bool) (*portalsv1.PushAnswer, error) {
		return nil, context.DeadlineExceeded
	}
	_, err = env.client.InjectSecrets(clientCtx(t, "allowed-token"), &portalsv1.PodSecrets{
		PodUid:  "pod-123",
		Secrets: secrets,
		Wait:    true,
	})
	if status.Code(err) != codes.DeadlineExceeded {
		t.Fatalf("code = %v, want DeadlineExceeded", status.Code(err))
	}

	// 5. Unlisted caller -> refused, nothing pushed
	pushCountBefore := env.core.PushCount()
	_, err = env.client.InjectSecrets(clientCtx(t, "unauthorized-token"), &portalsv1.PodSecrets{
		PodUid:  "pod-123",
		Secrets: secrets,
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied", status.Code(err))
	}
	if env.core.PushCount() != pushCountBefore {
		t.Errorf("push count increased on unauthorized call")
	}

	// 6. Empty pod UID -> InvalidArgument, nothing pushed
	pushCountBefore = env.core.PushCount()
	_, err = env.client.InjectSecrets(clientCtx(t, "allowed-token"), &portalsv1.PodSecrets{
		PodUid:  "",
		Secrets: secrets,
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", status.Code(err))
	}
	if env.core.PushCount() != pushCountBefore {
		t.Errorf("push count increased on invalid argument")
	}
}

func TestController_Unbind_Routing(t *testing.T) {
	env := newTestEnv(t)
	defer env.stop()

	// 1. With wait -> returns accepted answer
	env.core.pushFn = func(ctx context.Context, push *portalsv1.ControllerPush, wait bool) (*portalsv1.PushAnswer, error) {
		if !wait {
			t.Errorf("wait = false, want true")
		}
		return &portalsv1.PushAnswer{
			PodUid: push.GetUnbind().GetPodUid(),
			Status: portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_ACCEPTED,
		}, nil
	}

	resp, err := env.client.Unbind(clientCtx(t, "allowed-token"), &portalsv1.UnbindRequest{
		PodUid: "pod-123",
		Wait:   true,
	})
	if err != nil {
		t.Fatalf("Unbind failed: %v", err)
	}
	if resp.GetPodUid() != "pod-123" {
		t.Errorf("pod_uid = %q, want %q", resp.GetPodUid(), "pod-123")
	}
	if resp.GetStatus() != portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_ACCEPTED {
		t.Errorf("status = %v, want ACCEPTANCE_STATUS_ACCEPTED", resp.GetStatus())
	}
	if resp.GetBound() {
		t.Errorf("bound = true, want false")
	}

	// 2. Without wait -> returns pending immediately and push was submitted
	env.core.pushFn = func(ctx context.Context, push *portalsv1.ControllerPush, wait bool) (*portalsv1.PushAnswer, error) {
		if wait {
			t.Errorf("wait = true, want false")
		}
		return &portalsv1.PushAnswer{
			PodUid: push.GetUnbind().GetPodUid(),
			Status: portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_PENDING,
		}, nil
	}

	resp, err = env.client.Unbind(clientCtx(t, "allowed-token"), &portalsv1.UnbindRequest{
		PodUid: "pod-123",
		Wait:   false,
	})
	if err != nil {
		t.Fatalf("Unbind without wait failed: %v", err)
	}
	if resp.GetStatus() != portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_PENDING {
		t.Errorf("status = %v, want ACCEPTANCE_STATUS_PENDING", resp.GetStatus())
	}
	_, lastWait := env.core.LastPush()
	if lastWait {
		t.Errorf("lastWait = true, want false")
	}

	// 3. Refusal from node
	const refusalReason = "unbind refused by node"
	env.core.pushFn = func(ctx context.Context, push *portalsv1.ControllerPush, wait bool) (*portalsv1.PushAnswer, error) {
		return &portalsv1.PushAnswer{
			PodUid:        push.GetUnbind().GetPodUid(),
			Status:        portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_REFUSED,
			RefusalReason: refusalReason,
		}, nil
	}
	resp, err = env.client.Unbind(clientCtx(t, "allowed-token"), &portalsv1.UnbindRequest{
		PodUid: "pod-123",
		Wait:   true,
	})
	if err != nil {
		t.Fatalf("Unbind with refusal failed: %v", err)
	}
	if resp.GetStatus() != portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_REFUSED {
		t.Errorf("status = %v, want REFUSED", resp.GetStatus())
	}
	if resp.GetRefusalReason() != refusalReason {
		t.Errorf("refusal_reason = %q, want %q", resp.GetRefusalReason(), refusalReason)
	}

	// 4. Wait runs out -> DeadlineExceeded
	env.core.pushFn = func(ctx context.Context, push *portalsv1.ControllerPush, wait bool) (*portalsv1.PushAnswer, error) {
		return nil, context.DeadlineExceeded
	}
	_, err = env.client.Unbind(clientCtx(t, "allowed-token"), &portalsv1.UnbindRequest{
		PodUid: "pod-123",
		Wait:   true,
	})
	if status.Code(err) != codes.DeadlineExceeded {
		t.Fatalf("code = %v, want DeadlineExceeded", status.Code(err))
	}

	// 5. Unlisted caller -> refused, nothing pushed
	pushCountBefore := env.core.PushCount()
	_, err = env.client.Unbind(clientCtx(t, "unauthorized-token"), &portalsv1.UnbindRequest{
		PodUid: "pod-123",
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied", status.Code(err))
	}
	if env.core.PushCount() != pushCountBefore {
		t.Errorf("push count increased on unauthorized call")
	}

	// 6. Empty pod UID -> InvalidArgument, nothing pushed
	pushCountBefore = env.core.PushCount()
	_, err = env.client.Unbind(clientCtx(t, "allowed-token"), &portalsv1.UnbindRequest{
		PodUid: "",
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", status.Code(err))
	}
	if env.core.PushCount() != pushCountBefore {
		t.Errorf("push count increased on invalid argument")
	}
}

func TestController_Get_Unimplemented(t *testing.T) {
	env := newTestEnv(t)
	defer env.stop()

	// 1. Allowlisted client -> Unimplemented
	_, err := env.client.Get(clientCtx(t, "allowed-token"), &portalsv1.GetRequest{
		PodUid: "pod-123",
	})
	if err == nil {
		t.Fatal("Get succeeded, want Unimplemented")
	}
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("code = %v, want Unimplemented", status.Code(err))
	}
	if !strings.Contains(status.Convert(err).Message(), "state lives on the node") {
		t.Errorf("message = %q, want message explaining state lives on the node", status.Convert(err).Message())
	}

	// 2. Unlisted client -> PermissionDenied
	_, err = env.client.Get(clientCtx(t, "unauthorized-token"), &portalsv1.GetRequest{
		PodUid: "pod-123",
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("unlisted code = %v, want PermissionDenied", status.Code(err))
	}

	// 3. No token -> Unauthenticated
	_, err = env.client.Get(t.Context(), &portalsv1.GetRequest{
		PodUid: "pod-123",
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("no token code = %v, want Unauthenticated", status.Code(err))
	}
}

func TestController_NoSecretsInLogs(t *testing.T) {
	logBuf := &syncBuffer{}
	klog.LogToStderr(false)
	klog.SetOutput(logBuf)
	defer func() {
		klog.LogToStderr(true)
	}()

	env := newTestEnv(t)
	defer env.stop()

	const secretValue = "super-secret-credential-value-xyz987"
	const podUID = "pod-secret-test"

	env.core.pushFn = func(ctx context.Context, push *portalsv1.ControllerPush, wait bool) (*portalsv1.PushAnswer, error) {
		return &portalsv1.PushAnswer{
			PodUid: push.GetSecrets().GetPodUid(),
			Status: portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_ACCEPTED,
		}, nil
	}

	_, err := env.client.InjectSecrets(clientCtx(t, "allowed-token"), &portalsv1.PodSecrets{
		PodUid: podUID,
		Secrets: map[string][]byte{
			"api_token": []byte(secretValue),
		},
		Wait: true,
	})
	if err != nil {
		t.Fatalf("InjectSecrets failed: %v", err)
	}

	klog.Flush()
	logs := logBuf.String()

	// Assert secret is NEVER in logs
	if strings.Contains(logs, secretValue) {
		t.Fatalf("logs contain secret value! logs: %s", logs)
	}

	// Assert caller, method, pod UID, and outcome are logged
	if !strings.Contains(logs, testClientSA) {
		t.Errorf("logs do not contain caller %q. logs: %s", testClientSA, logs)
	}
	if !strings.Contains(logs, "InjectSecrets") {
		t.Errorf("logs do not contain method InjectSecrets. logs: %s", logs)
	}
	if !strings.Contains(logs, podUID) {
		t.Errorf("logs do not contain pod UID %q. logs: %s", podUID, logs)
	}
	if !strings.Contains(logs, "accepted") {
		t.Errorf("logs do not contain outcome 'accepted'. logs: %s", logs)
	}
}

func TestController_Concurrency(t *testing.T) {
	env := newTestEnv(t)
	defer env.stop()

	env.core.pushFn = func(ctx context.Context, push *portalsv1.ControllerPush, wait bool) (*portalsv1.PushAnswer, error) {
		return &portalsv1.PushAnswer{
			PodUid: podUIDFromPush(push),
			Status: portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_ACCEPTED,
		}, nil
	}

	var wg sync.WaitGroup
	for i := 0; i < 30; i++ {
		wg.Add(3)
		go func(id int) {
			defer wg.Done()
			_, _ = env.client.Bind(clientCtx(t, "allowed-token"), &portalsv1.PodPolicy{
				PodUid: "concurrent-pod",
				Policy: validTestPolicy(),
				Wait:   true,
			})
		}(i)
		go func(id int) {
			defer wg.Done()
			_, _ = env.client.InjectSecrets(clientCtx(t, "allowed-token"), &portalsv1.PodSecrets{
				PodUid:  "concurrent-pod",
				Secrets: map[string][]byte{"k": []byte("v")},
				Wait:    false,
			})
		}(i)
		go func(id int) {
			defer wg.Done()
			_, _ = env.client.Unbind(clientCtx(t, "allowed-token"), &portalsv1.UnbindRequest{
				PodUid: "concurrent-pod",
				Wait:   true,
			})
		}(i)
	}
	wg.Wait()
}
