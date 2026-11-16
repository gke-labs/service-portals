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
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	portalsv1 "github.com/gke-labs/service-portals/pkg/portals/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

func TestServePodBindService_Lifecycle(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "bind.sock")
	store, err := portalsv1.NewBindingStore("")
	if err != nil {
		t.Fatalf("failed to create BindingStore: %v", err)
	}

	stop, err := servePodBindService(sockPath, store)
	if err != nil {
		t.Fatalf("servePodBindService failed: %v", err)
	}
	defer stop()

	// 1. Verify socket file mode is 0600
	info, err := os.Stat(sockPath)
	if err != nil {
		t.Fatalf("os.Stat(%q) failed: %v", sockPath, err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Fatalf("socket permissions = %#o, want %#o", perm, 0600)
	}

	// 2. Dial the socket with a gRPC client
	conn, err := grpc.NewClient(
		"passthrough:///unix",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sockPath)
		}),
	)
	if err != nil {
		t.Fatalf("failed to dial gRPC unix socket: %v", err)
	}
	defer conn.Close()

	client := portalsv1.NewPodBindServiceClient(conn)
	podUID := "pod-test-uid-1"

	// 3. Bind a valid policy
	policy := &portalsv1.EgressPolicy{
		Rules: []*portalsv1.EgressRule{
			{
				Http: &portalsv1.HttpRule{
					Hostnames: []string{"api.example.com"},
					Ports:     &portalsv1.Ports{Numbers: []int32{80}},
					Effects: &portalsv1.HttpRuleEffects{
						ReplaceHeaders: []*portalsv1.CredentialHeader{
							{
								Header:        "Authorization",
								Prefix:        "Bearer ",
								CredentialUri: "secret://my-token",
							},
						},
					},
				},
			},
		},
	}

	bindResp, err := client.Bind(t.Context(), &portalsv1.PodPolicy{
		PodUid:   podUID,
		Identity: "test-user-alice",
		Policy:   policy,
	})
	if err != nil {
		t.Fatalf("client.Bind failed: %v", err)
	}
	if !bindResp.GetBound() || bindResp.GetPodUid() != podUID {
		t.Errorf("unexpected BindResponse: %+v", bindResp)
	}

	// 4. Inject secrets
	injectResp, err := client.InjectSecrets(t.Context(), &portalsv1.PodSecrets{
		PodUid: podUID,
		Secrets: map[string][]byte{
			"my-token": []byte("super-secret-token"),
		},
	})
	if err != nil {
		t.Fatalf("client.InjectSecrets failed: %v", err)
	}
	if injectResp.GetPodUid() != podUID {
		t.Errorf("unexpected InjectSecretsResponse: %+v", injectResp)
	}

	// 5. Read binding back with Get
	getResp, err := client.Get(t.Context(), &portalsv1.GetRequest{PodUid: podUID})
	if err != nil {
		t.Fatalf("client.Get failed: %v", err)
	}
	if !getResp.GetBound() {
		t.Errorf("expected pod to be bound")
	}
	if getResp.GetIdentity() != "test-user-alice" {
		t.Errorf("expected identity 'test-user-alice', got %q", getResp.GetIdentity())
	}
	if len(getResp.GetPolicy().GetRules()) != 1 {
		t.Fatalf("expected 1 rule in returned policy, got %d", len(getResp.GetPolicy().GetRules()))
	}
	if getResp.GetPolicy().GetRules()[0].GetHttp().GetHostnames()[0] != "api.example.com" {
		t.Errorf("unexpected hostname in policy rule: %v", getResp.GetPolicy().GetRules()[0].GetHttp().GetHostnames())
	}

	// Verify secrets exist in the store backing the service
	sec, ok := store.ResolveSecret(podUID, "my-token")
	if !ok || string(sec.Bytes()) != "super-secret-token" {
		t.Errorf("expected secret to be resolved in store")
	}

	// 6. Verify an invalid policy is rejected with InvalidArgument over the wire
	invalidPolicy := &portalsv1.EgressPolicy{
		Rules: []*portalsv1.EgressRule{
			{
				Http: &portalsv1.HttpRule{
					Hostnames: []string{""}, // Invalid empty hostname fails Validate()
				},
			},
		},
	}
	_, err = client.Bind(t.Context(), &portalsv1.PodPolicy{
		PodUid: podUID,
		Policy: invalidPolicy,
	})
	if err == nil {
		t.Fatalf("expected client.Bind to fail for invalid policy, got nil")
	}
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.InvalidArgument {
		t.Errorf("expected gRPC code InvalidArgument, got code %v (err: %v)", st.Code(), err)
	}

	// 7. Verify Unbind
	unbindResp, err := client.Unbind(t.Context(), &portalsv1.UnbindRequest{PodUid: podUID})
	if err != nil {
		t.Fatalf("client.Unbind failed: %v", err)
	}
	if unbindResp.GetBound() {
		t.Errorf("expected unbind response bound=false")
	}

	getAfterUnbind, err := client.Get(t.Context(), &portalsv1.GetRequest{PodUid: podUID})
	if err != nil {
		t.Fatalf("client.Get after unbind failed: %v", err)
	}
	if getAfterUnbind.GetBound() {
		t.Errorf("expected pod to report unbound after unbind")
	}

	// 8. Verify stop cleans up the socket file
	stop()
	if _, err := os.Stat(sockPath); !os.IsNotExist(err) {
		t.Errorf("expected socket %q to be removed after stop, err: %v", sockPath, err)
	}
}

func TestServePodBindService_RejectsNonAbsolutePath(t *testing.T) {
	store, err := portalsv1.NewBindingStore("")
	if err != nil {
		t.Fatalf("failed to create BindingStore: %v", err)
	}

	tests := []struct {
		name string
		path string
	}{
		{"empty path", ""},
		{"relative path", "bind.sock"},
		{"relative path with dot", "./bind.sock"},
		{"tcp host port", "127.0.0.1:8080"},
		{"port only", ":8080"},
		{"localhost port", "localhost:8080"},
		{"tcp scheme", "tcp://127.0.0.1:8080"},
		{"http scheme", "http://127.0.0.1:8080"},
		{"unix prefix", "unix:/run/service-portal/bind.sock"},
		{"unix scheme", "unix:///run/service-portal/bind.sock"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stop, err := servePodBindService(tt.path, store)
			if err == nil {
				stop()
				t.Fatalf("expected error serving PodBindService with non-absolute path %q, got nil", tt.path)
			}
		})
	}
}

func TestRun_PodMapEnabledStartsBindService(t *testing.T) {
	dir := t.TempDir()
	bindSock := filepath.Join(dir, "bind.sock")
	adminSock := filepath.Join(dir, "admin.sock")

	pm := NewPodMap()
	store, err := portalsv1.NewBindingStore("")
	if err != nil {
		t.Fatalf("failed to create BindingStore: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	runErrCh := make(chan error, 1)
	go func() {
		// Use ephemeral port to avoid colliding with other services
		t.Setenv("PORT", "0")
		t.Setenv("ADMIN_ADDR", "unix://"+adminSock)
		cfg := Config{
			PodMap:         pm,
			BindingStore:   store,
			BindSocketPath: bindSock,
		}
		runErrCh <- Run(ctx, cfg)
	}()

	// Wait for bind socket to be created
	var socketReady bool
	for range 50 {
		if _, err := os.Stat(bindSock); err == nil {
			socketReady = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !socketReady {
		t.Fatalf("bind socket was not created within deadline")
	}

	// Verify permissions
	info, err := os.Stat(bindSock)
	if err != nil {
		t.Fatalf("os.Stat(%q) failed: %v", bindSock, err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Fatalf("bind socket permissions = %#o, want %#o", perm, 0600)
	}

	// Dial gRPC and bind a policy
	conn, err := grpc.NewClient(
		"passthrough:///unix",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", bindSock)
		}),
	)
	if err != nil {
		t.Fatalf("dial bind socket failed: %v", err)
	}
	defer conn.Close()

	client := portalsv1.NewPodBindServiceClient(conn)
	resp, err := client.Bind(t.Context(), &portalsv1.PodPolicy{
		PodUid:   "test-pod-uid",
		Identity: "test-user",
		Policy: &portalsv1.EgressPolicy{
			Rules: []*portalsv1.EgressRule{
				{
					Http: &portalsv1.HttpRule{
						Hostnames: []string{"api.example.com"},
						Ports:     &portalsv1.Ports{Numbers: []int32{80}},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("Bind RPC failed: %v", err)
	}
	if !resp.GetBound() {
		t.Errorf("expected pod bound")
	}

	// Cancel context to stop Run
	cancel()

	select {
	case err := <-runErrCh:
		if err != nil {
			t.Errorf("Run returned unexpected error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("Run did not shut down within deadline")
	}

	// Socket should be cleaned up
	if _, err := os.Stat(bindSock); !os.IsNotExist(err) {
		t.Errorf("expected bind socket %q to be removed on shutdown, err: %v", bindSock, err)
	}
}

func TestRun_PodMapWithRulesDir_FailsStartup(t *testing.T) {
	tests := []struct {
		name     string
		cfg      Config
		setupEnv func(t *testing.T)
	}{
		{
			name: "Config.RulesDir with Config.PodMap",
			cfg: Config{
				PodMap:   NewPodMap(),
				RulesDir: "/etc/portals",
			},
		},
		{
			name: "RULES_DIR env with Config.PodMap",
			cfg: Config{
				PodMap: NewPodMap(),
			},
			setupEnv: func(t *testing.T) {
				t.Setenv("RULES_DIR", "/etc/portals")
			},
		},
		{
			name: "Config.RulesDir with ENABLE_POD_MAP env",
			cfg: Config{
				RulesDir: "/etc/portals",
			},
			setupEnv: func(t *testing.T) {
				t.Setenv("ENABLE_POD_MAP", "true")
			},
		},
		{
			name: "RULES_DIR env with ENABLE_POD_MAP env",
			cfg:  Config{},
			setupEnv: func(t *testing.T) {
				t.Setenv("ENABLE_POD_MAP", "true")
				t.Setenv("RULES_DIR", "/etc/portals")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setupEnv != nil {
				tt.setupEnv(t)
			}
			err := Run(t.Context(), tt.cfg)
			if err == nil {
				t.Fatalf("expected error running with pod map and rules directory, got nil")
			}
			if !strings.Contains(err.Error(), "cannot be configured with pod map enabled: NRI mode uses bound egress policies") {
				t.Errorf("expected error message explaining NRI mode uses bound egress policies, got: %v", err)
			}
		})
	}
}
