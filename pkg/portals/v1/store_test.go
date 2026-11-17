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

package portalsv1

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func mustNewStore(t *testing.T, dir string) *BindingStore {
	t.Helper()
	s, err := NewBindingStore(dir)
	if err != nil {
		t.Fatalf("NewBindingStore(%q) failed: %v", dir, err)
	}
	return s
}

func validTestPolicy() *EgressPolicy {
	return &EgressPolicy{
		Rules: []*EgressRule{
			{
				Https: &HttpsRule{
					Hostnames: []string{"api.github.com"},
					Effects: &HttpRuleEffects{
						ReplaceHeaders: []*CredentialHeader{
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
}

func invalidTestPolicy() *EgressPolicy {
	return &EgressPolicy{
		Rules: []*EgressRule{
			{
				Https: &HttpsRule{
					Hostnames: []string{"api.github.com"},
				},
			},
			{
				Https: &HttpsRule{
					Hostnames: []string{"api.github.com"},
				},
			},
		},
	}
}

func TestSecret_Redaction(t *testing.T) {
	const rawToken = "ghp_super_secret_token_12345"
	secret := Secret{value: []byte(rawToken)}

	for _, text := range []string{
		secret.String(),
		secret.GoString(),
		fmt.Sprint(secret),
		fmt.Sprintf("%v", secret),
		fmt.Sprintf("%+v", secret),
		fmt.Sprintf("%#v", secret),
		fmt.Sprintf("%s", secret),
		fmt.Sprintf("%q", secret),
	} {
		if strings.Contains(text, rawToken) {
			t.Errorf("formatting (%q) leaked secret token", text)
		}
		if !strings.Contains(text, "[REDACTED]") {
			t.Errorf("formatting (%q) expected [REDACTED]", text)
		}
	}

	// Verify json.Marshal does not leak secret token bytes
	jsonBytes, err := json.Marshal(secret)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	if strings.Contains(string(jsonBytes), rawToken) {
		t.Errorf("json.Marshal (%q) leaked secret token", string(jsonBytes))
	}

	// Verify slog logging
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	logger.Info("testing", "secret", secret)
	logged := buf.String()
	if strings.Contains(logged, rawToken) {
		t.Errorf("slog output (%q) leaked secret token", logged)
	}
	if !strings.Contains(logged, "[REDACTED]") {
		t.Errorf("slog output (%q) expected [REDACTED]", logged)
	}

	// Verify Bytes() returns raw bytes and a safe clone
	if !bytes.Equal(secret.Bytes(), []byte(rawToken)) {
		t.Errorf("Bytes() mismatch: got %q, want %q", secret.Bytes(), rawToken)
	}

	cloned := secret.Bytes()
	cloned[0] = 'X'
	if bytes.Equal(secret.Bytes(), cloned) {
		t.Errorf("mutating Bytes() result modified original secret")
	}
}

func TestBindingStore_BindValidation(t *testing.T) {
	ctx := t.Context()
	store := mustNewStore(t, "")

	// Empty pod_uid rejected with InvalidArgument
	if _, err := store.Bind(ctx, &PodPolicy{PodUid: "", Policy: validTestPolicy()}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument for empty pod_uid, got %v", err)
	}

	// Nil request rejected with InvalidArgument
	if _, err := store.Bind(ctx, nil); status.Code(err) != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument for nil request, got %v", err)
	}

	// Nil policy rejected with InvalidArgument and joined error
	if _, err := store.Bind(ctx, &PodPolicy{PodUid: "pod-1", Policy: nil}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument for nil policy, got %v", err)
	} else if !strings.Contains(status.Convert(err).Message(), "policy cannot be nil") {
		t.Errorf("expected 'policy cannot be nil' in message, got %v", err)
	}

	// Invalid policy rejected with InvalidArgument and joined validation errors
	invPolicy := invalidTestPolicy()
	expectedErr := invPolicy.Validate()
	if expectedErr == nil {
		t.Fatal("expected invalidTestPolicy to fail validation")
	}

	resp, err := store.Bind(ctx, &PodPolicy{
		PodUid:   "pod-1",
		Identity: "user@example.com",
		Policy:   invPolicy,
	})
	if err == nil {
		t.Fatalf("expected error binding invalid policy, got resp: %v", resp)
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument code, got %v", status.Code(err))
	}
	if status.Convert(err).Message() != expectedErr.Error() {
		t.Errorf("expected validation errors %q, got %q", expectedErr.Error(), status.Convert(err).Message())
	}

	// Valid policy binds successfully
	validPolicy := validTestPolicy()
	bindResp, err := store.Bind(ctx, &PodPolicy{
		PodUid:   "pod-1",
		Identity: "user@example.com",
		Policy:   validPolicy,
	})
	if err != nil {
		t.Fatalf("unexpected error binding valid policy: %v", err)
	}
	if bindResp.GetPodUid() != "pod-1" || !bindResp.GetBound() {
		t.Errorf("unexpected bind response: %v", bindResp)
	}

	// Verify policy is retrieved
	pol := store.Policy("pod-1")
	if pol == nil || len(pol.Rules) != 1 {
		t.Fatalf("expected 1 rule in retrieved policy, got %v", pol)
	}

	// Re-binding updates policy and identity
	updateResp, err := store.Bind(ctx, &PodPolicy{
		PodUid:   "pod-1",
		Identity: "admin@example.com",
		Policy:   validPolicy,
	})
	if err != nil {
		t.Fatalf("unexpected error re-binding: %v", err)
	}
	if !updateResp.GetBound() {
		t.Error("expected bound = true on re-bind")
	}
	getResp, err := store.Get(ctx, &GetRequest{PodUid: "pod-1"})
	if err != nil {
		t.Fatalf("unexpected Get error: %v", err)
	}
	if getResp.GetIdentity() != "admin@example.com" || !getResp.GetBound() {
		t.Errorf("expected identity admin@example.com, got %v", getResp)
	}
}

func TestBindingStore_InjectSecretsReplacement(t *testing.T) {
	ctx := t.Context()
	store := mustNewStore(t, "")

	// Empty pod_uid rejected with InvalidArgument
	if _, err := store.InjectSecrets(ctx, &PodSecrets{PodUid: ""}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument for empty pod_uid, got %v", err)
	}

	// Initial injection
	initial := map[string][]byte{
		"token1": []byte("value1"),
		"token2": []byte("value2"),
	}
	resp, err := store.InjectSecrets(ctx, &PodSecrets{
		PodUid:  "pod-1",
		Secrets: initial,
	})
	if err != nil {
		t.Fatalf("unexpected error on InjectSecrets: %v", err)
	}
	if resp.GetPodUid() != "pod-1" {
		t.Errorf("unexpected InjectSecrets response: %v", resp)
	}

	// Verify initial secrets resolved
	sec1, ok := store.ResolveSecret("pod-1", "token1")
	if !ok || string(sec1.Bytes()) != "value1" {
		t.Errorf("expected token1 = value1, got %q (ok=%v)", sec1.Bytes(), ok)
	}
	sec2, ok := store.ResolveSecret("pod-1", "token2")
	if !ok || string(sec2.Bytes()) != "value2" {
		t.Errorf("expected token2 = value2, got %q (ok=%v)", sec2.Bytes(), ok)
	}

	// Modifying original input map does not affect store
	initial["token1"][0] = 'Z'
	sec1Again, _ := store.ResolveSecret("pod-1", "token1")
	if string(sec1Again.Bytes()) != "value1" {
		t.Errorf("mutating input map affected store secret: %q", sec1Again.Bytes())
	}

	// Second injection replaces the entire set (does not merge)
	replacement := map[string][]byte{
		"token2": []byte("new-value2"),
		"token3": []byte("value3"),
	}
	if _, err := store.InjectSecrets(ctx, &PodSecrets{
		PodUid:  "pod-1",
		Secrets: replacement,
	}); err != nil {
		t.Fatalf("unexpected error replacing secrets: %v", err)
	}

	// token1 must now be gone
	if _, ok := store.ResolveSecret("pod-1", "token1"); ok {
		t.Errorf("expected token1 to be removed after secret replacement")
	}

	// token2 must be updated
	sec2New, ok := store.ResolveSecret("pod-1", "token2")
	if !ok || string(sec2New.Bytes()) != "new-value2" {
		t.Errorf("expected token2 = new-value2, got %q (ok=%v)", sec2New.Bytes(), ok)
	}

	// token3 must be present
	sec3, ok := store.ResolveSecret("pod-1", "token3")
	if !ok || string(sec3.Bytes()) != "value3" {
		t.Errorf("expected token3 = value3, got %q (ok=%v)", sec3.Bytes(), ok)
	}
}

func TestBindingStore_UnbindRemovesBoth(t *testing.T) {
	ctx := t.Context()
	store := mustNewStore(t, "")

	// Empty pod_uid rejected with InvalidArgument
	if _, err := store.Unbind(ctx, &UnbindRequest{PodUid: ""}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument for empty pod_uid, got %v", err)
	}

	// Bind and inject secrets
	if _, err := store.Bind(ctx, &PodPolicy{
		PodUid:   "pod-1",
		Identity: "user@example.com",
		Policy:   validTestPolicy(),
	}); err != nil {
		t.Fatalf("unexpected bind error: %v", err)
	}
	if _, err := store.InjectSecrets(ctx, &PodSecrets{
		PodUid: "pod-1",
		Secrets: map[string][]byte{
			"tok": []byte("secret-token"),
		},
	}); err != nil {
		t.Fatalf("unexpected inject error: %v", err)
	}

	// Verify both exist before unbind
	if store.Policy("pod-1") == nil {
		t.Fatal("expected policy before unbind")
	}
	if _, ok := store.ResolveSecret("pod-1", "tok"); !ok {
		t.Fatal("expected secret before unbind")
	}
	if getResp, err := store.Get(ctx, &GetRequest{PodUid: "pod-1"}); err != nil || !getResp.GetBound() {
		t.Fatalf("expected bound true before unbind, got %v (err=%v)", getResp, err)
	}

	// Unbind
	unbindResp, err := store.Unbind(ctx, &UnbindRequest{PodUid: "pod-1"})
	if err != nil {
		t.Fatalf("unexpected unbind error: %v", err)
	}
	if unbindResp.GetPodUid() != "pod-1" || unbindResp.GetBound() {
		t.Errorf("unexpected unbind response: %v", unbindResp)
	}

	// Policy and secrets must both be removed together
	if pol := store.Policy("pod-1"); pol != nil {
		t.Errorf("expected policy to be nil after unbind, got %v", pol)
	}
	if _, ok := store.ResolveSecret("pod-1", "tok"); ok {
		t.Errorf("expected secret to be removed after unbind")
	}

	// Get should report unbound
	getResp, err := store.Get(ctx, &GetRequest{PodUid: "pod-1"})
	if err != nil {
		t.Fatalf("unexpected Get error: %v", err)
	}
	if getResp.GetBound() {
		t.Errorf("expected Get bound=false after unbind, got %v", getResp)
	}
}

func TestBindingStore_UnboundPodDeny(t *testing.T) {
	ctx := t.Context()
	store := mustNewStore(t, "")

	// Pod with no binding has no policy (nil)
	if pol := store.Policy("non-existent"); pol != nil {
		t.Errorf("expected nil policy for unbound pod, got %v", pol)
	}
	if _, ok := store.ResolveSecret("non-existent", "tok"); ok {
		t.Errorf("expected no secret for unbound pod")
	}

	getResp, err := store.Get(ctx, &GetRequest{PodUid: "non-existent"})
	if err != nil {
		t.Fatalf("unexpected error on Get: %v", err)
	}
	if getResp.GetBound() {
		t.Errorf("expected bound = false on Get for unbound pod")
	}
}

func TestBindingStore_OrderOfOperations(t *testing.T) {
	ctx := t.Context()

	// Case 1: Secrets injected before Bind
	s1 := mustNewStore(t, "")
	if _, err := s1.InjectSecrets(ctx, &PodSecrets{
		PodUid:  "pod-1",
		Secrets: map[string][]byte{"tok": []byte("sec")},
	}); err != nil {
		t.Fatal(err)
	}
	// Not bound yet: Policy is nil
	if pol := s1.Policy("pod-1"); pol != nil {
		t.Errorf("expected nil policy before bind, got %v", pol)
	}
	if getResp, err := s1.Get(ctx, &GetRequest{PodUid: "pod-1"}); err != nil || getResp.GetBound() {
		t.Errorf("expected Get bound = false before bind, got %v", getResp)
	}
	// Now bind
	if _, err := s1.Bind(ctx, &PodPolicy{
		PodUid:   "pod-1",
		Identity: "id@test",
		Policy:   validTestPolicy(),
	}); err != nil {
		t.Fatal(err)
	}
	if getResp, err := s1.Get(ctx, &GetRequest{PodUid: "pod-1"}); err != nil || !getResp.GetBound() {
		t.Errorf("expected Get bound = true after bind, got %v", getResp)
	}
	if sec, ok := s1.ResolveSecret("pod-1", "tok"); !ok || string(sec.Bytes()) != "sec" {
		t.Errorf("expected secret preserved after bind, got %q (ok=%v)", sec.Bytes(), ok)
	}

	// Case 2: Bind before InjectSecrets
	s2 := mustNewStore(t, "")
	if _, err := s2.Bind(ctx, &PodPolicy{
		PodUid:   "pod-2",
		Identity: "id@test",
		Policy:   validTestPolicy(),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s2.InjectSecrets(ctx, &PodSecrets{
		PodUid:  "pod-2",
		Secrets: map[string][]byte{"tok": []byte("sec2")},
	}); err != nil {
		t.Fatal(err)
	}
	if pol := s2.Policy("pod-2"); pol == nil {
		t.Errorf("expected policy preserved after InjectSecrets")
	}
	if sec, ok := s2.ResolveSecret("pod-2", "tok"); !ok || string(sec.Bytes()) != "sec2" {
		t.Errorf("expected secret resolved, got %q (ok=%v)", sec.Bytes(), ok)
	}
}

func TestBindingStore_SelfContainedPerPod(t *testing.T) {
	ctx := t.Context()
	store := mustNewStore(t, "")

	// Bind Pod A and Pod B
	if _, err := store.Bind(ctx, &PodPolicy{
		PodUid:   "pod-A",
		Identity: "userA",
		Policy:   validTestPolicy(),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.InjectSecrets(ctx, &PodSecrets{
		PodUid:  "pod-A",
		Secrets: map[string][]byte{"secret": []byte("secA")},
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := store.Bind(ctx, &PodPolicy{
		PodUid:   "pod-B",
		Identity: "userB",
		Policy:   validTestPolicy(),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.InjectSecrets(ctx, &PodSecrets{
		PodUid:  "pod-B",
		Secrets: map[string][]byte{"secret": []byte("secB")},
	}); err != nil {
		t.Fatal(err)
	}

	// Verify Pod A and Pod B resolve their own secrets
	secA, _ := store.ResolveSecret("pod-A", "secret")
	secB, _ := store.ResolveSecret("pod-B", "secret")
	if string(secA.Bytes()) != "secA" || string(secB.Bytes()) != "secB" {
		t.Errorf("mismatch: A=%q, B=%q", secA.Bytes(), secB.Bytes())
	}

	// Unbinding Pod A leaves Pod B unaffected
	if _, err := store.Unbind(ctx, &UnbindRequest{PodUid: "pod-A"}); err != nil {
		t.Fatal(err)
	}
	if getResp, err := store.Get(ctx, &GetRequest{PodUid: "pod-A"}); err != nil || getResp.GetBound() {
		t.Error("pod-A should be unbound")
	}
	if getResp, err := store.Get(ctx, &GetRequest{PodUid: "pod-B"}); err != nil || !getResp.GetBound() {
		t.Error("pod-B should still be bound")
	}
	secBAfter, ok := store.ResolveSecret("pod-B", "secret")
	if !ok || string(secBAfter.Bytes()) != "secB" {
		t.Errorf("pod-B secret affected by unbinding pod-A: %q (ok=%v)", secBAfter.Bytes(), ok)
	}
}

func TestBindingStore_ConcurrentUse(t *testing.T) {
	ctx := t.Context()
	store := mustNewStore(t, "")
	validPol := validTestPolicy()

	const numWorkers = 16
	const iterations = 50

	var wg sync.WaitGroup
	wg.Add(numWorkers)

	for w := 0; w < numWorkers; w++ {
		go func(workerID int) {
			defer wg.Done()
			podUID := fmt.Sprintf("pod-%d", workerID%4)

			for i := 0; i < iterations; i++ {
				switch i % 5 {
				case 0:
					_, _ = store.Bind(ctx, &PodPolicy{
						PodUid:   podUID,
						Identity: fmt.Sprintf("user-%d", workerID),
						Policy:   validPol,
					})
				case 1:
					_, _ = store.InjectSecrets(ctx, &PodSecrets{
						PodUid: podUID,
						Secrets: map[string][]byte{
							"key": []byte(fmt.Sprintf("val-%d-%d", workerID, i)),
						},
					})
				case 2:
					_ = store.Policy(podUID)
					_, _ = store.ResolveSecret(podUID, "key")
				case 3:
					_, _ = store.Get(ctx, &GetRequest{PodUid: podUID})
				case 4:
					_, _ = store.Unbind(ctx, &UnbindRequest{PodUid: podUID})
				}
			}
		}(w)
	}

	wg.Wait()
}

func TestBindingStore_gRPCRegistration(t *testing.T) {
	store := mustNewStore(t, "")
	grpcServer := grpc.NewServer()
	// Must not panic when registering (verifies testEmbeddedByValue)
	RegisterPodBindServiceServer(grpcServer, store)
}

func TestBindingStore_Acceptance(t *testing.T) {
	ctx := t.Context()
	store := mustNewStore(t, "")

	// 1. Pod not bound
	status, missing := store.Acceptance("pod-1")
	if status != AcceptanceStatus_ACCEPTANCE_STATUS_PENDING || len(missing) != 0 {
		t.Fatalf("expected PENDING with empty missing, got %v, %v", status, missing)
	}

	// 2. Policy naming no secrets is accepted on its own
	noSecretsPolicy := &EgressPolicy{
		Rules: []*EgressRule{
			{Https: &HttpsRule{Hostnames: []string{"example.com"}}},
		},
	}
	if _, err := store.Bind(ctx, &PodPolicy{PodUid: "pod-no-secrets", Policy: noSecretsPolicy}); err != nil {
		t.Fatalf("Bind failed: %v", err)
	}
	status, missing = store.Acceptance("pod-no-secrets")
	if status != AcceptanceStatus_ACCEPTANCE_STATUS_ACCEPTED || len(missing) != 0 {
		t.Fatalf("expected ACCEPTED for policy naming no secrets, got %v, %v", status, missing)
	}

	// 3. Policy naming secrets: pending until all secrets arrive
	twoSecretsPolicy := &EgressPolicy{
		Rules: []*EgressRule{
			{
				Https: &HttpsRule{
					Hostnames: []string{"api.github.com"},
					Effects: &HttpRuleEffects{
						ReplaceHeaders: []*CredentialHeader{
							{Header: "Authorization", CredentialUri: "secret://token-1"},
							{Header: "X-Api-Key", CredentialUri: "secret://token-2"},
						},
					},
				},
			},
		},
	}
	if _, err := store.Bind(ctx, &PodPolicy{PodUid: "pod-1", Policy: twoSecretsPolicy}); err != nil {
		t.Fatalf("Bind failed: %v", err)
	}

	status, missing = store.Acceptance("pod-1")
	if status != AcceptanceStatus_ACCEPTANCE_STATUS_PENDING {
		t.Fatalf("expected PENDING, got %v", status)
	}
	if len(missing) != 2 || missing[0] != "token-1" || missing[1] != "token-2" {
		t.Fatalf("expected missing [token-1 token-2], got %v", missing)
	}

	// Inject one secret
	if _, err := store.InjectSecrets(ctx, &PodSecrets{
		PodUid:  "pod-1",
		Secrets: map[string][]byte{"token-1": []byte("val-1")},
	}); err != nil {
		t.Fatalf("InjectSecrets failed: %v", err)
	}
	status, missing = store.Acceptance("pod-1")
	if status != AcceptanceStatus_ACCEPTANCE_STATUS_PENDING {
		t.Fatalf("expected PENDING, got %v", status)
	}
	if len(missing) != 1 || missing[0] != "token-2" {
		t.Fatalf("expected missing [token-2], got %v", missing)
	}

	// Inject all secrets
	if _, err := store.InjectSecrets(ctx, &PodSecrets{
		PodUid:  "pod-1",
		Secrets: map[string][]byte{"token-1": []byte("val-1"), "token-2": []byte("val-2")},
	}); err != nil {
		t.Fatalf("InjectSecrets failed: %v", err)
	}
	status, missing = store.Acceptance("pod-1")
	if status != AcceptanceStatus_ACCEPTANCE_STATUS_ACCEPTED || len(missing) != 0 {
		t.Fatalf("expected ACCEPTED, got %v, %v", status, missing)
	}

	// Unbind reverts to pending
	if _, err := store.Unbind(ctx, &UnbindRequest{PodUid: "pod-1"}); err != nil {
		t.Fatalf("Unbind failed: %v", err)
	}
	status, missing = store.Acceptance("pod-1")
	if status != AcceptanceStatus_ACCEPTANCE_STATUS_PENDING {
		t.Fatalf("expected PENDING after unbind, got %v", status)
	}
}

func TestBindingStore_DurabilityAcrossRestart(t *testing.T) {
	ctx := t.Context()
	storeDir := filepath.Join(t.TempDir(), "bindings")

	s1 := mustNewStore(t, storeDir)
	pol := validTestPolicy()
	if _, err := s1.Bind(ctx, &PodPolicy{PodUid: "pod-1", Identity: "user@example.com", Policy: pol}); err != nil {
		t.Fatalf("Bind failed: %v", err)
	}
	if _, err := s1.InjectSecrets(ctx, &PodSecrets{
		PodUid: "pod-1",
		Secrets: map[string][]byte{
			"github-token": []byte("ghp_secret123"),
		},
	}); err != nil {
		t.Fatalf("InjectSecrets failed: %v", err)
	}

	// Create a new store on the same directory (simulating restart)
	s2 := mustNewStore(t, storeDir)

	// Pod must still be bound with the same policy
	retPol := s2.Policy("pod-1")
	if retPol == nil || len(retPol.Rules) != 1 {
		t.Fatalf("expected 1 rule in restored policy, got %v", retPol)
	}
	if retPol.Rules[0].Https.Hostnames[0] != "api.github.com" {
		t.Errorf("expected hostname api.github.com, got %s", retPol.Rules[0].Https.Hostnames[0])
	}

	// Secret must be resolvable
	sec, ok := s2.ResolveSecret("pod-1", "github-token")
	if !ok || string(sec.Bytes()) != "ghp_secret123" {
		t.Errorf("expected secret resolved, got %q (ok=%v)", sec.Bytes(), ok)
	}

	// Get should report bound
	getResp, err := s2.Get(ctx, &GetRequest{PodUid: "pod-1"})
	if err != nil || !getResp.GetBound() || getResp.GetIdentity() != "user@example.com" {
		t.Errorf("expected Get bound=true with identity user@example.com, got %v (err=%v)", getResp, err)
	}
}

func TestBindingStore_UnbindRemovesStoredState(t *testing.T) {
	ctx := t.Context()
	storeDir := filepath.Join(t.TempDir(), "bindings")
	s := mustNewStore(t, storeDir)

	if _, err := s.Bind(ctx, &PodPolicy{PodUid: "pod-1", Policy: validTestPolicy()}); err != nil {
		t.Fatal(err)
	}
	filePath := filepath.Join(storeDir, "pod-1.pb")
	if _, err := os.Stat(filePath); err != nil {
		t.Fatalf("expected stored file %s to exist: %v", filePath, err)
	}

	if _, err := s.Unbind(ctx, &UnbindRequest{PodUid: "pod-1"}); err != nil {
		t.Fatalf("Unbind failed: %v", err)
	}
	if _, err := os.Stat(filePath); !os.IsNotExist(err) {
		t.Errorf("expected stored file %s to be removed, got err: %v", filePath, err)
	}

	// Restarting store sees pod-1 as unbound
	s2 := mustNewStore(t, storeDir)
	if pol := s2.Policy("pod-1"); pol != nil {
		t.Errorf("expected nil policy in new store, got %v", pol)
	}
}

func TestBindingStore_RemovePod(t *testing.T) {
	ctx := t.Context()
	storeDir := filepath.Join(t.TempDir(), "bindings")
	s := mustNewStore(t, storeDir)

	if _, err := s.Bind(ctx, &PodPolicy{PodUid: "pod-1", Policy: validTestPolicy()}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Bind(ctx, &PodPolicy{PodUid: "pod-2", Policy: validTestPolicy()}); err != nil {
		t.Fatal(err)
	}

	s.RemovePod("pod-1")

	if s.Policy("pod-1") != nil {
		t.Error("expected pod-1 to be removed from memory")
	}
	if _, err := os.Stat(filepath.Join(storeDir, "pod-1.pb")); !os.IsNotExist(err) {
		t.Error("expected pod-1 file to be removed from directory")
	}

	// pod-2 must remain
	if s.Policy("pod-2") == nil {
		t.Error("expected pod-2 to remain in memory")
	}
	if _, err := os.Stat(filepath.Join(storeDir, "pod-2.pb")); err != nil {
		t.Errorf("expected pod-2 file to remain on disk: %v", err)
	}

	// After restart, pod-1 is absent and pod-2 is present
	s2 := mustNewStore(t, storeDir)
	if s2.Policy("pod-1") != nil {
		t.Error("expected pod-1 absent in new store")
	}
	if s2.Policy("pod-2") == nil {
		t.Error("expected pod-2 present in new store")
	}
}

func TestBindingStore_DropAbsent(t *testing.T) {
	ctx := t.Context()
	storeDir := filepath.Join(t.TempDir(), "bindings")
	s := mustNewStore(t, storeDir)

	for _, id := range []string{"pod-1", "pod-2", "pod-3"} {
		if _, err := s.Bind(ctx, &PodPolicy{PodUid: id, Policy: validTestPolicy()}); err != nil {
			t.Fatal(err)
		}
	}

	// Only pod-2 is active on the node
	s.DropAbsent([]string{"pod-2"})

	if s.Policy("pod-1") != nil || s.Policy("pod-3") != nil {
		t.Error("expected pod-1 and pod-3 to be dropped from memory")
	}
	if s.Policy("pod-2") == nil {
		t.Error("expected pod-2 to remain in memory")
	}
	if _, err := os.Stat(filepath.Join(storeDir, "pod-1.pb")); !os.IsNotExist(err) {
		t.Error("expected pod-1.pb removed")
	}
	if _, err := os.Stat(filepath.Join(storeDir, "pod-3.pb")); !os.IsNotExist(err) {
		t.Error("expected pod-3.pb removed")
	}
	if _, err := os.Stat(filepath.Join(storeDir, "pod-2.pb")); err != nil {
		t.Errorf("expected pod-2.pb preserved: %v", err)
	}

	// After restart, only pod-2 is loaded
	s2 := mustNewStore(t, storeDir)
	if s2.Policy("pod-1") != nil || s2.Policy("pod-3") != nil {
		t.Error("absent pods resurrected after restart")
	}
	if s2.Policy("pod-2") == nil {
		t.Error("active pod missing after restart")
	}
}

func TestBindingStore_CorruptOrTruncatedEntry(t *testing.T) {
	ctx := t.Context()
	storeDir := filepath.Join(t.TempDir(), "bindings")
	s := mustNewStore(t, storeDir)

	// Bind valid pod-1 and pod-3
	if _, err := s.Bind(ctx, &PodPolicy{PodUid: "pod-1", Policy: validTestPolicy()}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Bind(ctx, &PodPolicy{PodUid: "pod-3", Policy: validTestPolicy()}); err != nil {
		t.Fatal(err)
	}

	// Write corrupt/truncated entries
	// 1. Truncated protobuf bytes
	corruptPath := filepath.Join(storeDir, "pod-corrupt-pb.pb")
	if err := os.WriteFile(corruptPath, []byte{0x0a, 0x10, 0x01}, 0600); err != nil {
		t.Fatal(err)
	}
	// 2. Bound entry missing policy
	missingPolPath := filepath.Join(storeDir, "pod-missing-pol.pb")
	missingPolEntry, _ := proto.Marshal(&StoredBinding{PodUid: "pod-missing-pol", Bound: true})
	if err := os.WriteFile(missingPolPath, missingPolEntry, 0600); err != nil {
		t.Fatal(err)
	}
	// 3. Policy that fails validation (duplicate hostnames)
	invalidValPath := filepath.Join(storeDir, "pod-invalid-val.pb")
	invalidValEntry, _ := proto.Marshal(&StoredBinding{PodUid: "pod-invalid-val", Policy: invalidTestPolicy(), Bound: true})
	if err := os.WriteFile(invalidValPath, invalidValEntry, 0600); err != nil {
		t.Fatal(err)
	}

	// New store should drop corrupt entries and leave valid pods intact
	s2 := mustNewStore(t, storeDir)
	if s2.Policy("pod-1") == nil || s2.Policy("pod-3") == nil {
		t.Error("expected valid pods pod-1 and pod-3 to remain bound")
	}
	if s2.Policy("pod-corrupt-pb") != nil {
		t.Error("expected corrupt proto pod to be unbound")
	}
	if s2.Policy("pod-missing-pol") != nil {
		t.Error("expected missing policy pod to be unbound")
	}
	if s2.Policy("pod-invalid-val") != nil {
		t.Error("expected invalid policy validation pod to be unbound")
	}

	// Dropped corrupt files must be removed from disk
	if _, err := os.Stat(corruptPath); !os.IsNotExist(err) {
		t.Errorf("expected corrupt file %s to be removed from disk, got err: %v", corruptPath, err)
	}
	if _, err := os.Stat(missingPolPath); !os.IsNotExist(err) {
		t.Errorf("expected missing policy file %s to be removed from disk, got err: %v", missingPolPath, err)
	}
	if _, err := os.Stat(invalidValPath); !os.IsNotExist(err) {
		t.Errorf("expected invalid policy file %s to be removed from disk, got err: %v", invalidValPath, err)
	}
}

func TestBindingStore_OldJSONFormatDropped(t *testing.T) {
	ctx := t.Context()
	storeDir := filepath.Join(t.TempDir(), "bindings")
	s := mustNewStore(t, storeDir)

	// Bind valid pod-1 and pod-2
	if _, err := s.Bind(ctx, &PodPolicy{PodUid: "pod-valid-1", Policy: validTestPolicy()}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Bind(ctx, &PodPolicy{PodUid: "pod-valid-2", Policy: validTestPolicy()}); err != nil {
		t.Fatal(err)
	}

	// Write an entry in the old JSON format (where policy was bytes inside JSON record)
	oldJSONPath := filepath.Join(storeDir, "pod-old-json.json")
	oldJSON := []byte(`{"pod_uid":"pod-old-json","identity":"user@example.com","policy":"Cg8KDGFwaS5naXRodWIuY29t","bound":true}`)
	if err := os.WriteFile(oldJSONPath, oldJSON, 0600); err != nil {
		t.Fatal(err)
	}

	// New store should drop the old JSON format entry and leave valid entries intact
	s2 := mustNewStore(t, storeDir)
	if s2.Policy("pod-valid-1") == nil || s2.Policy("pod-valid-2") == nil {
		t.Error("expected valid pods pod-valid-1 and pod-valid-2 to remain bound")
	}
	if s2.Policy("pod-old-json") != nil {
		t.Error("expected old JSON format pod to be unbound")
	}
	getResp, err := s2.Get(ctx, &GetRequest{PodUid: "pod-old-json"})
	if err != nil {
		t.Fatalf("unexpected Get error: %v", err)
	}
	if getResp.GetBound() {
		t.Error("expected old JSON format pod Get bound=false")
	}

	// The old-format JSON file must be removed from disk
	if _, err := os.Stat(oldJSONPath); !os.IsNotExist(err) {
		t.Errorf("expected old JSON format file %s to be removed from disk, got err: %v", oldJSONPath, err)
	}
}

func TestBindingStore_PermissionsAndModes(t *testing.T) {
	ctx := t.Context()
	dir := t.TempDir()

	// 1. New directory created with 0700
	storeDir := filepath.Join(dir, "new-store")
	s := mustNewStore(t, storeDir)
	fi, err := os.Stat(storeDir)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0700 {
		t.Errorf("expected directory mode 0700, got %04o", fi.Mode().Perm())
	}

	// 2. Stored files created with 0600
	if _, err := s.Bind(ctx, &PodPolicy{PodUid: "pod-1", Policy: validTestPolicy()}); err != nil {
		t.Fatal(err)
	}
	fileFi, err := os.Stat(filepath.Join(storeDir, "pod-1.pb"))
	if err != nil {
		t.Fatal(err)
	}
	if fileFi.Mode().Perm() != 0600 {
		t.Errorf("expected file mode 0600, got %04o", fileFi.Mode().Perm())
	}

	// 3. Existing directory readable by others fails startup
	insecureDir := filepath.Join(dir, "insecure-store")
	if err := os.Mkdir(insecureDir, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := NewBindingStore(insecureDir); err == nil {
		t.Error("expected NewBindingStore to fail on directory readable by others (0755)")
	}

	// 4. Stored file readable by others is dropped and removed from disk
	validStoreDir := filepath.Join(dir, "valid-store")
	sValid := mustNewStore(t, validStoreDir)
	if _, err := sValid.Bind(ctx, &PodPolicy{PodUid: "pod-safe", Policy: validTestPolicy()}); err != nil {
		t.Fatal(err)
	}
	insecureFilePath := filepath.Join(validStoreDir, "pod-insecure.pb")
	insecureEntry, err := proto.Marshal(&StoredBinding{PodUid: "pod-insecure", Policy: validTestPolicy(), Bound: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(insecureFilePath, insecureEntry, 0644); err != nil {
		t.Fatal(err)
	}

	sRestarted := mustNewStore(t, validStoreDir)
	if sRestarted.Policy("pod-safe") == nil {
		t.Error("expected pod-safe to be bound")
	}
	if sRestarted.Policy("pod-insecure") != nil {
		t.Error("expected pod with 0644 file mode to be dropped and unbound")
	}
	if _, err := os.Stat(insecureFilePath); !os.IsNotExist(err) {
		t.Errorf("expected insecure file %s to be removed from disk, got err: %v", insecureFilePath, err)
	}
}

func TestBindingStore_FailedWriteFailsCall(t *testing.T) {
	ctx := t.Context()
	// Point store to a path where creating files fails even as root (a regular file path)
	nonDir := filepath.Join(t.TempDir(), "file-blocking-dir")
	if err := os.WriteFile(nonDir, []byte("blocker"), 0600); err != nil {
		t.Fatal(err)
	}
	s := &BindingStore{
		pods: make(map[string]*podEntry),
		dir:  nonDir,
	}

	// Bind must fail and leave pod unbound
	_, err := s.Bind(ctx, &PodPolicy{PodUid: "pod-1", Policy: validTestPolicy()})
	if err == nil {
		t.Error("expected Bind to fail when write fails")
	}
	if status.Code(err) != codes.Internal {
		t.Errorf("expected Internal code, got %v", status.Code(err))
	}
	if s.Policy("pod-1") != nil {
		t.Error("pod must not be bound after failed write")
	}

	// InjectSecrets must fail and leave secrets unset
	_, err = s.InjectSecrets(ctx, &PodSecrets{
		PodUid:  "pod-1",
		Secrets: map[string][]byte{"k": []byte("v")},
	})
	if err == nil {
		t.Error("expected InjectSecrets to fail when write fails")
	}
	if status.Code(err) != codes.Internal {
		t.Errorf("expected Internal code, got %v", status.Code(err))
	}
	if _, ok := s.ResolveSecret("pod-1", "k"); ok {
		t.Error("secret must not be resolved after failed write")
	}
}

func TestBindingStore_FailedUnbindFailsCall(t *testing.T) {
	ctx := t.Context()
	storeDir := filepath.Join(t.TempDir(), "unbind-fail-store")
	s := mustNewStore(t, storeDir)

	if _, err := s.Bind(ctx, &PodPolicy{PodUid: "pod-1", Policy: validTestPolicy()}); err != nil {
		t.Fatal(err)
	}

	// Make the stored file impossible to remove by replacing it with a non-empty directory.
	filePath := filepath.Join(storeDir, "pod-1.pb")
	if err := os.Remove(filePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filePath, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(filePath, "blocker"), []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}

	// Unbind must fail and leave pod bound in memory
	_, err := s.Unbind(ctx, &UnbindRequest{PodUid: "pod-1"})
	if err == nil {
		t.Fatal("expected Unbind to fail when stored file removal fails")
	}
	if status.Code(err) != codes.Internal {
		t.Errorf("expected Internal code, got %v", status.Code(err))
	}
	if s.Policy("pod-1") == nil {
		t.Error("pod policy must not be cleared from memory when unbind fails to remove stored file")
	}
}

func TestBindingStore_WaitMissingSecrets(t *testing.T) {
	ctx := t.Context()
	store := mustNewStore(t, "")

	twoSecretsPolicy := &EgressPolicy{
		Rules: []*EgressRule{
			{
				Https: &HttpsRule{
					Hostnames: []string{"api.github.com"},
					Effects: &HttpRuleEffects{
						ReplaceHeaders: []*CredentialHeader{
							{Header: "Authorization", CredentialUri: "secret://token-1"},
							{Header: "X-Api-Key", CredentialUri: "secret://token-2"},
						},
					},
				},
			},
		},
	}

	// 1. Bind with wait=true reports PENDING with all missing secrets
	bindResp, err := store.Bind(ctx, &PodPolicy{
		PodUid: "pod-1",
		Policy: twoSecretsPolicy,
		Wait:   true,
	})
	if err != nil {
		t.Fatalf("Bind with wait failed: %v", err)
	}
	if !bindResp.GetBound() {
		t.Errorf("expected bound = true")
	}
	if bindResp.GetStatus() != AcceptanceStatus_ACCEPTANCE_STATUS_PENDING {
		t.Errorf("status = %v, want PENDING", bindResp.GetStatus())
	}
	if want := []string{"token-1", "token-2"}; !slices.Equal(bindResp.GetMissingSecrets(), want) {
		t.Errorf("missing secrets = %v, want %v", bindResp.GetMissingSecrets(), want)
	}

	// 2. Inject one secret with wait=true reports PENDING with remaining missing secret
	injectResp, err := store.InjectSecrets(ctx, &PodSecrets{
		PodUid:  "pod-1",
		Secrets: map[string][]byte{"token-1": []byte("val-1")},
		Wait:    true,
	})
	if err != nil {
		t.Fatalf("InjectSecrets with wait failed: %v", err)
	}
	if injectResp.GetStatus() != AcceptanceStatus_ACCEPTANCE_STATUS_PENDING {
		t.Errorf("status = %v, want PENDING", injectResp.GetStatus())
	}
	if want := []string{"token-2"}; !slices.Equal(injectResp.GetMissingSecrets(), want) {
		t.Errorf("missing secrets = %v, want %v", injectResp.GetMissingSecrets(), want)
	}

	// 3. Inject all secrets with wait=true reports ACCEPTED with no missing secrets
	injectResp, err = store.InjectSecrets(ctx, &PodSecrets{
		PodUid:  "pod-1",
		Secrets: map[string][]byte{"token-1": []byte("val-1"), "token-2": []byte("val-2")},
		Wait:    true,
	})
	if err != nil {
		t.Fatalf("InjectSecrets with wait failed: %v", err)
	}
	if injectResp.GetStatus() != AcceptanceStatus_ACCEPTANCE_STATUS_ACCEPTED {
		t.Errorf("status = %v, want ACCEPTED", injectResp.GetStatus())
	}
	if len(injectResp.GetMissingSecrets()) != 0 {
		t.Errorf("missing secrets = %v, want empty", injectResp.GetMissingSecrets())
	}

	// 4. Bind with wait=false leaves status unspecified and missing secrets empty
	bindRespNoWait, err := store.Bind(ctx, &PodPolicy{
		PodUid: "pod-2",
		Policy: twoSecretsPolicy,
		Wait:   false,
	})
	if err != nil {
		t.Fatalf("Bind without wait failed: %v", err)
	}
	if bindRespNoWait.GetStatus() != AcceptanceStatus_ACCEPTANCE_STATUS_UNSPECIFIED {
		t.Errorf("status = %v, want UNSPECIFIED", bindRespNoWait.GetStatus())
	}
	if len(bindRespNoWait.GetMissingSecrets()) != 0 {
		t.Errorf("missing secrets = %v, want empty", bindRespNoWait.GetMissingSecrets())
	}
}
