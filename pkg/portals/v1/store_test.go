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
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

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
	store := NewBindingStore()

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
	store := NewBindingStore()

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
	store := NewBindingStore()

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
	store := NewBindingStore()

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
	s1 := NewBindingStore()
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
	s2 := NewBindingStore()
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
	store := NewBindingStore()

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
	store := NewBindingStore()
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
	store := NewBindingStore()
	grpcServer := grpc.NewServer()
	// Must not panic when registering (verifies testEmbeddedByValue)
	RegisterPodBindServiceServer(grpcServer, store)
}

func TestBindingStore_Acceptance(t *testing.T) {
	ctx := t.Context()
	store := NewBindingStore()

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
