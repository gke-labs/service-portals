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
	"bytes"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	portalsv1 "github.com/gke-labs/service-portals/pkg/portals/v1"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
)

func startTestBindService(t *testing.T) (string, *portalsv1.BindingStore) {
	t.Helper()
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "bind.sock")
	store, err := portalsv1.NewBindingStore("")
	if err != nil {
		t.Fatalf("failed to create BindingStore: %v", err)
	}

	l, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("failed to listen on unix socket %s: %v", sockPath, err)
	}

	srv := grpc.NewServer()
	portalsv1.RegisterPodBindServiceServer(srv, store)

	go func() {
		_ = srv.Serve(l)
	}()

	t.Cleanup(func() {
		srv.Stop()
		_ = l.Close()
	})

	return sockPath, store
}

func TestBindService_Lifecycle(t *testing.T) {
	sockPath, store := startTestBindService(t)
	podUID := "pod-lifecycle-test-uid"
	secretToken1 := "super-secret-token-xyz-12345"
	secretToken2 := "another-secret-key-67890"

	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	policyJSON := `{
  "rules": [
    {
      "http": {
        "hostnames": ["api.example.com"],
        "ports": {"numbers": [80]}
      }
    }
  ]
}`
	if err := os.WriteFile(policyPath, []byte(policyJSON), 0600); err != nil {
		t.Fatalf("failed to write policy file: %v", err)
	}

	secretsPath := filepath.Join(dir, "secrets.json")
	secretsJSON := `{
  "github-token": "` + secretToken1 + `",
  "api-key": "` + secretToken2 + `"
}`
	if err := os.WriteFile(secretsPath, []byte(secretsJSON), 0600); err != nil {
		t.Fatalf("failed to write secrets file: %v", err)
	}

	var allOutput bytes.Buffer

	// 1. Bind egress policy
	{
		var stdout bytes.Buffer
		err := runBindServiceCommand(t.Context(), []string{
			"bind",
			"-socket", sockPath,
			"-uid", podUID,
			"-identity", "test-user-alice",
			"-policy-file", policyPath,
		}, &stdout, nil)
		allOutput.Write(stdout.Bytes())
		if err != nil {
			t.Fatalf("bind command failed: %v", err)
		}
		if p := store.Policy(podUID); p == nil {
			t.Fatalf("expected policy to be bound in store")
		} else if len(p.GetRules()) != 1 || p.GetRules()[0].GetHttp().GetHostnames()[0] != "api.example.com" {
			t.Errorf("unexpected policy in store: %+v", p)
		}
	}

	// 2. Read binding back with get
	{
		var stdout bytes.Buffer
		err := runBindServiceCommand(t.Context(), []string{
			"get",
			"-socket", sockPath,
			"-uid", podUID,
		}, &stdout, nil)
		allOutput.Write(stdout.Bytes())
		if err != nil {
			t.Fatalf("get command failed: %v", err)
		}
		var getResp portalsv1.GetResponse
		if err := protojson.Unmarshal(stdout.Bytes(), &getResp); err != nil {
			t.Fatalf("failed to unmarshal get output: %v (output: %s)", err, stdout.String())
		}
		if !getResp.GetBound() {
			t.Errorf("expected get output to report bound: true")
		}
		if getResp.GetIdentity() != "test-user-alice" {
			t.Errorf("expected get output to contain identity test-user-alice, got %q", getResp.GetIdentity())
		}
		if len(getResp.GetPolicy().GetRules()) != 1 || getResp.GetPolicy().GetRules()[0].GetHttp().GetHostnames()[0] != "api.example.com" {
			t.Errorf("expected get output to contain policy rule for api.example.com, got %+v", getResp.GetPolicy())
		}
	}

	// 3. Inject named secrets from a file
	{
		var stdout bytes.Buffer
		err := runBindServiceCommand(t.Context(), []string{
			"inject-secrets",
			"-socket", sockPath,
			"-uid", podUID,
			"-secrets-file", secretsPath,
		}, &stdout, nil)
		allOutput.Write(stdout.Bytes())
		if err != nil {
			t.Fatalf("inject-secrets command failed: %v", err)
		}

		// Verify secrets are resolvable in the store
		sec1, ok1 := store.ResolveSecret(podUID, "github-token")
		if !ok1 || string(sec1.Bytes()) != secretToken1 {
			t.Errorf("store.ResolveSecret(github-token) = %v, %v; want %q, true", sec1, ok1, secretToken1)
		}
		sec2, ok2 := store.ResolveSecret(podUID, "api-key")
		if !ok2 || string(sec2.Bytes()) != secretToken2 {
			t.Errorf("store.ResolveSecret(api-key) = %v, %v; want %q, true", sec2, ok2, secretToken2)
		}
	}

	// 4. Unbind pod
	{
		var stdout bytes.Buffer
		err := runBindServiceCommand(t.Context(), []string{
			"unbind",
			"-socket", sockPath,
			"-uid", podUID,
		}, &stdout, nil)
		allOutput.Write(stdout.Bytes())
		if err != nil {
			t.Fatalf("unbind command failed: %v", err)
		}

		// Verify unbind removed both policy and secrets
		if p := store.Policy(podUID); p != nil {
			t.Errorf("expected policy to be removed after unbind, got %+v", p)
		}
		if _, ok := store.ResolveSecret(podUID, "github-token"); ok {
			t.Errorf("expected secrets to be removed after unbind")
		}
	}

	// 5. Read binding back after unbind
	{
		var stdout bytes.Buffer
		err := runBindServiceCommand(t.Context(), []string{
			"get",
			"-socket", sockPath,
			"-uid", podUID,
		}, &stdout, nil)
		allOutput.Write(stdout.Bytes())
		if err != nil {
			t.Fatalf("get command failed: %v", err)
		}
		var getResp portalsv1.GetResponse
		if err := protojson.Unmarshal(stdout.Bytes(), &getResp); err != nil {
			t.Fatalf("failed to unmarshal get output after unbind: %v (output: %s)", err, stdout.String())
		}
		if getResp.GetBound() {
			t.Errorf("expected get output after unbind to report bound: false, got true")
		}
	}

	// 6. Security rule: secret values must NEVER appear in output
	combined := allOutput.String()
	if strings.Contains(combined, secretToken1) {
		t.Fatalf("security violation: secret token 1 leaked in output: %q", combined)
	}
	if strings.Contains(combined, secretToken2) {
		t.Fatalf("security violation: secret token 2 leaked in output: %q", combined)
	}
}

func TestBindService_InvalidPolicy(t *testing.T) {
	sockPath, store := startTestBindService(t)
	podUID := "pod-invalid-policy-uid"

	dir := t.TempDir()
	invalidPolicyPath := filepath.Join(dir, "invalid_policy.json")
	// Empty hostname fails EgressPolicy.Validate()
	invalidPolicyJSON := `{
  "rules": [
    {
      "http": {
        "hostnames": [""]
      }
    }
  ]
}`
	if err := os.WriteFile(invalidPolicyPath, []byte(invalidPolicyJSON), 0600); err != nil {
		t.Fatalf("failed to write invalid policy file: %v", err)
	}

	var stdout bytes.Buffer
	err := runBindServiceCommand(t.Context(), []string{
		"bind",
		"-socket", sockPath,
		"-uid", podUID,
		"-policy-file", invalidPolicyPath,
	}, &stdout, nil)

	if err == nil {
		t.Fatalf("expected bind command to return error for invalid policy, got nil")
	}

	if !strings.Contains(err.Error(), "invalid hostname pattern") {
		t.Errorf("expected server validation message in error, got %q", err.Error())
	}

	// Verify nothing is bound
	if p := store.Policy(podUID); p != nil {
		t.Errorf("expected no policy to be bound in store after invalid policy rejection, got %+v", p)
	}
}

func TestBindService_SecretsViaStdin(t *testing.T) {
	sockPath, store := startTestBindService(t)
	podUID := "pod-stdin-secrets-uid"
	stdinSecret := "stdin-secret-token-value-abc-987"

	secretsJSON := `{
  "stdin-token": "` + stdinSecret + `"
}`

	var stdout bytes.Buffer
	err := runBindServiceCommand(t.Context(), []string{
		"inject-secrets",
		"-socket", sockPath,
		"-uid", podUID,
		"-secrets-file", "-",
	}, &stdout, strings.NewReader(secretsJSON))

	if err != nil {
		t.Fatalf("inject-secrets from stdin failed: %v", err)
	}

	sec, ok := store.ResolveSecret(podUID, "stdin-token")
	if !ok || string(sec.Bytes()) != stdinSecret {
		t.Fatalf("expected stdin secret to be resolved in store, got %v, %v", sec, ok)
	}

	if strings.Contains(stdout.String(), stdinSecret) {
		t.Fatalf("secret leaked in stdin command output")
	}
}

func TestBindService_MalformedSecrets(t *testing.T) {
	sockPath, _ := startTestBindService(t)
	podUID := "pod-malformed-secrets-uid"
	secretToken := "super-secret-that-must-not-leak-999"

	dir := t.TempDir()
	malformedPath := filepath.Join(dir, "malformed_secrets.json")
	// Malformed JSON that contains secret token followed by invalid syntax
	malformedJSON := `{"token": "` + secretToken + `", invalid-syntax`
	if err := os.WriteFile(malformedPath, []byte(malformedJSON), 0600); err != nil {
		t.Fatalf("failed to write malformed secrets file: %v", err)
	}

	var stdout bytes.Buffer
	err := runBindServiceCommand(t.Context(), []string{
		"inject-secrets",
		"-socket", sockPath,
		"-uid", podUID,
		"-secrets-file", malformedPath,
	}, &stdout, nil)

	if err == nil {
		t.Fatalf("expected inject-secrets command to return error for malformed secrets file, got nil")
	}

	if !strings.Contains(err.Error(), "secrets file is not valid") {
		t.Errorf("expected fixed validation error, got %q", err.Error())
	}

	combinedOutput := stdout.String() + " " + err.Error()
	if strings.Contains(combinedOutput, secretToken) {
		t.Fatalf("security violation: secret leaked in error output for malformed secrets file: %q", combinedOutput)
	}
	if strings.Contains(combinedOutput, "invalid-syntax") {
		t.Fatalf("security violation: file content leaked in error output: %q", combinedOutput)
	}
}

func TestBindService_PolicyViaStdin(t *testing.T) {
	sockPath, store := startTestBindService(t)
	podUID := "pod-stdin-policy-uid"

	policyJSON := `{
  "rules": [
    {
      "https": {
        "hostnames": ["secure.example.com"],
        "ports": {"numbers": [443]}
      }
    }
  ]
}`

	var stdout bytes.Buffer
	err := runBindServiceCommand(t.Context(), []string{
		"bind",
		"-socket", sockPath,
		"-uid", podUID,
		"-policy-file", "-",
	}, &stdout, strings.NewReader(policyJSON))

	if err != nil {
		t.Fatalf("bind from stdin failed: %v", err)
	}

	p := store.Policy(podUID)
	if p == nil || len(p.GetRules()) != 1 || p.GetRules()[0].GetHttps().GetHostnames()[0] != "secure.example.com" {
		t.Fatalf("unexpected policy bound from stdin: %+v", p)
	}
}

func TestBindService_FlagValidation(t *testing.T) {
	var stdout bytes.Buffer
	ctx := t.Context()

	// No action args
	if err := runBindServiceCommand(ctx, []string{}, &stdout, nil); err == nil {
		t.Errorf("expected error for empty args")
	}

	// Unknown action
	if err := runBindServiceCommand(ctx, []string{"invalid-action"}, &stdout, nil); err == nil {
		t.Errorf("expected error for unknown action")
	}

	// bind missing -uid or -policy-file
	if err := runBindServiceCommand(ctx, []string{"bind", "-uid", "test"}, &stdout, nil); err == nil {
		t.Errorf("expected error for bind missing -policy-file")
	}
	if err := runBindServiceCommand(ctx, []string{"bind", "-policy-file", "test.json"}, &stdout, nil); err == nil {
		t.Errorf("expected error for bind missing -uid")
	}

	// inject-secrets missing -uid or -secrets-file
	if err := runBindServiceCommand(ctx, []string{"inject-secrets", "-uid", "test"}, &stdout, nil); err == nil {
		t.Errorf("expected error for inject-secrets missing -secrets-file")
	}
	if err := runBindServiceCommand(ctx, []string{"inject-secrets", "-secrets-file", "sec.json"}, &stdout, nil); err == nil {
		t.Errorf("expected error for inject-secrets missing -uid")
	}

	// get missing -uid
	if err := runBindServiceCommand(ctx, []string{"get"}, &stdout, nil); err == nil {
		t.Errorf("expected error for get missing -uid")
	}

	// unbind missing -uid
	if err := runBindServiceCommand(ctx, []string{"unbind"}, &stdout, nil); err == nil {
		t.Errorf("expected error for unbind missing -uid")
	}
}
