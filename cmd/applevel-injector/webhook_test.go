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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMutatePod_OptedIn(t *testing.T) {
	podJSON := []byte(`{
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": "my-workload",
			"namespace": "test",
			"labels": {
				"portal.gke.io/enabled": "true"
			}
		},
		"spec": {
			"containers": [
				{
					"name": "workload",
					"image": "busybox:latest"
				}
			]
		}
	}`)

	patches, mutated, err := mutatePod(podJSON, "http://service-portal:8080", "/etc/service-portal/ca/tls.crt", "service-portal-ca")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !mutated {
		t.Fatal("expected pod to be mutated")
	}

	patchBytes, err := json.Marshal(patches)
	if err != nil {
		t.Fatalf("failed to marshal patches: %v", err)
	}
	patchStr := string(patchBytes)

	// Verify env vars injected
	expectedEnv := []string{
		"HTTP_PROXY",
		"HTTPS_PROXY",
		"http_proxy",
		"https_proxy",
		"NO_PROXY",
		"SSL_CERT_FILE",
		"REQUESTS_CA_BUNDLE",
		"NODE_EXTRA_CA_CERTS",
		"CURL_CA_BUNDLE",
	}
	for _, env := range expectedEnv {
		if !strings.Contains(patchStr, env) {
			t.Errorf("patch missing env var %s: %s", env, patchStr)
		}
	}

	// Verify volume mount and volume
	if !strings.Contains(patchStr, "/etc/service-portal/ca") {
		t.Errorf("patch missing CA volume mount: %s", patchStr)
	}
	if !strings.Contains(patchStr, "service-portal-ca") {
		t.Errorf("patch missing CA volume name: %s", patchStr)
	}
}

func TestMutatePod_NotOptedIn(t *testing.T) {
	podJSON := []byte(`{
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": "unrelated-pod",
			"namespace": "test"
		},
		"spec": {
			"containers": [
				{
					"name": "workload",
					"image": "busybox:latest"
				}
			]
		}
	}`)

	patches, mutated, err := mutatePod(podJSON, "http://service-portal:8080", "/etc/service-portal/ca/tls.crt", "service-portal-ca")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mutated {
		t.Error("expected pod NOT to be mutated")
	}
	if len(patches) > 0 {
		t.Errorf("expected 0 patches, got %d", len(patches))
	}
}

func TestHandleMutate_HTTPHandler(t *testing.T) {
	reqBody := `{
		"apiVersion": "admission.k8s.io/v1",
		"kind": "AdmissionReview",
		"request": {
			"uid": "test-uid-1234",
			"namespace": "test-ns",
			"object": {
				"apiVersion": "v1",
				"kind": "Pod",
				"metadata": {
					"name": "sandbox",
					"labels": {
						"portal.gke.io/app-level": "true"
					}
				},
				"spec": {
					"containers": [
						{
							"name": "app",
							"image": "node:20"
						}
					]
				}
			}
		}
	}`

	req := httptest.NewRequest(http.MethodPost, "/mutate", bytes.NewBufferString(reqBody))
	rec := httptest.NewRecorder()

	handleMutate(rec, req, "http://service-portal:8080", "/etc/service-portal/ca/tls.crt", "service-portal-ca")

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var respReview AdmissionReview
	if err := json.Unmarshal(rec.Body.Bytes(), &respReview); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if respReview.Response == nil {
		t.Fatal("response is nil")
	}
	if !respReview.Response.Allowed {
		t.Error("expected allowed = true")
	}
	if respReview.Response.PatchType != "JSONPatch" {
		t.Errorf("expected patchType JSONPatch, got %s", respReview.Response.PatchType)
	}
	if len(respReview.Response.Patch) == 0 {
		t.Error("expected non-empty patch")
	}
	if string(respReview.Response.UID) != "test-uid-1234" {
		t.Errorf("expected UID test-uid-1234, got %s", respReview.Response.UID)
	}
}
