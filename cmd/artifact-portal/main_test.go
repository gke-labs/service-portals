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
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gke-labs/service-portals/pkg/proxy"
)

func TestArtifactPortalCaching(t *testing.T) {
	cacheDir, err := os.MkdirTemp("", "artifact-portal-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(cacheDir)

	backendCallCount := 0
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendCallCount++
		w.Header().Set("Content-Type", "application/x-wheel+zip")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("package-content"))
	}))
	defer backend.Close()

	// Mock transport to redirect all requests to our mock backend
	p := &proxy.BaseProxy{
		Transport: &CachingTransport{
			Transport: &mockTransport{backendURL: backend.URL},
			CacheDir:  cacheDir,
		},
	}

	// 1. First request - Cache Miss
	req := httptest.NewRequest("GET", "http://files.pythonhosted.org/packages/test.whl", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("First request: expected status OK, got %v", resp.Status)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "package-content" {
		t.Errorf("First request: expected body 'package-content', got '%s'", string(body))
	}
	if backendCallCount != 1 {
		t.Errorf("First request: expected 1 backend call, got %d", backendCallCount)
	}

	// 2. Second request - Cache Hit
	w = httptest.NewRecorder()
	p.ServeHTTP(w, req)

	resp = w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Second request: expected status OK, got %v", resp.Status)
	}
	body, _ = io.ReadAll(resp.Body)
	if string(body) != "package-content" {
		t.Errorf("Second request: expected body 'package-content', got '%s'", string(body))
	}
	if backendCallCount != 1 {
		t.Errorf("Second request: expected NO additional backend call, got %d", backendCallCount)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/x-wheel+zip" {
		t.Errorf("Second request: expected Content-Type 'application/x-wheel+zip', got '%s'", ct)
	}
}

type mockTransport struct {
	backendURL string
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Rewrite request to point to backend
	newReq := req.Clone(req.Context())
	newReq.URL.Host = "localhost" // httptest.NewServer uses localhost
	// We need to keep the path but change the base URL
	// Actually easier to just create a new request
	req2, _ := http.NewRequest(req.Method, m.backendURL+req.URL.Path, req.Body)
	return http.DefaultTransport.RoundTrip(req2)
}
