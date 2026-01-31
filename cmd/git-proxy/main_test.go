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
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

func TestGitProxy(t *testing.T) {
	// 1. Start a mock backend
	backendHits := 0
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendHits++
		if r.URL.Path == "/google/re2.git/info/refs" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("git-refs"))
			return
		}
		if r.URL.Path == "/google/re2.git/objects/00/112233" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("git-object-data"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer backend.Close()

	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("Failed to parse backend URL: %v", err)
	}

	cacheDir, err := os.MkdirTemp("", "git-cache-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(cacheDir)

	// 2. Create the proxy
	proxy := newGitProxy(backendURL, cacheDir)

	// 3. Test non-cacheable request
	req := httptest.NewRequest("GET", "http://localhost:8080/google/re2.git/info/refs?service=git-upload-pack", nil)
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)
	if w.Code != http.StatusOK || w.Body.String() != "git-refs" {
		t.Errorf("info/refs failed: %d %s", w.Code, w.Body.String())
	}

	// 4. Test cacheable request (first time - should hit backend)
	req = httptest.NewRequest("GET", "http://localhost:8080/google/re2.git/objects/00/112233", nil)
	w = httptest.NewRecorder()
	proxy.ServeHTTP(w, req)
	if w.Code != http.StatusOK || w.Body.String() != "git-object-data" {
		t.Errorf("object request failed: %d %s", w.Code, w.Body.String())
	}
	if backendHits != 2 {
		t.Errorf("Expected 2 backend hits, got %d", backendHits)
	}

	// Verify file is in cache
	cacheFile := filepath.Join(cacheDir, "/google/re2.git/objects/00/112233")
	if _, err := os.Stat(cacheFile); os.IsNotExist(err) {
		t.Errorf("Cache file %s was not created", cacheFile)
	}

	// 5. Test cacheable request (second time - should NOT hit backend)
	w = httptest.NewRecorder()
	proxy.ServeHTTP(w, req)
	if w.Code != http.StatusOK || w.Body.String() != "git-object-data" {
		t.Errorf("second object request failed: %d %s", w.Code, w.Body.String())
	}
	if backendHits != 2 {
		t.Errorf("Expected still 2 backend hits, got %d", backendHits)
	}
}

func TestIsGitRequest(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{"/repo.git/info/refs", true},
		{"/repo.git/git-upload-pack", true},
		{"/repo.git/git-receive-pack", true},
		{"/repo.git/objects/00/11223344", true},
		{"/just/some/path", false},
		{"/favicon.ico", false},
	}

	for _, tc := range tests {
		req := httptest.NewRequest("GET", "http://localhost"+tc.path, nil)
		if got := isGitRequest(req); got != tc.expected {
			t.Errorf("isGitRequest(%q) = %v, want %v", tc.path, got, tc.expected)
		}
	}
}