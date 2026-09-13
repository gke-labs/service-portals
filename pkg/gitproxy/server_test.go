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

package gitproxy

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gke-labs/service-portals/pkg/cache"
)

func TestGitProxyRefRequestsNeverCached(t *testing.T) {
	var upstreamHits int32

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits := atomic.AddInt32(&upstreamHits, 1)
		w.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "001e# service=git-upload-pack\n00000032%04d refs/heads/main\n0000", hits)
	}))
	defer backend.Close()

	u, _ := url.Parse(backend.URL)
	c := cache.NewInMemoryCache(1 * time.Minute)
	s := NewServer(Config{
		DefaultTargetURL: backend.URL,
		Cache:            c,
		CacheTTL:         10 * time.Minute,
		Transport:        backend.Client().Transport,
	})

	// First refs request
	req1 := httptest.NewRequest("GET", fmt.Sprintf("/%s/repo.git/info/refs?service=git-upload-pack", u.Host), nil)
	w1 := httptest.NewRecorder()
	s.ServeHTTP(w1, req1)

	if w1.Header().Get("X-Git-Cache") != "BYPASS" {
		t.Errorf("expected X-Git-Cache: BYPASS, got %s", w1.Header().Get("X-Git-Cache"))
	}
	body1 := w1.Body.String()

	// Second refs request - must still hit upstream and return new ref data
	req2 := httptest.NewRequest("GET", fmt.Sprintf("/%s/repo.git/info/refs?service=git-upload-pack", u.Host), nil)
	w2 := httptest.NewRecorder()
	s.ServeHTTP(w2, req2)

	if w2.Header().Get("X-Git-Cache") != "BYPASS" {
		t.Errorf("expected X-Git-Cache: BYPASS, got %s", w2.Header().Get("X-Git-Cache"))
	}
	body2 := w2.Body.String()

	if atomic.LoadInt32(&upstreamHits) != 2 {
		t.Fatalf("expected 2 upstream hits for ref requests, got %d", atomic.LoadInt32(&upstreamHits))
	}
	if body1 == body2 {
		t.Errorf("expected different ref bodies from upstream, but got identical: %s", body1)
	}
}

func TestGitProxyUploadPackFetchCached(t *testing.T) {
	var upstreamHits int32

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&upstreamHits, 1)
		w.Header().Set("Content-Type", "application/x-git-upload-pack-result")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("PACK-DATA-BINARY-STREAM-CONTENT"))
	}))
	defer backend.Close()

	u, _ := url.Parse(backend.URL)
	c := cache.NewInMemoryCache(1 * time.Minute)
	s := NewServer(Config{
		DefaultTargetURL: backend.URL,
		Cache:            c,
		CacheTTL:         10 * time.Minute,
		Transport:        backend.Client().Transport,
	})

	fetchBody := []byte("0032want 7f83b1657ff1fc5354dc1008ecf50686d3c52b78\n00000009done\n")

	// First fetch request -> MISS
	req1 := httptest.NewRequest("POST", fmt.Sprintf("/%s/repo.git/git-upload-pack", u.Host), bytes.NewReader(fetchBody))
	w1 := httptest.NewRecorder()
	s.ServeHTTP(w1, req1)

	if w1.Header().Get("X-Git-Cache") != "MISS" {
		t.Errorf("expected X-Git-Cache: MISS on first request, got %s", w1.Header().Get("X-Git-Cache"))
	}
	if w1.Body.String() != "PACK-DATA-BINARY-STREAM-CONTENT" {
		t.Errorf("unexpected body: %s", w1.Body.String())
	}

	// Second fetch request with same body -> HIT
	req2 := httptest.NewRequest("POST", fmt.Sprintf("/%s/repo.git/git-upload-pack", u.Host), bytes.NewReader(fetchBody))
	w2 := httptest.NewRecorder()
	s.ServeHTTP(w2, req2)

	if w2.Header().Get("X-Git-Cache") != "HIT" {
		t.Errorf("expected X-Git-Cache: HIT on second request, got %s", w2.Header().Get("X-Git-Cache"))
	}
	if w2.Body.String() != "PACK-DATA-BINARY-STREAM-CONTENT" {
		t.Errorf("unexpected body: %s", w2.Body.String())
	}

	if atomic.LoadInt32(&upstreamHits) != 1 {
		t.Fatalf("expected exactly 1 upstream hit, got %d", atomic.LoadInt32(&upstreamHits))
	}
}

func TestGitProxyObjectRequestCachedOnDisk(t *testing.T) {
	var upstreamHits int32
	tmpDir := t.TempDir()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&upstreamHits, 1)
		w.Header().Set("Content-Type", "application/x-git-packed-objects")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("PACKFILE-CONTENT-1234567890"))
	}))
	defer backend.Close()

	u, _ := url.Parse(backend.URL)
	diskCache, err := cache.NewDiskCache(tmpDir, 10*time.Minute, 1*time.Minute)
	if err != nil {
		t.Fatalf("failed to create disk cache: %v", err)
	}

	s := NewServer(Config{
		DefaultTargetURL: backend.URL,
		Cache:            diskCache,
		CacheTTL:         10 * time.Minute,
		Transport:        backend.Client().Transport,
	})

	packPath := fmt.Sprintf("/%s/repo.git/objects/pack/pack-1234567890abcdef1234567890abcdef12345678.pack", u.Host)

	// First request -> MISS
	req1 := httptest.NewRequest("GET", packPath, nil)
	w1 := httptest.NewRecorder()
	s.ServeHTTP(w1, req1)

	if w1.Header().Get("X-Git-Cache") != "MISS" {
		t.Errorf("expected X-Git-Cache: MISS on first request, got %s", w1.Header().Get("X-Git-Cache"))
	}

	// Second request -> HIT
	req2 := httptest.NewRequest("GET", packPath, nil)
	w2 := httptest.NewRecorder()
	s.ServeHTTP(w2, req2)

	if w2.Header().Get("X-Git-Cache") != "HIT" {
		t.Errorf("expected X-Git-Cache: HIT on second request, got %s", w2.Header().Get("X-Git-Cache"))
	}

	if atomic.LoadInt32(&upstreamHits) != 1 {
		t.Fatalf("expected 1 upstream hit, got %d", atomic.LoadInt32(&upstreamHits))
	}
}

func TestGitProxyAuthTokenInjection(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer token-123" {
			t.Errorf("expected Authorization: Bearer token-123, got %s", auth)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("AUTHENTICATED"))
	}))
	defer backend.Close()

	u, _ := url.Parse(backend.URL)
	s := NewServer(Config{
		DefaultTargetURL:  backend.URL,
		DefaultAuthToken:  "token-123",
		DefaultAuthHeader: "Authorization",
		Transport:         backend.Client().Transport,
	})

	req := httptest.NewRequest("GET", fmt.Sprintf("/%s/repo.git/info/refs?service=git-upload-pack", u.Host), nil)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
	if w.Body.String() != "AUTHENTICATED" {
		t.Errorf("unexpected body: %s", w.Body.String())
	}
}

// TestGitCliWithProxy runs real git commands (clone, add commit, fetch, pull) against a mock git backend through gitproxy.
func TestGitCliWithProxy(t *testing.T) {
	gitBackendPath, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not installed, skipping CLI test")
	}

	// 1. Create a bare git repository as upstream
	upstreamDir := t.TempDir()
	gitDir := filepath.Join(upstreamDir, "repo.git")

	initCmd := exec.Command("git", "init", "--bare", "-b", "main", gitDir)
	if out, err := initCmd.CombinedOutput(); err != nil {
		t.Fatalf("git init --bare failed: %v, output: %s", err, out)
	}

	// Enable receive-pack and upload-pack in bare repo
	exec.Command("git", "-C", gitDir, "config", "http.receivepack", "true").Run()
	exec.Command("git", "-C", gitDir, "config", "http.uploadpack", "true").Run()

	// Seed the bare repo with initial commit
	seedDir := t.TempDir()
	exec.Command("git", "init", seedDir).Run()
	exec.Command("git", "-C", seedDir, "config", "user.email", "test@example.com").Run()
	exec.Command("git", "-C", seedDir, "config", "user.name", "Test User").Run()
	os.WriteFile(filepath.Join(seedDir, "file.txt"), []byte("initial content"), 0644)
	exec.Command("git", "-C", seedDir, "add", ".").Run()
	exec.Command("git", "-C", seedDir, "commit", "-m", "Initial commit").Run()
	exec.Command("git", "-C", seedDir, "push", gitDir, "HEAD:main").Run()

	// 2. Set up git http-backend server as upstream
	var fetchHits int32
	var lsRefsHits int32
	var refsHits int32

	httpBackendHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("service") == "git-upload-pack" || strings.HasSuffix(r.URL.Path, "/info/refs") {
			atomic.AddInt32(&refsHits, 1)
		}
		if strings.HasSuffix(r.URL.Path, "/git-upload-pack") && r.Method == http.MethodPost {
			body, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(body))
			if HasFetchCommand(body) {
				atomic.AddInt32(&fetchHits, 1)
			} else if HasLsRefsCommand(body) {
				atomic.AddInt32(&lsRefsHits, 1)
			}
		}

		cgiHandler := &cgi.Handler{
			Path: gitBackendPath,
			Args: []string{"http-backend"},
			Env: []string{
				"GIT_PROJECT_ROOT=" + upstreamDir,
				"GIT_HTTP_EXPORT_ALL=true",
				"REMOTE_USER=test",
			},
		}
		cgiHandler.ServeHTTP(w, r)
	})

	upstreamServer := httptest.NewServer(httpBackendHandler)
	defer upstreamServer.Close()

	// 3. Start GitProxy server
	c := cache.NewInMemoryCache(1 * time.Minute)
	proxyServer := httptest.NewServer(NewServer(Config{
		DefaultTargetURL: upstreamServer.URL,
		Cache:            c,
		CacheTTL:         10 * time.Minute,
		Transport:        upstreamServer.Client().Transport,
	}))
	defer proxyServer.Close()

	// 4. Test git clone using insteadOf
	clientDir := t.TempDir()
	upstreamRepoURL := fmt.Sprintf("%s/repo.git", upstreamServer.URL)
	proxyRepoURL := fmt.Sprintf("%s/%s/repo.git", proxyServer.URL, strings.TrimPrefix(upstreamServer.URL, "http://"))

	// Clone 1: first client clone
	clone1Dir := filepath.Join(clientDir, "clone1")
	cloneCmd1 := exec.Command("git",
		"-c", fmt.Sprintf("url.%s/.insteadOf=%s/", proxyServer.URL, upstreamServer.URL),
		"clone", upstreamRepoURL, clone1Dir)
	if out, err := cloneCmd1.CombinedOutput(); err != nil {
		t.Fatalf("first git clone failed: %v, output: %s", err, out)
	}

	content1, err := os.ReadFile(filepath.Join(clone1Dir, "file.txt"))
	if err != nil || string(content1) != "initial content" {
		t.Fatalf("unexpected content in clone 1: %s, err: %v", string(content1), err)
	}

	fetchHitsAfterClone1 := atomic.LoadInt32(&fetchHits)
	if fetchHitsAfterClone1 < 1 {
		t.Fatalf("expected at least 1 fetch hit after clone 1, got %d", fetchHitsAfterClone1)
	}

	// Clone 2: second client clone (should hit cache for upload-pack blobs!)
	clone2Dir := filepath.Join(clientDir, "clone2")
	cloneCmd2 := exec.Command("git",
		"-c", fmt.Sprintf("url.%s/.insteadOf=%s/", proxyServer.URL, upstreamServer.URL),
		"clone", upstreamRepoURL, clone2Dir)
	if out, err := cloneCmd2.CombinedOutput(); err != nil {
		t.Fatalf("second git clone failed: %v, output: %s", err, out)
	}

	fetchHitsAfterClone2 := atomic.LoadInt32(&fetchHits)
	if fetchHitsAfterClone2 != fetchHitsAfterClone1 {
		t.Fatalf("expected cache HIT on second clone (fetch hits unchanged), but hits went from %d to %d",
			fetchHitsAfterClone1, fetchHitsAfterClone2)
	}

	lsRefsHitsAfterClone2 := atomic.LoadInt32(&lsRefsHits)
	if lsRefsHitsAfterClone2 < 2 {
		t.Fatalf("expected ls-refs to hit upstream for ref discovery on each clone, but got %d", lsRefsHitsAfterClone2)
	}

	// 5. Push a new commit upstream and verify fetch picks up new ref and fetches new objects
	os.WriteFile(filepath.Join(seedDir, "file.txt"), []byte("second content"), 0644)
	exec.Command("git", "-C", seedDir, "add", ".").Run()
	exec.Command("git", "-C", seedDir, "commit", "-m", "Second commit").Run()
	exec.Command("git", "-C", seedDir, "push", gitDir, "HEAD:main").Run()

	// Run git pull in clone1
	pullCmd := exec.Command("git", "-C", clone1Dir,
		"-c", fmt.Sprintf("url.%s/.insteadOf=%s/", proxyServer.URL, upstreamServer.URL),
		"pull")
	if out, err := pullCmd.CombinedOutput(); err != nil {
		t.Fatalf("git pull failed: %v, output: %s", err, out)
	}

	contentUpdated, err := os.ReadFile(filepath.Join(clone1Dir, "file.txt"))
	if err != nil || string(contentUpdated) != "second content" {
		t.Fatalf("unexpected content after pull: %s, err: %v", string(contentUpdated), err)
	}

	// 6. Test git push using pushInsteadOf and direct push
	exec.Command("git", "-C", clone1Dir, "config", "user.email", "test@example.com").Run()
	exec.Command("git", "-C", clone1Dir, "config", "user.name", "Test User").Run()
	pushFile := filepath.Join(clone1Dir, "pushed.txt")
	os.WriteFile(pushFile, []byte("pushed content"), 0644)
	if out, err := exec.Command("git", "-C", clone1Dir, "add", ".").CombinedOutput(); err != nil {
		t.Fatalf("git add failed: %v, output: %s", err, out)
	}
	if out, err := exec.Command("git", "-C", clone1Dir, "commit", "-m", "Pushed commit").CombinedOutput(); err != nil {
		t.Fatalf("git commit failed: %v, output: %s", err, out)
	}

	// Push using pushInsteadOf to bypass proxy directly to upstream
	pushCmd := exec.Command("git", "-C", clone1Dir,
		"-c", fmt.Sprintf("url.%s/.insteadOf=%s/", proxyServer.URL, upstreamServer.URL),
		"-c", fmt.Sprintf("url.%s/.pushInsteadOf=%s/", upstreamServer.URL, upstreamServer.URL),
		"push", "origin", "main")
	if out, err := pushCmd.CombinedOutput(); err != nil {
		t.Fatalf("git push with pushInsteadOf failed: %v, output: %s", err, out)
	}

	// Clone to a new client to verify pushed commit
	clone3Dir := filepath.Join(clientDir, "clone3")
	cloneCmd3 := exec.Command("git",
		"-c", fmt.Sprintf("url.%s/.insteadOf=%s/", proxyServer.URL, upstreamServer.URL),
		"clone", upstreamRepoURL, clone3Dir)
	if out, err := cloneCmd3.CombinedOutput(); err != nil {
		t.Fatalf("third git clone failed: %v, output: %s", err, out)
	}

	contentPushed, err := os.ReadFile(filepath.Join(clone3Dir, "pushed.txt"))
	if err != nil || string(contentPushed) != "pushed content" {
		t.Fatalf("unexpected content after clone 3: %s, err: %v", string(contentPushed), err)
	}

	_ = proxyRepoURL
}

func TestGitProxyIncrementalCachingAndPruning(t *testing.T) {
	gitBackendPath, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not installed, skipping CLI test")
	}

	// 1. Create a bare git repository as upstream
	upstreamDir := t.TempDir()
	gitDir := filepath.Join(upstreamDir, "repo.git")

	initCmd := exec.Command("git", "init", "--bare", "-b", "main", gitDir)
	if out, err := initCmd.CombinedOutput(); err != nil {
		t.Fatalf("git init --bare failed: %v, output: %s", err, out)
	}
	exec.Command("git", "-C", gitDir, "config", "http.receivepack", "true").Run()
	exec.Command("git", "-C", gitDir, "config", "http.uploadpack", "true").Run()

	// Seed bare repo with Commit C1
	seedDir := t.TempDir()
	exec.Command("git", "init", seedDir).Run()
	exec.Command("git", "-C", seedDir, "config", "user.email", "test@example.com").Run()
	exec.Command("git", "-C", seedDir, "config", "user.name", "Test User").Run()
	os.WriteFile(filepath.Join(seedDir, "file1.txt"), []byte("commit 1 content"), 0644)
	exec.Command("git", "-C", seedDir, "add", ".").Run()
	exec.Command("git", "-C", seedDir, "commit", "-m", "Commit 1").Run()
	exec.Command("git", "-C", seedDir, "push", gitDir, "HEAD:main").Run()

	var fetchHits int32

	httpBackendHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/git-upload-pack") && r.Method == http.MethodPost {
			body, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(body))
			if HasFetchCommand(body) {
				atomic.AddInt32(&fetchHits, 1)
			}
		}

		cgiHandler := &cgi.Handler{
			Path: gitBackendPath,
			Args: []string{"http-backend"},
			Env: []string{
				"GIT_PROJECT_ROOT=" + upstreamDir,
				"GIT_HTTP_EXPORT_ALL=true",
				"REMOTE_USER=test",
			},
		}
		cgiHandler.ServeHTTP(w, r)
	})

	upstreamServer := httptest.NewServer(httpBackendHandler)
	defer upstreamServer.Close()

	c := cache.NewInMemoryCache(1 * time.Minute)
	proxyServer := httptest.NewServer(NewServer(Config{
		DefaultTargetURL: upstreamServer.URL,
		Cache:            c,
		CacheTTL:         10 * time.Minute,
		Transport:        upstreamServer.Client().Transport,
	}))
	defer proxyServer.Close()

	clientDir := t.TempDir()
	upstreamRepoURL := fmt.Sprintf("%s/repo.git", upstreamServer.URL)

	// Client 1 clones C1 via proxy -> MISS (fetchHits = 1)
	clone1Dir := filepath.Join(clientDir, "clone1")
	cloneCmd1 := exec.Command("git",
		"-c", fmt.Sprintf("url.%s/.insteadOf=%s/", proxyServer.URL, upstreamServer.URL),
		"clone", upstreamRepoURL, clone1Dir)
	if out, err := cloneCmd1.CombinedOutput(); err != nil {
		t.Fatalf("first clone failed: %v, output: %s", err, out)
	}

	if hits := atomic.LoadInt32(&fetchHits); hits != 1 {
		t.Fatalf("expected 1 fetch hit after clone 1, got %d", hits)
	}

	// Create commit C2 and C3 on upstream
	os.WriteFile(filepath.Join(seedDir, "file2.txt"), []byte("commit 2 content"), 0644)
	exec.Command("git", "-C", seedDir, "add", ".").Run()
	exec.Command("git", "-C", seedDir, "commit", "-m", "Commit 2").Run()
	os.WriteFile(filepath.Join(seedDir, "file3.txt"), []byte("commit 3 content"), 0644)
	exec.Command("git", "-C", seedDir, "add", ".").Run()
	exec.Command("git", "-C", seedDir, "commit", "-m", "Commit 3").Run()
	exec.Command("git", "-C", seedDir, "push", gitDir, "HEAD:main").Run()

	// Client 2 clones from scratch (wants C3, haves none) -> Proxy fetches delta/full from upstream (fetchHits = 2)
	clone2Dir := filepath.Join(clientDir, "clone2")
	cloneCmd2 := exec.Command("git",
		"-c", fmt.Sprintf("url.%s/.insteadOf=%s/", proxyServer.URL, upstreamServer.URL),
		"clone", upstreamRepoURL, clone2Dir)
	if out, err := cloneCmd2.CombinedOutput(); err != nil {
		t.Fatalf("second clone failed: %v, output: %s", err, out)
	}

	if hits := atomic.LoadInt32(&fetchHits); hits != 2 {
		t.Fatalf("expected 2 fetch hits after clone 2, got %d", hits)
	}

	// Client 1 (at C1) pulls to get C3 (wants C3, haves C1).
	// Proxy MUST serve this ENTIRELY FROM CACHE (pruning C1 objects and sending C2+C3) without hitting upstream!
	pullCmd1 := exec.Command("git", "-C", clone1Dir,
		"-c", fmt.Sprintf("url.%s/.insteadOf=%s/", proxyServer.URL, upstreamServer.URL),
		"pull")
	if out, err := pullCmd1.CombinedOutput(); err != nil {
		t.Fatalf("client 1 pull failed: %v, output: %s", err, out)
	}

	if hits := atomic.LoadInt32(&fetchHits); hits != 2 {
		t.Fatalf("expected fetch hits to stay at 2 after client 1 pull from cache, got %d", hits)
	}

	// Verify client 1 has all files
	for _, f := range []string{"file1.txt", "file2.txt", "file3.txt"} {
		if _, err := os.Stat(filepath.Join(clone1Dir, f)); err != nil {
			t.Errorf("expected %s in clone1 after pull, err: %v", f, err)
		}
	}

	// Client 3 clones from scratch (wants C3, haves none).
	// Proxy MUST serve Client 3 ENTIRELY FROM CACHE without hitting upstream!
	clone3Dir := filepath.Join(clientDir, "clone3")
	cloneCmd3 := exec.Command("git",
		"-c", fmt.Sprintf("url.%s/.insteadOf=%s/", proxyServer.URL, upstreamServer.URL),
		"clone", upstreamRepoURL, clone3Dir)
	if out, err := cloneCmd3.CombinedOutput(); err != nil {
		t.Fatalf("client 3 clone failed: %v, output: %s", err, out)
	}

	if hits := atomic.LoadInt32(&fetchHits); hits != 2 {
		t.Fatalf("expected fetch hits to stay at 2 after client 3 clone from cache, got %d", hits)
	}

	for _, f := range []string{"file1.txt", "file2.txt", "file3.txt"} {
		if _, err := os.Stat(filepath.Join(clone3Dir, f)); err != nil {
			t.Errorf("expected %s in clone3 after clone, err: %v", f, err)
		}
	}

	// Push commit C4 upstream
	os.WriteFile(filepath.Join(seedDir, "file4.txt"), []byte("commit 4 content"), 0644)
	exec.Command("git", "-C", seedDir, "add", ".").Run()
	exec.Command("git", "-C", seedDir, "commit", "-m", "Commit 4").Run()
	exec.Command("git", "-C", seedDir, "push", gitDir, "HEAD:main").Run()

	// Client 1 pulls C4 (wants C4, haves C3). Proxy fetches only C4 delta from upstream (fetchHits = 3)
	pullCmd1New := exec.Command("git", "-C", clone1Dir,
		"-c", fmt.Sprintf("url.%s/.insteadOf=%s/", proxyServer.URL, upstreamServer.URL),
		"pull")
	if out, err := pullCmd1New.CombinedOutput(); err != nil {
		t.Fatalf("client 1 second pull failed: %v, output: %s", err, out)
	}

	if hits := atomic.LoadInt32(&fetchHits); hits != 3 {
		t.Fatalf("expected 3 fetch hits after pulling C4, got %d", hits)
	}

	// Client 2 pulls C4 (wants C4, haves C3). Proxy serves from cache!
	pullCmd2New := exec.Command("git", "-C", clone2Dir,
		"-c", fmt.Sprintf("url.%s/.insteadOf=%s/", proxyServer.URL, upstreamServer.URL),
		"pull")
	if out, err := pullCmd2New.CombinedOutput(); err != nil {
		t.Fatalf("client 2 pull failed: %v, output: %s", err, out)
	}

	if hits := atomic.LoadInt32(&fetchHits); hits != 3 {
		t.Fatalf("expected fetch hits to stay at 3 after client 2 pull from cache, got %d", hits)
	}

	if _, err := os.Stat(filepath.Join(clone2Dir, "file4.txt")); err != nil {
		t.Errorf("expected file4.txt in clone2, err: %v", err)
	}
}
