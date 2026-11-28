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

package goproxy

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gke-labs/service-portals/pkg/diskcache"
)

func newTestProxyWithConfig(t *testing.T, upstream http.Handler, customize func(*Config)) (*Handler, string, *httptest.Server, *time.Time) {
	t.Helper()
	up := httptest.NewServer(upstream)
	t.Cleanup(up.Close)

	now := time.Now().Truncate(time.Second)
	var cfg Config
	cfg.InitDefaults()
	cfg.UpstreamURL = up.URL
	cfg.CacheDir = t.TempDir()
	if customize != nil {
		customize(&cfg)
	}
	h, err := NewHandler(cfg)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	h.retryDelay = time.Millisecond
	h.now = func() time.Time { return now }

	proxySrv := httptest.NewServer(h)
	t.Cleanup(proxySrv.Close)
	return h, cfg.CacheDir, proxySrv, &now
}

func newTestProxy(t *testing.T, upstream http.Handler, mutableTTL time.Duration) (*Handler, string, *httptest.Server, *time.Time) {
	t.Helper()
	return newTestProxyWithConfig(t, upstream, func(cfg *Config) {
		if mutableTTL > 0 {
			cfg.MutableTTL = mutableTTL
		}
	})
}

func doReq(t *testing.T, method, url string) (int, http.Header, string) {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	body, readErr := io.ReadAll(resp.Body)
	closeErr := resp.Body.Close()
	if readErr != nil {
		t.Fatalf("reading response body: %v", readErr)
	}
	if closeErr != nil {
		t.Fatalf("closing response body: %v", closeErr)
	}
	return resp.StatusCode, resp.Header, string(body)
}

func TestImmutableCaching(t *testing.T) {
	var hits atomic.Int32
	payloads := map[string]string{
		"/example.com/mod/@v/v1.0.0.zip":  "fake-zip-bytes",
		"/example.com/mod/@v/v1.0.0.mod":  "module example.com/mod",
		"/example.com/mod/@v/v1.0.0.info": `{"Version":"v1.0.0"}`,
	}
	_, _, srv, now := newTestProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		body, ok := payloads[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if _, err := io.WriteString(w, body); err != nil {
			t.Errorf("upstream write: %v", err)
		}
	}), 5*time.Minute)

	for path, want := range payloads {
		before := hits.Load()
		code, _, body := doReq(t, http.MethodGet, srv.URL+path)
		if code != http.StatusOK || body != want {
			t.Fatalf("GET %s = (%d, %q), want (200, %q)", path, code, body, want)
		}
		// Advance clock well past MutableTTL; immutable artifacts stay cached.
		*now = now.Add(365 * 24 * time.Hour)
		code, _, body = doReq(t, http.MethodGet, srv.URL+path)
		if code != http.StatusOK || body != want {
			t.Fatalf("cached GET %s = (%d, %q), want (200, %q)", path, code, body, want)
		}
		if got := hits.Load() - before; got != 1 {
			t.Fatalf("upstream hits for %s = %d, want 1", path, got)
		}
	}

	// HEAD on an uncached immutable artifact populates the cache for subsequent GET.
	headPath := "/example.com/head/@v/v1.2.3.info"
	payloads[headPath] = `{"Version":"v1.2.3"}`
	before := hits.Load()
	code, hdr, body := doReq(t, http.MethodHead, srv.URL+headPath)
	if code != http.StatusOK || body != "" || hdr.Get("Content-Type") != "application/json" {
		t.Fatalf("HEAD %s = (%d, %q, ct=%q), want (200, empty, application/json)", headPath, code, body, hdr.Get("Content-Type"))
	}
	code, _, body = doReq(t, http.MethodGet, srv.URL+headPath)
	if code != http.StatusOK || body != payloads[headPath] {
		t.Fatalf("GET after HEAD = (%d, %q), want (200, %q)", code, body, payloads[headPath])
	}
	if got := hits.Load() - before; got != 1 {
		t.Fatalf("upstream hits for HEAD+GET = %d, want 1", got)
	}
}

func TestMutableTTLExpiry(t *testing.T) {
	var hits atomic.Int32
	var version atomic.Int32
	version.Store(1)

	const (
		listV1   = "v1.0.0"
		listV2   = "v1.0.0,v1.1.0"
		latestV1 = `{"Version":"v1.0.0"}`
		latestV2 = `{"Version":"v1.1.0"}`
	)

	_, _, srv, now := newTestProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		v := version.Load()
		var body string
		if r.URL.Path == "/example.com/mod/@latest" {
			if v == 1 {
				body = latestV1
			} else {
				body = latestV2
			}
		} else {
			if v == 1 {
				body = listV1
			} else {
				body = listV2
			}
		}
		if _, err := io.WriteString(w, body); err != nil {
			t.Errorf("upstream write: %v", err)
		}
	}), 10*time.Second)

	for _, tc := range []struct {
		path  string
		want1 string
		want2 string
	}{
		{"/example.com/mod/@v/list", listV1, listV2},
		{"/example.com/mod/@latest", latestV1, latestV2},
	} {
		version.Store(1)
		before := hits.Load()

		code, _, body := doReq(t, http.MethodGet, srv.URL+tc.path)
		if code != http.StatusOK || body != tc.want1 {
			t.Fatalf("first GET %s = (%d, %q), want (200, %q)", tc.path, code, body, tc.want1)
		}

		// Within TTL: served from cache even after upstream changes.
		version.Store(2)
		*now = now.Add(5 * time.Second)
		code, _, body = doReq(t, http.MethodGet, srv.URL+tc.path)
		if code != http.StatusOK || body != tc.want1 {
			t.Fatalf("within-TTL GET %s = (%d, %q), want (200, %q)", tc.path, code, body, tc.want1)
		}
		if got := hits.Load() - before; got != 1 {
			t.Fatalf("within-TTL hits for %s = %d, want 1", tc.path, got)
		}

		// Past TTL: re-fetched from upstream and re-cached.
		*now = now.Add(6 * time.Second)
		code, _, body = doReq(t, http.MethodGet, srv.URL+tc.path)
		if code != http.StatusOK || body != tc.want2 {
			t.Fatalf("expired GET %s = (%d, %q), want (200, %q)", tc.path, code, body, tc.want2)
		}
		code, _, body = doReq(t, http.MethodGet, srv.URL+tc.path)
		if code != http.StatusOK || body != tc.want2 {
			t.Fatalf("re-cached GET %s = (%d, %q), want (200, %q)", tc.path, code, body, tc.want2)
		}
		if got := hits.Load() - before; got != 2 {
			t.Fatalf("post-expiry hits for %s = %d, want 2", tc.path, got)
		}
	}
}

func TestConcurrentMissDeduplication(t *testing.T) {
	var hits atomic.Int32
	started := make(chan struct{}, 1)
	release := make(chan struct{})

	_, _, srv, _ := newTestProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		select {
		case started <- struct{}{}:
		default:
		}
		<-release
		if _, err := io.WriteString(w, "shared-zip-content"); err != nil {
			t.Errorf("upstream write: %v", err)
		}
	}), 5*time.Minute)

	const concurrency = 10
	var wg sync.WaitGroup
	errs := make(chan error, concurrency)
	for range concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			code, _, body := doReq(t, http.MethodGet, srv.URL+"/example.com/mod/@v/v1.0.0.zip")
			if code != http.StatusOK || body != "shared-zip-content" {
				errs <- http.ErrHandlerTimeout
			}
		}()
	}

	<-started
	time.Sleep(30 * time.Millisecond)
	close(release)
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Fatalf("concurrent request failed: %v", err)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("upstream hits = %d, want 1", got)
	}
}

func TestRetryOnTransientUpstreamErrors(t *testing.T) {
	t.Run("5xx recovers", func(t *testing.T) {
		var hits atomic.Int32
		_, _, srv, _ := newTestProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if hits.Add(1) < 3 {
				http.Error(w, "temporary failure", http.StatusServiceUnavailable)
				return
			}
			if _, err := io.WriteString(w, "module ok"); err != nil {
				t.Errorf("upstream write: %v", err)
			}
		}), 5*time.Minute)

		code, _, body := doReq(t, http.MethodGet, srv.URL+"/example.com/mod/@v/v1.0.0.mod")
		if code != http.StatusOK || body != "module ok" {
			t.Fatalf("GET = (%d, %q), want (200, module ok)", code, body)
		}
		if got := hits.Load(); got != 3 {
			t.Fatalf("upstream hits = %d, want 3", got)
		}
		// Recovered response must now be cached.
		code, _, body = doReq(t, http.MethodGet, srv.URL+"/example.com/mod/@v/v1.0.0.mod")
		if code != http.StatusOK || body != "module ok" || hits.Load() != 3 {
			t.Fatalf("cached GET = (%d, %q, hits=%d), want cached 200", code, body, hits.Load())
		}
	})

	t.Run("connection drop EOF recovers", func(t *testing.T) {
		var hits atomic.Int32
		_, _, srv, _ := newTestProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if hits.Add(1) == 1 {
				hj, ok := w.(http.Hijacker)
				if !ok {
					t.Errorf("ResponseWriter does not implement http.Hijacker")
					return
				}
				conn, _, err := hj.Hijack()
				if err != nil {
					t.Errorf("Hijack: %v", err)
					return
				}
				if err := conn.Close(); err != nil {
					t.Errorf("closing hijacked conn: %v", err)
				}
				return
			}
			if _, err := io.WriteString(w, `{"Version":"v1.0.0"}`); err != nil {
				t.Errorf("upstream write: %v", err)
			}
		}), 5*time.Minute)

		code, _, body := doReq(t, http.MethodGet, srv.URL+"/example.com/mod/@v/v1.0.0.info")
		if code != http.StatusOK || body != `{"Version":"v1.0.0"}` {
			t.Fatalf("GET = (%d, %q), want 200", code, body)
		}
		if got := hits.Load(); got != 2 {
			t.Fatalf("upstream hits = %d, want 2", got)
		}
	})

	t.Run("partial body EOF recovers", func(t *testing.T) {
		var hits atomic.Int32
		_, cacheDir, srv, _ := newTestProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if hits.Add(1) == 1 {
				w.Header().Set("Content-Length", "100")
				w.WriteHeader(http.StatusOK)
				if _, err := io.WriteString(w, "partial"); err != nil {
					t.Errorf("partial write: %v", err)
				}
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
				panic(http.ErrAbortHandler)
			}
			if _, err := io.WriteString(w, "complete-zip"); err != nil {
				t.Errorf("upstream write: %v", err)
			}
		}), 5*time.Minute)

		code, _, body := doReq(t, http.MethodGet, srv.URL+"/example.com/mod/@v/v1.0.0.zip")
		if code != http.StatusOK || body != "complete-zip" {
			t.Fatalf("GET = (%d, %q), want (200, complete-zip)", code, body)
		}
		if got := hits.Load(); got != 2 {
			t.Fatalf("upstream hits = %d, want 2", got)
		}
		entries, err := os.ReadDir(cacheDir)
		if err != nil {
			t.Fatalf("ReadDir: %v", err)
		}
		if len(entries) != 1 {
			t.Fatalf("cache dir entries = %d, want 1 (no leftover temp files)", len(entries))
		}
	})
}

func TestPartialAndFailedResponsesNotCached(t *testing.T) {
	t.Run("404 not retried and not cached", func(t *testing.T) {
		var hits atomic.Int32
		_, cacheDir, srv, _ := newTestProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			http.Error(w, "not found", http.StatusNotFound)
		}), 5*time.Minute)

		code, _, _ := doReq(t, http.MethodGet, srv.URL+"/example.com/missing/@v/v1.0.0.info")
		if code != http.StatusNotFound || hits.Load() != 1 {
			t.Fatalf("first 404 = (%d, hits=%d), want (404, 1)", code, hits.Load())
		}
		code, _, _ = doReq(t, http.MethodGet, srv.URL+"/example.com/missing/@v/v1.0.0.info")
		if code != http.StatusNotFound || hits.Load() != 2 {
			t.Fatalf("second 404 = (%d, hits=%d), want (404, 2)", code, hits.Load())
		}
		entries, err := os.ReadDir(cacheDir)
		if err != nil {
			t.Fatalf("ReadDir: %v", err)
		}
		if len(entries) != 0 {
			t.Fatalf("cache dir entries = %d, want 0", len(entries))
		}
	})

	t.Run("persistent 500 not cached", func(t *testing.T) {
		var hits atomic.Int32
		_, cacheDir, srv, _ := newTestProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			http.Error(w, "boom", http.StatusInternalServerError)
		}), 5*time.Minute)

		code, _, _ := doReq(t, http.MethodGet, srv.URL+"/example.com/fail/@v/v1.0.0.mod")
		if code != http.StatusInternalServerError || hits.Load() != maxAttempts {
			t.Fatalf("500 = (%d, hits=%d), want (500, %d)", code, hits.Load(), maxAttempts)
		}
		entries, err := os.ReadDir(cacheDir)
		if err != nil {
			t.Fatalf("ReadDir: %v", err)
		}
		if len(entries) != 0 {
			t.Fatalf("cache dir entries = %d, want 0", len(entries))
		}
	})

	t.Run("persistent partial body not cached", func(t *testing.T) {
		var hits atomic.Int32
		_, cacheDir, srv, _ := newTestProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			w.Header().Set("Content-Length", "100")
			w.WriteHeader(http.StatusOK)
			if _, err := io.WriteString(w, "short"); err != nil {
				t.Errorf("partial write: %v", err)
			}
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			panic(http.ErrAbortHandler)
		}), 5*time.Minute)

		code, _, _ := doReq(t, http.MethodGet, srv.URL+"/example.com/trunc/@v/v1.0.0.zip")
		if code != http.StatusBadGateway || hits.Load() != maxAttempts {
			t.Fatalf("truncated = (%d, hits=%d), want (502, %d)", code, hits.Load(), maxAttempts)
		}
		entries, err := os.ReadDir(cacheDir)
		if err != nil {
			t.Fatalf("ReadDir: %v", err)
		}
		if len(entries) != 0 {
			t.Fatalf("cache dir entries = %d, want 0", len(entries))
		}
	})

	t.Run("POST is neither cached nor retried", func(t *testing.T) {
		var hits atomic.Int32
		_, cacheDir, srv, _ := newTestProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
		}), 5*time.Minute)

		code, _, _ := doReq(t, http.MethodPost, srv.URL+"/example.com/mod/@v/v1.0.0.info")
		if code != http.StatusServiceUnavailable || hits.Load() != 1 {
			t.Fatalf("POST = (%d, hits=%d), want (503, 1)", code, hits.Load())
		}
		entries, err := os.ReadDir(cacheDir)
		if err != nil {
			t.Fatalf("ReadDir: %v", err)
		}
		if len(entries) != 0 {
			t.Fatalf("cache dir entries = %d, want 0", len(entries))
		}
	})
}

func cacheDirBytes(t *testing.T, dir string) int64 {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	var total int64
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			t.Fatalf("Info(%s): %v", e.Name(), err)
		}
		total += info.Size()
	}
	return total
}

func TestLRUEviction(t *testing.T) {
	var hitsMu sync.Mutex
	hits := make(map[string]int)
	payloads := map[string]string{
		"/example.com/a/@v/v1.0.0.zip": strings.Repeat("a", 10),
		"/example.com/b/@v/v1.0.0.zip": strings.Repeat("b", 10),
		"/example.com/c/@v/v1.0.0.zip": strings.Repeat("c", 10),
		"/example.com/d/@v/v1.0.0.zip": strings.Repeat("d", 10),
	}
	hitCount := func(p string) int {
		hitsMu.Lock()
		defer hitsMu.Unlock()
		return hits[p]
	}

	_, cacheDir, srv, _ := newTestProxyWithConfig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitsMu.Lock()
		hits[r.URL.Path]++
		hitsMu.Unlock()
		if _, err := io.WriteString(w, payloads[r.URL.Path]); err != nil {
			t.Errorf("upstream write: %v", err)
		}
	}), func(cfg *Config) {
		cfg.MaxCacheBytes = 20
	})

	pathA := "/example.com/a/@v/v1.0.0.zip"
	pathB := "/example.com/b/@v/v1.0.0.zip"
	pathC := "/example.com/c/@v/v1.0.0.zip"
	pathD := "/example.com/d/@v/v1.0.0.zip"

	// Populate a (10B) and b (10B); total = 20B (within cap).
	for _, p := range []string{pathA, pathB} {
		code, _, body := doReq(t, http.MethodGet, srv.URL+p)
		if code != http.StatusOK || body != payloads[p] {
			t.Fatalf("GET %s = (%d, %q), want (200, %q)", p, code, body, payloads[p])
		}
	}

	// Read a so b becomes the least-recently-used entry.
	code, _, body := doReq(t, http.MethodGet, srv.URL+pathA)
	if code != http.StatusOK || body != payloads[pathA] || hitCount(pathA) != 1 {
		t.Fatalf("cached GET %s = (%d, %q, hits=%d), want cached hit", pathA, code, body, hitCount(pathA))
	}

	// Fetch c (10B): total would be 30B > 20B, so colder entry b must be evicted while a survives.
	code, _, body = doReq(t, http.MethodGet, srv.URL+pathC)
	if code != http.StatusOK || body != payloads[pathC] {
		t.Fatalf("GET %s = (%d, %q), want (200, %q)", pathC, code, body, payloads[pathC])
	}
	if got := cacheDirBytes(t, cacheDir); got > 20 {
		t.Fatalf("cacheDirBytes = %d, want <= 20", got)
	}

	// a and c must still be cached (no new upstream hit).
	for _, p := range []string{pathA, pathC} {
		code, _, body := doReq(t, http.MethodGet, srv.URL+p)
		if code != http.StatusOK || body != payloads[p] || hitCount(p) != 1 {
			t.Fatalf("GET %s after eviction = (%d, %q, hits=%d), want cached", p, code, body, hitCount(p))
		}
	}

	// Fetch d (10B): a was read before c, so a is now colder and evicted; c and d remain.
	code, _, body = doReq(t, http.MethodGet, srv.URL+pathD)
	if code != http.StatusOK || body != payloads[pathD] {
		t.Fatalf("GET %s = (%d, %q), want (200, %q)", pathD, code, body, payloads[pathD])
	}
	if got := cacheDirBytes(t, cacheDir); got > 20 {
		t.Fatalf("cacheDirBytes = %d, want <= 20", got)
	}

	// b was evicted earlier so requesting it must hit upstream again.
	code, _, body = doReq(t, http.MethodGet, srv.URL+pathB)
	if code != http.StatusOK || body != payloads[pathB] || hitCount(pathB) != 2 {
		t.Fatalf("re-fetch evicted %s = (%d, %q, hits=%d), want 2 upstream hits", pathB, code, body, hitCount(pathB))
	}
}

func TestCacheHitDoesNotExtendMutableTTL(t *testing.T) {
	var hits atomic.Int32
	var version atomic.Int32
	version.Store(1)

	h, _, srv, now := newTestProxyWithConfig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		v := version.Load()
		var body string
		if strings.HasSuffix(r.URL.Path, "/@latest") {
			body = fmt.Sprintf(`{"Version":"v1.%d.0"}`, v)
		} else {
			body = fmt.Sprintf("v1.%d.0\n", v)
		}
		if _, err := io.WriteString(w, body); err != nil {
			t.Errorf("upstream write: %v", err)
		}
	}), func(cfg *Config) {
		cfg.MutableTTL = 10 * time.Second
		cfg.MaxCacheBytes = 1024
	})

	for _, tc := range []struct {
		path  string
		want1 string
		want2 string
	}{
		{"/example.com/mod/@v/list", "v1.1.0\n", "v1.2.0\n"},
		{"/example.com/mod/@latest", `{"Version":"v1.1.0"}`, `{"Version":"v1.2.0"}`},
	} {
		version.Store(1)
		before := hits.Load()

		code, _, body := doReq(t, http.MethodGet, srv.URL+tc.path)
		if code != http.StatusOK || body != tc.want1 {
			t.Fatalf("initial GET %s = (%d, %q), want (200, %q)", tc.path, code, body, tc.want1)
		}
		infoBefore, err := h.cache.Stat(tc.path)
		if err != nil {
			t.Fatalf("Stat(%s): %v", tc.path, err)
		}

		// Repeated cache hits before TTL expiry must not modify ModTime or extend TTL.
		version.Store(2)
		for _, step := range []time.Duration{4 * time.Second, 4 * time.Second} {
			*now = now.Add(step)
			code, _, body = doReq(t, http.MethodGet, srv.URL+tc.path)
			if code != http.StatusOK || body != tc.want1 {
				t.Fatalf("cached GET %s = (%d, %q), want (200, %q)", tc.path, code, body, tc.want1)
			}
		}
		infoAfter, err := h.cache.Stat(tc.path)
		if err != nil {
			t.Fatalf("Stat after hits(%s): %v", tc.path, err)
		}
		if !infoAfter.ModTime().Equal(infoBefore.ModTime()) {
			t.Fatalf("ModTime changed on cache hit: before=%v after=%v", infoBefore.ModTime(), infoAfter.ModTime())
		}
		if got := hits.Load() - before; got != 1 {
			t.Fatalf("hits before expiry for %s = %d, want 1", tc.path, got)
		}

		// 11s since initial write (only 3s since last read): must expire and re-fetch.
		*now = now.Add(3 * time.Second)
		code, _, body = doReq(t, http.MethodGet, srv.URL+tc.path)
		if code != http.StatusOK || body != tc.want2 {
			t.Fatalf("post-TTL GET %s = (%d, %q), want (200, %q)", tc.path, code, body, tc.want2)
		}
		if got := hits.Load() - before; got != 2 {
			t.Fatalf("hits after expiry for %s = %d, want 2", tc.path, got)
		}
	}
}

func TestStartupScanAndTempCleanup(t *testing.T) {
	t.Run("accounts for pre-existing files and removes stale temp files", func(t *testing.T) {
		cacheDir := t.TempDir()
		pathOld := "/example.com/old/@v/v1.0.0.zip"
		pathNew := "/example.com/new/@v/v1.0.0.zip"
		pathFresh := "/example.com/fresh/@v/v1.0.0.zip"

		seed, err := diskcache.New(diskcache.Config{Dir: cacheDir})
		if err != nil {
			t.Fatalf("diskcache.New: %v", err)
		}
		baseTime := time.Now().Add(-time.Hour).Truncate(time.Second)
		if err := seed.Write(pathOld, strings.NewReader("0123456789"), 10, baseTime); err != nil {
			t.Fatalf("seed old: %v", err)
		}
		if err := seed.Write(pathNew, strings.NewReader("abcdefghij"), 10, baseTime.Add(time.Minute)); err != nil {
			t.Fatalf("seed new: %v", err)
		}
		tmpFile := filepath.Join(cacheDir, ".tmp-crashed-12345")
		if err := os.WriteFile(tmpFile, []byte("partial-garbage"), 0644); err != nil {
			t.Fatalf("WriteFile tmp: %v", err)
		}

		var hits atomic.Int32
		h, _, srv, _ := newTestProxyWithConfig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			if _, err := io.WriteString(w, "ZZZZZZZZZZ"); err != nil {
				t.Errorf("upstream write: %v", err)
			}
		}), func(cfg *Config) {
			cfg.CacheDir = cacheDir
			cfg.MaxCacheBytes = 20
		})

		// Stale .tmp-* file must be deleted on startup.
		if _, err := os.Stat(tmpFile); !os.IsNotExist(err) {
			t.Fatalf("stale temp file still exists: err=%v", err)
		}

		// Writing a 10B fresh entry pushes total to 30B > 20B, evicting older pre-existing file.
		code, _, body := doReq(t, http.MethodGet, srv.URL+pathFresh)
		if code != http.StatusOK || body != "ZZZZZZZZZZ" {
			t.Fatalf("GET %s = (%d, %q), want (200, ZZZZZZZZZZ)", pathFresh, code, body)
		}
		if _, err := h.cache.Stat(pathOld); !os.IsNotExist(err) {
			t.Fatalf("expected oldest pre-existing file to be evicted, stat err=%v", err)
		}
		if _, err := h.cache.Stat(pathNew); err != nil {
			t.Fatalf("expected newer pre-existing file to survive, stat err=%v", err)
		}
		if got := cacheDirBytes(t, cacheDir); got != 20 {
			t.Fatalf("cacheDirBytes = %d, want 20", got)
		}

		// Newer pre-existing file must still be served from cache without upstream hit.
		before := hits.Load()
		code, _, body = doReq(t, http.MethodGet, srv.URL+pathNew)
		if code != http.StatusOK || body != "abcdefghij" || hits.Load() != before {
			t.Fatalf("GET %s = (%d, %q, deltaHits=%d), want cached abcdefghij", pathNew, code, body, hits.Load()-before)
		}
	})

	t.Run("evicts pre-existing excess on startup", func(t *testing.T) {
		cacheDir := t.TempDir()
		pathOld := "/example.com/old/@v/v1.0.0.zip"
		pathNew := "/example.com/new/@v/v1.0.0.zip"
		seed, err := diskcache.New(diskcache.Config{Dir: cacheDir})
		if err != nil {
			t.Fatalf("diskcache.New: %v", err)
		}
		baseTime := time.Now().Add(-time.Hour).Truncate(time.Second)
		if err := seed.Write(pathOld, strings.NewReader("0123456789"), 10, baseTime); err != nil {
			t.Fatalf("seed old: %v", err)
		}
		if err := seed.Write(pathNew, strings.NewReader("abcdefghij"), 10, baseTime.Add(time.Minute)); err != nil {
			t.Fatalf("seed new: %v", err)
		}

		h, _, _, _ := newTestProxyWithConfig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		}), func(cfg *Config) {
			cfg.CacheDir = cacheDir
			cfg.MaxCacheBytes = 10
		})
		if _, err := h.cache.Stat(pathOld); !os.IsNotExist(err) {
			t.Fatalf("expected old pre-existing file evicted on startup, err=%v", err)
		}
		if _, err := h.cache.Stat(pathNew); err != nil {
			t.Fatalf("expected newer pre-existing file kept on startup, err=%v", err)
		}
		if got := cacheDirBytes(t, cacheDir); got != 10 {
			t.Fatalf("cacheDirBytes = %d, want 10", got)
		}
	})
}

func TestMaxCacheBytesConfig(t *testing.T) {
	t.Run("InitDefaults sets positive default", func(t *testing.T) {
		var cfg Config
		cfg.InitDefaults()
		var cacheCfg diskcache.Config
		cacheCfg.InitDefaults()
		if cfg.MaxCacheBytes != cacheCfg.MaxBytes || cfg.MaxCacheBytes <= 0 {
			t.Fatalf("InitDefaults().MaxCacheBytes = %d, want %d", cfg.MaxCacheBytes, cacheCfg.MaxBytes)
		}
	})

	t.Run("negative MaxCacheBytes rejected", func(t *testing.T) {
		var cfg Config
		cfg.InitDefaults()
		cfg.CacheDir = t.TempDir()
		cfg.MaxCacheBytes = -1
		if _, err := NewHandler(cfg); err == nil {
			t.Fatal("NewHandler accepted negative MaxCacheBytes, want error")
		}
	})

	t.Run("zero disables eviction and still cleans stale temp files", func(t *testing.T) {
		cacheDir := t.TempDir()
		tmpFile := filepath.Join(cacheDir, ".tmp-stale")
		if err := os.WriteFile(tmpFile, []byte("stale"), 0644); err != nil {
			t.Fatalf("WriteFile tmp: %v", err)
		}

		var hits atomic.Int32
		_, _, srv, _ := newTestProxyWithConfig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			if _, err := io.WriteString(w, strings.Repeat("x", 64)); err != nil {
				t.Errorf("upstream write: %v", err)
			}
		}), func(cfg *Config) {
			cfg.CacheDir = cacheDir
			cfg.MaxCacheBytes = 0
		})

		if _, err := os.Stat(tmpFile); !os.IsNotExist(err) {
			t.Fatalf("stale temp file still exists: err=%v", err)
		}
		paths := []string{
			"/example.com/p1/@v/v1.0.0.zip",
			"/example.com/p2/@v/v1.0.0.zip",
			"/example.com/p3/@v/v1.0.0.zip",
		}
		for _, p := range paths {
			code, _, _ := doReq(t, http.MethodGet, srv.URL+p)
			if code != http.StatusOK {
				t.Fatalf("GET %s = %d, want 200", p, code)
			}
		}
		if got := cacheDirBytes(t, cacheDir); got != 3*64 {
			t.Fatalf("cacheDirBytes = %d, want %d", got, 3*64)
		}
		// All three must remain cached.
		before := hits.Load()
		for _, p := range paths {
			code, _, _ := doReq(t, http.MethodGet, srv.URL+p)
			if code != http.StatusOK {
				t.Fatalf("cached GET %s = %d, want 200", p, code)
			}
		}
		if hits.Load() != before {
			t.Fatalf("unexpected upstream hits %d with eviction disabled", hits.Load()-before)
		}
	})
}

func TestOversizedArtifact(t *testing.T) {
	smallPath := "/example.com/small/@v/v1.0.0.zip"
	bigPath := "/example.com/big/@v/v1.0.0.zip"
	chunkedBigPath := "/example.com/chunked/@v/v1.0.0.zip"
	smallBody := "small"
	bigBody := strings.Repeat("B", 50)

	var smallHits atomic.Int32
	_, cacheDir, srv, _ := newTestProxyWithConfig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case smallPath:
			smallHits.Add(1)
			_, _ = io.WriteString(w, smallBody)
		case bigPath:
			_, _ = io.WriteString(w, bigBody)
		case chunkedBigPath:
			w.WriteHeader(http.StatusOK)
			for i := 0; i < len(bigBody); i += 10 {
				_, _ = io.WriteString(w, bigBody[i:i+10])
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
			}
		default:
			http.NotFound(w, r)
		}
	}), func(cfg *Config) {
		cfg.MaxCacheBytes = 20
	})

	// Cache a small entry first.
	code, _, body := doReq(t, http.MethodGet, srv.URL+smallPath)
	if code != http.StatusOK || body != smallBody {
		t.Fatalf("GET %s = (%d, %q), want (200, %q)", smallPath, code, body, smallBody)
	}

	// Both Content-Length and chunked oversized artifacts must be served cleanly without
	// evicting existing cache entries or leaving temp files behind.
	for _, p := range []string{bigPath, chunkedBigPath} {
		code, _, body = doReq(t, http.MethodGet, srv.URL+p)
		if code != http.StatusOK || body != bigBody {
			t.Fatalf("GET %s = (%d, len=%d), want (200, len=%d)", p, code, len(body), len(bigBody))
		}
	}

	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 || cacheDirBytes(t, cacheDir) != int64(len(smallBody)) {
		t.Fatalf("unexpected cache state after oversized fetch: entries=%d bytes=%d", len(entries), cacheDirBytes(t, cacheDir))
	}
	// Small entry must still be served from cache.
	code, _, body = doReq(t, http.MethodGet, srv.URL+smallPath)
	if code != http.StatusOK || body != smallBody || smallHits.Load() != 1 {
		t.Fatalf("GET %s after oversized = (%d, %q, hits=%d), want cached", smallPath, code, body, smallHits.Load())
	}
}

func TestConcurrentReadsAndEvictions(t *testing.T) {
	_, cacheDir, srv, _ := newTestProxyWithConfig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.WriteString(w, r.URL.Path); err != nil {
			t.Errorf("upstream write: %v", err)
		}
	}), func(cfg *Config) {
		cfg.MaxCacheBytes = 128
	})

	var wg sync.WaitGroup
	errs := make(chan string, 200)
	for g := range 10 {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := range 20 {
				p := fmt.Sprintf("/example.com/m%d/@v/v1.0.%d.zip", id, i%5)
				code, _, body := doReq(t, http.MethodGet, srv.URL+p)
				if code != http.StatusOK || body != p {
					errs <- fmt.Sprintf("GET %s = (%d, %q)", p, code, body)
					return
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for msg := range errs {
		t.Fatal(msg)
	}
	if got := cacheDirBytes(t, cacheDir); got > 128 {
		t.Fatalf("cacheDirBytes = %d, want <= 128", got)
	}
}
