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
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newTestProxy(t *testing.T, upstream http.Handler, mutableTTL time.Duration) (*Handler, *httptest.Server, *time.Time) {
	t.Helper()
	up := httptest.NewServer(upstream)
	t.Cleanup(up.Close)

	now := time.Now().Truncate(time.Second)
	var cfg Config
	cfg.InitDefaults()
	cfg.UpstreamURL = up.URL
	cfg.CacheDir = t.TempDir()
	if mutableTTL > 0 {
		cfg.MutableTTL = mutableTTL
	}
	h, err := NewHandler(cfg)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	h.retryDelay = time.Millisecond
	h.now = func() time.Time { return now }

	proxySrv := httptest.NewServer(h)
	t.Cleanup(proxySrv.Close)
	return h, proxySrv, &now
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
	_, srv, now := newTestProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	_, srv, now := newTestProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	_, srv, _ := newTestProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		_, srv, _ := newTestProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		_, srv, _ := newTestProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		h, srv, _ := newTestProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		entries, err := os.ReadDir(h.cacheDir)
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
		h, srv, _ := newTestProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		entries, err := os.ReadDir(h.cacheDir)
		if err != nil {
			t.Fatalf("ReadDir: %v", err)
		}
		if len(entries) != 0 {
			t.Fatalf("cache dir entries = %d, want 0", len(entries))
		}
	})

	t.Run("persistent 500 not cached", func(t *testing.T) {
		var hits atomic.Int32
		h, srv, _ := newTestProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			http.Error(w, "boom", http.StatusInternalServerError)
		}), 5*time.Minute)

		code, _, _ := doReq(t, http.MethodGet, srv.URL+"/example.com/fail/@v/v1.0.0.mod")
		if code != http.StatusInternalServerError || hits.Load() != maxAttempts {
			t.Fatalf("500 = (%d, hits=%d), want (500, %d)", code, hits.Load(), maxAttempts)
		}
		entries, err := os.ReadDir(h.cacheDir)
		if err != nil {
			t.Fatalf("ReadDir: %v", err)
		}
		if len(entries) != 0 {
			t.Fatalf("cache dir entries = %d, want 0", len(entries))
		}
	})

	t.Run("persistent partial body not cached", func(t *testing.T) {
		var hits atomic.Int32
		h, srv, _ := newTestProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		entries, err := os.ReadDir(h.cacheDir)
		if err != nil {
			t.Fatalf("ReadDir: %v", err)
		}
		if len(entries) != 0 {
			t.Fatalf("cache dir entries = %d, want 0", len(entries))
		}
	})

	t.Run("POST is neither cached nor retried", func(t *testing.T) {
		var hits atomic.Int32
		h, srv, _ := newTestProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
		}), 5*time.Minute)

		code, _, _ := doReq(t, http.MethodPost, srv.URL+"/example.com/mod/@v/v1.0.0.info")
		if code != http.StatusServiceUnavailable || hits.Load() != 1 {
			t.Fatalf("POST = (%d, hits=%d), want (503, 1)", code, hits.Load())
		}
		entries, err := os.ReadDir(h.cacheDir)
		if err != nil {
			t.Fatalf("ReadDir: %v", err)
		}
		if len(entries) != 0 {
			t.Fatalf("cache dir entries = %d, want 0", len(entries))
		}
	})
}
