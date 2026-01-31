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
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	target := os.Getenv("UPSTREAM_URL")
	if target == "" {
		target = "https://github.com"
	}

	targetURL, err := url.Parse(target)
	if err != nil {
		log.Fatalf("Invalid UPSTREAM_URL: %v", err)
	}

	cacheDir := os.Getenv("CACHE_DIR")
	if cacheDir == "" {
		cacheDir = "/tmp/git-cache"
	}
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		log.Fatalf("Failed to create cache dir: %v", err)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	proxy := newGitProxy(targetURL, cacheDir)

	log.Printf("Starting git proxy on :%s forwarding to %s (cache: %s)", port, target, cacheDir)
	if err := http.ListenAndServe(":"+port, proxy); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

type gitProxy struct {
	targetURL *url.URL
	cacheDir  string
	proxy     *httputil.ReverseProxy
}

func newGitProxy(targetURL *url.URL, cacheDir string) http.Handler {
	p := &gitProxy{
		targetURL: targetURL,
		cacheDir:  cacheDir,
		proxy:     httputil.NewSingleHostReverseProxy(targetURL),
	}

	originalDirector := p.proxy.Director
	p.proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = targetURL.Host
	}

	p.proxy.ModifyResponse = func(resp *http.Response) error {
		if isGitRequest(resp.Request) {
			log.Printf("Git %s %s -> %s", resp.Request.Method, resp.Request.URL.Path, resp.Status)
		} else {
			log.Printf("Proxied %s %s -> %s", resp.Request.Method, resp.Request.URL.Path, resp.Status)
		}

		// If it's a successful object request, we should have cached it if it wasn't already.
		// However, ReverseProxy doesn't make it easy to cache the body here without reading it all.
		// We handle caching in ServeHTTP before calling the proxy for GET requests.
		return nil
	}

	return p
}

func (p *gitProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if p.isCacheable(r) {
		if p.tryServeFromCache(w, r) {
			return
		}
		// If not in cache, we use a custom response writer to capture the data for the cache
		p.proxyAndCache(w, r)
		return
	}

	p.proxy.ServeHTTP(w, r)
}

func (p *gitProxy) isCacheable(r *http.Request) bool {
	// Only cache GET requests to /objects/ paths
	return r.Method == "GET" && strings.Contains(r.URL.Path, "/objects/")
}

func (p *gitProxy) tryServeFromCache(w http.ResponseWriter, r *http.Request) bool {
	cachePath := filepath.Join(p.cacheDir, r.URL.Path)
	if _, err := os.Stat(cachePath); err == nil {
		log.Printf("Serving from cache: %s", r.URL.Path)
		http.ServeFile(w, r, cachePath)
		return true
	}
	return false
}

func (p *gitProxy) proxyAndCache(w http.ResponseWriter, r *http.Request) {
	cachePath := filepath.Join(p.cacheDir, r.URL.Path)
	if err := os.MkdirAll(filepath.Dir(cachePath), 0755); err != nil {
		log.Printf("Failed to create cache subdir: %v", err)
		p.proxy.ServeHTTP(w, r)
		return
	}

	// We use a custom response writer to capture the output
	cw := &cachingResponseWriter{
		ResponseWriter: w,
		cachePath:      cachePath,
	}

	p.proxy.ServeHTTP(cw, r)

	if cw.file != nil {
		cw.file.Close()
		if cw.statusCode != http.StatusOK {
			// If it wasn't a 200, delete the partial/incorrect cache file
			os.Remove(cachePath)
		} else {
			log.Printf("Cached: %s", r.URL.Path)
		}
	}
}

type cachingResponseWriter struct {
	http.ResponseWriter
	cachePath  string
	file       *os.File
	statusCode int
}

func (cw *cachingResponseWriter) WriteHeader(code int) {
	cw.statusCode = code
	if code == http.StatusOK {
		f, err := os.Create(cw.cachePath)
		if err != nil {
			log.Printf("Failed to create cache file %s: %v", cw.cachePath, err)
		} else {
			cw.file = f
		}
	}
	cw.ResponseWriter.WriteHeader(code)
}

func (cw *cachingResponseWriter) Write(b []byte) (int, error) {
	if cw.file != nil {
		cw.file.Write(b)
	}
	return cw.ResponseWriter.Write(b)
}

func isGitRequest(req *http.Request) bool {
	path := req.URL.Path
	return strings.HasSuffix(path, "/info/refs") ||
		strings.Contains(path, "/git-upload-pack") ||
		strings.Contains(path, "/git-receive-pack") ||
		strings.Contains(path, "/objects/")
}