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
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gke-labs/service-portals/pkg/proxy"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8081"
	}

	cacheDir := os.Getenv("CACHE_DIR")
	if cacheDir == "" {
		cacheDir = "/tmp/artifact-portal-cache"
	}

	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		log.Fatalf("Failed to create cache dir: %v", err)
	}

	p := &proxy.BaseProxy{
		Transport: &CachingTransport{
			Transport: http.DefaultTransport,
			CacheDir:  cacheDir,
		},
	}

	log.Printf("Starting artifact-portal on :%s caching to %s", port, cacheDir)
	if err := http.ListenAndServe(":"+port, p); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

type CachingTransport struct {
	Transport http.RoundTripper
	CacheDir  string
}

func (t *CachingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != http.MethodGet || !t.isCacheable(req) {
		return t.Transport.RoundTrip(req)
	}

	cacheKey := t.getCacheKey(req)
	cachePath := filepath.Join(t.CacheDir, cacheKey)
	metaPath := cachePath + ".meta"

	if f, err := os.Open(cachePath); err == nil {
		log.Printf("Cache hit: %s", req.URL)
		
		contentType := "application/octet-stream"
		if meta, err := os.ReadFile(metaPath); err == nil {
			contentType = string(meta)
		}

		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       f,
			Header:     http.Header{"Content-Type": []string{contentType}},
			Request:    req,
		}, nil
	}

	log.Printf("Cache miss: %s", req.URL)
	resp, err := t.Transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return resp, nil
	}

	return t.teeToCache(resp, cachePath, metaPath), nil
}

func (t *CachingTransport) isCacheable(req *http.Request) bool {
	host := req.URL.Host
	path := req.URL.Path

	// PyPI artifacts
	if host == "files.pythonhosted.org" {
		if strings.HasSuffix(path, ".whl") ||
			strings.HasSuffix(path, ".tar.gz") ||
			strings.HasSuffix(path, ".zip") ||
			strings.HasSuffix(path, ".egg") {
			return true
		}
	}
	return false
}

func (t *CachingTransport) getCacheKey(req *http.Request) string {
	hash := sha256.Sum256([]byte(req.URL.String()))
	return fmt.Sprintf("%x", hash)
}

func (t *CachingTransport) teeToCache(resp *http.Response, cachePath, metaPath string) *http.Response {
	tmpFile, err := os.CreateTemp(t.CacheDir, "download-*")
	if err != nil {
		log.Printf("Failed to create temp file: %v", err)
		return resp
	}

	contentType := resp.Header.Get("Content-Type")
	originalBody := resp.Body
	tee := io.TeeReader(originalBody, tmpFile)

	resp.Body = &readCloser{
		Reader: tee,
		closeFunc: func() error {
			defer originalBody.Close()
			defer tmpFile.Close()

			// Move temp file to final location only if we successfully read everything
			// Ideally we would check if we read Content-Length bytes.
			if err := os.Rename(tmpFile.Name(), cachePath); err != nil {
				log.Printf("Failed to rename cache file: %v", err)
				os.Remove(tmpFile.Name())
			} else {
				log.Printf("Cached: %s", cachePath)
				if contentType != "" {
					os.WriteFile(metaPath, []byte(contentType), 0644)
				}
			}
			return nil
		},
	}
	return resp
}

type readCloser struct {
	io.Reader
	closeFunc func() error
}

func (rc *readCloser) Close() error {
	if rc.closeFunc != nil {
		err := rc.closeFunc()
		rc.closeFunc = nil
		return err
	}
	return nil
}
