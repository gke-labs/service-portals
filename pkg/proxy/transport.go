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

package proxy

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gke-labs/service-portals/pkg/cache"
)

// NewUpstreamTransport creates an http.RoundTripper suitable for upstream requests.
// If caDir is empty, it returns http.DefaultTransport without accessing the filesystem.
// If caDir contains certificate files, the transport's TLSClientConfig.RootCAs is configured
// with the host system roots plus those certificates.
// An empty directory means no additional CAs were supplied (the state of an optional ConfigMap
// volume when the ConfigMap is absent) and returns http.DefaultTransport.
// Any non-hidden file that cannot be parsed as a certificate returns an error.
func NewUpstreamTransport(caDir string) (http.RoundTripper, error) {
	if caDir == "" {
		return http.DefaultTransport, nil
	}

	pool, err := loadUpstreamCertPool(caDir)
	if err != nil {
		return nil, err
	}
	if pool == nil {
		return http.DefaultTransport, nil
	}

	baseTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("http.DefaultTransport is not an *http.Transport: %T", http.DefaultTransport)
	}

	transport := baseTransport.Clone()
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{}
	} else {
		transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	}
	transport.TLSClientConfig.RootCAs = pool

	return transport, nil
}

// loadUpstreamCertPool loads a certificate pool containing the host system's root certificates
// plus any additional CA certificates found in caDir.
// If caDir contains no non-hidden files, it returns (nil, nil), signaling that no extra CAs
// were supplied (the state of an optional ConfigMap volume when the ConfigMap is absent).
func loadUpstreamCertPool(caDir string) (*x509.CertPool, error) {
	entries, err := os.ReadDir(caDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read upstream CA directory %q: %w", caDir, err)
	}

	var certFiles []string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		filePath := filepath.Join(caDir, entry.Name())
		fi, err := os.Stat(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to stat upstream CA file %q: %w", filePath, err)
		}
		if fi.IsDir() {
			continue
		}
		certFiles = append(certFiles, filePath)
	}
	// An empty directory means no additional CAs were supplied (the state of an optional
	// ConfigMap volume when the ConfigMap is absent).
	if len(certFiles) == 0 {
		return nil, nil
	}

	rootPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("failed to load system root certificate pool: %w", err)
	}
	if rootPool == nil {
		return nil, errors.New("system root certificate pool is not available")
	}

	for _, certFile := range certFiles {
		data, err := os.ReadFile(certFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read upstream CA cert file %q: %w", certFile, err)
		}
		if len(bytes.TrimSpace(data)) == 0 {
			return nil, fmt.Errorf("upstream CA cert file %q is empty", certFile)
		}
		if !rootPool.AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("no valid CA certificates found in %q", certFile)
		}
	}

	return rootPool, nil
}

// CachedResponse represents the structure we store in the cache.
type CachedResponse struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

// CachingTransport is an http.RoundTripper that caches GET responses.
type CachingTransport struct {
	Cache      cache.Cache
	Transport  http.RoundTripper
	DefaultTTL time.Duration
}

// NewCachingTransport creates a new CachingTransport.
func NewCachingTransport(c cache.Cache, t http.RoundTripper, defaultTTL time.Duration) *CachingTransport {
	if t == nil {
		t = http.DefaultTransport
	}
	return &CachingTransport{
		Cache:      c,
		Transport:  t,
		DefaultTTL: defaultTTL,
	}
}

// RoundTrip implements the http.RoundTripper interface.
func (c *CachingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Only cache GET requests
	if req.Method != http.MethodGet {
		return c.Transport.RoundTrip(req)
	}

	key := req.URL.String()
	if val, ok := c.Cache.Get(key); ok {
		var cachedResp CachedResponse
		buf := bytes.NewBuffer(val)
		dec := gob.NewDecoder(buf)
		err := dec.Decode(&cachedResp)
		if err == nil {
			log.Printf("Cache hit for %s", key)
			return &http.Response{
				StatusCode: cachedResp.StatusCode,
				Status:     fmt.Sprintf("%d %s", cachedResp.StatusCode, http.StatusText(cachedResp.StatusCode)),
				Header:     cachedResp.Header,
				Body:       io.NopCloser(bytes.NewReader(cachedResp.Body)),
				Request:    req,
			}, nil
		}
		log.Printf("Failed to decode cached response for %s: %v", key, err)
	}

	resp, err := c.Transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	// Read the body to cache it
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp, err
	}
	if closeErr := resp.Body.Close(); closeErr != nil {
		log.Printf("Error closing response body: %v", closeErr)
	}

	// Reconstruct response body for returning
	resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	// Cache the response
	cachedResp := CachedResponse{
		StatusCode: resp.StatusCode,
		Header:     resp.Header,
		Body:       bodyBytes,
	}

	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(cachedResp); err == nil {
		c.Cache.Set(key, buf.Bytes(), c.DefaultTTL)
		log.Printf("Cached response for %s", key)
	} else {
		log.Printf("Failed to encode response for %s: %v", key, err)
	}

	return resp, nil
}

func init() {
	gob.Register(CachedResponse{})
}
