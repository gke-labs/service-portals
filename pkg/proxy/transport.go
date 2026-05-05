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
	"encoding/gob"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/gke-labs/service-portals/pkg/cache"
)

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
	resp.Body.Close()

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
