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
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gke-labs/service-portals/pkg/cache"
)

func TestCachingTransport(t *testing.T) {
	// Create a mock cache
	memCache := cache.NewInMemoryCache(0)

	// Create a mock upstream server
	callCount := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("hello"))
	}))
	defer ts.Close()

	transport := NewCachingTransport(memCache, http.DefaultTransport, 1*time.Minute)

	// First request (GET) - should miss cache and call upstream
	req, _ := http.NewRequest("GET", ts.URL, nil)
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if callCount != 1 {
		t.Errorf("Expected call count 1, got %d", callCount)
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello" {
		t.Errorf("Expected body 'hello', got '%s'", body)
	}

	// Second request (GET) - should hit cache and NOT call upstream
	resp2, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()

	if callCount != 1 {
		t.Errorf("Expected call count 1 (cached), got %d", callCount)
	}

	body2, _ := io.ReadAll(resp2.Body)
	if string(body2) != "hello" {
		t.Errorf("Expected body 'hello', got '%s'", body2)
	}

	// Third request (POST) - should NOT cache and call upstream
	req3, _ := http.NewRequest("POST", ts.URL, bytes.NewReader([]byte("data")))
	resp3, err := transport.RoundTrip(req3)
	if err != nil {
		t.Fatal(err)
	}
	defer resp3.Body.Close()

	if callCount != 2 {
		t.Errorf("Expected call count 2, got %d", callCount)
	}
}
