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
	"testing"

	"github.com/gke-labs/service-portals/pkg/proxy"
)

func TestRouter_ServeHTTP(t *testing.T) {
	// Setup a mock upstream
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	upstreamURL, _ := url.Parse(upstream.URL)
	p, _ := proxy.NewHTTPProxy(upstreamURL, "", "", "", "")

	router := &Router{
		routes: map[string]*proxy.HTTPProxy{
			"test.portal": p,
		},
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "test.portal"
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status OK, got %d", rec.Code)
	}
}
