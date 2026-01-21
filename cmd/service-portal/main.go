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
)

func main() {
	target := os.Getenv("TARGET_URL")
	if target == "" {
		target = "https://generativelanguage.googleapis.com"
	}

	upstreamAuthToken := os.Getenv("UPSTREAM_AUTH_TOKEN")
	if upstreamAuthToken == "" {
		log.Println("Warning: UPSTREAM_AUTH_TOKEN is not set. No Authorization header will be injected.")
	}

	targetURL, err := url.Parse(target)
	if err != nil {
		log.Fatalf("Invalid TARGET_URL: %v", err)
	}

	proxy := newProxy(targetURL, upstreamAuthToken)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Starting proxy on :%s forwarding to %s", port, target)
	if err := http.ListenAndServe(":"+port, proxy); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func newProxy(targetURL *url.URL, upstreamAuthToken string) *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		// TODO: Verify incoming Authorization header (e.g., K8s ServiceAccountToken)
		// before proxying. For MVP, we pass through but strictly speaking we should
		// validate here.

		originalDirector(req)
		req.Host = targetURL.Host
		if upstreamAuthToken != "" {
			req.Header.Set("Authorization", "Bearer "+upstreamAuthToken)
		}
		// Remove headers that might interfere or reveal the proxy's identity if desired
		req.Header.Del("X-Forwarded-For")
	}

	// Simple logging
	proxy.ModifyResponse = func(resp *http.Response) error {
		log.Printf("Proxied %s %s -> %s", resp.Request.Method, resp.Request.URL, resp.Status)
		return nil
	}

	return proxy
}
