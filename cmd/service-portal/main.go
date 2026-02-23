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
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	target := os.Getenv("TARGET_URL")
	if target == "" {
		target = "https://generativelanguage.googleapis.com"
	}

	upstreamAuthToken := os.Getenv("UPSTREAM_AUTH_TOKEN")
	if upstreamAuthToken == "" {
		log.Println("Warning: UPSTREAM_AUTH_TOKEN is not set. No Authorization header will be injected.")
	}

	upstreamAuthHeader := os.Getenv("UPSTREAM_AUTH_HEADER")
	if upstreamAuthHeader == "" {
		upstreamAuthHeader = "Authorization"
	}
	upstreamAuthHeader = http.CanonicalHeaderKey(upstreamAuthHeader)

	targetURL, err := url.Parse(target)
	if err != nil {
		return fmt.Errorf("invalid TARGET_URL: %w", err)
	}

	proxy := newProxy(targetURL, upstreamAuthToken, upstreamAuthHeader)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	srv := &http.Server{
		Addr:    ":" + port,
		Handler: proxy,
	}

	errChan := make(chan error, 1)
	go func() {
		log.Printf("Starting proxy on :%s forwarding to %s", port, target)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errChan <- fmt.Errorf("server failed: %w", err)
		}
	}()

	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
		log.Println("Shutting down server...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("server shutdown failed: %w", err)
		}
	}

	return nil
}

func newProxy(targetURL *url.URL, upstreamAuthToken string, upstreamAuthHeader string) *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		// TODO: Verify incoming Authorization header (e.g., K8s ServiceAccountToken)
		// before proxying. For MVP, we pass through but strictly speaking we should
		// validate here.

		originalDirector(req)
		req.Host = targetURL.Host
		if upstreamAuthToken != "" {
			if upstreamAuthHeader == "Authorization" {
				req.Header.Set(upstreamAuthHeader, "Bearer "+upstreamAuthToken)
			} else {
				req.Header.Set(upstreamAuthHeader, upstreamAuthToken)
			}
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
