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

package portals

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/gke-labs/service-portals/pkg/cache"
	"github.com/gke-labs/service-portals/pkg/proxy"
)

type Config struct {
	DefaultTargetURL  string
	DefaultAuthHeader string
	SetupProxy        func(*proxy.HTTPProxy)
	CacheTTL          time.Duration
}

func Run(ctx context.Context, config Config) error {
	target := os.Getenv("TARGET_URL")
	if target == "" {
		target = config.DefaultTargetURL
	}
	if target == "" {
		target = "https://generativelanguage.googleapis.com"
	}

	upstreamAuthToken := os.Getenv("UPSTREAM_AUTH_TOKEN")
	if upstreamAuthToken == "" {
		log.Println("Warning: UPSTREAM_AUTH_TOKEN is not set. No Authorization header will be injected.")
	}

	upstreamAuthHeader := os.Getenv("UPSTREAM_AUTH_HEADER")
	if upstreamAuthHeader == "" {
		if config.DefaultAuthHeader != "" {
			upstreamAuthHeader = config.DefaultAuthHeader
		} else {
			upstreamAuthHeader = "Authorization"
		}
	}

	targetURL, err := url.Parse(target)
	if err != nil {
		return fmt.Errorf("invalid TARGET_URL: %w", err)
	}

	caCertPath := os.Getenv("CA_CERT_PATH")
	caKeyPath := os.Getenv("CA_KEY_PATH")

	p, err := proxy.NewHTTPProxy(targetURL, upstreamAuthToken, upstreamAuthHeader, caCertPath, caKeyPath)
	if err != nil {
		return fmt.Errorf("failed to create proxy: %w", err)
	}

	cacheTTL := config.CacheTTL
	if cacheTTLEnv := os.Getenv("CACHE_TTL"); cacheTTLEnv != "" {
		if d, err := time.ParseDuration(cacheTTLEnv); err == nil {
			cacheTTL = d
		} else {
			log.Printf("Warning: invalid CACHE_TTL %q: %v", cacheTTLEnv, err)
		}
	}

	if cacheTTL > 0 {
		cleanupInterval := 1 * time.Minute
		if cleanupEnv := os.Getenv("CACHE_CLEANUP_INTERVAL"); cleanupEnv != "" {
			if d, err := time.ParseDuration(cleanupEnv); err == nil {
				cleanupInterval = d
			} else {
				log.Printf("Warning: invalid CACHE_CLEANUP_INTERVAL %q: %v", cleanupEnv, err)
			}
		}

		c := cache.NewInMemoryCache(cleanupInterval)
		p.Transport = proxy.NewCachingTransport(c, p.Transport, cacheTTL)
		log.Printf("Enabled caching with TTL %v (cleanup interval %v)", cacheTTL, cleanupInterval)
	}

	if config.SetupProxy != nil {
		config.SetupProxy(p)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	srv := &http.Server{
		Addr:    ":" + port,
		Handler: p,
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
