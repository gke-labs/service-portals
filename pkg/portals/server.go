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
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gke-labs/service-portals/pkg/cache"
	"github.com/gke-labs/service-portals/pkg/proxy"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
)

type CertificateProvider interface {
	GetCertificate(info *tls.ClientHelloInfo) (*tls.Certificate, error)
}

type Config struct {
	DefaultTargetURL  string
	DefaultAuthHeader string
	SetupProxy        func(*proxy.HTTPProxy)
	CacheTTL          time.Duration
	RulesDir          string
}

func Run(ctx context.Context, config Config) error {
	rulesDir := config.RulesDir
	if rulesDir == "" {
		rulesDir = os.Getenv("RULES_DIR")
	}

	target := os.Getenv("TARGET_URL")
	if target == "" && rulesDir == "" {
		target = config.DefaultTargetURL
		if target == "" {
			target = "https://generativelanguage.googleapis.com"
		}
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

	caCertPath := os.Getenv("CA_CERT_PATH")
	caKeyPath := os.Getenv("CA_KEY_PATH")
	proxyAuthToken := os.Getenv("PROXY_AUTH_TOKEN")

	var fallback *proxy.HTTPProxy
	if target != "" {
		targetURL, err := url.Parse(target)
		if err != nil {
			return fmt.Errorf("invalid TARGET_URL: %w", err)
		}

		p, err := proxy.NewHTTPProxy(targetURL, upstreamAuthToken, upstreamAuthHeader, caCertPath, caKeyPath)
		if err != nil {
			return fmt.Errorf("failed to create proxy: %w", err)
		}
		if proxyAuthToken != "" {
			p.RequiredProxyToken = proxyAuthToken
		}
		fallback = p
	}

	var c *cache.InMemoryCache
	cacheTTL := config.CacheTTL
	if cacheTTLEnv := os.Getenv("CACHE_TTL"); cacheTTLEnv != "" {
		d, err := time.ParseDuration(cacheTTLEnv)
		if err != nil {
			return fmt.Errorf("invalid CACHE_TTL %q: %w", cacheTTLEnv, err)
		}
		cacheTTL = d
	}

	if cacheTTL > 0 {
		cleanupInterval := 1 * time.Minute
		if cleanupEnv := os.Getenv("CACHE_CLEANUP_INTERVAL"); cleanupEnv != "" {
			d, err := time.ParseDuration(cleanupEnv)
			if err != nil {
				return fmt.Errorf("invalid CACHE_CLEANUP_INTERVAL %q: %w", cleanupEnv, err)
			}
			cleanupInterval = d
		}

		c = cache.NewInMemoryCache(cleanupInterval)
		if fallback != nil {
			fallback.Transport = proxy.NewCachingTransport(c, fallback.Transport, cacheTTL)
		}
		log.Printf("Enabled caching with TTL %v (cleanup interval %v)", cacheTTL, cleanupInterval)
	}

	if config.SetupProxy != nil && fallback != nil {
		config.SetupProxy(fallback)
	}

	var handler http.Handler
	if rulesDir != "" {
		var fallbackHandler http.Handler
		if fallback != nil {
			fallbackHandler = fallback
		}
		rr := NewRuleRouter(rulesDir, fallbackHandler, caCertPath, caKeyPath, cacheTTL, c)
		if proxyAuthToken != "" {
			rr.SetProxyAuthToken(proxyAuthToken)
		}
		if err := rr.loadRules(); err != nil {
			return fmt.Errorf("failed to load configuration rules: %w", err)
		}

		sighup := make(chan os.Signal, 1)
		signal.Notify(sighup, syscall.SIGHUP)
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case <-sighup:
					log.Println("Received SIGHUP, reloading configuration rules...")
					if err := rr.loadRules(); err != nil {
						log.Printf("Error reloading configuration: %v", err)
					} else {
						log.Println("Configuration successfully reloaded!")
					}
				}
			}
		}()

		handler = rr
	} else {
		handler = fallback
	}

	if os.Getenv("OTEL_INSTRUMENTATION_ENABLED") == "true" {
		otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	httpsPort := os.Getenv("HTTPS_PORT")
	if httpsPort == "" {
		httpsPort = "8443"
	}

	servedHandler := handler
	if os.Getenv("OTEL_INSTRUMENTATION_ENABLED") == "true" {
		servedHandler = otelhttp.NewHandler(handler, "service-portal")
		log.Println("OpenTelemetry server instrumentation enabled")
	}

	srv := &http.Server{
		Addr:    ":" + port,
		Handler: servedHandler,
	}

	var httpsSrv *http.Server
	if certProv, ok := handler.(CertificateProvider); ok {
		httpsSrv = &http.Server{
			Addr:    ":" + httpsPort,
			Handler: servedHandler,
			TLSConfig: &tls.Config{
				GetCertificate: certProv.GetCertificate,
			},
		}
	}

	targetDesc := target
	if rulesDir != "" {
		if target != "" {
			targetDesc = fmt.Sprintf("rules from %s (fallback: %s)", rulesDir, target)
		} else {
			targetDesc = fmt.Sprintf("rules from %s", rulesDir)
		}
	}

	errChan := make(chan error, 2)
	go func() {
		log.Printf("Starting HTTP proxy on :%s forwarding to %s", port, targetDesc)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errChan <- fmt.Errorf("HTTP server failed: %w", err)
		}
	}()

	if httpsSrv != nil {
		go func() {
			log.Printf("Starting HTTPS proxy on :%s forwarding to %s", httpsPort, targetDesc)
			if err := httpsSrv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				errChan <- fmt.Errorf("HTTPS server failed: %w", err)
			}
		}()
	}

	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
		log.Println("Shutting down servers...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Printf("HTTP server shutdown failed: %v", err)
		}
		if httpsSrv != nil {
			if err := httpsSrv.Shutdown(shutdownCtx); err != nil {
				log.Printf("HTTPS server shutdown failed: %v", err)
			}
		}
	}

	return nil
}
