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
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/gke-labs/service-portals/pkg/cache"
	"github.com/gke-labs/service-portals/pkg/proxy"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
)

// DefaultAdminSocketPath is the default Unix domain socket path for the local node agent admin and bind API.
const DefaultAdminSocketPath = "/run/service-portal/portal.sock"

type CertificateProvider interface {
	GetCertificate(info *tls.ClientHelloInfo) (*tls.Certificate, error)
}

type Config struct {
	DefaultTargetURL  string
	DefaultAuthHeader string
	SetupProxy        func(*proxy.HTTPProxy)
	CacheTTL          time.Duration
	RulesDir          string
	PodMap            *PodMap
}

// validateAdminAddr enforces that the administrative and Bind API server binds exclusively
// to a loopback IP (127.0.0.1 or ::1) or a private Unix domain socket.
func validateAdminAddr(addr string) error {
	if strings.HasPrefix(addr, "unix:") || strings.HasPrefix(addr, "/") {
		return nil
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("admin address %q must be in host:port format or a unix socket path: %w", addr, err)
	}
	if host == "" {
		return fmt.Errorf("admin address %q cannot bind to all interfaces; must specify loopback (127.0.0.1 or ::1)", addr)
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("admin address %q has invalid host %q; must be loopback (127.0.0.1 or ::1)", addr, host)
	}
	if !ip.IsLoopback() {
		return fmt.Errorf("admin address %q must bind to loopback (127.0.0.1 or ::1), refusing non-loopback address %s", addr, ip)
	}
	return nil
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

	var pm *PodMap
	if config.PodMap != nil {
		pm = config.PodMap
	} else if os.Getenv("ENABLE_POD_MAP") == "true" {
		pm = NewPodMap()
	}

	var adminSrv *http.Server
	var adminListener net.Listener
	var adminSockPath string
	if pm != nil {
		// Security: The admin and Bind API must bind exclusively to a private Unix domain socket
		// or loopback (127.0.0.1 or ::1). Because the node proxy runs with hostNetwork: true,
		// binding to 0.0.0.0 or an external interface would expose pod registration and policy
		// binding to any pod on the node network or external network entities, creating an
		// unauthenticated privilege escalation bypass (daemonset-mode.md Question 2).
		// Controller-facing remote transport with gRPC and mTLS is tracked separately in #227.
		adminAddr := os.Getenv("ADMIN_ADDR")
		if adminAddr == "" {
			adminAddr = DefaultAdminSocketPath
		}
		if err := validateAdminAddr(adminAddr); err != nil {
			return fmt.Errorf("security violation: %w", err)
		}

		adminSrv = &http.Server{
			Handler: pm.AdminHandler(),
		}

		if strings.HasPrefix(adminAddr, "unix://") || strings.HasPrefix(adminAddr, "/") {
			adminSockPath = strings.TrimPrefix(adminAddr, "unix://")
			if err := os.Remove(adminSockPath); err != nil && !os.IsNotExist(err) {
				log.Printf("warning: removing existing admin socket %s: %v", adminSockPath, err)
			}
			if err := os.MkdirAll(filepath.Dir(adminSockPath), 0750); err != nil {
				return fmt.Errorf("failed to create admin socket directory: %w", err)
			}
			l, err := net.Listen("unix", adminSockPath)
			if err != nil {
				return fmt.Errorf("failed to listen on admin unix socket %s: %w", adminSockPath, err)
			}
			// Security: The admin unix socket must be mode 0600 (accessible only by the listening
			// proxy UID and root). Making the socket world-writable would allow any process that can
			// see the hostPath to register arbitrary pods or bind policies, bypassing security
			// controls. The plugin runs as root and connects regardless. A failure to enforce
			// permissions must fail closed and stop startup.
			if err := os.Chmod(adminSockPath, 0600); err != nil {
				if cErr := l.Close(); cErr != nil {
					log.Printf("warning: closing admin listener: %v", cErr)
				}
				if rErr := os.Remove(adminSockPath); rErr != nil && !os.IsNotExist(rErr) {
					log.Printf("warning: removing admin socket %s: %v", adminSockPath, rErr)
				}
				return fmt.Errorf("failed to chmod admin socket %s to 0600: %w", adminSockPath, err)
			}
			adminListener = l
			go func() {
				log.Printf("Starting admin server on unix socket %s", adminSockPath)
				if err := adminSrv.Serve(adminListener); err != nil && err != http.ErrServerClosed {
					log.Printf("Admin server error: %v", err)
				}
			}()
		} else {
			adminSrv.Addr = adminAddr
			go func() {
				log.Printf("Starting admin and bind API server on %s", adminAddr)
				if err := adminSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					log.Printf("Admin server error: %v", err)
				}
			}()
		}
	}

	var handler http.Handler
	if rulesDir != "" {
		var fallbackHandler http.Handler
		if fallback != nil {
			fallbackHandler = fallback
		}
		rr := NewRuleRouter(rulesDir, fallbackHandler, caCertPath, caKeyPath, cacheTTL, c)
		if pm != nil {
			rr.SetPodMap(pm)
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

	bindHost := os.Getenv("PROXY_HOST")
	if bindHost == "" {
		bindHost = os.Getenv("BIND_HOST")
	}

	servedHandler := handler
	if os.Getenv("OTEL_INSTRUMENTATION_ENABLED") == "true" {
		servedHandler = otelhttp.NewHandler(handler, "service-portal")
		log.Println("OpenTelemetry server instrumentation enabled")
	}

	srv := &http.Server{
		Addr:    net.JoinHostPort(bindHost, port),
		Handler: servedHandler,
	}

	var httpsSrv *http.Server
	if certProv, ok := handler.(CertificateProvider); ok {
		httpsSrv = &http.Server{
			Addr:    net.JoinHostPort(bindHost, httpsPort),
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
		log.Printf("Starting HTTP proxy on %s forwarding to %s", srv.Addr, targetDesc)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errChan <- fmt.Errorf("HTTP server failed: %w", err)
		}
	}()

	if httpsSrv != nil {
		go func() {
			log.Printf("Starting HTTPS proxy on %s forwarding to %s", httpsSrv.Addr, targetDesc)
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
		if adminSrv != nil {
			if err := adminSrv.Shutdown(shutdownCtx); err != nil {
				log.Printf("Admin server shutdown failed: %v", err)
			}
		}
		if adminListener != nil {
			if err := adminListener.Close(); err != nil {
				log.Printf("Admin listener close error: %v", err)
			}
		}
		if adminSockPath != "" {
			if err := os.Remove(adminSockPath); err != nil && !os.IsNotExist(err) {
				log.Printf("Admin socket remove error: %v", err)
			}
		}
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
