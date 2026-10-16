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
	"strings"
	"syscall"
	"time"

	"github.com/gke-labs/service-portals/pkg/cache"
	"github.com/gke-labs/service-portals/pkg/dns"
	"github.com/gke-labs/service-portals/pkg/proxy"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
)

type CertificateProvider interface {
	GetCertificate(info *tls.ClientHelloInfo) (*tls.Certificate, error)
}

type Config struct {
	DefaultTargetURL   string
	DefaultAuthHeader  string
	SetupProxy         func(*proxy.HTTPProxy)
	CacheTTL           time.Duration
	RulesDir           string
	ProxyBindAddr      string
	DNSBindAddr        string
	ServeDNS           bool
	DefaultAction      string
	UpstreamDNSServers []string
}

func Run(ctx context.Context, config Config) error {
	target := os.Getenv("TARGET_URL")
	if target == "" {
		target = config.DefaultTargetURL
	}

	rulesDir := config.RulesDir
	if rulesDir == "" {
		rulesDir = os.Getenv("RULES_DIR")
	}

	if target == "" && rulesDir == "" {
		return fmt.Errorf("TARGET_URL or RULES_DIR must be configured")
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

	upstreamDNSServers := config.UpstreamDNSServers
	if len(upstreamDNSServers) == 0 {
		upstreamDNSServers = proxy.ResolveUpstreamDNSServers()
	}
	upstreamResolver := proxy.NewUpstreamResolver(upstreamDNSServers)

	var fallback *proxy.HTTPProxy
	if target != "" {
		targetURL, err := url.Parse(target)
		if err != nil {
			return fmt.Errorf("invalid TARGET_URL: %w", err)
		}

		p, err := proxy.NewHTTPProxyWithResolver(targetURL, upstreamAuthToken, upstreamAuthHeader, caCertPath, caKeyPath, upstreamResolver)
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

	var handler http.Handler
	var rr *RuleRouter

	if rulesDir != "" {
		var fallbackHandler http.Handler
		if fallback != nil {
			fallbackHandler = fallback
		}
		rr = NewRuleRouterWithResolver(rulesDir, fallbackHandler, caCertPath, caKeyPath, cacheTTL, c, upstreamResolver)
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
	} else if fallback != nil {
		handler = fallback
	} else {
		return fmt.Errorf("either TARGET_URL or RULES_DIR must be configured")
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

	proxyBindAddr := config.ProxyBindAddr
	if proxyBindAddr == "" {
		proxyBindAddr = os.Getenv("PROXY_BIND_ADDR")
	}

	httpAddr := ":" + port
	httpsAddr := ":" + httpsPort
	if proxyBindAddr != "" && proxyBindAddr != "0.0.0.0" {
		httpAddr = net.JoinHostPort(proxyBindAddr, port)
		httpsAddr = net.JoinHostPort(proxyBindAddr, httpsPort)
	}

	servedHandler := handler
	if os.Getenv("OTEL_INSTRUMENTATION_ENABLED") == "true" {
		servedHandler = otelhttp.NewHandler(handler, "service-portal")
		log.Println("OpenTelemetry server instrumentation enabled")
	}

	srv := &http.Server{
		Addr:    httpAddr,
		Handler: servedHandler,
	}

	var httpsSrv *http.Server
	if certProv, ok := handler.(CertificateProvider); ok {
		httpsSrv = &http.Server{
			Addr:    httpsAddr,
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

	serveDNS := config.ServeDNS
	if env := os.Getenv("SERVE_DNS"); env != "" {
		serveDNS = (env == "true" || env == "1")
	}

	var dnsSrv *dns.Server
	if serveDNS {
		dnsBindAddr := config.DNSBindAddr
		if dnsBindAddr == "" {
			dnsBindAddr = os.Getenv("DNS_BIND_ADDR")
		}
		if dnsBindAddr == "" {
			dnsBindAddr = "127.0.0.1:53"
		}

		defaultAction := config.DefaultAction
		if defaultAction == "" {
			defaultAction = os.Getenv("DEFAULT_ACTION")
		}
		if defaultAction == "" {
			defaultAction = "Deny"
		}

		var matcher dns.RuleMatcher
		if rr != nil {
			matcher = rr
		} else if fallback != nil && fallback.TargetURL != nil {
			matcher = dns.RuleMatcherFunc(func(host string) bool {
				targetHost := strings.ToLower(proxy.HostWithoutPort(fallback.TargetURL.Host))
				return targetHost != "" && host == targetHost
			})
		}

		dnsProxyIPStr := proxyBindAddr
		if dnsProxyIPStr == "" || dnsProxyIPStr == "0.0.0.0" {
			dnsProxyIPStr = "127.0.0.2"
		}
		dnsProxyIP := net.ParseIP(dnsProxyIPStr)

		var dnsProxyIPv6 net.IP
		if v6Str := os.Getenv("PROXY_BIND_ADDR_V6"); v6Str != "" {
			dnsProxyIPv6 = net.ParseIP(v6Str)
		} else {
			dnsProxyIPv6 = net.ParseIP("::1")
		}

		dnsCfg := dns.Config{
			BindAddr:        dnsBindAddr,
			ProxyIPv4:       dnsProxyIP,
			ProxyIPv6:       dnsProxyIPv6,
			Matcher:         matcher,
			DefaultAction:   defaultAction,
			UpstreamServers: upstreamDNSServers,
		}
		var err error
		dnsSrv, err = dns.NewServer(dnsCfg)
		if err != nil {
			return fmt.Errorf("failed to create DNS server: %w", err)
		}
		if err := dnsSrv.Start(ctx); err != nil {
			return fmt.Errorf("failed to start DNS server on %s: %w", dnsBindAddr, err)
		}
		log.Printf("Starting sidecar DNS server on %s (proxy IP: %s, defaultAction: %s)", dnsBindAddr, dnsProxyIP, defaultAction)
	}

	errChan := make(chan error, 3)
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
		if dnsSrv != nil {
			if err := dnsSrv.Shutdown(shutdownCtx); err != nil {
				log.Printf("DNS server shutdown failed: %v", err)
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
