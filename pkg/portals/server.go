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
	"errors"
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
	"github.com/gke-labs/service-portals/pkg/dns"
	"github.com/gke-labs/service-portals/pkg/networking"
	portalsv1 "github.com/gke-labs/service-portals/pkg/portals/v1"
	"github.com/gke-labs/service-portals/pkg/proxy"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"golang.org/x/net/dns/dnsmessage"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// DefaultAdminSocketPath is the default Unix domain socket path for the local node agent admin API.
const DefaultAdminSocketPath = "/run/service-portal/portal.sock"

// DefaultBindSocketPath is the default Unix domain socket path for the local node agent PodBindService gRPC API.
const DefaultBindSocketPath = "/run/service-portal/bind.sock"

// DefaultProxyDNSPort is the default unprivileged port for the proxy DNS server.
const DefaultProxyDNSPort = "1053"

// ResolveDNSPort returns the DNS port to use, checking the provided port,
// the PROXY_DNS_PORT environment variable, the DNS_PORT environment variable,
// and finally falling back to DefaultProxyDNSPort ("1053").
func ResolveDNSPort(configuredPort string) string {
	if configuredPort != "" {
		return configuredPort
	}
	if env := os.Getenv("PROXY_DNS_PORT"); env != "" {
		return env
	}
	if env := os.Getenv("DNS_PORT"); env != "" {
		return env
	}
	return DefaultProxyDNSPort
}

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
	BindingStore      *portalsv1.BindingStore
	BindSocketPath    string
	ServeDNS          bool
	DNSBindAddr       string
	ProxyDNSPort      string
	ProxyBindAddrV6   string
	DefaultAction     string
}

// servePodBindService starts a gRPC server hosting PodBindService on a private Unix domain socket.
// The socket is chmod 0600 (only accessible by proxy UID and root). Secret values are never logged;
// no message-logging interceptors are installed. Failing to create the socket or set its mode
// fails closed and stops startup.
func servePodBindService(sockPath string, store *portalsv1.BindingStore) (func(), error) {
	if store == nil {
		return nil, errors.New("cannot serve PodBindService with nil BindingStore")
	}
	if !filepath.IsAbs(sockPath) {
		return nil, fmt.Errorf("bind socket path %q must be an absolute path", sockPath)
	}

	if err := os.Remove(sockPath); err != nil && !os.IsNotExist(err) {
		log.Printf("warning: removing existing bind socket %s: %v", sockPath, err)
	}
	if err := os.MkdirAll(filepath.Dir(sockPath), 0750); err != nil {
		return nil, fmt.Errorf("failed to create bind socket directory: %w", err)
	}
	l, err := net.Listen("unix", sockPath)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on bind unix socket %s: %w", sockPath, err)
	}

	// Security: The bind unix socket must be mode 0600 (accessible only by the listening
	// proxy UID and root). Making the socket world-writable would allow any process that can
	// see the hostPath to register arbitrary pods or bind policies, bypassing security
	// controls. A failure to enforce permissions must fail closed and stop startup.
	if err := os.Chmod(sockPath, 0600); err != nil {
		if cErr := l.Close(); cErr != nil {
			log.Printf("warning: closing bind listener: %v", cErr)
		}
		if rErr := os.Remove(sockPath); rErr != nil && !os.IsNotExist(rErr) {
			log.Printf("warning: removing bind socket %s: %v", sockPath, rErr)
		}
		return nil, fmt.Errorf("failed to chmod bind socket %s to 0600: %w", sockPath, err)
	}

	grpcServer := grpc.NewServer()
	portalsv1.RegisterPodBindServiceServer(grpcServer, store)

	go func() {
		log.Printf("Starting PodBindService gRPC server on unix socket %s", sockPath)
		if err := grpcServer.Serve(l); err != nil && err != grpc.ErrServerStopped {
			log.Printf("PodBindService gRPC server error: %v", err)
		}
	}()

	stop := func() {
		stopped := make(chan struct{})
		go func() {
			grpcServer.GracefulStop()
			close(stopped)
		}()
		select {
		case <-stopped:
		case <-time.After(2 * time.Second):
			grpcServer.Stop()
		}
		if err := os.Remove(sockPath); err != nil && !os.IsNotExist(err) {
			log.Printf("warning: removing bind socket %s: %v", sockPath, err)
		}
	}

	return stop, nil
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

	var pm *PodMap
	if config.PodMap != nil {
		pm = config.PodMap
	} else if os.Getenv("ENABLE_POD_MAP") == "true" {
		pm = NewPodMap()
	}

	if pm != nil && rulesDir != "" {
		return fmt.Errorf("rules directory %q cannot be configured with pod map enabled: NRI mode uses bound egress policies", rulesDir)
	}

	caCertPath := os.Getenv("CA_CERT_PATH")
	caKeyPath := os.Getenv("CA_KEY_PATH")

	upstreamCACertPath := os.Getenv("UPSTREAM_CA_CERT_PATH")
	if pm == nil && upstreamCACertPath != "" {
		return fmt.Errorf("UPSTREAM_CA_CERT_PATH is only supported with pod map enabled (NRI mode)")
	}

	if upstreamCACertPath != "" && caCertPath != "" {
		cleanUpstream := filepath.Clean(upstreamCACertPath)
		cleanCA := filepath.Clean(caCertPath)
		cleanCADir := filepath.Clean(filepath.Dir(caCertPath))
		if cleanUpstream == cleanCA || cleanUpstream == cleanCADir {
			return fmt.Errorf("upstream CA cert path %q must not point to interception CA %q", upstreamCACertPath, caCertPath)
		}
	}

	var target string
	var fallback *proxy.HTTPProxy
	var c *cache.InMemoryCache
	var cacheTTL time.Duration
	if pm == nil {
		target = os.Getenv("TARGET_URL")
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

		cacheTTL = config.CacheTTL
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
	}

	var store *portalsv1.BindingStore
	var adminSrv *http.Server
	var adminListener net.Listener
	var adminSockPath string
	if pm != nil {
		store = config.BindingStore
		if store == nil {
			var err error
			store, err = portalsv1.NewBindingStore(os.Getenv("STORE_DIR"))
			if err != nil {
				return fmt.Errorf("failed to create binding store: %w", err)
			}
		}
		pm.SetBindingStore(store)

		// Security: The PodBindService gRPC API must bind exclusively to a private Unix domain
		// socket reachable only by the proxy UID and root (mode 0600), never a TCP address.
		// Because the node proxy runs with hostNetwork: true, binding to a TCP port would expose
		// policy binding and secret injection to any workload on the node network, creating an
		// unauthenticated privilege escalation bypass. Controller-facing remote transport with
		// gRPC and mTLS is tracked separately in #227.
		bindSockPath := config.BindSocketPath
		if bindSockPath == "" {
			bindSockPath = DefaultBindSocketPath
		}

		stopBind, err := servePodBindService(bindSockPath, store)
		if err != nil {
			return fmt.Errorf("failed to start PodBindService: %w", err)
		}
		defer stopBind()

		controllerAddr := os.Getenv("CONTROLLER_ADDR")
		if controllerAddr != "" {
			controllerCACertPath := os.Getenv("CONTROLLER_CA_CERT_PATH")
			if controllerCACertPath == "" {
				return errors.New("CONTROLLER_CA_CERT_PATH is required when CONTROLLER_ADDR is set")
			}
			if _, err := credentials.NewClientTLSFromFile(controllerCACertPath, ""); err != nil {
				return fmt.Errorf("failed to load controller CA cert from %s: %w", controllerCACertPath, err)
			}
			controllerTokenPath := os.Getenv("CONTROLLER_TOKEN_PATH")
			if controllerTokenPath == "" {
				return errors.New("CONTROLLER_TOKEN_PATH is required when CONTROLLER_ADDR is set")
			}
			if _, err := os.ReadFile(controllerTokenPath); err != nil {
				return fmt.Errorf("failed to read controller token file %s: %w", controllerTokenPath, err)
			}
			go runControllerClient(ctx, controllerClientConfig{
				addr:       controllerAddr,
				tokenPath:  controllerTokenPath,
				caCertPath: controllerCACertPath,
				pm:         pm,
				store:      store,
			})
		}

		// Security: The admin API must bind exclusively to a private Unix domain socket
		// or loopback (127.0.0.1 or ::1). Because the node proxy runs with hostNetwork: true,
		// binding to 0.0.0.0 or an external interface would expose pod registration to any
		// pod on the node network or external network entities, creating an unauthenticated
		// privilege escalation bypass (daemonset-mode.md Question 2).
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
	if pm != nil {
		transport, err := proxy.NewUpstreamTransport(upstreamCACertPath)
		if err != nil {
			return fmt.Errorf("failed to configure upstream transport: %w", err)
		}
		if os.Getenv("OTEL_INSTRUMENTATION_ENABLED") == "true" {
			transport = otelhttp.NewTransport(transport)
		}

		var signer *proxy.CertSigner
		if caCertPath != "" && caKeyPath != "" {
			s, err := proxy.NewCertSigner(caCertPath, caKeyPath)
			if err != nil {
				return fmt.Errorf("failed to create cert signer: %w", err)
			}
			signer = s
		}

		handler = NewEgressHandler(pm, store, transport, signer)
	} else if rulesDir != "" {
		var fallbackHandler http.Handler
		if fallback != nil {
			fallbackHandler = fallback
		}
		rr := NewRuleRouter(rulesDir, fallbackHandler, caCertPath, caKeyPath, cacheTTL, c)
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

	serveDNS := config.ServeDNS
	if env := os.Getenv("SERVE_DNS"); env != "" {
		serveDNS = (env == "true" || env == "1")
	}

	var dnsServers []*dns.Server
	if serveDNS {
		dnsPort := ResolveDNSPort(config.ProxyDNSPort)

		defaultAction := config.DefaultAction
		if defaultAction == "" {
			defaultAction = os.Getenv("DEFAULT_ACTION")
		}
		if defaultAction == "" {
			defaultAction = "Deny"
		}

		var evaluator dns.QueryEvaluator
		if qe, ok := handler.(dns.QueryEvaluator); ok {
			evaluator = qe
		} else if fallback != nil && fallback.TargetURL != nil {
			targetHost := strings.ToLower(proxy.HostWithoutPort(fallback.TargetURL.Host))
			evaluator = dns.QueryEvaluatorFunc(func(_ context.Context, h string, _ dnsmessage.Type, _ net.Addr) dns.QueryDecision {
				if targetHost != "" && (targetHost == h || strings.HasPrefix(h, targetHost+".")) {
					return dns.DecisionAllow
				}
				return dns.DecisionDeny
			})
		}

		var proxyIPv4 net.IP
		proxyIPStr := bindHost
		if proxyIPStr == "" || proxyIPStr == "0.0.0.0" {
			proxyIPStr = os.Getenv("PROXY_HOST")
		}
		if proxyIPStr != "" {
			proxyIPv4 = net.ParseIP(proxyIPStr)
		}

		var proxyIPv6 net.IP
		v6Str := config.ProxyBindAddrV6
		if v6Str == "" {
			v6Str = os.Getenv("PROXY_HOST_V6")
		}
		if v6Str == "" {
			v6Str = networking.DiscoverNodeIPv6()
		}
		if v6Str != "" {
			proxyIPv6 = net.ParseIP(v6Str)
		}

		var bindAddrs []string
		if config.DNSBindAddr != "" {
			bindAddrs = strings.Split(config.DNSBindAddr, ",")
		} else if env := os.Getenv("DNS_BIND_ADDR"); env != "" {
			bindAddrs = strings.Split(env, ",")
		} else {
			if proxyIPv4 != nil {
				bindAddrs = append(bindAddrs, net.JoinHostPort(proxyIPv4.String(), dnsPort))
			}
			if proxyIPv6 != nil {
				bindAddrs = append(bindAddrs, net.JoinHostPort(proxyIPv6.String(), dnsPort))
			}
			if len(bindAddrs) == 0 {
				bindAddrs = append(bindAddrs, ":"+dnsPort)
			}
		}

		for _, addr := range bindAddrs {
			addr = strings.TrimSpace(addr)
			if addr == "" {
				continue
			}
			dnsCfg := dns.Config{
				BindAddr:      addr,
				ProxyIPv4:     proxyIPv4,
				ProxyIPv6:     proxyIPv6,
				Evaluator:     evaluator,
				DefaultAction: defaultAction,
			}
			s, err := dns.NewServer(dnsCfg)
			if err != nil {
				return fmt.Errorf("failed to create DNS server for %s: %w", addr, err)
			}
			if err := s.Start(ctx); err != nil {
				return fmt.Errorf("failed to start DNS server on %s: %w", addr, err)
			}
			dnsServers = append(dnsServers, s)
			log.Printf("Starting node DNS server on %s (proxyIPv4: %s, proxyIPv6: %s, defaultAction: %s)", addr, proxyIPv4, proxyIPv6, defaultAction)
		}
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
	if pm != nil {
		targetDesc = "egress policy"
	} else if rulesDir != "" {
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
		for _, s := range dnsServers {
			if err := s.Shutdown(shutdownCtx); err != nil {
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
