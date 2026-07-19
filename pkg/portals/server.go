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
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gke-labs/service-portals/pkg/cache"
	pb "github.com/gke-labs/service-portals/pkg/portals/proto"
	"github.com/gke-labs/service-portals/pkg/proxy"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
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

// RouterOptions defines all configuration parameters for the router and servers.
type RouterOptions struct {
	TargetURL            string
	UpstreamAuthToken    string
	UpstreamAuthHeader   string
	CacheTTL             time.Duration
	CacheCleanupInterval time.Duration
	RulesDir             string
	Port                 string
	HTTPSPort            string
	GrpcPort             string
	CaCertPath           string
	CaKeyPath            string
	GrpcTLSCertPath      string
	GrpcTLSKeyPath       string
	GrpcClientCAPath     string
	OtelEnabled          bool
	SetupProxy           func(*proxy.HTTPProxy)
}

// Run implements the legacy entry point by translating environment variables into RouterOptions.
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

	caCertPath := os.Getenv("CA_CERT_PATH")
	caKeyPath := os.Getenv("CA_KEY_PATH")

	cacheTTL := config.CacheTTL
	if cacheTTLEnv := os.Getenv("CACHE_TTL"); cacheTTLEnv != "" {
		if d, err := time.ParseDuration(cacheTTLEnv); err == nil {
			cacheTTL = d
		} else {
			log.Printf("Warning: invalid CACHE_TTL %q: %v", cacheTTLEnv, err)
		}
	}

	cleanupInterval := 1 * time.Minute
	if cleanupEnv := os.Getenv("CACHE_CLEANUP_INTERVAL"); cleanupEnv != "" {
		if d, err := time.ParseDuration(cleanupEnv); err == nil {
			cleanupInterval = d
		} else {
			log.Printf("Warning: invalid CACHE_CLEANUP_INTERVAL %q: %v", cleanupEnv, err)
		}
	}

	rulesDir := config.RulesDir
	if rulesDir == "" {
		rulesDir = os.Getenv("RULES_DIR")
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	httpsPort := os.Getenv("HTTPS_PORT")
	if httpsPort == "" {
		httpsPort = "8443"
	}

	grpcPort := os.Getenv("GRPC_PORT")
	if grpcPort == "" {
		grpcPort = "8082"
	}

	grpcTLSCertPath := os.Getenv("GRPC_TLS_CERT_PATH")
	if grpcTLSCertPath == "" {
		grpcTLSCertPath = os.Getenv("TLS_CERT_PATH")
	}
	if grpcTLSCertPath == "" {
		grpcTLSCertPath = caCertPath
	}

	grpcTLSKeyPath := os.Getenv("GRPC_TLS_KEY_PATH")
	if grpcTLSKeyPath == "" {
		grpcTLSKeyPath = os.Getenv("TLS_KEY_PATH")
	}
	if grpcTLSKeyPath == "" {
		grpcTLSKeyPath = caKeyPath
	}

	grpcClientCAPath := os.Getenv("GRPC_CLIENT_CA_PATH")
	if grpcClientCAPath == "" {
		grpcClientCAPath = os.Getenv("CLIENT_CA_PATH")
	}
	if grpcClientCAPath == "" {
		grpcClientCAPath = caCertPath
	}

	otelEnabled := os.Getenv("OTEL_INSTRUMENTATION_ENABLED") == "true"

	opts := RouterOptions{
		TargetURL:            target,
		UpstreamAuthToken:    upstreamAuthToken,
		UpstreamAuthHeader:   upstreamAuthHeader,
		CacheTTL:             cacheTTL,
		CacheCleanupInterval: cleanupInterval,
		RulesDir:             rulesDir,
		Port:                 port,
		HTTPSPort:            httpsPort,
		GrpcPort:             grpcPort,
		CaCertPath:           caCertPath,
		CaKeyPath:            caKeyPath,
		GrpcTLSCertPath:      grpcTLSCertPath,
		GrpcTLSKeyPath:       grpcTLSKeyPath,
		GrpcClientCAPath:     grpcClientCAPath,
		OtelEnabled:          otelEnabled,
		SetupProxy:           config.SetupProxy,
	}

	return RunRouter(ctx, opts)
}

// RunRouter executes the router using explicit options, completely isolated from env/flags.
func RunRouter(ctx context.Context, opts RouterOptions) error {
	targetURL, err := url.Parse(opts.TargetURL)
	if err != nil {
		return fmt.Errorf("invalid TargetURL %q: %w", opts.TargetURL, err)
	}

	p, err := proxy.NewHTTPProxy(targetURL, opts.UpstreamAuthToken, opts.UpstreamAuthHeader, opts.CaCertPath, opts.CaKeyPath)
	if err != nil {
		return fmt.Errorf("failed to create proxy: %w", err)
	}

	var c *cache.InMemoryCache
	if opts.CacheTTL > 0 {
		cleanupInterval := opts.CacheCleanupInterval
		if cleanupInterval == 0 {
			cleanupInterval = 1 * time.Minute
		}
		c = cache.NewInMemoryCache(cleanupInterval)
		p.Transport = proxy.NewCachingTransport(c, p.Transport, opts.CacheTTL)
		log.Printf("Enabled caching with TTL %v (cleanup interval %v)", opts.CacheTTL, cleanupInterval)
	}

	if opts.SetupProxy != nil {
		opts.SetupProxy(p)
	}

	rr := NewRuleRouter(opts.RulesDir, p, opts.CaCertPath, opts.CaKeyPath, opts.CacheTTL, c)
	if opts.RulesDir != "" {
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
	}

	var handler http.Handler = rr

	if opts.OtelEnabled {
		otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
	}

	var grpcServer *grpc.Server

	if opts.GrpcTLSCertPath != "" && opts.GrpcTLSKeyPath != "" {
		cert, err := tls.LoadX509KeyPair(opts.GrpcTLSCertPath, opts.GrpcTLSKeyPath)
		if err != nil {
			return fmt.Errorf("failed to load gRPC server key pair: %w", err)
		}

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
		}

		if opts.GrpcClientCAPath != "" {
			caPem, err := os.ReadFile(opts.GrpcClientCAPath)
			if err != nil {
				return fmt.Errorf("failed to read gRPC client CA file: %w", err)
			}
			certPool := x509.NewCertPool()
			if !certPool.AppendCertsFromPEM(caPem) {
				return fmt.Errorf("failed to append client CA certs")
			}
			tlsConfig.ClientCAs = certPool
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		}

		creds := credentials.NewTLS(tlsConfig)
		grpcServer = grpc.NewServer(grpc.Creds(creds))
		log.Println("gRPC server configured with mTLS")
	} else {
		grpcServer = grpc.NewServer()
		log.Println("gRPC server configured without TLS (insecure)")
	}

	pb.RegisterSidecarReconfiguratorServer(grpcServer, NewConfiguratorServer(rr))

	lis, err := net.Listen("tcp", ":"+opts.GrpcPort)
	if err != nil {
		return fmt.Errorf("failed to listen on gRPC port %s: %w", opts.GrpcPort, err)
	}

	servedHandler := handler
	if opts.OtelEnabled {
		servedHandler = otelhttp.NewHandler(handler, "service-portal")
		log.Println("OpenTelemetry server instrumentation enabled")
	}

	srv := &http.Server{
		Addr:    ":" + opts.Port,
		Handler: servedHandler,
	}

	var httpsSrv *http.Server
	if certProv, ok := handler.(CertificateProvider); ok {
		httpsSrv = &http.Server{
			Addr:    ":" + opts.HTTPSPort,
			Handler: servedHandler,
			TLSConfig: &tls.Config{
				GetCertificate: certProv.GetCertificate,
			},
		}
	}

	g, groupCtx := errgroup.WithContext(ctx)

	g.Go(func() error {
		log.Printf("Starting HTTP proxy on :%s forwarding to %s", opts.Port, opts.TargetURL)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("HTTP server failed: %w", err)
		}
		return nil
	})

	if httpsSrv != nil {
		g.Go(func() error {
			log.Printf("Starting HTTPS proxy on :%s forwarding to %s", opts.HTTPSPort, opts.TargetURL)
			if err := httpsSrv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				return fmt.Errorf("HTTPS server failed: %w", err)
			}
			return nil
		})
	}

	g.Go(func() error {
		log.Printf("Starting gRPC configurator server on :%s", opts.GrpcPort)
		if err := grpcServer.Serve(lis); err != nil && err != grpc.ErrServerStopped {
			return fmt.Errorf("gRPC server failed: %w", err)
		}
		return nil
	})

	// Wait for context cancellation or any server failure
	g.Go(func() error {
		<-groupCtx.Done()
		log.Println("Shutting down servers...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		grpcServer.GracefulStop()

		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Printf("HTTP server shutdown failed: %v", err)
		}
		if httpsSrv != nil {
			if err := httpsSrv.Shutdown(shutdownCtx); err != nil {
				log.Printf("HTTPS server shutdown failed: %v", err)
			}
		}
		return nil
	})

	return g.Wait()
}
