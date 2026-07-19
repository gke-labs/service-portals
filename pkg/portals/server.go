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
	"github.com/gke-labs/service-portals/pkg/proxy"
	pb "github.com/gke-labs/service-portals/pkg/portals/proto"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
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

	var c *cache.InMemoryCache
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

		c = cache.NewInMemoryCache(cleanupInterval)
		p.Transport = proxy.NewCachingTransport(c, p.Transport, cacheTTL)
		log.Printf("Enabled caching with TTL %v (cleanup interval %v)", cacheTTL, cleanupInterval)
	}

	if config.SetupProxy != nil {
		config.SetupProxy(p)
	}

	rulesDir := config.RulesDir
	if rulesDir == "" {
		rulesDir = os.Getenv("RULES_DIR")
	}

	rr := NewRuleRouter(rulesDir, p, caCertPath, caKeyPath, cacheTTL, c)
	if rulesDir != "" {
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

	var grpcServer *grpc.Server

	if grpcTLSCertPath != "" && grpcTLSKeyPath != "" {
		cert, err := tls.LoadX509KeyPair(grpcTLSCertPath, grpcTLSKeyPath)
		if err != nil {
			return fmt.Errorf("failed to load gRPC server key pair: %w", err)
		}

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
		}

		if grpcClientCAPath != "" {
			caPem, err := os.ReadFile(grpcClientCAPath)
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

	lis, err := net.Listen("tcp", ":"+grpcPort)
	if err != nil {
		return fmt.Errorf("failed to listen on gRPC port %s: %w", grpcPort, err)
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

	errChan := make(chan error, 3)
	go func() {
		log.Printf("Starting HTTP proxy on :%s forwarding to %s", port, target)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errChan <- fmt.Errorf("HTTP server failed: %w", err)
		}
	}()

	if httpsSrv != nil {
		go func() {
			log.Printf("Starting HTTPS proxy on :%s forwarding to %s", httpsPort, target)
			if err := httpsSrv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				errChan <- fmt.Errorf("HTTPS server failed: %w", err)
			}
		}()
	}

	go func() {
		log.Printf("Starting gRPC configurator server on :%s", grpcPort)
		if err := grpcServer.Serve(lis); err != nil && err != grpc.ErrServerStopped {
			errChan <- fmt.Errorf("gRPC server failed: %w", err)
		}
	}()

	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
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
	}

	return nil
}
