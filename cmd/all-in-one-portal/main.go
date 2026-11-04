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
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/gke-labs/service-portals/pkg/portals"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	rulesDir := flag.String("rules-dir", "", "Directory containing configuration rules")
	serveDNSFlag := flag.Bool("serve-dns", false, "Serve bounded DNS for configured rule hosts")
	dnsBindAddr := flag.String("dns-bind-addr", "", "Address to bind DNS server")
	dnsPort := flag.String("dns-port", "", "Port to bind DNS server (default 53)")
	grpcBindAddr := flag.String("grpc-bind-addr", "", "Address to bind controller-facing gRPC server (e.g. :8444)")
	grpcCertFile := flag.String("grpc-tls-cert-file", "", "Server TLS certificate file for gRPC mTLS")
	grpcKeyFile := flag.String("grpc-tls-key-file", "", "Server TLS private key file for gRPC mTLS")
	grpcClientCAFile := flag.String("grpc-tls-client-ca-file", "", "Client CA certificate file for gRPC mTLS")
	grpcAllowedCallers := flag.String("grpc-allowed-callers", "", "Comma-separated allowlist of controller identities permitted to call the bind API")
	flag.Parse()

	serveDNS := *serveDNSFlag
	if env := os.Getenv("SERVE_DNS"); env != "" {
		serveDNS = (env == "true" || env == "1")
	}

	var allowedCallers []string
	if *grpcAllowedCallers != "" {
		for _, c := range strings.Split(*grpcAllowedCallers, ",") {
			if trimmed := strings.TrimSpace(c); trimmed != "" {
				allowedCallers = append(allowedCallers, trimmed)
			}
		}
	}

	config := portals.Config{
		ServeDNS:            serveDNS,
		DNSBindAddr:         *dnsBindAddr,
		ProxyDNSPort:        *dnsPort,
		GRPCBindAddr:        *grpcBindAddr,
		GRPCTLSCertFile:     *grpcCertFile,
		GRPCTLSKeyFile:      *grpcKeyFile,
		GRPCTLSClientCAFile: *grpcClientCAFile,
		GRPCAllowedCallers:  allowedCallers,
	}
	if *rulesDir != "" {
		config.RulesDir = *rulesDir
	}

	if err := portals.Run(ctx, config); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
