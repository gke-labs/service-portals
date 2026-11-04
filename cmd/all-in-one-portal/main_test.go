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
	"flag"
	"os"
	"testing"
)

func TestFlags(t *testing.T) {
	// Backup original args and reset flags
	origArgs := os.Args
	defer func() { os.Args = origArgs }()

	os.Args = []string{
		"cmd",
		"-rules-dir", "/tmp/rules",
		"-grpc-bind-addr", ":8444",
		"-grpc-tls-cert-file", "/etc/certs/tls.crt",
		"-grpc-tls-key-file", "/etc/certs/tls.key",
		"-grpc-tls-client-ca-file", "/etc/certs/ca.crt",
		"-grpc-allowed-callers", "sandbox-controller,claim-controller",
	}

	// Reset CommandLine so we can redefine/reparse flags
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

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

	_ = serveDNSFlag
	_ = dnsBindAddr
	_ = dnsPort

	if *rulesDir != "/tmp/rules" {
		t.Errorf("expected rules-dir to be /tmp/rules, got %q", *rulesDir)
	}
	if *grpcBindAddr != ":8444" {
		t.Errorf("expected grpc-bind-addr to be :8444, got %q", *grpcBindAddr)
	}
	if *grpcCertFile != "/etc/certs/tls.crt" {
		t.Errorf("expected grpc-tls-cert-file to be /etc/certs/tls.crt, got %q", *grpcCertFile)
	}
	if *grpcKeyFile != "/etc/certs/tls.key" {
		t.Errorf("expected grpc-tls-key-file to be /etc/certs/tls.key, got %q", *grpcKeyFile)
	}
	if *grpcClientCAFile != "/etc/certs/ca.crt" {
		t.Errorf("expected grpc-tls-client-ca-file to be /etc/certs/ca.crt, got %q", *grpcClientCAFile)
	}
	if *grpcAllowedCallers != "sandbox-controller,claim-controller" {
		t.Errorf("expected grpc-allowed-callers to be sandbox-controller,claim-controller, got %q", *grpcAllowedCallers)
	}
}
