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
	"syscall"

	"github.com/gke-labs/service-portals/pkg/portals"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	rulesDir := flag.String("rules-dir", "", "Directory containing configuration rules")
	serveDNSFlag := flag.Bool("serve-dns", false, "Serve DNS for configured rule hosts")
	dnsBindAddr := flag.String("dns-bind-addr", "", "Address to bind DNS server (default 127.0.0.1:53)")
	proxyBindAddr := flag.String("proxy-bind-addr", "", "Address to bind HTTP/HTTPS proxy (default: all interfaces, or 127.0.0.2 in sidecar mode)")
	defaultAction := flag.String("default-action", "", "Default action for unconfigured DNS hosts (Deny or Allow)")
	flag.Parse()

	bindAddr := *proxyBindAddr
	if bindAddr == "" {
		bindAddr = os.Getenv("PROXY_BIND_ADDR")
	}

	serveDNS := *serveDNSFlag
	if env := os.Getenv("SERVE_DNS"); env != "" {
		serveDNS = (env == "true" || env == "1")
	} else if !*serveDNSFlag && bindAddr != "" && bindAddr != "0.0.0.0" {
		// When bound to a specific loopback address (sidecar mode), default serveDNS to true
		serveDNS = true
	}

	config := portals.Config{
		ServeDNS:      serveDNS,
		DNSBindAddr:   *dnsBindAddr,
		ProxyBindAddr: bindAddr,
		DefaultAction: *defaultAction,
	}
	if *rulesDir != "" {
		config.RulesDir = *rulesDir
	}

	if err := portals.Run(ctx, config); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
