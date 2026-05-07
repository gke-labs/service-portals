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
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/gke-labs/service-portals/pkg/proxy"
)

type Router struct {
	routes map[string]*proxy.HTTPProxy
}

func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// Simple routing based on host header
	target := req.Host
	// Strip port if present
	if idx := strings.LastIndex(target, ":"); idx != -1 {
		target = target[:idx]
	}

	if p, ok := r.routes[target]; ok {
		p.ServeHTTP(w, req)
		return
	}

	http.Error(w, "Not Found", http.StatusNotFound)
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Configure services from env
	// Example: SERVICE_NAMES="gemini,github"
	// GEMINI_TARGET_URL=... GEMINI_AUTH_HEADER=...
	// GITHUB_TARGET_URL=... GITHUB_AUTH_HEADER=...
	serviceNames := strings.Split(os.Getenv("SERVICE_NAMES"), ",")
	routes := make(map[string]*proxy.HTTPProxy)

	for _, name := range serviceNames {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		prefix := strings.ToUpper(name) + "_"
		target := os.Getenv(prefix + "TARGET_URL")
		authHeader := os.Getenv(prefix + "AUTH_HEADER")
		authToken := os.Getenv(prefix + "AUTH_TOKEN")
		host := os.Getenv(prefix + "HOST") // e.g. gemini.portal

		if target == "" || host == "" {
			continue
		}

		targetURL, err := url.Parse(target)
		if err != nil {
			continue
		}

		p, err := proxy.NewHTTPProxy(targetURL, authToken, authHeader, "", "")
		if err == nil {
			routes[host] = p
		}
	}

	router := &Router{routes: routes}

	srv := &http.Server{
		Addr:    ":8080",
		Handler: router,
	}

	go func() {
		fmt.Println("Starting all-in-one proxy on :8080")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "server failed: %v\n", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
}
