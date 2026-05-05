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
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/gke-labs/service-portals/pkg/portals"
	"github.com/gke-labs/service-portals/pkg/proxy"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	targetURL := os.Getenv("TARGET_URL")
	if targetURL == "" {
		targetURL = "https://api.github.com/"
	}

	config := portals.Config{
		DefaultTargetURL:  targetURL,
		DefaultAuthHeader: "Authorization",
		SetupProxy: func(p *proxy.HTTPProxy) {
			p.Transport = &loggingTransport{
				underlying: p.Transport,
			}
		},
	}

	if err := portals.Run(ctx, config); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

type loggingTransport struct {
	underlying http.RoundTripper
}

func (t *loggingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	log.Printf("--- GitHub Portal: Request Intercepted ---")
	log.Printf("URL: %s", req.URL.String())
	log.Printf("Method: %s", req.Method)
	for k, v := range req.Header {
		if k == "Authorization" {
			log.Printf("Header %s: [REDACTED]", k)
			continue
		}
		log.Printf("Header %s: %v", k, v)
	}

	resp, err := t.underlying.RoundTrip(req)
	if err != nil {
		log.Printf("Error sending request: %v", err)
		return resp, err
	}

	log.Printf("--- GitHub Portal: Response Intercepted ---")
	log.Printf("Status: %s", resp.Status)

	for k, v := range resp.Header {
		log.Printf("Header %s: %v", k, v)
	}

	return resp, nil
}
