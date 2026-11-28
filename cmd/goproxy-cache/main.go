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
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/gke-labs/service-portals/pkg/goproxy"
)

func main() {
	var cfg goproxy.Config
	cfg.InitDefaults()

	listenAddr := flag.String("listen-addr", ":8080", "Address to listen on")
	flag.StringVar(&cfg.UpstreamURL, "upstream-url", cfg.UpstreamURL, "Upstream Go module proxy URL")
	flag.StringVar(&cfg.CacheDir, "cache-dir", filepath.Join(os.TempDir(), "goproxy-cache"), "On-disk cache directory")
	flag.DurationVar(&cfg.MutableTTL, "mutable-ttl", cfg.MutableTTL, "Cache TTL for mutable endpoints (/@v/list, /@latest)")
	flag.Parse()

	handler, err := goproxy.NewHandler(cfg)
	if err != nil {
		log.Fatal(err)
	}

	srv := &http.Server{
		Addr:              *listenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Printf("goproxy-cache shutdown error: %v", err)
		}
	}()

	log.Printf("goproxy-cache listening on %s -> %s (cache: %s)", *listenAddr, cfg.UpstreamURL, cfg.CacheDir)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
