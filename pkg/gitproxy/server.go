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

package gitproxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/gob"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gke-labs/service-portals/pkg/cache"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
)

// CachedResponse represents the cached HTTP response structure.
type CachedResponse struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

func init() {
	gob.Register(CachedResponse{})
}

// Config defines the configuration for GitProxy server.
type Config struct {
	DefaultTargetURL  string
	DefaultAuthHeader string
	DefaultAuthToken  string
	Cache             cache.Cache
	CacheTTL          time.Duration
	RepoCacheDir      string
	RepoCacheManager  *RepoCacheManager
	Transport         http.RoundTripper
	SetupProxy        func(*Server)
}

// Server is the HTTP handler for proxying and caching Git requests.
type Server struct {
	Config    Config
	Transport http.RoundTripper
	RepoCache *RepoCacheManager
}

// NewServer creates a new GitProxy Server.
func NewServer(config Config) *Server {
	t := config.Transport
	if t == nil {
		t = http.DefaultTransport
	}

	if os.Getenv("OTEL_INSTRUMENTATION_ENABLED") == "true" {
		t = otelhttp.NewTransport(t)
	}

	if config.DefaultAuthHeader == "" {
		config.DefaultAuthHeader = "Authorization"
	}

	repoCache := config.RepoCacheManager
	if repoCache == nil {
		repoCacheDir := config.RepoCacheDir
		if repoCacheDir == "" {
			repoCacheDir = os.Getenv("CACHE_DIR")
		}
		repoCache = NewRepoCacheManager(repoCacheDir)
	}

	s := &Server{
		Config:    config,
		Transport: t,
		RepoCache: repoCache,
	}

	if config.SetupProxy != nil {
		config.SetupProxy(s)
	}

	return s
}

func (s *Server) computeCacheKey(r *http.Request, targetURL *url.URL, body []byte) string {
	proto := r.Header.Get("Git-Protocol")
	if r.Method == http.MethodGet {
		return fmt.Sprintf("git:get:%s:%s", targetURL.String(), proto)
	}
	bodyHash := sha256.Sum256(body)
	return fmt.Sprintf("git:post:%s:%s:%x", targetURL.String(), proto, bodyHash)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	targetURL, err := ResolveUpstreamURL(r, s.Config.DefaultTargetURL)
	if err != nil {
		log.Printf("Git proxy resolution error for %s: %v", r.URL.Path, err)
		http.Error(w, fmt.Sprintf("Git proxy error: %v", err), http.StatusBadRequest)
		return
	}

	var reqBody []byte
	if r.Body != nil {
		reqBody, err = io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to read request body: %v", err), http.StatusBadRequest)
			return
		}
		_ = r.Body.Close()
	}

	reqType := ClassifyGitRequest(r, reqBody)

	// Intelligent per-commit packfile caching for upload-pack fetch operations
	if reqType == RequestTypeUploadPackFetch && s.RepoCache != nil {
		fetchReq, parseErr := ParseFetchRequest(reqBody)
		repoStore := s.RepoCache.GetRepoStore(targetURL.Path)

		if parseErr == nil && len(fetchReq.Wants) > 0 && repoStore.HasAllCommits(fetchReq.Wants) {
			objects, acks, err := repoStore.CollectObjectsForCommits(fetchReq.Wants, fetchReq.Haves)
			if err == nil && len(objects) > 0 {
				packfile, err := BuildPackfile(objects)
				if err == nil {
					respBytes := FormatSidebandPackfile(packfile, fetchReq.IsV2, acks, len(fetchReq.Haves) > 0)
					w.Header().Set("Content-Type", "application/x-git-upload-pack-result")
					w.Header().Set("X-Git-Cache", "HIT")
					w.Header().Set("Cache-Control", "no-cache")
					w.Header().Del("Content-Length")
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write(respBytes)
					log.Printf("Git upload-pack cache HIT for %s (%d wants, %d haves -> %d objects)",
						targetURL.Path, len(fetchReq.Wants), len(fetchReq.Haves), len(objects))
					return
				}
				log.Printf("Failed to build packfile from cache for %s: %v", targetURL.Path, err)
			} else {
				log.Printf("Failed to collect objects from cache for %s: %v", targetURL.Path, err)
			}
		}
	}

	cacheable := reqType.IsCacheable() && s.Config.Cache != nil && s.Config.CacheTTL > 0

	if cacheable {
		key := s.computeCacheKey(r, targetURL, reqBody)
		if val, ok := s.Config.Cache.Get(key); ok {
			var cachedResp CachedResponse
			dec := gob.NewDecoder(bytes.NewReader(val))
			if err := dec.Decode(&cachedResp); err == nil {
				log.Printf("Cache HIT for %s %s", r.Method, targetURL.String())
				for k, vv := range cachedResp.Header {
					for _, v := range vv {
						w.Header().Add(k, v)
					}
				}
				w.Header().Set("X-Git-Cache", "HIT")
				w.WriteHeader(cachedResp.StatusCode)
				_, _ = w.Write(cachedResp.Body)
				return
			}
			log.Printf("Failed to decode cache entry for %s: %v", key, err)
		}
	}

	upstreamReqBody := reqBody
	// If this is an upload-pack fetch missing some commits, augment with known haves from repo store
	if reqType == RequestTypeUploadPackFetch && s.RepoCache != nil {
		fetchReq, parseErr := ParseFetchRequest(reqBody)
		if parseErr == nil && len(fetchReq.Wants) > 0 {
			repoStore := s.RepoCache.GetRepoStore(targetURL.Path)
			knownCommits := repoStore.GetKnownCommits()
			if len(knownCommits) > 0 {
				haveSet := make(map[string]bool)
				var combinedHaves []string
				for _, h := range fetchReq.Haves {
					if !haveSet[h] {
						haveSet[h] = true
						combinedHaves = append(combinedHaves, h)
					}
				}
				for _, h := range knownCommits {
					if !haveSet[h] {
						haveSet[h] = true
						combinedHaves = append(combinedHaves, h)
					}
				}
				upstreamReqBody = BuildUpstreamFetchRequest(fetchReq.Wants, combinedHaves, fetchReq.IsV2)
			}
		}
	}

	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL.String(), bytes.NewReader(upstreamReqBody))
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to create upstream request: %v", err), http.StatusInternalServerError)
		return
	}

	// Copy headers
	for k, vv := range r.Header {
		for _, v := range vv {
			outReq.Header.Add(k, v)
		}
	}
	removeHopByHopHeaders(outReq.Header)
	outReq.Header.Del("X-Forwarded-For")
	outReq.Host = targetURL.Host

	// Inject auth token if configured and not present in request
	if s.Config.DefaultAuthToken != "" && outReq.Header.Get("Authorization") == "" {
		if s.Config.DefaultAuthHeader == "Authorization" {
			outReq.Header.Set("Authorization", "Bearer "+s.Config.DefaultAuthToken)
		} else {
			outReq.Header.Set(s.Config.DefaultAuthHeader, s.Config.DefaultAuthToken)
		}
	}

	resp, err := s.Transport.RoundTrip(outReq)
	if err != nil {
		log.Printf("Git proxy upstream error (%s -> %s): %v", r.URL.Path, targetURL.String(), err)
		http.Error(w, fmt.Sprintf("Upstream proxy error: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	removeHopByHopHeaders(resp.Header)
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}

	if cacheable && resp.StatusCode == http.StatusOK {
		w.Header().Set("X-Git-Cache", "MISS")

		respBodyBytes, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			log.Printf("Failed to read upstream response for %s: %v", targetURL.String(), readErr)
			http.Error(w, "Failed to read upstream response", http.StatusBadGateway)
			return
		}

		// If upload-pack fetch, ingest packfile into repo store
		if reqType == RequestTypeUploadPackFetch && s.RepoCache != nil {
			repoStore := s.RepoCache.GetRepoStore(targetURL.Path)
			packData, packErr := ExtractPackfileFromResponse(respBodyBytes)
			if packErr == nil {
				newCommits, ingestErr := repoStore.IngestPackfile(packData)
				if ingestErr == nil {
					log.Printf("Ingested packfile for %s: %d new commits cached", targetURL.Path, len(newCommits))
				} else {
					log.Printf("Failed to ingest packfile for %s: %v", targetURL.Path, ingestErr)
				}
			}

			// If upstream request was modified with extra haves, generate client response from repo store
			if !bytes.Equal(upstreamReqBody, reqBody) {
				fetchReq, _ := ParseFetchRequest(reqBody)
				if fetchReq != nil && len(fetchReq.Wants) > 0 && repoStore.HasAllCommits(fetchReq.Wants) {
					objects, acks, err := repoStore.CollectObjectsForCommits(fetchReq.Wants, fetchReq.Haves)
					if err == nil && len(objects) > 0 {
						packfile, err := BuildPackfile(objects)
						if err == nil {
							clientRespBytes := FormatSidebandPackfile(packfile, fetchReq.IsV2, acks, len(fetchReq.Haves) > 0)
							w.Header().Del("Content-Length")
							w.WriteHeader(http.StatusOK)
							_, _ = w.Write(clientRespBytes)
							return
						}
					}
				}
			}
		}

		// Default cache storage and write response
		cachedResp := CachedResponse{
			StatusCode: resp.StatusCode,
			Header:     resp.Header.Clone(),
			Body:       respBodyBytes,
		}
		var encBuf bytes.Buffer
		if err := gob.NewEncoder(&encBuf).Encode(cachedResp); err == nil {
			key := s.computeCacheKey(r, targetURL, reqBody)
			s.Config.Cache.Set(key, encBuf.Bytes(), s.Config.CacheTTL)
			log.Printf("Cache MISS (stored %d bytes) for %s %s", len(respBodyBytes), r.Method, targetURL.String())
		}

		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(respBodyBytes)))
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(respBodyBytes)
		return
	}

	// Non-cacheable or non-200 response
	w.Header().Set("X-Git-Cache", "BYPASS")
	w.WriteHeader(resp.StatusCode)

	flusher, isFlusher := w.(http.Flusher)
	buf := make([]byte, 32*1024)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			if _, writeErr := w.Write(buf[:n]); writeErr != nil {
				break
			}
			if isFlusher {
				flusher.Flush()
			}
		}
		if err != nil {
			break
		}
	}
	log.Printf("Proxied %s %s -> %s [%s]", r.Method, r.URL.Path, resp.Status, targetURL.String())
}

func removeHopByHopHeaders(h http.Header) {
	if c := h.Get("Connection"); c != "" {
		for _, f := range splitAndTrim(c) {
			h.Del(f)
		}
	}
	for _, f := range hopByHopHeaders {
		h.Del(f)
	}
}

var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailers",
	"Transfer-Encoding",
	"Upgrade",
}

func splitAndTrim(s string) []string {
	parts := strings.Split(s, ",")
	var res []string
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			res = append(res, trimmed)
		}
	}
	return res
}

// Run starts the GitProxy server and blocks until the context is canceled.
func Run(ctx context.Context, config Config, port string) error {
	if port == "" {
		port = os.Getenv("PORT")
	}
	if port == "" {
		port = "8080"
	}

	if config.DefaultTargetURL == "" {
		config.DefaultTargetURL = os.Getenv("TARGET_URL")
	}
	if config.DefaultAuthToken == "" {
		config.DefaultAuthToken = os.Getenv("UPSTREAM_AUTH_TOKEN")
	}
	if config.DefaultAuthHeader == "" {
		config.DefaultAuthHeader = os.Getenv("UPSTREAM_AUTH_HEADER")
		if config.DefaultAuthHeader == "" {
			config.DefaultAuthHeader = "Authorization"
		}
	}

	if config.Cache == nil {
		cacheTTL := config.CacheTTL
		if cacheTTLEnv := os.Getenv("CACHE_TTL"); cacheTTLEnv != "" {
			if d, err := time.ParseDuration(cacheTTLEnv); err == nil {
				cacheTTL = d
			} else {
				log.Printf("Warning: invalid CACHE_TTL %q: %v", cacheTTLEnv, err)
			}
		}
		if cacheTTL <= 0 {
			cacheTTL = 7 * 24 * time.Hour // Default 7 days
		}
		config.CacheTTL = cacheTTL

		cleanupInterval := 10 * time.Minute
		if cleanupEnv := os.Getenv("CACHE_CLEANUP_INTERVAL"); cleanupEnv != "" {
			if d, err := time.ParseDuration(cleanupEnv); err == nil {
				cleanupInterval = d
			} else {
				log.Printf("Warning: invalid CACHE_CLEANUP_INTERVAL %q: %v", cleanupEnv, err)
			}
		}

		cacheDir := os.Getenv("CACHE_DIR")
		if cacheDir != "" {
			diskCache, err := cache.NewDiskCache(cacheDir, cacheTTL, cleanupInterval)
			if err != nil {
				return fmt.Errorf("failed to create disk cache in %s: %w", cacheDir, err)
			}
			config.Cache = diskCache
			log.Printf("Enabled Git disk cache in %s with TTL %v (cleanup interval %v)", cacheDir, cacheTTL, cleanupInterval)
		} else {
			config.Cache = cache.NewInMemoryCache(cleanupInterval)
			log.Printf("Enabled Git in-memory cache with TTL %v (cleanup interval %v)", cacheTTL, cleanupInterval)
		}
	}

	handler := http.Handler(NewServer(config))

	if os.Getenv("OTEL_INSTRUMENTATION_ENABLED") == "true" {
		otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
		handler = otelhttp.NewHandler(handler, "gitproxy-server")
		log.Println("OpenTelemetry server instrumentation enabled")
	}

	srv := &http.Server{
		Addr:    ":" + port,
		Handler: handler,
	}

	errChan := make(chan error, 1)
	go func() {
		log.Printf("Starting Git caching proxy server on :%s", port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errChan <- fmt.Errorf("HTTP server failed: %w", err)
		}
	}()

	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
		log.Println("Shutting down Git proxy server...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}
