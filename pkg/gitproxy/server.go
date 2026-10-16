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
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/gob"
	"encoding/json"
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

// CachedHeader represents the metadata stored at the beginning of a streaming cache entry.
type CachedHeader struct {
	StatusCode int         `json:"status_code"`
	Header     http.Header `json:"header"`
}

type cachedEntry struct {
	StatusCode int
	Header     http.Header
	Body       io.ReadCloser
}

type bufferedReadCloser struct {
	io.Reader
	io.Closer
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
		if closeErr := r.Body.Close(); closeErr != nil {
			log.Printf("Error closing request body: %v", closeErr)
		}
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
					if _, err := w.Write(respBytes); err != nil {
						log.Printf("Failed to write upload-pack response for %s: %v", targetURL.Path, err)
					}
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
		if entry, ok := s.openCachedEntry(key); ok {
			defer func() {
				_ = entry.Body.Close()
			}()
			log.Printf("Cache HIT for %s %s", r.Method, targetURL.String())
			for k, vv := range entry.Header {
				for _, v := range vv {
					w.Header().Add(k, v)
				}
			}
			w.Header().Set("X-Git-Cache", "HIT")
			w.Header().Del("Content-Length")
			w.WriteHeader(entry.StatusCode)
			if _, err := io.Copy(w, entry.Body); err != nil {
				log.Printf("Failed to write cached response for %s: %v", key, err)
			}
			return
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
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Printf("Error closing upstream response body: %v", closeErr)
		}
	}()

	removeHopByHopHeaders(resp.Header)
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}

	if cacheable && resp.StatusCode == http.StatusOK {
		w.Header().Set("X-Git-Cache", "MISS")
		w.Header().Del("Content-Length")

		// If upstream request was modified with extra haves, response is for store, not client:
		// keep buffering and ingesting as today, then serve from store.
		if reqType == RequestTypeUploadPackFetch && s.RepoCache != nil && !bytes.Equal(upstreamReqBody, reqBody) {
			respBodyBytes, readErr := io.ReadAll(resp.Body)
			if readErr != nil {
				log.Printf("Failed to read upstream response for %s: %v", targetURL.String(), readErr)
				http.Error(w, "Failed to read upstream response", http.StatusBadGateway)
				return
			}

			repoStore := s.RepoCache.GetRepoStore(targetURL.Path)
			packData, packErr := ExtractPackfileFromResponse(respBodyBytes)
			if packErr != nil {
				log.Printf("Failed to extract packfile from response for %s: %v", targetURL.Path, packErr)
			} else {
				newCommits, ingestErr := repoStore.IngestPackfile(packData)
				if ingestErr == nil {
					log.Printf("Ingested packfile for %s: %d new commits cached", targetURL.Path, len(newCommits))
				} else {
					log.Printf("Failed to ingest packfile for %s: %v", targetURL.Path, ingestErr)
				}
			}

			clientRespBytes, err := buildFetchFromStore(repoStore, reqBody)
			if err != nil {
				log.Printf("Failed to serve cache-assisted fetch for %s: %v", targetURL.Path, err)
				http.Error(w, "cache-assisted fetch failed", http.StatusBadGateway)
				return
			}
			w.Header().Del("Content-Length")
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write(clientRespBytes); err != nil {
				log.Printf("Failed to write cache-assisted fetch response for %s: %v", targetURL.Path, err)
			}
			return
		}

		// Common case: stream upstream response to client, teeing into cache
		key := s.computeCacheKey(r, targetURL, reqBody)
		cw, cwErr := s.createCacheWriter(key, resp.StatusCode, resp.Header)
		if cwErr != nil {
			log.Printf("Failed to create cache writer for %s: %v", key, cwErr)
		} else {
			defer func() {
				_ = cw.Abort()
			}()
		}

		w.WriteHeader(resp.StatusCode)

		var clientStream io.Reader = resp.Body
		if cw != nil {
			clientStream = io.TeeReader(resp.Body, cw)
		}

		flusher, isFlusher := w.(http.Flusher)
		buf := make([]byte, 32*1024)
		var streamErr error
		var totalBytes int64

		for {
			n, rErr := clientStream.Read(buf)
			if n > 0 {
				totalBytes += int64(n)
				if _, wErr := w.Write(buf[:n]); wErr != nil {
					streamErr = wErr
					break
				}
				if isFlusher {
					flusher.Flush()
				}
			}
			if rErr != nil {
				if rErr != io.EOF {
					streamErr = rErr
				}
				break
			}
		}

		if streamErr != nil {
			log.Printf("Failed to stream upstream response for %s: %v", targetURL.String(), streamErr)
			if cw != nil {
				_ = cw.Abort()
			}
			return
		}

		// If upload-pack fetch, ingest packfile from the cached copy
		if reqType == RequestTypeUploadPackFetch && s.RepoCache != nil {
			repoStore := s.RepoCache.GetRepoStore(targetURL.Path)
			if cw != nil {
				bodyReader, rErr := cw.BodyReader()
				if rErr != nil {
					log.Printf("Failed to get body reader for %s: %v", targetURL.Path, rErr)
					_ = cw.Abort()
					return
				}

				packData, packErr := ExtractPackfileFromReader(bodyReader)
				_ = bodyReader.Close()
				if packErr != nil {
					log.Printf("Failed to extract packfile from response for %s: %v", targetURL.Path, packErr)
					_ = cw.Abort()
					return
				}

				newCommits, ingestErr := repoStore.IngestPackfile(packData)
				if ingestErr != nil {
					log.Printf("Failed to ingest packfile for %s: %v", targetURL.Path, ingestErr)
					_ = cw.Abort()
					return
				}
				log.Printf("Ingested packfile for %s: %d new commits cached", targetURL.Path, len(newCommits))
			}
		}

		if cw != nil {
			if commitErr := cw.Commit(); commitErr != nil {
				log.Printf("Failed to commit cache entry for %s: %v", key, commitErr)
			} else {
				log.Printf("Cache MISS (stored %d bytes) for %s %s", totalBytes, r.Method, targetURL.String())
			}
		}
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

func (s *Server) openCachedEntry(key string) (*cachedEntry, bool) {
	if s.Config.Cache == nil {
		return nil, false
	}

	// Try Open first (streaming from disk or memory)
	if opener, ok := s.Config.Cache.(interface {
		Open(key string) (io.ReadSeekCloser, error)
	}); ok {
		f, err := opener.Open(key)
		if err == nil {
			br := bufio.NewReader(f)
			metaLine, err := br.ReadBytes('\n')
			if err == nil {
				var meta CachedHeader
				if jsonErr := json.Unmarshal(bytes.TrimSpace(metaLine), &meta); jsonErr == nil && meta.StatusCode > 0 {
					return &cachedEntry{
						StatusCode: meta.StatusCode,
						Header:     meta.Header,
						Body:       &bufferedReadCloser{Reader: br, Closer: f},
					}, true
				}
			}
			// If not JSON metadata format, rewind and try legacy gob
			if _, seekErr := f.Seek(0, io.SeekStart); seekErr == nil {
				var cachedResp CachedResponse
				dec := gob.NewDecoder(f)
				if dec.Decode(&cachedResp) == nil {
					_ = f.Close()
					return &cachedEntry{
						StatusCode: cachedResp.StatusCode,
						Header:     cachedResp.Header,
						Body:       io.NopCloser(bytes.NewReader(cachedResp.Body)),
					}, true
				}
			}
			_ = f.Close()
		}
	}

	// Fallback to Get
	val, ok := s.Config.Cache.Get(key)
	if !ok {
		return nil, false
	}

	// Check if JSON line 1
	idx := bytes.IndexByte(val, '\n')
	if idx != -1 {
		var meta CachedHeader
		if jsonErr := json.Unmarshal(bytes.TrimSpace(val[:idx]), &meta); jsonErr == nil && meta.StatusCode > 0 {
			return &cachedEntry{
				StatusCode: meta.StatusCode,
				Header:     meta.Header,
				Body:       io.NopCloser(bytes.NewReader(val[idx+1:])),
			}, true
		}
	}

	// Fallback to legacy gob
	var cachedResp CachedResponse
	dec := gob.NewDecoder(bytes.NewReader(val))
	if dec.Decode(&cachedResp) == nil {
		return &cachedEntry{
			StatusCode: cachedResp.StatusCode,
			Header:     cachedResp.Header,
			Body:       io.NopCloser(bytes.NewReader(cachedResp.Body)),
		}, true
	}

	return nil, false
}

type serverCacheWriter struct {
	writer      cache.CacheWriter
	headerBytes int
}

func (s *Server) createCacheWriter(key string, statusCode int, header http.Header) (*serverCacheWriter, error) {
	if s.Config.Cache == nil {
		return nil, fmt.Errorf("cache is nil")
	}

	var cw cache.CacheWriter
	var err error
	if sc, ok := s.Config.Cache.(cache.StreamableCache); ok {
		cw, err = sc.NewWriter(key, s.Config.CacheTTL)
	} else {
		cw = &genericCacheWriter{
			cache: s.Config.Cache,
			key:   key,
			ttl:   s.Config.CacheTTL,
		}
	}
	if err != nil {
		return nil, err
	}

	meta := CachedHeader{
		StatusCode: statusCode,
		Header:     header.Clone(),
	}
	metaBytes, err := json.Marshal(meta)
	if err != nil {
		_ = cw.Abort()
		return nil, err
	}
	metaLine := append(metaBytes, '\n')
	if _, err := cw.Write(metaLine); err != nil {
		_ = cw.Abort()
		return nil, err
	}

	return &serverCacheWriter{
		writer:      cw,
		headerBytes: len(metaLine),
	}, nil
}

func (w *serverCacheWriter) Write(p []byte) (int, error) {
	return w.writer.Write(p)
}

func (w *serverCacheWriter) Commit() error {
	return w.writer.Commit()
}

func (w *serverCacheWriter) Abort() error {
	return w.writer.Abort()
}

func (w *serverCacheWriter) BodyReader() (io.ReadCloser, error) {
	readerHolder, ok := w.writer.(interface {
		Reader() (io.ReadCloser, error)
	})
	if !ok {
		return nil, fmt.Errorf("cache writer does not support reading data before commit")
	}

	rc, err := readerHolder.Reader()
	if err != nil {
		return nil, err
	}

	br := bufio.NewReader(rc)
	if _, err := br.ReadBytes('\n'); err != nil {
		_ = rc.Close()
		return nil, err
	}

	return &bufferedReadCloser{Reader: br, Closer: rc}, nil
}

type genericCacheWriter struct {
	cache   cache.Cache
	key     string
	ttl     time.Duration
	buf     bytes.Buffer
	aborted bool
	closed  bool
}

func (w *genericCacheWriter) Write(p []byte) (int, error) {
	if w.aborted || w.closed {
		return 0, fmt.Errorf("writer is closed")
	}
	return w.buf.Write(p)
}

func (w *genericCacheWriter) Reader() (io.ReadCloser, error) {
	if w.aborted {
		return nil, fmt.Errorf("writer was aborted")
	}
	return io.NopCloser(bytes.NewReader(w.buf.Bytes())), nil
}

func (w *genericCacheWriter) Abort() error {
	w.aborted = true
	w.buf.Reset()
	return nil
}

func (w *genericCacheWriter) Commit() error {
	if w.aborted {
		return fmt.Errorf("cannot commit aborted writer")
	}
	if w.closed {
		return nil
	}
	w.closed = true
	w.cache.Set(w.key, w.buf.Bytes(), w.ttl)
	return nil
}

func buildFetchFromStore(repoStore *RepoStore, reqBody []byte) ([]byte, error) {
	if repoStore == nil {
		return nil, fmt.Errorf("repo store is nil")
	}
	fetchReq, err := ParseFetchRequest(reqBody)
	if err != nil {
		return nil, fmt.Errorf("parsing fetch request: %w", err)
	}
	if fetchReq == nil || len(fetchReq.Wants) == 0 {
		return nil, fmt.Errorf("no wants in fetch request")
	}
	if !repoStore.HasAllCommits(fetchReq.Wants) {
		return nil, fmt.Errorf("repo store missing wanted commits")
	}
	objects, acks, err := repoStore.CollectObjectsForCommits(fetchReq.Wants, fetchReq.Haves)
	if err != nil {
		return nil, fmt.Errorf("collecting objects from cache: %w", err)
	}
	if len(objects) == 0 {
		return nil, fmt.Errorf("no objects collected for commits")
	}
	packfile, err := BuildPackfile(objects)
	if err != nil {
		return nil, fmt.Errorf("building packfile from cache: %w", err)
	}
	clientRespBytes := FormatSidebandPackfile(packfile, fetchReq.IsV2, acks, len(fetchReq.Haves) > 0)
	return clientRespBytes, nil
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
