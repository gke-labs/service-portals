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

package goproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gke-labs/service-portals/pkg/diskcache"
)

const (
	maxAttempts       = 3
	maxErrorBodyBytes = 64 << 10
)

// Config configures the Go module proxy pull-through cache handler.
type Config struct {
	UpstreamURL   string
	CacheDir      string
	MutableTTL    time.Duration
	MaxCacheBytes int64
}

// InitDefaults sets default configuration values.
func (c *Config) InitDefaults() {
	var cacheCfg diskcache.Config
	cacheCfg.InitDefaults()
	c.UpstreamURL = "https://proxy.golang.org"
	c.MutableTTL = 5 * time.Minute
	c.MaxCacheBytes = cacheCfg.MaxBytes
}

type flight struct {
	done        chan struct{}
	status      int
	contentType string
	body        []byte
	err         error
}

// Handler is an HTTP pull-through cache for a Go module proxy.
type Handler struct {
	upstream     string
	cache        *diskcache.Cache
	mutableTTL   time.Duration
	client       *http.Client
	now          func() time.Time
	retryDelay   time.Duration
	fetchTimeout time.Duration

	mu       sync.Mutex
	inflight map[string]*flight
}

// NewHandler creates a new Go module proxy cache handler.
// Callers should call cfg.InitDefaults() before overriding fields.
func NewHandler(cfg Config) (*Handler, error) {
	u, err := url.Parse(cfg.UpstreamURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("invalid upstream URL %q", cfg.UpstreamURL)
	}
	cache, err := diskcache.New(diskcache.Config{
		Dir:      cfg.CacheDir,
		MaxBytes: cfg.MaxCacheBytes,
	})
	if err != nil {
		return nil, err
	}
	return &Handler{
		upstream:     strings.TrimRight(u.String(), "/"),
		cache:        cache,
		mutableTTL:   cfg.MutableTTL,
		client:       &http.Client{},
		now:          time.Now,
		retryDelay:   200 * time.Millisecond,
		fetchTimeout: 5 * time.Minute,
		inflight:     make(map[string]*flight),
	}, nil
}

func classifyPath(p string) (cacheable, mutable bool, contentType string) {
	if strings.HasSuffix(p, "/@latest") && len(p) > len("/@latest") {
		return true, true, "application/json"
	}
	if strings.HasSuffix(p, "/@v/list") && len(p) > len("/@v/list") {
		return true, true, "text/plain; charset=utf-8"
	}
	idx := strings.LastIndex(p, "/@v/")
	if idx <= 0 || strings.Contains(p[idx+4:], "/") {
		return false, false, ""
	}
	file := p[idx+4:]
	switch ext := filepath.Ext(file); ext {
	case ".zip":
		return len(file) > len(ext), false, "application/zip"
	case ".mod":
		return len(file) > len(ext), false, "text/plain; charset=utf-8"
	case ".info":
		return len(file) > len(ext), false, "application/json"
	}
	return false, false, ""
}

func (h *Handler) isFresh(info os.FileInfo, mutable bool) bool {
	return !mutable || (h.mutableTTL > 0 && h.now().Sub(info.ModTime()) < h.mutableTTL)
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.EscapedPath()
	idempotent := r.Method == http.MethodGet || r.Method == http.MethodHead
	cacheable, mutable, contentType := false, false, ""
	if idempotent && r.URL.RawQuery == "" {
		cacheable, mutable, contentType = classifyPath(path)
	}
	if !cacheable {
		h.proxyDirect(w, r, idempotent)
		return
	}
	if h.serveCached(w, r, path, mutable, contentType, false) {
		return
	}
	f, err := h.doFlight(r.Context(), path, mutable)
	if err != nil {
		if errors.Is(err, diskcache.ErrTooLarge) {
			h.proxyDirect(w, r, idempotent)
			return
		}
		if !errors.Is(err, context.Canceled) {
			http.Error(w, "upstream fetch failed", http.StatusBadGateway)
		}
		return
	}
	if f.status == http.StatusOK {
		if !h.serveCached(w, r, path, mutable, contentType, true) {
			h.proxyDirect(w, r, idempotent)
		}
		return
	}
	if f.contentType != "" {
		w.Header().Set("Content-Type", f.contentType)
	}
	w.WriteHeader(f.status)
	if r.Method != http.MethodHead {
		_, err := w.Write(f.body)
		logErr("writing response", err)
	}
}

func (h *Handler) serveCached(w http.ResponseWriter, r *http.Request, key string, mutable bool, contentType string, ignoreTTL bool) bool {
	f, info, err := h.cache.Open(key)
	if err != nil {
		return false
	}
	defer func() { logErr("closing cache file", f.Close()) }()
	if !ignoreTTL && !h.isFresh(info, mutable) {
		return false
	}
	w.Header().Set("Content-Type", contentType)
	http.ServeContent(w, r, "", info.ModTime(), f)
	return true
}

func (h *Handler) doFlight(ctx context.Context, path string, mutable bool) (*flight, error) {
	h.mu.Lock()
	f, ok := h.inflight[path]
	if !ok {
		f = &flight{done: make(chan struct{})}
		h.inflight[path] = f
		go func() {
			// Detach from leader cancellation so one client disconnect does not abort shared fetches.
			fetchCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), h.fetchTimeout)
			defer cancel()
			f.status, f.contentType, f.body, f.err = h.fetchAndCache(fetchCtx, path, mutable)
			h.mu.Lock()
			delete(h.inflight, path)
			h.mu.Unlock()
			close(f.done)
		}()
	}
	h.mu.Unlock()
	select {
	case <-f.done:
		return f, f.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (h *Handler) send(ctx context.Context, method, target string, body io.Reader, attempt int) (*http.Response, error) {
	if attempt > 0 && h.retryDelay > 0 {
		t := time.NewTimer(h.retryDelay * time.Duration(attempt))
		select {
		case <-t.C:
		case <-ctx.Done():
			t.Stop()
			return nil, ctx.Err()
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return nil, err
	}
	return h.client.Do(req)
}

func (h *Handler) fetchAndCache(ctx context.Context, path string, mutable bool) (int, string, []byte, error) {
	if info, err := h.cache.Stat(path); err == nil && h.isFresh(info, mutable) {
		return http.StatusOK, "", nil, nil
	}
	var lastErr error
	for attempt := range maxAttempts {
		resp, err := h.send(ctx, http.MethodGet, h.upstream+path, nil, attempt)
		if err != nil {
			lastErr = err
			if ctx.Err() != nil {
				return 0, "", nil, err
			}
			continue
		}
		if resp.StatusCode >= http.StatusInternalServerError && attempt < maxAttempts-1 {
			logErr("closing upstream body", resp.Body.Close())
			lastErr = fmt.Errorf("upstream status %d", resp.StatusCode)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			body, err := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
			logErr("closing upstream body", resp.Body.Close())
			if err != nil {
				return 0, "", nil, err
			}
			return resp.StatusCode, resp.Header.Get("Content-Type"), body, nil
		}
		err = h.cache.Write(path, resp.Body, resp.ContentLength, h.now())
		logErr("closing upstream body", resp.Body.Close())
		if err == nil {
			return http.StatusOK, "", nil, nil
		}
		if errors.Is(err, diskcache.ErrTooLarge) {
			return 0, "", nil, diskcache.ErrTooLarge
		}
		lastErr = err
		if ctx.Err() != nil {
			return 0, "", nil, err
		}
	}
	return 0, "", nil, lastErr
}

func (h *Handler) proxyDirect(w http.ResponseWriter, r *http.Request, idempotent bool) {
	attempts, body := 1, io.Reader(r.Body)
	if idempotent {
		attempts, body = maxAttempts, nil
	}
	var resp *http.Response
	var err error
	for attempt := range attempts {
		resp, err = h.send(r.Context(), r.Method, h.upstream+r.URL.RequestURI(), body, attempt)
		if err != nil {
			if r.Context().Err() != nil {
				return
			}
			continue
		}
		if resp.StatusCode >= http.StatusInternalServerError && attempt < attempts-1 {
			logErr("closing upstream body", resp.Body.Close())
			continue
		}
		break
	}
	if err != nil {
		http.Error(w, "upstream request failed", http.StatusBadGateway)
		return
	}
	defer func() { logErr("closing upstream body", resp.Body.Close()) }()
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.WriteHeader(resp.StatusCode)
	if r.Method != http.MethodHead {
		_, err := io.Copy(w, resp.Body)
		logErr("streaming response", err)
	}
}

func logErr(desc string, err error) {
	if err != nil && !os.IsNotExist(err) {
		log.Printf("goproxy: %s: %v", desc, err)
	}
}
