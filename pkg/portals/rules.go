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
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gke-labs/service-portals/pkg/cache"
	"github.com/gke-labs/service-portals/pkg/proxy"
	"sigs.k8s.io/yaml"
)

// PortalRule represents the Kubernetes-inspired YAML object.
type PortalRule struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name string `json:"name"`
	} `json:"metadata"`
	Spec RuleSpec `json:"spec"`
}

// RuleSpec defines the specification for a dynamic proxy rule.
type RuleSpec struct {
	Host       string `json:"host"`
	RewriteURL string `json:"rewriteUrl"`
	AuthToken  string `json:"authToken"`
	AuthHeader string `json:"authHeader"`
	CacheTTL   string `json:"cacheTTL"`
}

// Rule represents a loaded routing rule with its proxy and name.
type Rule struct {
	Proxy *proxy.HTTPProxy
	Name  string
}

// RuleRouter routes incoming HTTP/HTTPS requests to the appropriate proxy based on host rules.
type RuleRouter struct {
	mu         sync.RWMutex
	routes     map[string]*Rule
	fallback   http.Handler
	rulesDir   string
	caCertPath string
	caKeyPath  string
	cacheTTL   time.Duration
	cache      *cache.InMemoryCache
}

// NewRuleRouter creates a new RuleRouter instance.
func NewRuleRouter(rulesDir string, fallback http.Handler, caCertPath, caKeyPath string, cacheTTL time.Duration, c *cache.InMemoryCache) *RuleRouter {
	return &RuleRouter{
		routes:     make(map[string]*Rule),
		fallback:   fallback,
		rulesDir:   rulesDir,
		caCertPath: caCertPath,
		caKeyPath:  caKeyPath,
		cacheTTL:   cacheTTL,
		cache:      c,
	}
}

// loadRules reads YAML rules from the configured rulesDir and rebuilds the routing table.
func (rr *RuleRouter) loadRules() error {
	if rr.rulesDir == "" {
		return nil
	}

	newRoutes := make(map[string]*Rule)
	var errs []error

	err := filepath.WalkDir(rr.rulesDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to read file %s: %w", path, err))
			return nil
		}

		parts := strings.Split(string(data), "---")
		for _, part := range parts {
			trimmed := strings.TrimSpace(part)
			if trimmed == "" {
				continue
			}

			var rule PortalRule
			if err := yaml.Unmarshal([]byte(trimmed), &rule); err != nil {
				errs = append(errs, fmt.Errorf("failed to parse YAML in %s: %w", path, err))
				continue
			}

			if rule.Kind != "PortalRule" {
				continue
			}

			if rule.Spec.Host == "" {
				log.Printf("Warning: Rule %q in %s is missing spec.host, skipping", rule.Metadata.Name, path)
				continue
			}

			// RewriteURL defaults to host
			rewriteURLStr := rule.Spec.RewriteURL
			if rewriteURLStr == "" {
				rewriteURLStr = rule.Spec.Host
			}

			// Prepend https:// if no scheme is present
			if !strings.Contains(rewriteURLStr, "://") {
				rewriteURLStr = "https://" + rewriteURLStr
			}

			rewriteURL, err := url.Parse(rewriteURLStr)
			if err != nil {
				errs = append(errs, fmt.Errorf("invalid rewriteUrl %q in rule %q: %w", rewriteURLStr, rule.Metadata.Name, err))
				continue
			}

			authHeader := rule.Spec.AuthHeader
			if authHeader == "" {
				authHeader = "Authorization"
			}

			p, err := proxy.NewHTTPProxy(rewriteURL, rule.Spec.AuthToken, authHeader, rr.caCertPath, rr.caKeyPath)
			if err != nil {
				errs = append(errs, fmt.Errorf("failed to create proxy for rule %q: %w", rule.Metadata.Name, err))
				continue
			}

			// Rule-specific cacheTTL takes precedence. If specified, setup caching.
			var cacheTTL time.Duration
			if rule.Spec.CacheTTL != "" {
				d, err := time.ParseDuration(rule.Spec.CacheTTL)
				if err != nil {
					errs = append(errs, fmt.Errorf("invalid cacheTTL %q in rule %q: %w", rule.Spec.CacheTTL, rule.Metadata.Name, err))
					continue
				}
				cacheTTL = d
			}

			if cacheTTL > 0 {
				if rr.cache == nil {
					// Instantiate on-demand cache with a 1-minute cleanup interval if not globally defined
					rr.cache = cache.NewInMemoryCache(1 * time.Minute)
				}
				p.Transport = proxy.NewCachingTransport(rr.cache, p.Transport, cacheTTL)
			}

			host := strings.ToLower(rule.Spec.Host)
			newRoutes[host] = &Rule{
				Proxy: p,
				Name:  rule.Metadata.Name,
			}
			log.Printf("Loaded rule %s: host %s -> %s", rule.Metadata.Name, host, rewriteURLStr)
		}

		return nil
	})

	if err != nil {
		return err
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	rr.mu.Lock()
	rr.routes = newRoutes
	rr.mu.Unlock()

	return nil
}

// ServeHTTP implements http.Handler to route the request based on Host.
func (rr *RuleRouter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}

	// Strip port if present, safe for IPv6
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(host)

	rr.mu.RLock()
	rule, ok := rr.routes[host]
	rr.mu.RUnlock()

	if ok {
		log.Printf("Request: %s %s | Matched rule: %s | Action: proxy", r.Method, host, rule.Name)
		rule.Proxy.ServeHTTP(w, r)
		return
	}

	if rr.fallback != nil {
		log.Printf("Request: %s %s | Matched rule: <none> | Action: fallback", r.Method, host)
		rr.fallback.ServeHTTP(w, r)
		return
	}

	log.Printf("Request: %s %s | Matched rule: <none> | Action: not found", r.Method, host)
	http.Error(w, "Not Found", http.StatusNotFound)
}
