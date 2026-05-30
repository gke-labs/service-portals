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
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gke-labs/service-portals/pkg/cache"
	"github.com/gke-labs/service-portals/pkg/proxy"
	"gopkg.in/yaml.v3"
)

// PortalRule represents the Kubernetes-inspired YAML object.
type PortalRule struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
	Spec RuleSpec `yaml:"spec"`
}

// RuleSpec defines the specification for a dynamic proxy rule.
type RuleSpec struct {
	Host       string `yaml:"host"`
	TargetURL  string `yaml:"targetUrl"`
	AuthToken  string `yaml:"authToken"`
	AuthHeader string `yaml:"authHeader"`
}

// RuleRouter routes incoming HTTP/HTTPS requests to the appropriate proxy based on host rules.
type RuleRouter struct {
	mu         sync.RWMutex
	routes     map[string]*proxy.HTTPProxy
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
		routes:     make(map[string]*proxy.HTTPProxy),
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

	newRoutes := make(map[string]*proxy.HTTPProxy)

	err := filepath.WalkDir(rr.rulesDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
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
			return fmt.Errorf("failed to read file %s: %w", path, err)
		}

		dec := yaml.NewDecoder(strings.NewReader(string(data)))
		for {
			var rule PortalRule
			if err := dec.Decode(&rule); err != nil {
				if err.Error() == "EOF" {
					break
				}
				return fmt.Errorf("failed to parse YAML in %s: %w", path, err)
			}

			if rule.Kind != "PortalRule" {
				continue
			}

			if rule.Spec.Host == "" {
				log.Printf("Warning: Rule %q in %s is missing spec.host, skipping", rule.Metadata.Name, path)
				continue
			}

			if rule.Spec.TargetURL == "" {
				log.Printf("Warning: Rule %q in %s is missing spec.targetUrl, skipping", rule.Metadata.Name, path)
				continue
			}

			targetURL, err := url.Parse(rule.Spec.TargetURL)
			if err != nil {
				return fmt.Errorf("invalid targetUrl %q in rule %q: %w", rule.Spec.TargetURL, rule.Metadata.Name, err)
			}

			authHeader := rule.Spec.AuthHeader
			if authHeader == "" {
				authHeader = "Authorization"
			}

			p, err := proxy.NewHTTPProxy(targetURL, rule.Spec.AuthToken, authHeader, rr.caCertPath, rr.caKeyPath)
			if err != nil {
				return fmt.Errorf("failed to create proxy for rule %q: %w", rule.Metadata.Name, err)
			}

			if rr.cacheTTL > 0 && rr.cache != nil {
				p.Transport = proxy.NewCachingTransport(rr.cache, p.Transport, rr.cacheTTL)
			}

			host := strings.ToLower(rule.Spec.Host)
			newRoutes[host] = p
			log.Printf("Loaded rule %s: host %s -> %s", rule.Metadata.Name, host, rule.Spec.TargetURL)
		}

		return nil
	})

	if err != nil {
		return err
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

	// Strip port if present
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		host = host[:idx]
	}
	host = strings.ToLower(host)

	rr.mu.RLock()
	p, ok := rr.routes[host]
	rr.mu.RUnlock()

	if ok {
		p.ServeHTTP(w, r)
		return
	}

	if rr.fallback != nil {
		rr.fallback.ServeHTTP(w, r)
		return
	}

	http.Error(w, "Not Found", http.StatusNotFound)
}
