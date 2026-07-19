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
	"crypto/tls"
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
	SecretRef  string `json:"secretRef"`
	AuthHeader string `json:"authHeader"`
	CacheTTL   string `json:"cacheTTL"`
}

// Rule represents a loaded routing rule with its proxy and name.
type Rule struct {
	Proxy *proxy.HTTPProxy
	Name  string
}

// SecurityPolicy defines the security posture of the sidecar container.
type SecurityPolicy struct {
	BlockExec     bool     `json:"blockExec"`
	AllowedImages []string `json:"allowedImages"`
}

// RuleRouter routes incoming HTTP/HTTPS requests to the appropriate proxy based on host rules.
type RuleRouter struct {
	mu                 sync.RWMutex
	routes             map[string]*Rule  // Combined active routes
	fileRules          map[string]*Rule  // Rules loaded from files in rulesDir
	dynamicRules       map[string]*Rule  // Dynamic rules set via the gRPC API
	dynamicRulesSource []PortalRule      // Source structures of dynamic rules
	secrets            map[string]string // Dynamic secrets map
	securityPolicy     *SecurityPolicy   // Current security policy
	fallback           http.Handler
	rulesDir           string
	caCertPath         string
	caKeyPath          string
	cacheTTL           time.Duration
	cache              *cache.InMemoryCache
}

// NewRuleRouter creates a new RuleRouter instance.
func NewRuleRouter(rulesDir string, fallback http.Handler, caCertPath, caKeyPath string, cacheTTL time.Duration, c *cache.InMemoryCache) *RuleRouter {
	return &RuleRouter{
		routes:       make(map[string]*Rule),
		fileRules:    make(map[string]*Rule),
		dynamicRules: make(map[string]*Rule),
		secrets:      make(map[string]string),
		fallback:     fallback,
		rulesDir:     rulesDir,
		caCertPath:   caCertPath,
		caKeyPath:    caKeyPath,
		cacheTTL:     cacheTTL,
		cache:        c,
	}
}

// rebuildRoutesLocked combines fileRules and dynamicRules into the active routes map.
// Callers must hold the write lock (rr.mu.Lock).
func (rr *RuleRouter) rebuildRoutesLocked() {
	combined := make(map[string]*Rule)

	// Copy file rules first
	for k, v := range rr.fileRules {
		combined[k] = v
	}

	// Dynamic rules override or add to file rules
	for k, v := range rr.dynamicRules {
		combined[k] = v
	}

	rr.routes = combined
}

// UpdateDynamicRules sets the dynamic rules in-memory and rebuilds the routing table.
func (rr *RuleRouter) UpdateDynamicRules(rules []PortalRule) error {
	newDynamicRules := make(map[string]*Rule)

	rr.mu.RLock()
	// Temporarily acquire lock on secrets map read
	secretsCopy := make(map[string]string)
	for k, v := range rr.secrets {
		secretsCopy[k] = v
	}
	rr.mu.RUnlock()

	for _, rule := range rules {
		if rule.Spec.Host == "" {
			return fmt.Errorf("rule metadata %q is missing spec.host", rule.Metadata.Name)
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
			return fmt.Errorf("invalid rewriteUrl %q in rule %q: %w", rewriteURLStr, rule.Metadata.Name, err)
		}

		authHeader := rule.Spec.AuthHeader
		if authHeader == "" {
			authHeader = "Authorization"
		}

		// Determine auth token: use SecretRef if present, otherwise fallback to AuthToken
		authToken := rule.Spec.AuthToken
		if rule.Spec.SecretRef != "" {
			token, exists := secretsCopy[rule.Spec.SecretRef]
			if !exists {
				return fmt.Errorf("secret %q referenced by rule %q not found", rule.Spec.SecretRef, rule.Metadata.Name)
			}
			authToken = token
		}

		p, err := proxy.NewHTTPProxy(rewriteURL, authToken, authHeader, rr.caCertPath, rr.caKeyPath)
		if err != nil {
			return fmt.Errorf("failed to create proxy for rule %q: %w", rule.Metadata.Name, err)
		}

		// Rule-specific cacheTTL takes precedence. If specified, setup caching.
		var cacheTTL time.Duration
		if rule.Spec.CacheTTL != "" {
			d, err := time.ParseDuration(rule.Spec.CacheTTL)
			if err != nil {
				return fmt.Errorf("invalid cacheTTL %q in rule %q: %w", rule.Spec.CacheTTL, rule.Metadata.Name, err)
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
		newDynamicRules[host] = &Rule{
			Proxy: p,
			Name:  rule.Metadata.Name,
		}
	}

	rr.mu.Lock()
	rr.dynamicRules = newDynamicRules
	rr.dynamicRulesSource = rules
	rr.rebuildRoutesLocked()
	rr.mu.Unlock()

	return nil
}

// SetSecret sets/registers a dynamic secret in memory.
func (rr *RuleRouter) SetSecret(name, value string) {
	rr.mu.Lock()
	defer rr.mu.Unlock()
	rr.secrets[name] = value
}

// GetSecrets returns all secret names with redacted values.
func (rr *RuleRouter) GetSecrets() map[string]string {
	rr.mu.RLock()
	defer rr.mu.RUnlock()

	redacted := make(map[string]string)
	for k := range rr.secrets {
		redacted[k] = "[REDACTED]"
	}
	return redacted
}

// GetDynamicRules returns a slice of currently loaded dynamic PortalRules.
func (rr *RuleRouter) GetDynamicRules() []PortalRule {
	rr.mu.RLock()
	defer rr.mu.RUnlock()

	copied := make([]PortalRule, len(rr.dynamicRulesSource))
	copy(copied, rr.dynamicRulesSource)
	return copied
}

// SetSecurityPolicy sets the current security policy.
func (rr *RuleRouter) SetSecurityPolicy(policy *SecurityPolicy) {
	rr.mu.Lock()
	defer rr.mu.Unlock()
	rr.securityPolicy = policy
}

// GetSecurityPolicy gets the current security policy.
func (rr *RuleRouter) GetSecurityPolicy() *SecurityPolicy {
	rr.mu.RLock()
	defer rr.mu.RUnlock()
	return rr.securityPolicy
}

// loadRules reads YAML rules from the configured rulesDir and rebuilds the routing table.
func (rr *RuleRouter) loadRules() error {
	if rr.rulesDir == "" {
		return nil
	}

	newFileRules := make(map[string]*Rule)
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
			newFileRules[host] = &Rule{
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
	rr.fileRules = newFileRules
	rr.rebuildRoutesLocked()
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

// GetCertificate implements the CertificateProvider interface to dynamically return certificates for TLS connections.
func (rr *RuleRouter) GetCertificate(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
	host := info.ServerName
	if host == "" {
		host = "localhost"
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(host)

	rr.mu.RLock()
	rule, ok := rr.routes[host]
	rr.mu.RUnlock()

	if ok {
		return rule.Proxy.GetCertificate(info)
	}

	if fallbackProxy, ok := rr.fallback.(*proxy.HTTPProxy); ok {
		return fallbackProxy.GetCertificate(info)
	}

	return nil, fmt.Errorf("no proxy available to sign certificate for %s", host)
}
