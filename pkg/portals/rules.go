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
	Host               string `json:"host"`
	RewriteURL         string `json:"rewriteUrl"`
	AuthToken          string `json:"authToken"`
	AuthHeader         string `json:"authHeader"`
	CacheTTL           string `json:"cacheTTL"`
	AttributionHeaders bool   `json:"attributionHeaders,omitempty"`
}

// Rule represents a loaded routing rule with its proxy and name.
type Rule struct {
	Proxy              *proxy.HTTPProxy
	Name               string
	AttributionHeaders bool
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
	podMap     *PodMap
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

// SetPodMap sets the PodMap for caller pod resolution and policy enforcement.
func (rr *RuleRouter) SetPodMap(pm *PodMap) {
	rr.mu.Lock()
	defer rr.mu.Unlock()
	rr.podMap = pm
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
				Proxy:              p,
				Name:               rule.Metadata.Name,
				AttributionHeaders: rule.Spec.AttributionHeaders,
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
	host = strings.ToLower(proxy.HostWithoutPort(host))

	rr.mu.RLock()
	rule, ok := rr.routes[host]
	pm := rr.podMap
	rr.mu.RUnlock()

	var pod *PodInfo
	if pm != nil {
		clientIP := proxy.HostWithoutPort(r.RemoteAddr)
		var found bool
		if pod, found = pm.GetPodByIP(clientIP); !found || pod == nil {
			log.Printf("Request: %s %s | Caller: unknown (%s) | Action: denied", r.Method, host, clientIP)
			http.Error(w, "Access Denied: caller not recognized as an opted-in pod", http.StatusForbidden)
			return
		}
		if !pod.Bound {
			log.Printf("Request: %s %s | Caller: %s/%s (%s) | State: unbound | Action: denied", r.Method, host, pod.Namespace, pod.Name, clientIP)
			http.Error(w, "Access Denied: pod is unbound", http.StatusForbidden)
			return
		}
	}

	caller := "<none>"
	if pod != nil {
		caller = pod.Namespace + "/" + pod.Name
	}

	if ok {
		if pm != nil && !pm.IsRuleAllowed(pod, rule.Name, host) {
			log.Printf("Request: %s %s | Caller: %s | Policy: %s | Matched rule: %s | Action: denied", r.Method, host, caller, pod.Policy, rule.Name)
			http.Error(w, "Access Denied: host not allowed by pod policy", http.StatusForbidden)
			return
		}
		if pod != nil {
			log.Printf("Request: %s %s | Caller: %s (identity: %s) | Matched rule: %s | Action: proxy", r.Method, host, caller, pod.Identity, rule.Name)
			// Security: Only send attribution headers upstream when the PortalRule explicitly opts in to them (#182 review).
			if rule.AttributionHeaders {
				r.Header.Set("X-Forwarded-Client-Pod", caller)
				if pod.Identity != "" {
					r.Header.Set("X-Consumer-Identity", pod.Identity)
				}
			}
		} else {
			log.Printf("Request: %s %s | Matched rule: %s | Action: proxy", r.Method, host, rule.Name)
		}
		rule.Proxy.ServeHTTP(w, r)
		return
	}

	if rr.fallback != nil {
		if pm != nil && !pm.IsRuleAllowed(pod, "fallback", host) {
			log.Printf("Request: %s %s | Caller: %s | Policy: %s | Matched rule: <fallback> | Action: denied", r.Method, host, caller, pod.Policy)
			http.Error(w, "Access Denied: host not allowed by pod policy", http.StatusForbidden)
			return
		}
		if pod != nil {
			log.Printf("Request: %s %s | Caller: %s | Matched rule: <none> | Action: fallback", r.Method, host, caller)
		} else {
			log.Printf("Request: %s %s | Matched rule: <none> | Action: fallback", r.Method, host)
		}
		rr.fallback.ServeHTTP(w, r)
		return
	}

	if pod != nil {
		log.Printf("Request: %s %s | Caller: %s | Matched rule: <none> | Action: denied", r.Method, host, caller)
	} else {
		log.Printf("Request: %s %s | Matched rule: <none> | Action: denied", r.Method, host)
	}
	http.Error(w, "Access Denied: host not allowed by portal rules", http.StatusForbidden)
}

// GetCertificate implements the CertificateProvider interface to dynamically return certificates for TLS connections.
func (rr *RuleRouter) GetCertificate(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
	host := info.ServerName
	if host == "" {
		host = "localhost"
	}
	host = proxy.HostWithoutPort(host)
	host = strings.ToLower(host)

	rr.mu.RLock()
	rule, ok := rr.routes[host]
	pm := rr.podMap
	rr.mu.RUnlock()

	if pm != nil {
		var clientIP string
		if info.Conn != nil && info.Conn.RemoteAddr() != nil {
			clientIP = proxy.HostWithoutPort(info.Conn.RemoteAddr().String())
		}
		pod, found := pm.GetPodByIP(clientIP)
		if !found || pod == nil {
			return nil, fmt.Errorf("access denied for caller %s: unknown caller", clientIP)
		}
		if !pod.Bound {
			return nil, fmt.Errorf("access denied for caller %s: pod is unbound", clientIP)
		}
		ruleName := ""
		if ok {
			ruleName = rule.Name
		}
		if !pm.IsRuleAllowed(pod, ruleName, host) {
			return nil, fmt.Errorf("access denied for caller %s: host %q not permitted by policy %q", clientIP, host, pod.Policy)
		}
	}

	if ok {
		return rule.Proxy.GetCertificate(info)
	}

	if fallbackProxy, ok := rr.fallback.(*proxy.HTTPProxy); ok {
		return fallbackProxy.GetCertificate(info)
	}

	return nil, fmt.Errorf("no rule matches host %q and no fallback configured to sign certificate", host)
}
