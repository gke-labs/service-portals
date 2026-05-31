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
	"bytes"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gke-labs/service-portals/pkg/proxy"
)

func TestLoadRulesAndRouting(t *testing.T) {
	// Create a temp directory for rules
	tmpDir, err := os.MkdirTemp("", "portal-rules-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Set up mock target backends
	backend1Called := false
	backend1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backend1Called = true
		if r.Header.Get("Authorization") != "Bearer token-1" {
			t.Errorf("expected Authorization header Bearer token-1, got: %q", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("backend-1-response"))
	}))
	defer backend1.Close()

	backend2Called := false
	backend2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backend2Called = true
		if r.Header.Get("X-Custom-Auth") != "token-2" {
			t.Errorf("expected X-Custom-Auth header token-2, got: %q", r.Header.Get("X-Custom-Auth"))
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("backend-2-response"))
	}))
	defer backend2.Close()

	ipv6BackendCalled := false
	ipv6Backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ipv6BackendCalled = true
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ipv6-response"))
	}))
	defer ipv6Backend.Close()

	fallbackCalled := false
	fallbackBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fallbackCalled = true
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("fallback-response"))
	}))
	defer fallbackBackend.Close()

	// Create fallback HTTPProxy
	fallbackURL, _ := url.Parse(fallbackBackend.URL)
	fallbackProxy, err := proxy.NewHTTPProxy(fallbackURL, "", "", "", "")
	if err != nil {
		t.Fatalf("failed to create fallback proxy: %v", err)
	}

	// Write rules to temp dir using rewritten json-aligned property names (rewriteUrl, cacheTTL)
	rule1Content := fmt.Sprintf(`
apiVersion: portals.gke.io/v1alpha1
kind: PortalRule
metadata:
  name: test-rule-1
spec:
  host: "service-1.portal"
  rewriteUrl: "%s"
  authToken: "token-1"
  authHeader: "Authorization"
  cacheTTL: "10s"
`, backend1.URL)

	rule2Content := fmt.Sprintf(`
apiVersion: portals.gke.io/v1alpha1
kind: PortalRule
metadata:
  name: test-rule-2
spec:
  host: "service-2.portal"
  rewriteUrl: "%s"
  authToken: "token-2"
  authHeader: "X-Custom-Auth"
`, backend2.URL)

	// Verify defaulting of rewriteUrl to host (when omitted) and prepend of https://
	ruleDefaultContent := `
apiVersion: portals.gke.io/v1alpha1
kind: PortalRule
metadata:
  name: test-rule-default
spec:
  host: "google.com"
`

	// Test rule for safe IPv6 support
	ipv6RuleContent := fmt.Sprintf(`
apiVersion: portals.gke.io/v1alpha1
kind: PortalRule
metadata:
  name: test-ipv6-rule
spec:
  host: "::1"
  rewriteUrl: "%s"
`, ipv6Backend.URL)

	// Also write a file containing multiple rules separated by "---"
	multiRuleContent := fmt.Sprintf(`
apiVersion: portals.gke.io/v1alpha1
kind: PortalRule
metadata:
  name: multi-rule-a
spec:
  host: "multi-a.portal"
  rewriteUrl: "%s"
---
apiVersion: portals.gke.io/v1alpha1
kind: PortalRule
metadata:
  name: multi-rule-b
spec:
  host: "multi-b.portal"
  rewriteUrl: "%s"
`, backend1.URL, backend2.URL)

	// An invalid rule that should be skipped or trigger warning
	invalidRuleContent := `
apiVersion: portals.gke.io/v1alpha1
kind: PortalRule
metadata:
  name: invalid-rule
spec:
  host: ""
  rewriteUrl: ""
`

	// A rule with a different Kind that should be skipped
	wrongKindContent := `
apiVersion: portals.gke.io/v1alpha1
kind: OtherConfig
metadata:
  name: wrong-kind
spec:
  host: "should-skip.portal"
  rewriteUrl: "https://skip.me"
`

	if err := os.WriteFile(filepath.Join(tmpDir, "rule1.yaml"), []byte(rule1Content), 0644); err != nil {
		t.Fatalf("failed to write rule1: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "rule2.yaml"), []byte(rule2Content), 0644); err != nil {
		t.Fatalf("failed to write rule2: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "rule_default.yaml"), []byte(ruleDefaultContent), 0644); err != nil {
		t.Fatalf("failed to write default rule: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "rule_ipv6.yaml"), []byte(ipv6RuleContent), 0644); err != nil {
		t.Fatalf("failed to write ipv6 rule: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "multi.yaml"), []byte(multiRuleContent), 0644); err != nil {
		t.Fatalf("failed to write multi rule: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "invalid.yaml"), []byte(invalidRuleContent), 0644); err != nil {
		t.Fatalf("failed to write invalid rule: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "wrong_kind.yaml"), []byte(wrongKindContent), 0644); err != nil {
		t.Fatalf("failed to write wrong kind: %v", err)
	}

	// Initialize RuleRouter
	rr := NewRuleRouter(tmpDir, fallbackProxy, "", "", 0, nil)
	if err := rr.loadRules(); err != nil {
		t.Fatalf("failed to load rules: %v", err)
	}

	// Verify routes are loaded (6 valid rules: rule1, rule2, ruleDefault, ruleIPv6, multi-a, multi-b)
	rr.mu.RLock()
	routesCount := len(rr.routes)
	rr.mu.RUnlock()
	if routesCount != 6 {
		t.Errorf("expected 6 loaded routes, got %d", routesCount)
	}

	// Verify default-to-host and https:// prefixing logic:
	rr.mu.RLock()
	googleRule, exists := rr.routes["google.com"]
	rr.mu.RUnlock()
	if !exists {
		t.Error("expected google.com rule to be loaded")
	} else if googleRule.Proxy.TargetURL.String() != "https://google.com" {
		t.Errorf("expected targeted URL 'https://google.com' for default host-derived rewrite url, got %q", googleRule.Proxy.TargetURL.String())
	}

	// Test case 1: Route matching service-1.portal
	{
		backend1Called = false
		req := httptest.NewRequest("GET", "/foo", nil)
		req.Host = "service-1.portal"
		rec := httptest.NewRecorder()
		rr.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", rec.Code)
		}
		if !backend1Called {
			t.Error("expected backend1 to be called")
		}
	}

	// Test case 2: Case insensitivity and port stripping matching SERVICE-2.PORTAL:1234
	{
		backend2Called = false
		req := httptest.NewRequest("GET", "/bar", nil)
		req.Host = "SERVICE-2.PORTAL:1234"
		rec := httptest.NewRecorder()
		rr.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", rec.Code)
		}
		if !backend2Called {
			t.Error("expected backend2 to be called")
		}
	}

	// Test case 3: IPv6 host routing and port-stripping matching [::1]:8080
	{
		ipv6BackendCalled = false
		req := httptest.NewRequest("GET", "/baz", nil)
		req.Host = "[::1]:8080"
		rec := httptest.NewRecorder()
		rr.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", rec.Code)
		}
		if !ipv6BackendCalled {
			t.Error("expected IPv6 backend to be called")
		}
	}

	// Test case 4: Fallback routing
	{
		fallbackCalled = false
		req := httptest.NewRequest("GET", "/baz", nil)
		req.Host = "unregistered.portal"
		rec := httptest.NewRecorder()
		rr.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", rec.Code)
		}
		if !fallbackCalled {
			t.Error("expected fallback backend to be called")
		}
	}
}

func TestSIGHUPReloading(t *testing.T) {
	// Create a temp directory for rules
	tmpDir, err := os.MkdirTemp("", "portal-rules-sighup-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	backendACalled := false
	backendA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendACalled = true
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("backend-A"))
	}))
	defer backendA.Close()

	backendBCalled := false
	backendB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendBCalled = true
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("backend-B"))
	}))
	defer backendB.Close()

	// Write initial rule pointing to backend A
	ruleContent := fmt.Sprintf(`
apiVersion: portals.gke.io/v1alpha1
kind: PortalRule
metadata:
  name: dynamic-rule
spec:
  host: "dynamic.portal"
  rewriteUrl: "%s"
`, backendA.URL)

	rulePath := filepath.Join(tmpDir, "rule.yaml")
	if err := os.WriteFile(rulePath, []byte(ruleContent), 0644); err != nil {
		t.Fatalf("failed to write rule: %v", err)
	}

	// Initialize Server config
	config := Config{
		RulesDir: tmpDir,
	}

	// Since we are running in an active test, we can directly invoke portals.Run in a goroutine
	// and set the port dynamically to avoid collisions.
	os.Setenv("PORT", "28080")
	os.Setenv("HTTPS_PORT", "28443")
	os.Setenv("TARGET_URL", backendA.URL) // fallback target url
	defer os.Unsetenv("PORT")
	defer os.Unsetenv("HTTPS_PORT")
	defer os.Unsetenv("TARGET_URL")

	errChan := make(chan error, 1)
	go func() {
		// Use t.Context() to gracefully bind the server lifecycle with the test execution context
		if err := Run(t.Context(), config); err != nil {
			errChan <- err
		}
	}()

	// Wait for the server to start (using a brief sleep/probe)
	time.Sleep(200 * time.Millisecond)

	// Query dynamic.portal (mocking the Host header via a proxy call)
	// Actually we can hit local :28080 with Host: dynamic.portal
	client := &http.Client{Timeout: 1 * time.Second}
	req, _ := http.NewRequest("GET", "http://localhost:28080/probe", nil)
	req.Host = "dynamic.portal"

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("failed to query local proxy: %v", err)
	}
	resp.Body.Close()

	if !backendACalled {
		t.Error("expected backendA to be called initially")
	}

	// Now modify the rule on disk to point to backend B
	ruleContentUpdated := fmt.Sprintf(`
apiVersion: portals.gke.io/v1alpha1
kind: PortalRule
metadata:
  name: dynamic-rule
spec:
  host: "dynamic.portal"
  rewriteUrl: "%s"
`, backendB.URL)

	if err := os.WriteFile(rulePath, []byte(ruleContentUpdated), 0644); err != nil {
		t.Fatalf("failed to rewrite rule: %v", err)
	}

	// Send SIGHUP to ourselves to trigger hot-reloading
	pid := os.Getpid()
	process, err := os.FindProcess(pid)
	if err != nil {
		t.Fatalf("failed to find current process: %v", err)
	}

	backendBCalled = false
	if err := process.Signal(syscall.SIGHUP); err != nil {
		t.Fatalf("failed to send SIGHUP signal: %v", err)
	}

	// Wait briefly for the reload routine to complete on SIGHUP
	time.Sleep(200 * time.Millisecond)

	// Query dynamic.portal again
	req2, _ := http.NewRequest("GET", "http://localhost:28080/probe", nil)
	req2.Host = "dynamic.portal"

	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatalf("failed to query local proxy after reload: %v", err)
	}
	resp2.Body.Close()

	if !backendBCalled {
		t.Error("expected backendB to be called after SIGHUP reload")
	}
}

func TestRuleRouterLogging(t *testing.T) {
	// Create a temp directory for rules
	tmpDir, err := os.MkdirTemp("", "portal-rules-logging-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	ruleContent := fmt.Sprintf(`
apiVersion: portals.gke.io/v1alpha1
kind: PortalRule
metadata:
  name: test-logging-rule
spec:
  host: "log-test.portal"
  rewriteUrl: "%s"
`, backend.URL)

	if err := os.WriteFile(filepath.Join(tmpDir, "rule.yaml"), []byte(ruleContent), 0644); err != nil {
		t.Fatalf("failed to write rule: %v", err)
	}

	fallbackBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer fallbackBackend.Close()

	fallbackURL, _ := url.Parse(fallbackBackend.URL)
	fallbackProxy, err := proxy.NewHTTPProxy(fallbackURL, "", "", "", "")
	if err != nil {
		t.Fatalf("failed to create fallback proxy: %v", err)
	}

	rr := NewRuleRouter(tmpDir, fallbackProxy, "", "", 0, nil)
	if err := rr.loadRules(); err != nil {
		t.Fatalf("failed to load rules: %v", err)
	}

	// Capture log output
	var logBuf bytes.Buffer
	originalOutput := log.Writer()
	log.SetOutput(&logBuf)
	defer log.SetOutput(originalOutput)

	// Test case A: proxy action
	{
		logBuf.Reset()
		req := httptest.NewRequest("GET", "/test", nil)
		req.Host = "log-test.portal"
		rec := httptest.NewRecorder()
		rr.ServeHTTP(rec, req)

		logStr := logBuf.String()
		expectedLog := "Request: GET log-test.portal | Matched rule: test-logging-rule | Action: proxy"
		if !strings.Contains(logStr, expectedLog) {
			t.Errorf("expected log to contain %q, got: %q", expectedLog, logStr)
		}
	}

	// Test case B: fallback action
	{
		logBuf.Reset()
		req := httptest.NewRequest("POST", "/other", nil)
		req.Host = "other-test.portal"
		rec := httptest.NewRecorder()
		rr.ServeHTTP(rec, req)

		logStr := logBuf.String()
		expectedLog := "Request: POST other-test.portal | Matched rule: <none> | Action: fallback"
		if !strings.Contains(logStr, expectedLog) {
			t.Errorf("expected log to contain %q, got: %q", expectedLog, logStr)
		}
	}

	// Test case C: not found action (if fallback is nil)
	{
		logBuf.Reset()
		rrNoFallback := NewRuleRouter(tmpDir, nil, "", "", 0, nil)
		if err := rrNoFallback.loadRules(); err != nil {
			t.Fatalf("failed to load rules for rrNoFallback: %v", err)
		}
		req := httptest.NewRequest("PUT", "/notfound", nil)
		req.Host = "other-test.portal"
		rec := httptest.NewRecorder()
		rrNoFallback.ServeHTTP(rec, req)

		logStr := logBuf.String()
		expectedLog := "Request: PUT other-test.portal | Matched rule: <none> | Action: not found"
		if !strings.Contains(logStr, expectedLog) {
			t.Errorf("expected log to contain %q, got: %q", expectedLog, logStr)
		}
	}
}
