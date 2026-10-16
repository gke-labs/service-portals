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
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
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

	// Test case C: denied action (if fallback is nil)
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

		if rec.Code != http.StatusForbidden {
			t.Errorf("expected status 403 Forbidden, got: %d", rec.Code)
		}

		logStr := logBuf.String()
		expectedLog := "Request: PUT other-test.portal | Matched rule: <none> | Action: denied"
		if !strings.Contains(logStr, expectedLog) {
			t.Errorf("expected log to contain %q, got: %q", expectedLog, logStr)
		}
	}
}

func createTestCA(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create CA cert: %v", err)
	}

	tmpDir := t.TempDir()
	certPath = filepath.Join(tmpDir, "ca.crt")
	keyPath = filepath.Join(tmpDir, "ca.key")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})

	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		t.Fatalf("failed to write ca.crt: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatalf("failed to write ca.key: %v", err)
	}

	return certPath, keyPath
}

func TestUnmatchedHostBehavior(t *testing.T) {
	caCertPath, caKeyPath := createTestCA(t)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("matched-backend-ok"))
	}))
	defer backend.Close()

	fallbackBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("fallback-backend-ok"))
	}))
	defer fallbackBackend.Close()

	rulesDir := t.TempDir()
	ruleContent := fmt.Sprintf(`
apiVersion: portals.gke.io/v1alpha1
kind: PortalRule
metadata:
  name: allowed-rule
spec:
  host: "allowed.portal"
  rewriteUrl: "%s"
`, backend.URL)

	if err := os.WriteFile(filepath.Join(rulesDir, "rule.yaml"), []byte(ruleContent), 0644); err != nil {
		t.Fatalf("failed to write rule.yaml: %v", err)
	}

	t.Run("with rules and no fallback (default egress allowlist)", func(t *testing.T) {
		rr := NewRuleRouter(rulesDir, nil, caCertPath, caKeyPath, 0, nil)
		if err := rr.loadRules(); err != nil {
			t.Fatalf("failed to load rules: %v", err)
		}

		// 1. Matched host HTTP
		req := httptest.NewRequest("GET", "/test", nil)
		req.Host = "allowed.portal"
		rec := httptest.NewRecorder()
		rr.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("expected 200 OK for matched host, got %d", rec.Code)
		}

		// 2. Matched host HTTPS GetCertificate
		cert, err := rr.GetCertificate(&tls.ClientHelloInfo{ServerName: "allowed.portal"})
		if err != nil {
			t.Errorf("expected GetCertificate to succeed for allowed.portal, got: %v", err)
		}
		if cert == nil {
			t.Error("expected non-nil cert for allowed.portal")
		}

		// 3. Unmatched host HTTP -> 403 Forbidden
		reqUnmatched := httptest.NewRequest("GET", "/test", nil)
		reqUnmatched.Host = "unmatched.portal"
		recUnmatched := httptest.NewRecorder()
		rr.ServeHTTP(recUnmatched, reqUnmatched)
		if recUnmatched.Code != http.StatusForbidden {
			t.Errorf("expected 403 Forbidden for unmatched host without fallback, got %d", recUnmatched.Code)
		}

		// 4. Unmatched host HTTPS GetCertificate -> denied (error)
		_, errUnmatched := rr.GetCertificate(&tls.ClientHelloInfo{ServerName: "unmatched.portal"})
		if errUnmatched == nil {
			t.Error("expected GetCertificate to fail for unmatched host without fallback, but it succeeded")
		}
	})

	t.Run("with rules and explicit fallback", func(t *testing.T) {
		fallbackURL, _ := url.Parse(fallbackBackend.URL)
		fallbackProxy, err := proxy.NewHTTPProxy(fallbackURL, "", "", caCertPath, caKeyPath)
		if err != nil {
			t.Fatalf("failed to create fallback proxy: %v", err)
		}

		rr := NewRuleRouter(rulesDir, fallbackProxy, caCertPath, caKeyPath, 0, nil)
		if err := rr.loadRules(); err != nil {
			t.Fatalf("failed to load rules: %v", err)
		}

		// 1. Matched host still hits matched rule
		req := httptest.NewRequest("GET", "/test", nil)
		req.Host = "allowed.portal"
		rec := httptest.NewRecorder()
		rr.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || rec.Body.String() != "matched-backend-ok" {
			t.Errorf("expected matched-backend-ok, got status %d body %q", rec.Code, rec.Body.String())
		}

		// 2. Unmatched host HTTP forwards to fallback
		reqUnmatched := httptest.NewRequest("GET", "/test", nil)
		reqUnmatched.Host = "unmatched.portal"
		recUnmatched := httptest.NewRecorder()
		rr.ServeHTTP(recUnmatched, reqUnmatched)
		if recUnmatched.Code != http.StatusOK || recUnmatched.Body.String() != "fallback-backend-ok" {
			t.Errorf("expected fallback-backend-ok, got status %d body %q", recUnmatched.Code, recUnmatched.Body.String())
		}

		// 3. Unmatched host HTTPS GetCertificate succeeds via fallback
		cert, err := rr.GetCertificate(&tls.ClientHelloInfo{ServerName: "unmatched.portal"})
		if err != nil {
			t.Errorf("expected GetCertificate to succeed for unmatched host with fallback, got: %v", err)
		}
		if cert == nil {
			t.Error("expected non-nil cert for unmatched host with fallback")
		}
	})
}

func TestExplicitProxyMode(t *testing.T) {
	caCertPath, caKeyPath := createTestCA(t)

	// Mock backend that records requests and echoes headers
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Received-Host", r.Host)
		w.Header().Set("X-Received-Auth", r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("backend-response-ok"))
	}))
	defer backend.Close()

	rulesDir := t.TempDir()
	ruleContent := fmt.Sprintf(`
apiVersion: portals.gke.io/v1alpha1
kind: PortalRule
metadata:
  name: gemini-rule
spec:
  host: "gemini.backend"
  rewriteUrl: "%s"
  authToken: "gemini-secret-token"
`, backend.URL)

	if err := os.WriteFile(filepath.Join(rulesDir, "gemini.yaml"), []byte(ruleContent), 0644); err != nil {
		t.Fatalf("failed to write rule: %v", err)
	}

	rr := NewRuleRouter(rulesDir, nil, caCertPath, caKeyPath, 0, nil)
	if err := rr.loadRules(); err != nil {
		t.Fatalf("failed to load rules: %v", err)
	}

	proxyServer := httptest.NewServer(rr)
	defer proxyServer.Close()

	proxyURL, _ := url.Parse(proxyServer.URL)
	caCertBytes, err := os.ReadFile(caCertPath)
	if err != nil {
		t.Fatalf("failed to read ca cert: %v", err)
	}
	rootCAs := x509.NewCertPool()
	rootCAs.AppendCertsFromPEM(caCertBytes)

	httpClient := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				RootCAs: rootCAs,
			},
		},
	}

	// 1. CONNECT tunnel for HTTPS matched host (Issue #127 fix)
	t.Run("CONNECT_HTTPS_MatchedHost", func(t *testing.T) {
		resp, err := httpClient.Get("https://gemini.backend/test-connect")
		if err != nil {
			t.Fatalf("CONNECT request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected status 200, got %d", resp.StatusCode)
		}
		if auth := resp.Header.Get("X-Received-Auth"); auth != "Bearer gemini-secret-token" {
			t.Errorf("expected Bearer gemini-secret-token, got %q", auth)
		}
	})

	// 2. Absolute-form HTTP matched host
	t.Run("Absolute_HTTP_MatchedHost", func(t *testing.T) {
		resp, err := httpClient.Get("http://gemini.backend/test-http")
		if err != nil {
			t.Fatalf("HTTP proxy request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected status 200, got %d", resp.StatusCode)
		}
		if auth := resp.Header.Get("X-Received-Auth"); auth != "Bearer gemini-secret-token" {
			t.Errorf("expected Bearer gemini-secret-token, got %q", auth)
		}
	})

	// 3. Unmatched host denied (403 Forbidden)
	t.Run("UnmatchedHost_Denied", func(t *testing.T) {
		resp, err := httpClient.Get("http://unmatched.backend/test")
		if err != nil {
			// Connect tunnel may fail directly with 403
			t.Logf("request correctly failed: %v", err)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("expected status 403 Forbidden for unmatched host, got %d", resp.StatusCode)
		}
	})

	// 4. Proxy-Authorization pod identity token
	t.Run("ProxyAuthorization_Enforcement", func(t *testing.T) {
		rrWithAuth := NewRuleRouter(rulesDir, nil, caCertPath, caKeyPath, 0, nil)
		rrWithAuth.SetProxyAuthToken("workload-token-xyz")
		if err := rrWithAuth.loadRules(); err != nil {
			t.Fatalf("failed to load rules: %v", err)
		}

		proxyWithAuthServer := httptest.NewServer(rrWithAuth)
		defer proxyWithAuthServer.Close()
		authProxyURL, _ := url.Parse(proxyWithAuthServer.URL)

		// Client without proxy auth -> 407
		unauthedClient := &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyURL(authProxyURL),
			},
		}
		resp, err := unauthedClient.Get("http://gemini.backend/test")
		if err != nil {
			t.Fatalf("unexpected transport error: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusProxyAuthRequired {
			t.Errorf("expected status 407 Proxy Authentication Required, got %d", resp.StatusCode)
		}

		// Client with Proxy URL embedded auth (http://workload-token-xyz:x@proxy)
		authedProxyURL, _ := url.Parse(authProxyURL.String())
		authedProxyURL.User = url.UserPassword("workload-token-xyz", "ignored")
		authedClient := &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyURL(authedProxyURL),
			},
		}
		authedResp, err := authedClient.Get("http://gemini.backend/test")
		if err != nil {
			t.Fatalf("authenticated proxy request failed: %v", err)
		}
		authedResp.Body.Close()
		if authedResp.StatusCode != http.StatusOK {
			t.Errorf("expected status 200 for authenticated proxy request, got %d", authedResp.StatusCode)
		}
	})
}
