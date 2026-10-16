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

package proxy

import (
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

func TestParseResolvConf(t *testing.T) {
	content := `
# Kubernetes cluster DNS
search default.svc.cluster.local svc.cluster.local cluster.local
nameserver 10.96.0.10
nameserver 127.0.0.1
nameserver 2001:db8::53
nameserver ::1
options ndots:5
`
	tmpDir := t.TempDir()
	resolvPath := filepath.Join(tmpDir, "resolv.conf")
	if err := os.WriteFile(resolvPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp resolv.conf: %v", err)
	}

	servers, err := ParseResolvConf(resolvPath)
	if err != nil {
		t.Fatalf("ParseResolvConf failed: %v", err)
	}

	// Should include 10.96.0.10 and 2001:db8::53, but exclude 127.0.0.1 and ::1 (loopbacks)
	expected := []string{"10.96.0.10", "2001:db8::53"}
	if len(servers) != len(expected) {
		t.Fatalf("expected %d servers, got %d (%v)", len(expected), len(servers), servers)
	}
	for i, s := range expected {
		if servers[i] != s {
			t.Errorf("server[%d]: expected %s, got %s", i, s, servers[i])
		}
	}
}

func TestResolveUpstreamDNSServers_EnvVar(t *testing.T) {
	t.Setenv("UPSTREAM_DNS_SERVERS", "10.96.0.10:53, 127.0.0.1:53, 1.1.1.1")
	servers, err := ResolveUpstreamDNSServers()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := []string{"10.96.0.10:53", "1.1.1.1"}
	if len(servers) != len(expected) {
		t.Fatalf("expected %d servers, got %d (%v)", len(expected), len(servers), servers)
	}
	for i, s := range expected {
		if servers[i] != s {
			t.Errorf("server[%d]: expected %s, got %s", i, s, servers[i])
		}
	}
}

func TestResolveUpstreamDNSServers_AllLoopback(t *testing.T) {
	t.Setenv("UPSTREAM_DNS_SERVERS", "127.0.0.1, 127.0.0.53, ::1")
	servers, err := ResolveUpstreamDNSServers()
	if err == nil {
		t.Fatalf("expected error when all nameservers are loopback, got servers: %v", servers)
	}
	if len(servers) != 0 {
		t.Errorf("expected no servers, got: %v", servers)
	}
}

func TestResolveUpstreamDNSServers_AllLoopbackResolvConf(t *testing.T) {
	tmpDir := t.TempDir()
	resolvPath := filepath.Join(tmpDir, "resolv.conf")
	content := "nameserver 127.0.0.1\nnameserver ::1\n"
	if err := os.WriteFile(resolvPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp resolv.conf: %v", err)
	}
	t.Setenv("UPSTREAM_DNS_SERVERS", "")
	t.Setenv("DNS_SERVER_IPS", "")
	t.Setenv("RESOLV_CONF", resolvPath)

	servers, err := ResolveUpstreamDNSServers()
	if err == nil {
		t.Fatalf("expected error when all nameservers in resolv.conf are loopback, got servers: %v", servers)
	}
	if len(servers) != 0 {
		t.Errorf("expected no servers, got: %v", servers)
	}
}

func TestNewHTTPProxyWithResolver_DiscoveryError(t *testing.T) {
	t.Setenv("UPSTREAM_DNS_SERVERS", "127.0.0.1")
	u, err := url.Parse("http://example.com")
	if err != nil {
		t.Fatalf("url.Parse failed: %v", err)
	}
	p, err := NewHTTPProxyWithResolver(u, "", "", "", "", nil)
	if err == nil {
		t.Fatalf("expected error when upstream DNS discovery fails, got proxy: %v", p)
	}
}

func TestNewHTTPProxy_LoopbackResolvConfFallback(t *testing.T) {
	tmpDir := t.TempDir()
	resolvPath := filepath.Join(tmpDir, "resolv.conf")
	content := "nameserver 127.0.0.53\n"
	if err := os.WriteFile(resolvPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp resolv.conf: %v", err)
	}
	t.Setenv("UPSTREAM_DNS_SERVERS", "")
	t.Setenv("DNS_SERVER_IPS", "")
	t.Setenv("RESOLV_CONF", resolvPath)

	u, err := url.Parse("http://example.com")
	if err != nil {
		t.Fatalf("url.Parse failed: %v", err)
	}

	// NewHTTPProxy falls back to the default resolver and succeeds
	p, err := NewHTTPProxy(u, "", "", "", "")
	if err != nil {
		t.Fatalf("expected NewHTTPProxy to succeed with default resolver fallback, got: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil proxy from NewHTTPProxy")
	}

	// NewHTTPProxyWithResolver(..., nil) is strict and errors
	pStrict, err := NewHTTPProxyWithResolver(u, "", "", "", "", nil)
	if err == nil {
		t.Fatalf("expected NewHTTPProxyWithResolver(..., nil) to fail, got proxy: %v", pStrict)
	}
}

func TestNewUpstreamResolver(t *testing.T) {
	resolver := NewUpstreamResolver([]string{"10.96.0.10:53"})
	if resolver == nil {
		t.Fatal("expected non-nil resolver")
	}
	if !resolver.PreferGo {
		t.Errorf("expected PreferGo to be true")
	}
	if resolver.Dial == nil {
		t.Errorf("expected Dial function to be set")
	}

	emptyResolver := NewUpstreamResolver(nil)
	if emptyResolver != nil {
		t.Errorf("expected nil resolver when no servers provided, got %v", emptyResolver)
	}
}

func TestNewTransport_WithResolver(t *testing.T) {
	resolver := NewUpstreamResolver([]string{"10.96.0.10:53"})
	tr := NewTransport(resolver)
	if tr == nil {
		t.Fatal("expected non-nil transport")
	}
	if tr.DialContext == nil {
		t.Errorf("expected DialContext to be set")
	}
}
