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

package main

import (
	"bytes"
	"errors"
	"flag"
	"strings"
	"testing"

	"github.com/gke-labs/service-portals/pkg/portals"
	klog "k8s.io/klog/v2"
)

func TestParseFlags(t *testing.T) {
	var buf bytes.Buffer
	cfg, err := parseFlags([]string{"-rules-dir", "/tmp/rules"}, &buf)
	if err != nil {
		t.Fatalf("parseFlags failed: %v", err)
	}
	if cfg.RulesDir != "/tmp/rules" {
		t.Errorf("expected rules-dir to be /tmp/rules, got %q", cfg.RulesDir)
	}
}

func TestDNSPortPrecedence(t *testing.T) {
	var buf bytes.Buffer

	// 1. Flag takes precedence over environment variables
	t.Run("FlagTakesPrecedence", func(t *testing.T) {
		t.Setenv("PROXY_DNS_PORT", "8053")
		t.Setenv("DNS_PORT", "7053")
		buf.Reset()
		cfg, err := parseFlags([]string{"-dns-port", "9053"}, &buf)
		if err != nil {
			t.Fatalf("parseFlags failed: %v", err)
		}
		if cfg.ProxyDNSPort != "9053" {
			t.Errorf("ProxyDNSPort = %q, want 9053", cfg.ProxyDNSPort)
		}
	})

	// 2. PROXY_DNS_PORT environment variable takes precedence over DNS_PORT and default
	t.Run("ProxyDNSPortEnvTakesPrecedence", func(t *testing.T) {
		t.Setenv("PROXY_DNS_PORT", "8053")
		t.Setenv("DNS_PORT", "7053")
		buf.Reset()
		cfg, err := parseFlags([]string{}, &buf)
		if err != nil {
			t.Fatalf("parseFlags failed: %v", err)
		}
		if cfg.ProxyDNSPort != "8053" {
			t.Errorf("ProxyDNSPort = %q, want 8053", cfg.ProxyDNSPort)
		}
	})

	// 3. DNS_PORT environment variable takes precedence over default when PROXY_DNS_PORT unset
	t.Run("DNSPortEnvUsedWhenNoProxyDNSPort", func(t *testing.T) {
		t.Setenv("PROXY_DNS_PORT", "")
		t.Setenv("DNS_PORT", "7053")
		buf.Reset()
		cfg, err := parseFlags([]string{}, &buf)
		if err != nil {
			t.Fatalf("parseFlags failed: %v", err)
		}
		if cfg.ProxyDNSPort != "7053" {
			t.Errorf("ProxyDNSPort = %q, want 7053", cfg.ProxyDNSPort)
		}
	})

	// 4. DefaultProxyDNSPort used when neither flag nor env is set
	t.Run("DefaultUsedWhenUnset", func(t *testing.T) {
		t.Setenv("PROXY_DNS_PORT", "")
		t.Setenv("DNS_PORT", "")
		buf.Reset()
		cfg, err := parseFlags([]string{}, &buf)
		if err != nil {
			t.Fatalf("parseFlags failed: %v", err)
		}
		if cfg.ProxyDNSPort != portals.DefaultProxyDNSPort {
			t.Errorf("ProxyDNSPort = %q, want %q", cfg.ProxyDNSPort, portals.DefaultProxyDNSPort)
		}
	})
}

func TestDNSPortHelp(t *testing.T) {
	t.Setenv("PROXY_DNS_PORT", "")
	t.Setenv("DNS_PORT", "")

	var buf bytes.Buffer
	_, err := parseFlags([]string{"-h"}, &buf)
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("expected ErrHelp, got: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, `Port to bind DNS server (default "1053")`) {
		t.Errorf("expected help output to contain default port once, got:\n%s", output)
	}
	if count := strings.Count(output, "1053"); count != 1 {
		t.Errorf("expected default port 1053 to appear exactly once, got count %d in:\n%s", count, output)
	}
}

func TestLogVerbosityEnv(t *testing.T) {
	t.Cleanup(func() {
		var l klog.Level
		if err := l.Set("0"); err != nil {
			t.Errorf("failed to reset klog verbosity: %v", err)
		}
	})

	t.Run("ValidLOG_VERBOSITY", func(t *testing.T) {
		t.Setenv("LOG_VERBOSITY", "1")
		var buf bytes.Buffer
		_, err := parseFlags([]string{}, &buf)
		if err != nil {
			t.Fatalf("parseFlags failed: %v", err)
		}
		if !klog.V(1).Enabled() {
			t.Errorf("expected verbosity 1 to be enabled after setting LOG_VERBOSITY=1")
		}
	})

	t.Run("InvalidLOG_VERBOSITY", func(t *testing.T) {
		t.Setenv("LOG_VERBOSITY", "invalid")
		var buf bytes.Buffer
		_, err := parseFlags([]string{}, &buf)
		if err == nil {
			t.Fatalf("expected parseFlags to fail with invalid LOG_VERBOSITY, got nil")
		}
	})

	t.Run("FlagOverridesEnv", func(t *testing.T) {
		t.Setenv("LOG_VERBOSITY", "1")
		var buf bytes.Buffer
		_, err := parseFlags([]string{"-v", "2"}, &buf)
		if err != nil {
			t.Fatalf("parseFlags failed: %v", err)
		}
		if !klog.V(2).Enabled() {
			t.Errorf("expected verbosity 2 to be enabled when -v 2 flag is passed")
		}
	})
}
