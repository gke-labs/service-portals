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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/containerd/nri/pkg/api"
)

func TestParseResolvConf(t *testing.T) {
	content := `# Dynamic resolv.conf
nameserver 10.96.0.10
search default.svc.cluster.local svc.cluster.local cluster.local
options ndots:5
nameserver 1.1.1.1
nameserver invalid-ip
`
	servers := parseResolvConf(content)
	if len(servers) != 2 {
		t.Fatalf("expected 2 valid nameservers, got %d: %v", len(servers), servers)
	}
	if servers[0] != "10.96.0.10" || servers[1] != "1.1.1.1" {
		t.Errorf("unexpected nameserver list: %v", servers)
	}
}

func TestMatchesPod(t *testing.T) {
	p := &portalPlugin{
		cfg: pluginConfig{
			labelKey: "service-portal.gke.io/intercept",
			labelVal: "true",
		},
	}

	tests := []struct {
		name     string
		pod      *api.PodSandbox
		expected bool
	}{
		{
			name:     "nil pod",
			pod:      nil,
			expected: false,
		},
		{
			name: "matching label",
			pod: &api.PodSandbox{
				Labels: map[string]string{
					"service-portal.gke.io/intercept": "true",
				},
			},
			expected: true,
		},
		{
			name: "matching annotation",
			pod: &api.PodSandbox{
				Annotations: map[string]string{
					"service-portal.gke.io/intercept": "true",
				},
			},
			expected: true,
		},
		{
			name: "unmatched pod with portal label",
			pod: &api.PodSandbox{
				Labels: map[string]string{
					"portal": "true",
				},
			},
			expected: false,
		},
		{
			name: "unmatched pod",
			pod: &api.PodSandbox{
				Labels: map[string]string{
					"app": "unrelated",
				},
			},
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := p.matchesPod(tc.pod); got != tc.expected {
				t.Errorf("matchesPod() = %v, expected %v", got, tc.expected)
			}
		})
	}
}

func TestGetInterceptIPAndHosts(t *testing.T) {
	p := &portalPlugin{
		cfg: pluginConfig{
			interceptIP:    "10.0.0.1",
			interceptHosts: "default.backend",
		},
	}

	podWithOverrides := &api.PodSandbox{
		Annotations: map[string]string{
			"service-portal.gke.io/intercept-ip":    "10.0.0.2",
			"service-portal.gke.io/intercept-hosts": "custom.backend",
		},
	}

	if ip := p.getInterceptIP(podWithOverrides); ip != "10.0.0.2" {
		t.Errorf("expected annotation override 10.0.0.2, got %s", ip)
	}
	if hosts := p.getInterceptHosts(podWithOverrides); hosts != "custom.backend" {
		t.Errorf("expected annotation override custom.backend, got %s", hosts)
	}

	podDefault := &api.PodSandbox{}
	if ip := p.getInterceptIP(podDefault); ip != "10.0.0.1" {
		t.Errorf("expected fallback to config 10.0.0.1, got %s", ip)
	}
	if hosts := p.getInterceptHosts(podDefault); hosts != "default.backend" {
		t.Errorf("expected fallback to config default.backend, got %s", hosts)
	}
}

func TestUpdatePodHostsEmptyUID(t *testing.T) {
	p := &portalPlugin{}
	pod := &api.PodSandbox{
		Namespace: "default",
		Name:      "test-pod",
	}
	if err := p.updatePodHosts(pod, "example.com", "10.0.0.1"); err == nil {
		t.Fatalf("expected error on empty pod UID, got nil")
	}
}

func TestAppendHostsEntry(t *testing.T) {
	p := &portalPlugin{
		cfg: pluginConfig{},
	}

	tmpDir := t.TempDir()
	hostsPath := filepath.Join(tmpDir, "etc-hosts")
	initialContent := "127.0.0.1 localhost\n::1 localhost\n"
	if err := os.WriteFile(hostsPath, []byte(initialContent), 0644); err != nil {
		t.Fatalf("failed to write initial hosts file: %v", err)
	}

	hostsStr := "gemini.backend, github.backend"
	interceptIP := "10.244.0.50"

	// First append should succeed
	if err := p.appendHostsEntry(hostsPath, hostsStr, interceptIP); err != nil {
		t.Fatalf("appendHostsEntry failed: %v", err)
	}

	contentBytes, err := os.ReadFile(hostsPath)
	if err != nil {
		t.Fatalf("read hosts file failed: %v", err)
	}
	content := string(contentBytes)
	if !strings.Contains(content, "10.244.0.50 gemini.backend github.backend") {
		t.Fatalf("expected hosts entry missing from file: %s", content)
	}

	// Second append should be a no-op (deduplicated)
	if err := p.appendHostsEntry(hostsPath, hostsStr, interceptIP); err != nil {
		t.Fatalf("second appendHostsEntry failed: %v", err)
	}

	contentBytesAfter, err := os.ReadFile(hostsPath)
	if err != nil {
		t.Fatalf("read hosts file after second append failed: %v", err)
	}
	if string(contentBytesAfter) != content {
		t.Fatalf("duplicate entry appended: %s", string(contentBytesAfter))
	}
}
