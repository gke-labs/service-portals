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
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/containerd/nri/pkg/api"
	"github.com/gke-labs/service-portals/pkg/portals"
)

func TestMatchesPod(t *testing.T) {
	p := &portalPlugin{}

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
			name: "annotation only is rejected (only label supported for opt-in)",
			pod: &api.PodSandbox{
				Annotations: map[string]string{
					"service-portal.gke.io/intercept": "true",
				},
			},
			expected: false,
		},
		{
			name: "undocumented shorthand label value 1 rejected",
			pod: &api.PodSandbox{
				Labels: map[string]string{
					"service-portal.gke.io/intercept": "1",
				},
			},
			expected: false,
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

func TestFindNetnsPath(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping network namespace test on non-linux OS")
	}

	p := &portalPlugin{}

	t.Run("nil pod", func(t *testing.T) {
		if _, err := p.findNetnsPath(nil); err == nil {
			t.Fatalf("expected error for nil pod, got nil")
		}
	})

	t.Run("sandbox with no Linux configuration", func(t *testing.T) {
		pod := &api.PodSandbox{
			Namespace: "default",
			Name:      "test-pod",
			Linux:     nil,
		}
		if _, err := p.findNetnsPath(pod); err == nil {
			t.Fatalf("expected error for sandbox with no Linux config, got nil")
		}
	})

	t.Run("sandbox with no network namespace entry (hostNetwork)", func(t *testing.T) {
		pod := &api.PodSandbox{
			Namespace: "default",
			Name:      "host-network-pod",
			Linux: &api.LinuxPodSandbox{
				Namespaces: []*api.LinuxNamespace{
					{Type: "ipc", Path: "/proc/1/ns/ipc"},
					{Type: "pid", Path: "/proc/1/ns/pid"},
				},
			},
		}
		path, err := p.findNetnsPath(pod)
		if err == nil {
			t.Fatalf("expected error for hostNetwork pod with no netns entry, got path: %s", path)
		}
		if !strings.Contains(err.Error(), "no network namespace entry") {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	t.Run("sandbox whose netns matches plugin host network namespace", func(t *testing.T) {
		pod := &api.PodSandbox{
			Namespace: "default",
			Name:      "same-netns-pod",
			Linux: &api.LinuxPodSandbox{
				Namespaces: []*api.LinuxNamespace{
					{Type: "network", Path: "/proc/self/ns/net"},
				},
			},
		}
		path, err := p.findNetnsPath(pod)
		if err == nil {
			t.Fatalf("expected error when netns matches plugin host netns, got path: %s", path)
		}
		if !strings.Contains(err.Error(), "matches plugin host network namespace") {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	t.Run("sandbox with non-existent netns path", func(t *testing.T) {
		pod := &api.PodSandbox{
			Namespace: "default",
			Name:      "missing-netns-pod",
			Linux: &api.LinuxPodSandbox{
				Namespaces: []*api.LinuxNamespace{
					{Type: "network", Path: "/nonexistent/netns/path"},
				},
			},
		}
		if _, err := p.findNetnsPath(pod); err == nil {
			t.Fatalf("expected error for non-existent netns path, got nil")
		}
	})
}

func TestGetRuntimeClass(t *testing.T) {
	tests := []struct {
		name     string
		pod      *api.PodSandbox
		expected string
	}{
		{
			name:     "nil pod",
			pod:      nil,
			expected: "",
		},
		{
			name: "pod with RuntimeHandler",
			pod: &api.PodSandbox{
				RuntimeHandler: "kata",
			},
			expected: "kata",
		},
		{
			name: "pod with annotation",
			pod: &api.PodSandbox{
				Annotations: map[string]string{
					"io.kubernetes.cri.runtime-handler": "gvisor",
				},
			},
			expected: "gvisor",
		},
		{
			name: "pod with neither",
			pod: &api.PodSandbox{
				Namespace: "default",
				Name:      "standard-pod",
			},
			expected: "",
		},
		{
			name: "RuntimeHandler takes precedence over annotation",
			pod: &api.PodSandbox{
				RuntimeHandler: "kata-qemu",
				Annotations: map[string]string{
					"io.kubernetes.cri.runtime-handler": "gvisor",
				},
			},
			expected: "kata-qemu",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := getRuntimeClass(tc.pod); got != tc.expected {
				t.Errorf("getRuntimeClass() = %q, expected %q", got, tc.expected)
			}
		})
	}
}

func TestIsSupportedRuntime(t *testing.T) {
	tests := []struct {
		runtime  string
		expected bool
	}{
		{"", true},
		{"runc", true},
		{"RUNC", true},
		{"gvisor", true},
		{"runsc", true},
		{"kata", true},
		{"kata-qemu", true},
		{"kata-clh", true},
		{"kata-fc", true},
		{"kata-containers", true},
		{"unknown-runtime", false},
		{"custom-microvm", false},
		{"unsupported", false},
	}

	for _, tc := range tests {
		t.Run(tc.runtime, func(t *testing.T) {
			if got := isSupportedRuntime(tc.runtime); got != tc.expected {
				t.Errorf("isSupportedRuntime(%q) = %v, expected %v", tc.runtime, got, tc.expected)
			}
		})
	}
}

func TestRuntimeClassValidation(t *testing.T) {
	p := &portalPlugin{
		cfg: pluginConfig{
			proxyHost:      "127.0.0.1",
			proxyPort:      "8080",
			proxyHTTPSPort: "8443",
			dnsServers:     []string{"10.96.0.10"},
			caCertPath:     "/etc/service-portal/ca/tls.crt",
		},
		pods: make(map[string]podNetworkState),
	}

	t.Run("opted-in pod with unknown runtime class fails RunPodSandbox", func(t *testing.T) {
		pod := &api.PodSandbox{
			Id:        "pod-unknown-1",
			Namespace: "default",
			Name:      "pod-unknown",
			Labels: map[string]string{
				"service-portal.gke.io/intercept": "true",
			},
			RuntimeHandler: "unknown-sandbox-runtime",
		}
		ctx := t.Context()
		err := p.RunPodSandbox(ctx, pod)
		if err == nil {
			t.Fatalf("expected RunPodSandbox to fail for unknown runtime class, got nil")
		}
		if !strings.Contains(err.Error(), "unsupported runtime class") {
			t.Errorf("expected error message to mention 'unsupported runtime class', got: %v", err)
		}
		if !strings.Contains(err.Error(), "refusing to start unprotected pod") {
			t.Errorf("expected error message to mention 'refusing to start unprotected pod', got: %v", err)
		}
	})

	t.Run("opted-in pod with unknown runtime class fails CreateContainer", func(t *testing.T) {
		ctx := t.Context()
		pod := &api.PodSandbox{
			Id:        "pod-unknown-2",
			Namespace: "default",
			Name:      "pod-unknown-ctr",
			Labels: map[string]string{
				"service-portal.gke.io/intercept": "true",
			},
			RuntimeHandler: "unsupported-runtime",
		}
		ctr := &api.Container{Name: "workload"}
		_, _, err := p.CreateContainer(ctx, pod, ctr)
		if err == nil {
			t.Fatalf("expected CreateContainer to fail for unknown runtime class, got nil")
		}
		if !strings.Contains(err.Error(), "unsupported runtime class") {
			t.Errorf("expected error message to mention 'unsupported runtime class', got: %v", err)
		}
	})

	t.Run("non-opted-in pod with unknown runtime class is ignored", func(t *testing.T) {
		ctx := t.Context()
		pod := &api.PodSandbox{
			Id:        "pod-unknown-3",
			Namespace: "default",
			Name:      "pod-unknown-unmatched",
			Labels: map[string]string{
				"app": "unrelated",
			},
			RuntimeHandler: "unknown-runtime",
		}
		if err := p.RunPodSandbox(ctx, pod); err != nil {
			t.Fatalf("expected RunPodSandbox to return nil for non-opted-in pod, got %v", err)
		}
		adj, updates, err := p.CreateContainer(ctx, pod, &api.Container{Name: "workload"})
		if err != nil || adj != nil || updates != nil {
			t.Fatalf("expected CreateContainer to return nil for non-opted-in pod, got adj=%v updates=%v err=%v", adj, updates, err)
		}
	})
}

func TestBuildHostIptablesRules(t *testing.T) {
	hostIface := "veth12345"
	proxyHost := "192.168.1.10"
	proxyPort := "8080"
	proxyHTTPSPort := "8443"
	dnsServers := []string{"10.96.0.10", "10.96.0.11"}

	rules := buildHostIptablesRules(hostIface, proxyHost, proxyPort, proxyHTTPSPort, dnsServers)

	// Verify required chains and jumps
	prChain := "PORTAL_PR_" + hostIface
	egChain := "PORTAL_EG_" + hostIface

	hasPrJump := false
	hasInputJump := false
	hasForwardJump := false
	hasDNAT80 := false
	hasDNAT443 := false
	hasDNS1 := false
	hasDNS2 := false
	hasReject := false

	for _, r := range rules {
		ruleStr := strings.Join(r, " ")
		if strings.Contains(ruleStr, "PREROUTING 1 -i "+hostIface+" -j "+prChain) {
			hasPrJump = true
		}
		if strings.Contains(ruleStr, "INPUT 1 -i "+hostIface+" -j "+egChain) {
			hasInputJump = true
		}
		if strings.Contains(ruleStr, "FORWARD 1 -i "+hostIface+" -j "+egChain) {
			hasForwardJump = true
		}
		if strings.Contains(ruleStr, "--dport 80 -j DNAT --to-destination 192.168.1.10:8080") {
			hasDNAT80 = true
		}
		if strings.Contains(ruleStr, "--dport 443 -j DNAT --to-destination 192.168.1.10:8443") {
			hasDNAT443 = true
		}
		if strings.Contains(ruleStr, "-d 10.96.0.10 -p udp --dport 53 -j ACCEPT") {
			hasDNS1 = true
		}
		if strings.Contains(ruleStr, "-d 10.96.0.11 -p tcp --dport 53 -j ACCEPT") {
			hasDNS2 = true
		}
		if strings.Contains(ruleStr, "-j REJECT --reject-with icmp-port-unreachable") {
			hasReject = true
		}
	}

	if !hasPrJump {
		t.Errorf("missing PREROUTING jump to %s", prChain)
	}
	if !hasInputJump {
		t.Errorf("missing INPUT jump to %s", egChain)
	}
	if !hasForwardJump {
		t.Errorf("missing FORWARD jump to %s", egChain)
	}
	if !hasDNAT80 {
		t.Errorf("missing DNAT rule for port 80")
	}
	if !hasDNAT443 {
		t.Errorf("missing DNAT rule for port 443")
	}
	if !hasDNS1 {
		t.Errorf("missing DNS rule for 10.96.0.10")
	}
	if !hasDNS2 {
		t.Errorf("missing DNS rule for 10.96.0.11")
	}
	if !hasReject {
		t.Errorf("missing default-deny REJECT rule")
	}
}

func TestBuildHostCleanupRules(t *testing.T) {
	hostIface := "vethtest"
	rules := buildHostCleanupRules(hostIface)

	prChain := "PORTAL_PR_" + hostIface
	egChain := "PORTAL_EG_" + hostIface

	expectedRules := []string{
		"-t nat -D PREROUTING -i " + hostIface + " -j " + prChain,
		"-t nat -F " + prChain,
		"-t nat -X " + prChain,
		"-t filter -D INPUT -i " + hostIface + " -j " + egChain,
		"-t filter -D FORWARD -i " + hostIface + " -j " + egChain,
		"-t filter -F " + egChain,
		"-t filter -X " + egChain,
	}

	if len(rules) != len(expectedRules) {
		t.Fatalf("expected %d cleanup rules, got %d", len(expectedRules), len(rules))
	}

	for i, expected := range expectedRules {
		got := strings.Join(rules[i], " ")
		if got != expected {
			t.Errorf("rule %d mismatch: got %q, expected %q", i, got, expected)
		}
	}
}

func TestPodCleanupIdempotent(t *testing.T) {
	var executedRules [][]string
	p := &portalPlugin{
		pods: map[string]podNetworkState{
			"pod-1": {
				hostInterface: "vethnonexistent",
				podIP:         "10.244.0.99",
				runtimeClass:  "runc",
			},
		},
		runIptables: func(rules [][]string) error {
			executedRules = append(executedRules, rules...)
			return nil
		},
	}

	pod := &api.PodSandbox{
		Id:        "pod-1",
		Namespace: "default",
		Name:      "test-pod",
		Labels: map[string]string{
			"service-portal.gke.io/intercept": "true",
		},
	}

	ctx := t.Context()

	// First cleanup removes from map and executes cleanup rules
	if err := p.StopPodSandbox(ctx, pod); err != nil {
		t.Fatalf("first StopPodSandbox failed: %v", err)
	}

	p.mu.Lock()
	_, found := p.pods["pod-1"]
	p.mu.Unlock()
	if found {
		t.Fatalf("expected pod-1 to be removed from map after StopPodSandbox")
	}

	// Second cleanup (RemovePodSandbox) is a safe no-op
	if err := p.RemovePodSandbox(ctx, pod); err != nil {
		t.Fatalf("second RemovePodSandbox failed: %v", err)
	}
}

func TestNotifyPodUpdate(t *testing.T) {
	var receivedMethod, receivedPath string
	var receivedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedMethod = r.Method
		receivedPath = r.URL.Path
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	p := &portalPlugin{
		cfg: pluginConfig{
			adminURL: server.URL,
		},
		pods:       make(map[string]podNetworkState),
		activePods: make(map[string]portals.PodInfo),
	}

	ctx := t.Context()
	info := portals.PodInfo{
		UID:       "test-uid",
		Namespace: "default",
		Name:      "test-pod",
		IPs:       []string{"10.244.0.5"},
	}

	if err := p.notifyPodUpdate(ctx, http.MethodPost, "/api/v1/pods", info); err != nil {
		t.Fatalf("notifyPodUpdate failed: %v", err)
	}

	if receivedMethod != http.MethodPost || receivedPath != "/api/v1/pods" {
		t.Errorf("unexpected method %s or path %s", receivedMethod, receivedPath)
	}
	var decoded portals.PodInfo
	if err := json.Unmarshal(receivedBody, &decoded); err != nil || decoded.UID != "test-uid" {
		t.Errorf("unexpected payload: %s", string(receivedBody))
	}

	// Test non-2xx status code returns error
	errorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal failure", http.StatusInternalServerError)
	}))
	defer errorServer.Close()
	p.cfg.adminURL = errorServer.URL
	if err := p.notifyPodUpdate(ctx, http.MethodPost, "/api/v1/pods", info); err == nil {
		t.Errorf("expected notifyPodUpdate to fail when admin server returns 500, got nil")
	}

	// Test Unix domain socket
	sockDir := t.TempDir()
	sockPath := filepath.Join(sockDir, "test.sock")
	l, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("failed to listen on unix socket: %v", err)
	}
	defer l.Close()
	udsServer := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	}
	go func() { _ = udsServer.Serve(l) }()
	defer udsServer.Close()

	p.cfg.adminURL = "unix://" + sockPath
	if err := p.notifyPodUpdate(ctx, http.MethodPost, "/api/v1/pods", info); err != nil {
		t.Errorf("expected notifyPodUpdate over UDS to succeed, got %v", err)
	}
}
