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
	"runtime"
	"strings"
	"testing"

	"github.com/containerd/nri/pkg/api"
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
