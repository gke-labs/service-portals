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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/containernetworking/cni/pkg/skel"
)

func TestParseConf(t *testing.T) {
	raw := []byte(`{
		"cniVersion": "0.4.0",
		"name": "kindnet",
		"type": "service-portal-cni",
		"proxyPort": 9080,
		"proxyHttpsPort": 9443,
		"interceptPorts": "80,443,8080",
		"gatewayIP": "10.244.0.1",
		"clusterDNS": "10.96.0.10"
	}`)

	conf, err := parseConf(raw)
	if err != nil {
		t.Fatalf("parseConf failed: %v", err)
	}

	if conf.ProxyPort != 9080 {
		t.Errorf("expected ProxyPort 9080, got %d", conf.ProxyPort)
	}
	if conf.ProxyHTTPSPort != 9443 {
		t.Errorf("expected ProxyHTTPSPort 9443, got %d", conf.ProxyHTTPSPort)
	}
	if conf.InterceptPorts != "80,443,8080" {
		t.Errorf("expected InterceptPorts '80,443,8080', got %q", conf.InterceptPorts)
	}
	if conf.GatewayIP != "10.244.0.1" {
		t.Errorf("expected GatewayIP '10.244.0.1', got %q", conf.GatewayIP)
	}
	if conf.ClusterDNS != "10.96.0.10" {
		t.Errorf("expected ClusterDNS '10.96.0.10', got %q", conf.ClusterDNS)
	}
	if conf.OptInLabel != "portals.gke.io/intercept" {
		t.Errorf("expected default OptInLabel 'portals.gke.io/intercept', got %q", conf.OptInLabel)
	}
}

func TestParseCNIArgs(t *testing.T) {
	tests := []struct {
		argsStr string
		wantNS  string
		wantPod string
	}{
		{
			argsStr: "Ignore=foo;K8S_POD_NAMESPACE=default;K8S_POD_NAME=my-pod;K8S_POD_INFRA_CONTAINER_ID=123",
			wantNS:  "default",
			wantPod: "my-pod",
		},
		{
			argsStr: "K8S_POD_NAME=test-pod;K8S_POD_NAMESPACE=kube-system",
			wantNS:  "kube-system",
			wantPod: "test-pod",
		},
		{
			argsStr: "OTHER_ARG=val",
			wantNS:  "",
			wantPod: "",
		},
	}

	for _, tc := range tests {
		ns, pod := parseCNIArgs(tc.argsStr)
		if ns != tc.wantNS || pod != tc.wantPod {
			t.Errorf("parseCNIArgs(%q) = (%q, %q); want (%q, %q)", tc.argsStr, ns, pod, tc.wantNS, tc.wantPod)
		}
	}
}

func TestCmdDelAndCheck(t *testing.T) {
	args := &skel.CmdArgs{
		ContainerID: "12345",
		Netns:       "/proc/1/ns/net",
		IfName:      "eth0",
	}

	if err := cmdDel(args); err != nil {
		t.Errorf("cmdDel failed: %v", err)
	}
	if err := cmdCheck(args); err != nil {
		t.Errorf("cmdCheck failed: %v", err)
	}
}

func TestIsPodSelected(t *testing.T) {
	// Mock Kube API server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/namespaces/default/pods/intercepted-pod":
			pod := PodMetadata{}
			pod.Metadata.Name = "intercepted-pod"
			pod.Metadata.Namespace = "default"
			pod.Metadata.Labels = map[string]string{
				"portals.gke.io/intercept": "true",
			}
			_ = json.NewEncoder(w).Encode(pod)
		case "/api/v1/namespaces/default/pods/annotated-pod":
			pod := PodMetadata{}
			pod.Metadata.Name = "annotated-pod"
			pod.Metadata.Namespace = "default"
			pod.Metadata.Annotations = map[string]string{
				"portals.gke.io/policy": "my-policy",
			}
			_ = json.NewEncoder(w).Encode(pod)
		case "/api/v1/namespaces/default/pods/unselected-pod":
			pod := PodMetadata{}
			pod.Metadata.Name = "unselected-pod"
			pod.Metadata.Namespace = "default"
			pod.Metadata.Labels = map[string]string{
				"app": "unrelated",
			}
			_ = json.NewEncoder(w).Encode(pod)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	// Write mock kubeconfig
	tmpDir := t.TempDir()
	kcPath := filepath.Join(tmpDir, "test.kubeconfig")
	kcContent := `
apiVersion: v1
clusters:
- cluster:
    server: ` + server.URL + `
    insecure-skip-tls-verify: true
  name: test-cluster
contexts:
- context:
    cluster: test-cluster
    user: test-user
  name: test-context
current-context: test-context
users:
- name: test-user
  user:
    token: test-token
`
	if err := os.WriteFile(kcPath, []byte(kcContent), 0600); err != nil {
		t.Fatalf("failed to write kubeconfig: %v", err)
	}

	conf := &PluginConf{
		OptInLabel: "portals.gke.io/intercept",
		OptInValue: "true",
		Kubeconfig: kcPath,
	}

	// 1. Intercepted pod via label
	sel, err := isPodSelected(conf, "default", "intercepted-pod")
	if err != nil {
		t.Fatalf("isPodSelected error: %v", err)
	}
	if !sel {
		t.Errorf("expected intercepted-pod to be selected")
	}

	// 2. Intercepted pod via annotation
	sel, err = isPodSelected(conf, "default", "annotated-pod")
	if err != nil {
		t.Fatalf("isPodSelected error: %v", err)
	}
	if !sel {
		t.Errorf("expected annotated-pod to be selected")
	}

	// 3. Unselected pod
	sel, err = isPodSelected(conf, "default", "unselected-pod")
	if err != nil {
		t.Fatalf("isPodSelected error: %v", err)
	}
	if sel {
		t.Errorf("expected unselected-pod to NOT be selected")
	}

	// 4. Missing pod (404)
	_, err = isPodSelected(conf, "default", "non-existent")
	if err == nil {
		t.Errorf("expected error for non-existent pod, got nil")
	}
}
