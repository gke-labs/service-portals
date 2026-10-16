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

package e2e

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

type Harness struct {
	ClusterName string
	IPFamily    string // "ipv4" or "dual"
	t           *testing.T
}

func NewHarness(t *testing.T, clusterName string) *Harness {
	ipFamily := strings.ToLower(strings.TrimSpace(os.Getenv("E2E_IP_FAMILY")))
	if ipFamily == "" {
		ipFamily = "ipv4"
	}
	return &Harness{
		ClusterName: clusterName,
		IPFamily:    ipFamily,
		t:           t,
	}
}

func (h *Harness) IsDualStack() bool {
	return h.IPFamily == "dual"
}

func (h *Harness) Setup() {
	h.t.Helper()
	// Check if cluster exists
	cmd := exec.Command("kind", "get", "clusters")
	out, err := cmd.Output()
	if err == nil && strings.Contains(string(out), h.ClusterName) {
		// Check whether existing cluster has matching IP family
		cmdCheck := exec.Command("kubectl", "get", "nodes", "-o", "jsonpath={.items[0].spec.podCIDRs}")
		outCheck, errCheck := cmdCheck.Output()
		isClusterDual := errCheck == nil && strings.Contains(string(outCheck), ":")
		if (h.IPFamily == "dual" && isClusterDual) || (h.IPFamily != "dual" && !isClusterDual) {
			h.t.Logf("Cluster %s already exists with matching IP family (%s)", h.ClusterName, h.IPFamily)
			return
		}
		h.t.Logf("Cluster %s exists but IP family does not match %s; recreating", h.ClusterName, h.IPFamily)
		h.Teardown()
	}

	h.t.Logf("Creating cluster %s (IPFamily: %s)", h.ClusterName, h.IPFamily)
	var configArgs []string
	if h.IPFamily == "dual" {
		tmpConfig, err := os.CreateTemp("", "kind-dual-*.yaml")
		if err != nil {
			h.t.Fatalf("Failed to create temporary kind config: %v", err)
		}
		defer os.Remove(tmpConfig.Name())

		kindConfig := `kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  ipFamily: dual
`
		if _, err := tmpConfig.WriteString(kindConfig); err != nil {
			h.t.Fatalf("Failed to write temporary kind config: %v", err)
		}
		if err := tmpConfig.Close(); err != nil {
			h.t.Fatalf("Failed to close temporary kind config: %v", err)
		}
		configArgs = []string{"--config", tmpConfig.Name()}
	}

	createArgs := append([]string{"create", "cluster", "--name", h.ClusterName}, configArgs...)
	cmd = exec.Command("kind", createArgs...)
	if out, err := cmd.CombinedOutput(); err != nil {
		h.t.Fatalf("Failed to create cluster: %v\nOutput: %s", err, out)
	}

	h.t.Cleanup(func() {
		h.Teardown()
	})
}

func (h *Harness) Teardown() {
	h.t.Helper()
	h.t.Logf("Deleting cluster %s", h.ClusterName)
	cmd := exec.Command("kind", "delete", "cluster", "--name", h.ClusterName)
	if out, err := cmd.CombinedOutput(); err != nil {
		h.t.Logf("Failed to delete cluster: %v\nOutput: %s", err, out)
	}
}

func (h *Harness) GetGitRoot() string {
	h.t.Helper()
	cmd := exec.Command("git", "rev-parse", "--show-toplevel")
	out, err := cmd.Output()
	if err != nil {
		h.t.Fatalf("Failed to find git root: %v", err)
	}
	return strings.TrimSpace(string(out))
}

func (h *Harness) RunCommand(name string, args ...string) {
	h.t.Helper()
	cmd := exec.Command(name, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		h.t.Fatalf("Command failed: %s %v\nOutput: %s", name, args, out)
	}
}

func (h *Harness) DockerBuild(tag, dockerfile, context string) {
	h.t.Helper()
	h.t.Logf("Building docker image %s", tag)
	h.RunCommand("docker", "build", "-t", tag, "-f", dockerfile, context)
}

func (h *Harness) KindLoad(tag string) {
	h.t.Helper()
	h.t.Logf("Loading image %s into kind", tag)
	h.RunCommand("kind", "load", "docker-image", tag, "--name", h.ClusterName)
}

func (h *Harness) KubectlApplyContent(content string) {
	h.t.Helper()
	h.t.Logf("Applying manifest content")
	cmd := exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = bytes.NewBufferString(content)
	if out, err := cmd.CombinedOutput(); err != nil {
		h.t.Fatalf("Failed to apply content: %v\nOutput: %s", err, out)
	}
}

func (h *Harness) WaitForDeployment(name string, timeout time.Duration) {
	h.t.Helper()
	h.t.Logf("Waiting for deployment %s", name)
	h.RunCommand("kubectl", "rollout", "status", "deployment/"+name, "--timeout="+timeout.String())
}

func (h *Harness) WaitForPodReady(labelSelector string, timeout time.Duration) {
	h.t.Helper()
	h.t.Logf("Waiting for pod with label %s to be ready", labelSelector)
	h.RunCommand("kubectl", "wait", "--for=condition=ready", "pod", "-l", labelSelector, "-A", "--timeout="+timeout.String())
}

func (h *Harness) DeletePod(name string) {
	h.t.Helper()
	// Ignore errors if pod doesn't exist
	if err := exec.Command("kubectl", "delete", "pod", name, "--ignore-not-found").Run(); err != nil {
		h.t.Logf("Failed to delete pod %s: %v", name, err)
	}
}

func (h *Harness) GetPodLogs(name string) string {
	h.t.Helper()
	out, err := exec.Command("kubectl", "logs", name).CombinedOutput()
	if err != nil {
		h.t.Fatalf("Failed to get logs for pod %s: %v", name, err)
	}
	return string(out)
}

func (h *Harness) WaitForPodSuccess(name string, timeout time.Duration) {
	h.t.Helper()
	h.t.Logf("Waiting for pod %s to succeed", name)
	start := time.Now()
	for {
		if time.Since(start) > timeout {
			h.t.Fatalf("Timed out waiting for pod %s to succeed", name)
		}
		cmd := exec.Command("kubectl", "get", "pod", name, "-o", "jsonpath={.status.phase}")
		out, err := cmd.Output()
		if err != nil {
			// Might not be created yet, ignore error
			time.Sleep(2 * time.Second)
			continue
		}
		status := string(out)
		if status == "Succeeded" {
			return
		}
		if status == "Failed" {
			h.t.Fatalf("Pod %s failed", name)
		}
		time.Sleep(2 * time.Second)
	}
}

func (h *Harness) GetServiceClusterIP(name string) string {
	h.t.Helper()
	cmd := exec.Command("kubectl", "get", "service", name, "-o", "jsonpath={.spec.clusterIP}")
	out, err := cmd.CombinedOutput()
	if err != nil {
		h.t.Fatalf("Failed to get ClusterIP for service %s: %v\nOutput: %s", name, err, out)
	}
	return strings.TrimSpace(string(out))
}

func (h *Harness) GetServiceClusterIPs(name string) []string {
	h.t.Helper()
	cmd := exec.Command("kubectl", "get", "service", name, "-o", "jsonpath={.spec.clusterIPs[*]}")
	out, err := cmd.CombinedOutput()
	if err != nil {
		h.t.Fatalf("Failed to get ClusterIPs for service %s: %v\nOutput: %s", name, err, out)
	}
	return strings.Fields(strings.TrimSpace(string(out)))
}

func (h *Harness) GetServiceIPv6ClusterIP(name string) string {
	h.t.Helper()
	ips := h.GetServiceClusterIPs(name)
	for _, ip := range ips {
		if strings.Contains(ip, ":") {
			return ip
		}
	}
	return ""
}

func (h *Harness) GetDeploymentLogs(name string) string {
	h.t.Helper()
	cmd := exec.Command("kubectl", "logs", "deployment/"+name)
	out, err := cmd.CombinedOutput()
	if err != nil {
		h.t.Fatalf("Failed to get logs for deployment %s: %v\nOutput: %s", name, err, out)
	}
	return string(out)
}
