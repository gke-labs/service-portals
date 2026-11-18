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
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	portalsv1 "github.com/gke-labs/service-portals/pkg/portals/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestServicePortal(t *testing.T) {
	if os.Getenv("RUN_E2E") == "" {
		t.Skip("RUN_E2E env var not set, skipping")
	}

	h := NewHarness(t, "service-portal-e2e")
	if h.IsGVisor() {
		t.Skip("skipping non-NRI test when running under gVisor runtime")
	}
	h.Setup()

	gitRoot := h.GetGitRoot()

	// Paths relative to git root
	h.DockerBuild("service-portal:e2e", filepath.Join(gitRoot, "images/service-portal/Dockerfile"), gitRoot)
	h.DockerBuild("toolbox:e2e", filepath.Join(gitRoot, "tests/toolbox/Dockerfile"), filepath.Join(gitRoot, "tests/toolbox"))

	h.KindLoad("service-portal:e2e")
	h.KindLoad("toolbox:e2e")

	// Deploy Backend (Toolbox Server)
	backendManifest := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: backend
  labels:
    app: backend
spec:
  replicas: 1
  selector:
    matchLabels:
      app: backend
  template:
    metadata:
      labels:
        app: backend
    spec:
      containers:
      - name: toolbox
        image: toolbox:e2e
        imagePullPolicy: Never
        args: ["server"]
        ports:
        - containerPort: 8080
---
apiVersion: v1
kind: Service
metadata:
  name: backend
spec:
  selector:
    app: backend
  ports:
  - port: 80
    targetPort: 8080
`
	h.KubectlApplyContent(backendManifest)
	h.WaitForDeployment("backend", 2*time.Minute)
	// TODO: Add health/readiness checks for services and deployments to avoid timing issues.
	time.Sleep(5 * time.Second)

	// Deploy Service Portal
	h.KubectlApplyContent(`
apiVersion: v1
kind: Secret
metadata:
  name: service-portal-secret
stringData:
  token: e2e-secret-token
`)

	portalManifestPath := filepath.Join(gitRoot, "k8s/manifests.yaml")
	b, err := os.ReadFile(portalManifestPath)
	if err != nil {
		t.Fatalf("Failed to read portal manifest: %v", err)
	}
	portalManifest := string(b)
	portalManifest = strings.ReplaceAll(portalManifest, "image: service-portal:latest", "image: service-portal:e2e\n        imagePullPolicy: Never")
	portalManifest = strings.ReplaceAll(portalManifest, "value: \"https://generativelanguage.googleapis.com\"", "value: \"http://backend\"")

	// Install cert-manager
	h.t.Log("Installing cert-manager")
	h.RunCommand("kubectl", "apply", "--server-side", "-f", "https://github.com/cert-manager/cert-manager/releases/download/v1.19.2/cert-manager.yaml")
	// Wait for cert-manager pods to be created
	time.Sleep(10 * time.Second)
	// Wait for cert-manager pods to be ready
	h.WaitForPodReady("app.kubernetes.io/instance=cert-manager", 3*time.Minute)

	h.KubectlApplyContent(portalManifest)
	h.WaitForDeployment("service-portal", 2*time.Minute)

	// Wait for CA secret to be created by cert-manager
	h.t.Log("Waiting for CA secret")
	for i := 0; i < 30; i++ {
		cmd := exec.Command("kubectl", "get", "secret", "service-portal-ca")
		if err := cmd.Run(); err == nil {
			break
		}
		if i == 29 {
			t.Fatal("Timed out waiting for service-portal-ca secret")
		}
		time.Sleep(2 * time.Second)
	}

	// Restart service-portal to ensure it picks up the CA secret (it might have started before the secret was created)
	h.RunCommand("kubectl", "rollout", "restart", "deployment/service-portal")
	h.WaitForDeployment("service-portal", 2*time.Minute)
	// TODO: Add health/readiness checks for services and deployments to avoid timing issues.
	time.Sleep(5 * time.Second)

	// Run Client
	clientPodName := "test-client"
	h.DeletePod(clientPodName)

	clientManifest := `
apiVersion: v1
kind: Pod
metadata:
  name: test-client
  labels:
    app: test-client
spec:
  containers:
  - name: toolbox
    image: toolbox:e2e
    imagePullPolicy: Never
    command: ["/app/toolbox", "client", "http://service-portal/"]
  restartPolicy: Never
`
	h.KubectlApplyContent(clientManifest)

	h.WaitForPodSuccess(clientPodName, 1*time.Minute)

	logs := h.GetPodLogs(clientPodName)
	t.Logf("Client logs: %s", logs)

	// Verify
	if !strings.Contains(logs, "Authorization") {
		t.Error("Logs do not contain Authorization header")
	}
	if !strings.Contains(logs, "Bearer e2e-secret-token") {
		t.Error("Logs do not contain correct token")
	}
}

func TestServicePortalAgent(t *testing.T) {
	if os.Getenv("RUN_E2E") == "" {
		t.Skip("RUN_E2E env var not set, skipping")
	}

	h := NewHarness(t, "service-portal-agent-e2e")
	if h.IsGVisor() {
		t.Skip("skipping non-NRI test when running under gVisor runtime")
	}
	h.Setup()

	gitRoot := h.GetGitRoot()

	// Paths relative to git root
	h.DockerBuild("service-portal-agent:e2e", filepath.Join(gitRoot, "images/service-portal-agent/Dockerfile"), gitRoot)
	h.DockerBuild("toolbox:e2e", filepath.Join(gitRoot, "tests/toolbox/Dockerfile"), filepath.Join(gitRoot, "tests/toolbox"))

	h.KindLoad("service-portal-agent:e2e")
	h.KindLoad("toolbox:e2e")

	// Deploy Backend (Toolbox Server)
	backendManifest := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: backend
  labels:
    app: backend
spec:
  replicas: 1
  selector:
    matchLabels:
      app: backend
  template:
    metadata:
      labels:
        app: backend
    spec:
      containers:
      - name: toolbox
        image: toolbox:e2e
        imagePullPolicy: Never
        args: ["server"]
        ports:
        - containerPort: 8080
---
apiVersion: v1
kind: Service
metadata:
  name: backend
spec:
  selector:
    app: backend
  ports:
  - port: 80
    targetPort: 8080
`
	h.KubectlApplyContent(backendManifest)
	h.WaitForDeployment("backend", 2*time.Minute)
	// TODO: Add health/readiness checks for services and deployments to avoid timing issues.
	time.Sleep(5 * time.Second)

	// Deploy Service Portal Agent
	h.KubectlApplyContent(`
apiVersion: v1
kind: Secret
metadata:
  name: service-portal-agent-secret
stringData:
  gemini-rule.yaml: |
    apiVersion: portals.gke.io/v1alpha1
    kind: PortalRule
    metadata:
      name: gemini
    spec:
      host: gemini.backend
      rewriteUrl: http://backend
      authToken: gemini-e2e-token
  github-rule.yaml: |
    apiVersion: portals.gke.io/v1alpha1
    kind: PortalRule
    metadata:
      name: github
    spec:
      host: github.backend
      rewriteUrl: http://backend
      authToken: github-e2e-token
`)

	portalManifest := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: service-portal-agent
  labels:
    app: service-portal-agent
spec:
  replicas: 1
  selector:
    matchLabels:
      app: service-portal-agent
  template:
    metadata:
      labels:
        app: service-portal-agent
    spec:
      containers:
      - name: service-portal-agent
        image: service-portal-agent:e2e
        imagePullPolicy: Never
        ports:
        - containerPort: 8080
        args: ["--rules-dir=/etc/portals"]
        volumeMounts:
        - name: rules-volume
          mountPath: /etc/portals
          readOnly: true
      volumes:
      - name: rules-volume
        secret:
          secretName: service-portal-agent-secret
---
apiVersion: v1
kind: Service
metadata:
  name: service-portal-agent
spec:
  selector:
    app: service-portal-agent
  ports:
  - port: 80
    targetPort: 8080
    protocol: TCP
`
	h.KubectlApplyContent(portalManifest)
	h.WaitForDeployment("service-portal-agent", 2*time.Minute)
	// TODO: Add health/readiness checks for services and deployments to avoid timing issues.
	time.Sleep(5 * time.Second)

	// Run Client 1: Gemini
	clientPodNameGemini := "test-client-gemini"
	h.DeletePod(clientPodNameGemini)

	clientManifestGemini := `
apiVersion: v1
kind: Pod
metadata:
  name: test-client-gemini
  labels:
    app: test-client-gemini
spec:
  containers:
  - name: toolbox
    image: toolbox:e2e
    imagePullPolicy: Never
    command: ["/bin/sh", "-c", "wget -qO- --header='Host: gemini.backend' http://service-portal-agent:80"]
  restartPolicy: Never
`
	h.KubectlApplyContent(clientManifestGemini)
	h.WaitForPodSuccess(clientPodNameGemini, 1*time.Minute)

	logsGemini := h.GetPodLogs(clientPodNameGemini)
	t.Logf("Gemini Client logs: %s", logsGemini)

	// Verify
	if !strings.Contains(logsGemini, "Authorization") {
		t.Error("Gemini Logs do not contain Authorization header")
	}
	if !strings.Contains(logsGemini, "Bearer gemini-e2e-token") {
		t.Error("Gemini Logs do not contain correct token")
	}

	// Run Client 2: GitHub
	clientPodNameGithub := "test-client-github"
	h.DeletePod(clientPodNameGithub)

	clientManifestGithub := `
apiVersion: v1
kind: Pod
metadata:
  name: test-client-github
  labels:
    app: test-client-github
spec:
  containers:
  - name: toolbox
    image: toolbox:e2e
    imagePullPolicy: Never
    command: ["/bin/sh", "-c", "wget -qO- --header='Host: github.backend' http://service-portal-agent:80"]
  restartPolicy: Never
`
	h.KubectlApplyContent(clientManifestGithub)
	h.WaitForPodSuccess(clientPodNameGithub, 1*time.Minute)

	logsGithub := h.GetPodLogs(clientPodNameGithub)
	t.Logf("Github Client logs: %s", logsGithub)

	// Verify
	if !strings.Contains(logsGithub, "Authorization") {
		t.Error("Github Logs do not contain Authorization header")
	}
	if !strings.Contains(logsGithub, "Bearer github-e2e-token") {
		t.Error("Github Logs do not contain correct token")
	}
}

func TestSidecarPortal(t *testing.T) {
	if os.Getenv("RUN_E2E") == "" {
		t.Skip("RUN_E2E env var not set, skipping")
	}

	h := NewHarness(t, "sidecar-portal-e2e")
	if h.IsGVisor() {
		t.Skip("skipping non-NRI test when running under gVisor runtime")
	}
	h.Setup()

	gitRoot := h.GetGitRoot()

	// Paths relative to git root
	h.DockerBuild("service-portal-agent:e2e", filepath.Join(gitRoot, "images/service-portal-agent/Dockerfile"), gitRoot)
	h.DockerBuild("init-service-portals:e2e", filepath.Join(gitRoot, "images/init-service-portals/Dockerfile"), gitRoot)
	h.DockerBuild("toolbox:e2e", filepath.Join(gitRoot, "tests/toolbox/Dockerfile"), filepath.Join(gitRoot, "tests/toolbox"))

	h.KindLoad("service-portal-agent:e2e")
	h.KindLoad("init-service-portals:e2e")
	h.KindLoad("toolbox:e2e")

	// Deploy Backend (Toolbox Server)
	backendManifest := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: backend
  labels:
    app: backend
spec:
  replicas: 1
  selector:
    matchLabels:
      app: backend
  template:
    metadata:
      labels:
        app: backend
    spec:
      containers:
      - name: toolbox
        image: toolbox:e2e
        imagePullPolicy: Never
        args: ["server"]
        ports:
        - containerPort: 8080
---
apiVersion: v1
kind: Service
metadata:
  name: backend
spec:
  selector:
    app: backend
  ports:
  - port: 80
    targetPort: 8080
`
	h.KubectlApplyContent(backendManifest)
	h.WaitForDeployment("backend", 2*time.Minute)
	// TODO: Add health/readiness checks for services and deployments to avoid timing issues.
	time.Sleep(5 * time.Second)

	// Deploy Client Pod with Sidecar
	clientPodName := "test-client-sidecar"
	h.DeletePod(clientPodName)

	clientManifest := `
apiVersion: v1
kind: Secret
metadata:
  name: sidecar-portal-rules-secret
stringData:
  gemini-rule.yaml: |
    apiVersion: portals.gke.io/v1alpha1
    kind: PortalRule
    metadata:
      name: gemini
    spec:
      host: gemini.backend
      rewriteUrl: http://backend
      authToken: gemini-sidecar-token
  github-rule.yaml: |
    apiVersion: portals.gke.io/v1alpha1
    kind: PortalRule
    metadata:
      name: github
    spec:
      host: github.backend
      rewriteUrl: http://backend
      authToken: github-sidecar-token
---
apiVersion: v1
kind: Pod
metadata:
  name: test-client-sidecar
  labels:
    app: test-client-sidecar
spec:
  hostAliases:
  - ip: "8.8.8.8"
    hostnames:
    - "gemini.backend"
    - "github.backend"
  initContainers:
  - name: init-service-portals
    image: init-service-portals:e2e
    imagePullPolicy: Never
    env:
    - name: PROXY_PORT
      value: "8080"
    - name: PROXY_HTTPS_PORT
      value: "8443"
    - name: PROXY_UID
      value: "1337"
    - name: INTERCEPT_PORTS
      value: "80,443"
    - name: CHOWN_UID
      value: "1337"
    - name: CHOWN_GID
      value: "1337"
    securityContext:
      capabilities:
        add: ["NET_ADMIN"]
      runAsUser: 0
    volumeMounts:
    - name: ca-cert
      mountPath: /etc/service-portal/ca
    - name: ca-key
      mountPath: /etc/service-portal/ca-private
  containers:
  - name: workload
    image: toolbox:e2e
    imagePullPolicy: Never
    securityContext:
      runAsUser: 1000
      allowPrivilegeEscalation: false
    command: ["/bin/sh", "-c", "sleep 3600"]
    volumeMounts:
    - name: ca-cert
      mountPath: /etc/service-portal/ca
      readOnly: true
  - name: service-portal-sidecar
    image: service-portal-agent:e2e
    imagePullPolicy: Never
    securityContext:
      runAsUser: 1337
      runAsGroup: 1337
    env:
    - name: CA_CERT_PATH
      value: "/etc/service-portal/ca-private/tls.crt"
    - name: CA_KEY_PATH
      value: "/etc/service-portal/ca-private/tls.key"
    args: ["--rules-dir=/etc/portals"]
    volumeMounts:
    - name: rules-volume
      mountPath: /etc/portals
      readOnly: true
    - name: ca-key
      mountPath: /etc/service-portal/ca-private
      readOnly: true
  volumes:
  - name: rules-volume
    secret:
      secretName: sidecar-portal-rules-secret
  - name: ca-cert
    emptyDir: {}
  - name: ca-key
    emptyDir: {}
`
	h.KubectlApplyContent(clientManifest)
	h.WaitForPodReady("app=test-client-sidecar", 2*time.Minute)

	// Test Gemini request via sidecar transparent proxying
	cmdGemini := exec.Command("kubectl", "exec", clientPodName, "-c", "workload", "--", "wget", "-qO-", "http://gemini.backend")
	outGemini, err := cmdGemini.CombinedOutput()
	if err != nil {
		t.Fatalf("Gemini request failed: %v. Output: %s", err, outGemini)
	}
	logsGemini := string(outGemini)
	t.Logf("Gemini request output: %s", logsGemini)

	if !strings.Contains(logsGemini, "Authorization") {
		t.Error("Gemini Logs do not contain Authorization header")
	}
	if !strings.Contains(logsGemini, "Bearer gemini-sidecar-token") {
		t.Error("Gemini Logs do not contain correct token")
	}

	// Test Gemini HTTPS request via sidecar transparent proxying
	cmdGeminiHTTPS := exec.Command("kubectl", "exec", clientPodName, "-c", "workload", "--", "wget", "--ca-certificate=/etc/service-portal/ca/tls.crt", "-qO-", "https://gemini.backend")
	outGeminiHTTPS, err := cmdGeminiHTTPS.CombinedOutput()
	if err != nil {
		t.Fatalf("Gemini HTTPS request failed: %v. Output: %s", err, outGeminiHTTPS)
	}
	logsGeminiHTTPS := string(outGeminiHTTPS)
	t.Logf("Gemini HTTPS request output: %s", logsGeminiHTTPS)

	if !strings.Contains(logsGeminiHTTPS, "Authorization") {
		t.Error("Gemini HTTPS Logs do not contain Authorization header")
	}
	if !strings.Contains(logsGeminiHTTPS, "Bearer gemini-sidecar-token") {
		t.Error("Gemini HTTPS Logs do not contain correct token")
	}

	// Test GitHub request via sidecar transparent proxying
	cmdGithub := exec.Command("kubectl", "exec", clientPodName, "-c", "workload", "--", "wget", "-qO-", "http://github.backend")
	outGithub, err := cmdGithub.CombinedOutput()
	if err != nil {
		t.Fatalf("GitHub request failed: %v. Output: %s", err, outGithub)
	}
	logsGithub := string(outGithub)
	t.Logf("GitHub request output: %s", logsGithub)

	if !strings.Contains(logsGithub, "Authorization") {
		t.Error("GitHub Logs do not contain Authorization header")
	}
	if !strings.Contains(logsGithub, "Bearer github-sidecar-token") {
		t.Error("GitHub Logs do not contain correct token")
	}

	// Test GitHub HTTPS request via sidecar transparent proxying
	cmdGithubHTTPS := exec.Command("kubectl", "exec", clientPodName, "-c", "workload", "--", "wget", "--ca-certificate=/etc/service-portal/ca/tls.crt", "-qO-", "https://github.backend")
	outGithubHTTPS, err := cmdGithubHTTPS.CombinedOutput()
	if err != nil {
		t.Fatalf("GitHub HTTPS request failed: %v. Output: %s", err, outGithubHTTPS)
	}
	logsGithubHTTPS := string(outGithubHTTPS)
	t.Logf("GitHub HTTPS request output: %s", logsGithubHTTPS)

	if !strings.Contains(logsGithubHTTPS, "Authorization") {
		t.Error("GitHub HTTPS Logs do not contain Authorization header")
	}
	if !strings.Contains(logsGithubHTTPS, "Bearer github-sidecar-token") {
		t.Error("GitHub HTTPS Logs do not contain correct token")
	}
}

func TestSidecarEgressDenied(t *testing.T) {
	if os.Getenv("RUN_E2E") == "" {
		t.Skip("RUN_E2E env var not set, skipping")
	}

	h := NewHarness(t, "sidecar-egress-denied-e2e")
	if h.IsGVisor() {
		t.Skip("skipping non-NRI test when running under gVisor runtime")
	}
	h.Setup()

	gitRoot := h.GetGitRoot()

	// Paths relative to git root
	h.DockerBuild("service-portal-agent:e2e", filepath.Join(gitRoot, "images/service-portal-agent/Dockerfile"), gitRoot)
	h.DockerBuild("init-service-portals:e2e", filepath.Join(gitRoot, "images/init-service-portals/Dockerfile"), gitRoot)
	h.DockerBuild("toolbox:e2e", filepath.Join(gitRoot, "tests/toolbox/Dockerfile"), filepath.Join(gitRoot, "tests/toolbox"))

	h.KindLoad("service-portal-agent:e2e")
	h.KindLoad("init-service-portals:e2e")
	h.KindLoad("toolbox:e2e")

	serviceIPFamilies := ""
	if h.IsDualStack() {
		serviceIPFamilies = `  ipFamilyPolicy: PreferDualStack
  ipFamilies:
  - IPv6
  - IPv4
`
	}

	// Deploy Backend (Toolbox Server with two ports: 80 and 8080)
	backendManifest := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: backend
  labels:
    app: backend
spec:
  replicas: 1
  selector:
    matchLabels:
      app: backend
  template:
    metadata:
      labels:
        app: backend
    spec:
      containers:
      - name: toolbox
        image: toolbox:e2e
        imagePullPolicy: Never
        args: ["server"]
        ports:
        - containerPort: 8080
---
apiVersion: v1
kind: Service
metadata:
  name: backend
spec:
` + serviceIPFamilies + `  selector:
    app: backend
  ports:
  - name: http
    port: 80
    targetPort: 8080
  - name: alt
    port: 8080
    targetPort: 8080
`
	h.KubectlApplyContent(backendManifest)
	h.WaitForDeployment("backend", 2*time.Minute)
	time.Sleep(5 * time.Second)

	backendIPv4ClusterIP := h.GetServiceIPv4ClusterIP("backend")
	if backendIPv4ClusterIP == "" {
		backendIPv4ClusterIP = h.GetServiceClusterIP("backend")
	}
	t.Logf("Backend IPv4 ClusterIP: %s", backendIPv4ClusterIP)
	backendIPv6ClusterIP := h.GetServiceIPv6ClusterIP("backend")
	if h.IsDualStack() {
		t.Logf("Backend IPv6 ClusterIP: %s", backendIPv6ClusterIP)
		if backendIPv6ClusterIP == "" {
			t.Fatalf("Expected IPv6 ClusterIP for backend service on dual-stack cluster, but none found")
		}
	}

	// Deploy Client Pod with Sidecar
	clientPodName := "test-client-sidecar-deny"
	h.DeletePod(clientPodName)

	hostAliasesSection := `  hostAliases:
  - ip: "8.8.8.8"
    hostnames:
    - "gemini.backend"
    - "github.backend"
    - "other.backend"`
	if h.IsDualStack() {
		// On dual-stack, gemini.backend maps to IPv4 dummy address 8.8.8.8 (exercising iptables REDIRECT)
		// while github.backend maps to IPv6 dummy address 2001:db8::1 (exercising ip6tables REDIRECT and :8443 dual-stack listener)
		hostAliasesSection = `  hostAliases:
  - ip: "8.8.8.8"
    hostnames:
    - "gemini.backend"
    - "other.backend"
  - ip: "2001:db8::1"
    hostnames:
    - "github.backend"
    - "other-v6.backend"`
	}

	githubRewriteURL := "http://backend"
	if h.IsDualStack() {
		// On dual-stack, route github.backend upstream directly to backend's IPv6 ClusterIP.
		// This forces the proxy to dial an IPv6 upstream, exercising real IPv6 egress and Neighbour Discovery.
		githubRewriteURL = "http://[" + backendIPv6ClusterIP + "]:80"
	}

	clientManifest := `
apiVersion: v1
kind: Secret
metadata:
  name: sidecar-portal-deny-rules-secret
stringData:
  gemini-rule.yaml: |
    apiVersion: portals.gke.io/v1alpha1
    kind: PortalRule
    metadata:
      name: gemini
    spec:
      host: gemini.backend
      rewriteUrl: http://backend
      authToken: gemini-sidecar-token
  github-rule.yaml: |
    apiVersion: portals.gke.io/v1alpha1
    kind: PortalRule
    metadata:
      name: github
    spec:
      host: github.backend
      rewriteUrl: ` + githubRewriteURL + `
      authToken: github-sidecar-token
---
apiVersion: v1
kind: Pod
metadata:
  name: test-client-sidecar-deny
  labels:
    app: test-client-sidecar-deny
spec:
` + hostAliasesSection + `
  initContainers:
  - name: init-service-portals
    image: init-service-portals:e2e
    imagePullPolicy: Never
    env:
    - name: PROXY_PORT
      value: "8080"
    - name: PROXY_HTTPS_PORT
      value: "8443"
    - name: PROXY_UID
      value: "1337"
    - name: INTERCEPT_PORTS
      value: "80,443"
    - name: CHOWN_UID
      value: "1337"
    - name: CHOWN_GID
      value: "1337"
    securityContext:
      capabilities:
        add: ["NET_ADMIN"]
      runAsUser: 0
    volumeMounts:
    - name: ca-cert
      mountPath: /etc/service-portal/ca
    - name: ca-key
      mountPath: /etc/service-portal/ca-private
  containers:
  - name: workload
    image: toolbox:e2e
    imagePullPolicy: Never
    securityContext:
      runAsUser: 1000
      allowPrivilegeEscalation: false
    command: ["/bin/sh", "-c", "sleep 3600"]
    volumeMounts:
    - name: ca-cert
      mountPath: /etc/service-portal/ca
      readOnly: true
  - name: service-portal-sidecar
    image: service-portal-agent:e2e
    imagePullPolicy: Never
    securityContext:
      runAsUser: 1337
      runAsGroup: 1337
    env:
    - name: CA_CERT_PATH
      value: "/etc/service-portal/ca-private/tls.crt"
    - name: CA_KEY_PATH
      value: "/etc/service-portal/ca-private/tls.key"
    args: ["--rules-dir=/etc/portals"]
    volumeMounts:
    - name: rules-volume
      mountPath: /etc/portals
      readOnly: true
    - name: ca-key
      mountPath: /etc/service-portal/ca-private
      readOnly: true
  volumes:
  - name: rules-volume
    secret:
      secretName: sidecar-portal-deny-rules-secret
  - name: ca-cert
    emptyDir: {}
  - name: ca-key
    emptyDir: {}
`
	h.KubectlApplyContent(clientManifest)
	h.WaitForPodReady("app=test-client-sidecar-deny", 2*time.Minute)

	runEgressDeniedAssertions(t, h, clientPodName, backendIPv4ClusterIP, "gemini.backend", "other.backend")
	runSidecarPositiveControls(t, h, clientPodName, "gemini.backend", "gemini-sidecar-token")
	if h.IsDualStack() {
		runSidecarDualStackAssertions(t, h, clientPodName, backendIPv6ClusterIP)
	}
}

func runEgressDeniedAssertions(t *testing.T, h *Harness, clientPodName, backendIPv4ClusterIP, targetHost, unlistedHost string) {
	// Case 1: Direct IP, intercepted port (must fail and never reach backend)
	t.Run("DirectIP_InterceptedPort_HTTP", func(t *testing.T) {
		cmd := exec.Command("kubectl", "exec", clientPodName, "-c", "workload", "--",
			"wget", "-T", "5", "-qO-", "http://"+backendIPv4ClusterIP+":80/direct-ip-http")
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("expected direct IP HTTP request to fail, but it succeeded: %s", out)
		}
		t.Logf("direct IP HTTP request failed as expected: %v (output: %s)", err, out)

		backendLogs := h.GetDeploymentLogs("backend")
		if strings.Contains(backendLogs, "/direct-ip-http") {
			t.Fatalf("backend access log contains /direct-ip-http, request unexpectedly reached backend")
		}
	})

	t.Run("DirectIP_InterceptedPort_HTTPS", func(t *testing.T) {
		cmd := exec.Command("kubectl", "exec", clientPodName, "-c", "workload", "--",
			"wget", "-T", "5", "--ca-certificate=/etc/service-portal/ca/tls.crt", "-qO-", "https://"+backendIPv4ClusterIP+":443/direct-ip-https")
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("expected direct IP HTTPS request to fail, but it succeeded: %s", out)
		}
		t.Logf("direct IP HTTPS request failed as expected: %v (output: %s)", err, out)

		backendLogs := h.GetDeploymentLogs("backend")
		if strings.Contains(backendLogs, "/direct-ip-https") {
			t.Fatalf("backend access log contains /direct-ip-https, request unexpectedly reached backend")
		}
	})

	// Case 2: Unlisted hostname, intercepted port (must fail and never reach backend)
	t.Run("UnlistedHostname_InterceptedPort_HTTP", func(t *testing.T) {
		cmd := exec.Command("kubectl", "exec", clientPodName, "-c", "workload", "--",
			"wget", "-T", "5", "-qO-", "http://"+unlistedHost+"/unlisted-http")
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("expected unlisted host HTTP request to fail, but it succeeded: %s", out)
		}
		t.Logf("unlisted host HTTP request failed as expected: %v (output: %s)", err, out)

		backendLogs := h.GetDeploymentLogs("backend")
		if strings.Contains(backendLogs, "/unlisted-http") {
			t.Fatalf("backend access log contains /unlisted-http, request unexpectedly reached backend")
		}
	})

	t.Run("UnlistedHostname_InterceptedPort_HTTPS", func(t *testing.T) {
		cmd := exec.Command("kubectl", "exec", clientPodName, "-c", "workload", "--",
			"wget", "-T", "5", "--ca-certificate=/etc/service-portal/ca/tls.crt", "-qO-", "https://"+unlistedHost+"/unlisted-https")
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("expected unlisted host HTTPS request to fail, but it succeeded: %s", out)
		}
		t.Logf("unlisted host HTTPS request failed as expected: %v (output: %s)", err, out)

		backendLogs := h.GetDeploymentLogs("backend")
		if strings.Contains(backendLogs, "/unlisted-https") {
			t.Fatalf("backend access log contains /unlisted-https, request unexpectedly reached backend")
		}
	})

	// Case 3: Non-intercepted port (must be rejected by egress filter)
	t.Run("NonInterceptedPort_HTTP_8080", func(t *testing.T) {
		cmd := exec.Command("kubectl", "exec", clientPodName, "-c", "workload", "--",
			"wget", "-T", "5", "-qO-", "http://"+backendIPv4ClusterIP+":8080/non-intercepted-8080")
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("expected non-intercepted port HTTP request to fail, but it succeeded: %s", out)
		}
		t.Logf("non-intercepted port HTTP request failed as expected: %v (output: %s)", err, out)

		backendLogs := h.GetDeploymentLogs("backend")
		if strings.Contains(backendLogs, "/non-intercepted-8080") {
			t.Fatalf("backend access log contains /non-intercepted-8080, request unexpectedly reached backend")
		}
	})

	t.Run("NonInterceptedPort_RawTCP_9999", func(t *testing.T) {
		cmd := exec.Command("kubectl", "exec", clientPodName, "-c", "workload", "--",
			"/app/toolbox", "probe", "tcp", backendIPv4ClusterIP+":9999", "3s")
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("expected raw TCP connection to port 9999 to fail, but it succeeded: %s", out)
		}
		t.Logf("raw TCP connection to port 9999 failed as expected: %v (output: %s)", err, out)
	})

	// Case 4: Arbitrary DNS (must fail, but cluster DNS resolution must work)
	t.Run("ArbitraryDNS_Blocked", func(t *testing.T) {
		cmdProbe := exec.Command("kubectl", "exec", clientPodName, "-c", "workload", "--",
			"/app/toolbox", "probe", "dns", "8.8.8.8", "example.com", "3s")
		outProbe, errProbe := cmdProbe.CombinedOutput()
		if errProbe == nil {
			t.Fatalf("expected DNS probe to 8.8.8.8 to fail, but it succeeded: %s", outProbe)
		}
		t.Logf("toolbox probe dns to 8.8.8.8 failed as expected: %v (output: %s)", errProbe, outProbe)

		cmdNslookup := exec.Command("kubectl", "exec", clientPodName, "-c", "workload", "--",
			"nslookup", "example.com", "8.8.8.8")
		outNslookup, errNslookup := cmdNslookup.CombinedOutput()
		if errNslookup == nil {
			t.Fatalf("expected nslookup to 8.8.8.8 to fail, but it succeeded: %s", outNslookup)
		}
		t.Logf("nslookup to 8.8.8.8 failed as expected: %v (output: %s)", errNslookup, outNslookup)
	})

	t.Run("ClusterDNS_Allowed", func(t *testing.T) {
		cmdProbe := exec.Command("kubectl", "exec", clientPodName, "-c", "workload", "--",
			"/app/toolbox", "probe", "dns", "cluster", "backend", "5s")
		outProbe, errProbe := cmdProbe.CombinedOutput()
		if errProbe != nil {
			h.DumpDNSDiagnostics(clientPodName, "workload")
			t.Fatalf("expected cluster DNS probe to succeed, but failed: %v (output: %s)", errProbe, outProbe)
		}
		t.Logf("cluster DNS probe succeeded: %s", outProbe)

		cmdNslookup := exec.Command("kubectl", "exec", clientPodName, "-c", "workload", "--",
			"nslookup", "backend")
		outNslookup, errNslookup := cmdNslookup.CombinedOutput()
		if errNslookup != nil {
			h.DumpDNSDiagnostics(clientPodName, "workload")
			t.Fatalf("expected cluster nslookup to succeed, but failed: %v (output: %s)", errNslookup, outNslookup)
		}
		t.Logf("cluster nslookup succeeded: %s", outNslookup)
	})

	// Case 5: Bypass attempt
	t.Run("BypassAttempt_Disallowed", func(t *testing.T) {
		cmdUID := exec.Command("kubectl", "exec", clientPodName, "-c", "workload", "--", "id", "-u")
		outUID, errUID := cmdUID.CombinedOutput()
		if errUID != nil {
			t.Fatalf("failed to get workload UID: %v (output: %s)", errUID, outUID)
		}
		uid := strings.TrimSpace(string(outUID))
		if uid == "1337" {
			t.Fatalf("workload container UID is unexpectedly 1337 (proxy UID)")
		}
		if uid != "1000" {
			t.Errorf("expected workload UID to be 1000, got %s", uid)
		}

		cmdNoNewPrivs := exec.Command("kubectl", "exec", clientPodName, "-c", "workload", "--",
			"grep", "NoNewPrivs", "/proc/self/status")
		outNoNewPrivs, errNoNewPrivs := cmdNoNewPrivs.CombinedOutput()
		if errNoNewPrivs != nil {
			t.Fatalf("failed to read /proc/self/status for NoNewPrivs: %v (output: %s)", errNoNewPrivs, outNoNewPrivs)
		}
		status := strings.TrimSpace(string(outNoNewPrivs))
		t.Logf("workload NoNewPrivs status: %s", status)
		if !strings.Contains(status, "NoNewPrivs:\t1") && !strings.Contains(status, "NoNewPrivs: 1") {
			t.Fatalf("expected NoNewPrivs to be 1 (allowPrivilegeEscalation: false), got: %q", status)
		}

		cmdSu := exec.Command("kubectl", "exec", clientPodName, "-c", "workload", "--",
			"su", "-", "1337", "-c", "id")
		outSu, errSu := cmdSu.CombinedOutput()
		if errSu == nil {
			t.Fatalf("expected su to UID 1337 to fail, but it succeeded: %s", outSu)
		}
		t.Logf("su to UID 1337 failed as expected: %v (output: %s)", errSu, outSu)
	})

	// Case 6: CONNECT method rejected with 405 Method Not Allowed
	t.Run("Connect_MethodNotAllowed_405", func(t *testing.T) {
		cmd := exec.Command("kubectl", "exec", clientPodName, "-c", "workload", "--",
			"/app/toolbox", "probe", "connect", targetHost+":80", targetHost+":443", "5s")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("expected CONNECT probe to succeed, got: %v (output: %s)", err, out)
		}
		outStr := strings.TrimSpace(string(out))
		t.Logf("CONNECT probe output: %s", outStr)
		if !strings.Contains(outStr, "STATUS 405") {
			t.Fatalf("expected STATUS 405, got: %s", outStr)
		}

		backendLogs := h.GetDeploymentLogs("backend")
		if strings.Contains(backendLogs, targetHost+":443") || strings.Contains(backendLogs, "CONNECT") {
			t.Fatalf("backend access log contains CONNECT request, request unexpectedly reached backend")
		}
	})
}

func runSidecarPositiveControls(t *testing.T, h *Harness, clientPodName, targetHost, expectedToken string) {
	t.Run("PositiveControl_HTTP", func(t *testing.T) {
		cmd := exec.Command("kubectl", "exec", clientPodName, "-c", "workload", "--",
			"wget", "-T", "5", "-qO-", "http://"+targetHost+"/positive-control-http")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("positive control HTTP request failed: %v (output: %s)", err, out)
		}
		logs := string(out)
		t.Logf("positive control HTTP output: %s", logs)

		if !strings.Contains(logs, "Authorization") {
			t.Errorf("positive control HTTP output missing Authorization header: %s", logs)
		}
		if !strings.Contains(logs, "Bearer "+expectedToken) {
			t.Errorf("positive control HTTP output missing expected token (%s): %s", expectedToken, logs)
		}
		if strings.Contains(logs, "X-Consumer-Identity") || strings.Contains(logs, "X-Forwarded-Client-Pod") {
			t.Errorf("attribution headers leaked to backend without opt-in: %s", logs)
		}

		backendLogs := h.GetDeploymentLogs("backend")
		if !strings.Contains(backendLogs, "/positive-control-http") {
			t.Fatalf("backend access log missing /positive-control-http")
		}
	})

	t.Run("PositiveControl_HTTPS", func(t *testing.T) {
		cmd := exec.Command("kubectl", "exec", clientPodName, "-c", "workload", "--",
			"wget", "--ca-certificate=/etc/service-portal/ca/tls.crt", "-qO-", "https://"+targetHost+"/positive-control")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("positive control request failed: %v (output: %s)", err, out)
		}
		logs := string(out)
		t.Logf("positive control output: %s", logs)

		if !strings.Contains(logs, "Authorization") {
			t.Errorf("positive control output missing Authorization header: %s", logs)
		}
		if !strings.Contains(logs, "Bearer "+expectedToken) {
			t.Errorf("positive control output missing expected token (%s): %s", expectedToken, logs)
		}

		backendLogs := h.GetDeploymentLogs("backend")
		if !strings.Contains(backendLogs, "/positive-control") {
			t.Fatalf("backend access log missing /positive-control")
		}
	})
}

func runNRIPositiveControls(t *testing.T, h *Harness, clientPodName, targetHost, expectedToken string) {
	t.Run("PositiveControl_HTTP_WithPlaceholder", func(t *testing.T) {
		cmd := exec.Command("kubectl", "exec", clientPodName, "-c", "workload", "--",
			"wget", "-T", "5", "-qO-", "--header=Authorization: placeholder-token", "http://"+targetHost+"/positive-control-http")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("positive control HTTP request with placeholder failed: %v", err)
		}
		logs := string(out)

		if !strings.Contains(logs, "Authorization") {
			t.Errorf("positive control HTTP output missing Authorization header")
		}
		if !strings.Contains(logs, "Bearer "+expectedToken) {
			t.Errorf("positive control HTTP output missing injected credential")
		}
		if strings.Contains(logs, "placeholder-token") {
			t.Errorf("positive control HTTP output still contains placeholder token")
		}
		if strings.Contains(logs, "X-Consumer-Identity") || strings.Contains(logs, "X-Forwarded-Client-Pod") {
			t.Errorf("attribution headers leaked to backend without opt-in")
		}

		backendLogs := h.GetDeploymentLogs("backend")
		if !strings.Contains(backendLogs, "/positive-control-http") {
			t.Fatalf("backend access log missing /positive-control-http")
		}
		t.Logf("positive control HTTP with placeholder succeeded: credential swapped")
	})

	t.Run("PositiveControl_HTTP_WithoutPlaceholder", func(t *testing.T) {
		cmd := exec.Command("kubectl", "exec", clientPodName, "-c", "workload", "--",
			"wget", "-T", "5", "-qO-", "http://"+targetHost+"/no-placeholder-http")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("positive control HTTP request without placeholder failed: %v", err)
		}
		logs := string(out)

		if strings.Contains(logs, "Authorization") {
			t.Errorf("request without placeholder header unexpectedly received Authorization header")
		}
		if strings.Contains(logs, expectedToken) {
			t.Errorf("request without placeholder header unexpectedly received credential")
		}

		backendLogs := h.GetDeploymentLogs("backend")
		if !strings.Contains(backendLogs, "/no-placeholder-http") {
			t.Fatalf("backend access log missing /no-placeholder-http")
		}
		t.Logf("positive control HTTP without placeholder succeeded: no credential added")
	})

	t.Run("PositiveControl_HTTPS_WithPlaceholder", func(t *testing.T) {
		cmd := exec.Command("kubectl", "exec", clientPodName, "-c", "workload", "--",
			"wget", "--ca-certificate=/etc/service-portal/ca/tls.crt", "-T", "5", "-qO-", "--header=Authorization: placeholder-token", "https://"+targetHost+"/positive-control-https")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("positive control HTTPS request with placeholder failed: %v", err)
		}
		logs := string(out)

		if !strings.Contains(logs, "Authorization") {
			t.Errorf("positive control HTTPS output missing Authorization header")
		}
		if !strings.Contains(logs, "Bearer "+expectedToken) {
			t.Errorf("positive control HTTPS output missing injected credential")
		}
		if strings.Contains(logs, "placeholder-token") {
			t.Errorf("positive control HTTPS output still contains placeholder token")
		}

		backendLogs := h.GetDeploymentLogs("backend")
		if !strings.Contains(backendLogs, "/positive-control-https") {
			t.Fatalf("backend access log missing /positive-control-https")
		}
		t.Logf("positive control HTTPS with placeholder succeeded: credential swapped")
	})

	t.Run("PositiveControl_HTTPS_WithoutPlaceholder", func(t *testing.T) {
		cmd := exec.Command("kubectl", "exec", clientPodName, "-c", "workload", "--",
			"wget", "--ca-certificate=/etc/service-portal/ca/tls.crt", "-T", "5", "-qO-", "https://"+targetHost+"/no-placeholder-https")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("positive control HTTPS request without placeholder failed: %v", err)
		}
		logs := string(out)

		if strings.Contains(logs, "Authorization") {
			t.Errorf("HTTPS request without placeholder header unexpectedly received Authorization header")
		}
		if strings.Contains(logs, expectedToken) {
			t.Errorf("HTTPS request without placeholder header unexpectedly received credential")
		}

		backendLogs := h.GetDeploymentLogs("backend")
		if !strings.Contains(backendLogs, "/no-placeholder-https") {
			t.Fatalf("backend access log missing /no-placeholder-https")
		}
		t.Logf("positive control HTTPS without placeholder succeeded: no credential added")
	})
}

func generateTestCA() (caCertPEM, caKeyPEM []byte, err error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Test Backend CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	return certPEM, keyPEM, nil
}

func generateSignedCert(caCertPEM, caKeyPEM []byte, hosts []string) (certPEM, keyPEM []byte, err error) {
	caBlock, _ := pem.Decode(caCertPEM)
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	keyBlock, _ := pem.Decode(caKeyPEM)
	caKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hosts[0]},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, caCert, &priv.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	cOut := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	kOut := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	return cOut, kOut, nil
}

func startPortForward(ctx context.Context, namespace, target string) (string, func(), error) {
	cmd := exec.CommandContext(ctx, "kubectl", "-n", namespace, "port-forward", target, ":8443")
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", nil, fmt.Errorf("getting port-forward stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return "", nil, fmt.Errorf("starting port-forward: %w", err)
	}

	addrCh := make(chan string, 1)
	errCh := make(chan error, 1)

	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			// Expected output format: "Forwarding from 127.0.0.1:XXXXX -> 8443"
			if strings.Contains(line, "Forwarding from") && strings.Contains(line, "-> 8443") {
				fields := strings.Fields(line)
				for _, f := range fields {
					if strings.HasPrefix(f, "127.0.0.1:") {
						addrCh <- f
						return
					}
				}
			}
		}
		if err := scanner.Err(); err != nil {
			errCh <- err
		} else {
			errMsg := strings.TrimSpace(errBuf.String())
			if errMsg != "" {
				errCh <- fmt.Errorf("port-forward exited without printing forwarding address: %s", errMsg)
			} else {
				errCh <- errors.New("port-forward exited without printing forwarding address")
			}
		}
	}()

	select {
	case addr := <-addrCh:
		var dialErr error
		for i := 0; i < 50; i++ {
			c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
			if err == nil {
				c.Close()
				dialErr = nil
				break
			}
			dialErr = err
			time.Sleep(100 * time.Millisecond)
		}
		if dialErr != nil {
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
			return "", nil, fmt.Errorf("timed out waiting for port-forward to accept connections: %w", dialErr)
		}
		cleanup := func() {
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
			}
		}
		return addr, cleanup, nil
	case err := <-errCh:
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		return "", nil, fmt.Errorf("port-forward failed: %w", err)
	case <-time.After(30 * time.Second):
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		return "", nil, errors.New("timed out waiting for port-forward output")
	}
}

func getServiceAccountToken(t *testing.T, sa, audience, namespace string) string {
	t.Helper()
	cmd := exec.Command("kubectl", "create", "token", sa, "--audience="+audience, "-n", namespace)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to create token for serviceaccount %s/%s: %v (output: %s)", namespace, sa, err, out)
	}
	return strings.TrimSpace(string(out))
}

func runSidecarDualStackAssertions(t *testing.T, h *Harness, clientPodName, backendIPv6ClusterIP string) {
	if backendIPv6ClusterIP == "" {
		t.Fatalf("runSidecarDualStackAssertions called on dual-stack cluster but backendIPv6ClusterIP is empty")
	}

	t.Run("DirectIPv6_InterceptedPort_HTTP", func(t *testing.T) {
		cmd := exec.Command("kubectl", "exec", clientPodName, "-c", "workload", "--",
			"wget", "-T", "5", "-qO-", "http://["+backendIPv6ClusterIP+"]:80/direct-ipv6-http")
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("expected direct IPv6 HTTP request to fail, but it succeeded: %s", out)
		}
		t.Logf("direct IPv6 HTTP request failed as expected: %v (output: %s)", err, out)

		backendLogs := h.GetDeploymentLogs("backend")
		if strings.Contains(backendLogs, "/direct-ipv6-http") {
			t.Fatalf("backend access log contains /direct-ipv6-http, request unexpectedly reached backend")
		}
	})

	t.Run("DirectIPv6_InterceptedPort_HTTPS", func(t *testing.T) {
		cmd := exec.Command("kubectl", "exec", clientPodName, "-c", "workload", "--",
			"wget", "-T", "5", "--ca-certificate=/etc/service-portal/ca/tls.crt", "-qO-", "https://["+backendIPv6ClusterIP+"]:443/direct-ipv6-https")
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("expected direct IPv6 HTTPS request to fail, but it succeeded: %s", out)
		}
		t.Logf("direct IPv6 HTTPS request failed as expected: %v (output: %s)", err, out)

		backendLogs := h.GetDeploymentLogs("backend")
		if strings.Contains(backendLogs, "/direct-ipv6-https") {
			t.Fatalf("backend access log contains /direct-ipv6-https, request unexpectedly reached backend")
		}
	})

	t.Run("UnlistedHostname_IPv6_InterceptedPort_HTTPS", func(t *testing.T) {
		cmd := exec.Command("kubectl", "exec", clientPodName, "-c", "workload", "--",
			"wget", "-T", "5", "--ca-certificate=/etc/service-portal/ca/tls.crt", "-qO-", "https://other-v6.backend/unlisted-ipv6-https")
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("expected unlisted host IPv6 HTTPS request to fail, but it succeeded: %s", out)
		}
		t.Logf("unlisted host IPv6 HTTPS request failed as expected: %v (output: %s)", err, out)

		backendLogs := h.GetDeploymentLogs("backend")
		if strings.Contains(backendLogs, "/unlisted-ipv6-https") {
			t.Fatalf("backend access log contains /unlisted-ipv6-https, request unexpectedly reached backend")
		}
	})

	t.Run("NonInterceptedPort_IPv6_HTTP_8080", func(t *testing.T) {
		cmd := exec.Command("kubectl", "exec", clientPodName, "-c", "workload", "--",
			"wget", "-T", "5", "-qO-", "http://["+backendIPv6ClusterIP+"]:8080/non-intercepted-ipv6-8080")
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("expected non-intercepted port IPv6 HTTP request to fail, but it succeeded: %s", out)
		}
		t.Logf("non-intercepted port IPv6 HTTP request failed as expected: %v (output: %s)", err, out)

		backendLogs := h.GetDeploymentLogs("backend")
		if strings.Contains(backendLogs, "/non-intercepted-ipv6-8080") {
			t.Fatalf("backend access log contains /non-intercepted-ipv6-8080, request unexpectedly reached backend")
		}
	})

	t.Run("NonInterceptedPort_IPv6_RawTCP_9999", func(t *testing.T) {
		cmd := exec.Command("kubectl", "exec", clientPodName, "-c", "workload", "--",
			"/app/toolbox", "probe", "tcp", "["+backendIPv6ClusterIP+"]:9999", "3s")
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("expected raw TCP connection to IPv6 port 9999 to fail, but it succeeded: %s", out)
		}
		t.Logf("raw TCP connection to IPv6 port 9999 failed as expected: %v (output: %s)", err, out)
	})

	// Verify IPv6 positive control path on dual-stack clusters:
	// github.backend maps to IPv6 dummy address 2001:db8::1 in hostAliases,
	// exercising the ip6tables REDIRECT path and the proxy's :8443 dual-stack listener on IPv6.
	t.Run("PositiveControl_IPv6_GithubHTTPS", func(t *testing.T) {
		cmd := exec.Command("kubectl", "exec", clientPodName, "-c", "workload", "--",
			"wget", "--ca-certificate=/etc/service-portal/ca/tls.crt", "-qO-", "https://github.backend/positive-control-ipv6")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("positive control IPv6 request failed: %v (output: %s)", err, out)
		}
		logs := string(out)
		t.Logf("positive control IPv6 output: %s", logs)

		if !strings.Contains(logs, "Authorization") {
			t.Errorf("positive control IPv6 output missing Authorization header: %s", logs)
		}
		if !strings.Contains(logs, "Bearer github-sidecar-token") {
			t.Errorf("positive control IPv6 output missing expected token: %s", logs)
		}

		backendLogs := h.GetDeploymentLogs("backend")
		if !strings.Contains(backendLogs, "/positive-control-ipv6") {
			t.Fatalf("backend access log missing /positive-control-ipv6")
		}
	})

	// Verify Neighbour Discovery (ND) works from workload container
	t.Run("NeighbourDiscovery_Functional", func(t *testing.T) {
		cmdRoute := exec.Command("kubectl", "exec", clientPodName, "-c", "workload", "--",
			"ip", "-6", "route", "show", "default")
		outRoute, errRoute := cmdRoute.CombinedOutput()
		if errRoute != nil {
			t.Fatalf("failed to get default IPv6 route: %v (output: %s)", errRoute, outRoute)
		}
		t.Logf("default IPv6 route: %s", strings.TrimSpace(string(outRoute)))

		fields := strings.Fields(string(outRoute))
		var gwIP string
		for i, f := range fields {
			if f == "via" && i+1 < len(fields) {
				gwIP = fields[i+1]
				break
			}
		}
		if gwIP == "" {
			t.Fatalf("could not determine default IPv6 gateway from: %s", outRoute)
		}
		t.Logf("default IPv6 gateway: %s", gwIP)

		cmdNeigh := exec.Command("kubectl", "exec", clientPodName, "-c", "workload", "--",
			"ip", "-6", "neigh", "show", gwIP)
		outNeigh, errNeigh := cmdNeigh.CombinedOutput()
		if errNeigh != nil {
			t.Fatalf("failed to execute 'ip -6 neigh show %s': %v (output: %s)", gwIP, errNeigh, outNeigh)
		}
		neighOutput := strings.TrimSpace(string(outNeigh))
		t.Logf("gateway neighbour entry:\n%s", neighOutput)

		if neighOutput == "" {
			t.Fatalf("no neighbour entry found for gateway %s", gwIP)
		}
		if strings.Contains(neighOutput, "FAILED") || strings.Contains(neighOutput, "INCOMPLETE") {
			t.Fatalf("neighbour discovery failed for gateway %s: %s", gwIP, neighOutput)
		}

		validStates := []string{"REACHABLE", "STALE", "DELAY", "PROBE"}
		matched := false
		for _, state := range validStates {
			if strings.Contains(neighOutput, state) {
				matched = true
				break
			}
		}
		if !matched {
			t.Fatalf("expected neighbour entry to be in REACHABLE, STALE, DELAY, or PROBE, but got: %s", neighOutput)
		}
	})

	// Fail-closed check: a variant pod where ip6tables is made to fail must not become Ready
	t.Run("FailClosed_InvalidIPv6Rules_PodNotReady", func(t *testing.T) {
		failPodName := "test-client-sidecar-failclosed"
		h.DeletePod(failPodName)

		failPodManifest := `
apiVersion: v1
kind: Pod
metadata:
  name: test-client-sidecar-failclosed
  labels:
    app: test-client-sidecar-failclosed
spec:
  initContainers:
  - name: init-service-portals
    image: init-service-portals:e2e
    imagePullPolicy: Never
    env:
    - name: TEST_FAIL_IP6TABLES
      value: "true"
    securityContext:
      capabilities:
        add: ["NET_ADMIN"]
      runAsUser: 0
    volumeMounts:
    - name: ca-cert
      mountPath: /etc/service-portal/ca
    - name: ca-key
      mountPath: /etc/service-portal/ca-private
  containers:
  - name: workload
    image: toolbox:e2e
    imagePullPolicy: Never
    command: ["/bin/sh", "-c", "sleep 3600"]
  volumes:
  - name: ca-cert
    emptyDir: {}
  - name: ca-key
    emptyDir: {}
`
		h.KubectlApplyContent(failPodManifest)
		defer h.DeletePod(failPodName)

		var exitCode string
		var waitingReason string
		var logsStr string
		initFailed := false

		start := time.Now()
		for time.Since(start) < 30*time.Second {
			cmdExit := exec.Command("kubectl", "get", "pod", failPodName, "-o",
				"jsonpath={.status.initContainerStatuses[0].state.terminated.exitCode}{.status.initContainerStatuses[0].lastState.terminated.exitCode}")
			outExit, _ := cmdExit.CombinedOutput()
			exitCode = strings.TrimSpace(string(outExit))

			cmdReason := exec.Command("kubectl", "get", "pod", failPodName, "-o",
				"jsonpath={.status.initContainerStatuses[0].state.waiting.reason}")
			outReason, _ := cmdReason.CombinedOutput()
			waitingReason = strings.TrimSpace(string(outReason))

			cmdLogs := exec.Command("kubectl", "logs", failPodName, "-c", "init-service-portals")
			outLogs, _ := cmdLogs.CombinedOutput()
			logsStr = string(outLogs)

			if (exitCode != "" && exitCode != "0") || waitingReason == "CrashLoopBackOff" || waitingReason == "Error" {
				if strings.Contains(logsStr, "Failing closed") {
					initFailed = true
					break
				}
			}
			time.Sleep(1 * time.Second)
		}

		t.Logf("variant pod init container exitCode=%q, waitingReason=%q", exitCode, waitingReason)
		t.Logf("variant pod initContainer logs:\n%s", logsStr)

		if !initFailed {
			t.Fatalf("expected init container to fail with non-zero exit code and 'Failing closed' log message, got exitCode=%q, waitingReason=%q, logs=%s",
				exitCode, waitingReason, logsStr)
		}

		cmdReady := exec.Command("kubectl", "get", "pod", failPodName, "-o", "jsonpath={.status.containerStatuses[0].ready}")
		outReady, _ := cmdReady.CombinedOutput()
		if strings.TrimSpace(string(outReady)) == "true" {
			t.Fatalf("expected variant pod with failing ip6tables to never become Ready, but container ready is true!")
		}
		t.Logf("variant pod readiness check confirmed not ready (ready=%s)", strings.TrimSpace(string(outReady)))
	})
}

func TestNRIPluginEgressDenied(t *testing.T) {
	if os.Getenv("RUN_E2E") == "" {
		t.Skip("RUN_E2E env var not set, skipping")
	}

	h := NewHarness(t, "nri-egress-denied-e2e")
	h.Setup()

	gitRoot := h.GetGitRoot()

	// Build and load images
	h.DockerBuild("service-portal-agent:e2e", filepath.Join(gitRoot, "images/service-portal-agent/Dockerfile"), gitRoot)
	h.DockerBuild("service-portal-nri-plugin:e2e", filepath.Join(gitRoot, "images/service-portal-nri-plugin/Dockerfile"), gitRoot)
	h.DockerBuild("toolbox:e2e", filepath.Join(gitRoot, "tests/toolbox/Dockerfile"), filepath.Join(gitRoot, "tests/toolbox"))
	h.DockerBuild("service-portal-controller:e2e", filepath.Join(gitRoot, "images/service-portal-controller/Dockerfile"), gitRoot)

	h.KindLoad("service-portal-agent:e2e")
	h.KindLoad("service-portal-nri-plugin:e2e")
	h.KindLoad("toolbox:e2e")
	h.KindLoad("service-portal-controller:e2e")

	serviceIPFamilies := ""
	if h.IsDualStack() {
		serviceIPFamilies = `
  ipFamilies:
  - IPv4
  - IPv6
  ipFamilyPolicy: RequireDualStack`
	}

	const (
		controllerAudience   = "https://service-portal-controller"
		nodeAgentAccount     = "system:serviceaccount:default:portal-node-agent"
		allowedClientSA      = "sandbox-controller"
		unauthorizedClientSA = "unauthorized-controller"
		allowedClientAccount = "system:serviceaccount:default:sandbox-controller"
	)

	// Create client service accounts for controller authorization tests
	clientSAManifest := `
apiVersion: v1
kind: ServiceAccount
metadata:
  name: sandbox-controller
  namespace: default
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: unauthorized-controller
  namespace: default
`
	h.KubectlApplyContent(clientSAManifest)
	t.Cleanup(func() {
		h.RunCommand("kubectl", "delete", "serviceaccount", allowedClientSA, unauthorizedClientSA, "-n", "default", "--ignore-not-found")
	})

	// Deploy Service Portal Controller certificates and manifest
	controllerCACert, controllerCAKey, err := generateTestCA()
	if err != nil {
		t.Fatalf("failed to generate controller CA: %v", err)
	}
	controllerCert, controllerKey, err := generateSignedCert(controllerCACert, controllerCAKey, []string{
		"service-portal-controller",
		"service-portal-controller.service-portal-system",
		"service-portal-controller.service-portal-system.svc",
		"service-portal-controller.service-portal-system.svc.cluster.local",
		"localhost",
		"127.0.0.1",
	})
	if err != nil {
		t.Fatalf("failed to generate controller serving cert: %v", err)
	}

	controllerTLSSecretManifest := fmt.Sprintf(`
apiVersion: v1
kind: Namespace
metadata:
  name: service-portal-system
---
apiVersion: v1
kind: Secret
metadata:
  name: service-portal-controller-tls
  namespace: service-portal-system
type: kubernetes.io/tls
data:
  tls.crt: %s
  tls.key: %s
`, base64.StdEncoding.EncodeToString(controllerCert),
		base64.StdEncoding.EncodeToString(controllerKey))
	h.KubectlApplyContent(controllerTLSSecretManifest)

	controllerCAManifest := fmt.Sprintf(`
apiVersion: v1
kind: Secret
metadata:
  name: service-portal-controller-ca
  namespace: default
data:
  tls.crt: %s
`, base64.StdEncoding.EncodeToString(controllerCACert))
	h.KubectlApplyContent(controllerCAManifest)

	controllerManifestPath := filepath.Join(gitRoot, "k8s/controller.yaml")
	bCtrl, err := os.ReadFile(controllerManifestPath)
	if err != nil {
		t.Fatalf("Failed to read controller manifest: %v", err)
	}
	controllerManifest := string(bCtrl)
	controllerManifest = strings.ReplaceAll(controllerManifest, "image: service-portal-controller:latest", "image: service-portal-controller:e2e\n        imagePullPolicy: Never")

	h.KubectlApplyContent(controllerManifest)

	// Assert once before running configure that the controller container is in CreateContainerConfigError naming the missing ConfigMap.
	var waitingReason string
	var waitingMessage string
	foundExpectedStatus := false
	startWaitConfigMap := time.Now()
	for time.Since(startWaitConfigMap) < 30*time.Second {
		cmdReason := exec.Command("kubectl", "-n", "service-portal-system", "get", "pods", "-l", "app=service-portal-controller",
			"-o", "jsonpath={.items[*].status.containerStatuses[*].state.waiting.reason}")
		outReason, _ := cmdReason.CombinedOutput()
		waitingReason = strings.TrimSpace(string(outReason))

		cmdMsg := exec.Command("kubectl", "-n", "service-portal-system", "get", "pods", "-l", "app=service-portal-controller",
			"-o", "jsonpath={.items[*].status.containerStatuses[*].state.waiting.message}")
		outMsg, _ := cmdMsg.CombinedOutput()
		waitingMessage = strings.TrimSpace(string(outMsg))

		if waitingReason == "CreateContainerConfigError" && strings.Contains(waitingMessage, "service-portal-config") {
			foundExpectedStatus = true
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !foundExpectedStatus {
		t.Fatalf("expected controller container to be waiting with reason CreateContainerConfigError and message naming 'service-portal-config', got reason=%q, message=%q",
			waitingReason, waitingMessage)
	}

	h.RunCommand(filepath.Join(gitRoot, "dev/tasks/configure"),
		"--audience="+controllerAudience,
		"--node-agent-account="+nodeAgentAccount,
		"--client-allowlist="+allowedClientAccount,
	)

	h.WaitForDeploymentInNamespace("service-portal-system", "service-portal-controller", 2*time.Minute)
	h.WaitForPodReady("app=service-portal-controller", 2*time.Minute)

	// Deploy Backend Service and Deployment
	backendCACert, backendCAKey, err := generateTestCA()
	if err != nil {
		t.Fatalf("failed to generate backend CA: %v", err)
	}
	backendCert, backendKey, err := generateSignedCert(backendCACert, backendCAKey, []string{
		"backend",
		"backend.default",
		"backend.default.svc",
		"backend.default.svc.cluster.local",
	})
	if err != nil {
		t.Fatalf("failed to generate backend serving cert: %v", err)
	}

	certManifest := fmt.Sprintf(`
apiVersion: v1
kind: Secret
metadata:
  name: backend-tls
type: kubernetes.io/tls
data:
  tls.crt: %s
  tls.key: %s
---
apiVersion: v1
kind: Secret
metadata:
  name: backend-ca
data:
  tls.crt: %s
`, base64.StdEncoding.EncodeToString(backendCert),
		base64.StdEncoding.EncodeToString(backendKey),
		base64.StdEncoding.EncodeToString(backendCACert))
	h.KubectlApplyContent(certManifest)

	backendManifest := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: backend
  labels:
    app: backend
spec:
  replicas: 1
  selector:
    matchLabels:
      app: backend
  template:
    metadata:
      labels:
        app: backend
    spec:
      containers:
      - name: toolbox
        image: toolbox:e2e
        imagePullPolicy: Never
        args: ["server"]
        env:
        - name: TLS_CERT_FILE
          value: "/etc/tls/tls.crt"
        - name: TLS_KEY_FILE
          value: "/etc/tls/tls.key"
        ports:
        - containerPort: 8080
        - containerPort: 8443
        volumeMounts:
        - name: tls-cert
          mountPath: /etc/tls
          readOnly: true
      volumes:
      - name: tls-cert
        secret:
          secretName: backend-tls
---
apiVersion: v1
kind: Service
metadata:
  name: backend
spec:` + serviceIPFamilies + `
  selector:
    app: backend
  ports:
  - name: http
    port: 80
    targetPort: 8080
  - name: https
    port: 443
    targetPort: 8443
  - name: alt
    port: 8080
    targetPort: 8080
---
apiVersion: v1
kind: Service
metadata:
  name: unlisted-backend
spec:` + serviceIPFamilies + `
  selector:
    app: backend
  ports:
  - name: http
    port: 80
    targetPort: 8080
`
	h.KubectlApplyContent(backendManifest)
	h.WaitForDeployment("backend", 2*time.Minute)
	time.Sleep(5 * time.Second)

	backendIPv4ClusterIP := h.GetServiceIPv4ClusterIP("backend")
	if backendIPv4ClusterIP == "" {
		backendIPv4ClusterIP = h.GetServiceClusterIP("backend")
	}
	t.Logf("Backend IPv4 ClusterIP: %s", backendIPv4ClusterIP)
	backendIPv6ClusterIP := h.GetServiceIPv6ClusterIP("backend")
	var proxyHostV6Env string
	if h.IsDualStack() {
		t.Logf("Backend IPv6 ClusterIP: %s", backendIPv6ClusterIP)
		if backendIPv6ClusterIP == "" {
			t.Fatalf("Expected IPv6 ClusterIP for backend service on dual-stack cluster, but none found")
		}
		cmdNodeIPv6 := exec.Command("kubectl", "get", "nodes", "-o", "jsonpath={.items[0].status.addresses[?(@.type==\"InternalIP\")].address}")
		if out, err := cmdNodeIPv6.CombinedOutput(); err == nil {
			for _, addr := range strings.Fields(string(out)) {
				if ip := net.ParseIP(addr); ip != nil && ip.To4() == nil {
					proxyHostV6Env = fmt.Sprintf("\n        - name: PROXY_HOST_V6\n          value: %q", addr)
					break
				}
			}
		}
	}

	// Deploy Node-Agent DaemonSet (Proxy + NRI Plugin)
	nodeAgentManifest := `
apiVersion: v1
kind: ServiceAccount
metadata:
  name: portal-node-agent
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: portal-node-agent
  labels:
    app: portal-node-agent
spec:
  selector:
    matchLabels:
      app: portal-node-agent
  template:
    metadata:
      labels:
        app: portal-node-agent
    spec:
      serviceAccountName: portal-node-agent
      tolerations:
      - key: "service-portal.gke.io/uninitialized"
        operator: "Exists"
        effect: "NoSchedule"
      dnsPolicy: ClusterFirstWithHostNet
      hostNetwork: true
      initContainers:
      - name: node-init
        image: service-portal-nri-plugin:e2e
        imagePullPolicy: Never
        args: ["init", "-ca-dir=/etc/service-portal/ca", "-socket-dir=/run/service-portal", "-proxy-uid=65532", "-proxy-gid=65532"]
        volumeMounts:
        - name: ca-volume
          mountPath: /etc/service-portal/ca
        - name: socket-volume
          mountPath: /run/service-portal
      containers:
      - name: proxy
        image: service-portal-agent:e2e
        imagePullPolicy: Never
        securityContext:
          capabilities:
            add: ["NET_BIND_SERVICE"]
        env:
        - name: PORT
          value: "8080"
        - name: HTTPS_PORT
          value: "8443"
        - name: PROXY_HOST
          valueFrom:
            fieldRef:
              fieldPath: status.hostIP
        - name: ENABLE_POD_MAP
          value: "true"
        - name: ADMIN_ADDR
          value: "/run/service-portal/portal.sock"
        - name: CA_CERT_PATH
          value: "/etc/service-portal/ca/tls.crt"
        - name: CA_KEY_PATH
          value: "/etc/service-portal/ca/tls.key"
        - name: SSL_CERT_FILE
          value: "/etc/service-portal/backend-ca/tls.crt"
        - name: SERVE_DNS
          value: "true"
        - name: STORE_DIR
          value: "/run/service-portal/store"
        - name: CONTROLLER_ADDR
          value: "service-portal-controller.service-portal-system.svc:8443"
        - name: CONTROLLER_TOKEN_PATH
          value: "/var/run/secrets/tokens/controller/token"
        - name: CONTROLLER_CA_CERT_PATH
          value: "/etc/service-portal/controller-ca/tls.crt"` + proxyHostV6Env + `
        volumeMounts:
        - name: ca-volume
          mountPath: /etc/service-portal/ca
          readOnly: true
        - name: backend-ca-volume
          mountPath: /etc/service-portal/backend-ca
          readOnly: true
        - name: controller-ca-volume
          mountPath: /etc/service-portal/controller-ca
          readOnly: true
        - name: controller-token
          mountPath: /var/run/secrets/tokens/controller
          readOnly: true
        - name: socket-volume
          mountPath: /run/service-portal
      - name: nri-plugin
        image: service-portal-nri-plugin:e2e
        imagePullPolicy: Never
        securityContext:
          capabilities:
            add: ["NET_ADMIN", "SYS_ADMIN"]
        env:
        - name: PROXY_HOST
          valueFrom:
            fieldRef:
              fieldPath: status.hostIP
        - name: PROXY_PORT
          value: "8080"
        - name: PROXY_HTTPS_PORT
          value: "8443"
        - name: ADMIN_URL
          value: "unix:///run/service-portal/portal.sock"
        - name: CA_CERT_PATH
          value: "/etc/service-portal/ca/tls.crt"
        - name: NRI_SOCKET_PATH
          value: "/var/run/nri/nri.sock"` + proxyHostV6Env + `
        volumeMounts:
        - name: ca-volume
          mountPath: /etc/service-portal/ca
        - name: nri-socket
          mountPath: /var/run/nri
        - name: netns
          mountPath: /run/netns
          mountPropagation: HostToContainer
        - name: socket-volume
          mountPath: /run/service-portal
      volumes:
      - name: backend-ca-volume
        secret:
          secretName: backend-ca
      - name: controller-ca-volume
        secret:
          secretName: service-portal-controller-ca
      - name: controller-token
        projected:
          sources:
          - serviceAccountToken:
              path: token
              expirationSeconds: 3600
              audience: https://service-portal-controller
      - name: ca-volume
        hostPath:
          path: /etc/service-portal/ca
          type: DirectoryOrCreate
      - name: nri-socket
        hostPath:
          path: /var/run/nri
      - name: netns
        hostPath:
          path: /run/netns
      - name: socket-volume
        hostPath:
          path: /run/service-portal
          type: DirectoryOrCreate
`

	// 1. Taint the node so uninitialized nodes cannot schedule opted-in pods
	taintCmd := exec.Command("kubectl", "taint", "nodes", "--all", "service-portal.gke.io/uninitialized:NoSchedule", "--overwrite")
	if out, err := taintCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to taint nodes: %v (output: %s)", err, out)
	}

	// 2. Deploy Client Pod with ONLY the intercept opt-in label:
	// No init container, no sidecar container, no NET_ADMIN, no CA mounts, no hostAliases.
	clientPodName := "test-client-nri-deny"
	h.DeletePod(clientPodName)

	runtimeClassField := ""
	if h.IsGVisor() {
		runtimeClassField = "  runtimeClassName: gvisor\n"
	}

	clientManifest := fmt.Sprintf(`
apiVersion: v1
kind: Pod
metadata:
  name: test-client-nri-deny
  labels:
    app: test-client-nri-deny
    service-portal.gke.io/intercept: "true"
spec:
%s  containers:
  - name: workload
    image: toolbox:e2e
    imagePullPolicy: Never
    securityContext:
      runAsUser: 1000
      allowPrivilegeEscalation: false
    command: ["/bin/sh", "-c", "sleep 3600"]
`, runtimeClassField)
	h.KubectlApplyContent(clientManifest)

	// 3. Assert the opted-in pod stays Pending while the taint is present
	time.Sleep(3 * time.Second)
	phaseCmd := exec.Command("kubectl", "get", "pod", clientPodName, "-o", "jsonpath={.status.phase}")
	phaseOut, err := phaseCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to check client pod phase: %v (output: %s)", err, phaseOut)
	}
	if !strings.Contains(string(phaseOut), "Pending") {
		t.Fatalf("expected client pod to stay Pending while node is tainted, got %s", phaseOut)
	}
	t.Logf("Client pod is correctly Pending due to node taint: %s", phaseOut)

	// 4. Deploy Node-Agent DaemonSet (with toleration; connects to NRI and registers)
	h.KubectlApplyContent(nodeAgentManifest)
	h.WaitForPodReady("app=portal-node-agent", 2*time.Minute)

	// 5. Remove node initialization taint once DaemonSet is ready
	unTaintCmd := exec.Command("kubectl", "taint", "nodes", "--all", "service-portal.gke.io/uninitialized-")
	if out, err := unTaintCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to remove node taint: %v (output: %s)", err, out)
	}

	// 6. Assert the client pod now schedules, transitions to Running, and becomes Ready
	h.WaitForPodReady("app=test-client-nri-deny", 2*time.Minute)

	// Verify controller is ready and node agent stream is connected
	t.Run("ControllerReady_NodeStreamConnected", func(t *testing.T) {
		h.WaitForDeploymentInNamespace("service-portal-system", "service-portal-controller", 2*time.Minute)
		h.WaitForPodReady("app=service-portal-controller", 2*time.Minute)

		var streamConnected bool
		for i := 0; i < 30; i++ {
			ctrlLogs := h.GetPodLogsByNamespaceAndLabel("service-portal-system", "app=service-portal-controller", "service-portal-controller")
			nodeLogs := h.GetPodLogsByLabel("app=portal-node-agent", "proxy")
			if strings.Contains(ctrlLogs, "stream connected") || strings.Contains(nodeLogs, "controller: stream connected") {
				streamConnected = true
				t.Logf("verified controller is ready and node agent stream is connected")
				break
			}
			time.Sleep(time.Second)
		}
		if !streamConnected {
			t.Fatalf("timed out waiting for node agent stream to connect to controller")
		}
	})

	if h.IsGVisor() {
		dmesgCmd := exec.Command("kubectl", "exec", clientPodName, "-c", "workload", "--", "dmesg")
		dmesgOut, err := dmesgCmd.CombinedOutput()
		if err != nil || !strings.Contains(string(dmesgOut), "Starting gVisor...") {
			t.Fatalf("expected client pod to run under gVisor runtime, dmesg output: %s (err: %v)", dmesgOut, err)
		}
		t.Logf("Verified client pod is running under gVisor runtime: %s", strings.Split(strings.TrimSpace(string(dmesgOut)), "\n")[0])
	}

	cmdUID := exec.Command("kubectl", "get", "pod", clientPodName, "-o", "jsonpath={.metadata.uid}")
	outUID, err := cmdUID.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to get client pod UID: %v (output: %s)", err, outUID)
	}
	clientUID := strings.TrimSpace(string(outUID))

	cmdNodeIP := exec.Command("kubectl", "get", "pod", clientPodName, "-o", "jsonpath={.status.hostIP}")
	outNodeIP, err := cmdNodeIP.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to get node IP: %v (output: %s)", err, outNodeIP)
	}
	nodeIP := strings.TrimSpace(string(outNodeIP))

	// 7. Verify unbound opted-in pod fails closed by default
	t.Run("UnboundPod_Denied", func(t *testing.T) {
		cmd := exec.Command("kubectl", "exec", clientPodName, "-c", "workload", "--",
			"wget", "-T", "5", "-qO-", "http://backend/unbound-check")
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("expected unbound pod request to be denied, but succeeded: %s", out)
		}
		t.Logf("unbound pod request denied as expected: %v (output: %s)", err, out)
	})

	// 8. Bind pod to user identity and egress policy via PodBindService using service-portal-nri-plugin CLI
	policyJSON := `{
  "rules": [
    {
      "http": {
        "hostnames": ["backend", "backend.default", "backend.default.svc", "backend.default.svc.cluster.local"],
        "effects": {
          "replaceHeaders": [
            {
              "header": "Authorization",
              "prefix": "Bearer ",
              "credentialUri": "secret://backend-token"
            }
          ]
        }
      }
    },
    {
      "https": {
        "hostnames": ["backend", "backend.default", "backend.default.svc", "backend.default.svc.cluster.local"],
        "effects": {
          "replaceHeaders": [
            {
              "header": "Authorization",
              "prefix": "Bearer ",
              "credentialUri": "secret://backend-token"
            }
          ]
        }
      }
    }
  ]
}`
	bindCmd := exec.Command("kubectl", "exec", "-i", "daemonset/portal-node-agent", "-c", "nri-plugin", "--",
		"service-portal-nri-plugin", "bind-service", "bind", "--socket", "/run/service-portal/bind.sock", "--uid", clientUID, "--identity", "test-user-alice", "--policy-file", "-")
	bindCmd.Stdin = strings.NewReader(policyJSON)
	bindOut, err := bindCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to bind pod %s via service-portal-nri-plugin bind-service bind: %v (output: %s)", clientUID, err, bindOut)
	}
	t.Logf("Successfully bound pod %s via node agent bind-service: %s", clientUID, bindOut)

	// Inject named secret over PodBindService. Secret value is passed via standard input and never as an argument or logged.
	secretJSON := `{"backend-token": "gemini-nri-token"}`
	injectCmd := exec.Command("kubectl", "exec", "-i", "daemonset/portal-node-agent", "-c", "nri-plugin", "--",
		"service-portal-nri-plugin", "bind-service", "inject-secrets", "--socket", "/run/service-portal/bind.sock", "--uid", clientUID, "--secrets-file", "-")
	injectCmd.Stdin = strings.NewReader(secretJSON)
	injectOut, err := injectCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to inject secrets for pod %s via service-portal-nri-plugin bind-service inject-secrets: %v (output: %s)", clientUID, err, injectOut)
	}
	t.Logf("Successfully injected secrets for pod %s via node agent bind-service", clientUID)

	// 9. Assert standard egress deny suite and positive controls succeed when bound
	runEgressDeniedAssertions(t, h, clientPodName, backendIPv4ClusterIP, "backend", "unlisted-backend")
	runNRIPositiveControls(t, h, clientPodName, "backend", "gemini-nri-token")

	// Bounded DNS assertion: query for unlisted name via cluster DNS must fail (NXDOMAIN)
	t.Run("ClusterDNS_UnlistedHost_Denied", func(t *testing.T) {
		cmdProbe := exec.Command("kubectl", "exec", clientPodName, "-c", "workload", "--",
			"/app/toolbox", "probe", "dns", "cluster", "unlisted-backend", "3s")
		outProbe, errProbe := cmdProbe.CombinedOutput()
		if errProbe == nil {
			t.Fatalf("expected unlisted DNS probe for unlisted-backend to fail, but it succeeded: %s", outProbe)
		}
		t.Logf("unlisted DNS probe for unlisted-backend failed as expected: %v (output: %s)", errProbe, outProbe)

		cmdNslookup := exec.Command("kubectl", "exec", clientPodName, "-c", "workload", "--",
			"nslookup", "unlisted-backend")
		outNslookup, errNslookup := cmdNslookup.CombinedOutput()
		if errNslookup == nil {
			t.Fatalf("expected unlisted nslookup for unlisted-backend to fail, but it succeeded: %s", outNslookup)
		}
		t.Logf("unlisted nslookup for unlisted-backend failed as expected: %v (output: %s)", errNslookup, outNslookup)
	})

	if h.IsDualStack() {
		runNRIDualStackAssertions(t, h, clientPodName, backendIPv6ClusterIP)
	}

	// 10. Assert proxy logs carry the pod namespace/name
	t.Run("ProxyLogsCarryPodIdentity", func(t *testing.T) {
		nodeAgentLogs := h.GetPodLogsByLabel("app=portal-node-agent", "proxy")
		if !strings.Contains(nodeAgentLogs, "Caller: default/"+clientPodName) {
			t.Fatalf("proxy logs missing expected caller pod 'Caller: default/%s':\n%s", clientPodName, nodeAgentLogs)
		}
		t.Logf("proxy logs correctly carry pod identity: default/%s", clientPodName)
	})

	// 11. Required direct-to-proxy deny case 1:
	// Opted-in bound pod connecting directly to <proxyHost>:8080 with a Host it is not entitled to is denied
	t.Run("DirectToProxy_OptedInPod_UnentitledHost_Denied", func(t *testing.T) {
		cmd := exec.Command("kubectl", "exec", clientPodName, "-c", "workload", "--",
			"wget", "-T", "5", "-qO-", "--header=Host: unlisted-backend", fmt.Sprintf("http://%s:8080/direct-unentitled", nodeIP))
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("expected direct connection to proxy with unentitled host to be denied, but succeeded: %s", out)
		}
		t.Logf("direct connection to proxy with unentitled host denied as expected: %v (output: %s)", err, out)
	})

	// 12. Required direct-to-proxy deny case 2:
	// Non-opted-in pod on the same node connecting directly to the proxy port is denied
	t.Run("DirectToProxy_NonOptedInPod_Denied", func(t *testing.T) {
		nonOptedPodName := "test-client-non-opted"
		h.DeletePod(nonOptedPodName)
		nonOptedManifest := `
apiVersion: v1
kind: Pod
metadata:
  name: test-client-non-opted
  labels:
    app: test-client-non-opted
spec:
  containers:
  - name: workload
    image: toolbox:e2e
    imagePullPolicy: Never
    securityContext:
      runAsUser: 1000
      allowPrivilegeEscalation: false
    command: ["/bin/sh", "-c", "sleep 3600"]
`
		h.KubectlApplyContent(nonOptedManifest)
		h.WaitForPodReady("app=test-client-non-opted", 2*time.Minute)
		defer h.DeletePod(nonOptedPodName)

		cmd := exec.Command("kubectl", "exec", nonOptedPodName, "-c", "workload", "--",
			"wget", "-T", "5", "-qO-", fmt.Sprintf("http://%s:8080/direct-from-non-opted", nodeIP))
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("expected non-opted-in pod connection to proxy to be denied, but succeeded: %s", out)
		}
		t.Logf("non-opted-in pod connection to proxy denied as expected: %v (output: %s)", err, out)
	})

	// 13. Restart proxy container and assert binding and secret resolution persist across restart
	t.Run("ProxyRestart_RetainsBindings", func(t *testing.T) {
		nodeContainer := fmt.Sprintf("%s-control-plane", h.ClusterName)
		cmdGetID := exec.Command("docker", "exec", nodeContainer, "crictl", "ps", "--name", "proxy", "-q")
		outGetID, err := cmdGetID.CombinedOutput()
		if err != nil {
			t.Fatalf("failed to get proxy container ID via crictl: %v (output: %s)", err, outGetID)
		}
		proxyContainerID := strings.TrimSpace(string(outGetID))
		if proxyContainerID == "" {
			t.Fatalf("no running proxy container found on node %s", nodeContainer)
		}

		t.Logf("Restarting proxy container %s on %s", proxyContainerID, nodeContainer)
		cmdStop := exec.Command("docker", "exec", nodeContainer, "crictl", "stop", proxyContainerID)
		if outStop, err := cmdStop.CombinedOutput(); err != nil {
			t.Fatalf("failed to stop proxy container %s: %v (output: %s)", proxyContainerID, err, outStop)
		}

		h.WaitForPodReady("app=portal-node-agent", 2*time.Minute)

		// Assert positive controls still succeed with swapped credentials without re-binding
		runNRIPositiveControls(t, h, clientPodName, "backend", "gemini-nri-token")
		t.Logf("Positive controls successfully passed after proxy container restart")
	})

	// 14. Unbind the pod and assert same request is then rejected
	t.Run("Unbind_RevertsToDenied", func(t *testing.T) {
		unbindCmd := exec.Command("kubectl", "exec", "-i", "daemonset/portal-node-agent", "-c", "nri-plugin", "--",
			"service-portal-nri-plugin", "bind-service", "unbind", "--socket", "/run/service-portal/bind.sock", "--uid", clientUID)
		unbindOut, err := unbindCmd.CombinedOutput()
		if err != nil {
			t.Fatalf("failed to unbind pod %s via service-portal-nri-plugin bind-service unbind: %v (output: %s)", clientUID, err, unbindOut)
		}
		t.Logf("Successfully unbound pod %s via node agent bind-service: %s", clientUID, unbindOut)

		cmdHTTP := exec.Command("kubectl", "exec", clientPodName, "-c", "workload", "--",
			"wget", "-T", "5", "-qO-", "--header=Authorization: placeholder-token", "http://backend/positive-control-http")
		outHTTP, errHTTP := cmdHTTP.CombinedOutput()
		if errHTTP == nil {
			t.Fatalf("expected HTTP request after unbind to be denied, but succeeded: %s", outHTTP)
		}
		t.Logf("HTTP request after unbind denied as expected: %v (output: %s)", errHTTP, outHTTP)

		cmdHTTPS := exec.Command("kubectl", "exec", clientPodName, "-c", "workload", "--",
			"wget", "--ca-certificate=/etc/service-portal/ca/tls.crt", "-T", "5", "-qO-", "--header=Authorization: placeholder-token", "https://backend/positive-control-https")
		outHTTPS, errHTTPS := cmdHTTPS.CombinedOutput()
		if errHTTPS == nil {
			t.Fatalf("expected HTTPS request after unbind to be denied, but succeeded: %s", outHTTPS)
		}
		t.Logf("HTTPS request after unbind denied as expected: %v (output: %s)", errHTTPS, outHTTPS)
	})

	// 15. Controller E2E: bind a pod through the Service Portal Controller deployed from k8s/controller.yaml
	controllerPodName := "test-client-controller"
	h.DeletePod(controllerPodName)
	t.Cleanup(func() {
		h.DeletePod(controllerPodName)
	})

	controllerClientPodManifest := fmt.Sprintf(`
apiVersion: v1
kind: Pod
metadata:
  name: %s
  labels:
    app: %s
    service-portal.gke.io/intercept: "true"
spec:
%s  containers:
  - name: workload
    image: toolbox:e2e
    imagePullPolicy: Never
    securityContext:
      runAsUser: 1000
      allowPrivilegeEscalation: false
    command: ["/bin/sh", "-c", "sleep 3600"]
`, controllerPodName, controllerPodName, runtimeClassField)
	h.KubectlApplyContent(controllerClientPodManifest)
	h.WaitForPodReady("app="+controllerPodName, 2*time.Minute)

	cmdCtrlUID := exec.Command("kubectl", "get", "pod", controllerPodName, "-o", "jsonpath={.metadata.uid}")
	outCtrlUID, err := cmdCtrlUID.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to get controller client pod UID: %v (output: %s)", err, outCtrlUID)
	}
	controllerPodUID := strings.TrimSpace(string(outCtrlUID))

	portForwardCtx, cancelPortForward := context.WithCancel(context.Background())
	t.Cleanup(cancelPortForward)

	controllerAddr, cleanupForward, err := startPortForward(portForwardCtx, "service-portal-system", "svc/service-portal-controller")
	if err != nil {
		t.Fatalf("failed to start port-forward to controller: %v", err)
	}
	t.Cleanup(cleanupForward)

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(controllerCACert)
	tlsCreds := credentials.NewTLS(&tls.Config{
		RootCAs:    caPool,
		ServerName: "service-portal-controller.service-portal-system.svc",
	})
	conn, err := grpc.NewClient(controllerAddr, grpc.WithTransportCredentials(tlsCreds))
	if err != nil {
		t.Fatalf("failed to dial controller at %s: %v", controllerAddr, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	bindClient := portalsv1.NewPodBindServiceClient(conn)

	authorizedToken := getServiceAccountToken(t, allowedClientSA, controllerAudience, "default")
	unauthorizedToken := getServiceAccountToken(t, unauthorizedClientSA, controllerAudience, "default")

	authCtx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+authorizedToken))
	unauthCtx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+unauthorizedToken))

	policyProto := &portalsv1.EgressPolicy{}
	if err := protojson.Unmarshal([]byte(policyJSON), policyProto); err != nil {
		t.Fatalf("failed to unmarshal policyJSON: %v", err)
	}

	// Subtest: a pod with no binding is denied (fail closed)
	t.Run("Controller_UnboundPod_Denied", func(t *testing.T) {
		cmd := exec.Command("kubectl", "exec", controllerPodName, "-c", "workload", "--",
			"wget", "-T", "5", "-qO-", "http://backend/controller-unbound-check")
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("expected unbound pod request through controller to be denied, but succeeded: %s", out)
		}
		t.Logf("unbound pod request denied as expected: %v (output: %s)", err, out)
	})

	// Subtest: a client whose service account is not on the allowlist gets PermissionDenied and the pod stays denied
	t.Run("Controller_UnauthorizedClient_PermissionDenied_PodStaysDenied", func(t *testing.T) {
		ctrlPolicy := &portalsv1.PodPolicy{
			PodUid:   controllerPodUID,
			Identity: "unauthorized-user",
			Policy:   policyProto,
			Wait:     true,
		}
		_, err := bindClient.Bind(unauthCtx, ctrlPolicy)
		if err == nil {
			t.Fatal("expected unauthorized client Bind to fail, but succeeded")
		}
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("expected PermissionDenied for unauthorized client, got %v: %v", status.Code(err), err)
		}
		t.Logf("unauthorized client Bind rejected with PermissionDenied as expected: %v", err)

		// Assert pod stays denied
		cmd := exec.Command("kubectl", "exec", controllerPodName, "-c", "workload", "--",
			"wget", "-T", "5", "-qO-", "http://backend/controller-unauth-check")
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("expected pod to stay denied after unauthorized Bind attempt, but succeeded: %s", out)
		}
		t.Logf("pod stayed denied after unauthorized Bind attempt: %v (output: %s)", err, out)
	})

	// Subtest: Bind then InjectSecrets, each with wait, end in accepted
	const controllerSecret = "controller-secret-token"
	t.Run("Controller_BindAndInjectSecrets_Accepted", func(t *testing.T) {
		ctrlPolicy := &portalsv1.PodPolicy{
			PodUid:   controllerPodUID,
			Identity: "test-user-controller",
			Policy:   policyProto,
			Wait:     true,
		}
		bindResp, err := bindClient.Bind(authCtx, ctrlPolicy)
		if err != nil {
			t.Fatalf("Bind with wait failed: %v", err)
		}
		if !bindResp.GetBound() {
			t.Fatalf("expected Bind with wait to report bound=true, got bound=%v", bindResp.GetBound())
		}
		if bindResp.GetStatus() != portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_PENDING {
			t.Fatalf("expected Bind with wait to report PENDING (awaiting secrets), got %v", bindResp.GetStatus())
		}
		if want := []string{"backend-token"}; !slices.Equal(bindResp.GetMissingSecrets(), want) {
			t.Fatalf("expected missing secrets %v after Bind with wait, got %v", want, bindResp.GetMissingSecrets())
		}
		t.Logf("Bind with wait completed successfully (status: %v, missing: %v)", bindResp.GetStatus(), bindResp.GetMissingSecrets())

		secretsReq := &portalsv1.PodSecrets{
			PodUid: controllerPodUID,
			Secrets: map[string][]byte{
				"backend-token": []byte(controllerSecret),
			},
			Wait: true,
		}
		injectResp, err := bindClient.InjectSecrets(authCtx, secretsReq)
		if err != nil {
			t.Fatalf("InjectSecrets with wait failed: %v", err)
		}
		if injectResp.GetStatus() != portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_ACCEPTED {
			t.Fatalf("expected InjectSecrets with wait to end in ACCEPTED, got %v (refusal: %s)", injectResp.GetStatus(), injectResp.GetRefusalReason())
		}
		if len(injectResp.GetMissingSecrets()) != 0 {
			t.Fatalf("expected no missing secrets after InjectSecrets with wait, got %v", injectResp.GetMissingSecrets())
		}
		t.Logf("InjectSecrets with wait ended in ACCEPTED as expected")
	})

	// Subtest: that pod's request reaches the backend with the placeholder replaced
	t.Run("Controller_BoundPod_RequestReachesBackend_CredentialSwapped", func(t *testing.T) {
		cmdHTTP := exec.Command("kubectl", "exec", controllerPodName, "-c", "workload", "--",
			"wget", "-T", "5", "-qO-", "--header=Authorization: placeholder-token", "http://backend/controller-positive-http")
		outHTTP, errHTTP := cmdHTTP.CombinedOutput()
		if errHTTP != nil {
			t.Fatalf("HTTP request from controller-bound pod failed: %v (output: %s)", errHTTP, outHTTP)
		}
		if !strings.Contains(string(outHTTP), "Bearer "+controllerSecret) {
			t.Fatalf("HTTP response missing injected credential")
		}
		if strings.Contains(string(outHTTP), "placeholder-token") {
			t.Fatalf("HTTP response still contains placeholder token")
		}

		cmdHTTPS := exec.Command("kubectl", "exec", controllerPodName, "-c", "workload", "--",
			"wget", "--ca-certificate=/etc/service-portal/ca/tls.crt", "-T", "5", "-qO-", "--header=Authorization: placeholder-token", "https://backend/controller-positive-https")
		outHTTPS, errHTTPS := cmdHTTPS.CombinedOutput()
		if errHTTPS != nil {
			t.Fatalf("HTTPS request from controller-bound pod failed: %v (output: %s)", errHTTPS, outHTTPS)
		}
		if !strings.Contains(string(outHTTPS), "Bearer "+controllerSecret) {
			t.Fatalf("HTTPS response missing injected credential")
		}
		if strings.Contains(string(outHTTPS), "placeholder-token") {
			t.Fatalf("HTTPS response still contains placeholder token")
		}

		backendLogs := h.GetDeploymentLogs("backend")
		if !strings.Contains(backendLogs, "/controller-positive-http") {
			t.Fatalf("backend access log missing /controller-positive-http")
		}
		if !strings.Contains(backendLogs, "/controller-positive-https") {
			t.Fatalf("backend access log missing /controller-positive-https")
		}
		t.Logf("verified backend received swapped credentials for both HTTP and HTTPS")
	})

	// Subtest: Unbind with wait returns the pod to denied
	t.Run("Controller_Unbind_RevertsToDenied", func(t *testing.T) {
		unbindResp, err := bindClient.Unbind(authCtx, &portalsv1.UnbindRequest{
			PodUid: controllerPodUID,
			Wait:   true,
		})
		if err != nil {
			t.Fatalf("Unbind with wait failed: %v", err)
		}
		if unbindResp.GetBound() {
			t.Fatalf("expected Unbind with wait to report bound=false, got bound=%v", unbindResp.GetBound())
		}
		if unbindResp.GetStatus() != portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_ACCEPTED {
			t.Fatalf("expected Unbind with wait to end in ACCEPTED, got %v", unbindResp.GetStatus())
		}
		t.Logf("Unbind with wait completed successfully (status: %v)", unbindResp.GetStatus())

		// Verify requests from pod are now denied
		cmdHTTP := exec.Command("kubectl", "exec", controllerPodName, "-c", "workload", "--",
			"wget", "-T", "5", "-qO-", "--header=Authorization: placeholder-token", "http://backend/controller-http-after-unbind")
		outHTTP, errHTTP := cmdHTTP.CombinedOutput()
		if errHTTP == nil {
			t.Fatalf("expected HTTP request after controller unbind to be denied, but succeeded: %s", outHTTP)
		}
		t.Logf("HTTP request after controller unbind denied as expected: %v (output: %s)", errHTTP, outHTTP)

		cmdHTTPS := exec.Command("kubectl", "exec", controllerPodName, "-c", "workload", "--",
			"wget", "--ca-certificate=/etc/service-portal/ca/tls.crt", "-T", "5", "-qO-", "--header=Authorization: placeholder-token", "https://backend/controller-https-after-unbind")
		outHTTPS, errHTTPS := cmdHTTPS.CombinedOutput()
		if errHTTPS == nil {
			t.Fatalf("expected HTTPS request after controller unbind to be denied, but succeeded: %s", outHTTPS)
		}
		t.Logf("HTTPS request after controller unbind denied as expected: %v (output: %s)", errHTTPS, outHTTPS)
	})
}

func runNRIDualStackAssertions(t *testing.T, h *Harness, clientPodName, backendIPv6ClusterIP string) {
	if backendIPv6ClusterIP == "" {
		t.Fatalf("runNRIDualStackAssertions called on dual-stack cluster but backendIPv6ClusterIP is empty")
	}

	t.Run("DirectIPv6_InterceptedPort_HTTP", func(t *testing.T) {
		cmd := exec.Command("kubectl", "exec", clientPodName, "-c", "workload", "--",
			"wget", "-T", "5", "-qO-", "http://["+backendIPv6ClusterIP+"]:80/direct-ipv6-http")
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("expected direct IPv6 HTTP request to fail, but it succeeded: %s", out)
		}
		t.Logf("direct IPv6 HTTP request failed as expected: %v (output: %s)", err, out)

		backendLogs := h.GetDeploymentLogs("backend")
		if strings.Contains(backendLogs, "/direct-ipv6-http") {
			t.Fatalf("backend access log contains /direct-ipv6-http, request unexpectedly reached backend")
		}
	})

	t.Run("DirectIPv6_InterceptedPort_HTTPS", func(t *testing.T) {
		cmd := exec.Command("kubectl", "exec", clientPodName, "-c", "workload", "--",
			"wget", "-T", "5", "--ca-certificate=/etc/service-portal/ca/tls.crt", "-qO-", "https://["+backendIPv6ClusterIP+"]:443/direct-ipv6-https")
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("expected direct IPv6 HTTPS request to fail, but it succeeded: %s", out)
		}
		t.Logf("direct IPv6 HTTPS request failed as expected: %v (output: %s)", err, out)

		backendLogs := h.GetDeploymentLogs("backend")
		if strings.Contains(backendLogs, "/direct-ipv6-https") {
			t.Fatalf("backend access log contains /direct-ipv6-https, request unexpectedly reached backend")
		}
	})

	t.Run("NonInterceptedPort_IPv6_HTTP_8080", func(t *testing.T) {
		cmd := exec.Command("kubectl", "exec", clientPodName, "-c", "workload", "--",
			"wget", "-T", "5", "-qO-", "http://["+backendIPv6ClusterIP+"]:8080/non-intercepted-ipv6-8080")
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("expected non-intercepted port IPv6 HTTP request to fail, but it succeeded: %s", out)
		}
		t.Logf("non-intercepted port IPv6 HTTP request failed as expected: %v (output: %s)", err, out)

		backendLogs := h.GetDeploymentLogs("backend")
		if strings.Contains(backendLogs, "/non-intercepted-ipv6-8080") {
			t.Fatalf("backend access log contains /non-intercepted-ipv6-8080, request unexpectedly reached backend")
		}
	})

	t.Run("NonInterceptedPort_IPv6_RawTCP_9999", func(t *testing.T) {
		cmd := exec.Command("kubectl", "exec", clientPodName, "-c", "workload", "--",
			"/app/toolbox", "probe", "tcp", "["+backendIPv6ClusterIP+"]:9999", "3s")
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("expected raw TCP connection to IPv6 port 9999 to fail, but it succeeded: %s", out)
		}
		t.Logf("raw TCP connection to IPv6 port 9999 failed as expected: %v (output: %s)", err, out)
	})

	t.Run("NeighbourDiscovery_Functional", func(t *testing.T) {
		cmdRoute := exec.Command("kubectl", "exec", clientPodName, "-c", "workload", "--",
			"ip", "-6", "route", "show", "default")
		outRoute, errRoute := cmdRoute.CombinedOutput()
		if errRoute != nil {
			t.Logf("could not query default IPv6 route: %v (output: %s)", errRoute, outRoute)
		} else {
			t.Logf("default IPv6 route: %s", strings.TrimSpace(string(outRoute)))
		}
	})
}
