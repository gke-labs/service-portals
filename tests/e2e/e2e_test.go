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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestServicePortal(t *testing.T) {
	if os.Getenv("RUN_E2E") == "" {
		t.Skip("RUN_E2E env var not set, skipping")
	}

	h := NewHarness(t, "service-portal-e2e")
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
    command: ["/app/toolbox", "client", "https://backend"]
    env:
    - name: HTTPS_PROXY
      value: "http://service-portal:80"
    - name: SSL_CERT_FILE
      value: "/etc/ssl/certs/service-portal-ca.crt"
    volumeMounts:
    - name: ca-cert
      mountPath: /etc/ssl/certs/service-portal-ca.crt
      subPath: tls.crt
  volumes:
  - name: ca-cert
    secret:
      secretName: service-portal-ca
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

func TestAllInOnePortal(t *testing.T) {
	if os.Getenv("RUN_E2E") == "" {
		t.Skip("RUN_E2E env var not set, skipping")
	}

	h := NewHarness(t, "all-in-one-portal-e2e")
	h.Setup()

	gitRoot := h.GetGitRoot()

	// Paths relative to git root
	h.DockerBuild("all-in-one-portal:e2e", filepath.Join(gitRoot, "images/all-in-one-portal/Dockerfile"), gitRoot)
	h.DockerBuild("toolbox:e2e", filepath.Join(gitRoot, "tests/toolbox/Dockerfile"), filepath.Join(gitRoot, "tests/toolbox"))

	h.KindLoad("all-in-one-portal:e2e")
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

	// Deploy All-In-One Portal
	h.KubectlApplyContent(`
apiVersion: v1
kind: Secret
metadata:
  name: all-in-one-portal-secret
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
  name: all-in-one-portal
  labels:
    app: all-in-one-portal
spec:
  replicas: 1
  selector:
    matchLabels:
      app: all-in-one-portal
  template:
    metadata:
      labels:
        app: all-in-one-portal
    spec:
      containers:
      - name: all-in-one-portal
        image: all-in-one-portal:e2e
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
          secretName: all-in-one-portal-secret
---
apiVersion: v1
kind: Service
metadata:
  name: all-in-one-portal
spec:
  selector:
    app: all-in-one-portal
  ports:
  - port: 80
    targetPort: 8080
    protocol: TCP
`
	h.KubectlApplyContent(portalManifest)
	h.WaitForDeployment("all-in-one-portal", 2*time.Minute)
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
    command: ["/bin/sh", "-c", "wget -qO- --header='Host: gemini.backend' http://all-in-one-portal:80"]
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
    command: ["/bin/sh", "-c", "wget -qO- --header='Host: github.backend' http://all-in-one-portal:80"]
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
	h.Setup()

	gitRoot := h.GetGitRoot()

	// Paths relative to git root
	h.DockerBuild("all-in-one-portal:e2e", filepath.Join(gitRoot, "images/all-in-one-portal/Dockerfile"), gitRoot)
	h.DockerBuild("init-service-portals:e2e", filepath.Join(gitRoot, "images/init-service-portals/Dockerfile"), gitRoot)
	h.DockerBuild("toolbox:e2e", filepath.Join(gitRoot, "tests/toolbox/Dockerfile"), filepath.Join(gitRoot, "tests/toolbox"))

	h.KindLoad("all-in-one-portal:e2e")
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
      host: api.github.com
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
  dnsPolicy: None
  dnsConfig:
    nameservers:
    - "127.0.0.1"
  securityContext:
    sysctls:
    - name: net.ipv4.ip_unprivileged_port_start
      value: "0"
  initContainers:
  - name: init-service-portals
    image: init-service-portals:e2e
    imagePullPolicy: Never
    env:
    - name: PROXY_PORT
      value: "80"
    - name: PROXY_HTTPS_PORT
      value: "443"
    - name: PROXY_UID
      value: "1337"
    - name: PROXY_BIND_ADDR
      value: "127.0.0.2"
    - name: INTERCEPT_PORTS
      value: "80,443"
    - name: DNS_SERVER_IPS
      value: "10.96.0.10"
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
    image: all-in-one-portal:e2e
    imagePullPolicy: Never
    securityContext:
      runAsUser: 1337
      runAsGroup: 1337
    env:
    - name: PORT
      value: "80"
    - name: HTTPS_PORT
      value: "443"
    - name: CA_CERT_PATH
      value: "/etc/service-portal/ca-private/tls.crt"
    - name: CA_KEY_PATH
      value: "/etc/service-portal/ca-private/tls.key"
    - name: PROXY_BIND_ADDR
      value: "127.0.0.2"
    - name: UPSTREAM_DNS_SERVERS
      value: "10.96.0.10"
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

	// Test GitHub request with real hostname api.github.com via sidecar DNS server (no hostAliases)
	cmdGithub := exec.Command("kubectl", "exec", clientPodName, "-c", "workload", "--", "wget", "-qO-", "http://api.github.com")
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

	// Test GitHub HTTPS request with real hostname api.github.com via sidecar DNS server (no hostAliases)
	cmdGithubHTTPS := exec.Command("kubectl", "exec", clientPodName, "-c", "workload", "--", "wget", "--ca-certificate=/etc/service-portal/ca/tls.crt", "-qO-", "https://api.github.com")
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

	// Test: arbitrary DNS to an external resolver (8.8.8.8) must be rejected
	cmdExternalDNS := exec.Command("kubectl", "exec", clientPodName, "-c", "workload", "--", "/app/toolbox", "probe", "dns", "8.8.8.8", "example.com", "2s")
	outExternalDNS, errExternalDNS := cmdExternalDNS.CombinedOutput()
	if errExternalDNS == nil {
		t.Errorf("Expected arbitrary DNS to 8.8.8.8:53 to fail, but it succeeded. Output: %s", outExternalDNS)
	} else {
		t.Logf("Arbitrary DNS to external resolver was correctly rejected: %v (%s)", errExternalDNS, strings.TrimSpace(string(outExternalDNS)))
	}

	// Test: unlisted host resolution via local sidecar DNS (127.0.0.1:53) returns NXDOMAIN / fails
	cmdUnlistedDNS := exec.Command("kubectl", "exec", clientPodName, "-c", "workload", "--", "/app/toolbox", "probe", "dns", "127.0.0.1", "unlisted.example.com", "2s")
	outUnlistedDNS, errUnlistedDNS := cmdUnlistedDNS.CombinedOutput()
	if errUnlistedDNS == nil {
		t.Errorf("Expected unlisted DNS query via local DNS to fail with NXDOMAIN, but it succeeded. Output: %s", outUnlistedDNS)
	} else {
		t.Logf("Unlisted domain was correctly rejected with NXDOMAIN: %v (%s)", errUnlistedDNS, strings.TrimSpace(string(outUnlistedDNS)))
	}
}

func TestSidecarEgressDenied(t *testing.T) {
	if os.Getenv("RUN_E2E") == "" {
		t.Skip("RUN_E2E env var not set, skipping")
	}

	h := NewHarness(t, "sidecar-egress-denied-e2e")
	h.Setup()

	gitRoot := h.GetGitRoot()

	// Paths relative to git root
	h.DockerBuild("all-in-one-portal:e2e", filepath.Join(gitRoot, "images/all-in-one-portal/Dockerfile"), gitRoot)
	h.DockerBuild("init-service-portals:e2e", filepath.Join(gitRoot, "images/init-service-portals/Dockerfile"), gitRoot)
	h.DockerBuild("toolbox:e2e", filepath.Join(gitRoot, "tests/toolbox/Dockerfile"), filepath.Join(gitRoot, "tests/toolbox"))

	h.KindLoad("all-in-one-portal:e2e")
	h.KindLoad("init-service-portals:e2e")
	h.KindLoad("toolbox:e2e")

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
  selector:
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

	backendClusterIP := h.GetServiceClusterIP("backend")
	t.Logf("Backend ClusterIP: %s", backendClusterIP)

	// Deploy Client Pod with Sidecar
	clientPodName := "test-client-sidecar-deny"
	h.DeletePod(clientPodName)

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
      rewriteUrl: http://backend
      authToken: github-sidecar-token
---
apiVersion: v1
kind: Pod
metadata:
  name: test-client-sidecar-deny
  labels:
    app: test-client-sidecar-deny
spec:
  hostAliases:
  - ip: "8.8.8.8"
    hostnames:
    - "gemini.backend"
    - "github.backend"
    - "other.backend"
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
    image: all-in-one-portal:e2e
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

	// Case 1: Direct IP, intercepted port (must fail and never reach backend)
	t.Run("DirectIP_InterceptedPort_HTTP", func(t *testing.T) {
		cmd := exec.Command("kubectl", "exec", clientPodName, "-c", "workload", "--",
			"wget", "-T", "5", "-qO-", "http://"+backendClusterIP+":80/direct-ip-http")
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
			"wget", "-T", "5", "--ca-certificate=/etc/service-portal/ca/tls.crt", "-qO-", "https://"+backendClusterIP+":443/direct-ip-https")
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
			"wget", "-T", "5", "-qO-", "http://other.backend/unlisted-http")
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
			"wget", "-T", "5", "--ca-certificate=/etc/service-portal/ca/tls.crt", "-qO-", "https://other.backend/unlisted-https")
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
			"wget", "-T", "5", "-qO-", "http://backend:8080/non-intercepted-8080")
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
			"/app/toolbox", "probe", "tcp", backendClusterIP+":9999", "3s")
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("expected raw TCP connection to port 9999 to fail, but it succeeded: %s", out)
		}
		t.Logf("raw TCP connection to port 9999 failed as expected: %v (output: %s)", err, out)
	})

	// Case 4: Arbitrary DNS (must fail, but cluster DNS resolution must work)
	t.Run("ArbitraryDNS_Blocked", func(t *testing.T) {
		// Probe external DNS server (8.8.8.8) using toolbox probe
		cmdProbe := exec.Command("kubectl", "exec", clientPodName, "-c", "workload", "--",
			"/app/toolbox", "probe", "dns", "8.8.8.8", "example.com", "3s")
		outProbe, errProbe := cmdProbe.CombinedOutput()
		if errProbe == nil {
			t.Fatalf("expected DNS probe to 8.8.8.8 to fail, but it succeeded: %s", outProbe)
		}
		t.Logf("toolbox probe dns to 8.8.8.8 failed as expected: %v (output: %s)", errProbe, outProbe)

		// Also assert nslookup against 8.8.8.8 fails
		cmdNslookup := exec.Command("kubectl", "exec", clientPodName, "-c", "workload", "--",
			"nslookup", "example.com", "8.8.8.8")
		outNslookup, errNslookup := cmdNslookup.CombinedOutput()
		if errNslookup == nil {
			t.Fatalf("expected nslookup to 8.8.8.8 to fail, but it succeeded: %s", outNslookup)
		}
		t.Logf("nslookup to 8.8.8.8 failed as expected: %v (output: %s)", errNslookup, outNslookup)
	})

	t.Run("ClusterDNS_Allowed", func(t *testing.T) {
		// Probe cluster DNS resolution using toolbox probe
		cmdProbe := exec.Command("kubectl", "exec", clientPodName, "-c", "workload", "--",
			"/app/toolbox", "probe", "dns", "cluster", "backend", "5s")
		outProbe, errProbe := cmdProbe.CombinedOutput()
		if errProbe != nil {
			h.DumpDNSDiagnostics(clientPodName, "workload")
			t.Fatalf("expected cluster DNS probe to succeed, but failed: %v (output: %s)", errProbe, outProbe)
		}
		t.Logf("cluster DNS probe succeeded: %s", outProbe)

		// Assert nslookup via cluster DNS succeeds
		cmdNslookup := exec.Command("kubectl", "exec", clientPodName, "-c", "workload", "--",
			"nslookup", "backend")
		outNslookup, errNslookup := cmdNslookup.CombinedOutput()
		if errNslookup != nil {
			h.DumpDNSDiagnostics(clientPodName, "workload")
			t.Fatalf("expected cluster nslookup to succeed, but failed: %v (output: %s)", errNslookup, outNslookup)
		}
		t.Logf("cluster nslookup succeeded: %s", outNslookup)
	})

	// Case 5: Positive control in the same test (asserts health and rule functionality)
	t.Run("PositiveControl_GeminiHTTPS", func(t *testing.T) {
		cmd := exec.Command("kubectl", "exec", clientPodName, "-c", "workload", "--",
			"wget", "--ca-certificate=/etc/service-portal/ca/tls.crt", "-qO-", "https://gemini.backend/positive-control")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("positive control request failed: %v (output: %s)", err, out)
		}
		logs := string(out)
		t.Logf("positive control output: %s", logs)

		if !strings.Contains(logs, "Authorization") {
			t.Errorf("positive control output missing Authorization header: %s", logs)
		}
		if !strings.Contains(logs, "Bearer gemini-sidecar-token") {
			t.Errorf("positive control output missing expected token: %s", logs)
		}

		backendLogs := h.GetDeploymentLogs("backend")
		if !strings.Contains(backendLogs, "/positive-control") {
			t.Fatalf("backend access log missing /positive-control")
		}
	})

	// Case 6: Bypass attempt
	t.Run("BypassAttempt_Disallowed", func(t *testing.T) {
		// 1. Assert workload container UID is not 1337
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

		// 2. Directly assert allowPrivilegeEscalation: false via NoNewPrivs kernel flag
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

		// 3. Secondary signal: attempting to switch to proxy UID 1337 fails
		cmdSu := exec.Command("kubectl", "exec", clientPodName, "-c", "workload", "--",
			"su", "-", "1337", "-c", "id")
		outSu, errSu := cmdSu.CombinedOutput()
		if errSu == nil {
			t.Fatalf("expected su to UID 1337 to fail, but it succeeded: %s", outSu)
		}
		t.Logf("su to UID 1337 failed as expected: %v (output: %s)", errSu, outSu)
	})
}
