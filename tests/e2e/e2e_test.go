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
	"fmt"
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

func TestInjectedSidecar(t *testing.T) {
	if os.Getenv("RUN_E2E") == "" {
		t.Skip("RUN_E2E env var not set, skipping")
	}

	h := NewHarness(t, "injected-sidecar-e2e")
	h.Setup()

	gitRoot := h.GetGitRoot()

	// Build and load all required images
	h.DockerBuild("portal-injector:e2e", filepath.Join(gitRoot, "images/portal-injector/Dockerfile"), gitRoot)
	h.DockerBuild("all-in-one-portal:e2e", filepath.Join(gitRoot, "images/all-in-one-portal/Dockerfile"), gitRoot)
	h.DockerBuild("init-service-portals:e2e", filepath.Join(gitRoot, "images/init-service-portals/Dockerfile"), gitRoot)
	h.DockerBuild("toolbox:e2e", filepath.Join(gitRoot, "tests/toolbox/Dockerfile"), filepath.Join(gitRoot, "tests/toolbox"))

	h.KindLoad("portal-injector:e2e")
	h.KindLoad("all-in-one-portal:e2e")
	h.KindLoad("init-service-portals:e2e")
	h.KindLoad("toolbox:e2e")

	// Install cert-manager
	h.t.Log("Installing cert-manager")
	h.RunCommand("kubectl", "apply", "--server-side", "-f", "https://github.com/cert-manager/cert-manager/releases/download/v1.19.2/cert-manager.yaml")
	time.Sleep(10 * time.Second)
	h.WaitForPodReady("app.kubernetes.io/instance=cert-manager", 3*time.Minute)

	// Apply CRD
	crdPath := filepath.Join(gitRoot, "k8s/crds/portals.gke.io_portalpolicies.yaml")
	h.RunCommand("kubectl", "apply", "-f", crdPath)

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
	time.Sleep(5 * time.Second)

	// Deploy Injector manifests
	h.RunCommand("kubectl", "apply", "-f", filepath.Join(gitRoot, "k8s/injector/rbac.yaml"))
	h.RunCommand("kubectl", "apply", "-f", filepath.Join(gitRoot, "k8s/injector/certificate.yaml"))
	h.RunCommand("kubectl", "apply", "-f", filepath.Join(gitRoot, "k8s/injector/service.yaml"))
	h.RunCommand("kubectl", "apply", "-f", filepath.Join(gitRoot, "k8s/injector/webhooks.yaml"))

	injectorDeploy := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: portal-injector
  namespace: service-portals
  labels:
    app: portal-injector
spec:
  replicas: 1
  selector:
    matchLabels:
      app: portal-injector
  template:
    metadata:
      labels:
        app: portal-injector
    spec:
      serviceAccountName: portal-injector
      containers:
      - name: injector
        image: portal-injector:e2e
        imagePullPolicy: Never
        args:
        - "--listen-addr=:8443"
        - "--tls-cert-file=/etc/webhook/certs/tls.crt"
        - "--tls-key-file=/etc/webhook/certs/tls.key"
        - "--native-sidecars=true"
        - "--default-init-image=init-service-portals:e2e"
        - "--default-proxy-image=all-in-one-portal:e2e"
        - "--dummy-ip=8.8.8.8"
        ports:
        - containerPort: 8443
          name: webhook
        readinessProbe:
          httpGet:
            path: /healthz
            port: 8443
            scheme: HTTPS
          initialDelaySeconds: 2
          periodSeconds: 5
        volumeMounts:
        - name: webhook-certs
          mountPath: /etc/webhook/certs
          readOnly: true
      volumes:
      - name: webhook-certs
        secret:
          secretName: portal-injector-webhook-cert
`
	h.KubectlApplyContent(injectorDeploy)
	h.RunCommand("kubectl", "rollout", "status", "deployment/portal-injector", "-n", "service-portals", "--timeout=2m")
	time.Sleep(5 * time.Second)

	// Create test namespace with injection enabled
	testNS := "test-injected"
	_ = exec.Command("kubectl", "create", "namespace", testNS).Run()
	h.RunCommand("kubectl", "label", "namespace", testNS, "portals.gke.io/injection=enabled", "--overwrite")

	// Create Secrets for token resolution
	h.KubectlApplyContent(fmt.Sprintf(`
apiVersion: v1
kind: Secret
metadata:
  name: gemini-creds
  namespace: %s
stringData:
  token: gemini-injected-token
---
apiVersion: v1
kind: Secret
metadata:
  name: github-creds
  namespace: %s
stringData:
  token: github-injected-token
`, testNS, testNS))

	// Apply PortalPolicy
	h.KubectlApplyContent(fmt.Sprintf(`
apiVersion: portals.gke.io/v1alpha1
kind: PortalPolicy
metadata:
  name: test-injected-policy
  namespace: %s
spec:
  podSelector:
    matchLabels:
      app: agent
  rules:
  - host: gemini.backend
    rewriteUrl: http://backend.default.svc.cluster.local
    authHeader: Authorization
    secretRef:
      name: gemini-creds
      key: token
  - host: github.backend
    rewriteUrl: http://backend.default.svc.cluster.local
    authHeader: Authorization
    secretRef:
      name: github-creds
      key: token
  intercept:
    ports: [80, 443]
`, testNS))

	// 1. Validation test: Attempt to create an invalid pod (running as user 1337) -> MUST be rejected!
	invalidPodManifest := fmt.Sprintf(`
apiVersion: v1
kind: Pod
metadata:
  name: invalid-pod
  namespace: %s
  labels:
    app: agent
spec:
  containers:
  - name: workload
    image: toolbox:e2e
    imagePullPolicy: Never
    securityContext:
      runAsUser: 1337
      runAsNonRoot: true
      allowPrivilegeEscalation: false
    command: ["sleep", "10"]
`, testNS)
	cmdInvalid := exec.Command("kubectl", "apply", "-f", "-")
	cmdInvalid.Stdin = strings.NewReader(invalidPodManifest)
	outInvalid, err := cmdInvalid.CombinedOutput()
	if err == nil {
		t.Fatalf("Expected invalid pod (runAsUser: 1337) to be rejected by webhook, but succeeded: %s", outInvalid)
	}
	t.Logf("Invalid pod successfully rejected: %s", outInvalid)
	if !strings.Contains(string(outInvalid), "1337") {
		t.Errorf("Expected rejection message to mention 1337, got: %s", outInvalid)
	}

	// 2. Deploy PLAIN workload pod: contains NO portal-specific bits at all!
	clientPodName := "test-workload"
	_ = exec.Command("kubectl", "delete", "pod", clientPodName, "-n", testNS, "--ignore-not-found").Run()

	plainPodManifest := fmt.Sprintf(`
apiVersion: v1
kind: Pod
metadata:
  name: %s
  namespace: %s
  labels:
    app: agent
spec:
  containers:
  - name: workload
    image: toolbox:e2e
    imagePullPolicy: Never
    securityContext:
      runAsNonRoot: true
      runAsUser: 1000
      allowPrivilegeEscalation: false
    command: ["/bin/sh", "-c", "sleep 3600"]
`, clientPodName, testNS)

	h.KubectlApplyContent(plainPodManifest)
	h.RunCommand("kubectl", "wait", "--namespace", testNS, "--for=condition=Ready", "pod/"+clientPodName, "--timeout=2m")

	// Verify pod annotations were added
	outAnno, err := exec.Command("kubectl", "get", "pod", clientPodName, "-n", testNS, "-o", "jsonpath={.metadata.annotations.portals\\.gke\\.io/status}").Output()
	if err != nil || string(outAnno) != "injected" {
		t.Fatalf("Expected pod annotation portals.gke.io/status=injected, got: %s (err: %v)", outAnno, err)
	}

	// Positive Control: HTTP and HTTPS requests to gemini.backend and github.backend
	cmdGemini := exec.Command("kubectl", "exec", clientPodName, "-n", testNS, "-c", "workload", "--", "wget", "-qO-", "http://gemini.backend")
	outGemini, err := cmdGemini.CombinedOutput()
	if err != nil {
		t.Fatalf("Gemini HTTP request failed: %v. Output: %s", err, outGemini)
	}
	if !strings.Contains(string(outGemini), "Bearer gemini-injected-token") {
		t.Errorf("Gemini HTTP Logs do not contain injected token: %s", outGemini)
	}

	cmdGeminiHTTPS := exec.Command("kubectl", "exec", clientPodName, "-n", testNS, "-c", "workload", "--", "wget", "-qO-", "https://gemini.backend")
	outGeminiHTTPS, err := cmdGeminiHTTPS.CombinedOutput()
	if err != nil {
		t.Fatalf("Gemini HTTPS request failed: %v. Output: %s", err, outGeminiHTTPS)
	}
	if !strings.Contains(string(outGeminiHTTPS), "Bearer gemini-injected-token") {
		t.Errorf("Gemini HTTPS Logs do not contain injected token: %s", outGeminiHTTPS)
	}

	cmdGithub := exec.Command("kubectl", "exec", clientPodName, "-n", testNS, "-c", "workload", "--", "wget", "-qO-", "http://github.backend")
	outGithub, err := cmdGithub.CombinedOutput()
	if err != nil {
		t.Fatalf("GitHub HTTP request failed: %v. Output: %s", err, outGithub)
	}
	if !strings.Contains(string(outGithub), "Bearer github-injected-token") {
		t.Errorf("GitHub HTTP Logs do not contain injected token: %s", outGithub)
	}

	cmdGithubHTTPS := exec.Command("kubectl", "exec", clientPodName, "-n", testNS, "-c", "workload", "--", "wget", "-qO-", "https://github.backend")
	outGithubHTTPS, err := cmdGithubHTTPS.CombinedOutput()
	if err != nil {
		t.Fatalf("GitHub HTTPS request failed: %v. Output: %s", err, outGithubHTTPS)
	}
	if !strings.Contains(string(outGithubHTTPS), "Bearer github-injected-token") {
		t.Errorf("GitHub HTTPS Logs do not contain injected token: %s", outGithubHTTPS)
	}

	// Deny assertions (#147):
	// 1. Non-intercepted port: wget to port 8080 should fail
	cmdNonIntercept := exec.Command("kubectl", "exec", clientPodName, "-n", testNS, "-c", "workload", "--", "wget", "-T", "3", "http://backend.default.svc.cluster.local:8080/")
	outNonIntercept, err := cmdNonIntercept.CombinedOutput()
	if err == nil {
		t.Errorf("Expected non-intercepted port connection to fail, but succeeded: %s", outNonIntercept)
	} else {
		t.Logf("Non-intercepted port correctly failed: %v (%s)", err, outNonIntercept)
	}

	// 2. Bypass attempt: workload runs as UID 1000 and cannot run as UID 1337
	cmdBypass := exec.Command("kubectl", "exec", clientPodName, "-n", testNS, "-c", "workload", "--", "id", "-u")
	outBypass, err := cmdBypass.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to check user ID: %v", err)
	}
	if strings.TrimSpace(string(outBypass)) != "1000" {
		t.Errorf("Expected workload UID to be 1000, got: %s", outBypass)
	}
}
