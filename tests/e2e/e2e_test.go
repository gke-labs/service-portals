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
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestServicePortal(t *testing.T) {
	if os.Getenv("E2E") == "" {
		t.Skip("E2E env var not set, skipping")
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

	// Deploy Service Portal
	portalManifest := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: service-portal
  labels:
    app: service-portal
spec:
  replicas: 1
  selector:
    matchLabels:
      app: service-portal
  template:
    metadata:
      labels:
        app: service-portal
    spec:
      containers:
      - name: service-portal
        image: service-portal:e2e
        imagePullPolicy: Never
        env:
        - name: TARGET_URL
          value: "http://backend"
        - name: UPSTREAM_AUTH_TOKEN
          value: "e2e-secret-token"
        ports:
        - containerPort: 8080
---
apiVersion: v1
kind: Service
metadata:
  name: service-portal
spec:
  selector:
    app: service-portal
  ports:
  - port: 80
    targetPort: 8080
`
	h.KubectlApplyContent(portalManifest)
	h.WaitForDeployment("service-portal", 2*time.Minute)

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
    command: ["/app/toolbox", "client", "http://service-portal"]
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
