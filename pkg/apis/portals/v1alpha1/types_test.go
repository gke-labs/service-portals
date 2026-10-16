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

package v1alpha1

import (
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/yaml"
)

func TestPortalPolicyYAMLRoundtrip(t *testing.T) {
	manifest := `apiVersion: portals.gke.io/v1alpha1
kind: PortalPolicy
metadata:
  name: agent-sandbox
  namespace: sandboxes
spec:
  podSelector:
    matchLabels:
      app: agent
  rules:
  - host: github.backend
    rewriteUrl: https://api.github.com
    authHeader: Authorization
    secretRef:
      name: github-creds
      key: token
  - host: gemini.backend
    rewriteUrl: https://generativelanguage.googleapis.com
    authHeader: x-goog-api-key
    secretRef:
      name: gemini-creds
      key: apiKey
    cacheTTL: 10m
  egress:
    defaultAction: Deny
    allowCIDRs:
    - 10.0.0.0/8
    allowPorts:
    - 53
    dns:
      servers:
      - 10.96.0.10
      allowMetadata: false
  intercept:
    ports:
    - 80
    - 443
  proxy:
    image: all-in-one-portal:latest
`

	var policy PortalPolicy
	if err := yaml.Unmarshal([]byte(manifest), &policy); err != nil {
		t.Fatalf("Failed to unmarshal PortalPolicy: %v", err)
	}

	if policy.Name != "agent-sandbox" || policy.Namespace != "sandboxes" {
		t.Errorf("Unexpected metadata: %s/%s", policy.Namespace, policy.Name)
	}
	if len(policy.Spec.Rules) != 2 {
		t.Fatalf("Expected 2 rules, got %d", len(policy.Spec.Rules))
	}
	if policy.Spec.Rules[0].Host != "github.backend" {
		t.Errorf("Unexpected rule host: %s", policy.Spec.Rules[0].Host)
	}
	if policy.Spec.Egress.DefaultAction != EgressActionDeny {
		t.Errorf("Unexpected default action: %s", policy.Spec.Egress.DefaultAction)
	}

	// Test DeepCopy
	copied := policy.DeepCopy()
	if copied == nil || copied.Name != policy.Name {
		t.Fatalf("DeepCopy failed")
	}

	// Test runtime.Object implementation
	var obj runtime.Object = copied
	if obj.GetObjectKind().GroupVersionKind() != policy.GetObjectKind().GroupVersionKind() {
		t.Errorf("GetObjectKind mismatch")
	}
}
