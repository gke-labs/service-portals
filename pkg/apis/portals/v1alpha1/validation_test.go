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
	"os"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

func TestIsValidHostname(t *testing.T) {
	tests := []struct {
		host  string
		valid bool
	}{
		{"github.backend", true},
		{"api.github.com", true},
		{"generativelanguage.googleapis.com", true},
		{"simple", true},
		{"host-with-hyphens.example.com", true},
		{"a.b.c", true},
		{"", false},
		{"-leading-hyphen.com", false},
		{"trailing-hyphen-.com", false},
		{"has..double-dot.com", false},
		{"has:port:8080", false},
		{"https://with-scheme.com", false},
		{"with/path", false},
		{"with spaces.com", false},
		{strings.Repeat("a", 64) + ".com", false},
		{strings.Repeat("a.", 130), false},
	}

	for _, tt := range tests {
		got := IsValidHostname(tt.host)
		if got != tt.valid {
			t.Errorf("IsValidHostname(%q) = %v, want %v", tt.host, got, tt.valid)
		}
	}
}

func TestLabelSelectorMatches(t *testing.T) {
	ls := &LabelSelector{
		MatchLabels: map[string]string{
			"app": "agent",
			"env": "prod",
		},
		MatchExpressions: []LabelSelectorRequirement{
			{
				Key:      "tier",
				Operator: LabelSelectorOpIn,
				Values:   []string{"frontend", "backend"},
			},
			{
				Key:      "quarantine",
				Operator: LabelSelectorOpDoesNotExist,
			},
		},
	}

	tests := []struct {
		name    string
		labels  map[string]string
		matches bool
	}{
		{
			name: "exact match",
			labels: map[string]string{
				"app":  "agent",
				"env":  "prod",
				"tier": "frontend",
			},
			matches: true,
		},
		{
			name: "missing matchLabels",
			labels: map[string]string{
				"app":  "agent",
				"tier": "frontend",
			},
			matches: false,
		},
		{
			name: "wrong matchLabel value",
			labels: map[string]string{
				"app":  "agent",
				"env":  "dev",
				"tier": "frontend",
			},
			matches: false,
		},
		{
			name: "NotIn match expression fails",
			labels: map[string]string{
				"app":  "agent",
				"env":  "prod",
				"tier": "database",
			},
			matches: false,
		},
		{
			name: "quarantine exists",
			labels: map[string]string{
				"app":        "agent",
				"env":        "prod",
				"tier":       "frontend",
				"quarantine": "true",
			},
			matches: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ls.Matches(tt.labels)
			if got != tt.matches {
				t.Errorf("Matches() = %v, want %v", got, tt.matches)
			}
		})
	}

	// Test nil selector matches all
	var nilSelector *LabelSelector
	if !nilSelector.Matches(map[string]string{"foo": "bar"}) {
		t.Errorf("nil selector should match any labels")
	}

	// Test NotIn and Exists
	exprSelector := &LabelSelector{
		MatchExpressions: []LabelSelectorRequirement{
			{
				Key:      "role",
				Operator: LabelSelectorOpNotIn,
				Values:   []string{"admin"},
			},
			{
				Key:      "zone",
				Operator: LabelSelectorOpExists,
			},
		},
	}

	if !exprSelector.Matches(map[string]string{"role": "user", "zone": "us-central1"}) {
		t.Errorf("expected match")
	}
	if exprSelector.Matches(map[string]string{"role": "admin", "zone": "us-central1"}) {
		t.Errorf("did not expect match when role is admin")
	}
	if exprSelector.Matches(map[string]string{"role": "user"}) {
		t.Errorf("did not expect match when zone is missing")
	}
}

func TestValidatePortalPolicy(t *testing.T) {
	validPolicy := &PortalPolicy{
		APIVersion: "portals.gke.io/v1alpha1",
		Kind:       "PortalPolicy",
		Metadata: ObjectMeta{
			Name:      "test-policy",
			Namespace: "default",
		},
		Spec: PortalPolicySpec{
			PodSelector: LabelSelector{
				MatchLabels: map[string]string{"app": "agent"},
			},
			Rules: []PolicyRule{
				{
					Host:       "github.backend",
					RewriteURL: "https://api.github.com",
					AuthHeader: "Authorization",
					SecretRef: SecretKeyRef{
						Name: "github-creds",
						Key:  "token",
					},
					CacheTTL: "5m",
				},
			},
			Egress: EgressConfig{
				DefaultAction: DefaultActionDeny,
				AllowCIDRs:    []string{"10.0.0.0/8"},
				AllowPorts:    []int{443, 80},
				DNS: DNSConfig{
					Servers:       []string{"10.96.0.10"},
					AllowMetadata: false,
				},
			},
			Intercept: InterceptConfig{
				Ports: []int{80, 443},
			},
		},
	}

	if err := Validate(validPolicy); err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}

	// Test invalid cases
	invalidPolicy := &PortalPolicy{
		Spec: PortalPolicySpec{
			Rules: []PolicyRule{
				{
					Host: "bad:host",
				},
			},
			Egress: EgressConfig{
				DefaultAction: "InvalidAction",
				AllowCIDRs:    []string{"invalid-cidr"},
				AllowPorts:    []int{999999},
				DNS: DNSConfig{
					Servers: []string{"not-an-ip"},
				},
			},
			Intercept: InterceptConfig{
				Ports: []int{0},
			},
		},
	}

	err := Validate(invalidPolicy)
	if err == nil {
		t.Fatalf("expected validation error, got nil")
	}
	errMsg := err.Error()
	expectedSubstrings := []string{
		"not a valid hostname",
		"secretRef.name is required",
		"secretRef.key is required",
		"defaultAction must be",
		"not a valid CIDR",
		"allowPorts[0] 999999 must be between 1 and 65535",
		"not a valid IP address",
		"intercept.ports[0] 0 must be between 1 and 65535",
	}
	for _, sub := range expectedSubstrings {
		if !strings.Contains(errMsg, sub) {
			t.Errorf("expected error message to contain %q, but got: %s", sub, errMsg)
		}
	}
}

func TestUnmarshalProposedYAML(t *testing.T) {
	rawYAML := `
apiVersion: portals.gke.io/v1alpha1
kind: PortalPolicy
metadata:
  name: agent-sandbox
  namespace: sandboxes
spec:
  podSelector:
    matchLabels: { app: agent }
  rules:
  - host: github.backend
    rewriteUrl: https://api.github.com
    authHeader: Authorization
    secretRef: { name: github-creds, key: token }
  - host: gemini.backend
    rewriteUrl: https://generativelanguage.googleapis.com
    authHeader: x-goog-api-key
    secretRef: { name: gemini-creds, key: apiKey }
    cacheTTL: 10m
  egress:
    defaultAction: Deny
    allowCIDRs: []
    allowPorts: []
    dns:
      servers: []
      allowMetadata: false
  intercept:
    ports: [80, 443]
  proxy:
    image: ""
    resources: {}
`

	var policy PortalPolicy
	if err := yaml.Unmarshal([]byte(rawYAML), &policy); err != nil {
		t.Fatalf("failed to unmarshal YAML: %v", err)
	}

	if policy.Metadata.Name != "agent-sandbox" || policy.Metadata.Namespace != "sandboxes" {
		t.Errorf("unexpected metadata: %+v", policy.Metadata)
	}
	if len(policy.Spec.Rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(policy.Spec.Rules))
	}
	if policy.Spec.Rules[0].Host != "github.backend" {
		t.Errorf("unexpected host: %s", policy.Spec.Rules[0].Host)
	}
	if policy.Spec.Rules[0].SecretRef.Name != "github-creds" || policy.Spec.Rules[0].SecretRef.Key != "token" {
		t.Errorf("unexpected secretRef: %+v", policy.Spec.Rules[0].SecretRef)
	}
	if policy.Spec.Egress.DefaultAction != DefaultActionDeny {
		t.Errorf("unexpected defaultAction: %s", policy.Spec.Egress.DefaultAction)
	}

	if err := Validate(&policy); err != nil {
		t.Fatalf("validation failed for proposed YAML: %v", err)
	}
}

func TestCRDManifestValidity(t *testing.T) {
	manifestPath := "../../../../k8s/crds/portals.gke.io_portalpolicies.yaml"
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("failed to read CRD manifest %s: %v", manifestPath, err)
	}

	var crd map[string]any
	if err := yaml.Unmarshal(data, &crd); err != nil {
		t.Fatalf("failed to parse CRD manifest YAML: %v", err)
	}

	if crd["kind"] != "CustomResourceDefinition" {
		t.Errorf("expected kind CustomResourceDefinition, got %v", crd["kind"])
	}

	metadata, ok := crd["metadata"].(map[string]any)
	if !ok || metadata["name"] != "portalpolicies.portals.gke.io" {
		t.Errorf("expected metadata.name portalpolicies.portals.gke.io, got %v", metadata["name"])
	}
}
