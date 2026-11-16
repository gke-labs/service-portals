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

package policy

import (
	"strings"
	"testing"

	"github.com/gke-labs/service-portals/pkg/apis/portals/v1alpha1"
	"github.com/gke-labs/service-portals/pkg/portals"
	"sigs.k8s.io/yaml"
)

func TestResolve_ProposedExample(t *testing.T) {
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
    image: "custom-proxy:v1"
    resources:
      limits:
        cpu: "500m"
`

	var policy v1alpha1.PortalPolicy
	if err := yaml.Unmarshal([]byte(rawYAML), &policy); err != nil {
		t.Fatalf("failed to unmarshal policy: %v", err)
	}

	secrets := MapSecretGetter{
		"sandboxes/github-creds": {
			"token": "ghp_secret_token_12345",
		},
		"sandboxes/gemini-creds": {
			"apiKey": "AIzaSy_secret_api_key_67890",
		},
	}

	cfg, err := Resolve(policy, secrets)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}

	// Verify Rules
	if len(cfg.Rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(cfg.Rules))
	}

	r0 := cfg.Rules[0]
	if r0.Spec.Host != "github.backend" || r0.Spec.AuthToken != "ghp_secret_token_12345" || r0.Spec.AuthHeader != "Authorization" {
		t.Errorf("unexpected rule 0: %+v", r0)
	}

	r1 := cfg.Rules[1]
	if r1.Spec.Host != "gemini.backend" || r1.Spec.AuthToken != "AIzaSy_secret_api_key_67890" || r1.Spec.AuthHeader != "x-goog-api-key" || r1.Spec.CacheTTL != "10m" {
		t.Errorf("unexpected rule 1: %+v", r1)
	}

	// Verify RuleDocuments
	if len(cfg.RuleDocuments) != 2 {
		t.Fatalf("expected 2 rule documents, got %d", len(cfg.RuleDocuments))
	}

	for docName, docContent := range cfg.RuleDocuments {
		var pr portals.PortalRule
		if err := yaml.Unmarshal([]byte(docContent), &pr); err != nil {
			t.Errorf("failed to unmarshal document %s: %v", docName, err)
		}
		if pr.Kind != "PortalRule" {
			t.Errorf("document %s has kind %q, want PortalRule", docName, pr.Kind)
		}
	}

	// Verify HostAliases
	if len(cfg.HostAliases) != 1 {
		t.Fatalf("expected 1 HostAlias, got %d", len(cfg.HostAliases))
	}
	if cfg.HostAliases[0].IP != DefaultDummyIP {
		t.Errorf("expected dummy IP %s, got %s", DefaultDummyIP, cfg.HostAliases[0].IP)
	}
	expectedHosts := []string{"gemini.backend", "github.backend"}
	if len(cfg.HostAliases[0].Hostnames) != 2 ||
		cfg.HostAliases[0].Hostnames[0] != expectedHosts[0] ||
		cfg.HostAliases[0].Hostnames[1] != expectedHosts[1] {
		t.Errorf("hostnames = %v, want %v", cfg.HostAliases[0].Hostnames, expectedHosts)
	}

	// Verify InitEnv
	if cfg.InitEnv["INTERCEPT_PORTS"] != "80,443" {
		t.Errorf("INTERCEPT_PORTS = %q, want 80,443", cfg.InitEnv["INTERCEPT_PORTS"])
	}
	if cfg.InitEnv["ALLOW_METADATA"] != "false" {
		t.Errorf("ALLOW_METADATA = %q, want false", cfg.InitEnv["ALLOW_METADATA"])
	}
	if cfg.InitEnv["EGRESS_ACTION"] != "REJECT" {
		t.Errorf("EGRESS_ACTION = %q, want REJECT", cfg.InitEnv["EGRESS_ACTION"])
	}

	// Verify ProxyEnv and Overrides
	if cfg.ProxyEnv["DEFAULT_ACTION"] != "Deny" {
		t.Errorf("DEFAULT_ACTION = %q, want Deny", cfg.ProxyEnv["DEFAULT_ACTION"])
	}
	if cfg.ProxyImage != "custom-proxy:v1" {
		t.Errorf("ProxyImage = %q, want custom-proxy:v1", cfg.ProxyImage)
	}
	if cfg.ProxyResources == nil {
		t.Errorf("expected ProxyResources to be set")
	}
}

func TestResolve_SecretNotFound(t *testing.T) {
	policy := v1alpha1.PortalPolicy{
		Metadata: v1alpha1.ObjectMeta{Namespace: "default"},
		Spec: v1alpha1.PortalPolicySpec{
			Rules: []v1alpha1.PolicyRule{
				{
					Host: "example.com",
					SecretRef: v1alpha1.SecretKeyRef{
						Name: "nonexistent",
						Key:  "token",
					},
				},
			},
		},
	}

	secrets := MapSecretGetter{}
	_, err := Resolve(policy, secrets)
	if err == nil {
		t.Fatalf("expected error for missing secret, got nil")
	}
	if !strings.Contains(err.Error(), "failed to resolve secret") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestResolve_EmptySecretToken(t *testing.T) {
	policy := v1alpha1.PortalPolicy{
		Metadata: v1alpha1.ObjectMeta{Namespace: "default"},
		Spec: v1alpha1.PortalPolicySpec{
			Rules: []v1alpha1.PolicyRule{
				{
					Host: "example.com",
					SecretRef: v1alpha1.SecretKeyRef{
						Name: "empty-secret",
						Key:  "token",
					},
				},
			},
		},
	}

	secrets := MapSecretGetter{
		"default/empty-secret": {
			"token": "",
		},
	}
	_, err := Resolve(policy, secrets)
	if err == nil {
		t.Fatalf("expected error for empty token, got nil")
	}
	if !strings.Contains(err.Error(), "empty token") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestResolve_NilSecrets(t *testing.T) {
	policy := v1alpha1.PortalPolicy{
		Spec: v1alpha1.PortalPolicySpec{
			Rules: []v1alpha1.PolicyRule{
				{
					Host: "example.com",
					SecretRef: v1alpha1.SecretKeyRef{
						Name: "test",
						Key:  "key",
					},
				},
			},
		},
	}

	_, err := Resolve(policy, nil)
	if err == nil {
		t.Fatalf("expected error for nil secrets getter")
	}
}

func TestResolve_InvalidPolicy(t *testing.T) {
	policy := v1alpha1.PortalPolicy{
		Spec: v1alpha1.PortalPolicySpec{
			Rules: []v1alpha1.PolicyRule{
				{
					Host: "invalid:hostname",
				},
			},
		},
	}

	secrets := MapSecretGetter{}
	_, err := Resolve(policy, secrets)
	if err == nil {
		t.Fatalf("expected validation error, got nil")
	}
	if !strings.Contains(err.Error(), "invalid policy") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestResolve_EgressConfig(t *testing.T) {
	policy := v1alpha1.PortalPolicy{
		Metadata: v1alpha1.ObjectMeta{Namespace: "default"},
		Spec: v1alpha1.PortalPolicySpec{
			Rules: []v1alpha1.PolicyRule{
				{
					Host: "api.example.com",
					SecretRef: v1alpha1.SecretKeyRef{
						Name: "my-secret",
						Key:  "token",
					},
				},
			},
			Egress: v1alpha1.EgressConfig{
				DefaultAction: "Allow",
				AllowCIDRs:    []string{"10.0.0.0/8", "172.16.0.0/12"},
				AllowPorts:    []int{8080, 9000},
				DNS: v1alpha1.DNSConfig{
					Servers:       []string{"10.96.0.10", "1.1.1.1"},
					AllowMetadata: true,
				},
			},
			Intercept: v1alpha1.InterceptConfig{
				Ports: []int{80, 443, 8443},
			},
		},
	}

	secrets := MapSecretGetter{
		"default/my-secret": {"token": "secret123"},
	}

	opts := Options{DummyIP: "192.0.2.1"}
	cfg, err := ResolveWithOptions(policy, secrets, opts)
	if err != nil {
		t.Fatalf("ResolveWithOptions failed: %v", err)
	}

	if cfg.HostAliases[0].IP != "192.0.2.1" {
		t.Errorf("HostAliases IP = %q, want 192.0.2.1", cfg.HostAliases[0].IP)
	}

	if cfg.InitEnv["INTERCEPT_PORTS"] != "80,443,8443" {
		t.Errorf("INTERCEPT_PORTS = %q", cfg.InitEnv["INTERCEPT_PORTS"])
	}
	if cfg.InitEnv["ALLOW_CIDRS"] != "10.0.0.0/8,172.16.0.0/12" {
		t.Errorf("ALLOW_CIDRS = %q", cfg.InitEnv["ALLOW_CIDRS"])
	}
	if cfg.InitEnv["ALLOW_PORTS"] != "8080,9000" {
		t.Errorf("ALLOW_PORTS = %q", cfg.InitEnv["ALLOW_PORTS"])
	}
	if cfg.InitEnv["DNS_SERVER_IPS"] != "10.96.0.10,1.1.1.1" {
		t.Errorf("DNS_SERVER_IPS = %q", cfg.InitEnv["DNS_SERVER_IPS"])
	}
	if cfg.InitEnv["ALLOW_METADATA"] != "true" {
		t.Errorf("ALLOW_METADATA = %q, want true", cfg.InitEnv["ALLOW_METADATA"])
	}
	if cfg.ProxyEnv["DEFAULT_ACTION"] != "Allow" {
		t.Errorf("DEFAULT_ACTION = %q, want Allow", cfg.ProxyEnv["DEFAULT_ACTION"])
	}

	// Check env list helpers
	initList := cfg.InitEnvList()
	if len(initList) < 5 {
		t.Errorf("expected at least 5 init env vars, got %d", len(initList))
	}
	// Verify sorted
	for i := 1; i < len(initList); i++ {
		if initList[i-1].Name >= initList[i].Name {
			t.Errorf("InitEnvList not sorted: %s >= %s", initList[i-1].Name, initList[i].Name)
		}
	}
}
