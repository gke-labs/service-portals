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
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/gke-labs/service-portals/pkg/apis/portals/v1alpha1"
	"github.com/gke-labs/service-portals/pkg/portals"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

type mapSecretGetter map[string]*corev1.Secret

func (m mapSecretGetter) GetSecret(_ context.Context, namespace, name string) (*corev1.Secret, error) {
	key := fmt.Sprintf("%s/%s", namespace, name)
	sec, ok := m[key]
	if !ok {
		return nil, fmt.Errorf("secret not found")
	}
	return sec, nil
}

func TestResolveSuccess(t *testing.T) {
	ctx := t.Context()

	secrets := mapSecretGetter{
		"sandboxes/github-creds": &corev1.Secret{
			Data: map[string][]byte{
				"token": []byte("gh-secret-token-123"),
			},
		},
		"sandboxes/gemini-creds": &corev1.Secret{
			StringData: map[string]string{
				"apiKey": "gemini-api-key-456",
			},
		},
	}

	policy := &v1alpha1.PortalPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "sandboxes",
		},
		Spec: v1alpha1.PortalPolicySpec{
			Rules: []v1alpha1.PortalPolicyRule{
				{
					Host:       "github.backend",
					RewriteURL: "https://api.github.com",
					AuthHeader: "Authorization",
					SecretRef: &v1alpha1.SecretKeyRef{
						Name: "github-creds",
						Key:  "token",
					},
				},
				{
					Host:       "gemini.backend",
					RewriteURL: "https://generativelanguage.googleapis.com",
					AuthHeader: "x-goog-api-key",
					SecretRef: &v1alpha1.SecretKeyRef{
						Name: "gemini-creds",
						Key:  "apiKey",
					},
					CacheTTL: "10m",
				},
			},
			Egress: &v1alpha1.EgressConfig{
				DefaultAction: v1alpha1.EgressActionDeny,
				AllowCIDRs:    []string{"10.0.0.0/8", "172.16.0.0/12"},
				AllowPorts:    []int32{8080, 9090},
				DNS: &v1alpha1.DNSConfig{
					Servers:       []string{"10.96.0.10"},
					AllowMetadata: true,
				},
			},
			Intercept: &v1alpha1.InterceptConfig{
				Ports: []int32{80, 443, 8000},
			},
			Proxy: &v1alpha1.ProxyConfig{
				Image: "custom-proxy:v1",
				Resources: corev1.ResourceRequirements{
					Limits: corev1.ResourceList{
						corev1.ResourceMemory: resource.MustParse("256Mi"),
					},
				},
			},
		},
	}

	cfg, err := Resolve(ctx, policy, secrets)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}

	// Verify rules YAML
	if len(cfg.RulesYAML) != 2 {
		t.Fatalf("Expected 2 rule YAMLs, got %d", len(cfg.RulesYAML))
	}

	ghYAML, ok := cfg.RulesYAML["github-backend.yaml"]
	if !ok {
		t.Fatalf("Missing github-backend.yaml in RulesYAML: %v", cfg.RulesYAML)
	}
	var ghRule portals.PortalRule
	if err := yaml.Unmarshal([]byte(ghYAML), &ghRule); err != nil {
		t.Fatalf("Failed to unmarshal ghRule: %v", err)
	}
	if ghRule.Spec.AuthToken != "gh-secret-token-123" {
		t.Errorf("Unexpected gh token: %s", ghRule.Spec.AuthToken)
	}
	if ghRule.Spec.Host != "github.backend" {
		t.Errorf("Unexpected gh host: %s", ghRule.Spec.Host)
	}

	geminiYAML, ok := cfg.RulesYAML["gemini-backend.yaml"]
	if !ok {
		t.Fatalf("Missing gemini-backend.yaml in RulesYAML: %v", cfg.RulesYAML)
	}
	var geminiRule portals.PortalRule
	if err := yaml.Unmarshal([]byte(geminiYAML), &geminiRule); err != nil {
		t.Fatalf("Failed to unmarshal geminiRule: %v", err)
	}
	if geminiRule.Spec.AuthToken != "gemini-api-key-456" {
		t.Errorf("Unexpected gemini token: %s", geminiRule.Spec.AuthToken)
	}
	if geminiRule.Spec.CacheTTL != "10m" {
		t.Errorf("Unexpected cacheTTL: %s", geminiRule.Spec.CacheTTL)
	}

	// Verify HostAliases
	if len(cfg.HostAliases) != 1 {
		t.Fatalf("Expected 1 hostAlias, got %d", len(cfg.HostAliases))
	}
	if cfg.HostAliases[0].IP != "8.8.8.8" {
		t.Errorf("Expected hostAlias IP 8.8.8.8, got %s", cfg.HostAliases[0].IP)
	}
	expectedHosts := []string{"gemini.backend", "github.backend"}
	if strings.Join(cfg.HostAliases[0].Hostnames, ",") != strings.Join(expectedHosts, ",") {
		t.Errorf("Unexpected hostnames: %v", cfg.HostAliases[0].Hostnames)
	}

	// Verify InitEnv
	envMap := make(map[string]string)
	for _, env := range cfg.InitEnv {
		envMap[env.Name] = env.Value
	}
	if envMap["INTERCEPT_PORTS"] != "80,443,8000" {
		t.Errorf("Unexpected INTERCEPT_PORTS: %s", envMap["INTERCEPT_PORTS"])
	}
	if envMap["ALLOW_CIDRS"] != "10.0.0.0/8,172.16.0.0/12" {
		t.Errorf("Unexpected ALLOW_CIDRS: %s", envMap["ALLOW_CIDRS"])
	}
	if envMap["ALLOW_PORTS"] != "8080,9090" {
		t.Errorf("Unexpected ALLOW_PORTS: %s", envMap["ALLOW_PORTS"])
	}
	if envMap["DNS_SERVER_IPS"] != "10.96.0.10" {
		t.Errorf("Unexpected DNS_SERVER_IPS: %s", envMap["DNS_SERVER_IPS"])
	}
	if envMap["ALLOW_METADATA"] != "true" {
		t.Errorf("Unexpected ALLOW_METADATA: %s", envMap["ALLOW_METADATA"])
	}

	// Verify Proxy Image and Resources
	if cfg.ProxyImage != "custom-proxy:v1" {
		t.Errorf("Unexpected ProxyImage: %s", cfg.ProxyImage)
	}
	if _, ok := cfg.ProxyResources.Limits[corev1.ResourceMemory]; !ok {
		t.Errorf("Missing memory limit in ProxyResources")
	}
}

func TestResolveErrors(t *testing.T) {
	ctx := t.Context()

	t.Run("nil policy", func(t *testing.T) {
		_, err := Resolve(ctx, nil, nil)
		if err == nil {
			t.Fatal("Expected error for nil policy")
		}
	})

	t.Run("missing host", func(t *testing.T) {
		p := &v1alpha1.PortalPolicy{
			Spec: v1alpha1.PortalPolicySpec{
				Rules: []v1alpha1.PortalPolicyRule{
					{Host: ""},
				},
			},
		}
		_, err := Resolve(ctx, p, nil)
		if err == nil || !strings.Contains(err.Error(), "missing required field 'host'") {
			t.Fatalf("Expected missing host error, got: %v", err)
		}
	})

	t.Run("secret not found", func(t *testing.T) {
		p := &v1alpha1.PortalPolicy{
			ObjectMeta: metav1.ObjectMeta{Namespace: "ns1"},
			Spec: v1alpha1.PortalPolicySpec{
				Rules: []v1alpha1.PortalPolicyRule{
					{
						Host: "test.com",
						SecretRef: &v1alpha1.SecretKeyRef{
							Name: "missing-sec",
							Key:  "tok",
						},
					},
				},
			},
		}
		secrets := mapSecretGetter{}
		_, err := Resolve(ctx, p, secrets)
		if err == nil || !strings.Contains(err.Error(), "failed to get secret") {
			t.Fatalf("Expected secret not found error, got: %v", err)
		}
	})

	t.Run("key not found in secret", func(t *testing.T) {
		p := &v1alpha1.PortalPolicy{
			ObjectMeta: metav1.ObjectMeta{Namespace: "ns1"},
			Spec: v1alpha1.PortalPolicySpec{
				Rules: []v1alpha1.PortalPolicyRule{
					{
						Host: "test.com",
						SecretRef: &v1alpha1.SecretKeyRef{
							Name: "my-sec",
							Key:  "wrong-key",
						},
					},
				},
			},
		}
		secrets := mapSecretGetter{
			"ns1/my-sec": &corev1.Secret{
				Data: map[string][]byte{"other-key": []byte("abc")},
			},
		}
		_, err := Resolve(ctx, p, secrets)
		if err == nil || !strings.Contains(err.Error(), "key \"wrong-key\" not found") {
			t.Fatalf("Expected key not found error, got: %v", err)
		}
	})
}
