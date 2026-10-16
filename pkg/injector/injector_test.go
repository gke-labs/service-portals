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

package injector

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/gke-labs/service-portals/pkg/apis/portals/v1alpha1"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
)

type fakePolicyLister struct {
	policies map[string][]*v1alpha1.PortalPolicy
}

func (f *fakePolicyLister) ListPolicies(_ context.Context, namespace string) ([]*v1alpha1.PortalPolicy, error) {
	return f.policies[namespace], nil
}

type fakeNamespaceGetter struct {
	namespaces map[string]*corev1.Namespace
}

func (f *fakeNamespaceGetter) GetNamespace(_ context.Context, name string) (*corev1.Namespace, error) {
	return f.namespaces[name], nil
}

type fakeSecretManager struct {
	secrets map[string]*corev1.Secret
}

func (f *fakeSecretManager) GetSecret(_ context.Context, namespace, name string) (*corev1.Secret, error) {
	key := fmt.Sprintf("%s/%s", namespace, name)
	sec, ok := f.secrets[key]
	if !ok {
		return nil, fmt.Errorf("secret not found")
	}
	return sec, nil
}

func (f *fakeSecretManager) CreateOrUpdateSecret(_ context.Context, namespace string, secret *corev1.Secret) error {
	if f.secrets == nil {
		f.secrets = make(map[string]*corev1.Secret)
	}
	key := fmt.Sprintf("%s/%s", namespace, secret.Name)
	f.secrets[key] = secret
	return nil
}

func representativePolicy() *v1alpha1.PortalPolicy {
	return &v1alpha1.PortalPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-policy",
			Namespace:  "sandboxes",
			Generation: 1,
			UID:        "pol-uid-1234",
		},
		Spec: v1alpha1.PortalPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": "agent",
				},
			},
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
			},
			Egress: &v1alpha1.EgressConfig{
				DefaultAction: v1alpha1.EgressActionDeny,
				AllowCIDRs:    []string{"10.0.0.0/8"},
				AllowPorts:    []int32{8080},
				DNS: &v1alpha1.DNSConfig{
					Servers: []string{"10.96.0.10"},
				},
			},
			Intercept: &v1alpha1.InterceptConfig{
				Ports: []int32{80, 443},
			},
		},
	}
}

func representativePod() *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "agent-pod",
			Namespace: "sandboxes",
			Labels: map[string]string{
				"app": "agent",
			},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "apps/v1",
					Kind:       "ReplicaSet",
					Name:       "agent-rs",
					UID:        "rs-uid-9999",
					Controller: ptr.To(true),
				},
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:  "workload",
					Image: "agent-image:latest",
					SecurityContext: &corev1.SecurityContext{
						RunAsNonRoot:             ptr.To(true),
						RunAsUser:                ptr.To(int64(1000)),
						AllowPrivilegeEscalation: ptr.To(false),
					},
				},
			},
		},
	}
}

func TestGoldenMutationPatch(t *testing.T) {
	ctx := t.Context()

	policy := representativePolicy()
	pod := representativePod()

	secrets := &fakeSecretManager{
		secrets: map[string]*corev1.Secret{
			"sandboxes/github-creds": {
				Data: map[string][]byte{"token": []byte("gh-token-secret")},
			},
		},
	}

	inj := &Injector{
		Policies: &fakePolicyLister{
			policies: map[string][]*v1alpha1.PortalPolicy{
				"sandboxes": {policy},
			},
		},
		Namespaces: &fakeNamespaceGetter{
			namespaces: map[string]*corev1.Namespace{
				"sandboxes": {
					ObjectMeta: metav1.ObjectMeta{
						Name:   "sandboxes",
						Labels: map[string]string{NamespaceLabelInjection: "enabled"},
					},
				},
			},
		},
		Secrets: secrets,
		Config: Config{
			NativeSidecars:    true,
			DefaultInitImage:  "init-service-portals:latest",
			DefaultProxyImage: "all-in-one-portal:latest",
			DummyIP:           "8.8.8.8",
		},
	}

	rawPod, err := json.Marshal(pod)
	if err != nil {
		t.Fatalf("Failed to marshal pod: %v", err)
	}

	req := &admissionv1.AdmissionRequest{
		UID:       "admission-uid-1",
		Namespace: "sandboxes",
		Object:    runtime.RawExtension{Raw: rawPod},
	}

	resp := inj.Mutate(ctx, req)
	if !resp.Allowed {
		t.Fatalf("Expected mutation allowed, got rejected: %s", resp.Result.Message)
	}

	if resp.PatchType == nil || *resp.PatchType != admissionv1.PatchTypeJSONPatch {
		t.Fatalf("Expected JSONPatch patchType, got %v", resp.PatchType)
	}

	var patches []PatchOperation
	if err := json.Unmarshal(resp.Patch, &patches); err != nil {
		t.Fatalf("Failed to parse patch: %v", err)
	}

	// Verify patch contains all required operations
	pathsFound := make(map[string]string)
	for _, p := range patches {
		pathsFound[p.Path] = p.Op
	}

	expectedPaths := []string{
		"/metadata/annotations",
		"/spec/initContainers",
		"/spec/containers",
		"/spec/volumes",
		"/spec/hostAliases",
	}

	for _, ep := range expectedPaths {
		if _, ok := pathsFound[ep]; !ok {
			t.Errorf("Expected patch operation for path %s, but not found in patches: %s", ep, string(resp.Patch))
		}
	}

	// Verify generated secret was created
	rulesSecName := "agent-rs-portal-rules-fbdc57ac"
	sec, err := secrets.GetSecret(ctx, "sandboxes", rulesSecName)
	if err != nil {
		t.Fatalf("Expected generated secret %s to exist, err: %v", rulesSecName, err)
	}
	if sec.StringData["github-backend.yaml"] == "" {
		t.Errorf("Expected secret data to contain github-backend.yaml")
	}
	if len(sec.OwnerReferences) == 0 || sec.OwnerReferences[0].Name != "agent-rs" {
		t.Errorf("Expected secret ownerRef to agent-rs, got %v", sec.OwnerReferences)
	}
}

func TestMutationWithCAEnvOptOut(t *testing.T) {
	ctx := t.Context()

	policy := representativePolicy()
	pod := representativePod()
	pod.Annotations = map[string]string{
		AnnotationInjectCAEnv: "false",
	}

	secrets := &fakeSecretManager{
		secrets: map[string]*corev1.Secret{
			"sandboxes/github-creds": {
				Data: map[string][]byte{"token": []byte("gh-token")},
			},
		},
	}

	inj := &Injector{
		Policies: &fakePolicyLister{
			policies: map[string][]*v1alpha1.PortalPolicy{"sandboxes": {policy}},
		},
		Namespaces: &fakeNamespaceGetter{
			namespaces: map[string]*corev1.Namespace{
				"sandboxes": {ObjectMeta: metav1.ObjectMeta{Name: "sandboxes", Labels: map[string]string{NamespaceLabelInjection: "enabled"}}},
			},
		},
		Secrets: secrets,
		Config:  Config{NativeSidecars: true},
	}

	rawPod, _ := json.Marshal(pod)
	req := &admissionv1.AdmissionRequest{
		UID:       "test-uid",
		Namespace: "sandboxes",
		Object:    runtime.RawExtension{Raw: rawPod},
	}

	resp := inj.Mutate(ctx, req)
	if !resp.Allowed {
		t.Fatalf("Mutation rejected: %s", resp.Result.Message)
	}

	var patches []PatchOperation
	_ = json.Unmarshal(resp.Patch, &patches)

	// In containers patch, verify SSL_CERT_FILE is NOT present
	for _, p := range patches {
		if p.Path == "/spec/containers" {
			containersBytes, _ := json.Marshal(p.Value)
			var containers []corev1.Container
			_ = json.Unmarshal(containersBytes, &containers)
			if len(containers) > 0 {
				for _, env := range containers[0].Env {
					if env.Name == "SSL_CERT_FILE" {
						t.Errorf("SSL_CERT_FILE should not be injected when inject-ca-env is false")
					}
				}
			}
		}
	}
}

func TestSelectionLogic(t *testing.T) {
	ctx := t.Context()
	policy := representativePolicy()

	secrets := &fakeSecretManager{
		secrets: map[string]*corev1.Secret{
			"sandboxes/github-creds": {Data: map[string][]byte{"token": []byte("tok")}},
		},
	}

	t.Run("opt out with inject false", func(t *testing.T) {
		pod := representativePod()
		pod.Annotations = map[string]string{AnnotationInject: "false"}

		inj := &Injector{
			Policies: &fakePolicyLister{policies: map[string][]*v1alpha1.PortalPolicy{"sandboxes": {policy}}},
			Namespaces: &fakeNamespaceGetter{
				namespaces: map[string]*corev1.Namespace{
					"sandboxes": {ObjectMeta: metav1.ObjectMeta{Name: "sandboxes", Labels: map[string]string{NamespaceLabelInjection: "enabled"}}},
				},
			},
			Secrets: secrets,
		}

		rawPod, _ := json.Marshal(pod)
		resp := inj.Mutate(ctx, &admissionv1.AdmissionRequest{UID: "u1", Namespace: "sandboxes", Object: runtime.RawExtension{Raw: rawPod}})
		if !resp.Allowed || len(resp.Patch) > 0 {
			t.Fatalf("Expected allowed without mutation for inject=false")
		}
	})

	t.Run("forced inject in unlabelled namespace", func(t *testing.T) {
		pod := representativePod()
		pod.Annotations = map[string]string{AnnotationInject: "true"}

		inj := &Injector{
			Policies: &fakePolicyLister{policies: map[string][]*v1alpha1.PortalPolicy{"sandboxes": {policy}}},
			Namespaces: &fakeNamespaceGetter{
				namespaces: map[string]*corev1.Namespace{
					"sandboxes": {ObjectMeta: metav1.ObjectMeta{Name: "sandboxes"}}, // NO injection label
				},
			},
			Secrets: secrets,
		}

		rawPod, _ := json.Marshal(pod)
		resp := inj.Mutate(ctx, &admissionv1.AdmissionRequest{UID: "u2", Namespace: "sandboxes", Object: runtime.RawExtension{Raw: rawPod}})
		if !resp.Allowed || len(resp.Patch) == 0 {
			t.Fatalf("Expected mutation when inject=true even without namespace label")
		}
	})

	t.Run("forced inject with no matching policy rejects", func(t *testing.T) {
		pod := representativePod()
		pod.Labels = map[string]string{"app": "unmatched"}
		pod.Annotations = map[string]string{AnnotationInject: "true"}

		inj := &Injector{
			Policies: &fakePolicyLister{policies: map[string][]*v1alpha1.PortalPolicy{"sandboxes": {policy}}},
			Namespaces: &fakeNamespaceGetter{
				namespaces: map[string]*corev1.Namespace{
					"sandboxes": {ObjectMeta: metav1.ObjectMeta{Name: "sandboxes"}},
				},
			},
			Secrets: secrets,
		}

		rawPod, _ := json.Marshal(pod)
		resp := inj.Mutate(ctx, &admissionv1.AdmissionRequest{UID: "u3", Namespace: "sandboxes", Object: runtime.RawExtension{Raw: rawPod}})
		if resp.Allowed {
			t.Fatalf("Expected rejection when forced inject has no matching policy")
		}
		if !strings.Contains(resp.Result.Message, "no PortalPolicy matches pod labels") {
			t.Errorf("Unexpected error message: %s", resp.Result.Message)
		}
	})

	t.Run("multiple matching policies rejects", func(t *testing.T) {
		policy2 := representativePolicy()
		policy2.Name = "second-policy"

		pod := representativePod()

		inj := &Injector{
			Policies: &fakePolicyLister{policies: map[string][]*v1alpha1.PortalPolicy{"sandboxes": {policy, policy2}}},
			Namespaces: &fakeNamespaceGetter{
				namespaces: map[string]*corev1.Namespace{
					"sandboxes": {ObjectMeta: metav1.ObjectMeta{Name: "sandboxes", Labels: map[string]string{NamespaceLabelInjection: "enabled"}}},
				},
			},
			Secrets: secrets,
		}

		rawPod, _ := json.Marshal(pod)
		resp := inj.Mutate(ctx, &admissionv1.AdmissionRequest{UID: "u4", Namespace: "sandboxes", Object: runtime.RawExtension{Raw: rawPod}})
		if resp.Allowed {
			t.Fatalf("Expected rejection when multiple policies match")
		}
		if !strings.Contains(resp.Result.Message, "multiple PortalPolicies matched pod") {
			t.Errorf("Unexpected error message: %s", resp.Result.Message)
		}
	})

	t.Run("already injected pod is idempotent", func(t *testing.T) {
		pod := representativePod()
		pod.Annotations = map[string]string{AnnotationStatus: StatusInjected}

		inj := &Injector{
			Policies: &fakePolicyLister{policies: map[string][]*v1alpha1.PortalPolicy{"sandboxes": {policy}}},
			Namespaces: &fakeNamespaceGetter{
				namespaces: map[string]*corev1.Namespace{
					"sandboxes": {ObjectMeta: metav1.ObjectMeta{Name: "sandboxes", Labels: map[string]string{NamespaceLabelInjection: "enabled"}}},
				},
			},
			Secrets: secrets,
		}

		rawPod, _ := json.Marshal(pod)
		resp := inj.Mutate(ctx, &admissionv1.AdmissionRequest{UID: "u5", Namespace: "sandboxes", Object: runtime.RawExtension{Raw: rawPod}})
		if !resp.Allowed || len(resp.Patch) > 0 {
			t.Fatalf("Expected idempotent no-op for already injected pod")
		}
	})
}

func TestValidationRejections(t *testing.T) {
	ctx := t.Context()

	tests := []struct {
		name        string
		modifyPod   func(p *corev1.Pod)
		expectedErr string
	}{
		{
			name: "hostNetwork true",
			modifyPod: func(p *corev1.Pod) {
				p.Spec.HostNetwork = true
			},
			expectedErr: "spec.hostNetwork: host network is not allowed on pods with service portal sidecars",
		},
		{
			name: "missing runAsNonRoot",
			modifyPod: func(p *corev1.Pod) {
				p.Spec.Containers[0].SecurityContext.RunAsNonRoot = nil
			},
			expectedErr: "securityContext.runAsNonRoot must be true to prevent running as proxy UID (1337)",
		},
		{
			name: "container runAsUser 1337",
			modifyPod: func(p *corev1.Pod) {
				p.Spec.Containers[0].SecurityContext.RunAsUser = ptr.To(int64(1337))
			},
			expectedErr: "securityContext.runAsUser cannot be 1337 (reserved for service portal proxy)",
		},
		{
			name: "pod spec runAsUser 1337",
			modifyPod: func(p *corev1.Pod) {
				p.Spec.SecurityContext = &corev1.PodSecurityContext{
					RunAsUser: ptr.To(int64(1337)),
				}
			},
			expectedErr: "spec.securityContext.runAsUser: cannot be 1337 (reserved for service portal proxy)",
		},
		{
			name: "missing allowPrivilegeEscalation false",
			modifyPod: func(p *corev1.Pod) {
				p.Spec.Containers[0].SecurityContext.AllowPrivilegeEscalation = nil
			},
			expectedErr: "securityContext.allowPrivilegeEscalation must be false to prevent privilege escalation to proxy UID (1337)",
		},
		{
			name: "allowPrivilegeEscalation true",
			modifyPod: func(p *corev1.Pod) {
				p.Spec.Containers[0].SecurityContext.AllowPrivilegeEscalation = ptr.To(true)
			},
			expectedErr: "securityContext.allowPrivilegeEscalation must be false to prevent privilege escalation to proxy UID (1337)",
		},
		{
			name: "container with NET_ADMIN capability",
			modifyPod: func(p *corev1.Pod) {
				p.Spec.Containers[0].SecurityContext.Capabilities = &corev1.Capabilities{
					Add: []corev1.Capability{"NET_ADMIN"},
				}
			},
			expectedErr: "securityContext.capabilities cannot include NET_ADMIN",
		},
		{
			name: "container with NET_RAW capability",
			modifyPod: func(p *corev1.Pod) {
				p.Spec.Containers[0].SecurityContext.Capabilities = &corev1.Capabilities{
					Add: []corev1.Capability{"NET_RAW"},
				}
			},
			expectedErr: "securityContext.capabilities cannot include NET_RAW",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pod := representativePod()
			tc.modifyPod(pod)

			err := ValidatePod(pod)
			if err == nil {
				t.Fatalf("Expected validation error, got nil")
			}
			if !strings.Contains(err.Error(), tc.expectedErr) {
				t.Errorf("Expected error containing %q, got: %q", tc.expectedErr, err.Error())
			}

			// Also verify that Injector.Validate rejects it
			inj := &Injector{}
			rawPod, _ := json.Marshal(pod)
			pod.Annotations = map[string]string{AnnotationStatus: StatusInjected}
			rawInjectedPod, _ := json.Marshal(pod)

			resp := inj.Validate(ctx, &admissionv1.AdmissionRequest{
				UID:       "val-uid",
				Namespace: "sandboxes",
				Object:    runtime.RawExtension{Raw: rawInjectedPod},
			})
			if resp.Allowed {
				t.Errorf("Validate endpoint should have rejected invalid pod")
			}
			if !strings.Contains(resp.Result.Message, tc.expectedErr) {
				t.Errorf("Validate response error mismatch: %s", resp.Result.Message)
			}
			_ = rawPod
		})
	}
}
