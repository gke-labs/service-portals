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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// PortalPolicy defines an egress security policy and proxy configuration for matching pods.
type PortalPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   PortalPolicySpec   `json:"spec,omitempty"`
	Status PortalPolicyStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// PortalPolicyList contains a list of PortalPolicy.
type PortalPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []PortalPolicy `json:"items"`
}

// PortalPolicySpec specifies the configuration rules and egress controls.
type PortalPolicySpec struct {
	PodSelector metav1.LabelSelector `json:"podSelector"`
	Rules       []PortalPolicyRule   `json:"rules,omitempty"`
	Egress      *EgressConfig        `json:"egress,omitempty"`
	Intercept   *InterceptConfig     `json:"intercept,omitempty"`
	Proxy       *ProxyConfig         `json:"proxy,omitempty"`
}

// PortalPolicyRule defines how a target host is proxied and authenticated.
type PortalPolicyRule struct {
	Host       string        `json:"host"`
	RewriteURL string        `json:"rewriteUrl,omitempty"`
	AuthHeader string        `json:"authHeader,omitempty"`
	SecretRef  *SecretKeyRef `json:"secretRef,omitempty"`
	CacheTTL   string        `json:"cacheTTL,omitempty"`
}

// SecretKeyRef references a key within a Secret in the same namespace.
type SecretKeyRef struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

// EgressAction defines what happens to unmatched outbound traffic.
type EgressAction string

const (
	EgressActionDeny  EgressAction = "Deny"
	EgressActionAllow EgressAction = "Allow"
)

// EgressConfig defines the outbound network egress policy.
type EgressConfig struct {
	DefaultAction EgressAction `json:"defaultAction,omitempty"`
	AllowCIDRs    []string     `json:"allowCIDRs,omitempty"`
	AllowPorts    []int32      `json:"allowPorts,omitempty"`
	DNS           *DNSConfig   `json:"dns,omitempty"`
}

// DNSConfig specifies DNS filtering and access settings.
type DNSConfig struct {
	Servers       []string `json:"servers,omitempty"`
	AllowMetadata bool     `json:"allowMetadata,omitempty"`
}

// InterceptConfig specifies which ports are intercepted by iptables.
type InterceptConfig struct {
	Ports []int32 `json:"ports,omitempty"`
}

// ProxyConfig specifies container image and resource overrides for the proxy sidecar.
type ProxyConfig struct {
	Image     string                      `json:"image,omitempty"`
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`
}

// PortalPolicyStatus defines the observed state of PortalPolicy.
type PortalPolicyStatus struct {
	Conditions   []metav1.Condition `json:"conditions,omitempty"`
	SelectedPods int                `json:"selectedPods,omitempty"`
}
