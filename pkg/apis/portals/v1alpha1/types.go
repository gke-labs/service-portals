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

// GroupName and Version define the API group and version for PortalPolicy.
const (
	GroupName = "portals.gke.io"
	Version   = "v1alpha1"
)

// Condition type constants.
const (
	ConditionTypeReady   = "Ready"
	ConditionTypeInvalid = "Invalid"
)

// Condition status constants.
const (
	ConditionStatusTrue    = "True"
	ConditionStatusFalse   = "False"
	ConditionStatusUnknown = "Unknown"
)

// Egress action constants.
const (
	DefaultActionDeny  = "Deny"
	DefaultActionAllow = "Allow"
)

// LabelSelector operator constants.
const (
	LabelSelectorOpIn           = "In"
	LabelSelectorOpNotIn        = "NotIn"
	LabelSelectorOpExists       = "Exists"
	LabelSelectorOpDoesNotExist = "DoesNotExist"
)

// PortalPolicy represents the namespaced PortalPolicy custom resource.
type PortalPolicy struct {
	APIVersion string             `json:"apiVersion,omitempty"`
	Kind       string             `json:"kind,omitempty"`
	Metadata   ObjectMeta         `json:"metadata,omitempty"`
	Spec       PortalPolicySpec   `json:"spec"`
	Status     PortalPolicyStatus `json:"status,omitempty"`
}

// PortalPolicyList is a list of PortalPolicy resources.
type PortalPolicyList struct {
	APIVersion string         `json:"apiVersion,omitempty"`
	Kind       string         `json:"kind,omitempty"`
	Metadata   ListMeta       `json:"metadata,omitempty"`
	Items      []PortalPolicy `json:"items"`
}

// ObjectMeta contains standard Kubernetes object metadata.
type ObjectMeta struct {
	Name        string            `json:"name,omitempty"`
	Namespace   string            `json:"namespace,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
	UID         string            `json:"uid,omitempty"`
	Generation  int64             `json:"generation,omitempty"`
}

// ListMeta contains metadata for resource lists.
type ListMeta struct {
	ResourceVersion string `json:"resourceVersion,omitempty"`
}

// PortalPolicySpec defines the desired state of PortalPolicy.
type PortalPolicySpec struct {
	PodSelector LabelSelector   `json:"podSelector"`
	Rules       []PolicyRule    `json:"rules,omitempty"`
	Egress      EgressConfig    `json:"egress,omitempty"`
	Intercept   InterceptConfig `json:"intercept,omitempty"`
	Proxy       ProxyConfig     `json:"proxy,omitempty"`
}

// LabelSelector is a label query over a set of resources.
type LabelSelector struct {
	MatchLabels      map[string]string          `json:"matchLabels,omitempty"`
	MatchExpressions []LabelSelectorRequirement `json:"matchExpressions,omitempty"`
}

// Matches evaluates whether this label selector matches the provided labels.
func (ls *LabelSelector) Matches(labels map[string]string) bool {
	if ls == nil {
		return true
	}

	for k, v := range ls.MatchLabels {
		if labels == nil || labels[k] != v {
			return false
		}
	}

	for _, expr := range ls.MatchExpressions {
		val, exists := labels[expr.Key]
		switch expr.Operator {
		case LabelSelectorOpIn:
			if !exists {
				return false
			}
			matched := false
			for _, allowed := range expr.Values {
				if val == allowed {
					matched = true
					break
				}
			}
			if !matched {
				return false
			}
		case LabelSelectorOpNotIn:
			if exists {
				for _, disallowed := range expr.Values {
					if val == disallowed {
						return false
					}
				}
			}
		case LabelSelectorOpExists:
			if !exists {
				return false
			}
		case LabelSelectorOpDoesNotExist:
			if exists {
				return false
			}
		default:
			return false
		}
	}

	return true
}

// LabelSelectorRequirement is a selector requirement with key, operator, and values.
type LabelSelectorRequirement struct {
	Key      string   `json:"key"`
	Operator string   `json:"operator"` // In, NotIn, Exists, DoesNotExist
	Values   []string `json:"values,omitempty"`
}

// PolicyRule defines a single routing and credential-swapping rule.
// Note: authToken is intentionally omitted; credentials must come via secretRef.
type PolicyRule struct {
	Name       string       `json:"name,omitempty"`
	Host       string       `json:"host"`
	RewriteURL string       `json:"rewriteUrl,omitempty"`
	AuthHeader string       `json:"authHeader,omitempty"`
	SecretRef  SecretKeyRef `json:"secretRef"`
	CacheTTL   string       `json:"cacheTTL,omitempty"`
}

// SecretKeyRef references a key of a Secret in the same namespace as the policy.
type SecretKeyRef struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

// EgressConfig defines the outbound traffic policy for selected pods.
type EgressConfig struct {
	DefaultAction string    `json:"defaultAction,omitempty"` // "Deny" | "Allow" (default: "Deny")
	AllowCIDRs    []string  `json:"allowCIDRs,omitempty"`
	AllowPorts    []int     `json:"allowPorts,omitempty"`
	DNS           DNSConfig `json:"dns,omitempty"`
}

// DNSConfig defines DNS-related egress filtering.
type DNSConfig struct {
	Servers       []string `json:"servers,omitempty"`
	AllowMetadata bool     `json:"allowMetadata,omitempty"`
}

// InterceptConfig defines traffic redirection settings.
type InterceptConfig struct {
	Ports []int `json:"ports,omitempty"`
}

// ProxyConfig defines sidecar proxy container overrides.
type ProxyConfig struct {
	Image     string `json:"image,omitempty"`
	Resources any    `json:"resources,omitempty"`
}

// PortalPolicyStatus defines the observed status of PortalPolicy.
type PortalPolicyStatus struct {
	Conditions   []Condition `json:"conditions,omitempty"`
	SelectedPods int         `json:"selectedPods,omitempty"`
}

// Condition represents the latest available observations of an object's state.
type Condition struct {
	Type               string `json:"type"`
	Status             string `json:"status"` // "True", "False", "Unknown"
	LastTransitionTime string `json:"lastTransitionTime,omitempty"`
	Reason             string `json:"reason,omitempty"`
	Message            string `json:"message,omitempty"`
}
