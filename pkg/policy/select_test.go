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
	"errors"
	"strings"
	"testing"

	"github.com/gke-labs/service-portals/pkg/apis/portals/v1alpha1"
)

func TestSelectPolicyForPod(t *testing.T) {
	policy1 := v1alpha1.PortalPolicy{
		Metadata: v1alpha1.ObjectMeta{
			Name:      "policy-agent",
			Namespace: "sandboxes",
		},
		Spec: v1alpha1.PortalPolicySpec{
			PodSelector: v1alpha1.LabelSelector{
				MatchLabels: map[string]string{"app": "agent"},
			},
		},
	}

	policy2 := v1alpha1.PortalPolicy{
		Metadata: v1alpha1.ObjectMeta{
			Name:      "policy-ci",
			Namespace: "sandboxes",
		},
		Spec: v1alpha1.PortalPolicySpec{
			PodSelector: v1alpha1.LabelSelector{
				MatchLabels: map[string]string{"app": "ci-runner"},
			},
		},
	}

	policyWildcard := v1alpha1.PortalPolicy{
		Metadata: v1alpha1.ObjectMeta{
			Name:      "policy-all-sandboxes",
			Namespace: "sandboxes",
		},
		Spec: v1alpha1.PortalPolicySpec{
			PodSelector: v1alpha1.LabelSelector{
				MatchExpressions: []v1alpha1.LabelSelectorRequirement{
					{
						Key:      "env",
						Operator: v1alpha1.LabelSelectorOpIn,
						Values:   []string{"sandbox"},
					},
				},
			},
		},
	}

	policies := []v1alpha1.PortalPolicy{policy1, policy2, policyWildcard}

	// Case 1: Exactly 1 matching policy
	t.Run("single matching policy", func(t *testing.T) {
		selected, err := SelectPolicyForPod(policies, map[string]string{"app": "agent", "env": "prod"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if selected == nil {
			t.Fatalf("expected policy to be selected, got nil")
		}
		if selected.Metadata.Name != "policy-agent" {
			t.Errorf("selected name = %q, want policy-agent", selected.Metadata.Name)
		}
	})

	// Case 2: 0 matching policies
	t.Run("no matching policies", func(t *testing.T) {
		selected, err := SelectPolicyForPod(policies, map[string]string{"app": "unrelated", "env": "prod"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if selected != nil {
			t.Errorf("expected nil for no matching policies, got: %+v", selected)
		}
	})

	// Case 3: Multiple matching policies (rejected at admission)
	t.Run("multiple matching policies rejected", func(t *testing.T) {
		selected, err := SelectPolicyForPod(policies, map[string]string{"app": "agent", "env": "sandbox"})
		if err == nil {
			t.Fatalf("expected error for multiple matching policies, got nil")
		}
		if selected != nil {
			t.Errorf("expected selected policy to be nil on error, got: %+v", selected)
		}
		if !errors.Is(err, ErrMultiplePoliciesMatched) {
			t.Errorf("expected ErrMultiplePoliciesMatched, got: %v", err)
		}
		errMsg := err.Error()
		if !strings.Contains(errMsg, "policy-agent") || !strings.Contains(errMsg, "policy-all-sandboxes") {
			t.Errorf("expected error message to cite conflicting policies, got: %s", errMsg)
		}
		if !strings.Contains(errMsg, "rejected at admission") {
			t.Errorf("expected error message to state rejected at admission, got: %s", errMsg)
		}
	})
}
