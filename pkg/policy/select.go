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
	"fmt"
	"strings"

	"github.com/gke-labs/service-portals/pkg/apis/portals/v1alpha1"
)

// ErrMultiplePoliciesMatched is returned when more than one PortalPolicy matches a pod.
var ErrMultiplePoliciesMatched = errors.New("multiple PortalPolicies matched pod")

// MatchPolicies returns all policies from the provided slice whose podSelector matches the given podLabels.
func MatchPolicies(policies []v1alpha1.PortalPolicy, podLabels map[string]string) []v1alpha1.PortalPolicy {
	var matches []v1alpha1.PortalPolicy
	for _, p := range policies {
		if p.Spec.PodSelector.Matches(podLabels) {
			matches = append(matches, p)
		}
	}
	return matches
}

// SelectPolicyForPod selects the unique PortalPolicy for a pod given its labels.
// Under the v1alpha1 specification:
//   - 0 matching policies: returns nil, nil (the pod is not managed by service-portals).
//   - Exactly 1 matching policy: returns that policy.
//   - Multiple matching policies: returns ErrMultiplePoliciesMatched with a descriptive error.
//     Policy merging is not supported in v1alpha1 and must be rejected at admission.
func SelectPolicyForPod(policies []v1alpha1.PortalPolicy, podLabels map[string]string) (*v1alpha1.PortalPolicy, error) {
	matches := MatchPolicies(policies, podLabels)
	if len(matches) == 0 {
		return nil, nil
	}
	if len(matches) == 1 {
		return &matches[0], nil
	}

	var names []string
	for _, p := range matches {
		name := p.Metadata.Name
		if p.Metadata.Namespace != "" {
			name = p.Metadata.Namespace + "/" + name
		}
		names = append(names, name)
	}

	return nil, fmt.Errorf("%w: matched %d policies (%s) for labels %v: policy merging is not supported in v1alpha1, rejected at admission",
		ErrMultiplePoliciesMatched, len(matches), strings.Join(names, ", "), podLabels)
}
