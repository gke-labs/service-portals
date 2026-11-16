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
	"sort"

	"github.com/gke-labs/service-portals/pkg/portals"
)

// SidecarConfig contains all generated configuration artifacts required by the sidecar container
// and init container for a pod.
type SidecarConfig struct {
	// Rules are the resolved PortalRule objects ready for the sidecar proxy.
	Rules []portals.PortalRule `json:"rules"`

	// RuleDocuments maps filenames (e.g. "github.backend.yaml") to the serialized YAML document strings.
	// These can be mounted directly into a Secret or ConfigMap volume for --rules-dir.
	RuleDocuments map[string]string `json:"ruleDocuments"`

	// InitEnv contains the environment variables for the init-service-portals container.
	InitEnv map[string]string `json:"initEnv"`

	// HostAliases contains the host-to-IP mappings for pod.spec.hostAliases.
	HostAliases []HostAlias `json:"hostAliases"`

	// ProxyImage is the proxy container image override, if specified in policy.
	ProxyImage string `json:"proxyImage,omitempty"`

	// ProxyResources is the proxy container compute resources override, if specified in policy.
	ProxyResources any `json:"proxyResources,omitempty"`

	// ProxyEnv contains environment variables for the proxy container.
	ProxyEnv map[string]string `json:"proxyEnv,omitempty"`
}

// HostAlias defines an IP to hostname mapping, mirroring Kubernetes corev1.HostAlias.
type HostAlias struct {
	IP        string   `json:"ip"`
	Hostnames []string `json:"hostnames"`
}

// EnvVar defines an environment variable name and value.
type EnvVar struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// InitEnvList returns the InitEnv map sorted by variable name.
func (c SidecarConfig) InitEnvList() []EnvVar {
	var names []string
	for k := range c.InitEnv {
		names = append(names, k)
	}
	sort.Strings(names)

	vars := make([]EnvVar, len(names))
	for i, name := range names {
		vars[i] = EnvVar{
			Name:  name,
			Value: c.InitEnv[name],
		}
	}
	return vars
}

// ProxyEnvList returns the ProxyEnv map sorted by variable name.
func (c SidecarConfig) ProxyEnvList() []EnvVar {
	var names []string
	for k := range c.ProxyEnv {
		names = append(names, k)
	}
	sort.Strings(names)

	vars := make([]EnvVar, len(names))
	for i, name := range names {
		vars[i] = EnvVar{
			Name:  name,
			Value: c.ProxyEnv[name],
		}
	}
	return vars
}
