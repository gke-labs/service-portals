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
	"sort"
	"strconv"
	"strings"

	"github.com/gke-labs/service-portals/pkg/apis/portals/v1alpha1"
	"github.com/gke-labs/service-portals/pkg/portals"
	"sigs.k8s.io/yaml"
)

// DefaultDummyIP is the IP address mapped in hostAliases to ensure intercepted connections
// route across a non-loopback interface for iptables redirection.
const DefaultDummyIP = "8.8.8.8"

// Options provides configuration parameters for policy resolution.
type Options struct {
	// DummyIP overrides the IP assigned to hostAliases (defaults to DefaultDummyIP).
	DummyIP string
}

// Resolve processes a PortalPolicy and retrieves required credentials using secrets to generate
// the complete SidecarConfig needed by the sidecar and init containers.
func Resolve(policy v1alpha1.PortalPolicy, secrets SecretGetter) (SidecarConfig, error) {
	return ResolveWithOptions(policy, secrets, Options{})
}

// ResolveWithOptions processes a PortalPolicy with additional resolution options.
func ResolveWithOptions(policy v1alpha1.PortalPolicy, secrets SecretGetter, opts Options) (SidecarConfig, error) {
	if err := v1alpha1.Validate(&policy); err != nil {
		return SidecarConfig{}, fmt.Errorf("invalid policy: %w", err)
	}

	if secrets == nil {
		return SidecarConfig{}, errors.New("secrets getter cannot be nil")
	}

	dummyIP := opts.DummyIP
	if dummyIP == "" {
		dummyIP = DefaultDummyIP
	}

	namespace := policy.Metadata.Namespace
	if namespace == "" {
		namespace = "default"
	}

	config := SidecarConfig{
		Rules:         make([]portals.PortalRule, 0, len(policy.Spec.Rules)),
		RuleDocuments: make(map[string]string),
		InitEnv:       make(map[string]string),
		ProxyEnv:      make(map[string]string),
	}

	// 1. Resolve Rules and Secret references
	hostSet := make(map[string]struct{})
	for i, rule := range policy.Spec.Rules {
		token, err := secrets.GetSecretKey(namespace, rule.SecretRef.Name, rule.SecretRef.Key)
		if err != nil {
			return SidecarConfig{}, fmt.Errorf("failed to resolve secret %s/%s:%s for rule on host %q: %w",
				namespace, rule.SecretRef.Name, rule.SecretRef.Key, rule.Host, err)
		}
		if token == "" {
			return SidecarConfig{}, fmt.Errorf("secret %s/%s key %q returned an empty token",
				namespace, rule.SecretRef.Name, rule.SecretRef.Key)
		}

		ruleName := rule.Name
		if ruleName == "" {
			ruleName = sanitizeHostToName(rule.Host)
		}

		authHeader := rule.AuthHeader
		if authHeader == "" {
			authHeader = "Authorization"
		}

		portalRule := portals.PortalRule{
			APIVersion: fmt.Sprintf("%s/%s", v1alpha1.GroupName, v1alpha1.Version),
			Kind:       "PortalRule",
			Metadata: struct {
				Name string `json:"name"`
			}{
				Name: ruleName,
			},
			Spec: portals.RuleSpec{
				Host:       rule.Host,
				RewriteURL: rule.RewriteURL,
				AuthToken:  token,
				AuthHeader: authHeader,
				CacheTTL:   rule.CacheTTL,
			},
		}

		yamlData, err := yaml.Marshal(portalRule)
		if err != nil {
			return SidecarConfig{}, fmt.Errorf("failed to marshal rule for host %q: %w", rule.Host, err)
		}

		docFileName := fmt.Sprintf("%s.yaml", ruleName)
		if _, exists := config.RuleDocuments[docFileName]; exists {
			docFileName = fmt.Sprintf("%s-%d.yaml", ruleName, i)
		}
		config.RuleDocuments[docFileName] = string(yamlData)
		config.Rules = append(config.Rules, portalRule)

		normalizedHost := strings.ToLower(strings.TrimSpace(rule.Host))
		hostSet[normalizedHost] = struct{}{}
	}

	// 2. Build hostAliases
	if len(hostSet) > 0 {
		hosts := make([]string, 0, len(hostSet))
		for h := range hostSet {
			hosts = append(hosts, h)
		}
		sort.Strings(hosts)

		config.HostAliases = []HostAlias{
			{
				IP:        dummyIP,
				Hostnames: hosts,
			},
		}
	}

	// 3. Configure Init Container Environment
	// INTERCEPT_PORTS
	if len(policy.Spec.Intercept.Ports) > 0 {
		var portStrs []string
		for _, p := range policy.Spec.Intercept.Ports {
			portStrs = append(portStrs, strconv.Itoa(p))
		}
		config.InitEnv["INTERCEPT_PORTS"] = strings.Join(portStrs, ",")
	} else {
		config.InitEnv["INTERCEPT_PORTS"] = "80,443"
	}

	// ALLOW_CIDRS
	if len(policy.Spec.Egress.AllowCIDRs) > 0 {
		config.InitEnv["ALLOW_CIDRS"] = strings.Join(policy.Spec.Egress.AllowCIDRs, ",")
	}

	// ALLOW_PORTS
	if len(policy.Spec.Egress.AllowPorts) > 0 {
		var portStrs []string
		for _, p := range policy.Spec.Egress.AllowPorts {
			portStrs = append(portStrs, strconv.Itoa(p))
		}
		config.InitEnv["ALLOW_PORTS"] = strings.Join(portStrs, ",")
	}

	// DNS_SERVER_IPS
	if len(policy.Spec.Egress.DNS.Servers) > 0 {
		config.InitEnv["DNS_SERVER_IPS"] = strings.Join(policy.Spec.Egress.DNS.Servers, ",")
	}

	// ALLOW_METADATA
	if policy.Spec.Egress.DNS.AllowMetadata {
		config.InitEnv["ALLOW_METADATA"] = "true"
	} else {
		config.InitEnv["ALLOW_METADATA"] = "false"
	}

	// EGRESS_ACTION
	config.InitEnv["EGRESS_ACTION"] = "REJECT"

	// 4. Configure Proxy Environment & Overrides
	defaultAction := policy.Spec.Egress.DefaultAction
	if defaultAction == "" {
		defaultAction = v1alpha1.DefaultActionDeny
	}
	config.ProxyEnv["DEFAULT_ACTION"] = defaultAction

	config.ProxyImage = policy.Spec.Proxy.Image
	config.ProxyResources = policy.Spec.Proxy.Resources

	return config, nil
}

// sanitizeHostToName turns a hostname into a DNS-1123 compatible resource name.
func sanitizeHostToName(host string) string {
	lower := strings.ToLower(host)
	replaced := strings.ReplaceAll(lower, ".", "-")
	return strings.Trim(replaced, "-")
}
