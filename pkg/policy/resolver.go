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
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/gke-labs/service-portals/pkg/apis/portals/v1alpha1"
	"github.com/gke-labs/service-portals/pkg/portals"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"
)

// SecretGetter abstracts retrieving Kubernetes Secrets.
type SecretGetter interface {
	GetSecret(ctx context.Context, namespace, name string) (*corev1.Secret, error)
}

// SecretGetterFunc is an adapter allowing the use of ordinary functions as SecretGetter.
type SecretGetterFunc func(ctx context.Context, namespace, name string) (*corev1.Secret, error)

func (f SecretGetterFunc) GetSecret(ctx context.Context, namespace, name string) (*corev1.Secret, error) {
	return f(ctx, namespace, name)
}

// SidecarConfig contains rendered configuration and artifacts for a sidecar pod.
type SidecarConfig struct {
	// RulesYAML maps filename (e.g. "github.yaml") to YAML content for PortalRule.
	RulesYAML map[string]string
	// InitEnv contains environment variables for the init-service-portals container.
	InitEnv []corev1.EnvVar
	// HostAliases contains the hostAlias mappings for intercepted hosts.
	HostAliases []corev1.HostAlias
	// ProxyImage is the image specified for the proxy sidecar, if any.
	ProxyImage string
	// ProxyResources are the resource requirements for the proxy sidecar.
	ProxyResources corev1.ResourceRequirements
}

var invalidNameRegex = regexp.MustCompile(`[^a-z0-9\-]+`)

func sanitizeRuleName(host string) string {
	s := strings.ToLower(host)
	s = invalidNameRegex.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if s == "" {
		return "rule"
	}
	return s
}

// Resolve resolves a PortalPolicy into the concrete SidecarConfig.
func Resolve(ctx context.Context, p *v1alpha1.PortalPolicy, secrets SecretGetter) (*SidecarConfig, error) {
	if p == nil {
		return nil, fmt.Errorf("policy cannot be nil")
	}

	config := &SidecarConfig{
		RulesYAML: make(map[string]string),
	}

	if p.Spec.Proxy != nil {
		config.ProxyImage = p.Spec.Proxy.Image
		config.ProxyResources = p.Spec.Proxy.Resources
	}

	var hosts []string
	seenHosts := make(map[string]bool)

	for i, rule := range p.Spec.Rules {
		host := strings.TrimSpace(rule.Host)
		if host == "" {
			return nil, fmt.Errorf("rule[%d] missing required field 'host'", i)
		}

		var authToken string
		if rule.SecretRef != nil {
			if rule.SecretRef.Name == "" || rule.SecretRef.Key == "" {
				return nil, fmt.Errorf("rule[%d] for host %q secretRef must specify name and key", i, host)
			}
			if secrets == nil {
				return nil, fmt.Errorf("secrets getter is required to resolve secretRef for host %q", host)
			}
			sec, err := secrets.GetSecret(ctx, p.Namespace, rule.SecretRef.Name)
			if err != nil {
				return nil, fmt.Errorf("failed to get secret %q in namespace %q for host %q: %w", rule.SecretRef.Name, p.Namespace, host, err)
			}
			if sec == nil {
				return nil, fmt.Errorf("secret %q not found in namespace %q for host %q", rule.SecretRef.Name, p.Namespace, host)
			}

			if val, ok := sec.Data[rule.SecretRef.Key]; ok {
				authToken = string(val)
			} else if val, ok := sec.StringData[rule.SecretRef.Key]; ok {
				authToken = val
			} else {
				return nil, fmt.Errorf("key %q not found in secret %q in namespace %q for host %q", rule.SecretRef.Key, rule.SecretRef.Name, p.Namespace, host)
			}
		}

		ruleName := sanitizeRuleName(host)
		portalRule := portals.PortalRule{
			APIVersion: "portals.gke.io/v1alpha1",
			Kind:       "PortalRule",
		}
		portalRule.Metadata.Name = ruleName
		portalRule.Spec.Host = host
		portalRule.Spec.RewriteURL = rule.RewriteURL
		portalRule.Spec.AuthHeader = rule.AuthHeader
		portalRule.Spec.AuthToken = authToken
		portalRule.Spec.CacheTTL = rule.CacheTTL

		yamlBytes, err := yaml.Marshal(portalRule)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal rule for host %q: %w", host, err)
		}

		filename := fmt.Sprintf("%s.yaml", ruleName)
		config.RulesYAML[filename] = string(yamlBytes)

		if !seenHosts[host] {
			seenHosts[host] = true
			hosts = append(hosts, host)
		}
	}

	sort.Strings(hosts)
	if len(hosts) > 0 {
		config.HostAliases = []corev1.HostAlias{
			{
				IP:        "8.8.8.8",
				Hostnames: hosts,
			},
		}
	}

	// Build init container environment variables
	interceptPorts := "80,443"
	if p.Spec.Intercept != nil && len(p.Spec.Intercept.Ports) > 0 {
		var portStrs []string
		for _, port := range p.Spec.Intercept.Ports {
			portStrs = append(portStrs, strconv.Itoa(int(port)))
		}
		interceptPorts = strings.Join(portStrs, ",")
	}

	initEnv := []corev1.EnvVar{
		{Name: "PROXY_PORT", Value: "8080"},
		{Name: "PROXY_HTTPS_PORT", Value: "8443"},
		{Name: "PROXY_UID", Value: "1337"},
		{Name: "INTERCEPT_PORTS", Value: interceptPorts},
		{Name: "CHOWN_UID", Value: "1337"},
		{Name: "CHOWN_GID", Value: "1337"},
	}

	if p.Spec.Egress != nil {
		if len(p.Spec.Egress.AllowCIDRs) > 0 {
			initEnv = append(initEnv, corev1.EnvVar{
				Name:  "ALLOW_CIDRS",
				Value: strings.Join(p.Spec.Egress.AllowCIDRs, ","),
			})
		}
		if len(p.Spec.Egress.AllowPorts) > 0 {
			var portStrs []string
			for _, port := range p.Spec.Egress.AllowPorts {
				portStrs = append(portStrs, strconv.Itoa(int(port)))
			}
			initEnv = append(initEnv, corev1.EnvVar{
				Name:  "ALLOW_PORTS",
				Value: strings.Join(portStrs, ","),
			})
		}
		if p.Spec.Egress.DNS != nil {
			if len(p.Spec.Egress.DNS.Servers) > 0 {
				initEnv = append(initEnv, corev1.EnvVar{
					Name:  "DNS_SERVER_IPS",
					Value: strings.Join(p.Spec.Egress.DNS.Servers, ","),
				})
			}
			if p.Spec.Egress.DNS.AllowMetadata {
				initEnv = append(initEnv, corev1.EnvVar{
					Name:  "ALLOW_METADATA",
					Value: "true",
				})
			}
		}
	}

	config.InitEnv = initEnv
	return config, nil
}
