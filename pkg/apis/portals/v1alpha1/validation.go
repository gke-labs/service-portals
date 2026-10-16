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
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var (
	// rfc1123LabelRegex matches a valid DNS label (RFC 1123).
	rfc1123LabelRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$`)
)

// IsValidHostname checks if host complies with RFC 1123 hostname specification.
func IsValidHostname(host string) bool {
	if len(host) == 0 || len(host) > 253 {
		return false
	}

	// Must not contain schemes or ports
	if strings.Contains(host, "://") || strings.Contains(host, ":") || strings.Contains(host, "/") {
		return false
	}

	labels := strings.Split(host, ".")
	for _, label := range labels {
		if !rfc1123LabelRegex.MatchString(label) {
			return false
		}
	}

	return true
}

// Validate performs structural and semantic validation on a PortalPolicy.
func Validate(policy *PortalPolicy) error {
	if policy == nil {
		return errors.New("policy cannot be nil")
	}

	var errs []string

	// Validate Rules
	for i, rule := range policy.Spec.Rules {
		prefix := fmt.Sprintf("spec.rules[%d]", i)

		if strings.TrimSpace(rule.Host) == "" {
			errs = append(errs, fmt.Sprintf("%s.host is required", prefix))
		} else if !IsValidHostname(rule.Host) {
			errs = append(errs, fmt.Sprintf("%s.host %q is not a valid hostname", prefix, rule.Host))
		}

		if strings.TrimSpace(rule.SecretRef.Name) == "" {
			errs = append(errs, fmt.Sprintf("%s.secretRef.name is required", prefix))
		}
		if strings.TrimSpace(rule.SecretRef.Key) == "" {
			errs = append(errs, fmt.Sprintf("%s.secretRef.key is required", prefix))
		}

		if rule.RewriteURL != "" {
			if _, err := url.Parse(rule.RewriteURL); err != nil {
				errs = append(errs, fmt.Sprintf("%s.rewriteUrl %q is invalid: %v", prefix, rule.RewriteURL, err))
			}
		}

		if rule.CacheTTL != "" {
			if _, err := time.ParseDuration(rule.CacheTTL); err != nil {
				errs = append(errs, fmt.Sprintf("%s.cacheTTL %q is invalid: %v", prefix, rule.CacheTTL, err))
			}
		}
	}

	// Validate Egress
	egress := policy.Spec.Egress
	if egress.DefaultAction != "" && egress.DefaultAction != DefaultActionDeny && egress.DefaultAction != DefaultActionAllow {
		errs = append(errs, fmt.Sprintf("spec.egress.defaultAction must be %q or %q, got %q", DefaultActionDeny, DefaultActionAllow, egress.DefaultAction))
	}

	for i, cidr := range egress.AllowCIDRs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			errs = append(errs, fmt.Sprintf("spec.egress.allowCIDRs[%d] %q is not a valid CIDR: %v", i, cidr, err))
		}
	}

	for i, port := range egress.AllowPorts {
		if port < 1 || port > 65535 {
			errs = append(errs, fmt.Sprintf("spec.egress.allowPorts[%d] %d must be between 1 and 65535", i, port))
		}
	}

	for i, server := range egress.DNS.Servers {
		if net.ParseIP(server) == nil {
			errs = append(errs, fmt.Sprintf("spec.egress.dns.servers[%d] %q is not a valid IP address", i, server))
		}
	}

	// Validate Intercept
	for i, port := range policy.Spec.Intercept.Ports {
		if port < 1 || port > 65535 {
			errs = append(errs, fmt.Sprintf("spec.intercept.ports[%d] %d must be between 1 and 65535", i, port))
		}
	}

	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}

	return nil
}
