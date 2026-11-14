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

package portalsv1

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"
)

// LoadPolicy parses protojson-encoded egress policy data and validates it.
func LoadPolicy(data []byte) (*EgressPolicy, error) {
	policy := &EgressPolicy{}
	if err := protojson.Unmarshal(data, policy); err != nil {
		return nil, fmt.Errorf("unmarshaling egress policy: %w", err)
	}
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	return policy, nil
}

type ruleInfo struct {
	member    string
	hostnames []string
	ports     *Ports
	effects   *HttpRuleEffects
}

func inspectRule(i int, r *EgressRule, errs *[]error) *ruleInfo {
	count := 0
	if r.Http != nil {
		count++
	}
	if r.Https != nil {
		count++
	}
	if r.TlsPassthrough != nil {
		count++
	}
	if count == 0 {
		*errs = append(*errs, fmt.Errorf("rules[%d]: rule must specify one of http, https, or tls_passthrough", i))
		return nil
	}
	if count > 1 {
		*errs = append(*errs, fmt.Errorf("rules[%d]: rule cannot specify multiple protocols", i))
	}
	if r.TlsPassthrough != nil {
		*errs = append(*errs, fmt.Errorf("rules[%d].tls_passthrough: tls_passthrough is not supported", i))
		return &ruleInfo{
			member:    "tls_passthrough",
			hostnames: r.TlsPassthrough.Hostnames,
			ports:     r.TlsPassthrough.Ports,
		}
	}
	if r.Http != nil {
		return &ruleInfo{
			member:    "http",
			hostnames: r.Http.Hostnames,
			ports:     r.Http.Ports,
			effects:   r.Http.Effects,
		}
	}
	return &ruleInfo{
		member:    "https",
		hostnames: r.Https.Hostnames,
		ports:     r.Https.Ports,
		effects:   r.Https.Effects,
	}
}

// Validate checks an EgressPolicy for syntactic and semantic validity according
// to the Agent Substrate egress policy specification.
func (p *EgressPolicy) Validate() error {
	if p == nil {
		return errors.New("policy cannot be nil")
	}
	var errs []error
	if len(p.Rules) > 256 {
		errs = append(errs, fmt.Errorf("rules: at most 256 rules allowed, got %d", len(p.Rules)))
	}

	type tieKey struct {
		pattern string
		port    portKey
	}
	seenTies := make(map[tieKey]int)

	for i, rule := range p.Rules {
		if rule == nil {
			errs = append(errs, fmt.Errorf("rules[%d]: rule cannot be nil", i))
			continue
		}
		info := inspectRule(i, rule, &errs)
		if info == nil {
			continue
		}

		validHostnames := validateHostnames(i, info.member, info.hostnames, &errs)
		effectivePorts := validatePorts(i, info.member, info.ports, &errs)
		if info.effects != nil {
			validateEffects(i, info.member, info.effects, &errs)
		}

		for _, pat := range validHostnames {
			for _, pk := range effectivePorts {
				k := tieKey{pattern: pat, port: pk}
				if prior, ok := seenTies[k]; ok && prior != i {
					portDesc := fmt.Sprintf("port %d", pk.number)
					if pk.all {
						portDesc = "every port"
					}
					errs = append(errs, fmt.Errorf("rules[%d] ties with rules[%d] on %q on %s", i, prior, pat, portDesc))
				} else {
					seenTies[k] = i
				}
			}
		}
	}

	return errors.Join(errs...)
}

func validateHostnames(i int, member string, patterns []string, errs *[]error) []string {
	if len(patterns) == 0 {
		*errs = append(*errs, fmt.Errorf("rules[%d].%s.hostnames: cannot be empty", i, member))
		return nil
	}
	if len(patterns) > 256 {
		*errs = append(*errs, fmt.Errorf("rules[%d].%s.hostnames: at most 256 hostnames allowed, got %d", i, member, len(patterns)))
	}
	seen := make(map[string]struct{}, len(patterns))
	var valid []string
	for _, raw := range patterns {
		ok := true
		if _, exists := seen[raw]; exists {
			*errs = append(*errs, fmt.Errorf("rules[%d].%s.hostnames: duplicate hostname %q", i, member, raw))
			ok = false
		} else {
			seen[raw] = struct{}{}
		}
		if !isValidHostnamePattern(raw) {
			*errs = append(*errs, fmt.Errorf("rules[%d].%s.hostnames: invalid hostname pattern %q", i, member, raw))
			ok = false
		}
		if ok {
			valid = append(valid, raw)
		}
	}
	return valid
}

func isValidHostnamePattern(raw string) bool {
	if raw == "*" {
		return true
	}
	name, wildcard := strings.CutPrefix(raw, "*.")
	if wildcard && strings.Contains(name, "*") {
		return false
	}
	if !wildcard && strings.Contains(raw, "*") {
		return false
	}
	return isValidHostname(name)
}

func isValidHostname(name string) bool {
	if len(name) == 0 || len(name) > 253 || strings.HasSuffix(name, ".") {
		return false
	}
	labels := strings.Split(name, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				return false
			}
		}
	}
	last := labels[len(labels)-1]
	for i := 0; i < len(last); i++ {
		if last[i] < '0' || last[i] > '9' {
			return true
		}
	}
	return false
}

type portKey struct {
	number int32
	all    bool
}

func validatePorts(i int, member string, ports *Ports, errs *[]error) []portKey {
	if ports == nil {
		if member == "http" {
			return []portKey{{number: 80}}
		}
		if member == "https" {
			return []portKey{{number: 443}}
		}
		if member == "tls_passthrough" {
			*errs = append(*errs, fmt.Errorf("rules[%d].tls_passthrough.ports: ports is required", i))
		}
		return nil
	}
	if ports.All != nil && len(ports.Numbers) > 0 {
		*errs = append(*errs, fmt.Errorf("rules[%d].%s.ports: cannot specify both all and numbers", i, member))
		return nil
	}
	if ports.All != nil {
		return []portKey{{all: true}}
	}
	if len(ports.Numbers) == 0 {
		*errs = append(*errs, fmt.Errorf("rules[%d].%s.ports: cannot be empty", i, member))
		return nil
	}
	if len(ports.Numbers) > 16 {
		*errs = append(*errs, fmt.Errorf("rules[%d].%s.ports.numbers: at most 16 ports allowed, got %d", i, member, len(ports.Numbers)))
	}
	seen := make(map[int32]struct{}, len(ports.Numbers))
	var keys []portKey
	for _, n := range ports.Numbers {
		ok := true
		if n < 1 || n > 65535 {
			*errs = append(*errs, fmt.Errorf("rules[%d].%s.ports.numbers: port %d out of range [1, 65535]", i, member, n))
			ok = false
		}
		if _, exists := seen[n]; exists {
			*errs = append(*errs, fmt.Errorf("rules[%d].%s.ports.numbers: duplicate port %d", i, member, n))
			ok = false
		} else {
			seen[n] = struct{}{}
		}
		if ok {
			keys = append(keys, portKey{number: n})
		}
	}
	return keys
}

func validateEffects(i int, member string, effects *HttpRuleEffects, errs *[]error) {
	if len(effects.ReplaceHeaders) == 0 {
		*errs = append(*errs, fmt.Errorf("rules[%d].%s.effects: at least one replace_headers entry is required", i, member))
		return
	}
	if len(effects.ReplaceHeaders) > 16 {
		*errs = append(*errs, fmt.Errorf("rules[%d].%s.effects.replace_headers: at most 16 replace_headers allowed, got %d", i, member, len(effects.ReplaceHeaders)))
	}
	seen := make(map[string]struct{}, len(effects.ReplaceHeaders))
	for j, inj := range effects.ReplaceHeaders {
		if inj == nil {
			*errs = append(*errs, fmt.Errorf("rules[%d].%s.effects.replace_headers[%d]: credential header cannot be nil", i, member, j))
			continue
		}
		if inj.Header == "" {
			*errs = append(*errs, fmt.Errorf("rules[%d].%s.effects.replace_headers[%d].header: header is required", i, member, j))
		} else if !isValidHeaderName(inj.Header) {
			*errs = append(*errs, fmt.Errorf("rules[%d].%s.effects.replace_headers[%d].header: invalid header name %q", i, member, j, inj.Header))
		}
		norm := strings.ToLower(inj.Header)
		if norm != "" {
			if _, exists := seen[norm]; exists {
				*errs = append(*errs, fmt.Errorf("rules[%d].%s.effects.replace_headers[%d].header: duplicate header %q", i, member, j, inj.Header))
			} else {
				seen[norm] = struct{}{}
			}
		}
		if !isValidHeaderValue(inj.Prefix) {
			*errs = append(*errs, fmt.Errorf("rules[%d].%s.effects.replace_headers[%d].prefix: invalid prefix %q", i, member, j, inj.Prefix))
		}
		if inj.ActorJwt != nil {
			*errs = append(*errs, fmt.Errorf("rules[%d].%s.effects.replace_headers[%d].actor_jwt: actor_jwt credential source is not supported", i, member, j))
		}
		if inj.CredentialUri == "" {
			*errs = append(*errs, fmt.Errorf("rules[%d].%s.effects.replace_headers[%d].credential_uri: credential_uri is required", i, member, j))
		} else if !isValidCredentialURI(inj.CredentialUri) {
			*errs = append(*errs, fmt.Errorf("rules[%d].%s.effects.replace_headers[%d].credential_uri: invalid credential URI %q, must be secret://<name>", i, member, j, inj.CredentialUri))
		}
	}
}

func isValidCredentialURI(raw string) bool {
	name, ok := strings.CutPrefix(raw, "secret://")
	if !ok || name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c <= ' ' || c >= 0x7f || strings.ContainsRune("/?#@:%\t\r\n", rune(c)) {
			return false
		}
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "secret" || u.Host != name || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return false
	}
	return true
}

func isValidHeaderName(v string) bool {
	if len(v) == 0 {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c))) {
			return false
		}
	}
	return true
}

func isValidHeaderValue(v string) bool {
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c != '\t' && (c < ' ' || c == 0x7f) {
			return false
		}
	}
	return true
}
