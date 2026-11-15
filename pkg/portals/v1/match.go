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
	"strings"
)

// Protocol identifies the network protocol of an egress destination.
type Protocol string

const (
	ProtocolHTTP           Protocol = "http"
	ProtocolHTTPS          Protocol = "https"
	ProtocolTLSPassthrough Protocol = "tls_passthrough"
)

const (
	hostRankUniversal = 1 // "*"
	hostRankWildcard  = 2 // "*.domain"
	hostRankExact     = 3 // "domain"

	portRankAll      = 1 // all ports
	portRankSpecific = 2 // explicit port number or default port
)

// Match returns the single deciding EgressRule for the given destination,
// or nil if no rule matches or if the deciding rule's protocol does not match.
// Unmatched requests are denied.
//
// Precedence follows the Agent Substrate specification in egress.proto:
// for a given destination name and port, the single deciding rule is chosen
// across all rules (an exact hostname beats a wildcard, then a specific port
// beats all ports). Traffic is allowed only if the deciding rule's protocol
// matches the requested protocol.
func (p *EgressPolicy) Match(protocol Protocol, hostname string, port int32) *EgressRule {
	if p == nil {
		return nil
	}
	hostname = strings.ToLower(strings.TrimSuffix(hostname, "."))
	if hostname == "" {
		return nil
	}

	var bestRule *EgressRule
	var bestProto Protocol
	var bestHostRank int
	var bestPortRank int

	for _, rule := range p.Rules {
		if rule == nil {
			continue
		}
		ruleProto, hostRank, portRank, ok := matchRule(rule, hostname, port)
		if !ok {
			continue
		}
		if bestRule == nil || hostRank > bestHostRank || (hostRank == bestHostRank && portRank > bestPortRank) {
			bestRule = rule
			bestProto = ruleProto
			bestHostRank = hostRank
			bestPortRank = portRank
		}
	}
	if bestProto != protocol {
		return nil
	}
	return bestRule
}

// CouldMatch reports whether any rule for the given protocol could match
// the given hostname for some port.
func (p *EgressPolicy) CouldMatch(protocol Protocol, hostname string) bool {
	if p == nil {
		return false
	}
	hostname = strings.ToLower(strings.TrimSuffix(hostname, "."))
	if hostname == "" {
		return false
	}

	for _, rule := range p.Rules {
		if rule == nil {
			continue
		}
		ruleProto, hostnames, _, _, ok := ruleTarget(rule)
		if !ok || ruleProto != protocol {
			continue
		}
		if _, matches := matchHostnames(hostnames, hostname); matches {
			return true
		}
	}
	return false
}

func matchRule(rule *EgressRule, hostname string, port int32) (Protocol, int, int, bool) {
	ruleProto, hostnames, ports, defaultPort, ok := ruleTarget(rule)
	if !ok {
		return "", 0, 0, false
	}

	portRank, portMatches := matchPort(ports, port, defaultPort)
	if !portMatches {
		return "", 0, 0, false
	}

	hostRank, hostMatches := matchHostnames(hostnames, hostname)
	if !hostMatches {
		return "", 0, 0, false
	}

	return ruleProto, hostRank, portRank, true
}

func ruleTarget(rule *EgressRule) (Protocol, []string, *Ports, int32, bool) {
	if rule.Http != nil {
		return ProtocolHTTP, rule.Http.Hostnames, rule.Http.Ports, 80, true
	}
	if rule.Https != nil {
		return ProtocolHTTPS, rule.Https.Hostnames, rule.Https.Ports, 443, true
	}
	if rule.TlsPassthrough != nil {
		return ProtocolTLSPassthrough, rule.TlsPassthrough.Hostnames, rule.TlsPassthrough.Ports, 0, true
	}
	return "", nil, nil, 0, false
}

func matchPort(ports *Ports, port int32, defaultPort int32) (int, bool) {
	if port < 1 || port > 65535 {
		return 0, false
	}
	if ports == nil {
		if defaultPort != 0 && port == defaultPort {
			return portRankSpecific, true
		}
		return 0, false
	}
	if ports.All != nil {
		return portRankAll, true
	}
	for _, n := range ports.Numbers {
		if n == port {
			return portRankSpecific, true
		}
	}
	return 0, false
}

func matchHostnames(patterns []string, hostname string) (int, bool) {
	bestRank := 0
	for _, pat := range patterns {
		rank := matchPattern(pat, hostname)
		if rank > bestRank {
			bestRank = rank
		}
	}
	return bestRank, bestRank > 0
}

func matchPattern(pat, hostname string) int {
	if pat == "*" {
		return hostRankUniversal
	}
	if suffix, ok := strings.CutPrefix(pat, "*."); ok {
		prefix, matched := strings.CutSuffix(hostname, "."+suffix)
		if matched && prefix != "" && !strings.Contains(prefix, ".") {
			return hostRankWildcard
		}
		return 0
	}
	if pat == hostname {
		return hostRankExact
	}
	return 0
}
