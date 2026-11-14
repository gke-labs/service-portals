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
	"testing"
)

func TestMatch_NilAndEmpty(t *testing.T) {
	var nilPolicy *EgressPolicy
	if got := nilPolicy.Match(ProtocolHTTP, "api.example.com", 80); got != nil {
		t.Errorf("expected nil for nil policy, got %v", got)
	}

	emptyPolicy := &EgressPolicy{}
	if got := emptyPolicy.Match(ProtocolHTTP, "api.example.com", 80); got != nil {
		t.Errorf("expected nil for empty policy, got %v", got)
	}

	policy := &EgressPolicy{
		Rules: []*EgressRule{
			{Http: &HttpRule{Hostnames: []string{"api.example.com"}}},
		},
	}
	if got := policy.Match(ProtocolHTTP, "", 80); got != nil {
		t.Errorf("expected nil for empty hostname, got %v", got)
	}
	if got := policy.Match(ProtocolHTTP, ".", 80); got != nil {
		t.Errorf("expected nil for dot-only hostname, got %v", got)
	}
}

func TestMatch_Protocol(t *testing.T) {
	httpRule := &EgressRule{
		Http: &HttpRule{Hostnames: []string{"api.example.com"}},
	}
	httpsRule := &EgressRule{
		Https: &HttpsRule{Hostnames: []string{"secure.example.com"}},
	}
	tlsPassthroughRule := &EgressRule{
		TlsPassthrough: &TlsPassthroughRule{
			Hostnames: []string{"passthrough.example.com"},
			Ports:     &Ports{Numbers: []int32{8443}},
		},
	}
	policy := &EgressPolicy{
		Rules: []*EgressRule{httpRule, httpsRule, tlsPassthroughRule},
	}

	tests := []struct {
		name     string
		protocol Protocol
		hostname string
		port     int32
		want     *EgressRule
	}{
		{
			name:     "http request matches http rule on default port 80",
			protocol: ProtocolHTTP,
			hostname: "api.example.com",
			port:     80,
			want:     httpRule,
		},
		{
			name:     "http request on port 443 does not match",
			protocol: ProtocolHTTP,
			hostname: "api.example.com",
			port:     443,
			want:     nil,
		},
		{
			name:     "https request matches https rule on default port 443",
			protocol: ProtocolHTTPS,
			hostname: "secure.example.com",
			port:     443,
			want:     httpsRule,
		},
		{
			name:     "https request on port 80 does not match",
			protocol: ProtocolHTTPS,
			hostname: "secure.example.com",
			port:     80,
			want:     nil,
		},
		{
			name:     "tls_passthrough matches tls_passthrough rule",
			protocol: ProtocolTLSPassthrough,
			hostname: "passthrough.example.com",
			port:     8443,
			want:     tlsPassthroughRule,
		},
		{
			name:     "tls_passthrough does not match on different port",
			protocol: ProtocolTLSPassthrough,
			hostname: "passthrough.example.com",
			port:     443,
			want:     nil,
		},
		{
			name:     "unknown protocol does not match",
			protocol: "unknown",
			hostname: "api.example.com",
			port:     80,
			want:     nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := policy.Match(tc.protocol, tc.hostname, tc.port)
			if got != tc.want {
				t.Errorf("Match(%q, %q, %d) = %v; want %v", tc.protocol, tc.hostname, tc.port, got, tc.want)
			}
		})
	}
}

func TestMatch_CrossProtocolPrecedence(t *testing.T) {
	// 1. Reviewer example:
	// An https rule for api.example.com and an http rule for * on all ports;
	// cleartext HTTP to api.example.com:443 must be denied, because the more specific
	// rule decides and it is not an http rule.
	httpsRule := &EgressRule{
		Https: &HttpsRule{
			Hostnames: []string{"api.example.com"},
		}, // default port 443
	}
	httpWildcardRule := &EgressRule{
		Http: &HttpRule{
			Hostnames: []string{"*"},
			Ports:     &Ports{All: &AllPorts{}},
		},
	}

	policy := &EgressPolicy{
		Rules: []*EgressRule{httpWildcardRule, httpsRule},
	}
	if err := policy.Validate(); err != nil {
		t.Fatalf("policy should be valid: %v", err)
	}

	// Cleartext HTTP to api.example.com:443 must be denied because httpsRule decides on (api.example.com, 443)
	if got := policy.Match(ProtocolHTTP, "api.example.com", 443); got != nil {
		t.Errorf("expected cleartext HTTP to api.example.com:443 to be denied by more specific https rule; got %v", got)
	}

	// HTTPS to api.example.com:443 is allowed by httpsRule
	if got := policy.Match(ProtocolHTTPS, "api.example.com", 443); got != httpsRule {
		t.Errorf("expected HTTPS to api.example.com:443 to match httpsRule; got %v, want %v", got, httpsRule)
	}

	// HTTP to api.example.com:80 is allowed by httpWildcardRule because httpsRule only covers port 443
	if got := policy.Match(ProtocolHTTP, "api.example.com", 80); got != httpWildcardRule {
		t.Errorf("expected HTTP to api.example.com:80 to match httpWildcardRule; got %v, want %v", got, httpWildcardRule)
	}

	// HTTP to other.example.com:443 is allowed by httpWildcardRule because httpsRule does not match the hostname
	if got := policy.Match(ProtocolHTTP, "other.example.com", 443); got != httpWildcardRule {
		t.Errorf("expected HTTP to other.example.com:443 to match httpWildcardRule; got %v, want %v", got, httpWildcardRule)
	}

	// 2. Reverse scenario:
	// An http rule on exact name api.example.com on all ports;
	// An https rule on wildcard *.example.com on specific port 443.
	// HTTPS to api.example.com:443 must be denied because exact host beats wildcard,
	// so the http rule decides the destination and it is not an https rule.
	exactHttpAllPorts := &EgressRule{
		Http: &HttpRule{
			Hostnames: []string{"api.example.com"},
			Ports:     &Ports{All: &AllPorts{}},
		},
	}
	wildcardHttpsSpecificPort := &EgressRule{
		Https: &HttpsRule{
			Hostnames: []string{"*.example.com"},
			Ports:     &Ports{Numbers: []int32{443}},
		},
	}
	p2 := &EgressPolicy{Rules: []*EgressRule{wildcardHttpsSpecificPort, exactHttpAllPorts}}
	if err := p2.Validate(); err != nil {
		t.Fatalf("p2 should be valid: %v", err)
	}

	if got := p2.Match(ProtocolHTTPS, "api.example.com", 443); got != nil {
		t.Errorf("expected HTTPS to api.example.com:443 to be denied because exact http rule decides; got %v", got)
	}
	if got := p2.Match(ProtocolHTTP, "api.example.com", 443); got != exactHttpAllPorts {
		t.Errorf("expected HTTP to api.example.com:443 to match exactHttpAllPorts; got %v", got)
	}
	if got := p2.Match(ProtocolHTTPS, "sub.example.com", 443); got != wildcardHttpsSpecificPort {
		t.Errorf("expected HTTPS to sub.example.com:443 to match wildcardHttpsSpecificPort; got %v", got)
	}
}

func TestMatch_Hostnames_ProtoCommentExamples(t *testing.T) {
	// egress.proto comment:
	// A wildcard replaces the complete leftmost label. "*.example.com" matches
	// exactly one non-empty label, such as "api.example.com". It does not match
	// "example.com" or "nested.api.example.com". "*" alone matches every name.
	// No other wildcard syntax is accepted. A pattern without a wildcard matches
	// only the complete normalized name.
	wildcardRule := &EgressRule{
		Https: &HttpsRule{Hostnames: []string{"*.example.com"}},
	}
	exactRule := &EgressRule{
		Https: &HttpsRule{Hostnames: []string{"example.com"}},
	}
	starRule := &EgressRule{
		Https: &HttpsRule{
			Hostnames: []string{"*"},
			Ports:     &Ports{Numbers: []int32{8443}},
		},
	}

	policy := &EgressPolicy{
		Rules: []*EgressRule{wildcardRule, exactRule, starRule},
	}

	tests := []struct {
		name     string
		hostname string
		port     int32
		want     *EgressRule
	}{
		{
			name:     "wildcard matches single non-empty leftmost label (api.example.com)",
			hostname: "api.example.com",
			port:     443,
			want:     wildcardRule,
		},
		{
			name:     "wildcard matches single label (foo.example.com)",
			hostname: "foo.example.com",
			port:     443,
			want:     wildcardRule,
		},
		{
			name:     "wildcard does not match example.com without subdomain label",
			hostname: "example.com",
			port:     443,
			want:     exactRule,
		},
		{
			name:     "wildcard does not match nested.api.example.com",
			hostname: "nested.api.example.com",
			port:     443,
			want:     nil, // starRule is on port 8443, so nothing matches on 443
		},
		{
			name:     "star alone matches nested.api.example.com on its port",
			hostname: "nested.api.example.com",
			port:     8443,
			want:     starRule,
		},
		{
			name:     "star alone matches single-label host",
			hostname: "internal",
			port:     8443,
			want:     starRule,
		},
		{
			name:     "star alone matches arbitrary multi-label host",
			hostname: "foo.bar.baz.org",
			port:     8443,
			want:     starRule,
		},
		{
			name:     "exact pattern matches only complete normalized name",
			hostname: "example.com",
			port:     443,
			want:     exactRule,
		},
		{
			name:     "exact pattern does not match prefix or suffix variations",
			hostname: "notexample.com",
			port:     443,
			want:     nil,
		},
		{
			name:     "hostname comparison is case-insensitive",
			hostname: "API.EXAMPLE.COM",
			port:     443,
			want:     wildcardRule,
		},
		{
			name:     "single trailing dot is stripped and matches",
			hostname: "api.example.com.",
			port:     443,
			want:     wildcardRule,
		},
		{
			name:     "exact pattern with single trailing dot matches",
			hostname: "example.com.",
			port:     443,
			want:     exactRule,
		},
		{
			name:     "multiple trailing dots fail closed",
			hostname: "example.com..",
			port:     443,
			want:     nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := policy.Match(ProtocolHTTPS, tc.hostname, tc.port)
			if got != tc.want {
				t.Errorf("Match(HTTPS, %q, %d) = %v; want %v", tc.hostname, tc.port, got, tc.want)
			}
		})
	}
}

func TestMatch_Ports(t *testing.T) {
	defaultHttpRule := &EgressRule{
		Http: &HttpRule{Hostnames: []string{"http.example.com"}},
	}
	defaultHttpsRule := &EgressRule{
		Https: &HttpsRule{Hostnames: []string{"https.example.com"}},
	}
	explicitPortsRule := &EgressRule{
		Https: &HttpsRule{
			Hostnames: []string{"explicit.example.com"},
			Ports:     &Ports{Numbers: []int32{8080, 8443}},
		},
	}
	allPortsRule := &EgressRule{
		Https: &HttpsRule{
			Hostnames: []string{"all.example.com"},
			Ports:     &Ports{All: &AllPorts{}},
		},
	}

	policy := &EgressPolicy{
		Rules: []*EgressRule{defaultHttpRule, defaultHttpsRule, explicitPortsRule, allPortsRule},
	}

	tests := []struct {
		name     string
		protocol Protocol
		hostname string
		port     int32
		want     *EgressRule
	}{
		{
			name:     "http default port is 80",
			protocol: ProtocolHTTP,
			hostname: "http.example.com",
			port:     80,
			want:     defaultHttpRule,
		},
		{
			name:     "http default port does not match port 8080",
			protocol: ProtocolHTTP,
			hostname: "http.example.com",
			port:     8080,
			want:     nil,
		},
		{
			name:     "https default port is 443",
			protocol: ProtocolHTTPS,
			hostname: "https.example.com",
			port:     443,
			want:     defaultHttpsRule,
		},
		{
			name:     "https default port does not match port 8443",
			protocol: ProtocolHTTPS,
			hostname: "https.example.com",
			port:     8443,
			want:     nil,
		},
		{
			name:     "explicit ports matches first number",
			protocol: ProtocolHTTPS,
			hostname: "explicit.example.com",
			port:     8080,
			want:     explicitPortsRule,
		},
		{
			name:     "explicit ports matches second number",
			protocol: ProtocolHTTPS,
			hostname: "explicit.example.com",
			port:     8443,
			want:     explicitPortsRule,
		},
		{
			name:     "explicit ports does not match default 443",
			protocol: ProtocolHTTPS,
			hostname: "explicit.example.com",
			port:     443,
			want:     nil,
		},
		{
			name:     "all ports matches any standard port",
			protocol: ProtocolHTTPS,
			hostname: "all.example.com",
			port:     443,
			want:     allPortsRule,
		},
		{
			name:     "all ports matches non-standard port 9999",
			protocol: ProtocolHTTPS,
			hostname: "all.example.com",
			port:     9999,
			want:     allPortsRule,
		},
		{
			name:     "all ports does not match port 0 (out of valid port range)",
			protocol: ProtocolHTTPS,
			hostname: "all.example.com",
			port:     0,
			want:     nil,
		},
		{
			name:     "all ports does not match negative port",
			protocol: ProtocolHTTPS,
			hostname: "all.example.com",
			port:     -1,
			want:     nil,
		},
		{
			name:     "all ports does not match port > 65535",
			protocol: ProtocolHTTPS,
			hostname: "all.example.com",
			port:     70000,
			want:     nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := policy.Match(tc.protocol, tc.hostname, tc.port)
			if got != tc.want {
				t.Errorf("Match(%q, %q, %d) = %v; want %v", tc.protocol, tc.hostname, tc.port, got, tc.want)
			}
		})
	}
}

func TestMatch_Precedence_ExactBeatsWildcard(t *testing.T) {
	// "an exact hostname beats a wildcard, then a specific port beats all ports"
	// Exact hostname on all ports vs Wildcard on specific port:
	// Exact hostname must beat wildcard.
	exactAllPorts := &EgressRule{
		Https: &HttpsRule{
			Hostnames: []string{"api.example.com"},
			Ports:     &Ports{All: &AllPorts{}},
		},
	}
	wildcardSpecificPort := &EgressRule{
		Https: &HttpsRule{
			Hostnames: []string{"*.example.com"},
			Ports:     &Ports{Numbers: []int32{443}},
		},
	}

	// Test with rules in order [exact, wildcard]
	p1 := &EgressPolicy{Rules: []*EgressRule{exactAllPorts, wildcardSpecificPort}}
	if err := p1.Validate(); err != nil {
		t.Fatalf("p1 should be valid: %v", err)
	}
	got1 := p1.Match(ProtocolHTTPS, "api.example.com", 443)
	if got1 != exactAllPorts {
		t.Errorf("expected exact hostname to beat wildcard on port 443; got %v, want %v", got1, exactAllPorts)
	}

	// Test with reversed rule order [wildcard, exact] to ensure order-independence
	p2 := &EgressPolicy{Rules: []*EgressRule{wildcardSpecificPort, exactAllPorts}}
	got2 := p2.Match(ProtocolHTTPS, "api.example.com", 443)
	if got2 != exactAllPorts {
		t.Errorf("expected exact hostname to beat wildcard regardless of rule order; got %v, want %v", got2, exactAllPorts)
	}

	// Non-exact subdomain still matches wildcard
	gotOther := p1.Match(ProtocolHTTPS, "other.example.com", 443)
	if gotOther != wildcardSpecificPort {
		t.Errorf("expected other.example.com to match wildcard rule; got %v, want %v", gotOther, wildcardSpecificPort)
	}
}

func TestMatch_Precedence_SpecificPortBeatsAllPorts(t *testing.T) {
	// "then a specific port beats all ports"
	exactSpecificPort := &EgressRule{
		Https: &HttpsRule{
			Hostnames: []string{"api.example.com"},
			Ports:     &Ports{Numbers: []int32{8443}},
		},
	}
	exactAllPorts := &EgressRule{
		Https: &HttpsRule{
			Hostnames: []string{"api.example.com"},
			Ports:     &Ports{All: &AllPorts{}},
		},
	}

	p := &EgressPolicy{Rules: []*EgressRule{exactAllPorts, exactSpecificPort}}
	if err := p.Validate(); err != nil {
		t.Fatalf("policy should be valid: %v", err)
	}

	// On port 8443, specific port beats all ports
	if got := p.Match(ProtocolHTTPS, "api.example.com", 8443); got != exactSpecificPort {
		t.Errorf("expected specific port to beat all ports on 8443; got %v, want %v", got, exactSpecificPort)
	}

	// On other ports (e.g. 443), only all ports matches
	if got := p.Match(ProtocolHTTPS, "api.example.com", 443); got != exactAllPorts {
		t.Errorf("expected all ports rule on 443; got %v, want %v", got, exactAllPorts)
	}

	// Test default port counts as specific port
	defaultPortRule := &EgressRule{
		Https: &HttpsRule{
			Hostnames: []string{"default.example.com"},
			// ports nil -> defaults to 443
		},
	}
	allPortsDefaultRule := &EgressRule{
		Https: &HttpsRule{
			Hostnames: []string{"default.example.com"},
			Ports:     &Ports{All: &AllPorts{}},
		},
	}
	pDefault := &EgressPolicy{Rules: []*EgressRule{allPortsDefaultRule, defaultPortRule}}
	if err := pDefault.Validate(); err != nil {
		t.Fatalf("pDefault should be valid: %v", err)
	}
	if got := pDefault.Match(ProtocolHTTPS, "default.example.com", 443); got != defaultPortRule {
		t.Errorf("expected default port 443 to beat all ports; got %v, want %v", got, defaultPortRule)
	}
	if got := pDefault.Match(ProtocolHTTPS, "default.example.com", 8443); got != allPortsDefaultRule {
		t.Errorf("expected all ports rule on 8443; got %v, want %v", got, allPortsDefaultRule)
	}
}

func TestMatch_Precedence_SpecificWildcardBeatsUniversalStar(t *testing.T) {
	// "*.example.com" is more specific than "*"
	wildcardAllPorts := &EgressRule{
		Https: &HttpsRule{
			Hostnames: []string{"*.example.com"},
			Ports:     &Ports{All: &AllPorts{}},
		},
	}
	starSpecificPort := &EgressRule{
		Https: &HttpsRule{
			Hostnames: []string{"*"},
			Ports:     &Ports{Numbers: []int32{443}},
		},
	}

	p := &EgressPolicy{Rules: []*EgressRule{starSpecificPort, wildcardAllPorts}}
	if err := p.Validate(); err != nil {
		t.Fatalf("policy should be valid: %v", err)
	}

	// For api.example.com:443, wildcard *.example.com beats universal *
	if got := p.Match(ProtocolHTTPS, "api.example.com", 443); got != wildcardAllPorts {
		t.Errorf("expected *.example.com (all ports) to beat * (port 443) on hostname specificity; got %v, want %v", got, wildcardAllPorts)
	}

	// For unrelated domain on 443, * matches
	if got := p.Match(ProtocolHTTPS, "foo.org", 443); got != starSpecificPort {
		t.Errorf("expected * rule for foo.org; got %v, want %v", got, starSpecificPort)
	}
}

func TestMatch_OverlappingRulesHierarchy(t *testing.T) {
	// A validated policy containing a full hierarchy of overlapping rules:
	// Rule 1: exact hostname, specific port
	// Rule 2: exact hostname, all ports
	// Rule 3: wildcard hostname, specific port
	// Rule 4: wildcard hostname, all ports
	// Rule 5: universal star, specific port
	// Rule 6: universal star, all ports
	rule1 := &EgressRule{
		Https: &HttpsRule{
			Hostnames: []string{"api.example.com"},
			Ports:     &Ports{Numbers: []int32{443}},
		},
	}
	rule2 := &EgressRule{
		Https: &HttpsRule{
			Hostnames: []string{"api.example.com"},
			Ports:     &Ports{All: &AllPorts{}},
		},
	}
	rule3 := &EgressRule{
		Https: &HttpsRule{
			Hostnames: []string{"*.example.com"},
			Ports:     &Ports{Numbers: []int32{443}},
		},
	}
	rule4 := &EgressRule{
		Https: &HttpsRule{
			Hostnames: []string{"*.example.com"},
			Ports:     &Ports{All: &AllPorts{}},
		},
	}
	rule5 := &EgressRule{
		Https: &HttpsRule{
			Hostnames: []string{"*"},
			Ports:     &Ports{Numbers: []int32{443}},
		},
	}
	rule6 := &EgressRule{
		Https: &HttpsRule{
			Hostnames: []string{"*"},
			Ports:     &Ports{All: &AllPorts{}},
		},
	}

	policy := &EgressPolicy{
		Rules: []*EgressRule{rule6, rule5, rule4, rule3, rule2, rule1},
	}
	if err := policy.Validate(); err != nil {
		t.Fatalf("overlapping hierarchy policy must be valid: %v", err)
	}

	tests := []struct {
		name     string
		hostname string
		port     int32
		want     *EgressRule
	}{
		{
			name:     "api.example.com:443 matches exact hostname on specific port (Rule 1)",
			hostname: "api.example.com",
			port:     443,
			want:     rule1,
		},
		{
			name:     "api.example.com:8443 matches exact hostname on all ports (Rule 2)",
			hostname: "api.example.com",
			port:     8443,
			want:     rule2,
		},
		{
			name:     "web.example.com:443 matches wildcard on specific port (Rule 3)",
			hostname: "web.example.com",
			port:     443,
			want:     rule3,
		},
		{
			name:     "web.example.com:8443 matches wildcard on all ports (Rule 4)",
			hostname: "web.example.com",
			port:     8443,
			want:     rule4,
		},
		{
			name:     "other.com:443 matches universal star on specific port (Rule 5)",
			hostname: "other.com",
			port:     443,
			want:     rule5,
		},
		{
			name:     "other.com:8443 matches universal star on all ports (Rule 6)",
			hostname: "other.com",
			port:     8443,
			want:     rule6,
		},
		{
			name:     "invalid port 0 matches nothing",
			hostname: "other.com",
			port:     0,
			want:     nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := policy.Match(ProtocolHTTPS, tc.hostname, tc.port)
			if got != tc.want {
				t.Errorf("Match(HTTPS, %q, %d) = %v; want %v", tc.hostname, tc.port, got, tc.want)
			}
		})
	}
}

func TestMatch_MultipleHostnamesInSingleRule(t *testing.T) {
	// A single rule with both wildcard and exact name should rank by most specific pattern matched
	rule := &EgressRule{
		Https: &HttpsRule{
			Hostnames: []string{"*.example.com", "special.example.com"},
			Ports:     &Ports{All: &AllPorts{}},
		},
	}
	fallbackRule := &EgressRule{
		Https: &HttpsRule{
			Hostnames: []string{"special.example.com"},
			Ports:     &Ports{Numbers: []int32{443}},
		},
	}

	// fallbackRule has exact host + specific port (rank 3, 2)
	// rule has exact host + all ports for special.example.com (rank 3, 1)
	p := &EgressPolicy{Rules: []*EgressRule{rule, fallbackRule}}
	if err := p.Validate(); err != nil {
		t.Fatalf("policy should be valid: %v", err)
	}

	// For special.example.com:443, fallbackRule wins because specific port beats all ports on exact host
	if got := p.Match(ProtocolHTTPS, "special.example.com", 443); got != fallbackRule {
		t.Errorf("expected fallbackRule on port 443; got %v, want %v", got, fallbackRule)
	}

	// For other.example.com:443, rule matches via wildcard
	if got := p.Match(ProtocolHTTPS, "other.example.com", 443); got != rule {
		t.Errorf("expected rule on other.example.com; got %v, want %v", got, rule)
	}
}

func TestMatch_ProtojsonLoadedPolicy(t *testing.T) {
	jsonPolicy := `{
		"rules": [
			{
				"https": {
					"hostnames": ["api.github.com"],
					"effects": {
						"replaceHeaders": [
							{
								"header": "Authorization",
								"prefix": "Bearer ",
								"credentialUri": "secret://github-token"
							}
						]
					}
				}
			},
			{
				"http": {
					"hostnames": ["*.crates.io"],
					"ports": {"all": {}}
				}
			}
		]
	}`

	policy, err := LoadPolicy([]byte(jsonPolicy))
	if err != nil {
		t.Fatalf("LoadPolicy failed: %v", err)
	}

	// HTTPS to api.github.com on default port 443 matches rule 0
	got1 := policy.Match(ProtocolHTTPS, "api.github.com", 443)
	if got1 != policy.Rules[0] {
		t.Errorf("expected rule 0 for api.github.com:443; got %v", got1)
	}

	// HTTP to api.github.com is denied
	if got := policy.Match(ProtocolHTTP, "api.github.com", 80); got != nil {
		t.Errorf("expected nil for HTTP to api.github.com; got %v", got)
	}

	// HTTP to static.crates.io:8080 matches rule 1
	got2 := policy.Match(ProtocolHTTP, "static.crates.io", 8080)
	if got2 != policy.Rules[1] {
		t.Errorf("expected rule 1 for static.crates.io:8080; got %v", got2)
	}

	// HTTPS to static.crates.io is denied
	if got := policy.Match(ProtocolHTTPS, "static.crates.io", 443); got != nil {
		t.Errorf("expected nil for HTTPS to static.crates.io; got %v", got)
	}
}

func TestCouldMatch(t *testing.T) {
	var nilPolicy *EgressPolicy
	if nilPolicy.CouldMatch(ProtocolHTTPS, "api.example.com") {
		t.Error("expected false for nil policy")
	}

	emptyPolicy := &EgressPolicy{}
	if emptyPolicy.CouldMatch(ProtocolHTTPS, "api.example.com") {
		t.Error("expected false for empty policy")
	}

	policy := &EgressPolicy{
		Rules: []*EgressRule{
			{
				Https: &HttpsRule{
					Hostnames: []string{"api.example.com", "*.sub.example.com"},
				},
			},
			{
				Http: &HttpRule{
					Hostnames: []string{"http.example.com"},
				},
			},
			nil,
		},
	}

	tests := []struct {
		name     string
		proto    Protocol
		host     string
		expected bool
	}{
		{"exact match https", ProtocolHTTPS, "api.example.com", true},
		{"exact match case insensitive", ProtocolHTTPS, "API.EXAMPLE.COM", true},
		{"exact match trailing dot", ProtocolHTTPS, "api.example.com.", true},
		{"wildcard match https", ProtocolHTTPS, "foo.sub.example.com", true},
		{"wildcard base domain does not match", ProtocolHTTPS, "sub.example.com", false},
		{"unrelated host https", ProtocolHTTPS, "other.com", false},
		{"http rule checked against https", ProtocolHTTPS, "http.example.com", false},
		{"http rule checked against http", ProtocolHTTP, "http.example.com", true},
		{"empty host", ProtocolHTTPS, "", false},
		{"dot only host", ProtocolHTTPS, ".", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := policy.CouldMatch(tc.proto, tc.host); got != tc.expected {
				t.Errorf("CouldMatch(%s, %q) = %v; want %v", tc.proto, tc.host, got, tc.expected)
			}
		})
	}
}
