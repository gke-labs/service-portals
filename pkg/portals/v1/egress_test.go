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
	"fmt"
	"strings"
	"testing"
)

func TestLoadPolicy_Accepted(t *testing.T) {
	tests := []struct {
		name string
		json string
	}{
		{
			name: "empty policy",
			json: `{}`,
		},
		{
			name: "empty rules",
			json: `{"rules": []}`,
		},
		{
			name: "simple http rule on default port 80",
			json: `{
				"rules": [
					{"http": {"hostnames": ["api.example.com"]}}
				]
			}`,
		},
		{
			name: "simple https rule on default port 443",
			json: `{
				"rules": [
					{"https": {"hostnames": ["api.example.com"]}}
				]
			}`,
		},
		{
			name: "http and https on default ports do not tie",
			json: `{
				"rules": [
					{"http": {"hostnames": ["api.example.com"]}},
					{"https": {"hostnames": ["api.example.com"]}}
				]
			}`,
		},
		{
			name: "wildcard hostname",
			json: `{
				"rules": [
					{"https": {"hostnames": ["*.example.com"]}}
				]
			}`,
		},
		{
			name: "star pattern matches all",
			json: `{
				"rules": [
					{"https": {"hostnames": ["*"]}}
				]
			}`,
		},
		{
			name: "explicit port numbers",
			json: `{
				"rules": [
					{"https": {
						"hostnames": ["api.example.com"],
						"ports": {"numbers": [443, 8443]}
					}}
				]
			}`,
		},
		{
			name: "all ports",
			json: `{
				"rules": [
					{"http": {
						"hostnames": ["api.example.com"],
						"ports": {"all": {}}
					}}
				]
			}`,
		},
		{
			name: "all ports and specific port on same name do not tie",
			json: `{
				"rules": [
					{"http": {
						"hostnames": ["api.example.com"],
						"ports": {"all": {}}
					}},
					{"http": {
						"hostnames": ["api.example.com"],
						"ports": {"numbers": [8080]}
					}}
				]
			}`,
		},
		{
			name: "same pattern on different ports does not tie",
			json: `{
				"rules": [
					{"http": {
						"hostnames": ["api.example.com"],
						"ports": {"numbers": [80]}
					}},
					{"http": {
						"hostnames": ["api.example.com"],
						"ports": {"numbers": [8080]}
					}}
				]
			}`,
		},
		{
			name: "effects with replace_headers",
			json: `{
				"rules": [
					{"https": {
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
					}}
				]
			}`,
		},
		{
			name: "multiple distinct headers in effects",
			json: `{
				"rules": [
					{"https": {
						"hostnames": ["api.github.com"],
						"effects": {
							"replaceHeaders": [
								{
									"header": "Authorization",
									"prefix": "Bearer ",
									"credentialUri": "secret://token"
								},
								{
									"header": "X-Custom-Header",
									"credentialUri": "secret://custom_secret.v1"
								}
							]
						}
					}}
				]
			}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			policy, err := LoadPolicy([]byte(tc.json))
			if err != nil {
				t.Fatalf("unexpected error loading policy: %v", err)
			}
			if policy == nil {
				t.Fatal("expected non-nil policy")
			}
		})
	}
}

func TestLoadPolicy_SizeLimits_Accepted(t *testing.T) {
	t.Run("exactly 256 rules", func(t *testing.T) {
		p := &EgressPolicy{}
		for i := 0; i < 256; i++ {
			p.Rules = append(p.Rules, &EgressRule{
				Http: &HttpRule{
					Hostnames: []string{fmt.Sprintf("host%d.example.com", i)},
				},
			})
		}
		if err := p.Validate(); err != nil {
			t.Fatalf("expected 256 rules to be accepted, got: %v", err)
		}
	})

	t.Run("exactly 256 hostnames in a rule", func(t *testing.T) {
		var hosts []string
		for i := 0; i < 256; i++ {
			hosts = append(hosts, fmt.Sprintf("host%d.example.com", i))
		}
		p := &EgressPolicy{
			Rules: []*EgressRule{
				{Http: &HttpRule{Hostnames: hosts}},
			},
		}
		if err := p.Validate(); err != nil {
			t.Fatalf("expected 256 hostnames to be accepted, got: %v", err)
		}
	})

	t.Run("exactly 16 ports in a rule", func(t *testing.T) {
		var ports []int32
		for i := int32(1); i <= 16; i++ {
			ports = append(ports, 8000+i)
		}
		p := &EgressPolicy{
			Rules: []*EgressRule{
				{Http: &HttpRule{Hostnames: []string{"example.com"}, Ports: &Ports{Numbers: ports}}},
			},
		}
		if err := p.Validate(); err != nil {
			t.Fatalf("expected 16 ports to be accepted, got: %v", err)
		}
	})

	t.Run("exactly 16 replace_headers in a rule", func(t *testing.T) {
		var headers []*CredentialHeader
		for i := 0; i < 16; i++ {
			headers = append(headers, &CredentialHeader{
				Header:        fmt.Sprintf("X-Header-%d", i),
				CredentialUri: fmt.Sprintf("secret://token-%d", i),
			})
		}
		p := &EgressPolicy{
			Rules: []*EgressRule{
				{
					Http: &HttpRule{
						Hostnames: []string{"example.com"},
						Effects:   &HttpRuleEffects{ReplaceHeaders: headers},
					},
				},
			},
		}
		if err := p.Validate(); err != nil {
			t.Fatalf("expected 16 headers to be accepted, got: %v", err)
		}
	})
}

func TestLoadPolicy_Rejected(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		wantErr string
	}{
		{
			name:    "invalid json syntax",
			json:    `{invalid`,
			wantErr: "unmarshaling egress policy",
		},
		{
			name: "rule with no protocol",
			json: `{
				"rules": [{}]
			}`,
			wantErr: "rule must specify one of",
		},
		{
			name: "rule with multiple protocols",
			json: `{
				"rules": [{
					"http": {"hostnames": ["example.com"]},
					"https": {"hostnames": ["example.com"]}
				}]
			}`,
			wantErr: "rule cannot specify multiple protocols",
		},
		{
			name: "unsupported tls_passthrough",
			json: `{
				"rules": [{
					"tlsPassthrough": {
						"hostnames": ["example.com"],
						"ports": {"all": {}}
					}
				}]
			}`,
			wantErr: "tls_passthrough is not supported",
		},
		{
			name: "unsupported actor_jwt credential source",
			json: `{
				"rules": [{
					"https": {
						"hostnames": ["api.example.com"],
						"effects": {
							"replaceHeaders": [{
								"header": "Authorization",
								"actorJwt": {
									"audiences": ["https://api.example.com"],
									"expirationSeconds": 900
								}
							}]
						}
					}
				}]
			}`,
			wantErr: "actor_jwt credential source is not supported",
		},
		{
			name: "empty hostnames list",
			json: `{
				"rules": [{"http": {"hostnames": []}}]
			}`,
			wantErr: "cannot be empty",
		},
		{
			name: "empty hostname string",
			json: `{
				"rules": [{"http": {"hostnames": [""]}}]
			}`,
			wantErr: "invalid hostname pattern",
		},
		{
			name: "uppercase hostname",
			json: `{
				"rules": [{"http": {"hostnames": ["API.EXAMPLE.COM"]}}]
			}`,
			wantErr: "invalid hostname pattern",
		},
		{
			name: "hostname with trailing dot",
			json: `{
				"rules": [{"http": {"hostnames": ["api.example.com."]}}]
			}`,
			wantErr: "invalid hostname pattern",
		},
		{
			name: "IP literal hostname",
			json: `{
				"rules": [{"http": {"hostnames": ["192.0.2.1"]}}]
			}`,
			wantErr: "invalid hostname pattern",
		},
		{
			name: "URL hostname",
			json: `{
				"rules": [{"http": {"hostnames": ["https://example.com"]}}]
			}`,
			wantErr: "invalid hostname pattern",
		},
		{
			name: "hostname with port",
			json: `{
				"rules": [{"http": {"hostnames": ["example.com:443"]}}]
			}`,
			wantErr: "invalid hostname pattern",
		},
		{
			name: "hostname with consecutive dots",
			json: `{
				"rules": [{"http": {"hostnames": ["foo..example.com"]}}]
			}`,
			wantErr: "invalid hostname pattern",
		},
		{
			name: "wildcard not leftmost",
			json: `{
				"rules": [{"http": {"hostnames": ["api.*.example.com"]}}]
			}`,
			wantErr: "invalid hostname pattern",
		},
		{
			name: "wildcard prefix without dot",
			json: `{
				"rules": [{"http": {"hostnames": ["*example.com"]}}]
			}`,
			wantErr: "invalid hostname pattern",
		},
		{
			name: "hostname label with underscore",
			json: `{
				"rules": [{"http": {"hostnames": ["foo_bar.com"]}}]
			}`,
			wantErr: "invalid hostname pattern",
		},
		{
			name: "hostname label leading hyphen",
			json: `{
				"rules": [{"http": {"hostnames": ["-example.com"]}}]
			}`,
			wantErr: "invalid hostname pattern",
		},
		{
			name: "hostname label trailing hyphen",
			json: `{
				"rules": [{"http": {"hostnames": ["example-.com"]}}]
			}`,
			wantErr: "invalid hostname pattern",
		},
		{
			name: "duplicate hostname within rule",
			json: `{
				"rules": [{"http": {"hostnames": ["api.example.com", "api.example.com"]}}]
			}`,
			wantErr: "duplicate hostname",
		},
		{
			name: "empty ports object",
			json: `{
				"rules": [{
					"http": {
						"hostnames": ["example.com"],
						"ports": {}
					}
				}]
			}`,
			wantErr: "cannot be empty",
		},
		{
			name: "ports with both all and numbers",
			json: `{
				"rules": [{
					"http": {
						"hostnames": ["example.com"],
						"ports": {
							"all": {},
							"numbers": [80]
						}
					}
				}]
			}`,
			wantErr: "cannot specify both all and numbers",
		},
		{
			name: "port zero",
			json: `{
				"rules": [{
					"http": {
						"hostnames": ["example.com"],
						"ports": {"numbers": [0]}
					}
				}]
			}`,
			wantErr: "out of range",
		},
		{
			name: "port out of range",
			json: `{
				"rules": [{
					"http": {
						"hostnames": ["example.com"],
						"ports": {"numbers": [65536]}
					}
				}]
			}`,
			wantErr: "out of range",
		},
		{
			name: "duplicate port number within rule",
			json: `{
				"rules": [{
					"http": {
						"hostnames": ["example.com"],
						"ports": {"numbers": [80, 80]}
					}
				}]
			}`,
			wantErr: "duplicate port",
		},
		{
			name: "effects with empty replaceHeaders",
			json: `{
				"rules": [{
					"http": {
						"hostnames": ["example.com"],
						"effects": {"replaceHeaders": []}
					}
				}]
			}`,
			wantErr: "at least one replace_headers entry is required",
		},
		{
			name: "effects with invalid header name",
			json: `{
				"rules": [{
					"http": {
						"hostnames": ["example.com"],
						"effects": {
							"replaceHeaders": [{
								"header": "Bad Header Name",
								"credentialUri": "secret://token"
							}]
						}
					}
				}]
			}`,
			wantErr: "invalid header name",
		},
		{
			name: "effects with duplicate header name case-insensitive",
			json: `{
				"rules": [{
					"http": {
						"hostnames": ["example.com"],
						"effects": {
							"replaceHeaders": [
								{"header": "Authorization", "credentialUri": "secret://t1"},
								{"header": "authorization", "credentialUri": "secret://t2"}
							]
						}
					}
				}]
			}`,
			wantErr: "duplicate header",
		},
		{
			name: "effects with invalid prefix control chars",
			json: `{
				"rules": [{
					"http": {
						"hostnames": ["example.com"],
						"effects": {
							"replaceHeaders": [{
								"header": "Authorization",
								"prefix": "Bearer\r",
								"credentialUri": "secret://token"
							}]
						}
					}
				}]
			}`,
			wantErr: "invalid prefix",
		},
		{
			name: "effects with missing credential_uri",
			json: `{
				"rules": [{
					"http": {
						"hostnames": ["example.com"],
						"effects": {
							"replaceHeaders": [{
								"header": "Authorization"
							}]
						}
					}
				}]
			}`,
			wantErr: "credential_uri is required",
		},
		{
			name: "credential_uri with empty secret name",
			json: `{
				"rules": [{
					"http": {
						"hostnames": ["example.com"],
						"effects": {
							"replaceHeaders": [{
								"header": "Authorization",
								"credentialUri": "secret://"
							}]
						}
					}
				}]
			}`,
			wantErr: "must be secret://<name>",
		},
		{
			name: "credential_uri with path",
			json: `{
				"rules": [{
					"http": {
						"hostnames": ["example.com"],
						"effects": {
							"replaceHeaders": [{
								"header": "Authorization",
								"credentialUri": "secret://name/extra"
							}]
						}
					}
				}]
			}`,
			wantErr: "must be secret://<name>",
		},
		{
			name: "credential_uri with query parameters",
			json: `{
				"rules": [{
					"http": {
						"hostnames": ["example.com"],
						"effects": {
							"replaceHeaders": [{
								"header": "Authorization",
								"credentialUri": "secret://name?query=val"
							}]
						}
					}
				}]
			}`,
			wantErr: "must be secret://<name>",
		},
		{
			name: "credential_uri with port",
			json: `{
				"rules": [{
					"http": {
						"hostnames": ["example.com"],
						"effects": {
							"replaceHeaders": [{
								"header": "Authorization",
								"credentialUri": "secret://name:80"
							}]
						}
					}
				}]
			}`,
			wantErr: "must be secret://<name>",
		},
		{
			name: "credential_uri with https scheme",
			json: `{
				"rules": [{
					"http": {
						"hostnames": ["example.com"],
						"effects": {
							"replaceHeaders": [{
								"header": "Authorization",
								"credentialUri": "https://example.com/secret"
							}]
						}
					}
				}]
			}`,
			wantErr: "must be secret://<name>",
		},
		{
			name: "credential_uri with ate-secret scheme",
			json: `{
				"rules": [{
					"http": {
						"hostnames": ["example.com"],
						"effects": {
							"replaceHeaders": [{
								"header": "Authorization",
								"credentialUri": "ate-secret://kubernetes.io/provider/ns/name"
							}]
						}
					}
				}]
			}`,
			wantErr: "must be secret://<name>",
		},
		{
			name: "two rules tie on same pattern and default port",
			json: `{
				"rules": [
					{"http": {"hostnames": ["api.example.com"]}},
					{"http": {"hostnames": ["api.example.com"]}}
				]
			}`,
			wantErr: "ties with",
		},
		{
			name: "two rules tie on same pattern and explicit same port",
			json: `{
				"rules": [
					{"https": {"hostnames": ["api.example.com"], "ports": {"numbers": [8443]}}},
					{"https": {"hostnames": ["api.example.com"], "ports": {"numbers": [8443]}}}
				]
			}`,
			wantErr: "ties with",
		},
		{
			name: "two rules tie on same pattern and every port",
			json: `{
				"rules": [
					{"http": {"hostnames": ["*"], "ports": {"all": {}}}},
					{"https": {"hostnames": ["*"], "ports": {"all": {}}}}
				]
			}`,
			wantErr: "ties with",
		},
		{
			name: "two rules tie on overlapping port list",
			json: `{
				"rules": [
					{"https": {"hostnames": ["api.example.com"], "ports": {"numbers": [443, 8080]}}},
					{"https": {"hostnames": ["api.example.com"], "ports": {"numbers": [8080, 9000]}}}
				]
			}`,
			wantErr: "ties with",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadPolicy([]byte(tc.json))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %q", tc.wantErr, err.Error())
			}
		})
	}
}

func TestLoadPolicy_SizeLimits_Rejected(t *testing.T) {
	t.Run("too many rules (257)", func(t *testing.T) {
		p := &EgressPolicy{}
		for i := 0; i < 257; i++ {
			p.Rules = append(p.Rules, &EgressRule{
				Http: &HttpRule{
					Hostnames: []string{fmt.Sprintf("host%d.example.com", i)},
				},
			})
		}
		err := p.Validate()
		if err == nil || !strings.Contains(err.Error(), "at most 256 rules allowed") {
			t.Fatalf("expected 256 rules limit error, got: %v", err)
		}
	})

	t.Run("too many hostnames in a rule (257)", func(t *testing.T) {
		var hosts []string
		for i := 0; i < 257; i++ {
			hosts = append(hosts, fmt.Sprintf("host%d.example.com", i))
		}
		p := &EgressPolicy{
			Rules: []*EgressRule{
				{Http: &HttpRule{Hostnames: hosts}},
			},
		}
		err := p.Validate()
		if err == nil || !strings.Contains(err.Error(), "at most 256 hostnames allowed") {
			t.Fatalf("expected 256 hostnames limit error, got: %v", err)
		}
	})

	t.Run("too many ports in a rule (17)", func(t *testing.T) {
		var ports []int32
		for i := int32(1); i <= 17; i++ {
			ports = append(ports, 8000+i)
		}
		p := &EgressPolicy{
			Rules: []*EgressRule{
				{Http: &HttpRule{Hostnames: []string{"example.com"}, Ports: &Ports{Numbers: ports}}},
			},
		}
		err := p.Validate()
		if err == nil || !strings.Contains(err.Error(), "at most 16 ports allowed") {
			t.Fatalf("expected 16 ports limit error, got: %v", err)
		}
	})

	t.Run("too many replace_headers in a rule (17)", func(t *testing.T) {
		var headers []*CredentialHeader
		for i := 0; i < 17; i++ {
			headers = append(headers, &CredentialHeader{
				Header:        fmt.Sprintf("X-Header-%d", i),
				CredentialUri: fmt.Sprintf("secret://token-%d", i),
			})
		}
		p := &EgressPolicy{
			Rules: []*EgressRule{
				{
					Http: &HttpRule{
						Hostnames: []string{"example.com"},
						Effects:   &HttpRuleEffects{ReplaceHeaders: headers},
					},
				},
			},
		}
		err := p.Validate()
		if err == nil || !strings.Contains(err.Error(), "at most 16 replace_headers allowed") {
			t.Fatalf("expected 16 replace_headers limit error, got: %v", err)
		}
	})
}

func TestValidate_ReportsAllErrors(t *testing.T) {
	// Verify that Validate does not return at the first error, but instead
	// collects and reports every issue in the policy via errors.Join.
	policyJSON := `{
		"rules": [
			{
				"http": {
					"hostnames": ["invalid..hostname", "good.example.com"],
					"ports": {"numbers": [80, 80]}
				}
			},
			{
				"https": {
					"hostnames": ["good.example.com"],
					"ports": {"numbers": [80]},
					"effects": {
						"replaceHeaders": [
							{
								"header": "Authorization",
								"prefix": "Bearer\r",
								"credentialUri": "https://invalid-uri.example.com"
							}
						]
					}
				}
			},
			{
				"tlsPassthrough": {
					"hostnames": ["secure.example.com"],
					"ports": {"all": {}}
				}
			}
		]
	}`

	_, err := LoadPolicy([]byte(policyJSON))
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	expectedSubstrings := []string{
		`rules[0].http.hostnames: invalid hostname pattern "invalid..hostname"`,
		`rules[0].http.ports.numbers: duplicate port 80`,
		`rules[1] ties with rules[0] on "good.example.com" on port 80`,
		`rules[1].https.effects.replace_headers[0].prefix: invalid prefix "Bearer\r"`,
		`rules[1].https.effects.replace_headers[0].credential_uri: invalid credential URI "https://invalid-uri.example.com", must be secret://<name>`,
		`rules[2].tls_passthrough: tls_passthrough is not supported`,
	}

	errStr := err.Error()
	for _, substr := range expectedSubstrings {
		if !strings.Contains(errStr, substr) {
			t.Errorf("expected error to contain %q, but got:\n%s", substr, errStr)
		}
	}
}

func TestValidate_NilCases(t *testing.T) {
	var p *EgressPolicy
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "policy cannot be nil") {
		t.Fatalf("expected nil policy error, got %v", err)
	}

	p = &EgressPolicy{Rules: []*EgressRule{nil}}
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "rule cannot be nil") {
		t.Fatalf("expected nil rule error, got %v", err)
	}
}
