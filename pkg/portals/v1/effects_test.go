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
	"net/http"
	"strings"
	"testing"
)

func TestApplyEffects_Present(t *testing.T) {
	// Canonical GitHub case: replace Authorization placeholder with Bearer token
	rule := &EgressRule{
		Https: &HttpsRule{
			Hostnames: []string{"api.github.com"},
			Effects: &HttpRuleEffects{
				ReplaceHeaders: []*CredentialHeader{
					{
						Header:        "Authorization",
						Prefix:        "Bearer ",
						CredentialUri: "secret://github-token",
					},
				},
			},
		},
	}

	resolver := func(name string) ([]byte, error) {
		if name == "github-token" {
			return []byte("ghp_secret1234567890"), nil
		}
		return nil, errors.New("unexpected secret name")
	}

	headers := http.Header{
		"Authorization": []string{"placeholder"},
		"Accept":        []string{"application/vnd.github.v3+json"},
	}

	if err := rule.ApplyEffects(headers, resolver); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := headers.Get("Authorization"); got != "Bearer ghp_secret1234567890" {
		t.Errorf("Authorization header = %q, want %q", got, "Bearer ghp_secret1234567890")
	}
	if got := headers.Get("Accept"); got != "application/vnd.github.v3+json" {
		t.Errorf("Accept header = %q, want %q", got, "application/vnd.github.v3+json")
	}
}

func TestApplyEffects_Absent(t *testing.T) {
	// When request does not carry the header, it is left unchanged and resolver is not called.
	rule := &EgressRule{
		Https: &HttpsRule{
			Hostnames: []string{"api.github.com"},
			Effects: &HttpRuleEffects{
				ReplaceHeaders: []*CredentialHeader{
					{
						Header:        "Authorization",
						Prefix:        "Bearer ",
						CredentialUri: "secret://github-token",
					},
				},
			},
		},
	}

	resolverCalled := false
	resolver := func(name string) ([]byte, error) {
		resolverCalled = true
		return nil, errors.New("resolver should not be called")
	}

	headers := http.Header{
		"User-Agent": []string{"curl/8.0"},
	}

	if err := rule.ApplyEffects(headers, resolver); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resolverCalled {
		t.Error("resolver was called for an absent header")
	}
	if got := headers.Get("Authorization"); got != "" {
		t.Errorf("Authorization header should be empty, got %q", got)
	}
	if got := headers.Get("User-Agent"); got != "curl/8.0" {
		t.Errorf("User-Agent = %q, want %q", got, "curl/8.0")
	}
}

func TestApplyEffects_CaseDifferences(t *testing.T) {
	tests := []struct {
		name          string
		ruleHeader    string
		requestHeader string
	}{
		{
			name:          "rule has Canonical, request has lowercase",
			ruleHeader:    "Authorization",
			requestHeader: "authorization",
		},
		{
			name:          "rule has Canonical, request has UPPERCASE",
			ruleHeader:    "Authorization",
			requestHeader: "AUTHORIZATION",
		},
		{
			name:          "rule has Canonical, request has mixedCase",
			ruleHeader:    "Authorization",
			requestHeader: "aUtHoRiZaTiOn",
		},
		{
			name:          "rule has lowercase, request has Canonical",
			ruleHeader:    "authorization",
			requestHeader: "Authorization",
		},
		{
			name:          "rule has lowercase, request has UPPERCASE",
			ruleHeader:    "authorization",
			requestHeader: "AUTHORIZATION",
		},
		{
			name:          "custom header case differences",
			ruleHeader:    "x-api-key",
			requestHeader: "X-Api-Key",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rule := &EgressRule{
				Https: &HttpsRule{
					Hostnames: []string{"api.example.com"},
					Effects: &HttpRuleEffects{
						ReplaceHeaders: []*CredentialHeader{
							{
								Header:        tc.ruleHeader,
								Prefix:        "Bearer ",
								CredentialUri: "secret://my-token",
							},
						},
					},
				},
			}

			resolver := func(name string) ([]byte, error) {
				if name == "my-token" {
					return []byte("secret_value"), nil
				}
				return nil, errors.New("not found")
			}

			headers := http.Header{
				tc.requestHeader: []string{"placeholder"},
			}

			if err := rule.ApplyEffects(headers, resolver); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if got := headers.Get(tc.ruleHeader); got != "Bearer secret_value" {
				t.Errorf("headers.Get(%q) = %q, want %q", tc.ruleHeader, got, "Bearer secret_value")
			}
			if got := headers.Get(tc.requestHeader); got != "Bearer secret_value" {
				t.Errorf("headers.Get(%q) = %q, want %q", tc.requestHeader, got, "Bearer secret_value")
			}

			// Ensure raw map no longer contains the old key if it differed in casing
			for k, v := range headers {
				if strings.EqualFold(k, tc.ruleHeader) && len(v) > 0 {
					if v[0] == "placeholder" {
						t.Errorf("placeholder leaked under key %q: %v", k, v)
					}
				}
			}
		})
	}
}

func TestApplyEffects_MultipleCasingsInRequest(t *testing.T) {
	// If request carries duplicate headers with different casings, all placeholders
	// must be replaced/discarded and only the credential header retained.
	rule := &EgressRule{
		Https: &HttpsRule{
			Hostnames: []string{"api.example.com"},
			Effects: &HttpRuleEffects{
				ReplaceHeaders: []*CredentialHeader{
					{
						Header:        "Authorization",
						Prefix:        "Bearer ",
						CredentialUri: "secret://my-token",
					},
				},
			},
		},
	}

	resolver := func(name string) ([]byte, error) {
		return []byte("token123"), nil
	}

	headers := http.Header{
		"authorization": []string{"placeholder1"},
		"Authorization": []string{"placeholder2"},
		"AUTHORIZATION": []string{"placeholder3"},
	}

	if err := rule.ApplyEffects(headers, resolver); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := headers.Get("Authorization"); got != "Bearer token123" {
		t.Errorf("Authorization = %q, want %q", got, "Bearer token123")
	}

	count := 0
	for k, v := range headers {
		if strings.EqualFold(k, "Authorization") {
			count++
			if len(v) != 1 || v[0] != "Bearer token123" {
				t.Errorf("unexpected value for %q: %v", k, v)
			}
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 matching header in map, got %d", count)
	}
}

func TestApplyEffects_Prefix(t *testing.T) {
	tests := []struct {
		name      string
		prefix    string
		token     string
		wantValue string
	}{
		{
			name:      "Bearer with trailing space",
			prefix:    "Bearer ",
			token:     "secret-token",
			wantValue: "Bearer secret-token",
		},
		{
			name:      "Empty prefix",
			prefix:    "",
			token:     "raw-api-key",
			wantValue: "raw-api-key",
		},
		{
			name:      "Token with trailing space",
			prefix:    "Token ",
			token:     "my-token",
			wantValue: "Token my-token",
		},
		{
			name:      "Custom prefix without space",
			prefix:    "Key:",
			token:     "secret-value",
			wantValue: "Key:secret-value",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rule := &EgressRule{
				Http: &HttpRule{
					Hostnames: []string{"api.example.com"},
					Effects: &HttpRuleEffects{
						ReplaceHeaders: []*CredentialHeader{
							{
								Header:        "X-Credential",
								Prefix:        tc.prefix,
								CredentialUri: "secret://cred",
							},
						},
					},
				},
			}

			resolver := func(name string) ([]byte, error) {
				return []byte(tc.token), nil
			}

			headers := http.Header{
				"X-Credential": []string{"placeholder"},
			}

			if err := rule.ApplyEffects(headers, resolver); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if got := headers.Get("X-Credential"); got != tc.wantValue {
				t.Errorf("X-Credential = %q, want %q", got, tc.wantValue)
			}
		})
	}
}

func TestApplyEffects_SeveralHeaders(t *testing.T) {
	rule := &EgressRule{
		Https: &HttpsRule{
			Hostnames: []string{"api.example.com"},
			Effects: &HttpRuleEffects{
				ReplaceHeaders: []*CredentialHeader{
					{
						Header:        "Authorization",
						Prefix:        "Bearer ",
						CredentialUri: "secret://auth-token",
					},
					{
						Header:        "X-API-Key",
						Prefix:        "",
						CredentialUri: "secret://api-key",
					},
					{
						Header:        "X-Signature",
						Prefix:        "sig=",
						CredentialUri: "secret://signature-key",
					},
				},
			},
		},
	}

	secrets := map[string][]byte{
		"auth-token":    []byte("auth_val"),
		"api-key":       []byte("key_val"),
		"signature-key": []byte("sig_val"),
	}
	resolver := func(name string) ([]byte, error) {
		if b, ok := secrets[name]; ok {
			return b, nil
		}
		return nil, errors.New("not found")
	}

	t.Run("all headers present", func(t *testing.T) {
		headers := http.Header{
			"Authorization": []string{"dummy1"},
			"X-API-Key":     []string{"dummy2"},
			"X-Signature":   []string{"dummy3"},
			"Content-Type":  []string{"application/json"},
		}

		if err := rule.ApplyEffects(headers, resolver); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got := headers.Get("Authorization"); got != "Bearer auth_val" {
			t.Errorf("Authorization = %q, want %q", got, "Bearer auth_val")
		}
		if got := headers.Get("X-API-Key"); got != "key_val" {
			t.Errorf("X-API-Key = %q, want %q", got, "key_val")
		}
		if got := headers.Get("X-Signature"); got != "sig=sig_val" {
			t.Errorf("X-Signature = %q, want %q", got, "sig=sig_val")
		}
		if got := headers.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q, want %q", got, "application/json")
		}
	})

	t.Run("subset of headers present", func(t *testing.T) {
		headers := http.Header{
			"Authorization": []string{"dummy1"},
			"Content-Type":  []string{"application/json"},
		}

		if err := rule.ApplyEffects(headers, resolver); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got := headers.Get("Authorization"); got != "Bearer auth_val" {
			t.Errorf("Authorization = %q, want %q", got, "Bearer auth_val")
		}
		if got := headers.Get("X-API-Key"); got != "" {
			t.Errorf("X-API-Key should be absent, got %q", got)
		}
		if got := headers.Get("X-Signature"); got != "" {
			t.Errorf("X-Signature should be absent, got %q", got)
		}
		if got := headers.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q, want %q", got, "application/json")
		}
	})
}

func TestApplyEffects_UnresolvedSecret(t *testing.T) {
	rule := &EgressRule{
		Https: &HttpsRule{
			Hostnames: []string{"api.example.com"},
			Effects: &HttpRuleEffects{
				ReplaceHeaders: []*CredentialHeader{
					{
						Header:        "Authorization",
						Prefix:        "Bearer ",
						CredentialUri: "secret://missing-token",
					},
				},
			},
		},
	}

	t.Run("resolver returns error", func(t *testing.T) {
		resolver := func(name string) ([]byte, error) {
			return nil, errors.New("secret store unavailable")
		}

		headers := http.Header{
			"Authorization": []string{"placeholder"},
		}

		err := rule.ApplyEffects(headers, resolver)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "missing-token") {
			t.Errorf("expected secret name in error, got: %v", err)
		}
		// Ensure placeholder is not modified
		if got := headers.Get("Authorization"); got != "placeholder" {
			t.Errorf("placeholder was modified on error, got %q", got)
		}
	})

	t.Run("resolver returns nil bytes", func(t *testing.T) {
		resolver := func(name string) ([]byte, error) {
			return nil, nil
		}

		headers := http.Header{
			"Authorization": []string{"placeholder"},
		}

		err := rule.ApplyEffects(headers, resolver)
		if err == nil {
			t.Fatal("expected error for nil secret bytes, got nil")
		}
		if got := headers.Get("Authorization"); got != "placeholder" {
			t.Errorf("placeholder was modified on error, got %q", got)
		}
	})

	t.Run("absent header does not fail on missing secret", func(t *testing.T) {
		resolver := func(name string) ([]byte, error) {
			return nil, errors.New("secret store unavailable")
		}

		headers := http.Header{
			"User-Agent": []string{"test"},
		}

		if err := rule.ApplyEffects(headers, resolver); err != nil {
			t.Fatalf("unexpected error for absent header: %v", err)
		}
	})

	t.Run("atomic failure in multi-header rule does not forward partial credentials", func(t *testing.T) {
		multiRule := &EgressRule{
			Https: &HttpsRule{
				Hostnames: []string{"api.example.com"},
				Effects: &HttpRuleEffects{
					ReplaceHeaders: []*CredentialHeader{
						{
							Header:        "Authorization",
							Prefix:        "Bearer ",
							CredentialUri: "secret://valid-token",
						},
						{
							Header:        "X-Secret",
							Prefix:        "",
							CredentialUri: "secret://unresolved-token",
						},
					},
				},
			},
		}

		resolver := func(name string) ([]byte, error) {
			if name == "valid-token" {
				return []byte("valid_val"), nil
			}
			return nil, errors.New("not found")
		}

		headers := http.Header{
			"Authorization": []string{"placeholder1"},
			"X-Secret":      []string{"placeholder2"},
		}

		err := multiRule.ApplyEffects(headers, resolver)
		if err == nil {
			t.Fatal("expected error due to unresolved secret, got nil")
		}

		// Ensure neither header was replaced
		if got := headers.Get("Authorization"); got != "placeholder1" {
			t.Errorf("Authorization was partially modified: %q", got)
		}
		if got := headers.Get("X-Secret"); got != "placeholder2" {
			t.Errorf("X-Secret was partially modified: %q", got)
		}
	})
}

func TestApplyEffects_InvalidHeaderValue(t *testing.T) {
	rule := &EgressRule{
		Https: &HttpsRule{
			Hostnames: []string{"api.example.com"},
			Effects: &HttpRuleEffects{
				ReplaceHeaders: []*CredentialHeader{
					{
						Header:        "Authorization",
						Prefix:        "Bearer ",
						CredentialUri: "secret://bad-token",
					},
				},
			},
		},
	}

	tests := []struct {
		name        string
		secretBytes []byte
	}{
		{
			name:        "trailing newline (e.g. from file)",
			secretBytes: []byte("token-value\n"),
		},
		{
			name:        "CRLF newline",
			secretBytes: []byte("token-value\r\n"),
		},
		{
			name:        "null byte",
			secretBytes: []byte("token\x00value"),
		},
		{
			name:        "ASCII control character (BEL)",
			secretBytes: []byte("token\x07value"),
		},
		{
			name:        "ASCII DEL character (0x7f)",
			secretBytes: []byte("token\x7fvalue"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resolver := func(name string) ([]byte, error) {
				if name == "bad-token" {
					return tc.secretBytes, nil
				}
				return nil, errors.New("not found")
			}

			headers := http.Header{
				"Authorization": []string{"placeholder"},
			}

			err := rule.ApplyEffects(headers, resolver)
			if err == nil {
				t.Fatalf("expected error for %s, got nil", tc.name)
			}

			// Must name the secret
			if !strings.Contains(err.Error(), "bad-token") {
				t.Errorf("error does not name secret: %v", err)
			}

			// Must not contain the secret value
			if strings.Contains(err.Error(), string(tc.secretBytes)) {
				t.Errorf("error contains secret value: %v", err)
			}

			// Placeholder must not be modified or forwarded
			if got := headers.Get("Authorization"); got != "placeholder" {
				t.Errorf("placeholder was modified on invalid header value, got %q", got)
			}
		})
	}
}

func TestApplyEffects_CredentialNeverInError(t *testing.T) {
	secretVal := "super-sensitive-token-9999"
	rule := &EgressRule{
		Https: &HttpsRule{
			Hostnames: []string{"api.example.com"},
			Effects: &HttpRuleEffects{
				ReplaceHeaders: []*CredentialHeader{
					{
						Header:        "Authorization",
						Prefix:        "Bearer ",
						CredentialUri: "secret://my-token",
					},
				},
			},
		},
	}

	resolver := func(name string) ([]byte, error) {
		return nil, errors.New("lookup failed")
	}

	headers := http.Header{
		"Authorization": []string{"placeholder"},
	}

	err := rule.ApplyEffects(headers, resolver)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if strings.Contains(err.Error(), secretVal) {
		t.Errorf("secret value appeared in error: %v", err)
	}
}

func TestApplyEffects_NilAndEmptyEdgeCases(t *testing.T) {
	resolver := func(name string) ([]byte, error) {
		return []byte("token"), nil
	}

	// 1. Nil rule
	var nilRule *EgressRule
	headers := http.Header{"Authorization": []string{"placeholder"}}
	if err := nilRule.ApplyEffects(headers, resolver); err != nil {
		t.Errorf("unexpected error on nil rule: %v", err)
	}
	if got := headers.Get("Authorization"); got != "placeholder" {
		t.Errorf("headers modified on nil rule: %q", got)
	}

	// 2. Rule without effects
	noEffectsRule := &EgressRule{
		Https: &HttpsRule{Hostnames: []string{"example.com"}},
	}
	if err := noEffectsRule.ApplyEffects(headers, resolver); err != nil {
		t.Errorf("unexpected error on no effects rule: %v", err)
	}

	// 3. TlsPassthrough rule
	passthroughRule := &EgressRule{
		TlsPassthrough: &TlsPassthroughRule{Hostnames: []string{"example.com"}},
	}
	if err := passthroughRule.ApplyEffects(headers, resolver); err != nil {
		t.Errorf("unexpected error on tls passthrough rule: %v", err)
	}

	// 4. Nil headers
	validRule := &EgressRule{
		Https: &HttpsRule{
			Effects: &HttpRuleEffects{
				ReplaceHeaders: []*CredentialHeader{
					{
						Header:        "Authorization",
						CredentialUri: "secret://my-token",
					},
				},
			},
		},
	}
	if err := validRule.ApplyEffects(nil, resolver); err != nil {
		t.Errorf("unexpected error on nil headers: %v", err)
	}

	// 5. Nil resolver when header is present
	if err := validRule.ApplyEffects(headers, nil); err == nil {
		t.Error("expected error when resolver is nil and header is present")
	}

	// 6. ActorJwt unsupported
	actorJwtRule := &EgressRule{
		Https: &HttpsRule{
			Effects: &HttpRuleEffects{
				ReplaceHeaders: []*CredentialHeader{
					{
						Header:   "Authorization",
						ActorJwt: &ActorJwtSource{Audiences: []string{"aud"}},
					},
				},
			},
		},
	}
	if err := actorJwtRule.ApplyEffects(headers, resolver); err == nil {
		t.Error("expected error on actor_jwt")
	}
}

func TestApplyEffects_IntegrationWithLoadPolicyAndMatch(t *testing.T) {
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
			}
		]
	}`

	policy, err := LoadPolicy([]byte(jsonPolicy))
	if err != nil {
		t.Fatalf("LoadPolicy failed: %v", err)
	}

	decidingRule := policy.Match(ProtocolHTTPS, "api.github.com", 443)
	if decidingRule == nil {
		t.Fatal("expected deciding rule for api.github.com:443")
	}

	secrets := map[string][]byte{
		"github-token": []byte("ghp_live_secret_token"),
	}
	resolver := func(name string) ([]byte, error) {
		if b, ok := secrets[name]; ok {
			return b, nil
		}
		return nil, errors.New("secret not found")
	}

	// Case 1: Request with placeholder
	headers1 := http.Header{
		"Authorization": []string{"ghp_placeholder"},
		"User-Agent":    []string{"git/2.40.0"},
	}
	if err := decidingRule.ApplyEffects(headers1, resolver); err != nil {
		t.Fatalf("ApplyEffects failed: %v", err)
	}
	if got := headers1.Get("Authorization"); got != "Bearer ghp_live_secret_token" {
		t.Errorf("Authorization = %q, want %q", got, "Bearer ghp_live_secret_token")
	}
	if got := headers1.Get("User-Agent"); got != "git/2.40.0" {
		t.Errorf("User-Agent = %q, want %q", got, "git/2.40.0")
	}

	// Case 2: Request without placeholder
	headers2 := http.Header{
		"User-Agent": []string{"git/2.40.0"},
	}
	if err := decidingRule.ApplyEffects(headers2, resolver); err != nil {
		t.Fatalf("ApplyEffects failed: %v", err)
	}
	if got := headers2.Get("Authorization"); got != "" {
		t.Errorf("Authorization should be absent, got %q", got)
	}
}

func TestApplyEffects_MalformedCredentialURI(t *testing.T) {
	tests := []struct {
		name          string
		credentialURI string
	}{
		{
			name:          "empty credential_uri",
			credentialURI: "",
		},
		{
			name:          "missing secret:// prefix",
			credentialURI: "my-token",
		},
		{
			name:          "secret:// with empty name",
			credentialURI: "secret://",
		},
		{
			name:          "https scheme",
			credentialURI: "https://example.com/secret",
		},
		{
			name:          "secret:// with path",
			credentialURI: "secret://my-token/extra",
		},
		{
			name:          "secret:// with port",
			credentialURI: "secret://my-token:80",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rule := &EgressRule{
				Https: &HttpsRule{
					Hostnames: []string{"api.example.com"},
					Effects: &HttpRuleEffects{
						ReplaceHeaders: []*CredentialHeader{
							{
								Header:        "Authorization",
								Prefix:        "Bearer ",
								CredentialUri: tc.credentialURI,
							},
						},
					},
				},
			}

			resolverCalled := false
			resolver := func(name string) ([]byte, error) {
				resolverCalled = true
				return []byte("secret_value"), nil
			}

			headers := http.Header{
				"Authorization": []string{"placeholder"},
				"Content-Type":  []string{"application/json"},
			}

			err := rule.ApplyEffects(headers, resolver)
			if err == nil {
				t.Fatalf("expected error for credential URI %q, got nil", tc.credentialURI)
			}
			if resolverCalled {
				t.Error("resolver was called for malformed credential URI")
			}
			if got := headers.Get("Authorization"); got != "placeholder" {
				t.Errorf("Authorization header was modified: %q, want %q", got, "placeholder")
			}
			if got := headers.Get("Content-Type"); got != "application/json" {
				t.Errorf("Content-Type header was modified: %q, want %q", got, "application/json")
			}
		})
	}

	t.Run("atomic failure with malformed credential URI leaves other headers untouched", func(t *testing.T) {
		rule := &EgressRule{
			Https: &HttpsRule{
				Hostnames: []string{"api.example.com"},
				Effects: &HttpRuleEffects{
					ReplaceHeaders: []*CredentialHeader{
						{
							Header:        "Authorization",
							Prefix:        "Bearer ",
							CredentialUri: "secret://valid-token",
						},
						{
							Header:        "X-Bad-Cred",
							Prefix:        "",
							CredentialUri: "malformed-uri",
						},
					},
				},
			},
		}

		resolver := func(name string) ([]byte, error) {
			if name == "valid-token" {
				return []byte("valid_token_val"), nil
			}
			t.Errorf("unexpected secret lookup for %q", name)
			return nil, errors.New("unexpected lookup")
		}

		headers := http.Header{
			"Authorization": []string{"placeholder1"},
			"X-Bad-Cred":    []string{"placeholder2"},
		}

		err := rule.ApplyEffects(headers, resolver)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if got := headers.Get("Authorization"); got != "placeholder1" {
			t.Errorf("Authorization header was modified: %q", got)
		}
		if got := headers.Get("X-Bad-Cred"); got != "placeholder2" {
			t.Errorf("X-Bad-Cred header was modified: %q", got)
		}
	})
}

func TestBackendURL(t *testing.T) {
	t.Run("nil rule returns nil", func(t *testing.T) {
		var r *EgressRule
		u, err := r.BackendURL()
		if err != nil || u != nil {
			t.Fatalf("got (%v, %v), want (nil, nil)", u, err)
		}
	})

	t.Run("rule without effects returns nil", func(t *testing.T) {
		r := &EgressRule{Https: &HttpsRule{Hostnames: []string{"proxy.golang.org"}}}
		u, err := r.BackendURL()
		if err != nil || u != nil {
			t.Fatalf("got (%v, %v), want (nil, nil)", u, err)
		}
	})

	t.Run("tls passthrough rule returns nil", func(t *testing.T) {
		r := &EgressRule{TlsPassthrough: &TlsPassthroughRule{Hostnames: []string{"example.com"}}}
		u, err := r.BackendURL()
		if err != nil || u != nil {
			t.Fatalf("got (%v, %v), want (nil, nil)", u, err)
		}
	})

	t.Run("http rule with valid backend URL", func(t *testing.T) {
		r := &EgressRule{
			Http: &HttpRule{
				Hostnames: []string{"deb.debian.org"},
				Effects:   &HttpRuleEffects{BackendUrl: "http://apt-cache.service-portal-system.svc:3142"},
			},
		}
		u, err := r.BackendURL()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if u == nil || u.Scheme != "http" || u.Host != "apt-cache.service-portal-system.svc:3142" {
			t.Fatalf("got %v, want http://apt-cache.service-portal-system.svc:3142", u)
		}
	})

	t.Run("https rule with valid backend URL", func(t *testing.T) {
		r := &EgressRule{
			Https: &HttpsRule{
				Hostnames: []string{"proxy.golang.org"},
				Effects:   &HttpRuleEffects{BackendUrl: "http://goproxy-cache.service-portal-system.svc:8080"},
			},
		}
		u, err := r.BackendURL()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if u == nil || u.Scheme != "http" || u.Host != "goproxy-cache.service-portal-system.svc:8080" {
			t.Fatalf("got %v, want http://goproxy-cache.service-portal-system.svc:8080", u)
		}
	})

	t.Run("malformed backend URL returns error", func(t *testing.T) {
		r := &EgressRule{
			Https: &HttpsRule{
				Hostnames: []string{"proxy.golang.org"},
				Effects:   &HttpRuleEffects{BackendUrl: "ftp://bad.example.com"},
			},
		}
		if u, err := r.BackendURL(); err == nil {
			t.Fatalf("expected error, got URL %v", u)
		}
	})
}
