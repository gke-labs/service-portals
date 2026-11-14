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
	"net/http"
	"strings"
)

// SecretResolver resolves a secret name to its token bytes.
// If the secret cannot be resolved, it returns a non-nil error.
type SecretResolver func(name string) ([]byte, error)

// ApplyEffects applies the EgressRule's effects to the request headers.
// Credentials are retrieved using the provided SecretResolver.
// Headers listed in replace_headers are replaced only when already present in the request.
func (r *EgressRule) ApplyEffects(headers http.Header, resolve SecretResolver) error {
	if r == nil || headers == nil {
		return nil
	}
	var effects *HttpRuleEffects
	if r.Http != nil {
		effects = r.Http.Effects
	} else if r.Https != nil {
		effects = r.Https.Effects
	}
	if effects == nil || len(effects.ReplaceHeaders) == 0 {
		return nil
	}

	type pendingReplacement struct {
		matchedKeys []string
		header      string
		value       string
	}
	var pending []pendingReplacement

	for _, rh := range effects.ReplaceHeaders {
		if rh == nil || rh.Header == "" {
			continue
		}

		var matchedKeys []string
		for k := range headers {
			if strings.EqualFold(k, rh.Header) {
				matchedKeys = append(matchedKeys, k)
			}
		}
		if len(matchedKeys) == 0 {
			continue
		}

		if rh.ActorJwt != nil {
			return errors.New("actor_jwt credential source is not supported")
		}

		secretName, err := parseCredentialURI(rh.CredentialUri)
		if err != nil {
			return err
		}
		if resolve == nil {
			return fmt.Errorf("resolving secret %q: no secret resolver provided", secretName)
		}

		secretBytes, err := resolve(secretName)
		if err != nil {
			return fmt.Errorf("resolving secret %q: %w", secretName, err)
		}
		if secretBytes == nil {
			return fmt.Errorf("resolving secret %q: secret not found", secretName)
		}
		if !isValidHeaderValue(string(secretBytes)) {
			return fmt.Errorf("resolving secret %q: credential value cannot be a header value", secretName)
		}

		pending = append(pending, pendingReplacement{
			matchedKeys: matchedKeys,
			header:      rh.Header,
			value:       rh.Prefix + string(secretBytes),
		})
	}

	for _, p := range pending {
		for _, k := range p.matchedKeys {
			delete(headers, k)
		}
		headers.Set(p.header, p.value)
	}

	return nil
}
