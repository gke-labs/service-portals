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
	"fmt"
)

// SecretGetter abstracts retrieving a secret value by namespace, name, and key.
type SecretGetter interface {
	GetSecretKey(namespace, name, key string) (string, error)
}

// SecretGetterFunc allows using a standalone function as a SecretGetter.
type SecretGetterFunc func(namespace, name, key string) (string, error)

// GetSecretKey implements SecretGetter.
func (f SecretGetterFunc) GetSecretKey(namespace, name, key string) (string, error) {
	return f(namespace, name, key)
}

// MapSecretGetter implements SecretGetter backed by a map.
// It supports keys formatted as "namespace/secretName" -> "key" -> "value"
// or simply "secretName" -> "key" -> "value".
type MapSecretGetter map[string]map[string]string

// GetSecretKey implements SecretGetter for MapSecretGetter.
func (m MapSecretGetter) GetSecretKey(namespace, name, key string) (string, error) {
	// First check namespace/name
	fullKey := fmt.Sprintf("%s/%s", namespace, name)
	if secretData, ok := m[fullKey]; ok {
		if val, exists := secretData[key]; exists {
			return val, nil
		}
		return "", fmt.Errorf("secret %q has no key %q", fullKey, key)
	}

	// Fallback to name only
	if secretData, ok := m[name]; ok {
		if val, exists := secretData[key]; exists {
			return val, nil
		}
		return "", fmt.Errorf("secret %q has no key %q", name, key)
	}

	return "", fmt.Errorf("secret %q not found in namespace %q", name, namespace)
}
