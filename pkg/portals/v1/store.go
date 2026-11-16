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
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"sync"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// Secret holds sensitive token bytes. Its formatting and logging representations
// never include the underlying value to prevent accidental secret leakage.
type Secret struct {
	value []byte
}

// String returns "[REDACTED]" to prevent secret leakage.
func (s Secret) String() string { return "[REDACTED]" }

// GoString returns "[REDACTED]" to prevent secret leakage in %#v formats.
func (s Secret) GoString() string { return "[REDACTED]" }

// Format implements fmt.Formatter so secret bytes are never printed by fmt verbs.
func (s Secret) Format(f fmt.State, c rune) {
	if _, err := io.WriteString(f, "[REDACTED]"); err != nil {
		return
	}
}

// LogValue implements slog.LogValuer so slog never logs secret bytes.
func (s Secret) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// Bytes returns a copy of the secret token bytes.
func (s Secret) Bytes() []byte { return bytes.Clone(s.value) }

type podEntry struct {
	identity string
	policy   *EgressPolicy
	secrets  map[string]Secret
	bound    bool
}

// BindingStore is an in-memory store keyed by pod UID that holds egress policy
// and secrets and implements PodBindServiceServer.
type BindingStore struct {
	UnimplementedPodBindServiceServer
	mu   sync.RWMutex
	pods map[string]*podEntry
}

var _ PodBindServiceServer = (*BindingStore)(nil)

// NewBindingStore creates a new empty BindingStore.
func NewBindingStore() *BindingStore {
	return &BindingStore{
		pods: make(map[string]*podEntry),
	}
}

// Bind validates the egress policy and associates it with the pod UID.
// Rejects an invalid policy with the joined validation errors.
func (s *BindingStore) Bind(ctx context.Context, req *PodPolicy) (*BindResponse, error) {
	if req == nil || req.GetPodUid() == "" {
		return nil, status.Error(codes.InvalidArgument, "pod_uid cannot be empty")
	}
	policy := req.GetPolicy()
	if err := policy.Validate(); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.pods[req.GetPodUid()]
	if !ok {
		entry = &podEntry{secrets: make(map[string]Secret)}
		s.pods[req.GetPodUid()] = entry
	}
	entry.identity = req.GetIdentity()
	entry.policy = proto.Clone(policy).(*EgressPolicy)
	entry.bound = true

	return &BindResponse{PodUid: req.GetPodUid(), Bound: true}, nil
}

// InjectSecrets replaces the whole set of named secrets for the pod UID.
// The request message is never logged, and secret bytes are copied into the
// store's own Secret type whose formatting never reveals the values.
func (s *BindingStore) InjectSecrets(ctx context.Context, req *PodSecrets) (*InjectSecretsResponse, error) {
	if req == nil || req.GetPodUid() == "" {
		return nil, status.Error(codes.InvalidArgument, "pod_uid cannot be empty")
	}

	reqSecrets := req.GetSecrets()
	newSecrets := make(map[string]Secret, len(reqSecrets))
	for k, v := range reqSecrets {
		newSecrets[k] = Secret{value: bytes.Clone(v)}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.pods[req.GetPodUid()]
	if !ok {
		entry = &podEntry{}
		s.pods[req.GetPodUid()] = entry
	}
	entry.secrets = newSecrets

	return &InjectSecretsResponse{PodUid: req.GetPodUid()}, nil
}

// Unbind dissociates a pod UID, removing policy and secrets together.
func (s *BindingStore) Unbind(ctx context.Context, req *UnbindRequest) (*UnbindResponse, error) {
	if req == nil || req.GetPodUid() == "" {
		return nil, status.Error(codes.InvalidArgument, "pod_uid cannot be empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.pods, req.GetPodUid())
	return &UnbindResponse{PodUid: req.GetPodUid(), Bound: false}, nil
}

// Get retrieves the current binding and status of a pod.
func (s *BindingStore) Get(ctx context.Context, req *GetRequest) (*GetResponse, error) {
	if req == nil || req.GetPodUid() == "" {
		return nil, status.Error(codes.InvalidArgument, "pod_uid cannot be empty")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, ok := s.pods[req.GetPodUid()]
	if !ok || !entry.bound {
		return &GetResponse{PodUid: req.GetPodUid(), Bound: false}, nil
	}

	return &GetResponse{
		PodUid:   req.GetPodUid(),
		Identity: entry.identity,
		Policy:   proto.Clone(entry.policy).(*EgressPolicy),
		Bound:    true,
	}, nil
}

// Policy returns the egress policy for a pod UID, or nil if the pod has no binding.
// Callers treat a nil policy as deny. Callers must not modify the returned policy.
func (s *BindingStore) Policy(podUID string) *EgressPolicy {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, ok := s.pods[podUID]
	if !ok || !entry.bound {
		return nil
	}
	return entry.policy
}

// ResolveSecret resolves a named secret for the given pod UID.
func (s *BindingStore) ResolveSecret(podUID, name string) (Secret, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, ok := s.pods[podUID]
	if !ok {
		return Secret{}, false
	}
	sec, ok := entry.secrets[name]
	if !ok {
		return Secret{}, false
	}
	return sec, true
}

// Acceptance reports the acceptance status of a pod UID and any missing secret names.
// Accepted means the node holds the policy and every secret the policy names.
func (s *BindingStore) Acceptance(podUID string) (AcceptanceStatus, []string) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, ok := s.pods[podUID]
	if !ok || !entry.bound || entry.policy == nil {
		return AcceptanceStatus_ACCEPTANCE_STATUS_PENDING, nil
	}

	var missing []string
	seen := make(map[string]bool)
	for _, rule := range entry.policy.GetRules() {
		var effects *HttpRuleEffects
		if rule.GetHttp() != nil {
			effects = rule.GetHttp().GetEffects()
		} else if rule.GetHttps() != nil {
			effects = rule.GetHttps().GetEffects()
		}
		if effects == nil {
			continue
		}
		for _, rh := range effects.GetReplaceHeaders() {
			if rh == nil {
				continue
			}
			name, err := parseCredentialURI(rh.GetCredentialUri())
			if err != nil || name == "" || seen[name] {
				continue
			}
			seen[name] = true
			if _, ok := entry.secrets[name]; !ok {
				missing = append(missing, name)
			}
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		return AcceptanceStatus_ACCEPTANCE_STATUS_PENDING, missing
	}
	return AcceptanceStatus_ACCEPTANCE_STATUS_ACCEPTED, nil
}
