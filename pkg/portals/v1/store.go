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
	"log"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
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

// BindingStore is a store keyed by pod UID that holds egress policy
// and secrets and implements PodBindServiceServer.
type BindingStore struct {
	UnimplementedPodBindServiceServer
	mu   sync.RWMutex
	pods map[string]*podEntry
	dir  string
}

var _ PodBindServiceServer = (*BindingStore)(nil)

// NewBindingStore creates a new BindingStore. If dir is non-empty,
// bindings are persisted to disk and restored across restarts.
func NewBindingStore(dir string) (*BindingStore, error) {
	if dir != "" {
		if err := checkDir(dir); err != nil {
			return nil, err
		}
	}
	s := &BindingStore{pods: make(map[string]*podEntry), dir: dir}
	if dir != "" {
		return s, s.loadFromDisk()
	}
	return s, nil
}

func checkDir(dir string) error {
	info, err := os.Stat(dir)
	if os.IsNotExist(err) {
		if err = os.MkdirAll(dir, 0700); err == nil {
			err = os.Chmod(dir, 0700)
		}
		if err != nil {
			return fmt.Errorf("creating directory %q: %w", dir, err)
		}
		info, err = os.Stat(dir)
	}
	if err != nil {
		return fmt.Errorf("stat directory %q: %w", dir, err)
	}
	if !info.IsDir() || info.Mode().Perm() != 0700 {
		return fmt.Errorf("directory %q must be mode 0700 (got %04o)", dir, info.Mode().Perm())
	}
	return nil
}

const (
	bindingFileSuffix    = ".pb"
	oldBindingFileSuffix = ".json"
)

func (s *BindingStore) dropEntry(podUID, path, reason string) {
	log.Printf("dropping binding entry for pod %s: %s", podUID, reason)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		log.Printf("failed to remove %s: %v", path, err)
	}
}

func (s *BindingStore) loadFromDisk() error {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return fmt.Errorf("reading directory %q: %w", s.dir, err)
	}
	for _, d := range entries {
		if d.IsDir() {
			continue
		}
		path := filepath.Join(s.dir, d.Name())
		if strings.HasPrefix(d.Name(), ".tmp-") {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				log.Printf("failed to remove temp file %s: %v", d.Name(), err)
			}
			continue
		}
		if strings.HasSuffix(d.Name(), oldBindingFileSuffix) {
			podUID, err := url.PathUnescape(strings.TrimSuffix(d.Name(), oldBindingFileSuffix))
			if err != nil {
				podUID = d.Name()
			}
			s.dropEntry(podUID, path, "old format")
			continue
		}
		if !strings.HasSuffix(d.Name(), bindingFileSuffix) {
			continue
		}
		podUID, err := url.PathUnescape(strings.TrimSuffix(d.Name(), bindingFileSuffix))
		if err != nil {
			podUID = d.Name()
		}
		fi, err := d.Info()
		if err != nil || fi.Mode().Perm()&0077 != 0 {
			s.dropEntry(podUID, path, "insecure file mode")
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			s.dropEntry(podUID, path, "read error")
			continue
		}
		var stored StoredBinding
		if err := proto.Unmarshal(data, &stored); err != nil {
			s.dropEntry(podUID, path, "malformed content")
			continue
		}
		if stored.GetPodUid() != "" {
			podUID = stored.GetPodUid()
		}
		pol := stored.GetPolicy()
		if pol != nil {
			if err := pol.Validate(); err != nil {
				s.dropEntry(podUID, path, "invalid policy")
				continue
			}
		}
		if stored.GetBound() && pol == nil {
			s.dropEntry(podUID, path, "missing policy")
			continue
		}
		entry := &podEntry{identity: stored.GetIdentity(), policy: pol, bound: stored.GetBound(), secrets: make(map[string]Secret, len(stored.GetSecrets()))}
		for k, v := range stored.GetSecrets() {
			entry.secrets[k] = Secret{value: bytes.Clone(v)}
		}
		s.pods[podUID] = entry
	}
	return nil
}

func (s *BindingStore) filePath(podUID string) string {
	return filepath.Join(s.dir, url.PathEscape(podUID)+bindingFileSuffix)
}

func (s *BindingStore) saveLocked(podUID string, entry *podEntry) error {
	if s.dir == "" {
		return nil
	}
	stored := &StoredBinding{
		PodUid:   podUID,
		Identity: entry.identity,
		Policy:   entry.policy,
		Bound:    entry.bound,
	}
	if len(entry.secrets) > 0 {
		stored.Secrets = make(map[string][]byte, len(entry.secrets))
		for k, v := range entry.secrets {
			stored.Secrets[k] = v.Bytes()
		}
	}
	data, err := proto.Marshal(stored)
	if err != nil {
		return fmt.Errorf("marshaling entry for pod %s: %w", podUID, err)
	}
	f, err := os.CreateTemp(s.dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("creating temp file for pod %s: %w", podUID, err)
	}
	tmp := f.Name()
	defer func() {
		if tmp != "" {
			if err := os.Remove(tmp); err != nil && !os.IsNotExist(err) {
				log.Printf("failed to remove temp file %s: %v", tmp, err)
			}
		}
	}()
	err = os.Chmod(tmp, 0600)
	if err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	if cErr := f.Close(); err == nil {
		err = cErr
	}
	if err != nil {
		return fmt.Errorf("writing temp file for pod %s: %w", podUID, err)
	}
	if err := os.Rename(tmp, s.filePath(podUID)); err != nil {
		return fmt.Errorf("committing entry for pod %s: %w", podUID, err)
	}
	tmp = ""
	return nil
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

	entry := s.pods[req.GetPodUid()]
	newEntry := &podEntry{identity: req.GetIdentity(), policy: proto.Clone(policy).(*EgressPolicy), bound: true}
	if entry != nil {
		newEntry.secrets = entry.secrets
	} else {
		newEntry.secrets = make(map[string]Secret)
	}
	if err := s.saveLocked(req.GetPodUid(), newEntry); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to persist binding: %v", err)
	}
	s.pods[req.GetPodUid()] = newEntry

	return &BindResponse{PodUid: req.GetPodUid(), Bound: true}, nil
}

// InjectSecrets replaces the whole set of named secrets for the pod UID.
// The request message is never logged, and secret bytes are copied into the
// store's own Secret type whose formatting never reveals the values.
func (s *BindingStore) InjectSecrets(ctx context.Context, req *PodSecrets) (*InjectSecretsResponse, error) {
	if req == nil || req.GetPodUid() == "" {
		return nil, status.Error(codes.InvalidArgument, "pod_uid cannot be empty")
	}

	newSecrets := make(map[string]Secret, len(req.GetSecrets()))
	for k, v := range req.GetSecrets() {
		newSecrets[k] = Secret{value: bytes.Clone(v)}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	entry := s.pods[req.GetPodUid()]
	newEntry := &podEntry{secrets: newSecrets}
	if entry != nil {
		newEntry.identity = entry.identity
		newEntry.policy = entry.policy
		newEntry.bound = entry.bound
	}
	if err := s.saveLocked(req.GetPodUid(), newEntry); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to persist secrets: %v", err)
	}
	s.pods[req.GetPodUid()] = newEntry

	return &InjectSecretsResponse{PodUid: req.GetPodUid()}, nil
}

// Unbind dissociates a pod UID, removing policy and secrets together.
// If the store is durable, removing the stored entry from disk must succeed
// before memory is cleared, so a failed write fails the call fail-closed.
func (s *BindingStore) Unbind(ctx context.Context, req *UnbindRequest) (*UnbindResponse, error) {
	if req == nil || req.GetPodUid() == "" {
		return nil, status.Error(codes.InvalidArgument, "pod_uid cannot be empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.dir != "" {
		if err := os.Remove(s.filePath(req.GetPodUid())); err != nil && !os.IsNotExist(err) {
			return nil, status.Errorf(codes.Internal, "failed to remove stored binding for pod %s: %v", req.GetPodUid(), err)
		}
	}
	delete(s.pods, req.GetPodUid())
	return &UnbindResponse{PodUid: req.GetPodUid(), Bound: false}, nil
}

// RemovePod removes a pod's policy and secrets from memory and from disk.
func (s *BindingStore) RemovePod(podUID string) {
	if podUID == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.pods, podUID)
	if s.dir != "" {
		if err := os.Remove(s.filePath(podUID)); err != nil && !os.IsNotExist(err) {
			log.Printf("failed to remove stored binding for pod %s: %v", podUID, err)
		}
	}
}

// DropAbsent removes stored bindings for any pods not present in activeUIDs.
func (s *BindingStore) DropAbsent(activeUIDs []string) {
	active := make(map[string]bool, len(activeUIDs))
	for _, uid := range activeUIDs {
		active[uid] = true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for uid := range s.pods {
		if !active[uid] {
			delete(s.pods, uid)
		}
	}
	if s.dir != "" {
		entries, err := os.ReadDir(s.dir)
		if err != nil {
			log.Printf("failed to read binding store directory: %v", err)
			return
		}
		for _, d := range entries {
			if d.IsDir() || !strings.HasSuffix(d.Name(), bindingFileSuffix) {
				continue
			}
			uid, err := url.PathUnescape(strings.TrimSuffix(d.Name(), bindingFileSuffix))
			if err == nil && !active[uid] {
				if err := os.Remove(filepath.Join(s.dir, d.Name())); err != nil && !os.IsNotExist(err) {
					log.Printf("failed to remove stored binding file %s: %v", d.Name(), err)
				}
			}
		}
	}
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
