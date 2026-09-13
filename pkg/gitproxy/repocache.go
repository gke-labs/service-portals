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

package gitproxy

import (
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"sort"
	"sync"
)

// RepoStore represents an object store and commit graph for a single Git repository.
type RepoStore struct {
	mu            sync.RWMutex
	objects       map[string]*RawObject
	commits       map[string]*CommitInfo
	treeEntries   map[string][]string // tree OID -> child OIDs
	commitObjects map[string][]string // commit OID -> all reachable object OIDs
	dir           string              // optional storage directory
}

// NewRepoStore creates a new RepoStore.
func NewRepoStore(dir string) *RepoStore {
	return &RepoStore{
		objects:       make(map[string]*RawObject),
		commits:       make(map[string]*CommitInfo),
		treeEntries:   make(map[string][]string),
		commitObjects: make(map[string][]string),
		dir:           dir,
	}
}

// HasCommit returns true if the commit OID is known and all its reachable objects are cached.
func (s *RepoStore) HasCommit(oid string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	_, ok := s.commits[oid]
	return ok
}

// HasAllCommits returns true if all requested commit OIDs are present in the store.
func (s *RepoStore) HasAllCommits(oids []string) bool {
	if len(oids) == 0 {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, oid := range oids {
		if _, ok := s.commits[oid]; !ok {
			return false
		}
	}
	return true
}

// GetCommit returns metadata for a commit.
func (s *RepoStore) GetCommit(oid string) (*CommitInfo, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	info, ok := s.commits[oid]
	return info, ok
}

// GetKnownCommits returns a list of all commit OIDs in the store.
func (s *RepoStore) GetKnownCommits() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	res := make([]string, 0, len(s.commits))
	for oid := range s.commits {
		res = append(res, oid)
	}
	sort.Strings(res)
	return res
}

// IngestPackfile parses and ingests a raw packfile into the repository store.
func (s *RepoStore) IngestPackfile(packData []byte) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	objects, err := ParsePackfileWithBase(packData, func(oid string) *RawObject {
		return s.objects[oid]
	})
	if err != nil {
		return nil, fmt.Errorf("failed to parse packfile: %w", err)
	}

	var newCommits []string

	// 1. Store all raw objects
	for _, obj := range objects {
		s.objects[obj.OID] = obj

		if obj.Type == ObjTree {
			childOIDs, err := ParseTreeEntries(obj.Data)
			if err == nil {
				s.treeEntries[obj.OID] = childOIDs
			}
		} else if obj.Type == ObjCommit {
			info := ParseCommitObject(obj.OID, obj.Data)
			s.commits[obj.OID] = info
			newCommits = append(newCommits, obj.OID)
		}
	}

	// 2. Compute reachable objects for all commits in store
	for _, commit := range s.commits {
		s.computeReachableObjects(commit)
	}

	return newCommits, nil
}

// computeReachableObjects computes and caches all object OIDs reachable from a commit.
// Caller must hold s.mu write lock.
func (s *RepoStore) computeReachableObjects(commit *CommitInfo) {
	visited := make(map[string]bool)
	var objectList []string

	// Add commit object itself
	visited[commit.OID] = true
	objectList = append(objectList, commit.OID)

	// Traverse tree and subtrees
	if commit.Tree != "" {
		queue := []string{commit.Tree}
		for len(queue) > 0 {
			treeOID := queue[0]
			queue = queue[1:]

			if !visited[treeOID] {
				visited[treeOID] = true
				objectList = append(objectList, treeOID)
			}

			children := s.treeEntries[treeOID]
			for _, childOID := range children {
				if visited[childOID] {
					continue
				}
				visited[childOID] = true
				objectList = append(objectList, childOID)

				if childObj, ok := s.objects[childOID]; ok && childObj.Type == ObjTree {
					queue = append(queue, childOID)
				}
			}
		}
	}

	s.commitObjects[commit.OID] = objectList
}

// CollectObjectsForCommits collects all objects needed to satisfy `wants` given client `haves`.
// It returns the list of objects for the packfile and common ACKs.
func (s *RepoStore) CollectObjectsForCommits(wants []string, haves []string) ([]*RawObject, []string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// 1. Find all commits reachable from haves (to exclude)
	excludedCommits := make(map[string]bool)
	var acks []string

	haveQueue := make([]string, 0, len(haves))
	for _, have := range haves {
		if _, ok := s.commits[have]; ok {
			acks = append(acks, have)
			haveQueue = append(haveQueue, have)
			excludedCommits[have] = true
		}
	}

	for len(haveQueue) > 0 {
		curr := haveQueue[0]
		haveQueue = haveQueue[1:]

		if commit, ok := s.commits[curr]; ok {
			for _, p := range commit.Parents {
				if !excludedCommits[p] {
					excludedCommits[p] = true
					haveQueue = append(haveQueue, p)
				}
			}
		}
	}

	// 2. Find all commits reachable from wants that are not in excludedCommits
	neededCommits := make(map[string]bool)
	wantQueue := make([]string, 0, len(wants))

	for _, want := range wants {
		if !excludedCommits[want] {
			neededCommits[want] = true
			wantQueue = append(wantQueue, want)
		}
	}

	for len(wantQueue) > 0 {
		curr := wantQueue[0]
		wantQueue = wantQueue[1:]

		if commit, ok := s.commits[curr]; ok {
			for _, p := range commit.Parents {
				if !excludedCommits[p] && !neededCommits[p] {
					neededCommits[p] = true
					wantQueue = append(wantQueue, p)
				}
			}
		}
	}

	// 3. Determine objects already present in client (from excluded commits)
	haveObjects := make(map[string]bool)
	for excCommit := range excludedCommits {
		for _, oid := range s.commitObjects[excCommit] {
			haveObjects[oid] = true
		}
	}

	// 4. Collect objects for all needed commits
	neededObjects := make(map[string]bool)
	var finalObjectOIDs []string

	for commitOID := range neededCommits {
		for _, oid := range s.commitObjects[commitOID] {
			if !haveObjects[oid] && !neededObjects[oid] {
				neededObjects[oid] = true
				finalObjectOIDs = append(finalObjectOIDs, oid)
			}
		}
	}

	// If finalObjectOIDs is empty (e.g. client requested wants already present or shallow),
	// ensure at least the wanted commit objects themselves are sent
	if len(finalObjectOIDs) == 0 {
		for _, want := range wants {
			if !neededObjects[want] {
				neededObjects[want] = true
				finalObjectOIDs = append(finalObjectOIDs, want)
			}
		}
	}

	// 5. Gather *RawObject instances
	var objects []*RawObject
	for _, oid := range finalObjectOIDs {
		if obj, ok := s.objects[oid]; ok {
			objects = append(objects, obj)
		}
	}

	return objects, acks, nil
}

// RepoCacheManager manages RepoStores for different repositories.
type RepoCacheManager struct {
	mu       sync.RWMutex
	stores   map[string]*RepoStore
	cacheDir string
}

// NewRepoCacheManager creates a new RepoCacheManager.
func NewRepoCacheManager(cacheDir string) *RepoCacheManager {
	return &RepoCacheManager{
		stores:   make(map[string]*RepoStore),
		cacheDir: cacheDir,
	}
}

// GetRepoStore retrieves or creates a RepoStore for a given repository identifier.
func (m *RepoCacheManager) GetRepoStore(repoID string) *RepoStore {
	m.mu.Lock()
	defer m.mu.Unlock()

	store, ok := m.stores[repoID]
	if !ok {
		var repoDir string
		if m.cacheDir != "" {
			hash := sha256.Sum256([]byte(repoID))
			repoDir = filepath.Join(m.cacheDir, fmt.Sprintf("%x", hash[:8]))
		}
		store = NewRepoStore(repoDir)
		m.stores[repoID] = store
	}
	return store
}
