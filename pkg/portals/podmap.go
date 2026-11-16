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

package portals

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"sync"

	portalsv1 "github.com/gke-labs/service-portals/pkg/portals/v1"
)

// PodInfo holds network metadata for an intercepted pod.
type PodInfo struct {
	UID         string            `json:"uid"`
	Namespace   string            `json:"namespace"`
	Name        string            `json:"name"`
	IPs         []string          `json:"ips"`
	Annotations map[string]string `json:"annotations,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
}

// PodMap tracks pod network identities on the node.
type PodMap struct {
	mu       sync.RWMutex
	byUID    map[string]*PodInfo
	byIP     map[string]*PodInfo
	store    *portalsv1.BindingStore
	watchers []chan struct{}
}

// NewPodMap creates a new PodMap.
func NewPodMap() *PodMap {
	return &PodMap{byUID: make(map[string]*PodInfo), byIP: make(map[string]*PodInfo)}
}

// SetBindingStore associates a BindingStore with the PodMap so that pod removals
// and synchronization update the store accordingly.
func (pm *PodMap) SetBindingStore(store *portalsv1.BindingStore) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.store = store
}

func (pm *PodMap) addOrUpdateLocked(info *PodInfo) {
	if info == nil || info.UID == "" {
		return
	}
	if ex, exists := pm.byUID[info.UID]; exists {
		newIPs := make(map[string]bool, len(info.IPs))
		for _, ip := range info.IPs {
			newIPs[ip] = true
		}
		for _, old := range ex.IPs {
			if !newIPs[old] {
				delete(pm.byIP, old)
			}
		}
	}
	pm.byUID[info.UID] = info
	for _, ip := range info.IPs {
		if ip != "" {
			pm.byIP[ip] = info
		}
	}
}

func (pm *PodMap) notifyWatchersLocked() {
	for _, ch := range pm.watchers {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// AddOrUpdatePod registers or updates a pod in the pod map.
func (pm *PodMap) AddOrUpdatePod(info *PodInfo) {
	if info == nil || info.UID == "" {
		return
	}
	pm.mu.Lock()
	defer pm.mu.Unlock()
	_, exists := pm.byUID[info.UID]
	pm.addOrUpdateLocked(info)
	if !exists {
		pm.notifyWatchersLocked()
	}
}

// RemovePod unregisters a pod by UID.
func (pm *PodMap) RemovePod(uid string) {
	pm.mu.Lock()
	if pod, ok := pm.byUID[uid]; ok {
		for _, ip := range pod.IPs {
			delete(pm.byIP, ip)
		}
		delete(pm.byUID, uid)
		pm.notifyWatchersLocked()
	}
	store := pm.store
	pm.mu.Unlock()

	if store != nil {
		store.RemovePod(uid)
	}
}

// SynchronizePods updates the active pod map from a full sync list.
func (pm *PodMap) SynchronizePods(pods []PodInfo) {
	pm.mu.Lock()
	active := make(map[string]bool, len(pods))
	activeUIDs := make([]string, 0, len(pods))
	changed := false
	for i := range pods {
		active[pods[i].UID] = true
		activeUIDs = append(activeUIDs, pods[i].UID)
		if _, exists := pm.byUID[pods[i].UID]; !exists && pods[i].UID != "" {
			changed = true
		}
		pm.addOrUpdateLocked(&pods[i])
	}
	for uid, pod := range pm.byUID {
		if !active[uid] {
			for _, ip := range pod.IPs {
				delete(pm.byIP, ip)
			}
			delete(pm.byUID, uid)
			changed = true
		}
	}
	if changed {
		pm.notifyWatchersLocked()
	}
	store := pm.store
	pm.mu.Unlock()

	if store != nil {
		store.DropAbsent(activeUIDs)
	}
}

// PodUIDs returns a sorted slice of all pod UIDs currently present on the node.
func (pm *PodMap) PodUIDs() []string {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	uids := make([]string, 0, len(pm.byUID))
	for uid := range pm.byUID {
		uids = append(uids, uid)
	}
	sort.Strings(uids)
	return uids
}

// HasPod reports whether a pod UID is currently present on the node.
func (pm *PodMap) HasPod(uid string) bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	_, ok := pm.byUID[uid]
	return ok
}

// Watch registers a channel to receive notifications when pods change on the node.
// Non-blocking send ensures a 1-slot channel coalesces rapid changes.
func (pm *PodMap) Watch(ch chan struct{}) func() {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.watchers = append(pm.watchers, ch)
	return func() {
		pm.mu.Lock()
		defer pm.mu.Unlock()
		for i, w := range pm.watchers {
			if w == ch {
				pm.watchers = append(pm.watchers[:i], pm.watchers[i+1:]...)
				break
			}
		}
	}
}

// GetPodByIP looks up a pod by client IP.
func (pm *PodMap) GetPodByIP(ip string) (*PodInfo, bool) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	pod, ok := pm.byIP[ip]
	return pod, ok
}

// AdminHandler returns an http.Handler serving the pod map management endpoints.
func (pm *PodMap) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/pods", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			pm.mu.RLock()
			pods := make([]*PodInfo, 0, len(pm.byUID))
			for _, p := range pm.byUID {
				pods = append(pods, p)
			}
			pm.mu.RUnlock()
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(pods); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		case http.MethodPost:
			var info PodInfo
			if err := json.NewDecoder(r.Body).Decode(&info); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			pm.AddOrUpdatePod(&info)
		case http.MethodPut:
			var pods []PodInfo
			if err := json.NewDecoder(r.Body).Decode(&pods); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			pm.SynchronizePods(pods)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/v1/pods/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			if uid := strings.TrimPrefix(r.URL.Path, "/api/v1/pods/"); uid != "" {
				pm.RemovePod(uid)
				return
			}
		}
		http.Error(w, "not found", http.StatusNotFound)
	})
	return mux
}
