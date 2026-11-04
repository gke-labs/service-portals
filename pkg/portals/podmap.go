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
	"fmt"
	"net/http"
	"strings"
	"sync"
)

// PodInfo holds identity, policy, and network metadata for an intercepted pod.
type PodInfo struct {
	UID         string            `json:"uid"`
	Namespace   string            `json:"namespace"`
	Name        string            `json:"name"`
	IPs         []string          `json:"ips"`
	Annotations map[string]string `json:"annotations,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Identity    string            `json:"identity,omitempty"`
	Policy      string            `json:"policy,omitempty"`
	Bound       bool              `json:"bound,omitempty"`
}

// PodMap tracks pod network identities and per-pod policies on the node.
type PodMap struct {
	mu    sync.RWMutex
	byUID map[string]*PodInfo
	byIP  map[string]*PodInfo
}

// NewPodMap creates a new PodMap.
func NewPodMap() *PodMap {
	return &PodMap{byUID: make(map[string]*PodInfo), byIP: make(map[string]*PodInfo)}
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
		info.Identity, info.Policy, info.Bound = ex.Identity, ex.Policy, ex.Bound
	} else if pol, ok := info.Annotations["service-portal.gke.io/policy"]; ok && pol != "" {
		info.Policy, info.Identity, info.Bound = pol, info.Annotations["service-portal.gke.io/identity"], true
	}
	pm.byUID[info.UID] = info
	for _, ip := range info.IPs {
		if ip != "" {
			pm.byIP[ip] = info
		}
	}
}

// AddOrUpdatePod registers or updates a pod in the pod map.
func (pm *PodMap) AddOrUpdatePod(info *PodInfo) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.addOrUpdateLocked(info)
}

// RemovePod unregisters a pod by UID.
func (pm *PodMap) RemovePod(uid string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	if pod, ok := pm.byUID[uid]; ok {
		for _, ip := range pod.IPs {
			delete(pm.byIP, ip)
		}
		delete(pm.byUID, uid)
	}
}

// SynchronizePods updates the active pod map from a full sync list.
func (pm *PodMap) SynchronizePods(pods []PodInfo) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	active := make(map[string]bool, len(pods))
	for i := range pods {
		active[pods[i].UID] = true
		pm.addOrUpdateLocked(&pods[i])
	}
	for uid, pod := range pm.byUID {
		if !active[uid] {
			for _, ip := range pod.IPs {
				delete(pm.byIP, ip)
			}
			delete(pm.byUID, uid)
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

// Bind assigns user identity and policy to a pod by UID.
func (pm *PodMap) Bind(uid, identity, policy string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pod, ok := pm.byUID[uid]
	if !ok {
		pod = &PodInfo{UID: uid}
		pm.byUID[uid] = pod
	}
	pod.Identity, pod.Policy, pod.Bound = identity, policy, true
	return nil
}

// Unbind revokes identity and policy from a pod, returning it to fail-closed state.
func (pm *PodMap) Unbind(uid string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pod, ok := pm.byUID[uid]
	if !ok {
		return fmt.Errorf("pod UID %q not found", uid)
	}
	pod.Identity, pod.Policy, pod.Bound = "", "", false
	return nil
}

// IsRuleAllowed checks if the given rule and host are permitted by the pod's policy.
func (pm *PodMap) IsRuleAllowed(pod *PodInfo, ruleName, host string) bool {
	if pod == nil || !pod.Bound || pod.Policy == "" {
		return false
	}
	for _, tok := range strings.Split(pod.Policy, ",") {
		tok = strings.TrimSpace(strings.ToLower(tok))
		if tok == "*" || tok == strings.ToLower(ruleName) || tok == strings.ToLower(host) {
			return true
		}
	}
	return false
}

// BindRequest represents the payload for the Bind API.
type BindRequest struct {
	PodUID   string `json:"podUID"`
	Identity string `json:"identity"`
	Policy   string `json:"policy"`
}

// UnbindRequest represents the payload for the Unbind API.
type UnbindRequest struct {
	PodUID string `json:"podUID"`
}

// AdminHandler returns an http.Handler serving the Bind API and pod map management endpoints.
func (pm *PodMap) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/bind", func(w http.ResponseWriter, r *http.Request) {
		var req BindRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			req.PodUID = r.URL.Query().Get("podUID")
			req.Identity = r.URL.Query().Get("identity")
			req.Policy = r.URL.Query().Get("policy")
		}
		if req.PodUID == "" {
			http.Error(w, "missing podUID", http.StatusBadRequest)
			return
		}
		if err := pm.Bind(req.PodUID, req.Identity, req.Policy); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]string{"status": "bound", "podUID": req.PodUID}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})
	mux.HandleFunc("/unbind", func(w http.ResponseWriter, r *http.Request) {
		var req UnbindRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			req.PodUID = r.URL.Query().Get("podUID")
		}
		if req.PodUID == "" {
			http.Error(w, "missing podUID", http.StatusBadRequest)
			return
		}
		if err := pm.Unbind(req.PodUID); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]string{"status": "unbound", "podUID": req.PodUID}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})
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
