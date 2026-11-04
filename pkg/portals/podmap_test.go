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
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPodMapAddAndLookup(t *testing.T) {
	pm := NewPodMap()

	info := &PodInfo{
		UID:       "pod-uid-1",
		Namespace: "default",
		Name:      "test-pod-1",
		IPs:       []string{"10.244.0.10", "2001:db8::10"},
		Annotations: map[string]string{
			"service-portal.gke.io/policy":   "backend",
			"service-portal.gke.io/identity": "user-bob",
		},
	}

	pm.AddOrUpdatePod(info)

	pod, ok := pm.GetPodByIP("10.244.0.10")
	if !ok || pod == nil {
		t.Fatalf("expected pod lookup for 10.244.0.10 to succeed, got ok=%v", ok)
	}
	if pod.UID != "pod-uid-1" || pod.Name != "test-pod-1" {
		t.Errorf("unexpected pod info: %+v", pod)
	}
	if !pod.Bound {
		t.Errorf("expected pod with policy annotation to be initialized as bound")
	}
	if pod.Identity != "user-bob" || pod.Policy != "backend" {
		t.Errorf("unexpected identity (%s) or policy (%s)", pod.Identity, pod.Policy)
	}

	// Lookup via IPv6
	podV6, ok := pm.GetPodByIP("2001:db8::10")
	if !ok || podV6.UID != "pod-uid-1" {
		t.Errorf("expected IPv6 lookup to find same pod, got %+v, ok=%v", podV6, ok)
	}

	// Unknown IP
	if _, ok := pm.GetPodByIP("10.244.0.99"); ok {
		t.Errorf("expected lookup for unknown IP to fail")
	}
}

func TestPodMapLifecycle_RestartWithNewIP(t *testing.T) {
	pm := NewPodMap()

	initial := &PodInfo{
		UID:       "pod-uid-restart",
		Namespace: "default",
		Name:      "restart-pod",
		IPs:       []string{"10.244.0.50"},
	}
	pm.AddOrUpdatePod(initial)

	// Bind via Bind API
	if err := pm.Bind("pod-uid-restart", "user-alice", "github,backend"); err != nil {
		t.Fatalf("bind failed: %v", err)
	}

	pod, ok := pm.GetPodByIP("10.244.0.50")
	if !ok || !pod.Bound || pod.Identity != "user-alice" {
		t.Fatalf("unexpected state after bind: %+v", pod)
	}

	// Pod restarts with a new IP: 10.244.0.60
	restarted := &PodInfo{
		UID:       "pod-uid-restart",
		Namespace: "default",
		Name:      "restart-pod",
		IPs:       []string{"10.244.0.60"},
	}
	pm.AddOrUpdatePod(restarted)

	// Old IP must no longer resolve
	if oldPod, ok := pm.GetPodByIP("10.244.0.50"); ok {
		t.Errorf("old IP 10.244.0.50 should not resolve after restart, got: %+v", oldPod)
	}

	// New IP must resolve with preserved binding and policy
	newPod, ok := pm.GetPodByIP("10.244.0.60")
	if !ok || newPod == nil {
		t.Fatalf("expected new IP 10.244.0.60 to resolve")
	}
	if !newPod.Bound {
		t.Errorf("expected bound state to be preserved across restart with new IP")
	}
	if newPod.Identity != "user-alice" || newPod.Policy != "github,backend" {
		t.Errorf("expected identity user-alice and policy github,backend, got: %+v", newPod)
	}
}

func TestPodMapBindAndUnbind(t *testing.T) {
	pm := NewPodMap()

	pod := &PodInfo{
		UID:       "unbound-pod",
		Namespace: "default",
		Name:      "unbound-client",
		IPs:       []string{"10.244.0.20"},
	}
	pm.AddOrUpdatePod(pod)

	retrieved, ok := pm.GetPodByIP("10.244.0.20")
	if !ok || retrieved == nil {
		t.Fatalf("pod not found")
	}
	if retrieved.Bound {
		t.Errorf("unannotated pod must start unbound by default")
	}
	if pm.IsRuleAllowed(retrieved, "backend", "backend") {
		t.Errorf("unbound pod must not be allowed access to any rule")
	}

	// Bind
	if err := pm.Bind("unbound-pod", "claim-controller-user", "backend"); err != nil {
		t.Fatalf("bind failed: %v", err)
	}
	if !retrieved.Bound || retrieved.Identity != "claim-controller-user" || retrieved.Policy != "backend" {
		t.Errorf("unexpected pod state after bind: %+v", retrieved)
	}
	if !pm.IsRuleAllowed(retrieved, "backend", "backend") {
		t.Errorf("expected backend rule to be allowed after bind")
	}
	if pm.IsRuleAllowed(retrieved, "other", "other.example.com") {
		t.Errorf("expected other rule to be denied under policy backend")
	}

	// Unbind (fail closed)
	if err := pm.Unbind("unbound-pod"); err != nil {
		t.Fatalf("unbind failed: %v", err)
	}
	if retrieved.Bound {
		t.Errorf("pod must not be bound after unbind")
	}
	if pm.IsRuleAllowed(retrieved, "backend", "backend") {
		t.Errorf("unbound pod must be denied all rules")
	}
}

func TestPodMapRemovePod(t *testing.T) {
	pm := NewPodMap()
	pm.AddOrUpdatePod(&PodInfo{
		UID: "temp-pod",
		IPs: []string{"10.244.0.30"},
	})
	if _, ok := pm.GetPodByIP("10.244.0.30"); !ok {
		t.Fatalf("expected pod present before remove")
	}

	pm.RemovePod("temp-pod")
	if _, ok := pm.GetPodByIP("10.244.0.30"); ok {
		t.Errorf("pod IP still present after remove")
	}
}

func TestPodMapSynchronizePods(t *testing.T) {
	pm := NewPodMap()
	pm.AddOrUpdatePod(&PodInfo{
		UID: "existing-pod-1",
		IPs: []string{"10.244.0.1"},
	})
	_ = pm.Bind("existing-pod-1", "user-1", "backend")

	pm.AddOrUpdatePod(&PodInfo{
		UID: "deleted-pod",
		IPs: []string{"10.244.0.2"},
	})

	syncList := []PodInfo{
		{
			UID: "existing-pod-1",
			IPs: []string{"10.244.0.1"},
		},
		{
			UID: "new-synced-pod",
			IPs: []string{"10.244.0.3"},
			Annotations: map[string]string{
				"service-portal.gke.io/policy": "synced-policy",
			},
		},
	}
	pm.SynchronizePods(syncList)

	// existing-pod-1 retained binding
	p1, ok := pm.GetPodByIP("10.244.0.1")
	if !ok || !p1.Bound || p1.Identity != "user-1" {
		t.Errorf("expected existing pod to retain binding after sync: %+v", p1)
	}

	// deleted-pod removed
	if _, ok := pm.GetPodByIP("10.244.0.2"); ok {
		t.Errorf("expected deleted-pod to be pruned on synchronize")
	}

	// new-synced-pod added
	p3, ok := pm.GetPodByIP("10.244.0.3")
	if !ok || !p3.Bound || p3.Policy != "synced-policy" {
		t.Errorf("expected new synced pod to be present: %+v", p3)
	}
}

func TestPodMapHTTPHandler(t *testing.T) {
	pm := NewPodMap()
	server := httptest.NewServer(pm.AdminHandler())
	defer server.Close()

	// 1. Register pod via POST /api/v1/pods
	pod := PodInfo{
		UID:       "http-test-pod",
		Namespace: "default",
		Name:      "test-http",
		IPs:       []string{"10.244.0.77"},
	}
	body, _ := json.Marshal(pod)
	res, err := http.Post(server.URL+"/api/v1/pods", "application/json", bytes.NewReader(body))
	if err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/v1/pods failed: err=%v, status=%d", err, res.StatusCode)
	}

	// 2. Call /bind
	bindReq := BindRequest{
		PodUID:   "http-test-pod",
		Identity: "api-caller",
		Policy:   "api-rule",
	}
	bindBody, _ := json.Marshal(bindReq)
	res, err = http.Post(server.URL+"/bind", "application/json", bytes.NewReader(bindBody))
	if err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("POST /bind failed: err=%v, status=%d", err, res.StatusCode)
	}

	p, ok := pm.GetPodByIP("10.244.0.77")
	if !ok || !p.Bound || p.Identity != "api-caller" {
		t.Fatalf("pod not bound properly via HTTP: %+v", p)
	}

	// 3. GET /api/v1/pods
	res, err = http.Get(server.URL + "/api/v1/pods")
	if err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/v1/pods failed: %v", err)
	}
	var pods []*PodInfo
	_ = json.NewDecoder(res.Body).Decode(&pods)
	if len(pods) != 1 || pods[0].UID != "http-test-pod" {
		t.Errorf("unexpected GET /api/v1/pods output: %+v", pods)
	}

	// 4. Call /unbind
	unbindReq := UnbindRequest{PodUID: "http-test-pod"}
	unbindBody, _ := json.Marshal(unbindReq)
	res, err = http.Post(server.URL+"/unbind", "application/json", bytes.NewReader(unbindBody))
	if err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("POST /unbind failed: %v", err)
	}
	if p.Bound {
		t.Errorf("pod should be unbound after /unbind call")
	}

	// 5. DELETE /api/v1/pods/{uid}
	req, _ := http.NewRequest(http.MethodDelete, server.URL+"/api/v1/pods/http-test-pod", nil)
	res, err = http.DefaultClient.Do(req)
	if err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("DELETE /api/v1/pods/http-test-pod failed: %v", err)
	}
	if _, ok := pm.GetPodByIP("10.244.0.77"); ok {
		t.Errorf("pod should be deleted after DELETE")
	}
}

func TestValidateAdminAddr(t *testing.T) {
	validAddrs := []string{
		"127.0.0.1:8081",
		"127.0.0.1:9090",
		"[::1]:8081",
		"localhost:8081",
		"/var/run/service-portal/admin.sock",
		"unix:/var/run/service-portal/admin.sock",
	}
	for _, addr := range validAddrs {
		if err := validateAdminAddr(addr); err != nil {
			t.Errorf("expected validateAdminAddr(%q) to succeed, got %v", addr, err)
		}
	}

	invalidAddrs := []string{
		":8081",
		"0.0.0.0:8081",
		"192.168.1.10:8081",
		"10.0.0.1:8081",
		"example.com:8081",
		"not-a-valid-address",
	}
	for _, addr := range invalidAddrs {
		if err := validateAdminAddr(addr); err == nil {
			t.Errorf("expected validateAdminAddr(%q) to fail, but it succeeded", addr)
		}
	}
}
