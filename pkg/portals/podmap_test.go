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
	"os"
	"path/filepath"
	"testing"

	portalsv1 "github.com/gke-labs/service-portals/pkg/portals/v1"
)

func TestPodMapAddAndLookup(t *testing.T) {
	pm := NewPodMap()

	info := &PodInfo{
		UID:       "pod-uid-1",
		Namespace: "default",
		Name:      "test-pod-1",
		IPs:       []string{"10.244.0.10", "2001:db8::10"},
	}

	pm.AddOrUpdatePod(info)

	pod, ok := pm.GetPodByIP("10.244.0.10")
	if !ok || pod == nil {
		t.Fatalf("expected pod lookup for 10.244.0.10 to succeed, got ok=%v", ok)
	}
	if pod.UID != "pod-uid-1" || pod.Name != "test-pod-1" {
		t.Errorf("unexpected pod info: %+v", pod)
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

	pod, ok := pm.GetPodByIP("10.244.0.50")
	if !ok || pod == nil {
		t.Fatalf("unexpected state after add: %+v", pod)
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

	// New IP must resolve
	newPod, ok := pm.GetPodByIP("10.244.0.60")
	if !ok || newPod == nil {
		t.Fatalf("expected new IP 10.244.0.60 to resolve")
	}
	if newPod.UID != "pod-uid-restart" {
		t.Errorf("expected UID pod-uid-restart, got: %+v", newPod)
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
		},
	}
	pm.SynchronizePods(syncList)

	// existing-pod-1 retained
	p1, ok := pm.GetPodByIP("10.244.0.1")
	if !ok || p1.UID != "existing-pod-1" {
		t.Errorf("expected existing pod to be retained after sync: %+v", p1)
	}

	// deleted-pod removed
	if _, ok := pm.GetPodByIP("10.244.0.2"); ok {
		t.Errorf("expected deleted-pod to be pruned on synchronize")
	}

	// new-synced-pod added
	p3, ok := pm.GetPodByIP("10.244.0.3")
	if !ok || p3.UID != "new-synced-pod" {
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

	p, ok := pm.GetPodByIP("10.244.0.77")
	if !ok || p.UID != "http-test-pod" {
		t.Fatalf("pod not stored properly via HTTP: %+v", p)
	}

	// 2. GET /api/v1/pods
	res, err = http.Get(server.URL + "/api/v1/pods")
	if err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/v1/pods failed: %v", err)
	}
	var pods []*PodInfo
	_ = json.NewDecoder(res.Body).Decode(&pods)
	if len(pods) != 1 || pods[0].UID != "http-test-pod" {
		t.Errorf("unexpected GET /api/v1/pods output: %+v", pods)
	}

	// 3. DELETE /api/v1/pods/{uid}
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

func TestPodMap_BindingStoreIntegration(t *testing.T) {
	ctx := t.Context()
	storeDir := filepath.Join(t.TempDir(), "store")
	store, err := portalsv1.NewBindingStore(storeDir)
	if err != nil {
		t.Fatalf("failed to create BindingStore: %v", err)
	}

	pm := NewPodMap()
	pm.SetBindingStore(store)

	// Bind policy for pod-1 and pod-2
	validPolicy := &portalsv1.EgressPolicy{
		Rules: []*portalsv1.EgressRule{
			{
				Https: &portalsv1.HttpsRule{
					Hostnames: []string{"api.example.com"},
				},
			},
		},
	}
	if _, err := store.Bind(ctx, &portalsv1.PodPolicy{PodUid: "pod-1", Policy: validPolicy}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Bind(ctx, &portalsv1.PodPolicy{PodUid: "pod-2", Policy: validPolicy}); err != nil {
		t.Fatal(err)
	}

	pm.AddOrUpdatePod(&PodInfo{UID: "pod-1", IPs: []string{"10.0.0.1"}})
	pm.AddOrUpdatePod(&PodInfo{UID: "pod-2", IPs: []string{"10.0.0.2"}})

	// 1. pm.RemovePod("pod-1") removes pod-1 from both PodMap and BindingStore
	pm.RemovePod("pod-1")
	if _, ok := pm.GetPodByIP("10.0.0.1"); ok {
		t.Error("pod-1 IP still present in PodMap after RemovePod")
	}
	if pol := store.Policy("pod-1"); pol != nil {
		t.Error("pod-1 policy still present in BindingStore after RemovePod")
	}
	if _, err := os.Stat(filepath.Join(storeDir, "pod-1.json")); !os.IsNotExist(err) {
		t.Error("pod-1.json still present on disk after RemovePod")
	}

	// pod-2 must still be intact
	if pol := store.Policy("pod-2"); pol == nil {
		t.Error("pod-2 policy missing from BindingStore")
	}

	// 2. pm.SynchronizePods drops absent pods from both PodMap and BindingStore
	pm.SynchronizePods([]PodInfo{{UID: "pod-3", IPs: []string{"10.0.0.3"}}})
	if _, ok := pm.GetPodByIP("10.0.0.2"); ok {
		t.Error("pod-2 IP still present in PodMap after SynchronizePods")
	}
	if pol := store.Policy("pod-2"); pol != nil {
		t.Error("pod-2 policy still present in BindingStore after SynchronizePods")
	}
	if _, err := os.Stat(filepath.Join(storeDir, "pod-2.json")); !os.IsNotExist(err) {
		t.Error("pod-2.json still present on disk after SynchronizePods")
	}
}
