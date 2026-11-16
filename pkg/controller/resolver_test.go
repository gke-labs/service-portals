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

package controller

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
)

func newTestPod(namespace, name string, uid types.UID, nodeName string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
			UID:       uid,
		},
		Spec: corev1.PodSpec{
			NodeName: nodeName,
		},
	}
}

// TestNodeResolver verifies all contract requirements against a fake Kubernetes API.
func TestNodeResolver(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	client := fake.NewClientset()
	changes := make(chan types.UID, 50)
	resolver, err := NewNodeResolver(client, func(uid types.UID) {
		changes <- uid
	})
	if err != nil {
		t.Fatalf("failed to create resolver: %v", err)
	}

	// 1. Before the first sync, the answer is unknown even if pods are known to exist.
	scheduledUID := types.UID("uid-scheduled-1")
	scheduledPod := newTestPod("default", "scheduled-pod", scheduledUID, "node-worker-1")
	if _, err := client.CoreV1().Pods("default").Create(ctx, scheduledPod, metav1.CreateOptions{}); err != nil {
		t.Fatalf("failed to create scheduled pod: %v", err)
	}

	if res := resolver.Resolve(scheduledUID); res.State != PodStateUnknown {
		t.Fatalf("expected PodStateUnknown before first sync, got %v", res.State)
	}
	if resolver.HasSynced() {
		t.Fatalf("expected HasSynced() to be false before Run")
	}

	// Start the resolver in background and wait for initial sync.
	go func() { _ = resolver.Run(ctx) }()
	if !cache.WaitForCacheSync(ctx.Done(), resolver.HasSynced) {
		t.Fatalf("timed out waiting for cache sync")
	}

	// Drain any change events from initial list
	drainChanges(changes)

	// 2. A scheduled pod's UID resolves to its node.
	if res := resolver.Resolve(scheduledUID); res.State != PodStateScheduled || res.Node != "node-worker-1" {
		t.Fatalf("expected scheduled pod to resolve to node-worker-1, got state=%v, node=%q", res.State, res.Node)
	}
	if node, err := resolver.NodeForPod(ctx, string(scheduledUID)); err != nil || node != "node-worker-1" {
		t.Fatalf("expected NodeForPod to return node-worker-1, got node=%q, err=%v", node, err)
	}

	// 3. An unknown UID is unknown.
	unknownUID := types.UID("uid-does-not-exist")
	if res := resolver.Resolve(unknownUID); res.State != PodStateUnknown {
		t.Fatalf("expected unknown UID to resolve to PodStateUnknown, got %v", res.State)
	}
	if node, err := resolver.NodeForPod(ctx, string(unknownUID)); err != nil || node != "" {
		t.Fatalf("expected NodeForPod for unknown UID to return empty, got node=%q, err=%v", node, err)
	}

	// 4. An unscheduled pod resolves to "not scheduled" and a watcher is told when it is scheduled.
	unscheduledUID := types.UID("uid-unscheduled-1")
	unscheduledPod := newTestPod("default", "unscheduled-pod", unscheduledUID, "")
	if _, err := client.CoreV1().Pods("default").Create(ctx, unscheduledPod, metav1.CreateOptions{}); err != nil {
		t.Fatalf("failed to create unscheduled pod: %v", err)
	}

	expectChange(t, changes, unscheduledUID)
	if res := resolver.Resolve(unscheduledUID); res.State != PodStateUnscheduled {
		t.Fatalf("expected unscheduled pod to resolve to PodStateUnscheduled, got %v", res.State)
	}

	// Unrelated update (annotations) should not notify onChange.
	unscheduledPod.Annotations = map[string]string{"foo": "bar"}
	if _, err := client.CoreV1().Pods("default").Update(ctx, unscheduledPod, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("failed to update annotations: %v", err)
	}
	select {
	case uid := <-changes:
		t.Fatalf("unexpected change notification on annotation update: %v", uid)
	case <-time.After(50 * time.Millisecond):
	}

	// Update pod to scheduled on "node-worker-2"
	unscheduledPod.Spec.NodeName = "node-worker-2"
	if _, err := client.CoreV1().Pods("default").Update(ctx, unscheduledPod, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("failed to update pod to scheduled: %v", err)
	}

	expectChange(t, changes, unscheduledUID)
	if res := resolver.Resolve(unscheduledUID); res.State != PodStateScheduled || res.Node != "node-worker-2" {
		t.Fatalf("expected pod to resolve to node-worker-2, got state=%v, node=%q", res.State, res.Node)
	}

	// 5. A deleted pod becomes unknown and a watcher is told.
	if err := client.CoreV1().Pods("default").Delete(ctx, unscheduledPod.Name, metav1.DeleteOptions{}); err != nil {
		t.Fatalf("failed to delete pod: %v", err)
	}

	expectChange(t, changes, unscheduledUID)
	if res := resolver.Resolve(unscheduledUID); res.State != PodStateUnknown {
		t.Fatalf("expected deleted pod to resolve to PodStateUnknown, got %v", res.State)
	}

	// 6. A recreated pod with the same name and a new UID does not match the old UID.
	recreatedName := "lifecycle-pod"
	oldUID := types.UID("uid-generation-1")
	podGen1 := newTestPod("default", recreatedName, oldUID, "node-worker-1")
	if _, err := client.CoreV1().Pods("default").Create(ctx, podGen1, metav1.CreateOptions{}); err != nil {
		t.Fatalf("failed to create initial pod: %v", err)
	}
	expectChange(t, changes, oldUID)
	if res := resolver.Resolve(oldUID); res.State != PodStateScheduled || res.Node != "node-worker-1" {
		t.Fatalf("expected oldUID to resolve to node-worker-1, got %v", res)
	}

	// Delete old pod
	if err := client.CoreV1().Pods("default").Delete(ctx, recreatedName, metav1.DeleteOptions{}); err != nil {
		t.Fatalf("failed to delete old pod: %v", err)
	}
	expectChange(t, changes, oldUID)

	// Create new pod with same name but new UID
	newUID := types.UID("uid-generation-2")
	podGen2 := newTestPod("default", recreatedName, newUID, "node-worker-3")
	if _, err := client.CoreV1().Pods("default").Create(ctx, podGen2, metav1.CreateOptions{}); err != nil {
		t.Fatalf("failed to create recreated pod: %v", err)
	}
	expectChange(t, changes, newUID)

	// Old UID remains unknown, new UID resolves to its node.
	if res := resolver.Resolve(oldUID); res.State != PodStateUnknown {
		t.Fatalf("expected old UID to remain PodStateUnknown, got %v", res.State)
	}
	if res := resolver.Resolve(newUID); res.State != PodStateScheduled || res.Node != "node-worker-3" {
		t.Fatalf("expected new UID to resolve to node-worker-3, got state=%v, node=%q", res.State, res.Node)
	}
}

func expectChange(t *testing.T, ch <-chan types.UID, expected types.UID) {
	t.Helper()
	select {
	case uid := <-ch:
		if uid != expected {
			t.Fatalf("expected change for UID %s, got %s", expected, uid)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for change notification for UID %s", expected)
	}
}

func drainChanges(ch <-chan types.UID) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}

// TestNodeResolverConcurrencyRace runs concurrent resolves, creates, updates and deletes to verify race freedom.
func TestNodeResolverConcurrencyRace(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	client := fake.NewClientset()
	resolver, err := NewNodeResolver(client, func(uid types.UID) {})
	if err != nil {
		t.Fatalf("failed to create resolver: %v", err)
	}
	go func() { _ = resolver.Run(ctx) }()
	if !cache.WaitForCacheSync(ctx.Done(), resolver.HasSynced) {
		t.Fatalf("timed out waiting for cache sync")
	}

	var wg sync.WaitGroup
	numPods := 20

	for i := 0; i < numPods; i++ {
		uid := types.UID(fmt.Sprintf("concurrent-pod-%d", i))
		name := fmt.Sprintf("concurrent-name-%d", i)

		wg.Add(1)
		go func(pUID types.UID, pName string, idx int) {
			defer wg.Done()
			p := newTestPod("default", pName, pUID, "")
			_, _ = client.CoreV1().Pods("default").Create(ctx, p, metav1.CreateOptions{})
			p.Spec.NodeName = fmt.Sprintf("node-%d", idx%3)
			_, _ = client.CoreV1().Pods("default").Update(ctx, p, metav1.UpdateOptions{})
			_ = resolver.Resolve(pUID)
			_ = client.CoreV1().Pods("default").Delete(ctx, pName, metav1.DeleteOptions{})
			_ = resolver.Resolve(pUID)
		}(uid, name, i)
	}

	wg.Wait()
}
