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

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// PodState represents the scheduling and binding state of a pod.
type PodState string

const (
	PodStateUnknown     PodState = "unknown"
	PodStateUnscheduled PodState = "unscheduled"
	PodStateScheduled   PodState = "scheduled"
)

// Resolution is the resolved node location and state for a pod UID.
type Resolution struct {
	UID   types.UID
	State PodState
	Node  string
}

func (r Resolution) String() string {
	if r.State == PodStateScheduled {
		return fmt.Sprintf("%s (%s)", r.State, r.Node)
	}
	return string(r.State)
}

const uidIndex = "uid"

// NodeResolver resolves a pod UID to its bound node using the Kubernetes API.
// It fails closed: before initial cache sync or for unknown pods,
// the answer is PodStateUnknown.
type NodeResolver struct {
	informer cache.SharedIndexInformer
	onChange func(types.UID)
}

// NewNodeResolver creates a NodeResolver backed by a Pod informer.
// The relay requires read-only RBAC permissions on pods (verbs: get, list, watch).
// The onChange callback is called whenever a pod's scheduling or node binding changes;
// it must not block.
func NewNodeResolver(client kubernetes.Interface, onChange func(types.UID)) (*NodeResolver, error) {
	informer := informers.NewSharedInformerFactory(client, 0).Core().V1().Pods().Informer()
	if err := informer.AddIndexers(cache.Indexers{uidIndex: uidIndexFunc}); err != nil {
		return nil, fmt.Errorf("adding uid indexer: %w", err)
	}

	r := &NodeResolver{
		informer: informer,
		onChange: onChange,
	}

	if _, err := informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    r.onAdd,
		UpdateFunc: r.onUpdate,
		DeleteFunc: r.onDelete,
	}); err != nil {
		return nil, fmt.Errorf("registering pod event handler: %w", err)
	}

	return r, nil
}

// Run starts the pod informer and blocks until ctx is canceled.
func (r *NodeResolver) Run(ctx context.Context) error {
	r.informer.Run(ctx.Done())
	return ctx.Err()
}

// HasSynced reports whether the informer has synced its initial cache.
func (r *NodeResolver) HasSynced() bool {
	return r.informer.HasSynced()
}

// Resolve returns the node resolution for the given pod UID.
// If the informer has not synced, or the pod is unknown or deleted,
// it returns PodStateUnknown.
func (r *NodeResolver) Resolve(uid types.UID) Resolution {
	if !r.HasSynced() {
		return Resolution{UID: uid, State: PodStateUnknown}
	}
	objs, err := r.informer.GetIndexer().ByIndex(uidIndex, string(uid))
	if err != nil || len(objs) == 0 {
		return Resolution{UID: uid, State: PodStateUnknown}
	}
	pod, ok := objs[0].(*corev1.Pod)
	if !ok {
		return Resolution{UID: uid, State: PodStateUnknown}
	}
	return resolutionFromPod(pod)
}

// NodeForPod returns the node running the pod UID, or empty string if not scheduled or unknown.
// Implements PodLookup.
func (r *NodeResolver) NodeForPod(ctx context.Context, podUID string) (string, error) {
	res := r.Resolve(types.UID(podUID))
	if res.State == PodStateScheduled {
		return res.Node, nil
	}
	return "", nil
}

func (r *NodeResolver) onAdd(obj any) {
	if r.onChange != nil {
		if pod := extractPod(obj); pod != nil {
			r.onChange(pod.UID)
		}
	}
}

func (r *NodeResolver) onUpdate(oldObj, newObj any) {
	if r.onChange == nil {
		return
	}
	oldPod, newPod := extractPod(oldObj), extractPod(newObj)
	if newPod == nil {
		return
	}
	if oldPod != nil && oldPod.UID != newPod.UID {
		r.onChange(oldPod.UID)
		r.onChange(newPod.UID)
		return
	}
	if oldPod == nil || oldPod.Spec.NodeName != newPod.Spec.NodeName {
		r.onChange(newPod.UID)
	}
}

func (r *NodeResolver) onDelete(obj any) {
	if r.onChange != nil {
		if pod := extractPod(obj); pod != nil {
			r.onChange(pod.UID)
		}
	}
}

func uidIndexFunc(obj any) ([]string, error) {
	if pod, ok := obj.(*corev1.Pod); ok {
		return []string{string(pod.UID)}, nil
	}
	if tombstone, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		if pod, ok := tombstone.Obj.(*corev1.Pod); ok {
			return []string{string(pod.UID)}, nil
		}
	}
	return nil, fmt.Errorf("unexpected object type %T", obj)
}

func extractPod(obj any) *corev1.Pod {
	if pod, ok := obj.(*corev1.Pod); ok {
		return pod
	}
	if tombstone, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		pod, _ := tombstone.Obj.(*corev1.Pod)
		return pod
	}
	return nil
}

func resolutionFromPod(pod *corev1.Pod) Resolution {
	if pod.Spec.NodeName != "" {
		return Resolution{UID: pod.UID, State: PodStateScheduled, Node: pod.Spec.NodeName}
	}
	return Resolution{UID: pod.UID, State: PodStateUnscheduled}
}
