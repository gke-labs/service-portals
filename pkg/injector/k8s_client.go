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

package injector

import (
	"context"
	"fmt"

	"github.com/gke-labs/service-portals/pkg/apis/portals/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

var portalPoliciesGVR = schema.GroupVersionResource{
	Group:    v1alpha1.GroupName,
	Version:  v1alpha1.SchemeGroupVersion.Version,
	Resource: "portalpolicies",
}

// DynamicPolicyLister implements PolicyLister using the dynamic client.
type DynamicPolicyLister struct {
	Client dynamic.Interface
}

func (l *DynamicPolicyLister) ListPolicies(ctx context.Context, namespace string) ([]*v1alpha1.PortalPolicy, error) {
	unstructuredList, err := l.Client.Resource(portalPoliciesGVR).Namespace(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list portalpolicies: %w", err)
	}

	var policies []*v1alpha1.PortalPolicy
	for _, item := range unstructuredList.Items {
		var p v1alpha1.PortalPolicy
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(item.Object, &p); err != nil {
			return nil, fmt.Errorf("failed to convert unstructured policy %s: %w", item.GetName(), err)
		}
		policies = append(policies, &p)
	}

	return policies, nil
}

// KubeNamespaceGetter implements NamespaceGetter using kubernetes.Interface.
type KubeNamespaceGetter struct {
	Client kubernetes.Interface
}

func (g *KubeNamespaceGetter) GetNamespace(ctx context.Context, name string) (*corev1.Namespace, error) {
	ns, err := g.Client.CoreV1().Namespaces().Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return ns, nil
}

// KubeSecretManager implements SecretManager using kubernetes.Interface.
type KubeSecretManager struct {
	Client kubernetes.Interface
}

func (m *KubeSecretManager) GetSecret(ctx context.Context, namespace, name string) (*corev1.Secret, error) {
	return m.Client.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
}

func (m *KubeSecretManager) CreateOrUpdateSecret(ctx context.Context, namespace string, secret *corev1.Secret) error {
	_, err := m.Client.CoreV1().Secrets(namespace).Create(ctx, secret, metav1.CreateOptions{})
	if err == nil {
		return nil
	}
	if !apierrors.IsAlreadyExists(err) {
		return err
	}

	existing, err := m.Client.CoreV1().Secrets(namespace).Get(ctx, secret.Name, metav1.GetOptions{})
	if err != nil {
		return err
	}

	existing.StringData = secret.StringData
	existing.Data = secret.Data
	if len(secret.OwnerReferences) > 0 {
		existing.OwnerReferences = secret.OwnerReferences
	}

	_, err = m.Client.CoreV1().Secrets(namespace).Update(ctx, existing, metav1.UpdateOptions{})
	return err
}
