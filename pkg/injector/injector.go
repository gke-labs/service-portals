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
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"

	"github.com/gke-labs/service-portals/pkg/apis/portals/v1alpha1"
	"github.com/gke-labs/service-portals/pkg/policy"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/utils/ptr"
)

const (
	AnnotationInject        = "portals.gke.io/inject"
	AnnotationInjectCAEnv   = "portals.gke.io/inject-ca-env"
	AnnotationStatus        = "portals.gke.io/status"
	AnnotationPolicy        = "portals.gke.io/policy"
	AnnotationPolicyGen     = "portals.gke.io/policy-generation"
	NamespaceLabelInjection = "portals.gke.io/injection"
	StatusInjected          = "injected"
	ProxyUID                = int64(1337)
)

// PolicyLister lists PortalPolicy resources in a namespace.
type PolicyLister interface {
	ListPolicies(ctx context.Context, namespace string) ([]*v1alpha1.PortalPolicy, error)
}

// NamespaceGetter retrieves a Namespace by name.
type NamespaceGetter interface {
	GetNamespace(ctx context.Context, name string) (*corev1.Namespace, error)
}

// SecretManager handles reading and creating/updating Secrets.
type SecretManager interface {
	GetSecret(ctx context.Context, namespace, name string) (*corev1.Secret, error)
	CreateOrUpdateSecret(ctx context.Context, namespace string, secret *corev1.Secret) error
}

// Config configures the admission injector.
type Config struct {
	NativeSidecars    bool
	DefaultInitImage  string
	DefaultProxyImage string
	DummyIP           string
}

// Injector performs mutation and validation of pods.
type Injector struct {
	Policies   PolicyLister
	Namespaces NamespaceGetter
	Secrets    SecretManager
	Config     Config
}

// PatchOperation defines an RFC 6902 JSON patch operation.
type PatchOperation struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value any    `json:"value,omitempty"`
}

// ValidatePod checks workload security constraints for injected pods.
func ValidatePod(pod *corev1.Pod) error {
	if pod.Spec.HostNetwork {
		return fmt.Errorf("spec.hostNetwork: host network is not allowed on pods with service portal sidecars")
	}

	allContainers := append([]corev1.Container{}, pod.Spec.Containers...)
	for _, ic := range pod.Spec.InitContainers {
		if ic.Name != "init-service-portals" && ic.Name != "service-portal-sidecar" {
			allContainers = append(allContainers, ic)
		}
	}

	podRunAsNonRoot := pod.Spec.SecurityContext != nil && pod.Spec.SecurityContext.RunAsNonRoot != nil && *pod.Spec.SecurityContext.RunAsNonRoot

	if pod.Spec.SecurityContext != nil && pod.Spec.SecurityContext.RunAsUser != nil && *pod.Spec.SecurityContext.RunAsUser == ProxyUID {
		return fmt.Errorf("spec.securityContext.runAsUser: cannot be %d (reserved for service portal proxy)", ProxyUID)
	}

	for _, c := range allContainers {
		if c.Name == "init-service-portals" || c.Name == "service-portal-sidecar" {
			continue
		}

		containerRunAsNonRoot := c.SecurityContext != nil && c.SecurityContext.RunAsNonRoot != nil && *c.SecurityContext.RunAsNonRoot
		if !containerRunAsNonRoot && !podRunAsNonRoot {
			return fmt.Errorf("container %q: securityContext.runAsNonRoot must be true to prevent running as proxy UID (%d)", c.Name, ProxyUID)
		}

		if c.SecurityContext != nil && c.SecurityContext.RunAsUser != nil && *c.SecurityContext.RunAsUser == ProxyUID {
			return fmt.Errorf("container %q: securityContext.runAsUser cannot be %d (reserved for service portal proxy)", c.Name, ProxyUID)
		}

		allowPrivilegeEscalation := c.SecurityContext != nil && c.SecurityContext.AllowPrivilegeEscalation != nil && *c.SecurityContext.AllowPrivilegeEscalation
		if c.SecurityContext == nil || c.SecurityContext.AllowPrivilegeEscalation == nil || allowPrivilegeEscalation {
			return fmt.Errorf("container %q: securityContext.allowPrivilegeEscalation must be false to prevent privilege escalation to proxy UID (%d)", c.Name, ProxyUID)
		}

		if c.SecurityContext != nil && c.SecurityContext.Capabilities != nil {
			for _, cap := range c.SecurityContext.Capabilities.Add {
				capStr := strings.ToUpper(string(cap))
				if capStr == "NET_ADMIN" || capStr == "CAP_NET_ADMIN" || capStr == "NET_RAW" || capStr == "CAP_NET_RAW" {
					return fmt.Errorf("container %q: securityContext.capabilities cannot include %s", c.Name, capStr)
				}
			}
		}
	}

	return nil
}

// SelectPolicy selects the matching PortalPolicy for a pod.
func (inj *Injector) SelectPolicy(ctx context.Context, namespace string, pod *corev1.Pod) (*v1alpha1.PortalPolicy, error) {
	if pod.Annotations != nil && pod.Annotations[AnnotationInject] == "false" {
		return nil, nil
	}

	forced := pod.Annotations != nil && pod.Annotations[AnnotationInject] == "true"

	if !forced {
		if inj.Namespaces != nil && namespace != "" {
			ns, err := inj.Namespaces.GetNamespace(ctx, namespace)
			if err != nil {
				return nil, fmt.Errorf("failed to get namespace %q: %w", namespace, err)
			}
			if ns == nil || ns.Labels[NamespaceLabelInjection] != "enabled" {
				return nil, nil
			}
		} else {
			return nil, nil
		}
	}

	if inj.Policies == nil {
		if forced {
			return nil, fmt.Errorf("no policy provider configured to evaluate forced injection")
		}
		return nil, nil
	}

	policies, err := inj.Policies.ListPolicies(ctx, namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to list PortalPolicies in namespace %q: %w", namespace, err)
	}

	var matching []*v1alpha1.PortalPolicy
	podLabels := labels.Set(pod.Labels)

	for _, p := range policies {
		sel, err := metav1.LabelSelectorAsSelector(&p.Spec.PodSelector)
		if err != nil {
			log.Printf("Warning: invalid podSelector in policy %s/%s: %v", p.Namespace, p.Name, err)
			continue
		}
		if sel.Matches(podLabels) {
			matching = append(matching, p)
		}
	}

	if len(matching) == 0 {
		if forced {
			return nil, fmt.Errorf("no PortalPolicy matches pod labels in namespace %q despite %s: %q", namespace, AnnotationInject, "true")
		}
		log.Printf("Debug: no PortalPolicy matches pod in namespace %q", namespace)
		return nil, nil
	}

	if len(matching) > 1 {
		var names []string
		for _, m := range matching {
			names = append(names, m.Name)
		}
		sort.Strings(names)
		return nil, fmt.Errorf("multiple PortalPolicies matched pod in namespace %q: [%s]", namespace, strings.Join(names, ", "))
	}

	return matching[0], nil
}

// Mutate handles pod mutation admission review.
func (inj *Injector) Mutate(ctx context.Context, req *admissionv1.AdmissionRequest) *admissionv1.AdmissionResponse {
	if req == nil {
		return &admissionv1.AdmissionResponse{Allowed: false, Result: &metav1.Status{Message: "empty admission request"}}
	}

	var pod corev1.Pod
	if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
		return &admissionv1.AdmissionResponse{
			UID:     req.UID,
			Allowed: false,
			Result:  &metav1.Status{Message: fmt.Sprintf("failed to unmarshal pod: %v", err)},
		}
	}

	// Idempotency: re-admission of an already-injected pod is a no-op
	if pod.Annotations != nil && pod.Annotations[AnnotationStatus] == StatusInjected {
		return &admissionv1.AdmissionResponse{
			UID:     req.UID,
			Allowed: true,
		}
	}

	matchedPolicy, err := inj.SelectPolicy(ctx, req.Namespace, &pod)
	if err != nil {
		return &admissionv1.AdmissionResponse{
			UID:     req.UID,
			Allowed: false,
			Result:  &metav1.Status{Message: err.Error()},
		}
	}

	if matchedPolicy == nil {
		return &admissionv1.AdmissionResponse{
			UID:     req.UID,
			Allowed: true,
		}
	}

	// Validate workload security requirements before injecting
	if err := ValidatePod(&pod); err != nil {
		return &admissionv1.AdmissionResponse{
			UID:     req.UID,
			Allowed: false,
			Result:  &metav1.Status{Message: err.Error()},
		}
	}

	sidecarConfig, err := policy.Resolve(ctx, matchedPolicy, inj.Secrets)
	if err != nil {
		return &admissionv1.AdmissionResponse{
			UID:     req.UID,
			Allowed: false,
			Result:  &metav1.Status{Message: fmt.Sprintf("failed to resolve policy %s: %v", matchedPolicy.Name, err)},
		}
	}

	patches, err := inj.buildMutationPatches(ctx, req.Namespace, &pod, matchedPolicy, sidecarConfig)
	if err != nil {
		return &admissionv1.AdmissionResponse{
			UID:     req.UID,
			Allowed: false,
			Result:  &metav1.Status{Message: fmt.Sprintf("failed to build mutation patches: %v", err)},
		}
	}

	patchBytes, err := json.Marshal(patches)
	if err != nil {
		return &admissionv1.AdmissionResponse{
			UID:     req.UID,
			Allowed: false,
			Result:  &metav1.Status{Message: fmt.Sprintf("failed to marshal patches: %v", err)},
		}
	}

	patchType := admissionv1.PatchTypeJSONPatch
	return &admissionv1.AdmissionResponse{
		UID:       req.UID,
		Allowed:   true,
		Patch:     patchBytes,
		PatchType: &patchType,
	}
}

// Validate handles pod validation admission review.
func (inj *Injector) Validate(ctx context.Context, req *admissionv1.AdmissionRequest) *admissionv1.AdmissionResponse {
	if req == nil {
		return &admissionv1.AdmissionResponse{Allowed: false, Result: &metav1.Status{Message: "empty admission request"}}
	}

	var pod corev1.Pod
	if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
		return &admissionv1.AdmissionResponse{
			UID:     req.UID,
			Allowed: false,
			Result:  &metav1.Status{Message: fmt.Sprintf("failed to unmarshal pod: %v", err)},
		}
	}

	shouldValidate := false
	if pod.Annotations != nil && (pod.Annotations[AnnotationStatus] == StatusInjected || pod.Annotations[AnnotationInject] == "true") {
		shouldValidate = true
	} else {
		matchedPolicy, err := inj.SelectPolicy(ctx, req.Namespace, &pod)
		if err != nil {
			return &admissionv1.AdmissionResponse{
				UID:     req.UID,
				Allowed: false,
				Result:  &metav1.Status{Message: err.Error()},
			}
		}
		if matchedPolicy != nil {
			shouldValidate = true
		}
	}

	if shouldValidate {
		if err := ValidatePod(&pod); err != nil {
			return &admissionv1.AdmissionResponse{
				UID:     req.UID,
				Allowed: false,
				Result:  &metav1.Status{Message: err.Error()},
			}
		}
	}

	return &admissionv1.AdmissionResponse{
		UID:     req.UID,
		Allowed: true,
	}
}

func (inj *Injector) buildMutationPatches(ctx context.Context, namespace string, pod *corev1.Pod, pol *v1alpha1.PortalPolicy, cfg *policy.SidecarConfig) ([]PatchOperation, error) {
	// 1. Determine generated rules secret name and owner references
	podOwner := "pod"
	var ownerRef *metav1.OwnerReference

	for _, o := range pod.OwnerReferences {
		if o.Controller != nil && *o.Controller {
			podOwner = o.Name
			ownerRef = o.DeepCopy()
			break
		}
	}
	if ownerRef == nil && len(pod.OwnerReferences) > 0 {
		podOwner = pod.OwnerReferences[0].Name
		ownerRef = pod.OwnerReferences[0].DeepCopy()
	}
	if ownerRef == nil {
		if pod.Name != "" {
			podOwner = pod.Name
		} else if pod.GenerateName != "" {
			podOwner = strings.TrimSuffix(pod.GenerateName, "-")
		}
		ownerRef = &metav1.OwnerReference{
			APIVersion: v1alpha1.SchemeGroupVersion.String(),
			Kind:       "PortalPolicy",
			Name:       pol.Name,
			UID:        pol.UID,
		}
	}

	// Calculate deterministic hash of rules content
	h := sha256.New()
	var filenames []string
	for fn := range cfg.RulesYAML {
		filenames = append(filenames, fn)
	}
	sort.Strings(filenames)
	for _, fn := range filenames {
		h.Write([]byte(fn))
		h.Write([]byte(cfg.RulesYAML[fn]))
	}
	rulesHash := fmt.Sprintf("%x", h.Sum(nil))[:8]
	rulesSecretName := fmt.Sprintf("%s-portal-rules-%s", podOwner, rulesHash)

	// Create or update generated rules Secret
	if inj.Secrets != nil {
		secretObj := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      rulesSecretName,
				Namespace: namespace,
			},
			StringData: cfg.RulesYAML,
		}
		if ownerRef != nil {
			secretObj.OwnerReferences = []metav1.OwnerReference{*ownerRef}
		}
		if err := inj.Secrets.CreateOrUpdateSecret(ctx, namespace, secretObj); err != nil {
			return nil, fmt.Errorf("failed to create/update rules secret %q: %w", rulesSecretName, err)
		}
	}

	var patches []PatchOperation

	// 2. Annotations
	if len(pod.Annotations) == 0 {
		patches = append(patches, PatchOperation{
			Op:   "add",
			Path: "/metadata/annotations",
			Value: map[string]string{
				AnnotationStatus:    StatusInjected,
				AnnotationPolicy:    pol.Name,
				AnnotationPolicyGen: fmt.Sprintf("%d", pol.Generation),
			},
		})
	} else {
		patches = append(patches,
			PatchOperation{Op: "add", Path: "/metadata/annotations/" + escapeJSONPointer(AnnotationStatus), Value: StatusInjected},
			PatchOperation{Op: "add", Path: "/metadata/annotations/" + escapeJSONPointer(AnnotationPolicy), Value: pol.Name},
			PatchOperation{Op: "add", Path: "/metadata/annotations/" + escapeJSONPointer(AnnotationPolicyGen), Value: fmt.Sprintf("%d", pol.Generation)},
		)
	}

	// 3. Init Containers
	initImage := inj.Config.DefaultInitImage
	if initImage == "" {
		initImage = "init-service-portals:latest"
	}
	proxyImage := cfg.ProxyImage
	if proxyImage == "" {
		proxyImage = inj.Config.DefaultProxyImage
	}
	if proxyImage == "" {
		proxyImage = "all-in-one-portal:latest"
	}

	initContainer := corev1.Container{
		Name:            "init-service-portals",
		Image:           initImage,
		ImagePullPolicy: corev1.PullIfNotPresent,
		Env:             cfg.InitEnv,
		SecurityContext: &corev1.SecurityContext{
			Capabilities: &corev1.Capabilities{
				Add: []corev1.Capability{"NET_ADMIN"},
			},
			RunAsUser:  ptr.To(int64(0)),
			RunAsGroup: ptr.To(int64(0)),
			Privileged: ptr.To(false),
		},
		VolumeMounts: []corev1.VolumeMount{
			{Name: "ca-cert", MountPath: "/etc/service-portal/ca"},
			{Name: "ca-key", MountPath: "/etc/service-portal/ca-private"},
		},
	}

	sidecarContainer := corev1.Container{
		Name:            "service-portal-sidecar",
		Image:           proxyImage,
		ImagePullPolicy: corev1.PullIfNotPresent,
		SecurityContext: &corev1.SecurityContext{
			RunAsUser:                ptr.To(ProxyUID),
			RunAsGroup:               ptr.To(ProxyUID),
			AllowPrivilegeEscalation: ptr.To(false),
			ReadOnlyRootFilesystem:   ptr.To(true),
		},
		Ports: []corev1.ContainerPort{
			{ContainerPort: 8080, Name: "proxy"},
			{ContainerPort: 8443, Name: "proxy-https"},
		},
		Env: []corev1.EnvVar{
			{Name: "CA_CERT_PATH", Value: "/etc/service-portal/ca-private/tls.crt"},
			{Name: "CA_KEY_PATH", Value: "/etc/service-portal/ca-private/tls.key"},
		},
		Args: []string{"--rules-dir=/etc/portals"},
		VolumeMounts: []corev1.VolumeMount{
			{Name: "rules-volume", MountPath: "/etc/portals", ReadOnly: true},
			{Name: "ca-key", MountPath: "/etc/service-portal/ca-private", ReadOnly: true},
		},
		Resources: cfg.ProxyResources,
	}

	if inj.Config.NativeSidecars {
		always := corev1.ContainerRestartPolicyAlways
		sidecarContainer.RestartPolicy = &always

		newInitContainers := []corev1.Container{initContainer, sidecarContainer}
		newInitContainers = append(newInitContainers, pod.Spec.InitContainers...)

		if len(pod.Spec.InitContainers) == 0 {
			patches = append(patches, PatchOperation{
				Op:    "add",
				Path:  "/spec/initContainers",
				Value: newInitContainers,
			})
		} else {
			patches = append(patches, PatchOperation{
				Op:    "replace",
				Path:  "/spec/initContainers",
				Value: newInitContainers,
			})
		}
	} else {
		newInitContainers := []corev1.Container{initContainer}
		newInitContainers = append(newInitContainers, pod.Spec.InitContainers...)

		if len(pod.Spec.InitContainers) == 0 {
			patches = append(patches, PatchOperation{
				Op:    "add",
				Path:  "/spec/initContainers",
				Value: newInitContainers,
			})
		} else {
			patches = append(patches, PatchOperation{
				Op:    "replace",
				Path:  "/spec/initContainers",
				Value: newInitContainers,
			})
		}

		// Fallback for older clusters: regular container
		pod.Spec.Containers = append(pod.Spec.Containers, sidecarContainer)
	}

	// 4. Workload Containers mutation: ca-cert mount and environment variables
	injectCAEnv := true
	if pod.Annotations != nil && pod.Annotations[AnnotationInjectCAEnv] == "false" {
		injectCAEnv = false
	}

	caMount := corev1.VolumeMount{
		Name:      "ca-cert",
		MountPath: "/etc/service-portal/ca",
		ReadOnly:  true,
	}

	caEnvVars := []corev1.EnvVar{
		{Name: "SSL_CERT_FILE", Value: "/etc/service-portal/ca/tls.crt"},
		{Name: "REQUESTS_CA_BUNDLE", Value: "/etc/service-portal/ca/tls.crt"},
		{Name: "NODE_EXTRA_CA_CERTS", Value: "/etc/service-portal/ca/tls.crt"},
	}

	updatedContainers := make([]corev1.Container, len(pod.Spec.Containers))
	for i, c := range pod.Spec.Containers {
		cCopy := *c.DeepCopy()
		if cCopy.Name != "service-portal-sidecar" {
			// Add ca-cert mount if not present
			hasMount := false
			for _, m := range cCopy.VolumeMounts {
				if m.MountPath == "/etc/service-portal/ca" {
					hasMount = true
					break
				}
			}
			if !hasMount {
				cCopy.VolumeMounts = append(cCopy.VolumeMounts, caMount)
			}

			// Add CA environment variables if enabled and not present
			if injectCAEnv {
				for _, caEnv := range caEnvVars {
					hasEnv := false
					for _, env := range cCopy.Env {
						if env.Name == caEnv.Name {
							hasEnv = true
							break
						}
					}
					if !hasEnv {
						cCopy.Env = append(cCopy.Env, caEnv)
					}
				}
			}
		}
		updatedContainers[i] = cCopy
	}

	patches = append(patches, PatchOperation{
		Op:    "replace",
		Path:  "/spec/containers",
		Value: updatedContainers,
	})

	// 5. Volumes
	portalVolumes := []corev1.Volume{
		{
			Name: "rules-volume",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: rulesSecretName,
				},
			},
		},
		{
			Name: "ca-cert",
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{},
			},
		},
		{
			Name: "ca-key",
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{},
			},
		},
	}

	newVolumes := append([]corev1.Volume{}, pod.Spec.Volumes...)
	newVolumes = append(newVolumes, portalVolumes...)

	if len(pod.Spec.Volumes) == 0 {
		patches = append(patches, PatchOperation{
			Op:    "add",
			Path:  "/spec/volumes",
			Value: newVolumes,
		})
	} else {
		patches = append(patches, PatchOperation{
			Op:    "replace",
			Path:  "/spec/volumes",
			Value: newVolumes,
		})
	}

	// 6. HostAliases
	if len(cfg.HostAliases) > 0 {
		newHostAliases := append([]corev1.HostAlias{}, pod.Spec.HostAliases...)
		newHostAliases = append(newHostAliases, cfg.HostAliases...)

		if len(pod.Spec.HostAliases) == 0 {
			patches = append(patches, PatchOperation{
				Op:    "add",
				Path:  "/spec/hostAliases",
				Value: newHostAliases,
			})
		} else {
			patches = append(patches, PatchOperation{
				Op:    "replace",
				Path:  "/spec/hostAliases",
				Value: newHostAliases,
			})
		}
	}

	return patches, nil
}

func escapeJSONPointer(s string) string {
	s = strings.ReplaceAll(s, "~", "~0")
	s = strings.ReplaceAll(s, "/", "~1")
	return s
}
