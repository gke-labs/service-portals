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

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"time"
)

type AdmissionReview struct {
	APIVersion string             `json:"apiVersion"`
	Kind       string             `json:"kind"`
	Request    *AdmissionRequest  `json:"request,omitempty"`
	Response   *AdmissionResponse `json:"response,omitempty"`
}

type AdmissionRequest struct {
	UID       string          `json:"uid"`
	Namespace string          `json:"namespace"`
	Object    json.RawMessage `json:"object"`
}

type AdmissionResponse struct {
	UID       string `json:"uid"`
	Allowed   bool   `json:"allowed"`
	PatchType string `json:"patchType,omitempty"`
	Patch     []byte `json:"patch,omitempty"`
}

type JSONPatchOp struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value any    `json:"value"`
}

type EnvVar struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type VolumeMount struct {
	Name      string `json:"name"`
	MountPath string `json:"mountPath"`
	ReadOnly  bool   `json:"readOnly"`
}

type Volume struct {
	Name   string        `json:"name"`
	Secret *SecretVolume `json:"secret,omitempty"`
}

type SecretVolume struct {
	SecretName string `json:"secretName"`
}

type PodMeta struct {
	Metadata struct {
		Name        string            `json:"name"`
		Namespace   string            `json:"namespace"`
		Labels      map[string]string `json:"labels"`
		Annotations map[string]string `json:"annotations"`
	} `json:"metadata"`
	Spec struct {
		Containers []struct {
			Name         string        `json:"name"`
			Env          []EnvVar      `json:"env"`
			VolumeMounts []VolumeMount `json:"volumeMounts"`
		} `json:"containers"`
		Volumes []Volume `json:"volumes"`
	} `json:"spec"`
}

func mutatePod(podJSON []byte, proxyURL, caCertPath, caSecretName string) ([]JSONPatchOp, bool, error) {
	var pod PodMeta
	if err := json.Unmarshal(podJSON, &pod); err != nil {
		return nil, false, fmt.Errorf("failed to parse pod JSON: %w", err)
	}

	// Check for opt-in label or annotation
	optedIn := false
	if pod.Metadata.Labels != nil {
		if pod.Metadata.Labels["portal.gke.io/enabled"] == "true" ||
			pod.Metadata.Labels["portal.gke.io/app-level"] == "true" {
			optedIn = true
		}
	}
	if pod.Metadata.Annotations != nil {
		if pod.Metadata.Annotations["portal.gke.io/inject"] == "true" ||
			pod.Metadata.Annotations["portal.gke.io/app-level"] == "true" {
			optedIn = true
		}
	}

	if !optedIn {
		return nil, false, nil
	}

	var patches []JSONPatchOp

	envVarsToInject := []EnvVar{
		{Name: "HTTP_PROXY", Value: proxyURL},
		{Name: "HTTPS_PROXY", Value: proxyURL},
		{Name: "http_proxy", Value: proxyURL},
		{Name: "https_proxy", Value: proxyURL},
		{Name: "NO_PROXY", Value: "localhost,127.0.0.1,.svc,.cluster.local"},
		{Name: "no_proxy", Value: "localhost,127.0.0.1,.svc,.cluster.local"},
		{Name: "SSL_CERT_FILE", Value: caCertPath},
		{Name: "REQUESTS_CA_BUNDLE", Value: caCertPath},
		{Name: "NODE_EXTRA_CA_CERTS", Value: caCertPath},
		{Name: "CURL_CA_BUNDLE", Value: caCertPath},
	}

	caMount := VolumeMount{
		Name:      "service-portal-ca",
		MountPath: "/etc/service-portal/ca",
		ReadOnly:  true,
	}

	for i, c := range pod.Spec.Containers {
		if len(c.Env) == 0 {
			patches = append(patches, JSONPatchOp{
				Op:    "add",
				Path:  fmt.Sprintf("/spec/containers/%d/env", i),
				Value: envVarsToInject,
			})
		} else {
			for _, ev := range envVarsToInject {
				patches = append(patches, JSONPatchOp{
					Op:    "add",
					Path:  fmt.Sprintf("/spec/containers/%d/env/-", i),
					Value: ev,
				})
			}
		}

		if len(c.VolumeMounts) == 0 {
			patches = append(patches, JSONPatchOp{
				Op:    "add",
				Path:  fmt.Sprintf("/spec/containers/%d/volumeMounts", i),
				Value: []VolumeMount{caMount},
			})
		} else {
			patches = append(patches, JSONPatchOp{
				Op:    "add",
				Path:  fmt.Sprintf("/spec/containers/%d/volumeMounts/-", i),
				Value: caMount,
			})
		}
	}

	caVolume := Volume{
		Name: "service-portal-ca",
		Secret: &SecretVolume{
			SecretName: caSecretName,
		},
	}

	if len(pod.Spec.Volumes) == 0 {
		patches = append(patches, JSONPatchOp{
			Op:    "add",
			Path:  "/spec/volumes",
			Value: []Volume{caVolume},
		})
	} else {
		patches = append(patches, JSONPatchOp{
			Op:    "add",
			Path:  "/spec/volumes/-",
			Value: caVolume,
		})
	}

	return patches, true, nil
}

func handleMutate(w http.ResponseWriter, r *http.Request, proxyURL, caCertPath, caSecretName string) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Error reading request body: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var review AdmissionReview
	if err := json.Unmarshal(body, &review); err != nil {
		log.Printf("Error parsing AdmissionReview: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if review.Request == nil {
		http.Error(w, "missing admission request", http.StatusBadRequest)
		return
	}

	resp := &AdmissionResponse{
		UID:     review.Request.UID,
		Allowed: true,
	}

	patches, mutated, err := mutatePod(review.Request.Object, proxyURL, caCertPath, caSecretName)
	if err != nil {
		log.Printf("Mutation error: %v", err)
		resp.Allowed = false
	} else if mutated && len(patches) > 0 {
		patchBytes, err := json.Marshal(patches)
		if err != nil {
			log.Printf("Error marshaling patch: %v", err)
			resp.Allowed = false
		} else {
			resp.PatchType = "JSONPatch"
			resp.Patch = patchBytes
			log.Printf("Mutated pod in namespace %s: injected proxy env and CA mounts", review.Request.Namespace)
		}
	}

	outReview := AdmissionReview{
		APIVersion: review.APIVersion,
		Kind:       review.Kind,
		Response:   resp,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(outReview); err != nil {
		log.Printf("Error writing response: %v", err)
	}
}

func generateSelfSignedCert(serviceName, namespace string) ([]byte, []byte, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	dnsNames := []string{
		serviceName,
		fmt.Sprintf("%s.%s", serviceName, namespace),
		fmt.Sprintf("%s.%s.svc", serviceName, namespace),
		fmt.Sprintf("%s.%s.svc.cluster.local", serviceName, namespace),
		"localhost",
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   fmt.Sprintf("%s.%s.svc", serviceName, namespace),
			Organization: []string{"Service Portals"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              dnsNames,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})

	return certPEM, keyPEM, nil
}

func main() {
	port := flag.String("port", "8443", "Port for HTTPS admission webhook")
	proxyURL := flag.String("proxy-url", "http://service-portal:8080", "Proxy URL to inject")
	caCertPath := flag.String("ca-cert-path", "/etc/service-portal/ca/tls.crt", "CA certificate path to inject")
	caSecretName := flag.String("ca-secret-name", "service-portal-ca", "Name of CA Secret to mount")
	certFile := flag.String("tls-cert-file", "", "Path to TLS cert file")
	keyFile := flag.String("tls-key-file", "", "Path to TLS key file")
	serviceName := flag.String("service-name", "applevel-injector", "Webhook service name")
	namespace := flag.String("namespace", "default", "Webhook service namespace")
	writeCAPath := flag.String("write-ca-cert-to", "", "File path to write self-signed CA cert for caBundle")

	flag.Parse()

	if envProxy := os.Getenv("PROXY_URL"); envProxy != "" {
		*proxyURL = envProxy
	}
	if envNamespace := os.Getenv("POD_NAMESPACE"); envNamespace != "" {
		*namespace = envNamespace
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("ok")); err != nil {
			log.Printf("failed to write healthz response: %v", err)
		}
	})
	mux.HandleFunc("/mutate", func(w http.ResponseWriter, r *http.Request) {
		handleMutate(w, r, *proxyURL, *caCertPath, *caSecretName)
	})

	server := &http.Server{
		Addr:    ":" + *port,
		Handler: mux,
	}

	var tlsCert tls.Certificate
	if *certFile != "" && *keyFile != "" {
		c, err := tls.LoadX509KeyPair(*certFile, *keyFile)
		if err != nil {
			log.Fatalf("Failed to load TLS cert/key: %v", err)
		}
		tlsCert = c
	} else {
		certPEM, keyPEM, err := generateSelfSignedCert(*serviceName, *namespace)
		if err != nil {
			log.Fatalf("Failed to generate self-signed cert: %v", err)
		}
		c, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			log.Fatalf("Failed to parse generated TLS cert/key: %v", err)
		}
		tlsCert = c

		if *writeCAPath != "" {
			if err := os.WriteFile(*writeCAPath, certPEM, 0644); err != nil {
				log.Printf("Warning: failed to write CA cert to %s: %v", *writeCAPath, err)
			}
		}
	}

	server.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}

	log.Printf("Starting applevel-injector on :%s (proxy: %s)", *port, *proxyURL)
	if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server error: %v", err)
	}
}
