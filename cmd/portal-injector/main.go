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
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/gke-labs/service-portals/pkg/injector"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

func main() {
	listenAddr := flag.String("listen-addr", ":8443", "Address to listen on for webhook requests")
	tlsCertFile := flag.String("tls-cert-file", "/etc/webhook/certs/tls.crt", "Path to TLS certificate file")
	tlsKeyFile := flag.String("tls-key-file", "/etc/webhook/certs/tls.key", "Path to TLS private key file")
	nativeSidecars := flag.Bool("native-sidecars", true, "Use native sidecar containers (k8s >= 1.29)")
	defaultInitImage := flag.String("default-init-image", "init-service-portals:latest", "Default init container image")
	defaultProxyImage := flag.String("default-proxy-image", "all-in-one-portal:latest", "Default proxy sidecar image")
	dummyIP := flag.String("dummy-ip", "8.8.8.8", "Dummy IP used for hostAliases")

	var kubeconfig *string
	if home := homedir.HomeDir(); home != "" {
		kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
	} else {
		kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
	}
	flag.Parse()

	config, err := rest.InClusterConfig()
	if err != nil {
		if kcfg := os.Getenv("KUBECONFIG"); kcfg != "" {
			config, err = clientcmd.BuildConfigFromFlags("", kcfg)
		} else if *kubeconfig != "" {
			config, err = clientcmd.BuildConfigFromFlags("", *kubeconfig)
		}
		if err != nil {
			log.Fatalf("Failed to create kubernetes config: %v", err)
		}
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("Failed to create kubernetes clientset: %v", err)
	}

	dynClient, err := dynamic.NewForConfig(config)
	if err != nil {
		log.Fatalf("Failed to create dynamic client: %v", err)
	}

	inj := &injector.Injector{
		Policies:   &injector.DynamicPolicyLister{Client: dynClient},
		Namespaces: &injector.KubeNamespaceGetter{Client: clientset},
		Secrets:    &injector.KubeSecretManager{Client: clientset},
		Config: injector.Config{
			NativeSidecars:    *nativeSidecars,
			DefaultInitImage:  *defaultInitImage,
			DefaultProxyImage: *defaultProxyImage,
			DummyIP:           *dummyIP,
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/mutate", inj.HandleMutate)
	mux.HandleFunc("/validate", inj.HandleValidate)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("OK")); err != nil {
			log.Printf("Failed to write healthz response: %v", err)
		}
	})

	server := &http.Server{
		Addr:              *listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		log.Printf("Starting portal-injector on %s", *listenAddr)
		if err := server.ListenAndServeTLS(*tlsCertFile, *tlsKeyFile); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server failed: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("Shutting down portal-injector server...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("Server shutdown error: %v", err)
	}
	log.Println("Server gracefully stopped")
}
