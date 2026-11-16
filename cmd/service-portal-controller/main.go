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
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gke-labs/service-portals/pkg/controller"
	portalsv1 "github.com/gke-labs/service-portals/pkg/portals/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"
)

// Config holds configuration parameters for the controller.
type Config struct {
	ListenAddr       string
	TLSCertFile      string
	TLSKeyFile       string
	Audience         string
	NodeAgentAccount string
	ClientAllowlist  []string
	Kubeconfig       string
	PushTimeout      time.Duration
}

func parseFlags(args []string) (Config, error) {
	fs := flag.NewFlagSet("service-portal-controller", flag.ContinueOnError)
	var cfg Config
	var clientAllowlist string

	fs.StringVar(&cfg.ListenAddr, "listen-address", ":8443", "Address and port to listen on")
	fs.StringVar(&cfg.TLSCertFile, "tls-cert-file", "", "Path to TLS server certificate file")
	fs.StringVar(&cfg.TLSKeyFile, "tls-key-file", "", "Path to TLS server private key file")
	fs.StringVar(&cfg.Audience, "audience", "", "TokenReview audience for the controller")
	fs.StringVar(&cfg.NodeAgentAccount, "node-agent-account", "", "Service account allowed for node agents")
	fs.StringVar(&clientAllowlist, "client-allowlist", "", "Comma-separated list of permitted client service accounts")
	fs.StringVar(&cfg.Kubeconfig, "kubeconfig", "", "Path to kubeconfig file (optional, uses in-cluster config if empty)")
	fs.DurationVar(&cfg.PushTimeout, "push-timeout", time.Minute, "Push timeout waiting for node acceptance")

	if err := fs.Parse(args); err != nil {
		return cfg, err
	}

	if clientAllowlist != "" {
		for _, sa := range strings.Split(clientAllowlist, ",") {
			if trimmed := strings.TrimSpace(sa); trimmed != "" {
				cfg.ClientAllowlist = append(cfg.ClientAllowlist, trimmed)
			}
		}
	}
	return cfg, nil
}

func run(ctx context.Context, cfg Config, kubeClient kubernetes.Interface, lis net.Listener) error {
	if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" {
		return errors.New("TLS certificate and key files are required")
	}
	tlsCert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
	if err != nil {
		return fmt.Errorf("loading TLS key pair: %w", err)
	}

	if cfg.Audience == "" {
		return errors.New("audience is required")
	}
	if cfg.NodeAgentAccount == "" {
		return errors.New("node agent service account is required")
	}
	if len(cfg.ClientAllowlist) == 0 {
		klog.Warning("client allowlist is empty; all client calls will be refused")
	}

	if kubeClient == nil {
		var restConfig *rest.Config
		if cfg.Kubeconfig != "" {
			restConfig, err = clientcmd.BuildConfigFromFlags("", cfg.Kubeconfig)
		} else {
			restConfig, err = rest.InClusterConfig()
		}
		if err != nil {
			return fmt.Errorf("kubernetes configuration error: %w", err)
		}
		kubeClient, err = kubernetes.NewForConfig(restConfig)
		if err != nil {
			return fmt.Errorf("creating kubernetes client: %w", err)
		}
	}

	if _, err := kubeClient.CoreV1().Pods("").List(ctx, metav1.ListOptions{Limit: 1}); err != nil {
		return fmt.Errorf("accessing Kubernetes API: %w", err)
	}

	auth, err := controller.NewAuthenticator(controller.AuthenticatorConfig{
		Audience:         cfg.Audience,
		NodeAgentAccount: cfg.NodeAgentAccount,
		ClientAllowlist:  cfg.ClientAllowlist,
		TokenReviews:     kubeClient.AuthenticationV1().TokenReviews(),
	})
	if err != nil {
		return fmt.Errorf("creating authenticator: %w", err)
	}

	var routingServer *controller.Server
	resolver, err := controller.NewNodeResolver(kubeClient, func(uid types.UID) {
		if routingServer != nil {
			routingServer.PodChanged(string(uid))
		}
	})
	if err != nil {
		return fmt.Errorf("creating node resolver: %w", err)
	}

	routingServer = controller.NewServer(controller.ServerConfig{
		Lookup:      resolver,
		Identity:    auth.AuthorizeNodeAgent,
		PushTimeout: cfg.PushTimeout,
	})

	ctrl, err := controller.NewController(auth, routingServer)
	if err != nil {
		return fmt.Errorf("creating controller: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS13,
	}
	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
	portalsv1.RegisterNodeStreamServiceServer(grpcServer, routingServer)
	portalsv1.RegisterPodBindServiceServer(grpcServer, ctrl)

	if lis == nil {
		listenAddr := cfg.ListenAddr
		if listenAddr == "" {
			listenAddr = ":8443"
		}
		lis, err = net.Listen("tcp", listenAddr)
		if err != nil {
			return fmt.Errorf("listening on %s: %w", listenAddr, err)
		}
		defer func() {
			if cErr := lis.Close(); cErr != nil && !errors.Is(cErr, net.ErrClosed) {
				klog.V(4).Infof("error closing listener: %v", cErr)
			}
		}()
	}

	go func() {
		if rErr := resolver.Run(ctx); rErr != nil && !errors.Is(rErr, context.Canceled) {
			klog.Errorf("node resolver error: %v", rErr)
		}
	}()

	go func() {
		<-ctx.Done()
		grpcServer.GracefulStop()
	}()

	klog.Infof("service-portal-controller serving TLS on %s", lis.Addr())
	if err := grpcServer.Serve(lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		return fmt.Errorf("grpc serve: %w", err)
	}
	return nil
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	cfg, err := parseFlags(os.Args[1:])
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		klog.Fatalf("invalid configuration: %v", err)
	}

	if err := run(ctx, cfg, nil, nil); err != nil {
		klog.Fatalf("controller failed: %v", err)
	}
}
