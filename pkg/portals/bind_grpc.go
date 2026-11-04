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
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	portalsv1 "github.com/gke-labs/service-portals/pkg/portals/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"k8s.io/klog/v2"
)

// Dedicated CA vs Cluster CA:
// The controller-facing Bind API requires client certificates for mTLS authentication.
// A dedicated CA (e.g. provisioned via a dedicated Secret or cert-manager) is strongly
// preferred over the cluster CA for two reasons:
// 1. Cryptographic domain separation: Trusting the cluster CA
//    (/var/run/secrets/kubernetes.io/serviceaccount/ca.crt) would allow any in-cluster
//    identity possessing a cluster-CA-signed cert (e.g. kubelets, control plane nodes,
//    or identities issued certs via the Kubernetes CSR API) to complete the TLS
//    handshake to node agents. A dedicated CA ensures only components explicitly
//    issued Bind API client certificates can establish a TLS session.
// 2. Lifecycle and rotation: The cluster CA has a cluster-wide lifecycle and rotation
//    schedule tied to the Kubernetes control plane. A dedicated CA decouples node-agent
//    mTLS credential rotation from control-plane certificate management.

// PodBindServer implements portalsv1.PodBindServiceServer over authenticated gRPC.
type PodBindServer struct {
	portalsv1.UnimplementedPodBindServiceServer
	podMap         *PodMap
	allowedCallers map[string]bool
}

// NewPodBindServer constructs a PodBindServer backed by a PodMap and an allowlist of controller identities.
func NewPodBindServer(pm *PodMap, allowedCallers []string) *PodBindServer {
	allowlist := make(map[string]bool, len(allowedCallers))
	for _, c := range allowedCallers {
		if trimmed := strings.TrimSpace(c); trimmed != "" {
			allowlist[trimmed] = true
		}
	}
	return &PodBindServer{
		podMap:         pm,
		allowedCallers: allowlist,
	}
}

// Bind assigns user identity and policy to a pod by UID.
func (s *PodBindServer) Bind(ctx context.Context, req *portalsv1.BindRequest) (*portalsv1.BindResponse, error) {
	if req.GetPodUid() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "pod_uid is required")
	}
	if err := s.podMap.Bind(req.GetPodUid(), req.GetIdentity(), req.GetPolicy()); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to bind pod: %v", err)
	}
	return &portalsv1.BindResponse{
		PodUid: req.GetPodUid(),
		Bound:  true,
	}, nil
}

// Unbind revokes identity and policy from a pod, returning it to fail-closed state.
func (s *PodBindServer) Unbind(ctx context.Context, req *portalsv1.UnbindRequest) (*portalsv1.UnbindResponse, error) {
	if req.GetPodUid() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "pod_uid is required")
	}
	if err := s.podMap.Unbind(req.GetPodUid()); err != nil {
		return nil, status.Errorf(codes.NotFound, "%v", err)
	}
	return &portalsv1.UnbindResponse{
		PodUid: req.GetPodUid(),
		Bound:  false,
	}, nil
}

// Get retrieves current identity, policy, and network status for a pod by UID.
func (s *PodBindServer) Get(ctx context.Context, req *portalsv1.GetRequest) (*portalsv1.GetResponse, error) {
	if req.GetPodUid() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "pod_uid is required")
	}
	pod, ok := s.podMap.GetPodByUID(req.GetPodUid())
	if !ok {
		return nil, status.Errorf(codes.NotFound, "pod UID %q not found", req.GetPodUid())
	}
	return &portalsv1.GetResponse{
		PodUid:    pod.UID,
		Namespace: pod.Namespace,
		Name:      pod.Name,
		Ips:       pod.IPs,
		Identity:  pod.Identity,
		Policy:    pod.Policy,
		Bound:     pod.Bound,
	}, nil
}

// UnaryServerInterceptor returns an interceptor that authenticates callers via mTLS and enforces the allowlist.
func (s *PodBindServer) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if _, err := s.authorize(ctx); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

func (s *PodBindServer) authorize(ctx context.Context) (string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok || p.AuthInfo == nil {
		klog.Errorf("rejecting unauthenticated bind call: no peer auth info")
		return "", status.Errorf(codes.Unauthenticated, "unauthenticated: transport security is required")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(tlsInfo.State.VerifiedChains) == 0 || len(tlsInfo.State.VerifiedChains[0]) == 0 {
		klog.Errorf("rejecting unauthenticated bind call: no verified client certificate")
		return "", status.Errorf(codes.Unauthenticated, "unauthenticated: verified client certificate is required")
	}

	clientCert := tlsInfo.State.VerifiedChains[0][0]
	caller, authorized := s.isCallerAuthorized(clientCert)
	if !authorized {
		klog.Errorf("rejecting unauthorized bind caller %q (subject: %s, SANs: %v)", caller, clientCert.Subject, clientCert.DNSNames)
		return "", status.Errorf(codes.PermissionDenied, "caller %q is not authorized", caller)
	}
	return caller, nil
}

func (s *PodBindServer) isCallerAuthorized(cert *x509.Certificate) (string, bool) {
	if cert == nil {
		return "", false
	}
	var identities []string
	if cert.Subject.CommonName != "" {
		identities = append(identities, cert.Subject.CommonName)
	}
	for _, san := range cert.DNSNames {
		identities = append(identities, san)
	}
	for _, uri := range cert.URIs {
		identities = append(identities, uri.String())
	}

	primary := cert.Subject.CommonName
	if primary == "" && len(identities) > 0 {
		primary = identities[0]
	}

	if len(s.allowedCallers) == 0 {
		return primary, false
	}

	for _, id := range identities {
		if s.allowedCallers[id] || s.allowedCallers["*"] {
			return id, true
		}
	}
	return primary, false
}

// LoadServerMTLSConfig loads server certificate, private key, and client CA certificate pool.
func LoadServerMTLSConfig(certFile, keyFile, clientCAFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load server certificate key pair (%s, %s): %w", certFile, keyFile, err)
	}
	caData, err := os.ReadFile(clientCAFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read client CA certificate %s: %w", clientCAFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caData) {
		return nil, fmt.Errorf("failed to parse client CA certificates from %s", clientCAFile)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// NewGRPCServer creates and configures a grpc.Server serving PodBindService with mTLS and caller authorization.
func NewGRPCServer(pm *PodMap, allowedCallers []string, tlsConfig *tls.Config) (*grpc.Server, error) {
	if tlsConfig == nil {
		return nil, fmt.Errorf("tlsConfig is required: mTLS must be enforced for controller-facing bind API")
	}
	tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	creds := credentials.NewTLS(tlsConfig)
	bindServer := NewPodBindServer(pm, allowedCallers)
	grpcServer := grpc.NewServer(
		grpc.Creds(creds),
		grpc.UnaryInterceptor(bindServer.UnaryServerInterceptor()),
	)
	portalsv1.RegisterPodBindServiceServer(grpcServer, bindServer)
	return grpcServer, nil
}
