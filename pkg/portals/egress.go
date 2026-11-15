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
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"

	portalsv1 "github.com/gke-labs/service-portals/pkg/portals/v1"
	"github.com/gke-labs/service-portals/pkg/proxy"
)

var _ CertificateProvider = (*EgressHandler)(nil)

// EgressHandler decides intercepted requests against the caller pod's bound egress policy.
type EgressHandler struct {
	podMap    *PodMap
	store     *portalsv1.BindingStore
	transport http.RoundTripper
	signer    *proxy.CertSigner
}

// NewEgressHandler creates an EgressHandler that resolves caller pods via podMap,
// looks up egress policies and secrets in store, signs TLS certificates via signer,
// and forwards allowed traffic via transport.
func NewEgressHandler(podMap *PodMap, store *portalsv1.BindingStore, transport http.RoundTripper, signer *proxy.CertSigner) *EgressHandler {
	return &EgressHandler{
		podMap:    podMap,
		store:     store,
		transport: transport,
		signer:    signer,
	}
}

// GetCertificate implements CertificateProvider to answer TLS handshakes with
// certificates signed by the pod-local CA when allowed by the caller pod's egress policy.
func (h *EgressHandler) GetCertificate(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if info == nil {
		return nil, errors.New("missing client hello info")
	}
	var remoteAddr string
	if info.Conn != nil && info.Conn.RemoteAddr() != nil {
		remoteAddr = info.Conn.RemoteAddr().String()
	}

	pod, policy, err := h.resolveCaller(remoteAddr)
	if err != nil {
		return nil, err
	}

	host := strings.TrimSpace(info.ServerName)
	if host == "" {
		return nil, errors.New("missing server name in TLS handshake")
	}
	host = proxy.HostWithoutPort(host)
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" {
		return nil, errors.New("missing server name in TLS handshake")
	}

	if !policy.CouldMatch(portalsv1.ProtocolHTTPS, host) {
		return nil, fmt.Errorf("access denied for caller %s: host %q not permitted by egress policy", podCaller(pod), host)
	}

	if h.signer == nil {
		return nil, errors.New("no CA configured to sign certificate")
	}

	return h.signer.GetCertificate(info)
}

// ServeHTTP decides an intercepted request from the caller pod's bound policy.
func (h *EgressHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		http.Error(w, "CONNECT not allowed", http.StatusMethodNotAllowed)
		return
	}

	pod, policy, err := h.resolveCaller(r.RemoteAddr)
	if err != nil {
		remoteIP := clientIP(r.RemoteAddr)
		if pod == nil {
			log.Printf("Request: %s %s | Caller: unknown (%s) | Action: denied", r.Method, r.Host, remoteIP)
			http.Error(w, "Access Denied: unknown caller", http.StatusForbidden)
		} else {
			caller := podCaller(pod)
			log.Printf("Request: %s %s | Caller: %s (%s) | State: unbound | Action: denied", r.Method, r.Host, caller, remoteIP)
			http.Error(w, "Access Denied: unbound pod", http.StatusForbidden)
		}
		return
	}

	caller := podCaller(pod)

	targetHost, port, err := requestTarget(r)
	if err != nil {
		log.Printf("Request: %s %q | Caller: %s | Action: denied (invalid destination: %v)", r.Method, r.Host, caller, err)
		http.Error(w, "Access Denied: invalid destination host or port", http.StatusForbidden)
		return
	}

	proto := portalsv1.ProtocolHTTP
	if r.TLS != nil {
		proto = portalsv1.ProtocolHTTPS
	}

	rule := policy.Match(proto, targetHost, port)
	if rule == nil {
		log.Printf("Request: %s %s:%d (proto: %s) | Caller: %s | Action: denied (no matching rule)", r.Method, targetHost, port, proto, caller)
		http.Error(w, "Access Denied: request not allowed by egress policy", http.StatusForbidden)
		return
	}

	outReq := r.Clone(r.Context())
	outReq.RequestURI = ""
	outReq.URL.Scheme = string(proto)
	outReq.URL.Host = net.JoinHostPort(targetHost, strconv.Itoa(int(port)))
	outReq.Host = r.Host

	err = rule.ApplyEffects(outReq.Header, func(name string) ([]byte, error) {
		sec, ok := h.store.ResolveSecret(pod.UID, name)
		if !ok {
			return nil, fmt.Errorf("secret %q not found", name)
		}
		return sec.Bytes(), nil
	})
	if err != nil {
		log.Printf("Request: %s %s:%d | Caller: %s | Action: denied (effects error: %v)", r.Method, targetHost, port, caller, err)
		http.Error(w, "Access Denied: error applying egress effects", http.StatusForbidden)
		return
	}

	log.Printf("Request: %s %s:%d | Caller: %s | Action: proxy", r.Method, targetHost, port, caller)
	proxy.Forward(w, outReq, h.transport)
}

func (h *EgressHandler) resolveCaller(remoteAddr string) (*PodInfo, *portalsv1.EgressPolicy, error) {
	remoteIP := clientIP(remoteAddr)
	pod, err := h.lookupCaller(remoteIP)
	if err != nil {
		return nil, nil, fmt.Errorf("unknown caller (%s)", remoteIP)
	}

	var policy *portalsv1.EgressPolicy
	if h.store != nil {
		policy = h.store.Policy(pod.UID)
	}
	if policy == nil {
		return pod, nil, fmt.Errorf("unbound pod (%s)", pod.UID)
	}
	return pod, policy, nil
}

func clientIP(remoteAddr string) string {
	ip := proxy.HostWithoutPort(remoteAddr)
	if strings.HasPrefix(ip, "[") && strings.HasSuffix(ip, "]") {
		return ip[1 : len(ip)-1]
	}
	return ip
}

func (h *EgressHandler) lookupCaller(ip string) (*PodInfo, error) {
	if h.podMap == nil {
		return nil, errors.New("no pod map")
	}
	pod, ok := h.podMap.GetPodByIP(ip)
	if !ok || pod == nil || pod.UID == "" {
		return nil, errors.New("pod not found")
	}
	return pod, nil
}

func podCaller(pod *PodInfo) string {
	if pod.Namespace != "" && pod.Name != "" {
		return pod.Namespace + "/" + pod.Name
	}
	return pod.UID
}

func requestTarget(r *http.Request) (string, int32, error) {
	if r.Host == "" {
		return "", 0, errors.New("missing host")
	}
	var hostname string
	var port int32
	if hStr, pStr, err := net.SplitHostPort(r.Host); err == nil {
		p, err := strconv.ParseUint(pStr, 10, 16)
		if err != nil || p == 0 {
			return "", 0, errors.New("invalid port")
		}
		hostname, port = hStr, int32(p)
	} else {
		hostname = r.Host
		if strings.HasPrefix(hostname, "[") && strings.HasSuffix(hostname, "]") {
			hostname = hostname[1 : len(hostname)-1]
		}
		if strings.Contains(hostname, ":") && net.ParseIP(hostname) == nil {
			return "", 0, errors.New("invalid host")
		}
		if r.TLS != nil {
			port = 443
		} else {
			port = 80
		}
	}
	hostname = strings.ToLower(strings.TrimSuffix(hostname, "."))
	if hostname == "" {
		return "", 0, errors.New("empty host")
	}
	return hostname, port, nil
}
