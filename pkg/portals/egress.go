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
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gke-labs/service-portals/pkg/dns"
	portalsv1 "github.com/gke-labs/service-portals/pkg/portals/v1"
	"github.com/gke-labs/service-portals/pkg/proxy"
	"github.com/gke-labs/service-portals/pkg/scoped"
	"golang.org/x/net/dns/dnsmessage"
)

var _ CertificateProvider = (*EgressHandler)(nil)
var _ dns.QueryEvaluator = (*EgressHandler)(nil)

// EgressHandler decides intercepted requests against the caller pod's bound egress policy.
type EgressHandler struct {
	podMap        *PodMap
	store         *portalsv1.BindingStore
	transport     http.RoundTripper
	signer        *proxy.CertSigner
	searchDomains []string // all entries from /etc/resolv.conf search line
	clusterDomain string   // cluster domain parsed from <namespace>.svc.<domain>
	podSearchRest string   // search suffix after namespace from entry 0, e.g. "svc.cluster.local"
	deduper       *refusalDeduper
}

// NewEgressHandler creates an EgressHandler that resolves caller pods via podMap,
// looks up egress policies and secrets in store, signs TLS certificates via signer,
// and forwards allowed traffic via transport.
func NewEgressHandler(podMap *PodMap, store *portalsv1.BindingStore, transport http.RoundTripper, signer *proxy.CertSigner) *EgressHandler {
	searches, clusterDomain, podSearchRest := parseResolvConf("/etc/resolv.conf")
	if podSearchRest == "" {
		log.Printf("Warning: /etc/resolv.conf search line has no cluster search entry (<namespace>.svc.<domain>); short in-cluster names will be refused")
	}
	return &EgressHandler{
		podMap:        podMap,
		store:         store,
		transport:     transport,
		signer:        signer,
		searchDomains: searches,
		clusterDomain: clusterDomain,
		podSearchRest: podSearchRest,
		deduper:       newRefusalDeduper(defaultMaxRefusalItems, defaultRefusalWindow),
	}
}

// parseResolvConf extracts the search list from a resolv.conf file and parses
// the cluster domain and per-pod search suffix.
//
// In Kubernetes (pkg/kubelet/network/dns/dns.go: (*Configurer).generateSearchesForDNSClusterFirst),
// kubelet generates the search list for ClusterFirst and ClusterFirstWithHostNet pods as:
//
//	[0]: <namespace>.svc.<clusterDomain>
//	[1]: svc.<clusterDomain>
//	[2]: <clusterDomain>
//	followed by the node's search domains.
//
// Because the node agent runs with dnsPolicy: ClusterFirstWithHostNet in its own namespace,
// entry 0 is <agentNamespace>.svc.<clusterDomain>. The cluster domain is extracted from
// entry 0, and the remainder after the namespace ("svc.<clusterDomain>") is saved to complete
// short in-cluster names for calling pods without hard-coding ".svc" or "cluster.local".
// If the search line contains no entry of the form <namespace>.svc.<domain>, no fallback
// is applied and short in-cluster names fail closed.
func parseResolvConf(path string) (searches []string, clusterDomain, podSearchRest string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 1 && fields[0] == "search" {
			searches = fields[1:]
			break
		}
	}
	if len(searches) == 0 {
		return nil, "", ""
	}

	parts := strings.Split(searches[0], ".")
	if len(parts) >= 3 && parts[1] == "svc" {
		clusterDomain = strings.Join(parts[2:], ".")
		podSearchRest = strings.Join(parts[1:], ".")
	}
	return searches, clusterDomain, podSearchRest
}

// resolveUpstreamHost completes short or partly qualified in-cluster names with
// the calling pod's namespace and the cluster's search path, not the node agent's.
// Fully qualified and external names are unaffected.
//
// In Kubernetes (pkg/kubelet/network/dns/dns.go: (*Configurer).generateSearchesForDNSClusterFirst),
// kubelet generates the search list for ClusterFirst and ClusterFirstWithHostNet pods as:
//
//	<namespace>.svc.<clusterDomain>, svc.<clusterDomain>, <clusterDomain>, then host searches.
//
// Because the node agent runs with dnsPolicy: ClusterFirstWithHostNet, its own /etc/resolv.conf
// search list matches the calling pod's search list with only the namespace in the first entry
// differing. The suffix for a calling pod is derived by replacing the node agent's namespace in
// the first search entry with the calling pod's namespace.
//
// For single-label names (e.g. "backend"), only the calling pod's own namespace
// is tried: the rest of a pod's search path (and any node search domains) is
// deliberately not emulated, so a single-label name that is not a Service in the
// pod's namespace is refused. If the node agent's resolv.conf has no cluster search
// entry (<namespace>.svc.<domain>), single-label names are refused (fail closed).
//
// For TLS (https) upstreams reached by short name, setting outReq.URL.Host to the
// completed name means upstream TLS certificate verification validates against
// <name>.<namespace>.svc.<clusterDomain>, not <name>; the Host header the upstream
// sees is still what the pod sent. Keying outReq.URL.Host by the completed name
// ensures pooled connections are isolated per namespace and cannot be reused
// across pods in different namespaces.
func (h *EgressHandler) resolveUpstreamHost(targetHost string, pod *PodInfo) (string, error) {
	host := proxy.HostWithoutPort(targetHost)
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" {
		return "", errors.New("empty host")
	}
	if net.ParseIP(host) != nil || host == "localhost" {
		return host, nil
	}

	if h.clusterDomain != "" {
		clusterSuffix := "." + h.clusterDomain
		if strings.HasSuffix(host, clusterSuffix) {
			return host, nil
		}
		if strings.HasSuffix(host, ".svc") {
			return host + clusterSuffix, nil
		}
	}

	if !strings.Contains(host, ".") {
		if pod == nil || pod.Namespace == "" {
			return "", errors.New("cannot resolve short name for caller: pod namespace unknown")
		}
		if h.podSearchRest == "" {
			return "", errors.New("cannot resolve short in-cluster name: no cluster search domain found in resolv.conf")
		}
		return host + "." + pod.Namespace + "." + h.podSearchRest, nil
	}

	return host, nil
}

// GetCertificate implements CertificateProvider to answer TLS handshakes with
// certificates signed by the pod-local CA when allowed by the caller pod's egress policy.
func (h *EgressHandler) GetCertificate(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if info == nil {
		return nil, errors.New("missing client hello info")
	}
	var clientAddr net.Addr
	if info.Conn != nil {
		clientAddr = info.Conn.RemoteAddr()
	}

	host := strings.TrimSpace(info.ServerName)
	cleanHost := strings.ToLower(strings.TrimSuffix(proxy.HostWithoutPort(host), "."))

	decision, pod, _ := h.evaluateHTTP(clientAddr, portalsv1.ProtocolHTTPS, cleanHost)
	switch decision {
	case httpDecisionHold:
		caller := podCaller(pod)
		remoteIP := clientIP(clientAddr)
		log.Printf("TLS handshake | Caller: %s (%s) | State: unbound | Action: drop", caller, remoteIP)
		dns.HoldConnection(info.Context(), info.Conn)
		return nil, fmt.Errorf("unbound pod (%s)", pod.UID)
	case httpDecisionRefuseUnknown:
		return nil, fmt.Errorf("unknown caller (%s)", clientIP(clientAddr))
	case httpDecisionRefuse:
		if cleanHost == "" {
			return nil, errors.New("missing server name in TLS handshake")
		}
		return nil, fmt.Errorf("access denied for caller %s: host %q not permitted by egress policy", podCaller(pod), cleanHost)
	case httpDecisionAllow:
		if h.signer == nil {
			return nil, errors.New("no CA configured to sign certificate")
		}
		return h.signer.GetCertificate(info)
	default:
		return nil, errors.New("access denied")
	}
}

const (
	defaultRefusalWindow   = 10 * time.Second
	defaultMaxRefusalItems = 1000
)

type refusalKey struct {
	caller string // pod UID or client IP
	name   string // normalized query host
	reason string // refusal reason
}

type refusalEntry struct {
	windowStart time.Time
	count       int
}

type refusalDeduper struct {
	mu       sync.Mutex
	capacity int
	window   time.Duration
	entries  map[refusalKey]refusalEntry
	now      func() time.Time
}

func newRefusalDeduper(capacity int, window time.Duration) *refusalDeduper {
	return &refusalDeduper{
		capacity: capacity,
		window:   window,
		entries:  make(map[refusalKey]refusalEntry),
		now:      time.Now,
	}
}

// record tracks a refusal for key. It returns whether the refusal should be logged
// and how many identical refusals were suppressed in the previous window.
// The suppressed count is reported on the next line for that key, so if the pod
// stops asking it is never reported. The first occurrence for a key is always logged.
func (d *refusalDeduper) record(key refusalKey) (bool, int) {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := d.now()

	if entry, ok := d.entries[key]; ok {
		if now.Sub(entry.windowStart) >= d.window {
			repeated := entry.count - 1
			d.entries[key] = refusalEntry{windowStart: now, count: 1}
			return true, repeated
		}
		entry.count++
		d.entries[key] = entry
		return false, 0
	}

	if len(d.entries) >= d.capacity {
		for k, e := range d.entries {
			if now.Sub(e.windowStart) >= d.window {
				delete(d.entries, k)
			}
		}
		if len(d.entries) >= d.capacity {
			clear(d.entries)
		}
	}
	d.entries[key] = refusalEntry{windowStart: now, count: 1}
	return true, 0
}

// isSearchExpansion reports whether host is an unlisted name produced by kubelet's ndots:5
// search-domain expansion of a base name that the pod's policy actually permits.
// It tests whether stripping one of the caller pod's expected search suffixes:
//  1. the pod's own first search entry (<namespace>.svc.<clusterDomain>),
//  2. the remaining search entries from the agent's /etc/resolv.conf (e.g. svc.<clusterDomain>),
//  3. the cluster domain itself (<clusterDomain>),
//
// produces a base name permitted by the policy.
// If stripping a valid search suffix yields a permitted base name, the refusal is expected
// resolver noise under ndots:5 and is logged at V(1).
// Real mismatches—where the base name is not in policy, or where the pod asks for an allowed
// short name qualified in a different namespace (e.g. backend.other-ns.svc.cluster.local)—do
// not match an allowed base name and remain logged at V(0).
func (h *EgressHandler) isSearchExpansion(pod *PodInfo, policy *portalsv1.EgressPolicy, host string) bool {
	if policy == nil {
		return false
	}
	cleanHost := strings.Trim(strings.ToLower(proxy.HostWithoutPort(host)), ".")
	check := func(sd string) bool {
		sd = strings.Trim(sd, ".")
		if sd != "" && strings.HasSuffix(cleanHost, "."+sd) {
			base := strings.TrimSuffix(cleanHost, "."+sd)
			return base != "" && (policy.CouldMatch(portalsv1.ProtocolHTTP, base) || policy.CouldMatch(portalsv1.ProtocolHTTPS, base))
		}
		return false
	}
	if pod != nil && pod.Namespace != "" && h.podSearchRest != "" {
		if check(pod.Namespace + "." + h.podSearchRest) {
			return true
		}
	}
	start := 0
	if h.podSearchRest != "" && len(h.searchDomains) > 0 {
		start = 1
	}
	for _, sd := range h.searchDomains[start:] {
		if check(sd) {
			return true
		}
	}
	return h.clusterDomain != "" && check(h.clusterDomain)
}

type httpDecision int

const (
	httpDecisionAllow httpDecision = iota
	httpDecisionHold
	httpDecisionRefuse
	httpDecisionRefuseUnknown
)

// evaluateHTTP decides what the proxy does with a caller and host for proto.
func (h *EgressHandler) evaluateHTTP(clientAddr net.Addr, proto portalsv1.Protocol, host string) (httpDecision, *PodInfo, *portalsv1.EgressPolicy) {
	pod, policy, err := h.resolveCaller(clientAddr)
	if err != nil {
		if pod == nil {
			return httpDecisionRefuseUnknown, nil, nil
		}
		return httpDecisionHold, pod, nil
	}

	cleanHost := proxy.HostWithoutPort(host)
	cleanHost = strings.TrimSuffix(strings.ToLower(cleanHost), ".")
	if cleanHost != "" && policy.CouldMatch(proto, cleanHost) {
		return httpDecisionAllow, pod, policy
	}

	return httpDecisionRefuse, pod, policy
}

// EvaluateQuery evaluates a DNS query for the caller at clientAddr in a single decision step,
// logging refused and dropped queries with source address, pod identity, query name, and reason.
func (h *EgressHandler) EvaluateQuery(ctx context.Context, host string, qtype dnsmessage.Type, clientAddr net.Addr) dns.QueryDecision {
	decision, pod, policy := h.evaluateHTTP(clientAddr, portalsv1.ProtocolHTTP, host)
	if decision == httpDecisionRefuse {
		decision, pod, policy = h.evaluateHTTP(clientAddr, portalsv1.ProtocolHTTPS, host)
	}

	switch decision {
	case httpDecisionAllow:
		logger := scoped.Log(ctx)
		if logger.V(1).Enabled() {
			h.logDNSQuery(ctx, "dns query answered", host, qtype, clientAddr, pod, policy, "allowed by policy", "answered")
		}
		return dns.DecisionAllow
	case httpDecisionHold:
		h.logDNSQuery(ctx, "dns query refused or dropped", host, qtype, clientAddr, pod, policy, "pod has no policy", "dropped")
		return dns.DecisionDrop
	case httpDecisionRefuseUnknown:
		// Where DNS genuinely differs: an unidentified caller is dropped for DNS but refused for HTTP.
		h.logDNSQuery(ctx, "dns query refused or dropped", host, qtype, clientAddr, pod, policy, "unknown caller", "dropped")
		return dns.DecisionDrop
	case httpDecisionRefuse:
		h.logDNSQuery(ctx, "dns query refused or dropped", host, qtype, clientAddr, pod, policy, "name not in policy", "NXDOMAIN")
		return dns.DecisionNXDomain
	default:
		return dns.DecisionDrop
	}
}

func (h *EgressHandler) logDNSQuery(ctx context.Context, msg, host string, qtype dnsmessage.Type, clientAddr net.Addr, pod *PodInfo, policy *portalsv1.EgressPolicy, reason, action string) {
	logger := scoped.Log(ctx)
	if h.isSearchExpansion(pod, policy, host) {
		logger = logger.V(1)
	}
	if !logger.Enabled() {
		return
	}

	podKey := ""
	if pod != nil {
		podKey = pod.UID
	} else if clientAddr != nil {
		podKey = clientIP(clientAddr)
	}

	cleanHost := strings.Trim(strings.ToLower(proxy.HostWithoutPort(host)), ".")
	shouldLog, repeated := h.deduper.record(refusalKey{
		caller: podKey,
		name:   cleanHost,
		reason: reason,
	})
	if !shouldLog {
		return
	}

	src := ""
	if clientAddr != nil {
		src = clientAddr.String()
	}
	args := []any{
		"source", src,
	}
	if pod != nil {
		args = append(args, "pod", podCaller(pod), "podUID", pod.UID)
	}
	args = append(args,
		"name", host,
		"type", strings.TrimPrefix(qtype.String(), "Type"),
		"reason", reason,
		"action", action,
	)
	if repeated > 0 {
		args = append(args, "repeated", repeated)
	}
	logger.Info(msg, args...)
}

// ServeHTTP decides an intercepted request from the caller pod's bound policy.
func (h *EgressHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		http.Error(w, "CONNECT not allowed", http.StatusMethodNotAllowed)
		return
	}

	clientAddr := parseRemoteAddr(r.RemoteAddr)
	proto := portalsv1.ProtocolHTTP
	if r.TLS != nil {
		proto = portalsv1.ProtocolHTTPS
	}

	decision, pod, policy := h.evaluateHTTP(clientAddr, proto, r.Host)
	remoteIP := clientIP(clientAddr)

	switch decision {
	case httpDecisionRefuseUnknown:
		log.Printf("Request: %s %s | Caller: unknown (%s) | Action: denied", r.Method, r.Host, remoteIP)
		http.Error(w, "Access Denied: unknown caller", http.StatusForbidden)
		return
	case httpDecisionHold:
		caller := podCaller(pod)
		log.Printf("Request: %s %s | Caller: %s (%s) | State: unbound | Action: drop", r.Method, r.Host, caller, remoteIP)
		// Hold the request with no response until the client's connection closes
		// or the request is cancelled, so an unbound pod sees a timeout and retries
		// rather than receiving a 403. By the time ServeHTTP returns, the client has
		// gone, so no response is written.
		if ctx := r.Context(); ctx != nil && ctx.Done() != nil {
			<-ctx.Done()
		}
		return
	case httpDecisionRefuse:
		caller := podCaller(pod)
		targetHost, port, err := requestTarget(r)
		if err != nil {
			log.Printf("Request: %s %q | Caller: %s | Action: denied (invalid destination: %v)", r.Method, r.Host, caller, err)
			http.Error(w, "Access Denied: invalid destination host or port", http.StatusForbidden)
			return
		}
		log.Printf("Request: %s %s:%d (proto: %s) | Caller: %s | Action: denied (no matching rule)", r.Method, targetHost, port, proto, caller)
		http.Error(w, "Access Denied: request not allowed by egress policy", http.StatusForbidden)
		return
	case httpDecisionAllow:
	}

	caller := podCaller(pod)

	targetHost, port, err := requestTarget(r)
	if err != nil {
		log.Printf("Request: %s %q | Caller: %s | Action: denied (invalid destination: %v)", r.Method, r.Host, caller, err)
		http.Error(w, "Access Denied: invalid destination host or port", http.StatusForbidden)
		return
	}

	rule := policy.Match(proto, targetHost, port)
	if rule == nil {
		log.Printf("Request: %s %s:%d (proto: %s) | Caller: %s | Action: denied (no matching rule)", r.Method, targetHost, port, proto, caller)
		http.Error(w, "Access Denied: request not allowed by egress policy", http.StatusForbidden)
		return
	}

	var dialScheme, dialHost string
	backendURL, err := rule.BackendURL()
	if err != nil {
		log.Printf("Request: %s %s:%d | Caller: %s | Action: denied (invalid backend URL: %v)", r.Method, targetHost, port, caller, err)
		http.Error(w, "Access Denied: invalid backend URL", http.StatusForbidden)
		return
	}
	if backendURL != nil {
		dialScheme = backendURL.Scheme
		dialHost = backendURL.Host
	} else {
		resolvedHost, err := h.resolveUpstreamHost(targetHost, pod)
		if err != nil {
			log.Printf("Request: %s %s:%d | Caller: %s | Action: denied (resolve error: %v)", r.Method, targetHost, port, caller, err)
			http.Error(w, "Access Denied: cannot resolve host for caller", http.StatusForbidden)
			return
		}
		dialScheme = string(proto)
		dialHost = net.JoinHostPort(resolvedHost, strconv.Itoa(int(port)))
	}

	outReq := r.Clone(r.Context())
	outReq.RequestURI = ""
	outReq.URL.Scheme = dialScheme
	outReq.URL.Host = dialHost
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

	if backendURL != nil {
		log.Printf("Request: %s %s:%d | Caller: %s | Action: proxy (backend: %s://%s)", r.Method, targetHost, port, caller, dialScheme, dialHost)
	} else {
		log.Printf("Request: %s %s:%d | Caller: %s | Action: proxy", r.Method, targetHost, port, caller)
	}
	proxy.Forward(w, outReq, h.transport)
}

func (h *EgressHandler) resolveCaller(addr net.Addr) (*PodInfo, *portalsv1.EgressPolicy, error) {
	remoteIP := clientIP(addr)
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

func parseRemoteAddr(remoteAddr string) net.Addr {
	ap, err := netip.ParseAddrPort(remoteAddr)
	if err != nil {
		return nil
	}
	return net.TCPAddrFromAddrPort(ap)
}

func clientIP(addr net.Addr) string {
	if a, ok := addr.(interface{ AddrPort() netip.AddrPort }); ok {
		ip := a.AddrPort().Addr().Unmap()
		if ip.IsValid() {
			return ip.String()
		}
	}
	return ""
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
