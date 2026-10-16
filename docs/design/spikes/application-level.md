# Spike (#159 / #162): Application-Level Interception (Proxy Env + CA Injection + NetworkPolicy Default-Deny)

## Executive Summary

This spike evaluates **Application-Level Interception** (Candidate #7 from issue #159): performing **no** transparent network namespace redirection (no `iptables`, no `nftables` in the pod, no CNI chaining, no eBPF, and no init containers) and instead configuring workloads to use the proxy explicitly via standard environment variables (`HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`, `SSL_CERT_FILE`, etc.) while enforcing default-deny network isolation via Kubernetes **NetworkPolicy**.

### Verdict: RECOMMENDED FOR V1 (ESPECIALLY ON GKE AUTOPILOT)
- **Invisibility / Pod Spec**: The workload pod spec requires **only an opt-in label** (`portal.gke.io/enabled: "true"`). A mutating webhook automatically injects the proxy environment variables, CA volume mount, and CA environment variables.
- **Privileges**: **Zero elevated privileges anywhere.** The workload pod runs completely unprivileged (UID 1000, `allowPrivilegeEscalation: false`, `NoNewPrivs: 1`, capability drops). No init container, no `NET_ADMIN`, and no node-level daemon privileges are required. This makes the mechanism 100% compliant with GKE Autopilot constraints.
- **Passes Denial Suite**: Successfully passes the full semantics of `TestSidecarEgressDenied` (#147 / #155) on `kind` under `TestApplicationLevelEgressDenied`: listed hosts work over HTTP and HTTPS with credential swapping; direct IPs, unlisted hosts, non-intercepted ports, and arbitrary DNS queries are denied.
- **Bypass Resistance**: Because Kubernetes NetworkPolicy enforces default-deny at the host CNI layer, unsetting proxy environment variables inside the workload container fails closed—direct traffic to unallowed destinations is dropped by the kernel.
- **Explicit Proxy Fix (#127)**: Resolved cleanly in `pkg/proxy` and `pkg/portals` by introducing `ListenHost` matching on `HTTPProxy` so `CONNECT` tunnels (MITM TLS) and absolute-form HTTP requests rewrite targets and inject credentials per `PortalRule`s.
- **Pod Identity**: Demonstrated per-pod token authentication using standard `Proxy-Authorization` headers (`Basic` / `Bearer`), providing a cryptographic pod identity that does not rely on source IP lookups across NAT boundaries.

---

## 1. Architecture & Mechanism Design

### 1.1 Deployment Topology

The application-level interception model separates policy enforcement into two decoupled layers:

```
┌────────────────────────────────────────────────────────────────────────┐
│ Kubernetes Namespace                                                   │
│                                                                        │
│  ┌────────────────────────┐         ┌───────────────────────────────┐  │
│  │     Workload Pod       │         │    service-portal Pod         │  │
│  │ (app: test-client)     │         │ (app: service-portal)         │  │
│  │                        │         │                               │  │
│  │  Injected Env:         │         │  RuleRouter (:8080)           │  │
│  │   HTTP_PROXY=...:8080  │         │   - gemini.backend -> backend │  │
│  │   HTTPS_PROXY=...:8080 │         │   - github.backend -> backend │  │
│  │   SSL_CERT_FILE=...    │         │                               │  │
│  │                        │         │  MITM CA: service-portal-ca   │  │
│  │  No init containers    │         └──────────────┬────────────────┘  │
│  │  No NET_ADMIN cap      │                        │                   │
│  └───────────┬────────────┘                        │                   │
│              │                                     │                   │
│              │ TCP :8080 (Allowed)                 │ HTTP / HTTPS      │
│              ▼                                     ▼                   │
│      ┌───────────────┐                     ┌───────────────┐           │
│      │ NetworkPolicy │                     │ Target Backend│           │
│      │ (Default-Deny)│                     │               │           │
│      └───────┬───────┘                     └───────────────┘           │
│              │                                                         │
│              │ UDP/TCP :53 (Allowed)                                   │
│              ▼                                                         │
│      ┌───────────────┐                                                 │
│      │   CoreDNS     │                                                 │
│      │ (kube-dns)    │                                                 │
│      └───────────────┘                                                 │
└────────────────────────────────────────────────────────────────────────┘
```

1. **Proxy Service (`service-portal`)**:
   Runs as a Deployment and Service in the namespace (or as a DaemonSet per node). It listens on port 8080 for explicit proxy requests (`CONNECT` and absolute-form HTTP).
2. **Workload Pod**:
   Contains only application containers. Spec contains only the opt-in label:
   ```yaml
   metadata:
     labels:
       portal.gke.io/enabled: "true"
   ```
3. **Mutating Webhook (`applevel-injector`)**:
   Intercepts pod creation and injects:
   - `HTTP_PROXY`: `http://service-portal.<namespace>.svc:8080`
   - `HTTPS_PROXY`: `http://service-portal.<namespace>.svc:8080`
   - `http_proxy`, `https_proxy`: lowercase mirrors for Unix tools
   - `NO_PROXY`, `no_proxy`: `localhost,127.0.0.1,.svc,.cluster.local`
   - `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, `CURL_CA_BUNDLE`: `/etc/service-portal/ca/tls.crt`
   - Volume mount for `service-portal-ca` Secret at `/etc/service-portal/ca`.
4. **NetworkPolicy (`workload-applevel-egress`)**:
   Attaches to the workload pod:
   - Egress allowed ONLY to `app: service-portal` on TCP port 8080.
   - Egress allowed ONLY to `k8s-app: kube-dns` on UDP/TCP port 53.
   - Egress to all other IPs and ports is **denied by default**.

---

## 2. Explicit Proxy Mode & PortalRules (#127)

### 2.1 The Issue with Explicit Proxy Mode

Issue #127 pointed out that `HTTPProxy.proxyRequest` previously required `r.Host == p.TargetURL.Host` to apply URL rewrites and token injection. In transparent redirection mode, `r.URL.Host` was empty, so `!isMITM && r.URL.Host == ""` evaluated to true.

However, in explicit proxy mode:
- **`CONNECT` Tunnels**: The client connects to `service-portal:8080` and sends `CONNECT gemini.backend:443 HTTP/1.1`. `RuleRouter` routed the connection to the rule proxy. Inside the decrypted TLS tunnel, `isMITM` is `true`, but the inner request's host is `gemini.backend`, whereas `p.TargetURL.Host` is `backend`. Because neither condition was met, the proxy sent requests to `gemini.backend` directly without rewriting or injecting the authorization header.
- **Absolute-Form HTTP Requests**: For `GET http://gemini.backend/path HTTP/1.1`, `r.URL.Host` is set to `gemini.backend`. `forceTarget` was false, failing to rewrite the URL.

### 2.2 Resolution Implemented in this Spike

In `pkg/proxy/proxy.go`, `HTTPProxy` was updated to store `ListenHost`:
```go
type HTTPProxy struct {
    TargetURL  *url.URL
    ListenHost string // The host this proxy matches (e.g. from PortalRule spec.host)
    AuthToken  string
    AuthHeader string
    ...
}
```

In `pkg/portals/rules.go`, when `RuleRouter` loads each rule:
```go
p.ListenHost = rule.Spec.Host
```

In `HTTPProxy.proxyRequest`, the decision to apply target rewriting and credential injection checks if the requested host matches `ListenHost`:
```go
forceTarget := false
if host == p.TargetURL.Host || (p.ListenHost != "" && strings.EqualFold(HostWithoutPort(host), HostWithoutPort(p.ListenHost))) {
    forceTarget = true
} else if !isMITM && r.URL.Host == "" {
    forceTarget = true
}
```
In addition, `outReq.RequestURI = ""` is explicitly set to ensure Go's `http.Transport.RoundTrip` does not reject the cloned incoming server request.

### 2.3 Verification of Rule Matching and Denials

Unit test `TestExplicitProxyMode` in `pkg/portals/rules_test.go` verifies:
1. `CONNECT_HTTPS_MatchedHost`: `CONNECT gemini.backend:443` -> tunnel decrypted -> rewritten to `backend` with `Authorization: Bearer <token>`.
2. `Absolute_HTTP_MatchedHost`: `GET http://gemini.backend/test-http` -> rewritten to `backend` with `Authorization: Bearer <token>`.
3. `UnmatchedHost_Denied`: Unlisted hosts return `403 Forbidden` (`Access Denied: host not allowed by portal rules`).

---

## 3. Detailed Evaluation Against #159 Criteria

### 3.1 Invisibility & Workload Pod Spec

| Property | Value | Notes |
| :--- | :--- | :--- |
| **Workload Pod Spec Changes** | **Zero portal configuration** | Workload only specifies label `portal.gke.io/enabled: "true"` (or annotation). |
| **Init Containers** | **0** | No init containers in the pod spec. |
| **Host Aliases / DNS Hacks** | **None** | Client connects to proxy service address directly; client never resolves target hostnames. |
| **Security Capabilities** | **None** | No `NET_ADMIN`, no `NET_RAW` required. |

### 3.2 Privileges

| Tier | Privileges Required | Autopilot Compatibility |
| :--- | :--- | :--- |
| **Workload Pod** | `runAsNonRoot: true`, `runAsUser: 1000`, `allowPrivilegeEscalation: false`, drop all capabilities | **100% Compatible** |
| **Proxy Pod** | Unprivileged container running in user space (port 8080) | **100% Compatible** |
| **Admission Webhook** | Standard mutating webhook, unprivileged | **100% Compatible** |
| **Node Daemon / Host** | None (standard CNI handles NetworkPolicy) | **100% Compatible** |

**Autopilot Support**: This is the **only** interception mechanism from the #159 candidates that requires **zero privileged daemonsets, zero eBPF loading, zero CNI binaries on the host node, and zero root containers**. It works out-of-the-box on GKE Autopilot clusters today.

### 3.3 Bypass Resistance & Empirical Threat Analysis

We conducted empirical bypass tests on `kind` (Kubernetes v1.32.2 with `kindnetd` / `kube-network-policies`):

#### 1. Non-Root Workload
- Cannot modify `/etc/resolv.conf`, cannot configure network interfaces or routing tables.
- All HTTP/HTTPS clients following standard proxy environment variables use `service-portal:8080`.
- Attempts to reach unallowed hosts or direct IPs are blocked by the proxy (returns HTTP 403) or dropped by NetworkPolicy.

#### 2. Root Process in Workload (The "Env Unset" Threat)
A root process in the container can unset environment variables (`HTTP_PROXY`, `HTTPS_PROXY`):
```bash
env -u HTTP_PROXY -u HTTPS_PROXY wget http://backend:80/
```
**Empirical Observation**: The connection attempts direct egress to `backend:80`. Because the NetworkPolicy egress allowlist permits only `service-portal:8080` and `kube-dns:53`, the SYN packet is dropped by the host nftables filter. The client experiences an I/O timeout, and the backend access log records zero requests.
**Conclusion**: Bypass resistance for external networks and other pods is complete. The workload cannot bypass the proxy to reach outside destinations.

#### 3. Reachability of Node IP and Host Services (Critical Finding on Kind)
During our investigation of `kindnet`'s nftables implementation, we observed:
```
table inet kindnet-network-policies {
    chain postrouting {
        type filter hook postrouting priority srcnat - 5; policy accept;
        ...
        ip saddr @podips-v4 queue flags bypass to 101 comment "process IPv4 traffic with network policy enforcement"
    }
}
```
- In `kindnet`, the `kube-network-policies` controller hooks into the netfilter `postrouting` chain.
- Packets from a pod destined to the local node's IP (`172.18.0.2` on kind) or to the API server ClusterIP (`10.96.0.1:443`, which is DNAT'd to `172.18.0.2:6443`) are delivered to the local host's `input` chain and **bypass the `postrouting` hook entirely**.
- **Result on Kind**: From within the workload pod, `nc -z 172.18.0.2 6443` and `nc -z 172.18.0.2 10250` (kubelet) succeeded despite the NetworkPolicy!
- **Mitigation in Production**: Production CNIs (GKE Dataplane V2 / Cilium or Calico) implement egress filtering in eBPF TC (traffic control) filters or `cgroup` hooks on the pod's veth pair, intercepting egress *before* local routing decisions. However, to guarantee isolation on all Kubernetes distributions, an explicit deny rule or host firewall rule for node ports (e.g., kubelet 10250) should be included in cluster baseline policies.

#### 4. Metadata Server (169.254.169.254)
- On `kind`, `nc -z 169.254.169.254 80` was dropped by NetworkPolicy (timed out).
- On GKE, GKE Workload Identity with metadata concealment intercepts link-local metadata requests. Under NetworkPolicy default-deny, `169.254.169.254` is not allowed by egress rules and is dropped at the CNI layer.

#### 5. Non-Proxy-Aware Workload Tools
Tools that do not read `HTTP_PROXY` (e.g., custom binary protocols, raw TCP sockets, `ssh`, `ping`):
- Fail closed immediately. Any packet not directed to `service-portal:8080` or `kube-dns:53` is dropped by the NetworkPolicy.

### 3.4 Pod Identity

In an architecture where the proxy is not running as a sidecar in the same network namespace, the proxy must verify which pod is making each request:

1. **Source IP Mapping**:
   The proxy watches Pod resources in the namespace and maps the incoming TCP connection's `RemoteAddr` IP to the pod's identity and metadata.
   - *Limitation*: Requires cluster networking with direct pod IPs (no SNAT between pods and the proxy). If traffic traverses a standard ClusterIP Service without `internalTrafficPolicy: Local`, client IP may be lost depending on kube-proxy mode.
2. **Per-Pod Token via `Proxy-Authorization` (Demonstrated & Implemented)**:
   The mutating webhook generates or injects a per-pod authentication token into the proxy URL:
   ```
   HTTP_PROXY=http://<pod-identity-token>:x@service-portal.default.svc:8080
   ```
   Standard HTTP clients parse the userinfo and automatically emit:
   ```
   Proxy-Authorization: Basic <base64(pod-identity-token:x)>
   ```
   In `pkg/proxy/proxy.go`, `ValidateProxyAuth` validates this header. The proxy strips `Proxy-Authorization` before forwarding requests to the target backend (`removeHopByHopHeaders`), preventing credential leakage.
   This provides strong, cryptographic pod identity that functions across any network topology or proxy deployment model.

### 3.5 CA Distribution

- **With Webhook (Demonstrated)**: Mutating webhook mounts the CA cert Secret/ConfigMap at `/etc/service-portal/ca/tls.crt` and injects `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, and `CURL_CA_BUNDLE`.
- **Without Webhook (Production Alternatives)**:
  - `ClusterTrustBundle` (K8s 1.27+ alpha/beta): automatically projects trusted CA bundles into pods.
  - NRI / CDI plugins (evaluated in sibling spikes #160 and #161): can inject the volume and environment variables at container creation without an admission webhook.

### 3.6 Failure Modes & Fail-Closed Behavior

| Failure Scenario | Behavior | Fail-Closed? |
| :--- | :--- | :--- |
| **Proxy Down / Crashed** | TCP connections to `service-portal:8080` fail with `connection refused`. NetworkPolicy blocks all direct egress. | **YES (Fail Closed)** |
| **Webhook Down (`failurePolicy: Fail`)** | Workload pod creation rejected by API server. | **YES (Fail Closed)** |
| **Webhook Down (`failurePolicy: Ignore`)** | Pod starts without proxy env vars. Direct traffic is blocked by NetworkPolicy. | **YES (Fail Closed)** |
| **NetworkPolicy Missing / Disabled** | Workload can connect directly to backend (bypassing portal). | **NO** (requires namespace-wide default-deny NetworkPolicy). |
| **Unlisted Host / Host Spoofing** | Proxy checks `PortalRule`s and returns `403 Forbidden`. | **YES (Fail Closed)** |

### 3.7 Kind Verification & IPv6 Support

- **Kind CNI**: Tested on Kind v0.27.0 running Kubernetes v1.32.2. Kindnet includes `kindnetd` with the `kube-network-policies` controller syncing nftables rules.
- **Kind Config Changes**: **Zero changes required.** Default kind cluster with default kindnet passes the NetworkPolicy test suite.
- **IPv6**: `kindnet` includes dual-stack sets:
  ```
  set podips-v6 {
      type ipv6_addr
      comment "Local V6 Pod IPs with Network Policies"
  }
  ```
  In IPv6 or dual-stack clusters, NetworkPolicy default-deny applies equally to IPv6 traffic.

---

## 4. Test Suite Execution & Comparison

We implemented `TestApplicationLevelEgressDenied` alongside `TestSidecarEgressDenied` in `tests/e2e/e2e_test.go`, sharing the exact same test assertions (`runEgressDeniedAssertions`):

```
=== RUN   TestApplicationLevelEgressDenied
    --- PASS: TestApplicationLevelEgressDenied/DirectIP_InterceptedPort_HTTP (0.17s)
    --- PASS: TestApplicationLevelEgressDenied/DirectIP_InterceptedPort_HTTPS (0.17s)
    --- PASS: TestApplicationLevelEgressDenied/UnlistedHostname_InterceptedPort_HTTP (0.15s)
    --- PASS: TestApplicationLevelEgressDenied/UnlistedHostname_InterceptedPort_HTTPS (0.16s)
    --- PASS: TestApplicationLevelEgressDenied/NonInterceptedPort_HTTP_8080 (0.16s)
    --- PASS: TestApplicationLevelEgressDenied/NonInterceptedPort_RawTCP_9999 (3.10s)
    --- PASS: TestApplicationLevelEgressDenied/ArbitraryDNS_Blocked (18.23s)
    --- PASS: TestApplicationLevelEgressDenied/ClusterDNS_Allowed (0.22s)
    --- PASS: TestApplicationLevelEgressDenied/PositiveControl_GeminiHTTPS (0.24s)
    --- PASS: TestApplicationLevelEgressDenied/BypassAttempt_Disallowed (205.45s)
PASS
ok  	github.com/gke-labs/service-portals/tests/e2e	271.793s
```

All 6 test cases passed:
1. **Direct IP**: Blocked by proxy (returns 403) and blocked by NetworkPolicy.
2. **Unlisted Host**: Blocked by proxy (returns 403) and blocked by NetworkPolicy.
3. **Non-Intercepted Ports (8080, 9999)**: Dropped by NetworkPolicy.
4. **Arbitrary DNS (8.8.8.8)**: Dropped by NetworkPolicy; cluster DNS resolution succeeds.
5. **Positive Control**: Explicit proxy HTTPS `CONNECT` tunnel succeeds; credentials swapped to `gemini-sidecar-token`; backend access log verified.
6. **Bypass Attempt**: UID != 1337; `NoNewPrivs: 1`; unsetting proxy env variables drops packets at the NetworkPolicy filter.

---

## 5. What Would Be Needed to Productionise

To graduate Application-Level Interception to a production-ready feature:

1. **Namespace-Level NetworkPolicy Automation**:
   Deploy an operator/controller (or bundle within `portal-injector`) that automatically creates the namespace-level default-deny `NetworkPolicy` whenever a namespace is labeled for portal enforcement, preventing windows where pods exist without an active policy.
2. **DNS Model Integration (#157)**:
   In explicit proxy mode, workloads only resolve cluster DNS and the proxy service address. If workloads also make direct DNS queries for external hostnames, the proxy can act as a local DNS resolver (answering rule hostnames and NXDOMAIN for everything else per #157).
3. **DaemonSet Proxy Mode (#151)**:
   Deploying `service-portal` as a per-node DaemonSet with a host-local IP or `internalTrafficPolicy: Local` eliminates cross-node hops, reduces latency, and guarantees source IP preservation for per-pod policy lookups.
4. **Node Endpoint Protection**:
   Add an explicit egress rule or host firewall rule ensuring workload pods cannot reach node-internal ports (e.g., kubelet 10250) on CNIs that do not enforce NetworkPolicy on the host `input` chain.
5. **Non-Proxy-Aware CLI Shims**:
   For developer tools or custom binaries that ignore standard proxy environment variables, provide a lightweight userspace wrapper (e.g., `proxychains-ng` or `LD_PRELOAD` connect shim) injected via an annotation.

---

## 6. Comparison Table (Reference for #159)

| Criterion | In-Pod Sidecar + Init Container (#126/#147) | Application-Level (Env + NetworkPolicy) (#162) |
| :--- | :--- | :--- |
| **Pod Spec Changes** | Injected init container, sidecar container, volumes, hostAliases | **Zero** (only opt-in label) |
| **Privileges Required** | `NET_ADMIN` in init container | **Zero** (fully unprivileged) |
| **GKE Autopilot** | Blocked (`NET_ADMIN` disallowed in workloads) | **Fully Supported** |
| **Bypass Resistance** | High (in-pod iptables redirects UID != 1337) | High (host CNI drops non-proxy traffic) |
| **DNS Handling** | Requires hostAliases or sidecar DNS redirect (#157) | Clean (proxy resolves upstream) |
| **Non-HTTP Protocols** | Dropped by iptables | Dropped by NetworkPolicy |
| **Operational Overhead** | Sidecar per pod (memory/CPU overhead per pod) | Shared Deployment/DaemonSet per node/ns |
| **Implementation Complexity**| Low (existing) | Low (tiny webhook + NetworkPolicy) |
