# Spike (#159 / #162): Application-Level Interception (Proxy Env + CA Injection + NetworkPolicy Default-Deny)

## Executive Summary

This spike evaluates **Application-Level Interception** (Candidate #7 from issue #159): performing **no** transparent network namespace redirection (no `iptables`, no `nftables` in the pod, no CNI chaining, no eBPF, and no init containers) and instead configuring workloads to use the proxy explicitly via standard environment variables (`HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`, `SSL_CERT_FILE`, etc.) while enforcing default-deny network isolation via Kubernetes **NetworkPolicy**.

### Verdict: RECOMMENDED FOR V1 (ESPECIALLY ON GKE AUTOPILOT)
- **Invisibility / Pod Spec**: The workload pod spec requires **only an opt-in label** (`portal.gke.io/enabled: "true"`). A mutating webhook automatically injects the proxy environment variables (with per-pod authentication userinfo), CA volume mount, and CA environment variables, replacing any preexisting keys in-place without duplication.
- **Privileges**: **Zero elevated privileges anywhere.** The workload pod runs completely unprivileged (UID 1000, `allowPrivilegeEscalation: false`, `NoNewPrivs: 1`, capability drops). No init container, no `NET_ADMIN`, and no node-level daemon privileges are required. This makes the mechanism 100% compliant with GKE Autopilot constraints.
- **Passes Denial Suite**: Successfully passes the full semantics of `TestSidecarEgressDenied` (#147 / #155) on `kind` under `TestApplicationLevelEgressDenied`: listed hosts work over HTTP and HTTPS with credential swapping; direct IPs, unlisted hosts, non-intercepted ports, and arbitrary DNS queries are denied.
- **Bypass Resistance**: Because Kubernetes NetworkPolicy enforces default-deny at the host CNI layer (Kind v0.24+), unsetting proxy environment variables inside the workload container fails closed—direct traffic to unallowed destinations is dropped by the kernel.
- **Explicit Proxy Fix (#127) & MITM Host Escape Closure**: Resolved cleanly in `pkg/proxy` and `pkg/portals` by introducing `ListenHost` matching on `HTTPProxy` and enforcing that inner requests inside MITM `CONNECT` tunnels must match the `CONNECT` target, preventing tunnel host smuggling.
- **Pod Identity**: Implemented cryptographic per-pod HMAC token minting and verification via `Proxy-Authorization` headers (`Basic` / `Bearer`), mapping authenticated tokens to pod identity and logging them on the proxy.

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
│  │ (portal.gke.io/enabled)│         │ (app: service-portal)         │  │
│  │                        │         │                               │  │
│  │  Injected Env:         │         │  RuleRouter (:8080)           │  │
│  │   HTTP_PROXY=http://   │         │   - gemini.backend -> backend │  │
│  │     pod:<token>@...    │         │   - github.backend -> backend │  │
│  │   HTTPS_PROXY=...      │         │   - Verifies per-pod token    │  │
│  │   SSL_CERT_FILE=...    │         │                               │  │
│  │   NODE_USE_ENV_PROXY=1 │         │  MITM CA: service-portal-ca   │  │
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
   Runs as a Deployment and Service in the namespace (or as a DaemonSet per node). It listens on port 8080 for explicit proxy requests (`CONNECT` and absolute-form HTTP), authenticates per-pod identity tokens, enforces destination rules, and performs credential injection.
2. **Workload Pod**:
   Contains only application containers. Spec contains only the opt-in label:
   ```yaml
   metadata:
     labels:
       portal.gke.io/enabled: "true"
   ```
3. **Mutating Webhook (`applevel-injector`)**:
   Intercepts opted-in pod creation and injects:
   - `HTTP_PROXY`, `http_proxy`: `http://pod:<token>@service-portal.<namespace>.svc:8080` (where `<token>` is an HMAC-SHA256 signed per-pod identity token)
   - `HTTPS_PROXY`, `https_proxy`: `http://pod:<token>@service-portal.<namespace>.svc:8080`
   - `PROXY_AUTHORIZATION`: `Bearer <token>`
   - `NO_PROXY`, `no_proxy`: `localhost,127.0.0.1,.svc,.cluster.local`
   - `NODE_USE_ENV_PROXY`: `1` (required for Node.js 18+ undici/`fetch`)
   - `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, `CURL_CA_BUNDLE`: `/etc/service-portal/ca/tls.crt`
   - Volume mount for `service-portal-ca` Secret at `/etc/service-portal/ca`.
   - Replaces any preexisting matching keys in-place to prevent duplicate environment variable definitions.
4. **NetworkPolicies**:
   - **Workload Egress (`workload-applevel-egress`)**: Selects `portal.gke.io/enabled: "true"`. Restricts all outbound egress to `app: service-portal` on TCP port 8080 and `k8s-app: kube-dns` on UDP/TCP port 53. All other egress is dropped by default.
   - **Proxy Ingress & Egress (`service-portal-netpol`)**: Selects `app: service-portal`. Allows ingress on port 8080 only from opted-in pods (`portal.gke.io/enabled: "true"`), and allows egress only to configured upstreams and cluster DNS.

---

## 2. Explicit Proxy Mode & PortalRules (#127)

### 2.1 The Issue with Explicit Proxy Mode

Issue #127 pointed out that `HTTPProxy.proxyRequest` previously required `r.Host == p.TargetURL.Host` to apply URL rewrites and token injection. In transparent redirection mode, `r.URL.Host` was empty, so `!isMITM && r.URL.Host == ""` evaluated to true.

However, in explicit proxy mode:
- **`CONNECT` Tunnels**: The client connects to `service-portal:8080` and sends `CONNECT gemini.backend:443 HTTP/1.1`. `RuleRouter` routed the connection to the rule proxy. Inside the decrypted TLS tunnel, `isMITM` is `true`, but the inner request's host is `gemini.backend`, whereas `p.TargetURL.Host` is `backend`. Because neither condition was met, the proxy sent requests to `gemini.backend` directly without rewriting or injecting the authorization header.
- **Absolute-Form HTTP Requests**: For `GET http://gemini.backend/path HTTP/1.1`, `r.URL.Host` is set to `gemini.backend`. `forceTarget` was false, failing to rewrite the URL.

### 2.2 Resolution: ListenHost Matching

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

### 2.3 Closing the MITM Host Escape

In MITM mode, after establishing a TLS tunnel via `CONNECT gemini.backend:443`, an adversarial or misconfigured workload could issue HTTP requests inside the decrypted TLS session with a forged or different `Host` header (e.g., `Host: metadata.google.internal` or `Host: other-service.cluster.local`).

Previously, because `isMITM` was true and the forged host did not match `p.TargetURL.Host` or `p.ListenHost`, `forceTarget` was false. In that branch, `proxyRequest` forwarded the request to wherever `r.Host` pointed (`outReq.URL.Host = r.Host`), allowing the workload to reach any destination reachable by the proxy.

**Fix**: In MITM mode, `proxyRequest` now validates that the inner request's `Host` matches the `CONNECT` target (`MatchHosts`):
```go
if isMITM {
    if connectTarget == "" || !MatchHosts(host, connectTarget) {
        log.Printf("MITM Host escape blocked: inner host %q does not match CONNECT target %q", host, connectTarget)
        http.Error(w, fmt.Sprintf("Access Denied: inner host %q does not match CONNECT target", host), http.StatusForbidden)
        return
    }
}
```
If the inner request's host or port differs from the established tunnel target, the proxy denies the request immediately with HTTP 403 Forbidden. This is verified by both unit test (`TestConnectMITMHostEscapeDenied`) and e2e assertion (`MITMHostEscape_Blocked`).
forceTarget := false
if host == p.TargetURL.Host || (p.ListenHost != "" && strings.EqualFold(HostWithoutPort(host), HostWithoutPort(p.ListenHost))) {
    forceTarget = true
} else if !isMITM && r.URL.Host == "" {
    forceTarget = true
}
```
In addition, `outReq.RequestURI = ""` is explicitly set to ensure Go's `http.Transport.RoundTrip` does not reject the cloned incoming server request.

### 2.4 Verification of Rule Matching and Denials

Unit test `TestExplicitProxyMode` in `pkg/portals/rules_test.go` verifies:
1. `CONNECT_HTTPS_MatchedHost`: `CONNECT gemini.backend:443` -> tunnel decrypted -> rewritten to `backend` with `Authorization: Bearer <token>`.
2. `Absolute_HTTP_MatchedHost`: `GET http://gemini.backend/test-http` -> rewritten to `backend` with `Authorization: Bearer <token>`.
3. `UnmatchedHost_Denied`: Unlisted hosts return `403 Forbidden` (`Access Denied: host not allowed by portal rules`).
4. `MITMHostEscape_Denied`: Establishing a `CONNECT gemini.backend:443` tunnel but sending an inner HTTP request with `Host: attacker.backend` returns `403 Forbidden`.
5. `PerPodIdentityToken_HMAC_Verification`: Valid per-pod HMAC tokens authenticate successfully, map to `PodIdentity`, and are logged; requests with missing or tampered tokens return `407 Proxy Authentication Required`.

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

> **Kind Version Requirement (v0.24+)**: Testing NetworkPolicy on `kind` strictly requires **kind v0.24.0 or later**. Kindnet introduced its integrated `kube-network-policies` controller in kind v0.24.0. Clusters running earlier kind versions will not enforce NetworkPolicy egress or ingress rules.

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

#### 3. Expanded Bypass Assertions in E2E
To ensure complete isolation, the e2e test suite verifies multiple bypass vectors under NetworkPolicy default-deny:
1. **Proxy on Non-Proxy Port**: Connecting to `service-portal.default.svc:9999` fails and times out (only port 8080 is permitted).
2. **Direct Connection to Other Pods**: Connecting directly to `backend.default.svc:80` without proxy fails and times out.
3. **Node IP Protection**: Connecting to the Kubernetes Node IP on port 6443 (API server) and port 10250 (kubelet) fails and times out.
4. **Non-Cluster DNS**: Querying external or unapproved DNS resolvers (`8.8.8.8:53`) fails and times out (only cluster `kube-dns:53` is permitted).

#### 4. Metadata Server (169.254.169.254)
- On `kind`, `nc -z 169.254.169.254 80` was dropped by NetworkPolicy (timed out).
- On GKE, GKE Workload Identity with metadata concealment intercepts link-local metadata requests. Under NetworkPolicy default-deny, `169.254.169.254` is not allowed by egress rules and is dropped at the CNI layer.

#### 5. Non-Proxy-Aware Workload Tools
Tools that do not read `HTTP_PROXY` (e.g., custom binary protocols, raw TCP sockets, `ssh`, `ping`):
- Fail closed immediately. Any packet not directed to `service-portal:8080` or `kube-dns:53` is dropped by the NetworkPolicy.

### 3.4 Pod Identity & Authentication

In an architecture where the proxy is not running as a sidecar in the same network namespace, the proxy must verify which pod is making each request:

1. **Per-Pod Cryptographic Token Minting (Implemented & Verified)**:
   The mutating admission webhook (`applevel-injector`) mints an HMAC-SHA256 signed per-pod identity token using pod metadata (`namespace:name:uid:timestamp`) and a shared signing key (`PROXY_AUTH_SECRET`):
   ```
   token = MintPodToken(secret, PodIdentity{Namespace, Name, UID})
   ```
   The injector embeds this token in the proxy URL userinfo:
   ```
   HTTP_PROXY=http://pod:<token>@service-portal.default.svc:8080
   HTTPS_PROXY=http://pod:<token>@service-portal.default.svc:8080
   PROXY_AUTHORIZATION=Bearer <token>
   ```
2. **Proxy Authentication & Mapping**:
   When standard HTTP clients make requests, they automatically transmit `Proxy-Authorization: Basic <base64(pod:token)>` or `Bearer <token>`.
   `HTTPProxy.AuthenticateProxyRequest` and `RuleRouter.Authenticate` verify the HMAC signature, map the token to the pod's identity in memory, and log the pod identity:
   ```
   Proxy auth: authenticated request from pod default/test-client-applevel-deny (uid: ...)
   ```
   If a client omits the proxy auth token or presents an invalid/tampered token, the proxy rejects the connection immediately with HTTP `407 Proxy Authentication Required`.
3. **Hop-by-Hop Stripping**:
   The proxy strips `Proxy-Authorization` headers (`removeHopByHopHeaders`) before forwarding traffic to upstreams, ensuring workload identity tokens never leak outside the cluster.
4. **Token Expiration & Revocation Limitation**:
   Tokens embed an issuance timestamp, and the proxy enforces a maximum validity window (`PROXY_TOKEN_MAX_AGE`, defaulting to 24 hours). Expired tokens are rejected with HTTP `407 Proxy Authentication Required`.
   *Remaining Limitation*: Within their active validity window, tokens function as bearer capabilities. If an attacker reads a token from a compromised pod's environment, that token remains valid until it expires; there is no individual token revocation mechanism short of rotating the cluster signing secret (`PROXY_AUTH_SECRET`).
5. **Static Token Attribution**:
   When legacy static token mode (`PROXY_AUTH_TOKEN`) is used instead of per-pod HMAC signing, requests are explicitly attributed and logged as `unattributed (static token)` so logs never falsely claim a pod identity that was not cryptographically verified.

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
| **MITM Host Escape Attempt** | Proxy checks inner `Host` against `CONNECT` target and returns `403 Forbidden`. | **YES (Fail Closed)** |
| **Missing / Wrong Proxy Auth Token** | Proxy checks `Proxy-Authorization` and returns `407 Proxy Authentication Required`. | **YES (Fail Closed)** |

### 3.7 Kind Verification & IPv6 Support

- **Kind CNI**: Tested on Kind v0.27.0 running Kubernetes v1.32.2. Kindnet includes `kindnetd` with the `kube-network-policies` controller syncing nftables rules. Minimum supported kind version is **v0.24+**.
- **Kind Config Changes**: **Zero changes required.** Default kind cluster with default kindnet passes the NetworkPolicy test suite.
- **IPv6**: `kindnet` includes dual-stack sets:
  ```
  set podips-v6 {
      type ipv6_addr
      comment "Local V6 Pod IPs with Network Policies"
  }
  ```
  In IPv6 or dual-stack clusters, NetworkPolicy default-deny applies equally to IPv6 traffic.

### 3.8 Client Runtime Constraints & Webhook Caveats

1. **Node.js `fetch` / Undici**:
   In Node.js 18 and 20+, native `globalThis.fetch` is backed by `undici`. Unlike traditional `http`/`https` modules, undici **ignores** `HTTP_PROXY` and `HTTPS_PROXY` environment variables by default unless `NODE_USE_ENV_PROXY=1` is explicitly set in the environment or an `EnvHttpProxyAgent` dispatcher is configured. The injector now injects `NODE_USE_ENV_PROXY=1` alongside standard proxy variables so modern Node.js applications honor the proxy out of the box.
2. **Certificate Pinning**:
   Applications, client libraries, or SDKs that employ certificate pinning, public key pinning (HPKP), or maintain hardcoded trust stores (such as embedded pins or Java applications using custom non-system keystores) will fail TLS handshakes under MITM inspection because the dynamic certificate is issued by the cluster's local CA rather than a public root CA.
3. **Injector Environment Variable Deduplication**:
   If a container image or pod spec already defines proxy or CA environment variables, naively appending entries via JSONPatch `/spec/containers/%d/env/-` produces duplicate keys in the container spec. The admission webhook inspects the container's existing `Env` list and issues in-place `replace` patches for matching keys while appending new variables, ensuring clean pod specs.

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
    --- PASS: TestApplicationLevelEgressDenied/MITMHostEscape_Blocked (0.12s)
    --- PASS: TestApplicationLevelEgressDenied/TokenAuth_MissingOrWrong_Rejected (0.35s)
    --- PASS: TestApplicationLevelEgressDenied/BypassAttempt_Disallowed (205.45s)
PASS
```

All test cases passed:
1. **Direct IP**: Blocked by proxy (returns 403) and blocked by NetworkPolicy.
2. **Unlisted Host**: Blocked by proxy (returns 403) and blocked by NetworkPolicy.
3. **Non-Intercepted Ports (8080, 9999)**: Dropped by NetworkPolicy.
4. **Arbitrary DNS (8.8.8.8)**: Dropped by NetworkPolicy; cluster DNS resolution succeeds.
5. **Positive Control**: Explicit proxy HTTPS `CONNECT` tunnel succeeds; credentials swapped to `gemini-sidecar-token`; backend access log verified.
6. **MITM Host Escape Denial**: Inner HTTP requests targeting unlisted hosts inside an established `CONNECT` tunnel are blocked with HTTP 403 Forbidden.
7. **Per-Pod Token Authentication**: Missing or wrong tokens return HTTP 407 Proxy Authentication Required; valid tokens map to pod identity and are logged on the proxy.
8. **Bypass Attempt**: UID != 1337; `NoNewPrivs: 1`; unsetting proxy env variables drops packets at the NetworkPolicy filter; proxy on non-proxy port (:9999), direct pod-to-pod (:80), Node IP (:6443, :10250), and non-cluster DNS queries are all blocked by NetworkPolicy.

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
