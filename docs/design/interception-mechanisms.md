# Decision Record: Alternative Interception Mechanisms and Convergence on NRI Single Mode

**Author**: codebot-robot (decisions by the project owner, 2026-11-03/04)  
**Status**: Decision Record (Approved: NRI Single Target Mode)  
**Date**: November 2026  
**Target Path**: `docs/design/interception-mechanisms.md`  
**Tracking Issues**: [#159](https://github.com/gke-labs/service-portals/issues/159), [#200](https://github.com/gke-labs/service-portals/issues/200), [#225](https://github.com/gke-labs/service-portals/issues/225) (re-file of #208)  
**Related Documents on `main`**:
- Spikes: [`docs/design/spikes/nri.md`](spikes/nri.md) (PR #198), [`docs/design/spikes/application-level.md`](spikes/application-level.md) (PR #215, PR #220), [`docs/design/spikes/cni-plugin.md`](spikes/cni-plugin.md) (PR #196), [`docs/design/spikes/dra-cdi.md`](spikes/dra-cdi.md) (PR #168)
- Architecture & Roadmap: [`docs/design/daemonset-mode.md`](daemonset-mode.md), [`docs/roadmap.md`](../roadmap.md), [`docs/deployment-modes.md`](../deployment-modes.md)
- Follow-up Work: PR #223 (Host-side enforcement, #181), PR #222 (Caller identity, #182), PR #221 (CONNECT removed, #218), #224 (gVisor verification), #183 (IPv6 & bounded DNS), PR #209 (DNS server, #201)

---

## 1. Executive Summary & Problem Statement

`service-portals` acts as an intercepting reverse proxy and credential swapper for untrusted application sandboxes (e.g., LLM agents, code execution runners, CI pipelines). Outbound requests to target domains (e.g., `api.anthropic.com`, `generics.google.internal`) are intercepted transparently, placeholder tokens are swapped with production credentials, and unauthorized egress is denied by default ("Tokens that aren't there can't leak").

### Status Quo & The PSA Baseline Blocker
Today, interception is established by the user explicitly adding an `initContainers` entry (`init-service-portals`) and an in-pod proxy container (`all-in-one-portal`) running as UID 1337 to their pod specification ([`k8s/sidecar.yaml`](../../k8s/sidecar.yaml), [`docs/sidecar-container.md`](../sidecar-container.md); mutating webhook injection remains an unmerged proposal in [#150](https://github.com/gke-labs/service-portals/issues/150) / PR #156).

Multi-tenant Kubernetes clusters standardly enforce Pod Security Admission (PSA) at the `baseline` level in consumer namespaces. PSA `baseline` permits only the default capability set, which does not include `NET_ADMIN`; adding capabilities beyond the default is strictly prohibited (the `restricted` profile allows only `NET_BIND_SERVICE` to be added). Consequently, a native sidecar or in-pod init container requiring `CAP_NET_ADMIN` cannot be deployed in standard consumer namespaces without cluster-wide policy exemptions.

Furthermore, in-pod netfilter rules require exempting the proxy's own egress (`iptables -m owner --uid-owner 1337 -j RETURN`). Because PSA `baseline` permits `runAsUser: 1337`, any workload process running as UID 1337 completely bypasses interception. Finally, in-pod netfilter rules are silently lost under sandboxed runtimes (gVisor and Kata Containers).

### Recorded Architectural Decisions
Following empirical evaluation across four spikes ([#164](https://github.com/gke-labs/service-portals/pull/164), [#165](https://github.com/gke-labs/service-portals/pull/165), [#166](https://github.com/gke-labs/service-portals/pull/166), [#168](https://github.com/gke-labs/service-portals/pull/168)) and direction from the project owner (2026-11-03):

1. **NRI is the Single Mode**: The Node Resource Interface (NRI) within containerd is the single target interception mode. Lifecycle hooks execute via containerd NRI (`github.com/containerd/nri/pkg/stub`). Redirection and egress default-deny rules attach to the host side of the `veth`/`tap` peer interface ([#181](https://github.com/gke-labs/service-portals/issues/181), implemented in PR #223). Caller identity and per-pod policy are resolved at the node proxy ([#182](https://github.com/gke-labs/service-portals/issues/182), implemented in PR #222). Dual-stack IPv6 egress parity and bounded DNS are tracked in [#183](https://github.com/gke-labs/service-portals/issues/183) (open).
2. **No Explicit-Proxy Support at All**: CONNECT and `HTTP_PROXY` mode are removed from `pkg/proxy`, and CONNECT is rejected with `405 Method Not Allowed` ([#218](https://github.com/gke-labs/service-portals/issues/218), implemented in PR #221). Interception is packet-level DNAT only; the workload never speaks to a proxy explicitly.
3. **Application-Level Mode is Not Pursued**: Evaluated in PR #164 ([`docs/design/spikes/application-level.md`](spikes/application-level.md), PR #215, PR #220). Project owner decision (2026-11-03): no separate code path for Autopilot and no interim mode. GKE Autopilot: NRI when available, otherwise unsupported.
4. **CNI Chaining and DRA/CDI are Not Pursued**: Evaluated in PR #166 ([`docs/design/spikes/cni-plugin.md`](spikes/cni-plugin.md)) and PR #168 ([`docs/design/spikes/dra-cdi.md`](spikes/dra-cdi.md)); both are dropped. eBPF socket hooks (`cgroup/connect4`) remain deferred due to verifier complexity and collisions with GKE Dataplane V2 / Cilium.
5. **Sidecar DNS Reduced to Node Proxy**: Standalone sidecar DNS ([#157](https://github.com/gke-labs/service-portals/issues/157)) was reduced to the embedded `pkg/dns` server (PR #209). Serving DNS to opted-in pods happens from the NRI node proxy under [#183](https://github.com/gke-labs/service-portals/issues/183).
6. **Removal of Legacy Modes Once NRI Meets the Bar**: Per [#200](https://github.com/gke-labs/service-portals/issues/200), once NRI satisfies its acceptance criteria, the init-container sidecar mode, explicit Service mode, and single-target portal binaries will be deleted.

---

## 2. Sources and Observed Spike Results

All observations and findings below are sourced directly from the spike writeups merged on `main`:

### 2.1 CNI Chaining Plugin ([`docs/design/spikes/cni-plugin.md`](spikes/cni-plugin.md), PR #166, PR #196)
Evaluated appending a chained CNI plugin to `/etc/cni/net.d/*.conflist` (e.g., `10-kindnet.conflist`), executing synchronously on CNI `ADD` within CRI `RunPodSandbox`:
- **Managed CNI Ownership Conflicts**: Chaining conflicts directly with managed CNIs like GKE Dataplane V2 / Cilium, which operate in `cni-exclusive` mode `[unverified]` and periodically reconcile and overwrite `/etc/cni/net.d/*.conflist`.
- **Missing Pod Labels in `CNI_ARGS`**: CNI args provide only `K8S_POD_NAME` and `K8S_POD_NAMESPACE`. Opt-in evaluation required synchronous API queries using a static node-scoped kubeconfig whose token expired without refresh.
- **In-Pod Rules Fail under Sandboxed Runtimes**: Rules installed via `nsenter` into the pod netns are not traversed by gVisor's netstack or a Kata microVM guest kernel.
- **Threat Model Gaps in Prototype**:
  - *Retained UID-1337 Exemption*: Netfilter rules retained the UID-1337 exemption in both `nat` and `filter` tables despite having no in-pod proxy, creating an egress bypass under PSA `baseline` (`runAsUser: 1337`).
  - *Unfiltered IPv6*: Rules configured only IPv4 `iptables`; `ip6tables` was omitted, leaving all IPv6 egress open and unfiltered.
  - *Bypass-Test False Positive*: In the bypass verification test, `iptables -L` executed inside the pod passed only because the `toolbox` container image lacked the `iptables` binary, not because capability restrictions blocked execution.
- *Carried Forward*: CNI `prevResult` names the host-side peer interface (`veth*`/`tap*`), demonstrating where network enforcement must attach to protect sandboxed runtimes ([#181](https://github.com/gke-labs/service-portals/issues/181)).

### 2.2 DRA Driver + CDI Hooks ([`docs/design/spikes/dra-cdi.md`](spikes/dra-cdi.md), PR #168)
Evaluated modeling egress as an abstract device claim (`portal-egress.portals.gke.io`) via Dynamic Resource Allocation (`resource.k8s.io/v1beta1`) and Container Device Interface (CDI) OCI `createRuntime` hooks (`/usr/local/bin/portal-cdi-hook`):
- **Unnatural Capacity Semantics**: DRA models scarce physical hardware. Modeling egress required artificial static capacity pools (`ResourceSlice` with `egress-0`, `egress-1`, `egress-2`), causing scheduling deadlocks under cluster autoscaling without custom dynamic controllers.
- **Pod Invisibility Bar Unmet**: The opt-in contract failed the invisibility goal. Test pod manifests still had to declare the `service-portal-sidecar` container, a `hostPath` volume for CA files, a `Secret` volume for rules, and `hostAliases`. Kubernetes core provides no claim defaulting without an admission webhook.
- **Per-Container Hook Lifecycle**: The CDI hook executes per-container rather than per-pod. Any `initContainers` execute before the hook runs, escaping unintercepted.
- **Prototype Failed Open**: While OCI hook specification mandates container termination on non-zero exit codes, the prototype hook (`cmd/portal-cdi-hook/main.go:336-345`) logged iptables application errors as warnings and exited 0, launching unprotected containers.
- **Severe Security Defect**: The prototype driver generated both `tls.crt` and `tls.key` into `/var/run/service-portal/ca` and bind-mounted that host directory into workload containers, exposing the node-wide CA private key directly to workloads.
- **Host Path Fragility**: Required copying a hook binary to `/usr/local/bin`, which is mounted read-only on Container-Optimized OS (COS) `[unverified]`.

### 2.3 Application-Level Interception ([`docs/design/spikes/application-level.md`](spikes/application-level.md), PR #164, PR #215, PR #220)
Evaluated zero-privilege interception via proxy environment variables (`HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`, `NODE_USE_ENV_PROXY=1`, `SSL_CERT_FILE`) and default-deny Kubernetes `NetworkPolicy`:
- **Zero Privileges Verified**: Workloads ran completely unprivileged (`runAsNonRoot: true`, UID 1000, `allowPrivilegeEscalation: false`, 0 capabilities). Unsetting proxy variables failed closed against host nftables on kindnet v0.24+ (tested on kind v0.27.0 `[as observed in CI]`).
- **Attribution via Per-Pod HMAC Tokens**: The mutating webhook minted HMAC-SHA256 tokens embedded in proxy URL userinfo (`http://pod:<token>@...`), transmitted via `Proxy-Authorization` and verified by the proxy to map `namespace/name`.
- **Open-Relay Finding**: Without per-pod caller authentication, any pod or host process capable of reaching the proxy's port can use it as an open credential-injecting relay.
- **MITM Host-Escape Closure**: Workloads inside an allowed `CONNECT <host>:443` tunnel could send inner HTTP requests with forged `Host` headers targeting unlisted destinations. The spike patched this via `MatchHosts`; on `main`, the vulnerability was permanently closed by deleting CONNECT support entirely ([#218](https://github.com/gke-labs/service-portals/issues/218), PR #221) rather than merging the Host-check patch in #186.
- **Verdict**: Not pursued. The project will not maintain a divergent code path for GKE Autopilot.

### 2.4 containerd NRI Plugin Spike & Follow-ups ([`docs/design/spikes/nri.md`](spikes/nri.md), PR #198, PR #222, PR #223)
Evaluated containerd Node Resource Interface (`cmd/portal-nri-plugin`) via DaemonSet mounting `/var/run/nri/nri.sock`:
- **Invisible Pod Spec & Elimination of UID 1337 Bypass**: Workloads specify only label `service-portal.gke.io/intercept: "true"`. CA bundle is injected via NRI `CreateContainer` adjustments. In-pod iptables eliminated the UID-1337 exemption.
- **Prototype State (as merged in PR #198)**:
  - Rules installed via `nsenter` into pod netns silently lost under gVisor and Kata.
  - Node proxy listened on `0.0.0.0:8080/8443` with no caller check, acting as an open credential-injecting relay: any pod on the node network could reach the proxy and obtain credentials.
  - IPv6 traffic was completely unfiltered.
  - Taint gate (`service-portal.gke.io/uninitialized:NoSchedule`) was applied and removed by an external actor, leaving a fail-open window on plugin restart.
- **Host-Side Enforcement Delta ([#181](https://github.com/gke-labs/service-portals/issues/181), PR #223)**: Moved netfilter rules from the pod netns to the host peer interface (`veth*`/`tap*`). `PORTAL_PR_<hostIface>` inserted at position 1 of `PREROUTING`; `PORTAL_EG_<hostIface>` inserted at position 1 of `INPUT` and `FORWARD`. Opted-in pods with unsupported runtime classes fail closed.
- **Caller Identity & Per-Pod Policy ([#182](https://github.com/gke-labs/service-portals/issues/182), PR #222)**: Pod map indexed by UID and IP exposed over loopback Admin API (`127.0.0.1:8081`). Proxy resolves caller IP from `RemoteAddr`. Unbound pods fail closed. Explicit Bind API (`POST /bind`, `POST /unbind`) handles warm pools without pod spec mutation. Direct requests for unentitled hosts or from non-opted-in callers return 403 Forbidden.

The complete 16-subtest suite passes in CI (pasted from `docs/design/spikes/nri.md` as updated by PR #222; `TestNRIPluginEgressDenied` in 130.64s):
```text
=== RUN   TestNRIPluginEgressDenied
    --- PASS: TestNRIPluginEgressDenied/UnboundPod_Denied (0.08s)
    --- PASS: TestNRIPluginEgressDenied/DirectIP_InterceptedPort_HTTP (0.14s)
    --- PASS: TestNRIPluginEgressDenied/DirectIP_InterceptedPort_HTTPS (0.15s)
    --- PASS: TestNRIPluginEgressDenied/UnlistedHostname_InterceptedPort_HTTP (0.14s)
    --- PASS: TestNRIPluginEgressDenied/UnlistedHostname_InterceptedPort_HTTPS (0.15s)
    --- PASS: TestNRIPluginEgressDenied/NonInterceptedPort_HTTP_8080 (1.16s)
    --- PASS: TestNRIPluginEgressDenied/NonInterceptedPort_RawTCP_9999 (0.08s)
    --- PASS: TestNRIPluginEgressDenied/ArbitraryDNS_Blocked (0.18s)
    --- PASS: TestNRIPluginEgressDenied/ClusterDNS_Allowed (0.18s)
    --- PASS: TestNRIPluginEgressDenied/PositiveControl_HTTP (0.14s)
    --- PASS: TestNRIPluginEgressDenied/PositiveControl_HTTPS (0.22s)
    --- PASS: TestNRIPluginEgressDenied/BypassAttempt_Disallowed (0.24s)
    --- PASS: TestNRIPluginEgressDenied/ProxyLogsCarryPodIdentity (0.05s)
    --- PASS: TestNRIPluginEgressDenied/DirectToProxy_OptedInPod_UnentitledHost_Denied (0.08s)
    --- PASS: TestNRIPluginEgressDenied/DirectToProxy_NonOptedInPod_Denied (32.16s)
    --- PASS: TestNRIPluginEgressDenied/Unbind_RevertsToDenied (0.09s)
PASS
```

---

## 3. Comprehensive Mechanism Comparison

### 3.1 Mechanism Overview & Runtime Class Support Matrix

| Mechanism | Hook Point | Workload Pod Spec Changes | PSA Compatibility | Runtime Class Support (runc / gVisor / Kata) | Platform Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **In-Pod Sidecar + Init Container (#147)** | Pod spec init container (webhook unmerged #150) | Declared init container, sidecar, volumes, hostAliases | **Fails Baseline** (requires `CAP_NET_ADMIN` in pod) | • `runc`: Preserved<br>• `gVisor`: **Silently lost** (netstack bypass)<br>• `Kata`: **Silently lost** (VM kernel bypass) | Legacy recommendation; scheduled for removal (#200) |
| **Chained CNI Plugin Spike (#166)** | CNI `ADD`/`DEL` in `RunPodSandbox` | Zero changes (label opt-in) | Passes Baseline & Restricted (0 pod caps) | • `runc`: Preserved<br>• `gVisor`: **Silently lost** (in-pod netns rules)<br>• `Kata`: **Silently lost** (in-pod netns rules) | Dropped / not pursued |
| **DRA Driver + CDI Hooks Spike (#168)** | CDI `createRuntime` OCI hook | Sidecar, hostPath, Secret, hostAliases, resourceClaims | Passes Baseline & Restricted (0 pod caps) | • `runc`: Preserved<br>• `gVisor`: **Silently lost** (in-pod netns rules)<br>• `Kata`: **Silently lost** (in-pod netns rules) | Dropped / not pursued |
| **Application-Level Spike (#164)** | Mutating webhook + CNI NetworkPolicy | Injected proxy env vars and CA volume mount | Passes Baseline & Restricted (0 pod caps) | • `runc`: Preserved<br>• `gVisor`: Preserved (host NetworkPolicy)<br>• `Kata`: Preserved (host NetworkPolicy) | Dropped / not pursued (no Autopilot code path) |
| **NRI Prototype (as merged in #198)** | containerd NRI (`RunPodSandbox`, pod netns) | Zero changes (label opt-in: `service-portal.gke.io/intercept: "true"`) | Passes Baseline & Restricted (0 pod caps) | • `runc`: Preserved<br>• `gVisor`: **Silently lost** (in-pod netns rules)<br>• `Kata`: **Silently lost** (in-pod netns rules) | In-pod netns prototype; superseded by #181 |
| **NRI Target Single Mode (#181/#182/#183)** | containerd NRI (host peer `veth`/`tap` interface) | Zero changes (label opt-in: `service-portal.gke.io/intercept: "true"`) | Passes Baseline & Restricted (0 pod caps) | • `runc`: Preserved<br>• `gVisor`: **Preserved** `[unverified until #224]`<br>• `Kata`: **Preserved** `[unverified until #224]` | **Single Target Mode** (all other modes removed once bar met) |

### 3.2 Security, Threat Model & Failure Mode Comparison Matrix

| Evaluation Dimension | In-Pod Sidecar (#147) | Chained CNI (#166) | DRA + CDI (#168) | Application-Level (#164) | NRI: Prototype (Merged #198) | NRI: Target Single Mode (#181/#182/#183) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Runtime Class (runc / gVisor / Kata)** | `runc`: Preserved<br>`gVisor`: **Silently lost**<br>`Kata`: **Silently lost** | `runc`: Preserved<br>`gVisor`: **Silently lost**<br>`Kata`: **Silently lost** | `runc`: Preserved<br>`gVisor`: **Silently lost**<br>`Kata`: **Silently lost** | `runc`: Preserved<br>`gVisor`: Preserved<br>`Kata`: Preserved | `runc`: Preserved<br>`gVisor`: **Silently lost**<br>`Kata`: **Silently lost** | `runc`: Preserved<br>`gVisor`: **Preserved** `[unverified until #224]`<br>`Kata`: **Preserved** `[unverified until #224]` |
| **IPv6 Egress** | Configured via `ip6tables` (`ap-e2e-dual`) | **Unfiltered** (IPv4 iptables only) | **Unfiltered** (IPv4 iptables only) | Preserved in kindnet sets `[untested for app-level]` | **Unfiltered** (IPv4 iptables only) | **Target: Blocked / Parity** (`ip6tables` host rules, #183 open) |
| **DNS Exfiltration through CoreDNS** | **Exfiltration Possible** (UDP 53 open to CoreDNS) | **Exfiltration Possible** (UDP 53 open to CoreDNS) | **Exfiltration Possible** (UDP 53 open to CoreDNS) | **Exfiltration Possible** (UDP 53 open to CoreDNS) | **Exfiltration Possible** (UDP 53 open to CoreDNS) | **Target: prevented by bounded DNS (#183 open)** |
| **Source-IP Spoofing (`NET_RAW`)** | Ineffective (in-pod iptables redirects all 80/443) | **Vulnerable** (proxy unauthenticated) | N/A (in-pod sidecar proxy) | Ineffective (HMAC token in header required) | **Vulnerable** (open relay on host network) | **Prevented** (Host-side pod map + TCP 3-way handshake + veth isolation) |
| **Per-Pod Attribution** | High (1:1 local sidecar) | **None** (proxy unauthenticated) | N/A (1:1 local sidecar) | High (HMAC per-pod tokens in userinfo) | **None** (open relay; caller IP unverified) | **High** (host pod map, `RemoteAddr` resolution, Bind API, attribution headers) |
| **Behavior: Node Proxy Down** | Fail-Closed (connection refused) | Fail-Closed (connection refused) | Fail-Closed (connection refused) | Fail-Closed (connection refused) | Fail-Closed (connection refused) | Fail-Closed (connection refused: host DNAT hits dead port) |
| **Behavior: Hook / Daemon Down** | Fail-Closed (`failurePolicy: Fail`) | Fail-Closed (`FailedCreatePodSandBox`) | Fail-Open in prototype (hook logged error, exit 0) | Fail-Closed (`NetworkPolicy` drops egress) | Fail-Open on restart until containerd reconnects | Fail-Closed at startup via taint gate; restart gap open |

---

## 4. Threat & Security Analysis

### 4.1 Runtime Class Isolation (runc vs. gVisor vs. Kata)
In-pod netfilter rules fail silently under sandboxed runtimes:
- **gVisor (`runsc`)**: Untrusted code executes in the Sentry userspace kernel. Its userspace network stack (`netstack`) writes raw Ethernet frames directly to the `veth` interface via `AF_PACKET` sockets, bypassing netfilter chains in the pod network namespace entirely.
- **Kata Containers**: Sandboxes execute inside dedicated microVM guest kernels. Egress traffic originates in the guest VM and exits via a host `tap` device. Rules in a host-side pod netns are never traversed.

**Host-Side Solution ([#181](https://github.com/gke-labs/service-portals/issues/181), PR #223)**: Moving redirection and filtering to the host peer interface (`veth*` or `tap*`) in the host root network namespace ensures all egress frames—regardless of runtime—must traverse host netfilter hooks before routing. Unsupported runtime classes fail closed on sandbox creation. Live verification under gVisor on kind is tracked in [#224](https://github.com/gke-labs/service-portals/issues/224) (`[unverified]` until merged).

### 4.2 `CAP_NET_RAW` Source-IP Spoofing & TCP Handshake Defense
Under PSA `baseline`, workload containers retain `CAP_NET_RAW`, permitting `SOCK_RAW`/`AF_PACKET` sockets to emit packets with forged source IPs.

As documented in PR #222's writeup, the host-side pod map and TCP architecture prevent IP spoofing:
1. **TCP 3-Way Handshake Protection**: The portal operates as an L7 reverse proxy over TCP. Initiating an HTTP request or TLS handshake strictly requires completing the TCP handshake (`SYN` -> `SYN-ACK` -> `ACK`). If Pod A forges Pod B's source IP in a `SYN` packet:
   - The proxy replies with `SYN-ACK` addressed to Pod B's IP.
   - The Linux kernel and CNI bridge route the `SYN-ACK` to Pod B's `veth` interface.
   - Pod A never receives the `SYN-ACK` and cannot guess TCP sequence numbers.
   - Pod B receives an unexpected `SYN-ACK` for a connection it never initiated and immediately transmits a TCP `RST`, tearing down the embryonic connection.
   - Pod A cannot complete the handshake, establish a stream, or receive credentials.
2. **Host-Side Peer Interface Isolation**: Each pod attaches to a dedicated host-side `veth` or `tap` peer. CNI interface filtering and host reverse path filtering (where `rp_filter` is strict `[unverified: CNI and distribution dependent]`) drop frames whose source IPs do not match the assigned interface.

### 4.3 DNS Exfiltration through CoreDNS
Port 53 to CoreDNS is open in every interception mechanism that allows cluster DNS resolution. Therefore, claiming arbitrary DNS exfiltration is "prevented" is false for any mechanism that leaves UDP/TCP 53 open to cluster DNS without inspection. Workloads can tunnel data via DNS query names (e.g., `<encoded-payload>.attacker.com`) forwarded by CoreDNS to external upstreams.

**Resolution**: Sidecar DNS ([#157](https://github.com/gke-labs/service-portals/issues/157)) was reduced to the embedded `pkg/dns` server (PR #209). In NRI target mode ([#183](https://github.com/gke-labs/service-portals/issues/183)), opted-in pods have port 53 redirected to the node proxy's bounded DNS server, which resolves only allowed `PortalRule` hosts and returns `NXDOMAIN` (or drops) external queries, eliminating CoreDNS exfiltration.

---

## 5. NRI Fail-Closed Lifecycle & Operational Guarantees

### 5.1 Hook Lifecycle and Synchronize
- `RunPodSandbox`: Synchronous CRI hook. Resolves the host peer interface, creates per-interface chains `PORTAL_PR_<hostIface>` (NAT) and `PORTAL_EG_<hostIface>` (Filter), and inserts jumps at position 1. Unknown runtime classes fail closed immediately.
- `CreateContainer`: Injects CA bundle bind mount (`/etc/service-portal/ca/tls.crt`) and `SSL_CERT_FILE` into container adjustments. Fails closed if the node CA bundle is missing on the host.
- `StopPodSandbox` / `RemovePodSandbox`: Idempotently unlinks jumps and deletes host chains.
- `Synchronize`: Invoked when the plugin registers or reconnects. Re-discovers existing sandboxes and re-applies host rules. Containerd treats a non-nil error from `Synchronize` as failed registration and aborts the connection.

### 5.2 Pre-Registration and the Taint Gate
- **Pre-Registration under `/opt/nri/plugins`**: containerd supports pre-registering plugins via binary drop-in under `/opt/nri/plugins`, allowing containerd to manage plugin discovery.
- **Node Taint Gate**: As described in [`docs/design/spikes/nri.md`](spikes/nri.md), fail-closed node startup is achieved via a taint gate:
  1. The node is tainted with `service-portal.gke.io/uninitialized:NoSchedule`.
  2. Incoming workload pods remain in `Pending` status.
  3. The `portal-node-agent` DaemonSet launches, registers with NRI, and enters `Ready`.
  4. The taint is removed, releasing workloads to schedule onto the node with active interception.
  *Note*: In current releases, the taint is applied and removed by an external actor (e.g. cluster provisioning script or node controller), not by the plugin itself.
- **Restart Gap**: If the NRI plugin crashes or restarts after the taint has been removed, a fail-open gap exists: newly scheduled pods starting before containerd reconnects to the plugin may execute unprotected.
- **containerd `required_plugins`**: containerd provides configuration to designate specific plugins as required (`required_plugins` in containerd 2.0+ `[unverified]`). When configured, containerd halts pod sandbox creation if a required plugin is disconnected.

### 5.3 Design Proposals of this Document
The following improvements are design proposals of this document (not yet implemented in the prototype):
- *Design Proposal (Automated Taint Controller)*: Package a dedicated node initializer or kubelet startup hook that automatically taints the node upon boot and clears it only after `portal-nri-plugin` reports healthy via an agent status check.
- *Design Proposal (Reconciliation Robustness)*: Enhance `Synchronize` to isolate sandbox failures so that an error on a single terminating pod does not cause containerd to reject the entire plugin registration.

---

## 6. Roadmap, Acceptance Bar, and Migration Plan

### 6.1 Acceptance Bar for "NRI Works Well" ([#200](https://github.com/gke-labs/service-portals/issues/200))
Meeting this acceptance bar gates the removal of legacy modes (Step 2 of [#200](https://github.com/gke-labs/service-portals/issues/200)):

1. **Deny Suite on kind (including direct-to-proxy cases)**:
   The [#147](https://github.com/gke-labs/service-portals/issues/147) default-deny suite passes in NRI mode on kind, including both direct-to-proxy cases ([#182](https://github.com/gke-labs/service-portals/issues/182)):
   - Opted-in pod connecting directly to proxy with unentitled host is denied (403).
   - Non-opted-in pod connecting directly to proxy is denied (403).  
   *Status*: **Implemented and Passing** in PR #222 (`TestNRIPluginEgressDenied`).
2. **Host-Side Enforcement for Sandboxed Runtimes**:
   Interception rules attach to the host peer interface ([#181](https://github.com/gke-labs/service-portals/issues/181)).  
   *Status*: **Implemented** in PR #223. MicroVM verification on kind under gVisor is **Open** ([#224](https://github.com/gke-labs/service-portals/issues/224)).
3. **IPv6 Egress Parity and Bounded DNS**:
   Dual-stack rejection and bounded DNS server integration ([#183](https://github.com/gke-labs/service-portals/issues/183)).  
   *Status*: **Open** ([#183](https://github.com/gke-labs/service-portals/issues/183)). Sidecar DNS server implemented in `pkg/dns` (PR #209).
4. **Fail-Closed Operation**:
   Demonstrated fail-closed behavior via taint gating and pre-registration without silent fallback.  
   *Status*: Taint pattern demonstrated in e2e test; restart gap mitigation open.
5. **Per-Pod Identity & Attribution**:
   Proxy resolves calling pod and logs attribution ([#182](https://github.com/gke-labs/service-portals/issues/182)).  
   *Status*: **Implemented and Passing** in PR #222 (pod map, `RemoteAddr` resolution, Bind API, attribution headers).
6. **Migration Note & Platform Policy**:
   Migration guide from sidecar to NRI. Autopilot policy established: unsupported where NRI is unavailable.  
   *Status*: **Decided**; documented below.

### 6.2 Removal List (Step 2 from [#200](https://github.com/gke-labs/service-portals/issues/200))
Once the acceptance bar is satisfied, legacy components will be removed in separate, focused pull requests:
- **Explicit Proxy / CONNECT Mode**: Removed from `pkg/proxy`, CONNECT returns 405 ([#218](https://github.com/gke-labs/service-portals/issues/218), PR #221 completed).
- **Explicit Service Mode**: Delete `k8s/manifests.yaml`, single-target portal binaries (`gemini-portal/`, `anthropic-portal/`, `github-portal/`), and `cmd/service-portal/`.
- **In-Pod Sidecar Mode**: Delete `init-service-portals`, `sidecar.yaml`, associated tests, and close #150 / #156 (never merged).

### 6.3 Migration & Platform Policy
- **Sidecar to NRI Migration**: Clusters running the sidecar mode transition to NRI by deploying the `portal-node-agent` DaemonSet and updating pod manifests to remove `initContainers`, sidecar containers, CA volume mounts, and `hostAliases`, retaining only label `service-portal.gke.io/intercept: "true"`. Pods migrate node-by-node or deployment-by-deployment without downtime.
- **Unsupported Platform Policy (GKE Autopilot)**: Per the project owner decision (2026-11-03), no separate application-level code path will be maintained. On platforms where containerd NRI is unavailable (such as GKE Autopilot today), `service-portals` is explicitly unsupported until managed NRI or equivalent platform hooks become available.

---

## 7. Version Claims & Platform Matrix

Consistent with spike writeup markings, platform versions and support statuses are documented as follows:
- **containerd on kind**: Kind node image `kindest/node:v1.32.2` runs containerd v2.0.2 with NRI enabled by default (`disable = false`).
- **containerd on GKE Standard**: containerd 1.7+ in GKE 1.29+ includes NRI compiled-in `[unverified]`; default enablement without configuration flags is standard in containerd 2.0+ (GKE 1.33+ `[unverified]`).
- **Dynamic Resource Allocation (DRA)**: KEP-4381 `resource.k8s.io/v1beta1` in Kubernetes 1.31–1.32; targeting v1 GA in Kubernetes 1.34 `[unverified]`.
- **ClusterTrustBundle**: Kubernetes 1.27+ alpha / beta in Kubernetes 1.29+ `[unverified]`.
- **Container-Optimized OS (COS)**: `/usr/local/bin` mounted read-only `[unverified]`.
- **GKE Dataplane V2 (Cilium)**: Operates in `cni-exclusive` mode, reconciling `/etc/cni/net.d` `[unverified]`.
- **containerd `required_plugins`**: Supported in containerd 2.0+ `[unverified]`.
