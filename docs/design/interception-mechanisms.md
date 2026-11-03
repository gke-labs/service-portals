# Design & Decision Record: Alternative Interception Mechanisms for Service Portals

**Author**: codebot-robot / justinsb  
**Status**: Decision Record (Approved: NRI + Host-Side Enforcement; Interim: Application-Level)  
**Date**: November 2026  
**Target Path**: `docs/design/interception-mechanisms.md`  
**Tracking Issue**: [#159](https://github.com/gke-labs/service-portals/issues/159) / [#195](https://github.com/gke-labs/service-portals/issues/195)  
**Related Issues & Spikes**:
- Spike PRs: [#164](https://github.com/gke-labs/service-portals/pull/164) (Application-Level), [#165](https://github.com/gke-labs/service-portals/pull/165) (containerd NRI), [#166](https://github.com/gke-labs/service-portals/pull/166) (Chained CNI), [#168](https://github.com/gke-labs/service-portals/pull/168) (DRA/CDI)
- Spike Writeups: [`docs/design/spikes/application-level.md`](spikes/application-level.md), [`docs/design/spikes/nri.md`](spikes/nri.md), [`docs/design/spikes/cni-plugin.md`](spikes/cni-plugin.md), [`docs/design/spikes/dra-cdi.md`](spikes/dra-cdi.md)
- Core Issues: [#147](https://github.com/gke-labs/service-portals/issues/147) (Deny Suite), [#148](https://github.com/gke-labs/service-portals/issues/148) (Egress Knobs), [#150](https://github.com/gke-labs/service-portals/issues/150) (Webhook Injector), [#151](https://github.com/gke-labs/service-portals/issues/151) (DaemonSet Mode), [#157](https://github.com/gke-labs/service-portals/issues/157) (Sidecar DNS), [#181](https://github.com/gke-labs/service-portals/issues/181) (Host-Side veth/tap Enforcement), [#182](https://github.com/gke-labs/service-portals/issues/182) (Node Proxy Pod Resolution & Attribution), [#183](https://github.com/gke-labs/service-portals/issues/183) (IPv6 Rules & Bounded DNS)

---

## 1. Executive Summary & Problem Statement

`service-portals` acts as an intercepting proxy and credential swapper for untrusted application sandboxes (e.g., LLM agents, code execution runners, CI pipelines). Outbound requests to target domains (e.g., `api.anthropic.com`, `generics.google.internal`) are intercepted transparently, placeholder tokens are swapped with production credentials, and unauthorized egress is denied by default ("Tokens that aren't there can't leak").

### The Status Quo: In-Pod Init Container & Webhook
Today, interception is established via an admission webhook ([#150](https://github.com/gke-labs/service-portals/issues/150)) that modifies incoming Pod specifications to inject:
1. **An `initContainers` entry (`init-service-portals`)**: Runs with `CAP_NET_ADMIN` to configure `iptables` NAT redirection (`REDIRECT` to ports 8080/8443) and egress filtering rules (`PORTAL_EGRESS` chain) inside the pod network namespace, and generates an ephemeral root CA.
2. **A proxy container (`all-in-one-portal` / `service-portal-sidecar`)**: Runs as UID 1337 holding the pod's secrets and CA private key.
3. **CA Volume Mounts & Environment Variables**: Mounts public certificates into workload containers and sets `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, and `NODE_EXTRA_CA_CERTS`.
4. **DNS Configuration / Host Aliases**: Routes target hostnames to interceptable IPs via CoreDNS or sidecar DNS ([#157](https://github.com/gke-labs/service-portals/issues/157)).

### Limitations of Today's Approach & The PSA Baseline Blocker
While functional, this model has critical architectural and security constraints that prevent broad multi-tenant adoption:
- **The PSA Baseline Constraint (Primary Blocker)**: Multi-tenant clusters and consumer namespaces standardly enforce Kubernetes Pod Security Admission (PSA) at the `baseline` level. PSA `baseline` permits only the default capability set (in which `CAP_NET_ADMIN` is not included; adding capabilities beyond default is prohibited, whereas `restricted` permits only adding `NET_BIND_SERVICE`). The status quo init container (`init-service-portals`), as well as a native sidecar approach, requires `CAP_NET_ADMIN` in the Pod manifest. Requiring `CAP_NET_ADMIN` in consumer pods violates PSA `baseline` and prevents deployment in standard production environments without cluster-wide security exemptions.
- **The UID-1337 Loop Avoidance Vulnerability**: In-pod iptables redirection requires loop avoidance to prevent the proxy's outbound traffic from redirecting into itself (`iptables -m owner --uid-owner 1337 -j RETURN`). If a workload container process can run as or switch to UID 1337, or if a bug allows UID manipulation, the workload can completely bypass interception.
- **Risk of Workload Capability Escalation**: If an untrusted workload container possesses or acquires `CAP_NET_ADMIN` (or runs with `allowPrivilegeEscalation: true`), it can flush or manipulate the pod-local iptables chains (`iptables -F`).
- **Silent Loss of Interception in Sandboxed Runtimes (gVisor & Kata)**: Mechanisms that install iptables rules via `nsenter` into the container network namespace succeed under standard `runc`, but are **silently lost** under sandboxed runtimes. Under gVisor (`runsc`), Netstack (user-space TCP/IP) manages networking in the Sentry process and emits packets directly via an `AF_PACKET` socket to the `veth` interface, bypassing in-pod netfilter rules. Under Kata Containers, the container process runs inside a guest VM kernel, completely isolated from in-pod host namespace rules. In both cases, outbound traffic leaks unintercepted.
- **Container Startup Latency**: Executing an init container incurs container runtime orchestration overhead (image verification, cgroup initialization, process execution, certificate generation) adding hundreds of milliseconds to sandbox startup.
- **Webhook Fragility**: A cluster-wide mutating webhook introduces an operational dependency. If the webhook service is unavailable, pod creation fails or falls back to unintercepted execution.

### The Recorded Architectural Decisions
Based on empirical findings across the four spike prototypes ([#164](https://github.com/gke-labs/service-portals/pull/164), [#165](https://github.com/gke-labs/service-portals/pull/165), [#166](https://github.com/gke-labs/service-portals/pull/166), [#168](https://github.com/gke-labs/service-portals/pull/168)):

1. **Build First (Target Architecture)**: **containerd Node Resource Interface (NRI) Plugin with Host-Side Enforcement**.
   - Build on **NRI** as the runtime lifecycle hook.
   - Redirect and egress enforcement rules are installed on the **host side** of the `veth`/`tap` interface (in the host root network namespace) rather than via `nsenter` into the pod network namespace. This ensures interception is strictly preserved across standard `runc`, `gVisor` (`runsc`), and `Kata Containers` ([#181](https://github.com/gke-labs/service-portals/issues/181)).
   - Pair with a per-node proxy that resolves the calling pod from host-side socket/IP metadata, applying per-pod policy and attribution ([#182](https://github.com/gke-labs/service-portals/issues/182)).
   - Enforce IPv6 egress filtering alongside IPv4, and bound DNS exfiltration by restricting external query forwarding ([#183](https://github.com/gke-labs/service-portals/issues/183)).
   - **Elimination of the UID-1337 Exemption**: As proven in the NRI spike ([`docs/design/spikes/nri.md`](spikes/nri.md)), placing the proxy on the host network removes all UID exemptions from the pod network path. Workload traffic on intercepted ports is unconditionally redirected regardless of UID.
   - **Host-Side Enforcement Delta (#181)**: The prototype spike (#165) installed rules via `nsenter --net` into the pod netns (`nri.md:69, 114, 183`); transitioning enforcement from in-pod netns to the host-side `veth`/`tap` peer interface is the unbuilt delta tracked in [#181](https://github.com/gke-labs/service-portals/issues/181).
2. **Interim Path & GKE Autopilot**: **Application-Level Interception (Option 7, [#164](https://github.com/gke-labs/service-portals/pull/164))**.
   - Requires **zero elevated privileges anywhere** (no `NET_ADMIN`, no host daemons, no root). Workloads run with `drop: ["ALL"]`, fully compliant with PSA `baseline` and `restricted` profiles.
   - Works immediately on GKE Autopilot and any standard Kubernetes cluster today without node-level permissions.
   - Enforces default-deny isolation via standard Kubernetes `NetworkPolicy`.
   - Injects proxy environment variables (`HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`, `SSL_CERT_FILE`) and projected/mounted CA bundles.
   - **Controller-Created Pods**: Consumers or controllers that construct the pod spec directly (e.g., LLM sandbox runners, CI job builders) require **no webhook**; they inject proxy environment variables and CA mounts directly.
   - **Per-Pod Cost Attribution**: Uses per-pod `Proxy-Authorization` tokens injected into the proxy URL ([#164](https://github.com/gke-labs/service-portals/pull/164)), providing cryptographic pod identity and cost attribution immune to IP spoofing.
   - **Open-Relay Fix & MITM Host Check**: Resolved explicit proxy handling (#127) with `ListenHost` matching and prevents tunnel smuggling/open relays by validating that inner HTTP request hosts match the established MITM `CONNECT` tunnel target.
3. **Drop List (Explored & Not Pursued)**:
   - **CNI Chaining ([#166](https://github.com/gke-labs/service-portals/pull/166))**: Dropped. Modifying `/etc/cni/net.d/*.conflist` conflicts with provider CNI reconciling (GKE Dataplane V2 / Cilium); `CNI_ARGS` omits pod labels (triggering an API server thundering herd); CNI cannot inject CA certificates; in-pod rules are silently lost under gVisor/Kata; and Autopilot forbids CNI directory mounts.
   - **DRA Driver + CDI Hooks ([#168](https://github.com/gke-labs/service-portals/pull/168))**: Dropped. DRA is an architectural mismatch (modeling software egress policy as scarce physical hardware claims); causes API claim storage and scheduling churn; lacks namespace-level defaulting without reintroducing a mutating webhook; in-pod CDI OCI hooks are silently lost under gVisor/Kata; and Autopilot prohibits user-deployed DRA drivers.
   - **Native Sidecar with `CAP_NET_ADMIN` (Option 6)**: Dropped. Consumer namespaces enforce PSA `baseline`, which permits only default capabilities and strictly forbids `CAP_NET_ADMIN`.
   - **eBPF (Option 4)**: Deferred. Attaching cgroup `connect4/connect6` socket hooks requires host privileges blocked on Autopilot, risks collisions with GKE Dataplane V2 / Cilium eBPF programs, carries high kernel verifier maintenance overhead, and cannot inject CA certificates into container filesystems.

---

## 2. Comprehensive Comparison Matrices

### 2.1 Architectural & Runtime Class Comparison Matrix

The following matrix evaluates the candidate interception mechanisms against pod visibility, privilege requirements, PSA baseline compatibility, runtime-class support, platform availability, and operational overhead:

| Mechanism | Invisibility (Pod Spec Changes) | Privileges & PSA Baseline / Autopilot Support | Runtime Class Support: runc / gVisor / Kata | Kind & GKE Support (Standard vs Autopilot) | Operational Complexity & Blast Radius |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1. NRI Plugin + Host-Side Enforcement** *(Target Architecture)* | **Highest**: Workload pod needs only an opt-in label (`portals.gke.io/intercept`). | **Node Daemon**: Privileged DaemonSet with `hostPath` to `/var/run/nri/nri.sock`.<br>**Workload**: Zero capabilities (100% PSA **baseline** & **restricted** compliant).<br>**Autopilot**: ❌ Blocked (user NRI plugins forbidden). | **Target (host-side): Preserved across all runtimes**:<br>• `runc`: ✅ Preserved (host veth peer)<br>• `gVisor`: ✅ Preserved (host veth peer)<br>• `Kata`: ✅ Preserved (host tap device)<br>*(Note: Spike #165 was nsenter-based; host-side enforcement is the unbuilt delta in #181)* | **Kind**: ✅ Fully supported (containerd 2.0+ default).<br>**GKE Standard**: ✅ Supported (containerd 1.7+ in GKE 1.29+; containerd 2.0 default `[unverified]` in GKE 1.33+).<br>**GKE Autopilot**: ❌ Blocked. | **Moderate**: Node daemon per node. Blast radius isolated to opted-in pods on that node. |
| **2. DRA Driver + CDI Hooks** *(Dropped, #168)* | **Low**: Requires `spec.resourceClaims` and container `resources.claims` in pod spec, or mutating webhook. | **Node Daemon**: Privileged DRA driver DaemonSet.<br>**Workload**: Zero capabilities.<br>**Autopilot**: ❌ Blocked (user DRA drivers forbidden). | • `runc`: ✅ Preserved<br>• `gVisor`: ❌ **Silently lost** (CDI OCI hook `nsenter` in pod netns ignored by Netstack)<br>• `Kata`: ❌ **Silently lost** (OCI hook inside host netns ignored by guest VM) | **Kind**: ⚠️ Requires kind feature gate `DynamicResourceAllocation` and containerd CDI config.<br>**GKE Standard**: ⚠️ Beta in 1.31–1.32 (KEP-4381; GA timeline `[unverified]`).<br>**Autopilot**: ❌ Blocked. | **Very High**: Severe architectural mismatch (security policy as hardware claim). Heavy claim CRD & scheduler churn. |
| **3. CNI Chaining Plugin** *(Dropped, #166)* | **High**: Pod needs only an opt-in label. | **Node Daemon**: Privileged installer writing to `/etc/cni/net.d` and `/opt/cni/bin`.<br>**Workload**: Zero capabilities.<br>**Autopilot**: ❌ Blocked. | • `runc`: ✅ Preserved<br>• `gVisor`: ❌ **Silently lost** (CNI `nsenter` rules ignored by Netstack)<br>• `Kata`: ❌ **Silently lost** (host netns rules ignored by guest VM) | **Kind**: ✅ Supported.<br>**GKE Standard**: ⚠️ Fragile (conflicts with Dataplane V2 / Cilium conflist reconciliation).<br>**Autopilot**: ❌ Blocked. | **High**: Conflist file overwrites risk node-wide networking outage. Upgrades risk `ETXTBSY`. |
| **4. eBPF (cgroup sock_addr & TC)** *(Deferred)* | **Highest**: Zero changes to pod spec (matches pod cgroup). | **Node Daemon**: Privileged daemon with `CAP_BPF`, `CAP_NET_ADMIN`, `hostPID`.<br>**Workload**: Zero capabilities.<br>**Autopilot**: ❌ Blocked (`CAP_BPF` forbidden). | • `runc`: ✅ Preserved (socket hook)<br>• `gVisor`: ❌ **Silently lost** (Sentry Netstack bypasses host socket hooks)<br>• `Kata`: ❌ **Silently lost** (guest VM kernel sockets not attached to host cgroup) | **Kind**: ⚠️ Requires host cgroup v2 & BPF capabilities.<br>**GKE Standard**: ⚠️ Risk of hook collisions with Dataplane V2 / Cilium.<br>**Autopilot**: ❌ Blocked. | **Very High**: High kernel verifier maintenance cost, kernel version dependency, cannot inject CA bundles. |
| **5. Host-Side for Sandboxed Runtimes** *(Subsumed into #1)* | **Highest**: Zero changes beyond `runtimeClassName` (`gvisor` / `kata`). | **Node Daemon**: Host daemon manipulates host-end `veth` / `tap`.<br>**Workload**: Zero capabilities.<br>**Autopilot**: ❌ User host daemons blocked. | • `runc`: ✅ Preserved (host veth)<br>• `gVisor`: ✅ Preserved (host veth peer)<br>• `Kata`: ✅ Preserved (host tap) | **Kind**: ❌ Kata requires KVM / nested virtualization.<br>**GKE Standard**: ✅ Supported (GKE Sandbox).<br>**Autopilot**: ❌ Custom host daemons blocked. | **Moderate**: Optimal architectural fit for sandboxed runtimes; subsumed into NRI host-side design. |
| **6. Native Sidecar (In-Pod NET_ADMIN)** *(Dropped)* | **Moderate**: Requires webhook to inject sidecar (`restartPolicy: Always`). | **Pod Capability**: Sidecar container requires `CAP_NET_ADMIN`.<br>**PSA Baseline**: ❌ **Strictly violates PSA baseline**.<br>**Autopilot**: ⚠️ Only with `--workload-policies=allow-net-admin`. | • `runc`: ✅ Preserved<br>• `gVisor`: ❌ **Silently lost / fails** (gVisor restricts netns iptables)<br>• `Kata`: ❌ **Silently lost** | **Kind**: ✅ Supported (Kubernetes 1.29+).<br>**GKE Standard**: ✅ Supported.<br>**Autopilot**: ⚠️ Requires specialized cluster flag; rejected in standard tenant namespaces. | **Low**: Standard Kubernetes pod objects, but blocked by standard multi-tenant cluster security policies. |
| **7. Application-Level Only (HTTP_PROXY + NetworkPolicy)** *(Approved Interim & Autopilot, #164)* | **High**: Pod needs proxy env vars and CA mount. Controller-created pods need **zero webhook**. | **Zero Privileges Anywhere**: Workload runs unprivileged (`runAsUser: 1000`, `drop: ["ALL"]`). No node daemons.<br>**PSA Baseline**: ✅ **100% Compliant**.<br>**Autopilot**: ✅ **100% Compliant**. | **Preserved across all runtimes**:<br>• `runc`: ✅ Preserved (NetworkPolicy at host veth)<br>• `gVisor`: ✅ Preserved (NetworkPolicy at host veth peer)<br>• `Kata`: ✅ Preserved (NetworkPolicy at host tap) | **Kind**: ✅ Supported (standard kindnet).<br>**GKE Standard**: ✅ Supported.<br>**GKE Autopilot**: ✅ 100% Supported out of the box with standard cluster settings. | **Lowest**: Zero custom node binaries, zero kernel hooks. Standard Kubernetes manifests and NetworkPolicies. |

---

### 2.2 Security, Threat Model & Attribution Evaluation Matrix

The following matrix compares how each mechanism defends against bypass vectors, spoofing, DNS exfiltration, IPv6 leaks, attribution challenges, and component downtime:

| Evaluation Dimension | 1. NRI Plugin + Host-Side Enforcement *(Target)* | 2. DRA Driver + CDI Hooks *(#168)* | 3. CNI Chaining Plugin *(#166)* | 4. eBPF (cgroup / TC) | 5. Host-Side Sandboxed *(#5)* | 6. Native Sidecar | 7. Application-Level (#164) *(Interim / Autopilot)* |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Runtime Class Interception (runc / gVisor / Kata)** | **Target: Preserved on all**: Rules attached to host-end `vethXXXX` / `tapXXXX` (holds under runc, gVisor, Kata). Prototype spike (#165) installed in-pod via `nsenter --net`; host-side enforcement is the unbuilt delta (#181). | **Silently lost** on gVisor & Kata: CDI `createRuntime` hook enters pod netns via `nsenter` (ignored by Netstack/VM). | **Silently lost** on gVisor & Kata: CNI `ADD` installs rules inside pod netns via `nsenter` (ignored by Netstack/VM). | **Silently lost** on gVisor & Kata: Host cgroup socket hooks do not attach to Sentry or VM kernel sockets. | **Preserved on all**: Host-side redirection attached to host peer interface. | **Silently lost** on gVisor & Kata: In-pod rules inside guest netns do not intercept Sentry/VM traffic. | **Preserved on all**: CNI enforces NetworkPolicy default-deny on the host-end veth/tap for all runtimes. |
| **Bypass Resistance (Root in Container)** | **Unbypassable**: Workload has no `NET_ADMIN`. Cannot see or modify host-side rules on `vethXXXX`. | **Unbypassable**: Workload has no `NET_ADMIN`. Cannot modify rules. | **Unbypassable**: Workload has no `NET_ADMIN`. Cannot modify netfilter rules. | **Unbypassable**: Kernel cgroup hook operates outside container control. | **Unbypassable**: Isolation boundary is the VM/hypervisor. | **Moderate**: Workload dropping privileges cannot bypass, but risk if container escalates to root with `NET_ADMIN`. | **Unbypassable**: If root unsets `HTTP_PROXY`, direct outbound packets are dropped by host NetworkPolicy. |
| **UID-1337 Loop Avoidance Exemption** | **Completely Eliminated**: Proxy runs on host network. No UID exemption exists in the pod network path. | Still present: Hook installs in-pod redirect with `-m owner --uid-owner 1337 RETURN`. | Still present: In-pod redirect requires loop avoidance exemption for local proxy. | **Eliminated**: Socket hook skips redirect if socket belongs to proxy cgroup. | **Completely Eliminated**: Redirect exists only on ingress of `vethXXXX`; proxy sends via `eth0`. | Still present: Sidecar iptables relies on UID-1337 loop avoidance exemption. | **Completely Eliminated**: Explicit proxy requests; no iptables redirect or UID loop avoidance required. |
| **Source-IP Spoofing with `NET_RAW` (PSA Baseline)** | **Prevented**: Node agent maps host `veth` interface and container cgroup directly. `NET_RAW` cannot spoof host veth identity. | **Vulnerable**: If workload retains `NET_RAW`, forged UDP packets can spoof source IP to node proxy. | **Vulnerable**: Forged UDP packets can spoof source IP; TCP handshake required for HTTP/HTTPS. | **Prevented**: Identity derived from kernel `bpf_get_current_cgroup_id()`, unforgeable via raw sockets. | **Prevented**: Host `veth`/`tap` interface maps 1:1 to pod sandbox ID. | **N/A**: In-pod sidecar communication over loopback. | **Prevented**: Per-pod `Proxy-Authorization` token in proxy request header provides cryptographic identity. |
| **DNS Exfiltration through CoreDNS** | **Vulnerable if unaddressed**: In-pod or host-side port 53 allowlist to CoreDNS permits arbitrary forwarding. Requires bounded DNS (#157, #183). | **Vulnerable**: Allows port 53 to CoreDNS, which resolves and forwards arbitrary domains. | **Vulnerable**: Allows port 53 to CoreDNS, which forwards arbitrary external domain queries. | **Mitigated**: eBPF can intercept UDP port 53 and filter DNS queries in-kernel. | **Mitigated**: Host-side filter can intercept DNS queries and forward only to portal DNS router. | **Vulnerable**: In-pod filter allows port 53 to CoreDNS, enabling DNS tunneling. | **Vulnerable unless CoreDNS is restricted (#157)**: NetworkPolicy allows port 53 to CoreDNS (`application-level.md:76`), which forwards arbitrary external domain queries upstream. |
| **IPv6 Leak Prevention** | **Enforced**: Host-side rules include parallel `ip6tables` / `nftables` default-deny on `vethXXXX` (#183). | **Partial**: Prototype installed `ip6tables`, but in-pod rules are lost under sandboxed runtimes. | **Partial**: Requires CNI plugin to install explicit `ip6tables` rules; prototype left IPv6 unfiltered (`cni-plugin.md:21`). | **Enforced**: `sock_addr/connect6` intercepts IPv6 outbound sockets in the kernel. | **Enforced**: Host interface filter applies to both IPv4 and IPv6 traffic. | **Partial**: Requires sidecar entrypoint to configure `ip6tables` in pod netns. | **Enforced**: Dual-stack NetworkPolicy (`ipBlock` / IPv6 pod sets) drops all direct IPv6 egress. |
| **Per-Pod Cost Attribution** | **High**: NRI maintains node-local `pod-to-IP` map + host socket cgroup correlation (#182). | **Moderate**: Claim parameters track pod UID, but dynamic attribution at node proxy requires lookup. | **Difficult**: `CNI_ARGS` lacks labels; proxy must poll API server cache by client IP. | **Native**: Direct cgroup ID lookup in BPF hash map for each connection. | **High**: 1:1 mapping between host `veth`/`tap` and pod sandbox ID. | **Implicit**: 1:1 dedicated proxy per pod; direct billing to pod identity. | **Strong & Cryptographic**: Injected per-pod `Proxy-Authorization` token (#164) validates exact pod identity. |
| **Behavior when Node Proxy is Down** | **Fail-Closed**: Host-side redirect targets local proxy port. If proxy is dead, TCP SYN gets `RST` (connection refused). All other egress dropped. | **Fail-Closed**: In-pod redirect to dead proxy port fails with connection refused; non-intercepted egress rejected. | **Fail-Closed**: Redirect to dead proxy fails with connection refused; egress filter chain drops direct traffic. | **Fail-Closed**: BPF socket hook returns `0` (drop/reject) or redirects to dead port. | **Fail-Closed**: Host-side rules drop egress or redirect to dead proxy port. | **Fail-Closed**: In-pod proxy crash causes pod restart; probes fail. | **Fail-Closed**: Workload connections to proxy fail (`connection refused`); NetworkPolicy drops any direct egress. |

---

## 3. Detailed Technical Evaluation of Each Mechanism

### Mechanism 1: Node Resource Interface (NRI) Plugin + Host-Side Enforcement *(Target Architecture)*
The Node Resource Interface is an open standard (managed under containerd and CRI-O) that enables out-of-tree plugins to subscribe to container lifecycle events.
- **Runtime Availability**: In containerd 2.0+ (the default in kind v0.27+ and Kubernetes 1.32+ `[unverified]`), NRI is compiled in and enabled by default (`disable = false`). On GKE Standard nodes running version 1.29 and later, containerd 1.7+ includes NRI compiled-in ([`docs/design/spikes/nri.md`](spikes/nri.md):118); default enablement without configuration flags is standard in containerd 2.0+ (GKE 1.33+ `[unverified]`).
- **Elimination of the In-Pod UID-1337 Loop Avoidance Exemption**:
  As empirically demonstrated in `docs/design/spikes/nri.md` (lines 122–125), moving the proxy to the host network completely eliminates the UID-1337 exemption. In sidecar mode, an in-pod iptables exemption (`-m owner --uid-owner 1337 -j RETURN`) was required so the proxy could reach upstreams without looping. An attacker escalating to UID 1337 could bypass the proxy. Under the NRI host-side architecture, the proxy runs on the host network outside the pod netns. **No UID exemption exists in the pod network namespace or on the veth interface.** Even if a container process runs as UID 1337, its traffic is unconditionally intercepted.
- **Host-Side Enforcement (Preserving runc, gVisor, and Kata)**:
  Prior prototypes installed iptables rules by executing `nsenter -t <PID> -n iptables` into the pod network namespace. While this works under `runc`, it is **silently lost under gVisor and Kata**.
  To solve this, the NRI plugin coordinates with a host-side network agent:
  1. During `RunPodSandbox`, containerd supplies the pod sandbox ID, metadata, and host networking details.
  2. The agent identifies the host peer interface (`vethXXXX` for runc/gVisor, or `tapXXXX` for Kata) in the host root network namespace.
  3. The agent attaches traffic redirection and default-deny egress rules to the **host end** of the interface (via `tc` clsact or host netfilter/nftables).
  4. Workload packets emitted from `eth0` inside the sandbox must traverse the host-side filter. Whether the sandbox runs user-space Netstack (gVisor) or an internal VM kernel (Kata), outbound traffic cannot escape the host-side enforcement boundary.
  *(Note: The spike prototype in #165 verified the NRI lifecycle hook using in-pod `nsenter`; moving enforcement to the host-side interface is the unbuilt delta tracked in #181).*
- **CA Mount and Env Injection**: During `CreateContainer`, the NRI plugin injects a host bind mount of the node CA certificate directly into `/etc/service-portal/ca/tls.crt` and sets `SSL_CERT_FILE=/etc/service-portal/ca/tls.crt`. The workload pod spec requires zero volume or env declarations.
- **Fail-Closed Mechanics & Daemon Downtime**:
  Any containerd configuration for `default_validator.required_plugins` or the pod annotation `required-plugins.noderesource.dev` is `[unverified]` in standard containerd releases.
  As empirically observed in `nri.md:169`, containerd CRI by default proceeds **without** the plugin (failing open) if an external NRI socket plugin daemon is down or unregistered.
  To address fail-closed requirements, the spike writeup (`nri.md:170–172`) evaluated:
  (A) **Pre-registration under `/opt/nri/plugins`**: Pre-registering binary plugins in `/opt/nri/plugins` causes containerd to spawn the plugin directly and fail pod creation closed if the binary is missing or fails (the caveat that containerd discovers `/opt/nri/plugins` binaries only during initial daemon startup and lacks dynamic rescan on running nodes is `[unverified]`).
  (B) **Node Gate**: A node readiness gate (`nri.service-portal.io/ready=true`) enforced by admission to prevent scheduling intercepted pods to unready nodes.
  
  Building on these findings, this document proposes the following production design:
  1. **Node Taint Gating**: Nodes initialize with the taint `service-portal.gke.io/uninitialized:NoSchedule` (a proposal of this document), which opted-in sandboxes do not tolerate. The NRI DaemonSet tolerates this taint and removes it via the Kubernetes API only after successfully connecting to containerd and completing synchronization.
  2. **`Synchronize` Reconciliation**: As a design proposal of this document, when `portal-node-agent` starts or reconnects, it handles containerd's `Synchronize(pods, containers)` callback to reconcile running sandboxes and re-apply firewall rules and hosts mappings for all opted-in pods.

---

### Mechanism 2: DRA Driver + Container Device Interface (CDI) Hooks *(Dropped - #168)*
Dynamic Resource Allocation replaces legacy device plugins with claims-based resource management (`resource.k8s.io`).
- **Version Status**: DRA was overhauled in Kubernetes 1.30/1.31 with Structured Parameters (KEP-4381) under API group `resource.k8s.io/v1beta1` (Beta in K8s 1.31–1.32, as verified in [`docs/design/spikes/dra-cdi.md`](spikes/dra-cdi.md):40). Previous claims of GA in 1.34/1.37 or GA on GKE Standard in March 2026 are `[unverified]`.
- **Architectural Mismatch & Rejection Rationale**:
  1. **Treating Security Policy as a Hardware Device**: DRA is designed for physical or assignable hardware (GPUs, TPUs, SR-IOV NICs). Modeling network egress policy as an abstract device requires creating a `ResourceClaim` object per sandbox pod, adding substantial API storage overhead and scheduling churn.
  2. **The Defaulting Catch-22**: Kubernetes core cannot default `spec.resourceClaims` onto pods without an admission webhook. Defaulting claims requires a mutating webhook, defeating the core goal of avoiding webhooks.
  3. **Invisibility Bar Not Met**: As documented in `dra-cdi.md:151-158`, the spike prototype did not meet the pod-level invisibility bar: the pod spec still required the sidecar container, `hostPath` CA volumes, rule Secret volumes, and `hostAliases`.
  4. **Hook Failed Open on iptables Error**: While DRA failed closed at the kubelet preparation layer when the driver was unregistered, the prototype CDI OCI hook (`cmd/portal-cdi-hook/main.go:336-345`) logged iptables application errors as warnings and exited with code 0 (`dra-cdi.md:177-187`), allowing runc to start the container unprotected if rule application failed.
  5. **Silent Loss in Sandboxed Runtimes**: CDI OCI `createRuntime` hooks execute `nsenter` into the pod netns from the host, which is silently lost under gVisor and Kata.
  6. **Autopilot Incompatible**: GKE Autopilot strictly forbids third-party DRA drivers and privileged DaemonSets.

---

### Mechanism 3: CNI Chaining Plugin *(Dropped - #166)*
Modeled after `istio-cni`, this mechanism inserts a binary into `/etc/cni/net.d/*.conflist` executed during CNI `ADD`.
- **Rejection Rationale**:
  1. **Provider CNI Conflist Conflicts**: On GKE Dataplane V2 (Cilium-based), the managed CNI agent periodically reconciles and overwrites `/etc/cni/net.d/*.conflist`. Modifying the conflist on disk leads to race conditions, configuration loss, or broken node networking.
  2. **Missing Pod Labels in `CNI_ARGS`**: Containerd passes only `K8S_POD_NAME` and `K8S_POD_NAMESPACE` in `CNI_ARGS`. Determining whether a pod requires interception requires a synchronous HTTP query to `kube-apiserver` during pod creation, creating an API server thundering herd during burst scheduling.
  3. **Threat Model Gaps & Prototype Caveats**: As documented in `cni-plugin.md:21`:
     - The prototype retained the UID-1337 loop avoidance exemption in both `nat` and `filter` tables despite having no in-pod proxy, creating an egress bypass under PSA baseline (`runAsUser: 1337`).
     - IPv6 egress was left completely unfiltered.
     - The bypass verification subtest (`iptables -L`) passed only because the toolbox test image lacked the `iptables` binary.
  4. **Inability to Distribute CA Bundles**: CNI operates strictly at layer 3/4. It cannot inject volume mounts or environment variables into container filesystems.
  5. **Silent Loss in Sandboxed Runtimes**: Rules installed inside `CNI_NETNS` do not intercept Netstack (gVisor) or microVM (Kata) traffic.
  6. **Autopilot Incompatible**: Host paths to `/etc/cni/net.d` and `/opt/cni/bin` are rejected on GKE Autopilot.

---

### Mechanism 4: eBPF (cgroup sock_addr & Traffic Control) *(Deferred)*
eBPF programs attached to pod cgroups via `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` intercept outbound `connect()` system calls in the kernel.
- **Evaluation & Rejection Rationale**:
  1. **High Verifier & Kernel Maintenance Cost**: Supporting eBPF across varying Linux kernels, COS releases, and kind environments introduces significant engineering maintenance.
  2. **Collision with Dataplane V2 / Cilium**: GKE Dataplane V2 heavily utilizes eBPF on host cgroups. Chaining custom socket hooks risks verifier conflicts or hook overwrites.
  3. **No CA Distribution**: eBPF cannot inject CA certificates into container filesystems.
  4. **Silent Loss on MicroVMs**: Guest VM sockets (Kata) and Sentry Netstack sockets (gVisor) bypass host cgroup socket hooks.
  5. **Autopilot Incompatible**: `CAP_BPF` and host cgroup access are prohibited on Autopilot.

---

### Mechanism 5: Host-Side Interception for Sandboxed Runtimes *(Subsumed into Mechanism 1)*
When sandboxes run under specialized isolation runtimes (`runtimeClassName: gvisor` in GKE Sandbox, or `runtimeClassName: kata` in Kata Containers):
- **gVisor (runsc)**: Uses Netstack in userspace; outbound traffic is emitted via an `AF_PACKET` socket to a `veth` pair (`eth0` in sandbox, `vethXXXX` on host).
- **Kata / MicroVMs**: The guest VM kernel connects via a virtual `tapXXXX` interface on the host.
- **Architectural Fit**: Moving redirection and egress filtering to the **host end** of the interface (`vethXXXX` or `tapXXXX`) provides unbypassable isolation:
  - Guest processes have zero access to host routing or iptables.
  - Interception holds identically across `runc`, `gVisor`, and `Kata`.
  - Subsumed as the network enforcement mechanism for the NRI plugin (Mechanism 1).

---

### Mechanism 6: Native Sidecar (In-Pod NET_ADMIN) *(Dropped)*
Kubernetes 1.29+ natively supports sidecar containers (`initContainers` with `restartPolicy: Always`). User namespaces (`hostUsers: false`) graduated to Beta in K8s 1.30 (KEP-127; claims of GA in 1.36 are `[unverified]`).
- **Rejection Rationale**:
  1. **Strict Violation of PSA Baseline**: Standard consumer and multi-tenant namespaces enforce PSA `baseline`. PSA `baseline` permits only default capabilities, strictly forbidding `CAP_NET_ADMIN`. While GKE Autopilot supports an optional flag (`--workload-policies=allow-net-admin`), consumer namespaces running standard baseline policies cannot deploy pods requesting `CAP_NET_ADMIN`.
  2. **Silent Loss under gVisor**: In-pod iptables rules configured by the native sidecar are ignored by gVisor's Netstack.
  3. **Retains UID-1337 Exemption**: Inside the shared pod network namespace, the sidecar still relies on UID-1337 loop avoidance.

---

### Mechanism 7: Application-Level Only (HTTP_PROXY + NetworkPolicy) *(Approved Interim & Autopilot Path - #164)*
Option 7 establishes a zero-privilege interception and egress enforcement model:
1. **Workload Environment**: The workload pod runs completely unprivileged (`runAsUser: 1000`, `drop: ["ALL"]`, `allowPrivilegeEscalation: false`). No init container, no `NET_ADMIN`.
2. **Proxy Environment Injection**: Standard proxy variables (`HTTP_PROXY`, `HTTPS_PROXY`, `http_proxy`, `https_proxy`, `NO_PROXY`, `no_proxy`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`) are configured on workload containers.
3. **Egress NetworkPolicy Enforcement**: A standard Kubernetes `NetworkPolicy` isolates the sandbox pod:
   - External egress to `0.0.0.0/0` is **denied by default**.
   - Egress is permitted **only** to the proxy endpoint (TCP port 8080) and cluster CoreDNS (UDP/TCP port 53).
4. **Explicit Proxy Support & Open-Relay / MITM Host Check (#127)**:
   In explicit proxy mode, clients issue `CONNECT target:443` or absolute-form `GET http://target/`. As resolved in [#164](https://github.com/gke-labs/service-portals/pull/164), `HTTPProxy` matches `ListenHost` to ensure target rewriting and credential injection execute seamlessly for explicit proxy requests. In addition, `proxyRequest` validates that inner HTTP request hosts match the `CONNECT` tunnel target, closing the MITM host escape / open-relay loophole.
5. **Controller-Created Pods Require Zero Webhooks**:
   For consumers or automated orchestrators (LLM sandbox managers, CI runners) that build Pod specifications programmatically, proxy environment variables, CA volume projections, and per-pod authentication tokens can be written **directly into the Pod manifest**. No admission webhook is required.
6. **Per-Pod Cost Attribution**:
   The proxy URL includes a per-pod authentication token (`http://<pod-token>:x@service-portal:8080`). Clients automatically transmit `Proxy-Authorization: Basic <base64>`, which the proxy validates and strips before upstream dispatch, providing tamper-proof cost attribution.

---

## 4. Cross-Cutting Architectural Concerns

### 4.1 Per-Pod Identity, Source-IP Spoofing & Cost Attribution
When a proxy is shared outside the pod (per-node DaemonSet or namespace service):
- **Refuting the kindnet Anti-Spoofing Claim**:
  Prior text claimed that kindnet enforces source-IP anti-spoofing via eBPF or `rp_filter`. **This claim is unsupported.** Under kindnet (`ptp` CNI with `kube-network-policies`), eBPF source-IP anti-spoofing is not implemented. Furthermore, PSA `baseline` permits `CAP_NET_RAW`. A workload container retaining `CAP_NET_RAW` can forge source IPs on raw frames or UDP packets.
- **The Interim Attribution Solution (Application-Level, [#164](https://github.com/gke-labs/service-portals/pull/164))**:
  Workloads transmit a per-pod `Proxy-Authorization` token in the proxy request header. The proxy validates the token against its pod registry, establishing authenticated pod identity for tenant quota, rate-limiting, and LLM billing without relying on client source IP.
- **The Node Agent Attribution Solution (NRI Target Architecture, #182)**:
  The NRI plugin receives pod sandbox metadata (`Pod UID`, `Namespace`, `Name`, `IP`, `CgroupParent`) synchronously during `RunPodSandbox`. The node daemon populates an in-memory **pod-to-IP map**. When a connection arrives at the node proxy listener, the proxy resolves the client IP against the local NRI map, or queries the host socket cgroup ID (`SO_ORIGINAL_DST` / eBPF socket cookie) to verify the pod cgroup directly on the host socket.

### 4.2 CA Certificate Distribution Without a Webhook
- **`ClusterTrustBundle`**: `ClusterTrustBundle` was introduced as an Alpha feature in Kubernetes 1.27 (`certificates.k8s.io/v1alpha1`). Claims that `ClusterTrustBundle` graduated to GA in upstream K8s 1.37 and GKE 1.37 (`certificates.k8s.io/v1`) are `[unverified]`. Where available, projected volumes can mount cluster trust anchors:
  ```yaml
  volumes:
  - name: ca-bundle
    projected:
      sources:
      - clusterTrustBundle:
          name: portal-root-ca
          path: tls.crt
  ```
- **NRI Container Adjustments**: The NRI plugin injects host CA bind mounts into `/etc/service-portal/ca/tls.crt` during `CreateContainer`, requiring zero volume declarations in the pod spec.
- **Controller-Created Pods**: Controllers generating pod manifests inject standard `Secret` or `ConfigMap` volume mounts directly.

### 4.3 Runtime Class Isolation (runc vs gVisor vs Kata)
- **Why In-Pod `nsenter` Fails Under Sandboxed Runtimes**:
  The nsenter-based variants (NRI as spiked, DRA, CNI) entered the pod netns via `nsenter -t <PID> -n iptables`.
  - Under **gVisor (`runsc`)**, Netstack runs inside the unprivileged Sentry process in user space. Netstack emits raw Ethernet packets directly to the host `veth` endpoint via `AF_PACKET`, completely bypassing Linux netfilter tables in the sandbox network namespace.
  - Under **Kata Containers**, the application runs inside an isolated microVM with its own guest Linux kernel. Rules injected into the host-side container netns have zero visibility or effect inside the guest kernel.
  In both runtimes, in-pod netfilter rules are **silently lost**, allowing outbound traffic to bypass the proxy.
- **Host-Side Enforcement as the Solution (#181)**:
  Redirection and egress drop filters must be installed on the **host peer interface** (`vethXXXX` or `tapXXXX`) in the host root network namespace. Traffic exiting the sandbox must cross the host interface, guaranteeing that interception holds uniformly under `runc`, `gVisor`, and `Kata`.

### 4.4 Loop Avoidance Mechanics & UID-1337 Elimination
| Method | Where Applied | Risk Profile |
| :--- | :--- | :--- |
| **UID 1337 Exemption (Status Quo)** | In-pod iptables | **Vulnerable**: Workload running as or switching to UID 1337 completely bypasses interception. |
| **Host-Side Interface Routing (NRI Target)** | Host `vethXXXX` / `tapXXXX` | **Zero Risk**: Redirection rule applies strictly to ingress traffic arriving on `vethXXXX`. Outbound proxy traffic leaves physical `eth0`. **The UID-1337 exemption is completely eliminated.** |
| **Explicit HTTP(S)_PROXY (Interim)** | Application layer | **Zero Risk**: Workload connects explicitly to proxy listener; proxy establishes direct upstream connection. |

### 4.5 DNS Exfiltration through CoreDNS
- **The Threat**:
  The nsenter-based variants (NRI as spiked, DRA, CNI) permit outbound UDP/TCP port 53 to cluster CoreDNS (`10.96.0.10:53`). Because CoreDNS by default forwards unhandled domain queries to upstream resolvers, an untrusted workload can exfiltrate sensitive data via DNS tunneling (e.g., encoding secrets in queries like `<encoded-data>.attacker.com`).
- **Mitigation & Evaluation in Service Portals**:
  1. **Application-Level Model (#164)**: While HTTP(S) proxy clients delegate hostname resolution to the proxy upstream, the workload NetworkPolicy still permits outbound UDP/TCP port 53 to cluster CoreDNS (`application-level.md:76`). Because CoreDNS by default forwards unhandled domain queries to upstream resolvers, the workload remains vulnerable to DNS tunneling unless CoreDNS or cluster DNS egress is restricted (tracked in #157).
  2. **Sidecar / Node DNS (#157, #183)**: For transparent interception, CoreDNS or a node-local DNS proxy intercepts port 53 and resolves only explicitly declared `PortalRule` hostnames, returning `NXDOMAIN` or `REFUSED` for arbitrary external queries.

### 4.6 IPv6 Handling & Dual-Stack Leak Prevention
If IPv6 is enabled in the cluster or node kernel but egress filtering rules apply only to IPv4 (`iptables`), a compromised workload can bypass interception by connecting to external destinations over IPv6.
- **Enforcement**:
  - In NRI host-side enforcement, parallel `ip6tables` or unified `nftables inet` rules are attached to `vethXXXX` to reject all non-intercepted IPv6 egress ([#183](https://github.com/gke-labs/service-portals/issues/183)).
  - In Application-Level mode, the default-deny `NetworkPolicy` specifies dual-stack egress policies (`ipBlock` cidrs covering both `0.0.0.0/0` and `::/0`).

### 4.7 Failure Modes & Downtime Behavior
| Failure Scenario | NRI + Host-Side (Target) | Application-Level (Interim) |
| :--- | :--- | :--- |
| **Hook / Webhook Down** | **NRI**: By default without plugin, containerd proceeds without hooks (`nri.md:169`). Fail-Closed achieved via pre-registration (`/opt/nri/plugins`) or proposed node taint gating (`service-portal.gke.io/uninitialized:NoSchedule`). Unverified `required_plugins` validator configuration. | Fail-Closed: Pod creation fails (`failurePolicy: Fail`), or starts unconfigured where NetworkPolicy drops all egress. |
| **Node Proxy Daemon Down** | Fail-Closed: Outbound connections to redirected ports receive `TCP RST` (connection refused). All other egress is dropped by host filter. | Fail-Closed: Workload connections to proxy receive `TCP RST`. All direct egress is dropped by NetworkPolicy. |
| **Workload Unsets Proxy Env** | N/A (Transparent host-side redirect). | Fail-Closed: Direct connection attempts are dropped by host NetworkPolicy. |
| **NetworkPolicy Disabled** | N/A (Host-side netfilter enforced). | Fail-Open: Workload can connect directly to upstreams (requires namespace policy automation). |

---

## 5. Strategic Implementation Plan & Decision Roadmap

```
+-------------------------------------------------------------------------------+
| PHASE 1: INTERIM & AUTOPILOT (IMMEDIATE)                                      |
|                                                                               |
|  Application-Level Interception (#164)                                        |
|  • Workload: Zero capabilities (runAsUser: 1000, drop: ["ALL"]).              |
|  • Pod Spec: Proxy env vars + CA volume + Proxy-Authorization token.          |
|  • Enforcement: Kubernetes NetworkPolicy default-deny on egress.              |
|  • Controller Pods: Build spec directly with NO webhook required.             |
|  • Platform: 100% GKE Autopilot & PSA baseline compliant today.               |
+-------------------------------------------------------------------------------+
                                       │
                                       ▼
+-------------------------------------------------------------------------------+
| PHASE 2: TARGET ARCHITECTURE (BUILD FIRST)                                    |
|                                                                               |
|  containerd NRI Plugin + Host-Side veth/tap Enforcement (#181, #182, #183)    |
|  • Lifecycle Hook: containerd NRI daemon (/var/run/nri/nri.sock).             |
|  • Network Enforcement: Host-side filter on vethXXXX / tapXXXX (#181).        |
|  • Pod Attribution: NRI pod map resolves calling pods at node proxy (#182).   |
|  • Dual-Stack & DNS: IPv6 filtering + bounded DNS resolution (#183).          |
|  • Runtime Support: Uniformly preserves runc, gVisor, and Kata.               |
|  • Security: Zero in-pod privileges; eliminates UID-1337 loop avoidance.     |
|  • Platform: GKE Standard & bare-metal Kubernetes.                            |
+-------------------------------------------------------------------------------+
                                       │
                                       ▼
+-------------------------------------------------------------------------------+
| PHASE 3: DEPRECATION & REMOVAL                                                |
|                                                                               |
|  Retire Status Quo In-Pod Init Container                                      |
|  • Coexistence flag: portals.gke.io/interception-mode                         |
|  • Cutover automated controllers to app-level / NRI modes.                    |
|  • Deprecate and remove init-service-portals container image.                 |
+-------------------------------------------------------------------------------+
```

### 5.1 Build First: NRI Plugin with Host-Side Enforcement
The primary production architecture for high-density sandbox environments on GKE Standard:
1. **Node DaemonSet (`portal-node-agent`)**:
   - Deploys as a DaemonSet mounting `/var/run/nri/nri.sock` and registering with containerd.
   - Listens on host network ports 8080 (HTTP) and 8443 (HTTPS) with host CA credentials.
2. **Host-Side Redirection & Filter (#181)**:
   - Subscribes to `RunPodSandbox` to capture the pod sandbox ID and host interface name.
   - Attaches netfilter / `tc` rules to the host peer interface (`vethXXXX` or `tapXXXX`):
     - Redirect TCP 80 -> host 8080.
     - Redirect TCP 443 -> host 8443.
     - Allow host proxy ports and cluster DNS.
     - Default-deny all other TCP/UDP egress.
3. **CA Mount Injection**:
   - Subscribes to `CreateContainer` to inject the host CA certificate bind mount and `SSL_CERT_FILE` into container adjustments.
4. **Attribution & Pod Resolution (#182)**:
   - Maintains an in-memory pod-to-IP map populated during `RunPodSandbox` for per-pod quota, policy lookup, and credential routing.
5. **IPv6 Parity & Bounded DNS (#183)**:
   - Installs dual-stack drop rules on the host interface and restricts DNS resolution to declared policy hosts.

### 5.2 Interim Path & Autopilot: Application-Level Interception
The production path for GKE Autopilot and immediate zero-privilege deployment:
1. **NetworkPolicy Generation**: Automatically deploy a namespace-level default-deny egress `NetworkPolicy` permitting traffic only to the proxy service and CoreDNS.
2. **Explicit Proxy Routing**: Workloads use standard `HTTP_PROXY` and `HTTPS_PROXY` variables.
3. **Cryptographic Pod Identity**: Workloads include a per-pod `Proxy-Authorization` token in the proxy URL, ensuring accurate attribution even if workloads possess `CAP_NET_RAW`.
4. **Explicit Proxy Rule Router**: Leverage `ListenHost` matching in `HTTPProxy` (from [#164](https://github.com/gke-labs/service-portals/pull/164)) to handle `CONNECT` tunnels and absolute-form HTTP requests, verifying inner hosts match the `CONNECT` target.

### 5.3 Controller-Created Pods: Webhook-Free Integration
Automated controllers (e.g., LLM sandbox dispatchers, execution runners, CI worker pools) that construct `Pod` manifests directly **do not need a mutating admission webhook**.
The controller directly writes into the pod spec:
- Container `env`: `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`.
- Container `volumeMounts`: CA certificate secret or projected volume.
- Proxy URL: `http://<per-pod-token>:x@service-portal.<ns>.svc:8080`.
This eliminates webhook downtime dependencies and accelerates sandbox scheduling.

### 5.4 The Acceptance Bar (Quality Gate)
Before any interception mechanism graduates to default status, it must satisfy the unified acceptance suite:
1. **The #147 Deny Test Suite**: All 10 negative and positive assertions must pass:
   - Direct IP HTTP/HTTPS requests blocked.
   - Unlisted hostname HTTP/HTTPS requests blocked.
   - Non-intercepted TCP/UDP ports rejected immediately.
   - Arbitrary external DNS (e.g., 8.8.8.8) blocked.
   - Positive control verified (credential swap + TLS verification).
   - Workload privilege escalation to proxy UID 1337 prevented.
2. **MicroVM & Sandboxed Runtime Verification**:
   - Interception must be verified under `runtimeClassName: gvisor` (`runsc`) and `runtimeClassName: kata`.
   - Confirms zero silent loss of rules through Netstack or guest VM interfaces.
3. **IPv6 Leak Prevention**:
   - Verifies that direct IPv6 connections (`curl -6 http://[...]`) fail closed.
4. **DNS Exfiltration Prevention**:
   - Verifies that external domain queries forwarded through CoreDNS cannot be used to leak data.
5. **Per-Pod Cost Attribution with `CAP_NET_RAW`**:
   - Verifies that an untrusted pod possessing `CAP_NET_RAW` (allowed under PSA baseline) cannot spoof another pod's identity or hijack another tenant's credentials.

### 5.5 Migration & Cutover Strategy
1. **Coexistence Flag**:
   Support the annotation `portals.gke.io/interception-mode`:
   - `init-container` (Status quo, deprecated)
   - `app-level` (Interim / Autopilot)
   - `nri-host` (Target NRI architecture)
2. **Controller Cutover**:
   Update automated sandbox orchestrators to emit `app-level` pod specifications directly with per-pod `Proxy-Authorization` tokens.
3. **Node Pool Deployment**:
   Deploy the `portal-node-agent` DaemonSet onto GKE Standard node pools running containerd 2.0+.
4. **Deprecation & Removal**:
   Once NRI host-side enforcement and application-level modes are validated in production, deprecate and remove the `init-service-portals` init container image and associated `CAP_NET_ADMIN` requirements.

---

## 6. Empirical Findings from the Four Spikes

To evaluate the candidates empirically, four separate spike prototypes were developed, tested, and documented against the full #147 default-deny egress test suite on `kind`:

### 6.1 Spike 1: Application-Level Interception ([#164](https://github.com/gke-labs/service-portals/pull/164))
* **Tracking Issue**: [#162](https://github.com/gke-labs/service-portals/issues/162) | **Branch**: `spike/application-level` | **Document**: [`docs/design/spikes/application-level.md`](spikes/application-level.md)
* **Architecture**: Unprivileged pod (UID 1000, `drop: ["ALL"]`, zero capabilities) configured with proxy env vars and default-deny Kubernetes `NetworkPolicy`.
* **Empirical Test Suite**: `TestApplicationLevelEgressDenied` passed all assertions cleanly:
  ```text
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
  ```
* **Key Findings**:
  - Unsetting proxy environment variables inside the workload fails closed: direct packets are dropped by host NetworkPolicy netfilter rules.
  - Resolved explicit proxy handling (#127) via `ListenHost` matching in `HTTPProxy`.
  - Proved per-pod `Proxy-Authorization` token authentication for cryptographic identity.
  - Closed MITM host escape / open relay by verifying inner HTTP hosts match the `CONNECT` target.
  - Discovered that on kindnet, packets destined to local node IP (`172.18.0.2:6443`) bypass `postrouting` NetworkPolicy hooks, highlighting the need for node firewall rules on certain CNIs.
  - **DNS Exfiltration**: While proxy clients delegate external hostname resolution to the proxy upstream, CoreDNS remains reachable over port 53 (`application-level.md:76`) and forwards arbitrary external domain queries, necessitating CoreDNS policy controls (#157).

### 6.2 Spike 2: containerd NRI Plugin ([#165](https://github.com/gke-labs/service-portals/pull/165))
* **Tracking Issue**: [#161](https://github.com/gke-labs/service-portals/issues/161) | **Branch**: `spike/nri` | **Document**: [`docs/design/spikes/nri.md`](spikes/nri.md)
* **Architecture**: Node-level DaemonSet connecting to containerd `/var/run/nri/nri.sock` via `github.com/containerd/nri/pkg/stub`. Subscribes to `RunPodSandbox` and `CreateContainer`.
* **Empirical Test Suite**: `TestNRIPluginEgressDenied` passed all 10 assertions:
  ```text
  === RUN   TestNRIPluginEgressDenied
      --- PASS: TestNRIPluginEgressDenied/DirectIP_InterceptedPort_HTTP (0.17s)
      --- PASS: TestNRIPluginEgressDenied/DirectIP_InterceptedPort_HTTPS (0.17s)
      --- PASS: TestNRIPluginEgressDenied/UnlistedHostname_InterceptedPort_HTTP (0.15s)
      --- PASS: TestNRIPluginEgressDenied/UnlistedHostname_InterceptedPort_HTTPS (0.18s)
      --- PASS: TestNRIPluginEgressDenied/NonInterceptedPort_HTTP_8080 (1.21s)
      --- PASS: TestNRIPluginEgressDenied/NonInterceptedPort_RawTCP_9999 (0.10s)
      --- PASS: TestNRIPluginEgressDenied/ArbitraryDNS_Blocked (0.21s)
      --- PASS: TestNRIPluginEgressDenied/ClusterDNS_Allowed (0.22s)
      --- PASS: TestNRIPluginEgressDenied/PositiveControl_GeminiHTTPS (0.25s)
      --- PASS: TestNRIPluginEgressDenied/BypassAttempt_Disallowed (0.32s)
  PASS
  ```
* **Key Findings & Unbuilt Delta**:
  - **Eliminated the UID-1337 exemption**: Proxy runs on host network; workload traffic is unconditionally DNAT'd to the node proxy.
  - Workload pod spec is **100% invisible**: zero init containers, zero sidecars, zero capabilities, zero volume mounts.
  - Confirmed containerd 2.0+ on kind v0.27.0 enables NRI out of the box without configuration patches.
  - DaemonSets mounting `/run/netns` require `mountPropagation: HostToContainer` to see dynamically created CNI netns mount points.
  - **nsenter Limitation & Host-Side Delta (#181)**: The prototype spike installed rules with `nsenter --net=<netnsPath> iptables` into the pod network namespace (`nri.md:69, 114, 183`). Like DRA and CNI, in-pod netns rules do not intercept traffic under gVisor Netstack or Kata microVMs. Transitioning enforcement to the host-side `vethXXXX` / `tapXXXX` peer interface is the unbuilt delta tracked in [#181](https://github.com/gke-labs/service-portals/issues/181).

### 6.3 Spike 3: Chained CNI Plugin ([#166](https://github.com/gke-labs/service-portals/pull/166))
* **Tracking Issue**: [#163](https://github.com/gke-labs/service-portals/issues/163) | **Branch**: `spike/cni-plugin` | **Document**: [`docs/design/spikes/cni-plugin.md`](spikes/cni-plugin.md)
* **Architecture**: Binary (`service-portal-cni`) chained into `/etc/cni/net.d/10-kindnet.conflist`, executed synchronously during CNI `ADD`.
* **Empirical Test Suite & Prototype Deficiencies**:
  - `TestCNIPluginEgressDenied` passed the test assertions, but the spike report (`cni-plugin.md:21`) revealed significant deficiencies:
    1. **Bypass Subtest False Positive**: The bypass verification subtest (`iptables -L`) passed trivially only because the toolbox test image lacked the `iptables` binary.
    2. **UID-1337 Exemption Retained**: The plugin retained the UID-1337 exemption in both `nat` and `filter` tables despite having no in-pod proxy, leaving an egress bypass under PSA baseline (`runAsUser: 1337`).
    3. **IPv6 Left Unfiltered**: Only IPv4 rules were configured; IPv6 traffic remained completely unfiltered.
    4. **Sandboxed Runtimes Unprotected**: Rules installed in `CNI_NETNS` are silently bypassed by gVisor Netstack and Kata VM kernels.
  - **Fatal Drawbacks**: CNI conflists are actively reconciled by managed CNIs (GKE Dataplane V2 / Cilium); `CNI_ARGS` lacks pod labels, forcing synchronous API calls; CNI cannot distribute CA certificates; and Autopilot disallows host CNI modifications.

### 6.4 Spike 4: DRA Driver + CDI Hooks ([#168](https://github.com/gke-labs/service-portals/pull/168))
* **Tracking Issue**: [#160](https://github.com/gke-labs/service-portals/issues/160) | **Branch**: `spike/dra-cdi` | **Document**: [`docs/design/spikes/dra-cdi.md`](spikes/dra-cdi.md)
* **Architecture**: Node DRA driver registering via kubelet plugin registration, returning CDI specs with OCI `createRuntime` hooks.
* **Empirical Test Suite & Prototype Deficiencies**:
  - `TestDRAEgressDenied` passed deny assertions, but the writeup (`dra-cdi.md:151-158, 177-187`) noted critical shortcomings:
    1. **Hook Failed Open on iptables Error**: While DRA failed closed at the kubelet scheduling/preparation layer when the driver was unregistered (`FailedPrepareDynamicResources`), the prototype CDI OCI hook (`cmd/portal-cdi-hook/main.go:336-345`) logged iptables application errors as warnings and exited with code 0 (`dra-cdi.md:177-187`), allowing runc to launch the container unprotected if iptables failed.
    2. **Invisibility Bar Not Met**: Full pod spec invisibility was not achieved (`dra-cdi.md:151-158`). The test pod still had to explicitly declare the `service-portal-sidecar` container, a `hostPath` volume for CA keys, a `Secret` volume for rules, and `hostAliases` for backend mapping.
    3. **Severe Conceptual Mismatch**: Modeling egress security policy as a hardware device creates high scheduling and claim storage churn.
    4. **Sandboxed Runtimes Unprotected**: In-pod CDI OCI hooks executing `nsenter` are silently lost under gVisor Netstack and Kata VM kernels.
