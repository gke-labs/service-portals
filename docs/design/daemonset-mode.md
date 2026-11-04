# Design: Per-Node (DaemonSet) Mode via NRI and Host-Side Enforcement

**Author**: codebot-robot / justinsb  
**Status**: Decision Record & Implementation Architecture  
**Date**: November 2026  
**Target Path**: `docs/design/daemonset-mode.md`  
**Tracking Issue**: [#151](https://github.com/gke-labs/service-portals/issues/151)  
**Related Issues & Decisions**:
- Decision Record: [#167](https://github.com/gke-labs/service-portals/pull/167) (`docs/design/interception-mechanisms.md`)
- Related Spikes: [#161](https://github.com/gke-labs/service-portals/issues/161) / [#165](https://github.com/gke-labs/service-portals/pull/165) (containerd NRI Plugin), [#163](https://github.com/gke-labs/service-portals/issues/163) / [#166](https://github.com/gke-labs/service-portals/pull/166) (Chained CNI), [#162](https://github.com/gke-labs/service-portals/issues/162) / [#164](https://github.com/gke-labs/service-portals/pull/164) (Application-Level)
- Core Follow-Ups: [#181](https://github.com/gke-labs/service-portals/issues/181) (Host-Side Enforcement Delta on `veth`/`tap`), [#182](https://github.com/gke-labs/service-portals/issues/182) (Pod Identity & Authentication at Proxy), [#97](https://github.com/gke-labs/service-portals/issues/97) / [#99](https://github.com/gke-labs/service-portals/issues/99) (Dynamic Configurator), [#147](https://github.com/gke-labs/service-portals/issues/147) (Deny Suite), [#149](https://github.com/gke-labs/service-portals/issues/149) (`PortalPolicy` CRD)

---

## 1. Executive Summary & Context

`service-portals` intercepts outbound network calls from untrusted or semi-trusted application sandboxes (e.g., AI agents, evaluation runners, CI jobs) and swaps placeholder credentials with real API tokens while strictly dropping unauthorized egress traffic ("Tokens that aren't there can't leak").

### The Initial Path and the PSA Baseline Blocker
The project initially investigated two deployment models:
1. **Transparent In-Pod Sidecar Mode** ([#147](https://github.com/gke-labs/service-portals/issues/147), [#148](https://github.com/gke-labs/service-portals/issues/148), [#150](https://github.com/gke-labs/service-portals/issues/150)): Each pod runs an `init-service-portals` init container with `CAP_NET_ADMIN` to configure in-pod `iptables` redirection rules and an ephemeral Root CA, followed by an `all-in-one-portal` sidecar container as UID 1337.
2. **Early DaemonSet Mode Proposals**: Evaluated CNI chaining ([#166](https://github.com/gke-labs/service-portals/pull/166)) or host `nsenter` node agents to steer traffic to a per-node proxy.

However, comparative evaluation across architectural spikes ([#159](https://github.com/gke-labs/service-portals/issues/159), recorded in [#167](https://github.com/gke-labs/service-portals/pull/167)) established that:
- **The PSA Baseline Constraint Disqualifies In-Pod `NET_ADMIN`**: Standard multi-tenant clusters enforce Kubernetes Pod Security Admission (PSA) at the `baseline` level [unverified: Kubernetes Pod Security Standards]. PSA `baseline` strictly prohibits `CAP_NET_ADMIN` in pod manifests. Requiring `CAP_NET_ADMIN` prevents deployment in standard consumer namespaces without cluster-wide policy exemptions.
- **In-Pod Rules Fail Silently under Sandboxed Runtimes (gVisor & Kata)**: Rules installed inside the container network namespace are ignored by gVisor's userspace Netstack and Kata microVM guest kernels, allowing egress to leak unintercepted.
- **CNI Chaining Conflicts with Managed CNIs**: Spiked in [#166](https://github.com/gke-labs/service-portals/pull/166) ([`docs/design/spikes/cni-plugin.md`](spikes/cni-plugin.md)), CNI chaining was dropped due to conflist ownership conflicts with GKE Dataplane V2 / Cilium `cni-exclusive` mode [unverified], missing pod labels in `CNI_ARGS`, and inability to distribute CA bundles.
- **The UID-1337 Loop Exemption Creates a Bypass**: In-pod iptables requires exempting proxy traffic (`-m owner --uid-owner 1337 -j RETURN`). Because PSA `baseline` permits `runAsUser: 1337` [unverified: Kubernetes Pod Security Standards], any workload container running as UID 1337 completely bypasses interception.

### The Recorded Architectural Decision
As recorded in [#167](https://github.com/gke-labs/service-portals/pull/167), we **are** building a **Per-Node (DaemonSet) Mode on containerd Node Resource Interface (NRI) with Host-Side Enforcement ([#181](https://github.com/gke-labs/service-portals/issues/181))** for GKE Standard and self-managed Kubernetes clusters, complemented by an **Application-Level Interception** path ([#164](https://github.com/gke-labs/service-portals/pull/164)) for GKE Autopilot.

This document details the concrete architecture for the NRI per-node path, covering:
1. Redirection via NRI and host-side interface hooks (pointing to [#167](https://github.com/gke-labs/service-portals/pull/167)),
2. Runtime class uniformity across standard `runc`, `gVisor`, and `Kata Containers`,
3. Pod identity and caller authentication at the proxy ([#182](https://github.com/gke-labs/service-portals/issues/182)),
4. CA certificate distribution without mutating admission webhooks,
5. Secrets scope, multi-tenant blast radius, and the Dynamic Configurator ([#97](https://github.com/gke-labs/service-portals/issues/97) / [#99](https://github.com/gke-labs/service-portals/issues/99)),
6. Loop avoidance and elimination of the UID-1337 bypass vulnerability via host-side enforcement ([#181](https://github.com/gke-labs/service-portals/issues/181); `[unverified until #181]`),
7. Fail-closed failure semantics under agent and node startup scenarios.

---

## 2. Architecture: NRI Node Agent with Host-Side Enforcement

```
Workload Sandboxes (0 Linux Capabilities, PSA Baseline & Restricted Compliant)
+--------------------------------------+       +--------------------------------------+
| Pod A (Namespace: tenant-a)          |       | Pod B (Namespace: tenant-b)          |
| Runtime: runc / gVisor / Kata        |       | Runtime: runc / gVisor / Kata        |
|                                      |       |                                      |
|  +--------------------------------+  |       |  +--------------------------------+  |
|  | Workload Container (UID 1000)  |  |       |  | Workload Container (UID 1000)  |  |
|  | • 0 Caps (no NET_ADMIN)        |  |       |  | • 0 Caps (no NET_ADMIN)        |  |
|  | • SSL_CERT_FILE (NRI injected) |  |       |  | • SSL_CERT_FILE (NRI injected) |  |
|  +----------------+---------------+  |       |  +----------------+---------------+  |
+-------------------|------------------+       +-------------------|------------------+
                    | eth0                                         | eth0
                    |                                              |
====================|==============================================|===================
Host Network        v veth-a / tap-a                               v veth-b / tap-b
Namespace           +------------------------------+               +------------------+
(netns_host)        | Host-Side Filter & Redirect  |               | Host-Side Filter |
                    | (veth-a peer in netns_host)  |               | & Redirect       |
                    | • TCP 80/443 -> Host :8080/8443              |                  |
                    | • Egress Drop (Non-Intercept)|               +--------+---------+
                    +--------------+---------------+                        |
                                   |                                        |
                                   v Redirected TCP Traffic                 v
+-------------------------------------------------------------------------------------+
| Node DaemonSet (portal-node-agent / cmd/daemonset-portal)                           |
|                                                                                     |
|  [NRI Lifecycle Plugin] (/var/run/nri/nri.sock)                                     |
|  • RunPodSandbox: Captures pod metadata, identifies host interface (veth/tap)      |
|  • CreateContainer: Injects host CA bind mount & SSL_CERT_FILE via ContainerAdjust |
|                                                                                     |
|  [Multi-Tenant Proxy Engine] (:8080 HTTP / :8443 HTTPS)                             |
|  • Caller Authentication: Resolves Source IP & Host cgroup ID -> Pod Identity (#182)|
|  • Loop Avoidance: Ingress on veth redirected; proxy egress leaves via eth0         |
|  • Direct Connection Drop: Rejects un-redirected connections (SO_ORIGINAL_DST)     |
|  • Dynamic Configurator (#97/#99): JIT secret delivery; RAM zeroing on Pod Stop    |
+------------------------------------------+------------------------------------------+
                                           | Outbound TLS (Host eth0)
                                           v
                                 +--------------------+
                                 | Upstream APIs      |
                                 +--------------------+
```

### Architectural Components
1. **Containerd NRI Control Socket (`/var/run/nri/nri.sock`)**: The node agent registers as an NRI plugin using the official NRI stub library (`github.com/containerd/nri/pkg/stub`). NRI is compiled in and enabled by default (`disable = false`) in containerd 2.0+ (the default in kind v0.27+ and Kubernetes 1.32+ `[unverified]`). On GKE Standard nodes running version 1.29 and later, containerd 1.7+ includes NRI compiled-in ([`docs/design/spikes/nri.md`](spikes/nri.md):118); default enablement without configuration flags is standard in containerd 2.0+ (GKE 1.33+ `[unverified]`).
2. **Host-Side Interface Enforcement ([#181](https://github.com/gke-labs/service-portals/issues/181))**: Egress filtering and redirection rules attach to the host peer network interface (`vethXXXX` or `tapXXXX`) in the host root network namespace (`netns_host`), ensuring uniform interception across standard `runc`, `gVisor`, and `Kata Containers`.
3. **Multi-Tenant Proxy (`cmd/daemonset-portal` or `cmd/all-in-one-portal`)**: Binds to host network ports 8080 and 8443, decrypting intercepted TLS using the Node Root CA, authenticating calling pods via source IP and host cgroup tracking ([#182](https://github.com/gke-labs/service-portals/issues/182)), swapping credentials, and dispatching to upstream APIs.

---

## 3. Seven Core Design Questions (NRI Architecture)

### Question 1: Redirection Mechanism (Pointer to #167 Decision)

The evaluation of transparent redirection mechanisms was conducted in issue [#159](https://github.com/gke-labs/service-portals/issues/159) across seven distinct options and four empirical spikes:
- Spike [#164](https://github.com/gke-labs/service-portals/pull/164): Application-Level Interception ([`docs/design/spikes/application-level.md`](spikes/application-level.md))
- Spike [#165](https://github.com/gke-labs/service-portals/pull/165): containerd NRI Plugin ([`docs/design/spikes/nri.md`](spikes/nri.md))
- Spike [#166](https://github.com/gke-labs/service-portals/pull/166): Chained CNI Plugin ([`docs/design/spikes/cni-plugin.md`](spikes/cni-plugin.md))
- Spike [#168](https://github.com/gke-labs/service-portals/pull/168): DRA Driver + CDI Hooks ([`docs/design/spikes/dra-cdi.md`](spikes/dra-cdi.md))

The definitive comparative findings and decision are recorded in **[#167](https://github.com/gke-labs/service-portals/pull/167) (`docs/design/interception-mechanisms.md`)**:
- **CNI Chaining Plugin (Dropped - [#166](https://github.com/gke-labs/service-portals/pull/166))**: CNI chaining is not pursued. On GKE Dataplane V2 (Cilium-based), the managed CNI daemon periodically reconciles and overwrites `/etc/cni/net.d/*.conflist` (`cni-exclusive` mode `[unverified]`). Furthermore, CNI plugins receive only `K8S_POD_NAME` and `K8S_POD_NAMESPACE` in `CNI_ARGS` (requiring synchronous API server calls to resolve pod labels), cannot inject CA certificates into container filesystems, and rules in `CNI_NETNS` fail silently under gVisor and Kata.
- **Node Agent with `nsenter` (Dropped)**: Ingesting pod creation events asynchronously is fatally racy and fails open during daemon restarts. More fundamentally, in-pod netfilter rules are bypassed by sandboxed runtimes.
- **eBPF Socket Hooks (`cgroup/connect4`) (Deferred)**: High verifier complexity across varying Linux kernel versions and direct conflicts with host eBPF programs in GKE Dataplane V2.
- **Decided Architecture**: **containerd NRI Plugin with Host-Side Interface Enforcement ([#181](https://github.com/gke-labs/service-portals/issues/181))**.

---

### Dedicated Section: Runtime Class Isolation (runc vs. gVisor vs. Kata)

A primary reason in-pod interception mechanisms (init containers, CNI `nsenter`, and CDI hooks) were disqualified in [#159](https://github.com/gke-labs/service-portals/issues/159) is their silent loss of enforcement under sandboxed runtimes:

```
In-Pod Netns Rules (Bypassed by Sandboxed Runtimes)
[ gVisor Sentry (Netstack) ] ------------(AF_PACKET raw frame)------------> [ Host veth ]
         |                                                                        ^
         x In-pod netfilter bypassed (never traversed)                            |
                                                                                  |
Host-Side Interface Enforcement (Uniformly Enforced across All Runtimes)          |
All sandbox traffic must cross host vethXXXX / tapXXXX: --------------------------+
  • runc:  Standard veth peer in host root netns -> Filtered & Redirected
  • gVisor: Netstack frame arrives on host veth   -> Filtered & Redirected
  • Kata:   Guest VM kernel packet exits tap device -> Filtered & Redirected
```

#### Why In-Pod Enforcement Fails
1. **Standard `runc`**: Containers share the Linux network namespace created for the sandbox. Netfilter rules configured inside the namespace intercept traffic; however, configuring them requires `CAP_NET_ADMIN` in the pod spec (violating PSA `baseline` [unverified: Kubernetes Pod Security Standards]).
2. **gVisor (`runsc` / GKE Sandbox)**: gVisor executes untrusted application code in a sandboxed userspace kernel (the Sentry). Networking is handled by gVisor's internal userspace network stack (Netstack). Outbound TCP/IP packets are serialized into raw Ethernet frames and written directly to the `veth` endpoint via an `AF_PACKET` socket. Consequently, netfilter and iptables rules inside the sandbox network namespace are **completely bypassed and never traversed**.
3. **Kata Containers**: Application code runs inside a lightweight hardware-isolated virtual machine (microVM) with its own guest Linux kernel. Host-side network namespace rules have no visibility or enforcement capability inside the guest kernel. Outbound packets exit the guest VM via a virtual `tap` device on the host.

#### The Host-Side Enforcement Solution ([#181](https://github.com/gke-labs/service-portals/issues/181))
In containerd NRI, `RunPodSandbox` executes synchronously before sandbox containers start. When host-side enforcement is used:
1. The NRI plugin detects the host peer interface associated with the pod:
   - For `runc` and `gVisor`: The host `veth` peer interface (`vethXXXX`).
   - For `Kata Containers`: The host `tap` interface (`tapXXXX`).
2. The agent installs netfilter rules (`iptables` / `nftables`) or Traffic Control (`tc`) filters directly on the host interface in the **host root network namespace**:
   - `PREROUTING`: Packets arriving on `vethXXXX`/`tapXXXX` on TCP ports 80 and 443 are redirected to the node proxy listener (`:8080` / `:8443`).
   - Egress Filter: Packets arriving on `vethXXXX`/`tapXXXX` destined for non-intercepted ports or unauthorized external DNS are dropped immediately (`REJECT` / `DROP`).
3. **Result**: Because all egress traffic from the sandbox—regardless of whether it was generated by runc, gVisor Netstack, or a Kata guest kernel—must traverse the host peer interface, interception and default-deny egress are **100% preserved across all runtime classes**.

---

### Question 2: Pod Identity & Caller Authentication at the Proxy (Tracked as #182)

In transparent sidecar mode, pod identity is implicit: the proxy binds to `127.0.0.1` inside the pod's private network namespace. In DaemonSet mode, the node proxy is a shared host daemon serving multiple pods from different tenants.

The prototype spike ([`docs/design/spikes/nri.md`](spikes/nri.md):141) identified a critical security requirement: the node proxy must strictly authenticate calling pods to ensure that tenant credentials are never leaked to unauthorized pods on the same node.

```
Incoming TCP Connection -> [ Node Proxy Listener (:8080 / :8443) ]
                                  |
                                  +--> 1. Check SO_ORIGINAL_DST (Drop direct connections)
                                  +--> 2. Resolve Caller Identity:
                                  |      a) Synchronous NRI IP -> Pod Cache
                                  |      b) Host Socket cgroup ID Correlation
                                  +--> 3. Lookup Tenant Policy & Secrets (#97/#99)
```

#### Mapping Connection to Pod Identity
1. **Synchronous NRI Metadata Index**:
   - When a pod sandbox is created, containerd calls `RunPodSandbox` on the NRI plugin. The plugin receives the pod's `Pod UID`, `Namespace`, `Name`, `IP`, and `Linux.CgroupParent` synchronously *before* containers can execute.
   - The node daemon populates an in-memory index mapping `PodIP -> PodMetadata`.
   - When an intercepted TCP connection arrives at the proxy, the proxy resolves `RemoteAddr` (client IP) against this synchronous cache.
2. **Original Destination Resolution**:
   - Intercepted connections retrieve the original target destination using `getsockopt(fd, SOL_IP, SO_ORIGINAL_DST)` (or `SO_ORIGINAL_DST` for IPv6).
   - If `SO_ORIGINAL_DST` matches the proxy's own listener IP and port (indicating a direct, non-intercepted connection), the proxy **immediately drops the connection**. Direct connections are strictly forbidden, closing the open-proxy loophole (#126).
3. **Source IP Spoofing & `CAP_NET_RAW` under PSA Baseline**:
   - Under PSA `baseline` [unverified: Kubernetes Pod Security Standards], containers are permitted `CAP_NET_RAW` by default.
   - **TCP 3-Way Handshake Protection**: An attacker cannot complete a TCP handshake with a forged source IP. If Pod A emits a TCP SYN spoofing Pod B's IP (`10.244.1.50`):
     1. The proxy replies with a SYN-ACK routed back to the legitimate owner of `10.244.1.50` (Pod B).
     2. Pod B's kernel receives a SYN-ACK for a socket it never opened and emits a TCP RST.
     3. The connection is torn down; Pod A cannot transmit HTTP data.
   - **Host Socket Cgroup Correlation ([#182](https://github.com/gke-labs/service-portals/issues/182))**:
     Because enforcement resides on the host, the node agent can inspect the caller's kernel cgroup ID on the host socket (via eBPF `sock_ops` or `bpf_get_current_cgroup_id()`). This binds the incoming connection directly to the pod's cgroup ID in the kernel, making spoofing mathematically impossible even if a container possesses `CAP_NET_RAW`.
4. **Admin Endpoint Isolation**:
   - Administrative endpoints (`/healthz`, `/metrics`, debug profilers, and dynamic configurator endpoints) bind exclusively to `127.0.0.1` or a private Unix domain socket, inaccessible to pod network CIDRs.

---

### Question 3: CA and Trust Distribution via NRI

In transparent HTTPS interception, the proxy terminates TLS and dynamically mints a certificate for the target hostname (e.g., `api.github.com` or `generativelanguage.googleapis.com`). Standard container runtimes validate this certificate against their trust store.

#### Solving the Trust Dilemma Without Mutating Webhooks
The early sidecar design assumed that distributing CA certificates required a mutating admission webhook to modify the pod spec (injecting volumes and environment variables).

**NRI eliminates the mutating webhook entirely**:
1. During `CreateContainer`, containerd delivers the container creation request to the NRI plugin.
2. The plugin returns a `ContainerAdjustment` containing:
   ```go
   adjustment.AddMount(&api.Mount{
       Destination: "/etc/service-portal/ca/tls.crt",
       Source:      "/etc/service-portal/ca/tls.crt",
       Type:        "bind",
       Options:     []string{"rbind", "ro"},
   })
   adjustment.AddEnv("SSL_CERT_FILE", "/etc/service-portal/ca/tls.crt")
   ```
3. Containerd injects the host CA certificate bind mount and `SSL_CERT_FILE` environment variable directly into the container filesystem before the container process is executed.
4. **Result**: Workload pod specs require **zero volume declarations, zero volume mounts, and zero environment variables**. The pod spec remains 100% clean and invisible.

#### Cryptographic Blast Radius: Node CA vs. Ephemeral Pod CAs
- In transparent sidecar mode, each pod generates an ephemeral, pod-scoped Root CA whose private key is destroyed when the pod terminates.
- In DaemonSet mode, the node proxy maintains a **Node Root CA**.
- *Blast Radius*: The node proxy holds the Node Root CA private key in memory. If the node proxy process is compromised, an attacker could sign arbitrary TLS certificates for any intercepted pod scheduled on that node.
- *Mitigations*:
  - The Node Root CA is generated ephemerally in RAM when the DaemonSet agent boots on the node; it is never persisted to disk or shared across nodes.
  - Ephemeral Node CAs are rotated periodically.
  - When available, Kubernetes `ClusterTrustBundle` (`certificates.k8s.io/v1alpha1`, Alpha in K8s 1.27; current status unverified) can distribute cluster trust anchors without managing custom secrets.

---

### Question 4: Secrets Scope & Multi-Tenant Blast Radius (Dynamic Configurator)

In sidecar mode, secrets follow process-level least privilege: Pod A's proxy only mounts Pod A's Secret. In DaemonSet mode, a single daemon serves multiple tenant sandboxes on the same node.

Static mounting (mounting all secrets in the cluster to the DaemonSet) is unacceptable. DaemonSet mode integrates with the **Dynamic Configurator** architecture ([#97](https://github.com/gke-labs/service-portals/issues/97) / [#99](https://github.com/gke-labs/service-portals/issues/99)):

```
[ Central Portal Controller ]
         |
         | 1. Pod A scheduled on Node 1 (opt-in: policy-a)
         | 2. Push Policy A + Secret A (gRPC over mTLS / Node UDS)
         v
[ Node Proxy DaemonSet (Node 1) ]
         |
         | In-memory Active Policy Map: [ Pod A UID -> Secret A ]
         |
         | 3. Pod A terminates (NRI StopPodSandbox event)
         | 4. Evict Secret A & cryptographically zero RAM
         v
[ Zeroed Memory ]
```

1. **Just-In-Time (JIT) Secret Provisioning**:
   - The central controller watches pod scheduling. When Pod A is scheduled to Node 1, the controller pushes the resolved `PortalPolicy` and upstream credentials to Node 1's proxy via a secure gRPC channel (authenticated via mTLS or local Unix Domain Socket).
   - The node proxy loads the credentials into an ephemeral in-memory cache keyed by `PodUID`.
2. **Immediate Cryptographic Revocation**:
   - When Pod A terminates, NRI triggers `StopPodSandbox`.
   - The proxy immediately purges the cache entry and overwrites the secret bytes in RAM with zeroes.
3. **Security Scope Assessment**:
   - JIT provisioning guarantees that credentials are only resident in memory while an active pod requires them.
   - *Residual Multi-Tenant Trade-off*: While an untrusted sandbox is running, its credentials share process memory with other active pods on that node. Workloads requiring strict memory address space isolation should utilize Application-Level Interception ([#164](https://github.com/gke-labs/service-portals/pull/164)) or dedicated node pools.

---

### Question 5: Loop Avoidance & Traffic Segregation Without the UID-1337 Trick

In transparent sidecar mode, avoiding network redirection loops required an iptables exemption inside the pod network namespace:
```bash
iptables -t nat -A PORTAL_OUTPUT -m owner --uid-owner 1337 -j RETURN
iptables -A OUTPUT -m owner --uid-owner 1337 -j ACCEPT
```

#### The Critical Security Vulnerability of UID 1337 Exemption
As proven in [#159](https://github.com/gke-labs/service-portals/issues/159), this in-pod exemption is fundamentally insecure under PSA `baseline` [unverified: Kubernetes Pod Security Standards]:
- PSA `baseline` permits workloads to specify `runAsUser: 1337`.
- If an untrusted container runs as UID 1337, or if an attacker switches to UID 1337, **all of their outbound traffic matches the exemption rule and bypasses interception completely**.

#### Elimination of UID-1337 Exemption in Host-Side NRI Mode
In the target NRI per-node architecture with host-side enforcement ([#181](https://github.com/gke-labs/service-portals/issues/181)):
1. The proxy runs in the host root network namespace (`netns_host`).
2. Redirection rules attach strictly to the **host peer interface** (`vethXXXX` or `tapXXXX`) in the host root netns:
   - Only incoming traffic arriving from the pod sandbox across `vethXXXX` on ports 80/443 will be redirected to `:8080`/`:8443`.
   - Outbound traffic generated by the proxy originates in `netns_host` and leaves the node via the physical egress interface (`eth0`). It **never traverses the ingress path of the pod's `vethXXXX` interface**.
3. **Expected Property**: **No UID exemption will exist in the datapath** `[unverified until #181]`.
   - Inside the pod, there will be no iptables rules and no UID exemptions.
   - Even if a workload runs as UID 1337 or UID 0, its traffic hitting the host peer interface will be unconditionally redirected to the proxy. Host-side enforcement will eliminate the UID 1337 bypass vector `[unverified until #181]`.
   - *Honest Prototype Note*: The prototype spike in [#165](https://github.com/gke-labs/service-portals/pull/165) (open; see [`docs/design/spikes/nri.md`](spikes/nri.md)) still installed iptables rules inside the pod network namespace via host `nsenter` and retained the in-pod UID exemption. Moving enforcement to the host peer interface to realize this property is the unbuilt delta tracked in [#181](https://github.com/gke-labs/service-portals/issues/181).

---

### Question 6: Failure Modes: Guaranteeing Fail-Closed

In a credential-swapping proxy protecting untrusted sandboxes, **fail-open is a catastrophic security failure**—it allows an untrusted workload to send un-swapped requests or exfiltrate data directly to the internet.

#### Analysis of Failure Scenarios

| Failure Event | NRI + Host-Side Enforcement Behavior | Guarantee |
| :--- | :--- | :--- |
| **Node Boot / Agent Not Ready** | Nodes start with a taint `service-portal.gke.io/uninitialized:NoSchedule` [unverified: custom taint pattern; containerd proposals for `default_validator.required_plugins` or `required-plugins.noderesource.dev` are unverified in standard containerd releases]. Intercepted workloads do not tolerate this taint and cannot schedule until the NRI DaemonSet connects, synchronizes, and removes the taint. | **Strictly Fail-Closed** (Workload never schedules or starts). |
| **NRI Plugin Error during `RunPodSandbox`** | If rule application fails, the plugin returns an error to containerd CRI. Containerd aborts sandbox creation (`Warning FailedCreatePodSandBox`). Workload containers are never created. | **Strictly Fail-Closed** (Workload never executes). |
| **NRI Plugin Error during `CreateContainer`** | Containerd CRI aborts container launch with `CreateContainerError`. | **Strictly Fail-Closed**. |
| **Node Proxy Crashes or Restarts** | Host-side netfilter rules redirect ports 80/443 to the proxy port. Because the proxy process is down, the kernel immediately emits `ECONNREFUSED` (TCP RST). Non-intercepted ports remain blocked by host-side drop rules. | **Strictly Fail-Closed** (All outbound traffic fails immediately). |
| **Proxy Out of Memory (OOM)** | Active connections terminate; new connections fail with `ECONNREFUSED`. Host-side drop rules remain active in kernel netfilter. | **Strictly Fail-Closed**. |
| **NRI Daemon Crash / Disconnect** | Containerd NRI by default proceeds without hooks if external socket plugins disconnect (`docs/design/spikes/nri.md:169`). Mitigated by: (1) Persistent host netfilter rules protect existing pods, (2) `Synchronize` reconciles all sandboxes upon daemon reconnect, and (3) Host watchdog re-applies node taint on agent failure. | **Fail-Closed** via node taint gating and `Synchronize`. |

#### Mechanics of Fail-Closed Host Filtering
1. The host peer interface has a default `DROP` or `REJECT` rule for non-intercepted egress:
   ```bash
   iptables -A FORWARD -i veth+ -p tcp --dport 80 -j ACCEPT
   iptables -A FORWARD -i veth+ -p tcp --dport 443 -j ACCEPT
   iptables -A FORWARD -i veth+ -p udp --dport 53 -d <Cluster-DNS-IP> -j ACCEPT
   iptables -A FORWARD -i veth+ -j REJECT --reject-with icmp-port-unreachable
   ```
2. Intercepted traffic is DNAT'd to the host proxy listener. If the proxy daemon is unavailable, the kernel emits a TCP RST. Under no circumstances can unauthorized packets leave the node uninspected.

---

### Question 7: Shared Components with Other Deployment Paths

DaemonSet mode reuses the core policy, routing, proxying, and validation infrastructure across `service-portals`:

```
+-----------------------------------------------------------------------------------+
| SHARED CODEBASE                                                                   |
|                                                                                   |
|  • pkg/apis/portals/v1alpha1 (PortalPolicy CRD schema, #149)                      |
|  • pkg/policy (CRD validation, rule resolution, Secret fetching, allowlists)     |
|  • pkg/portals (RuleRouter, dynamic SNI cert minting, header rewrite, caching)     |
|  • pkg/proxy (HTTP/HTTPS proxy engine, streaming transport, error handling)       |
|  • tests/e2e (TestSidecarPortal + TestSidecarEgressDenied deny test suite, #147)  |
+-----------------------------------------------------------------------------------+
             |                                                  |
             v                                                  v
+-----------------------------+                    +-----------------------------+
| Application-Level Path      |                    | NRI Per-Node Path           |
| (Interim & Autopilot, #164) |                    | (Target Architecture, #181) |
|                             |                    |                             |
| • Zero-privilege pods       |                    | • portal-node-agent Daemon  |
| • HTTP_PROXY + NetworkPolicy|                    | • NRI containerd plugin     |
| • Proxy-Authorization token |                    | • Host-side veth/tap rules  |
+-----------------------------+                    +-----------------------------+
```

1. **`PortalPolicy` CRD ([#149](https://github.com/gke-labs/service-portals/issues/149))**: Workload owners define identical `PortalPolicy` resources regardless of whether the cluster runs in Application-Level or NRI Per-Node mode.
2. **Proxy Core (`pkg/portals`, `pkg/proxy`)**: Dynamic SNI certificate generation, HTTP request rewriting, credential injection, response caching (`pkg/cache`), and default-deny host matching (#126) logic are reused without modification.
3. **End-to-End Deny Test Suite ([#147](https://github.com/gke-labs/service-portals/issues/147))**:
   The NRI Per-Node mode will target passing the exact same negative and positive assertions demonstrated in the nsenter-based spike `TestNRIPluginEgressDenied` ([#165](https://github.com/gke-labs/service-portals/pull/165) (open; see [`docs/design/spikes/nri.md`](spikes/nri.md))):
   - Direct IP connections on intercepted ports -> Denied.
   - Unlisted hostnames on intercepted ports -> Denied.
   - Non-intercepted TCP/UDP ports -> Rejected.
   - Arbitrary external DNS -> Blocked (cluster DNS only).
   - Positive control -> Allowed with credential swap.
   - Workload bypass attempts (UID 1337) -> Denied.

---

## 4. Architectural Trade-Off Analysis

| Dimension | Transparent Sidecar (Status Quo) | Application-Level (Interim / Autopilot, #164) | NRI Per-Node Mode (Target, #181) |
| :--- | :--- | :--- | :--- |
| **PSA Compatibility** | ❌ **Violates `baseline`** (`CAP_NET_ADMIN` in pod) | ✅ **100% `baseline` & `restricted`** compliant | ✅ **100% `baseline` & `restricted`** compliant |
| **Workload Privileges** | Requires in-pod `NET_ADMIN` | Zero capabilities (`drop: ["ALL"]`) | Zero capabilities (`drop: ["ALL"]`) |
| **Sandboxed Runtimes** | ❌ **Silently lost** under gVisor & Kata | ✅ Preserved (app-level proxying) | ✅ **Preserved** (host `veth`/`tap` enforcement) |
| **UID-1337 Bypass** | ❌ **Vulnerable** (`runAsUser: 1337` bypasses) | ✅ Immune (explicit proxy connection) | ✅ **Immune** (no UID exemption on host veth `[unverified until #181]`) |
| **Per-Pod Memory Cost** | ~15–30MB per pod (Go runtime per sandbox) | ~15–30MB per pod (or shared service) | **~0MB per pod** (amortized across node) |
| **Startup Latency** | +200–500ms (init container + sidecar) | ~0ms | **~0ms** (sub-millisecond NRI hook) |
| **Secret Blast Radius** | Isolated to 1 pod | Isolated to 1 pod (or shared service) | **Node-scoped** (JIT dynamic configurator) |
| **GKE Platform Support** | Standard only (Autopilot blocks `NET_ADMIN` by default) | **GKE Autopilot & GKE Standard** | **GKE Standard** (Autopilot blocks user NRI) |

---

## 5. Architectural Decision & Strategy

### Recorded Decision: **BUILD PER-NODE MODE ON NRI WITH HOST-SIDE ENFORCEMENT**

Following the comparative findings in [#159](https://github.com/gke-labs/service-portals/issues/159) and the architectural decision recorded in [#167](https://github.com/gke-labs/service-portals/pull/167):
1. **Target Node Architecture (GKE Standard & Bare-Metal)**:
   We are building the **containerd NRI Plugin with Host-Side Interface Enforcement ([#181](https://github.com/gke-labs/service-portals/issues/181))** as the primary high-density per-node architecture. It eliminates pod-level capabilities, enforces fail-closed default-deny egress, uniformly protects `runc`, `gVisor`, and `Kata Containers`, and will eliminate the UID-1337 bypass vulnerability once host-side enforcement lands ([#181](https://github.com/gke-labs/service-portals/issues/181); `[unverified until #181]`).
2. **Interim & Autopilot Architecture**:
   **Application-Level Interception ([#164](https://github.com/gke-labs/service-portals/pull/164))** provides immediate, zero-privilege deployment on GKE Autopilot and PSA restricted environments using standard Kubernetes `NetworkPolicy`.
3. **Deprecation of In-Pod Init Container**:
   The legacy in-pod init container (`init-service-portals`) and native sidecar with in-pod `NET_ADMIN` are deprecated due to PSA baseline violations [unverified: Kubernetes Pod Security Standards], sandboxed runtime bypasses, and UID-1337 vulnerability.

---

## 6. Staged Implementation Plan (NRI Per-Node Path)

The implementation of the NRI per-node architecture proceeds in four distinct, verifiable stages:

```
+-----------------------------------------------------------------------------+
| Stage 1: NRI Node Agent MVP on Kind (Spiked in #165, open; see nri.md)      |
| • Connect to containerd /var/run/nri/nri.sock via nri/pkg/stub              |
| • Subscribe to RunPodSandbox, StopPodSandbox, CreateContainer               |
| • In-memory pod cache & CA bind-mount injection via ContainerAdjustment     |
| • TestNRIPluginEgressDenied verified on containerd 2.0.2 (nsenter-based     |
|   spike in nri.md; host-side enforcement unbuilt in #181)                   |
+-----------------------------------------------------------------------------+
                                      │
                                      ▼
+-----------------------------------------------------------------------------+
| Stage 2: Host-Side Enforcement Delta (#181)                                 |
| • Capture host peer interface (vethXXXX / tapXXXX) during RunPodSandbox     |
| • Install netfilter / tc redirect & drop rules on host-side peer interface  |
| • Eliminate in-pod nsenter execution entirely                               |
| • Verify uniform enforcement on runc, gVisor (runsc), and Kata Containers   |
+-----------------------------------------------------------------------------+
                                      │
                                      ▼
+-----------------------------------------------------------------------------+
| Stage 3: Pod Identity & Strict Caller Authentication (#182)                 |
| • Synchronous NRI metadata cache indexed by Pod IP and CgroupParent         |
| • Host socket cgroup ID correlation (SO_PEERCRED / eBPF socket cookie)      |
| • Reject direct listener connections (SO_ORIGINAL_DST inspection)           |
| • Isolate administrative endpoints to localhost / Unix domain socket        |
+-----------------------------------------------------------------------------+
                                      │
                                      ▼
+-----------------------------------------------------------------------------+
| Stage 4: Dynamic Configurator Integration (#97/#99)                         |
| • Central controller pushes JIT PortalPolicy and secrets over secure gRPC   |
| • Ephemeral in-memory secret cache keyed by PodUID                          |
| • NRI StopPodSandbox triggers immediate cryptographic zeroing of secret RAM |
| • Standardize node taint gating (service-portal.gke.io/uninitialized)       |
+-----------------------------------------------------------------------------+
```

### Stage 1: NRI Node Agent MVP on Kind (Spiked in [#165](https://github.com/gke-labs/service-portals/pull/165) (open; see [`docs/design/spikes/nri.md`](spikes/nri.md)))
- **Status**: Spiked in [#165](https://github.com/gke-labs/service-portals/pull/165) (open; see [`docs/design/spikes/nri.md`](spikes/nri.md)).
- **Deliverables**:
  1. `cmd/portal-nri-plugin`: DaemonSet connecting to containerd `/var/run/nri/nri.sock`.
  2. `CreateContainer` adjustment injecting CA bind mount (`/etc/service-portal/ca/tls.crt`) and `SSL_CERT_FILE`.
  3. Node taint gating (`service-portal.gke.io/uninitialized:NoSchedule`) removed upon daemon synchronization.
  4. Validated in the nsenter-based prototype: `TestNRIPluginEgressDenied` passed on containerd 2.0.2 (see [`docs/design/spikes/nri.md`](spikes/nri.md)), noting that this prototype used in-pod `nsenter` rather than the host-side interface enforcement designed in [#181](https://github.com/gke-labs/service-portals/issues/181).

### Stage 2: Host-Side Enforcement Delta ([#181](https://github.com/gke-labs/service-portals/issues/181))
- **Deliverables**:
  1. Transition rule configuration from in-pod `nsenter` to the host root network namespace.
  2. Extract host-side interface name (`vethXXXX` / `tapXXXX`) from containerd sandbox info during `RunPodSandbox`.
  3. Install host-side netfilter/tc rules on `vethXXXX`/`tapXXXX` directing ports 80/443 to the node proxy listener.
  4. Add e2e validation under `runtimeClassName: gvisor` confirming Netstack traffic is intercepted with zero bypass.

### Stage 3: Pod Identity & Caller Authentication ([#182](https://github.com/gke-labs/service-portals/issues/182))
- **Status**: Implemented in #222 (pending merge; tracking #182).
- **Deliverables**:
  1. Synchronous `RemoteAddr` -> Pod identity resolution in `pkg/portals` backed by an in-memory pod map populated by `portal-nri-plugin` (`RunPodSandbox`, `StopPodSandbox`, `Synchronize`).
  2. Per-pod policy enforcement: caller pod identity maps to allowed `PortalRule`s; unentitled hosts are rejected with HTTP 403.
  3. Dynamic Bind API (`/bind` and `/unbind`) on the node agent: warm-pool sandboxes start unbound (fail closed by default), and coordinators bind/unbind identities without pod spec mutations.
  4. Direct-to-proxy connection protection: direct connections to proxy ports from non-opted-in pods or with unentitled hosts are denied.
  5. Proxy logs carry pod namespace/name. Attribution headers (`X-Consumer-Identity`, `X-Forwarded-Client-Pod`) are sent upstream only for PortalRules that set `attributionHeaders: true`; by default nothing about the caller leaves the cluster.

### Stage 4: Dynamic Configurator Integration ([#97](https://github.com/gke-labs/service-portals/issues/97) / [#99](https://github.com/gke-labs/service-portals/issues/99))
- **Deliverables**:
  1. Implement secure gRPC client in the node agent connecting to the central portal controller.
  2. Just-In-Time delivery of secrets when opted-in pods are scheduled to the node.
  3. Cryptographic zeroing and eviction of secrets from memory on `StopPodSandbox`.
  4. Production node taint controller to guarantee fail-closed node initialization.
