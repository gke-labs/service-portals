# Design: DaemonSet (Per-Node) Mode

**Author**: codebot-robot / justinsb  
**Status**: Proposal / Review  
**Date**: October 2026  
**Target Path**: `docs/design/daemonset-mode.md`  
**Tracking Issue**: [#151](https://github.com/gke-labs/service-portals/issues/151)  

---

## 1. Executive Summary & Context

`service-portals` intercepts outbound network calls from untrusted or semi-trusted application sandboxes (e.g., AI agents, evaluation runners, CI jobs) and swaps placeholder credentials with real API tokens while strictly dropping unauthorized egress traffic ("Tokens that aren't there can't leak").

The current primary path is the **Transparent Sidecar Mode** (progressing through [#147](https://github.com/gke-labs/service-portals/issues/147), [#148](https://github.com/gke-labs/service-portals/issues/148), [#149](https://github.com/gke-labs/service-portals/issues/149), and [#150](https://github.com/gke-labs/service-portals/issues/150)):
- Each pod runs an `init-service-portals` init container with `NET_ADMIN` to configure pod-local `iptables` rules and generate an ephemeral Root CA.
- Each pod runs an `all-in-one-portal` sidecar container as UID 1337 holding only that pod's specific CA private key and secrets.
- Injected automatically via an admission webhook (`cmd/portal-injector`).

While the sidecar model provides ideal defense-in-depth, per-pod process isolation, and zero host-level privileges, it incurs overhead:
- **Resource Footprint**: One Go proxy process per pod. For high-density clusters hosting hundreds or thousands of concurrent, short-lived agent sandboxes per node, running a dedicated proxy container per sandbox consumes substantial memory and container runtime resources.
- **Startup Latency**: Init-container execution, certificate generation, and container runtime orchestration add hundreds of milliseconds to sandbox startup.
- **Webhook Requirement**: Requires a mutating admission webhook with rights to inject containers, volumes, and environment variables into pod specs.

A **DaemonSet Mode**—deploying a single proxy daemon per node that enforces per-pod policies for all pods residing on that node—offers potential benefits for high-density, ephemeral sandbox workloads. However, operating a multi-tenant proxy outside the pod's private network namespace fundamentally alters traffic redirection, identity verification, cryptographic trust distribution, and the security blast radius.

This document details the architectural requirements, compares implementation options, answers the seven core design questions, provides a clear recommendation, and outlines a staged rollout plan.

---

## 2. Architecture Comparison

```
Sidecar Architecture (1:1 Isolation)
+---------------------------------------------------------------------------------+
| Pod Network Namespace (netns_pod)                                               |
|                                                                                 |
|  +--------------------+                               +----------------------+  |
|  | Workload Container |                               | Sidecar Proxy        |  |
|  | (UID 1000)         |  Port 80/443 (iptables)       | (UID 1337)           |  |
|  | Holds NO secrets   |------------------------------>| Ephemeral Pod-CA     |  |
|  | Reads ca-cert      |                               | Pod-only Secrets     |  |
|  +--------------------+                               +----------+-----------+  |
|                                                                  |              |
+------------------------------------------------------------------|--------------+
                                                                   v Outbound TLS
                                                         +--------------------+
                                                         | Upstream APIs      |
                                                         +--------------------+

DaemonSet Architecture (1:N Shared Node Proxy)
+----------------------------------+       +----------------------------------+
| Pod A (Namespace: tenant-a)      |       | Pod B (Namespace: tenant-b)      |
|                                  |       |                                  |
|  +--------------------+          |       |  +--------------------+          |
|  | Workload Container |          |       |  | Workload Container |          |
|  | Policy: agent-a    |          |       |  | Policy: agent-b    |          |
|  +---------+----------+          |       |  +---------+----------+          |
+------------|---------------------+       +------------|---------------------+
             | Intercepted                              | Intercepted
             | (CNI / eBPF)                             | (CNI / eBPF)
             v                                          v
+-----------------------------------------------------------------------------+
| Host Network Namespace (netns_host)                                         |
|                                                                             |
|  +-----------------------------------------------------------------------+  |
|  | Node Proxy DaemonSet (cmd/daemonset-portal)                           |  |
|  |                                                                       |  |
|  | • Multi-Tenant Connection Handler (Source IP / cgroup ID -> Pod)      |  |
|  | • Dynamic Policy & Secret Store (tenant-a & tenant-b secrets in RAM)  |  |
|  | • Node Root CA / Dynamic TLS Minting                                  |  |
|  | • Loop Avoidance: Host UID 1337 / cgroup exemption                    |  |
|  +-----------------------------------+-----------------------------------+  |
+--------------------------------------|--------------------------------------+
                                       v Outbound TLS (Host Netns)
                             +--------------------+
                             | Upstream APIs      |
                             +--------------------+
```

---

## 3. Seven Core Design Questions

### Question 1: Redirection Without a Per-Pod Init Container

In sidecar mode, an unprivileged pod runs an init container with `CAP_NET_ADMIN` inside its own private network namespace. Because the init container executes before application containers start, redirection and egress rules are guaranteed race-free.

In DaemonSet mode, there is no per-pod init container. Outbound TCP traffic on target ports (80, 443) must be steered to the node proxy listener without pod-level setup.

We evaluate three potential redirection mechanisms:

#### Option (a): CNI Chaining Plugin
- **Mechanism**: A dedicated CNI plugin binary (`service-portal-cni`) installed in `/opt/cni/bin/` and chained into the host CNI network configuration (e.g., `/etc/cni/net.d/10-kindnet.conflist`, `/etc/cni/net.d/01-cni.conflist`). When the container runtime (containerd/CRI-O) creates a pod sandbox, it executes `CNI ADD`. The plugin receives the pod's network namespace (`CNI_NETNS`) and pod metadata (`CNI_ARGS`). It enters the pod network namespace and installs the `iptables` redirection rules (`PREROUTING`/`OUTPUT` DNAT to the node proxy IP and port) along with egress drop rules.
- **Race-Freedom**: **Guaranteed (100% race-free)**. In the Kubernetes CRI lifecycle, network setup must succeed and return exit code 0 before any container in the pod is created or started. No workload process can execute a single instruction or send a single packet prior to rule installation.
- **Privileges**: The DaemonSet requires host filesystem mounts (`hostPath` to `/opt/cni/bin` and `/etc/cni/net.d`) during installation to drop the binary and update configuration. However, the runtime proxy process does *not* require continuous `hostPID` or `privileged: true`. The CNI plugin itself is invoked directly by CRI as root on the host.
- **Failure Mode & Startup Ordering**:
  - If a pod starts on a node before the CNI plugin is installed or configured, the CRI fails pod sandbox creation (`failed to find plugin "service-portal-cni"`). The pod remains stuck in `ContainerCreating` / `CreateContainerError` and application code never executes. **This is strictly fail-closed.**
  - Pre-existing pods (running before the CNI plugin was added to the chain) lack rules until they are restarted.
- **Compatibility**: Requires standard CNI chaining support (compatible with Kind, Flannel, Calico, AWS VPC CNI). May require specific integration or hooks for pure eBPF CNIs such as GKE Datapath v2 (Cilium).

#### Option (b): Node Agent Watching Pod Creation and Using `nsenter`
- **Mechanism**: A userspace DaemonSet watches Kubernetes API pod events or monitors the local container runtime socket (`/run/containerd/containerd.sock`). When a new pod is scheduled or detected, the agent identifies the pod's container process ID (PID) and executes `nsenter -t <pid> -n iptables ...` to inject redirection rules into the running pod's network namespace.
- **Race-Freedom**: **Inherently and fatally racy**.
  - Kubelet starts the workload container immediately after the primary CNI network setup completes.
  - The DaemonSet receives the event asynchronously (API server informer latency is typically 10ms–100ms+; CRI event streams still suffer non-zero scheduling delays).
  - During this startup window, the workload container is already executing code. An untrusted agent or malicious payload can establish direct outbound connections, exfiltrate environment data, or query external DNS before `nsenter` executes.
  - Even attempting to pause containers via cgroupv2 `cgroup.freeze` is racy because the container begins execution before the freeze signal arrives.
- **Privileges**: Requires extreme node privileges: `hostPID: true`, `hostNetwork: true`, `privileged: true` (or `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_NET_ADMIN`), and access to the host `/proc` and container runtime socket.
- **Failure Mode**: If the DaemonSet crashes or restarts, new pods scheduled during the downtime run completely unintercepted and unmonitored (**fatal fail-open**).
- **Verdict**: **Disqualified**. Cannot provide the default-deny and isolation guarantees required by `service-portals`.

#### Option (c): eBPF Redirect Keyed on Pod Cgroup
- **Mechanism**: An eBPF program (`cgroup/connect4` and `cgroup/connect6`) attached to the root pod cgroup (e.g., `/sys/fs/cgroup/kubepods.slice` on cgroupv2 systems). When any container process initiates a TCP connection via `connect(2)`, the kernel hook executes *before* the SYN packet is generated.
  - The program inspects the calling socket's cgroup ID (`bpf_get_current_cgroup_id()`) and checks an eBPF map (`pod_policy_map`) maintained by the DaemonSet.
  - If the connection belongs to a managed pod:
    - Target ports (80, 443): rewrites destination IP and port to the local node proxy listener (`127.0.0.1:8080/8443` or node IP). The original destination is saved in a BPF connection tracking map (`sock_ops`).
    - Non-target ports: returns `-EPERM`, instantly rejecting the connection at the socket layer.
- **Race-Freedom**:
  - The eBPF program is attached at the parent cgroup slice *before* individual pod cgroups are created.
  - **Map Synchronization Race**: When a new pod starts, its cgroup ID must be populated in the BPF map.
    - If the kernel program defaults to **Deny** on unknown cgroups within `kubepods.slice`, early connections fail until the userspace agent populates the policy. This achieves race-free, fail-closed behavior, though it may produce transient connection errors during the first millisecond of container boot.
    - If it defaults to Allow, a startup leak window exists.
- **Privileges**: Requires `CAP_BPF` (or `CAP_SYS_ADMIN`), `CAP_NET_ADMIN`, access to `/sys/fs/bpf` (for map pinning) and `/sys/fs/cgroup`. Does not require `hostPID`.
- **Failure Mode & Startup Ordering**:
  - Pinned eBPF programs in `/sys/fs/bpf` persist across DaemonSet crashes and restarts, maintaining fail-closed protection in the kernel.
  - Requires Linux kernel >= 5.8+ and pure cgroupv2. May conflict with other host eBPF socket programs (e.g., Cilium host routing).

#### Redirection Comparison Matrix

| Evaluation Criterion | Option (a): CNI Chaining Plugin | Option (b): Node Agent (`nsenter`) | Option (c): eBPF (`cgroup/connect4`) |
| :--- | :--- | :--- | :--- |
| **Race-Freedom** | **Complete** (runs synchronously before container execution) | **Fails** (unavoidable window between start and rule inject) | **Conditional** (race-free if unmapped cgroups default to drop) |
| **Privileges Required** | `hostPath` (`/opt/cni/bin`, `/etc/cni/net.d`) for installer | `hostPID: true`, `hostNetwork: true`, `privileged: true`, CRI socket | `CAP_BPF`, `CAP_NET_ADMIN`, `/sys/fs/bpf`, `/sys/fs/cgroup` |
| **Startup Race (Agent Down)** | **Fail-Closed** (CRI sandbox creation fails if plugin missing) | **Fail-Open** (workload runs unrestricted) | **Fail-Closed** (kernel BPF persists via pinned maps) |
| **Kernel Requirements** | Standard Linux (any kernel supporting `iptables`) | Standard Linux | Kernel >= 5.8+, pure cgroupv2 |
| **Implementation Complexity** | Medium (straightforward CNI binary; tested pattern) | Low implementation, Zero security | High (eBPF verifier, map management, cgroup tracking) |

**Conclusion on Redirection**: Option (a) (CNI Chaining) is the most robust and portable mechanism for standard clusters; Option (c) (eBPF) is the preferred alternative for pure cgroupv2/eBPF environments. Option (b) is rejected.

---

### Question 2: Pod Identity at the Proxy

In sidecar mode, pod identity is implicit: the proxy only accepts connections from the loopback interface of its own private network namespace.

In DaemonSet mode, the node proxy runs on the host and accepts connections from hundreds of distinct pods spanning different namespaces, labels, and `PortalPolicy` rules.

```
Incoming TCP Connection -> [ Node Proxy Listener ]
                                  |
                                  +--> 1. Identify Pod: Source IP -> Pod Mapping
                                  +--> 2. Original Destination: SO_ORIGINAL_DST
                                  +--> 3. Policy Resolution: Pod -> PortalPolicy
```

#### Mapping Connection to Pod Identity
1. **Source IP Lookup**:
   - The proxy inspects the incoming client address (`RemoteAddr`). Because traffic is routed or DNAT'd from the pod netns to the host proxy, the source IP is the Pod IP (e.g., `10.244.1.42`).
   - The node proxy maintains an in-memory index mapping `PodIP -> PodMetadata (Namespace, Name, UID, Labels)`.
   - The index is synchronized locally via the Kubelet Pod API (`http://127.0.0.1:10255/pods` or `https://127.0.0.1:10250/pods`) or a node-filtered Kubernetes API Informer (`spec.nodeName == NODE_NAME`).
2. **Original Destination Resolution**:
   - For intercepted traffic, the proxy retrieves the original target IP and port using `getsockopt(fd, SOL_IP, SO_ORIGINAL_DST)` (or `SO_ORIGINAL_DST` for IPv6).
   - Under eBPF, the original destination and cgroup ID are retrieved directly from a BPF connection tracking map.
3. **Policy Resolution**:
   - The proxy matches the Pod's labels and namespace against active `PortalPolicy` resources (using `pkg/policy`) to determine allowed hosts, upstream rewrite URLs, and credentials.

#### Source IP Spoofing & Security Context Requirements
Can a compromised or malicious pod forge its source IP to impersonate another pod on the node and hijack its credentials?

- **TCP 3-Way Handshake Protection**:
  - Under normal conditions, an attacker cannot complete a TCP handshake with a spoofed source IP.
  - If Pod A sends a TCP SYN packet to the node proxy with a spoofed source IP of Pod B (`10.244.1.50`):
    1. The proxy replies with a SYN-ACK addressed to `10.244.1.50` (Pod B).
    2. The Linux kernel network stack in Pod B receives a SYN-ACK for a socket it never opened.
    3. Pod B immediately emits a TCP RST packet to the proxy, tearing down the embryonic connection.
    4. The connection is never established, and Pod A cannot send HTTP request data.
- **Spoofing Risks via Raw Sockets (`CAP_NET_RAW` / `CAP_NET_ADMIN`)**:
  - If a container retains `CAP_NET_RAW`, it can craft raw Ethernet/IP packets, send gratuitous ARPs, or attempt local ARP/NDP poisoning if pods reside on a shared bridge without CNI hairpin/anti-spoofing enforcement.
- **Pod IP Churn & Recycling Race**:
  - In clusters with rapid pod churn (short-lived agent sandboxes), IP addresses are recycled quickly. If the proxy's local pod cache has a synchronization lag, a new pod could temporarily inherit the identity and secrets of a deleted pod.
- **Mandatory Workload Security Requirements**:
  To guarantee identity integrity in DaemonSet mode:
  1. Workload pods **must drop `NET_RAW` and `NET_ADMIN`**:
     ```yaml
     securityContext:
       capabilities:
         drop: ["NET_RAW", "NET_ADMIN"]
       runAsNonRoot: true
       allowPrivilegeEscalation: false
     ```
  2. The proxy must index pods by `(PodIP, PodUID, StartTime)`, and immediately invalidate cache entries upon pod deletion notifications.
  3. When eBPF is used, the proxy keys identity on kernel `cgroup_id`, completely bypassing IP-based identification and making spoofing mathematically impossible regardless of container capabilities.

---

### Question 3: CA and Trust Distribution

In transparent HTTPS interception, the proxy terminates TLS and dynamically mints a certificate for the target hostname (e.g., `gemini.backend` or `api.github.com`). Client runtimes (`curl`, Python `requests`, Node `fetch`, Go `http.Client`) validate this certificate against their trust store.

```
Sidecar Mode (Isolated Trust)
[ Pod A Workload ] ---> trusts [ Ephemeral CA A ] (Key in Pod A Sidecar only)
[ Pod B Workload ] ---> trusts [ Ephemeral CA B ] (Key in Pod B Sidecar only)

DaemonSet Mode (Shared Node Trust)
[ Pod A Workload ] ---\
                       +---> trusts [ Node Root CA ] (Key in Node Proxy)
[ Pod B Workload ] ---/
```

#### Per-Node CA vs. Per-Pod Minted CAs
- **Option 1: Per-Node Root CA**
  - The node proxy maintains a single Node Root CA.
  - All pods running on that node trust this Node Root CA.
  - *Security Blast Radius*: The node proxy holds the CA private key. If the node proxy is compromised (e.g., via an HTTP parser vulnerability or arbitrary code execution), the attacker gains the Node Root CA private key and can decrypt, intercept, and forge TLS traffic for **every** pod running on that node.
- **Option 2: Per-Pod Sub-CAs Minted by Node CA**
  - The node proxy mints an intermediate CA per pod.
  - However, because the workload still validates the trust chain back to the Node Root CA, every pod on the node must still trust the Node Root CA. Thus, intermediate CAs add complexity without reducing the cryptographic blast radius if the node proxy is compromised.

#### The Trust Distribution Dilemma (The "No Webhook" Paradox)
A primary motivation for DaemonSet mode is avoiding mutating admission webhooks. However, distributing CA trust creates a fundamental paradox:

**How does the workload trust the proxy's CA certificate without a pod mutation?**

1. **Standard Containers Do Not Trust Local CAs**: Standard container images (Alpine, Debian, Ubuntu, distroless) only include public commercial Root CAs.
2. **Mounting Certificates Requires Pod Spec Mutation**:
   - In Kubernetes, a file cannot be mounted from the host (`hostPath`) or a `Secret`/`ConfigMap` unless declared in `spec.volumes` and `spec.containers[*].volumeMounts`.
   - Setting environment variables (`SSL_CERT_FILE=/etc/service-portal/ca/tls.crt`, `REQUESTS_CA_BUNDLE=...`, `NODE_EXTRA_CA_CERTS=...`) requires modifying `spec.containers[*].env`.
3. **Alternative: `ClusterTrustBundle` (Kubernetes 1.27+)**:
   - Kubernetes supports `ClusterTrustBundle` objects to distribute cluster-wide trust bundles.
   - However, using `ClusterTrustBundle` *still requires* projecting the bundle into the pod via `volumeMounts` in the Pod spec!
4. **Alternative: Out-of-band Host Filesystem Injection**:
   - A privileged host agent could theoretically write the CA certificate directly into `/proc/<pid>/root/etc/ssl/certs/...` after container creation.
   - *Why this fails*: It is fragile, racy, violates container filesystem immutability, fails on `readOnlyRootFilesystem: true`, requires distribution-specific paths and certificate rebuild commands (`update-ca-certificates`), and is impossible for `scratch` or distroless images.
5. **Alternative: Custom Base Images**:
   - Pre-installing the cluster CA into all organizational base images.
   - *Why this fails*: Imposes high operational friction and prevents developers from running standard off-the-shelf images.

**Verdict on CA/Trust**: **DaemonSet mode does NOT eliminate the need for pod mutation if HTTPS interception is required.** Unless workloads only use cleartext HTTP or images have pre-baked trust, a mutating webhook (or pod template update) is still necessary to inject the CA certificate and environment variables into the workload.

---

### Question 4: Secrets Scope & Multi-Tenant Blast Radius

In sidecar mode, secrets follow the principle of least privilege:
- Pod A's sidecar proxy only mounts the Kubernetes Secret for Pod A's `PortalPolicy`.
- Pod B's sidecar proxy only mounts Pod B's Secret.
- The operating system kernel enforces memory address space isolation between the two proxy processes.
- A compromise or crash of Pod A's proxy has zero impact on Pod B's credentials.

In DaemonSet mode, the node proxy is a shared multi-tenant daemon:
- **Blast Radius**: The single proxy process holds in memory the credentials for **all** policies active across all pods running on that node.
- **Attack Surface**:
  - Memory read vulnerabilities (buffer overflows, Go runtime memory corruption, heap inspection).
  - HTTP request smuggling / pipelining flaws where requests from Pod A are conflated with Pod B.
  - Inadvertent exposure of credentials through error responses, debug logs, or pprof/metrics endpoints.
  - A compromise of the node proxy exposes API keys and tokens for every tenant on the node.

#### Mitigation: Dynamic Configurator (#97 / #99)
Static Secret mounting (e.g., mounting all Secrets in the namespace to the DaemonSet) is unacceptable for multi-tenant nodes. Instead, DaemonSet mode should use the **Dynamic Configurator** architecture:

```
[ Central Controller ]
         |
         | 1. Pod A scheduled on Node 1
         | 2. Push Policy A + Secrets (gRPC over mTLS / UDS)
         v
[ Node Proxy (Node 1) ]
         |
         | Active in-memory policy store: [ Pod A: Secret A ]
         |
         | 3. Pod A terminates
         | 4. Evict & securely zero Secret A from memory
         v
[ Zeroed Memory ]
```

1. **Just-In-Time (JIT) Secret Provisioning**:
   - A central controller tracks pod scheduling.
   - When Pod A is scheduled on Node 1, the controller pushes the resolved credentials for Pod A to Node 1's proxy via a secure gRPC channel (authenticated via mTLS or local Unix Domain Socket).
   - The node proxy loads the credentials into an ephemeral in-memory cache indexed by `PodUID`.
2. **Immediate Revocation**:
   - When Pod A terminates, the controller notifies the proxy (or the proxy detects pod deletion via local Kubelet events).
   - The proxy immediately purges and zeroes the secret data from memory.
3. **Evaluation**:
   - JIT provisioning significantly reduces the *idle* blast radius: credentials are only present while an associated pod is actively executing on the node.
   - However, during concurrent execution of multiple untrusted sandboxes on the same node, all active credentials remain co-located in the same process memory space.

---

### Question 5: Loop Avoidance & Traffic Segregation

In sidecar mode, loop avoidance is solved cleanly inside the pod's private network namespace:
```bash
iptables -t nat -A PORTAL_OUTPUT -m owner --uid-owner 1337 -j RETURN
iptables -A OUTPUT -m owner --uid-owner 1337 -j ACCEPT
```
The sidecar proxy runs as UID 1337. Traffic originating from the proxy is exempted from interception and allowed out to the host.

In DaemonSet mode, the workload runs in `netns_pod` and the proxy runs in `netns_host`. Outbound connections from the proxy to external APIs (e.g., `https://api.github.com:443`) originate directly in `netns_host`.

#### Preventing Host-Level Egress Loops
If node-level or host-level redirection rules are installed, the node proxy's outbound requests must not be redirected back into its own listening socket:
1. **Host UID Exemption**:
   - The DaemonSet process runs under a dedicated, unprivileged host UID (e.g., UID `1337`).
   - Host-level routing / `iptables` rules must explicitly exclude UID 1337:
     ```bash
     iptables -t nat -A OUTPUT -m owner --uid-owner 1337 -j RETURN
     ```
2. **Cgroup / Slice Exemption**:
   - If using systemd or cgroupv2 BPF hooks, the DaemonSet is placed in a dedicated slice (e.g., `system.slice/service-portal.service`), and the BPF program filters out connections where `bpf_get_current_cgroup_id() == daemonset_cgroup_id`.

#### Preventing Unauthorized Direct Access to Proxy Listeners
Pods must not be permitted to connect directly to the proxy's administrative or proxy ports:
1. **Direct Interception Verification**:
   - The proxy inspects `SO_ORIGINAL_DST` on every accepted TCP connection.
   - If `SO_ORIGINAL_DST` matches the proxy's own listening IP and port (indicating a direct, non-intercepted connection rather than a redirected packet), the proxy **immediately drops the connection**. This closes the open-proxy fallback loophole (#126).
2. **Admin Port Isolation**:
   - Administrative endpoints (`/healthz`, `/metrics`, debug profilers, and gRPC configurators) must bind exclusively to `127.0.0.1` or a private host Unix Domain Socket, inaccessible to pod network CIDRs.

---

### Question 6: Failure Modes: Guaranteeing Fail-Closed

In a credential-swapping proxy protecting untrusted sandboxes, **fail-open is a catastrophic security failure**—it allows an untrusted workload to send un-swapped requests or exfiltrate data directly to the internet.

The system must guarantee that under all failure conditions, unauthorized egress is strictly blocked (**fail-closed**).

#### Analysis of Failure Scenarios

| Failure Event | DaemonSet Behavior | Guarantee |
| :--- | :--- | :--- |
| **Node Proxy Crashes or Restarts** | Netns `iptables` rules redirect ports 80/443 to the proxy port. Because the proxy process is down, the kernel immediately sends `ECONNREFUSED` (TCP RST). Non-intercepted ports remain blocked by the netns drop rules. | **Strictly Fail-Closed** (All egress fails immediately; no bypass). |
| **Node Boot / Agent Not Ready** | With CNI chaining, CRI calls to `CNI ADD` fail if the plugin cannot verify the agent. The pod sandbox fails creation and no container runs. | **Strictly Fail-Closed** (Workload never starts). |
| **Proxy Out of Memory (OOM)** | The proxy is killed by the OOM killer; active connections terminate; new connections fail with `ECONNREFUSED`. Egress filters remain intact in the kernel. | **Strictly Fail-Closed**. |
| **Network Partition / Upstream API Down** | Proxy returns HTTP 502/504 to the workload; credentials are never leaked. | **Strictly Fail-Closed**. |
| **eBPF Program Unload** | If eBPF programs are pinned in `/sys/fs/bpf`, they persist across userspace daemon crashes. If unpinned programs crash, socket hooks default to drop if configured with fallback deny. | **Fail-Closed** with pinned BPF programs. |

**Mechanics of Fail-Closed Egress Filtering**:
1. The CNI chaining plugin configures a default `REJECT` or `DROP` rule at the end of the pod netns `PORTAL_EGRESS` chain:
   ```bash
   iptables -A PORTAL_EGRESS -j REJECT --reject-with icmp-port-unreachable
   ```
2. Intercepted ports (80, 443) are DNAT'd to the host proxy listener IP.
3. If the host proxy is down, the kernel sends a TCP RST for the forwarded packet.
4. Under no circumstances can a packet bypass redirection and leave the host uninspected.

---

### Question 7: Shared Components with the Sidecar Path

To maintain architectural cohesion, ensure consistency, and prevent code divergence, DaemonSet mode shares the vast majority of its core implementation with the sidecar path:

```
+-----------------------------------------------------------------------------------+
| SHARED CODEBASE                                                                   |
|                                                                                   |
|  • pkg/apis/portals/v1alpha1 (PortalPolicy CRD schema)                            |
|  • pkg/policy (CRD validation, rule resolution, Secret fetching, allowlists)     |
|  • pkg/portals (RuleRouter, dynamic SNI cert minting, header rewrite, caching)     |
|  • pkg/proxy (HTTP/HTTPS proxy engine, streaming transport, error handling)       |
|  • tests/e2e (TestSidecarPortal + TestSidecarEgressDenied deny test suite)        |
+-----------------------------------------------------------------------------------+
             |                                                  |
             v                                                  v
+-----------------------------+                    +-----------------------------+
| Sidecar Path                |                    | DaemonSet Path              |
|                             |                    |                             |
| • cmd/all-in-one-portal     |                    | • cmd/daemonset-portal      |
| • cmd/init-service-portals  |                    | • CNI Chaining Plugin       |
| • cmd/portal-injector       |                    | • Dynamic Configurator UDS  |
+-----------------------------+                    +-----------------------------+
```

1. **`PortalPolicy` CRD (#149)**:
   - The user-facing API remains identical. A `PortalPolicy` defines allowed hosts, rewrite targets, credentials (`secretRef`), egress allowlists, and DNS policies.
   - Workload owners write the exact same policy regardless of whether the cluster executes in sidecar or DaemonSet mode.
2. **Policy Resolution (`pkg/policy`)**:
   - The DaemonSet uses `pkg/policy.Resolve` to parse policies and resolve credentials.
3. **Proxy Core (`pkg/portals`, `pkg/proxy`)**:
   - The dynamic SNI certificate generation, HTTP request rewriting, credential injection, response caching (`pkg/cache`), and default-deny host matching (#126) logic are reused without modification.
4. **End-to-End Deny Test Suite (#147)**:
   - The test assertions designed for `#147` must pass identically in DaemonSet mode:
     1. Direct IP connects on intercepted ports -> Denied.
     2. Unlisted hostnames on intercepted ports -> Denied.
     3. Non-intercepted ports -> Blocked.
     4. Arbitrary external DNS -> Blocked (cluster DNS only).
     5. Positive control -> Allowed with credential swap.
     6. Bypass attempts (e.g. attempting to run as UID 1337) -> Denied.

---

## 4. Architectural Trade-Off Analysis

| Dimension | Sidecar Mode (Current) | DaemonSet Mode (Proposed) |
| :--- | :--- | :--- |
| **Per-Pod Memory Overhead** | ~15–30MB per pod (Go runtime + proxy per sandbox) | ~0MB per pod (amortized across node) |
| **Startup Latency** | +200–500ms (init container + sidecar startup) | ~0ms added to pod container launch |
| **Cryptographic Isolation** | **Per-pod ephemeral Root CA** (compromise is pod-scoped) | **Shared Node CA** (compromise breaks all node TLS) |
| **Secret Blast Radius** | **Strictly scoped to 1 pod** | **Shared across all pods on node** |
| **Node Privileges** | **Zero host privileges** (pod-scoped `NET_ADMIN` in init) | **Requires host filesystem / CNI / eBPF access** |
| **Bypass Resistance** | **Kernel-enforced netns isolation** | **Dependent on CNI / eBPF rules and anti-spoofing** |
| **Pod Mutation Needed?** | Yes (injector webhook for sidecar + CA mount) | **Still Yes** (for CA certificate mount + env vars) |
| **Operational Complexity** | Low (standard K8s pod primitives) | High (host CNI chaining or kernel eBPF) |

---

## 5. Recommendation

### Recommendation: **BUILD LATER**
**(Sidecar path first; re-evaluate DaemonSet mode for high-density agent clusters)**

### Rationale:
1. **Security Superiority of Sidecar**: The sidecar architecture provides unmatched defense-in-depth:
   - Process and memory address space isolation between untrusted tenants.
   - An ephemeral, per-pod Root CA that eliminates the risk of node-wide TLS interception if a proxy instance is compromised.
   - Minimal secret exposure: each proxy instance only holds credentials for its own pod.
   - Operates entirely within standard Kubernetes user-space without requiring host privileges (`hostPath`, `CAP_BPF`, or CNI modifications).
2. **The "No-Webhook" Assumption Fails**: A central argument for DaemonSet mode is avoiding mutating admission webhooks. However, as demonstrated in Question 3, **HTTPS interception still requires mounting the CA certificate and setting environment variables inside the workload container**. Unless all cluster workloads run custom pre-baked base images or only speak cleartext HTTP, pod mutation is still mandatory.
3. **Execution Sequencing**: The project's immediate focus should remain on hardening and completing the sidecar path:
   - Fix unmatched host fallthrough (#126).
   - Implement the complete egress deny e2e test suite (#147).
   - Harden `init-service-portals` against DNS tunneling, IPv6, and metadata bypass (#148).
   - Define the `PortalPolicy` CRD and resolver (#149).
   - Implement the `portal-injector` mutating webhook (#150).
4. **Trigger for Building DaemonSet Mode**: DaemonSet mode should be prioritized only when a clear operational scale barrier is reached—specifically, platforms running high densities of short-lived agent sandboxes (e.g., hundreds of ephemeral 2-second pods per node) where sidecar Go runtime memory consumption or container startup latency is a proven bottleneck.

---

## 6. Staged Implementation Plan (When Ready to Build)

If and when the project decides to build DaemonSet mode, the implementation should proceed in four distinct, verifiable stages:

```
+-----------------------------------------------------------------------------+
| Stage 1: MVP DaemonSet on Kind (Passes #147 Deny Suite)                     |
| • CNI chaining plugin for Kind (bridge iptables)                            |
| • Host-network cmd/daemonset-portal (UID 1337)                              |
| • Source IP -> Pod resolution via Kubelet API; SO_ORIGINAL_DST              |
| • Node CA mount via hostPath / ConfigMap                                    |
| • Validated by tests/e2e TestSidecarEgressDenied                            |
+-----------------------------------------------------------------------------+
                                      |
                                      v
+-----------------------------------------------------------------------------+
| Stage 2: Dynamic Secret Scoping & Security Hardening                        |
| • Just-In-Time (JIT) gRPC secret delivery (#97/#99)                         |
| • In-memory secret zeroing on pod termination                               |
| • Admission validation: reject NET_RAW / NET_ADMIN on workloads             |
| • Anti-spoofing verification; direct-connect drop                           |
+-----------------------------------------------------------------------------+
                                      |
                                      v
+-----------------------------------------------------------------------------+
| Stage 3: Advanced Datapath (eBPF / cgroupv2)                                |
| • cgroup/connect4 socket redirection replacing iptables                     |
| • Kernel-enforced cgroup_id pod identity (immune to IP spoofing)            |
| • Socket-level reject (-EPERM) for non-intercepted ports                     |
+-----------------------------------------------------------------------------+
                                      |
                                      v
+-----------------------------------------------------------------------------+
| Stage 4: Production Packaging & Automated Trust                             |
| • ClusterTrustBundle integration for zero-manual CA distribution           |
| • Certified support for cloud CNIs (GKE Datapath v2, AWS VPC CNI)           |
+-----------------------------------------------------------------------------+
```

### Stage 1: Minimum Viable DaemonSet on Kind (Passing #147 Deny Suite)
The objective of Stage 1 is the smallest functional implementation that proves transparent node-level redirection and passes the e2e deny suite (#147) in a local `kind` cluster.

- **Deliverables**:
  1. `cmd/daemonset-portal`: A host-network daemon listening on port 8080 (HTTP) and 8443 (HTTPS), running as host UID 1337.
  2. `cmd/service-portal-cni`: A minimal CNI chaining plugin that configures `iptables` in the pod netns during `CNI ADD`:
     - DNAT port 80 and 443 to the host IP.
     - Drop all other outbound TCP/UDP traffic except cluster DNS.
  3. **Pod Identity**: The proxy queries `http://127.0.0.1:10255/pods` to map source IP to pod labels and `PortalPolicy`.
  4. **Loop Avoidance**: Host `iptables` rule exempting UID 1337 outbound traffic.
  5. **CA Trust**: Node CA cert mounted into test workload pod via ConfigMap/hostPath.
- **Acceptance Gate**:
  - `RUN_E2E=1 go test ./tests/e2e -run DaemonSet` passes all six assertions from `#147`:
    - Direct IP blocked.
    - Unlisted host blocked.
    - Non-intercepted port rejected.
    - Arbitrary DNS blocked.
    - Positive control succeeds with credential swap.
    - Bypass attempts fail.

### Stage 2: Dynamic Secret Scoping & Security Hardening
- **Deliverables**:
  1. Implement JIT secret provisioning via gRPC configurator (#97 / #99).
  2. Memory zeroing on pod deletion.
  3. Validating admission rules ensuring workload pods drop `NET_RAW` and `NET_ADMIN`.
  4. Proxy-side rejection of direct connections (where `SO_ORIGINAL_DST` equals proxy listener).

### Stage 3: Advanced Datapath (eBPF / cgroupv2)
- **Deliverables**:
  1. eBPF `cgroup/connect4` and `cgroup/connect6` programs attached to `kubepods.slice`.
  2. Direct socket redirection avoiding iptables NAT overhead.
  3. Kernel cgroup ID tracking for non-spoofable identity.
  4. Socket-level `-EPERM` rejection for blocked egress ports.

### Stage 4: Production Packaging & Automated Trust
- **Deliverables**:
  1. Integration with Kubernetes `ClusterTrustBundle` for standardized CA distribution.
  2. Cloud CNI compatibility adapters and Helm charts / K8s manifests.
