# Design: Interception Mechanisms for Service Portals

**Author**: codebot-robot / justinsb  
**Status**: Proposal / Investigation  
**Date**: October 2026  
**Target Path**: `docs/design/interception-mechanisms.md`  
**Tracking Issue**: [#159](https://github.com/gke-labs/service-portals/issues/159)  
**Related Issues**: [#147](https://github.com/gke-labs/service-portals/issues/147) (Deny Suite), [#148](https://github.com/gke-labs/service-portals/issues/148) (Egress Knobs), [#150](https://github.com/gke-labs/service-portals/issues/150) (Webhook Injector), [#151](https://github.com/gke-labs/service-portals/issues/151) (DaemonSet Mode), [#157](https://github.com/gke-labs/service-portals/issues/157) (Sidecar DNS)  
**Spike Artifact**: Branch [`spike/issue-159-node-hook`](https://github.com/codebot-robot/service-portals/tree/spike/issue-159-node-hook) (passes the #147 deny suite on kind with zero init containers)

---

## 1. Executive Summary & Problem Statement

`service-portals` acts as an intercepting proxy and credential swapper for untrusted application sandboxes (e.g., LLM agents, code execution runners, CI pipelines). Outbound requests to target domains (e.g., `api.anthropic.com`, `generics.google.internal`) are intercepted transparently, placeholder tokens are swapped with production credentials, and unauthorized egress is denied by default ("Tokens that aren't there can't leak").

### The Status Quo: In-Pod Init Container & Webhook
Today, interception is established via an admission webhook ([#150](https://github.com/gke-labs/service-portals/issues/150)) that modifies incoming Pod specifications to inject:
1. **An `initContainers` entry (`init-service-portals`)**: Runs with `CAP_NET_ADMIN` to configure `iptables` NAT redirection (`REDIRECT` to ports 8080/8443) and egress filtering rules (`PORTAL_EGRESS` chain) inside the pod network namespace, and generates an ephemeral root CA.
2. **A proxy container (`all-in-one-portal` / `service-portal-sidecar`)**: Runs as UID 1337 holding the pod's secrets and CA private key.
3. **CA Volume Mounts & Environment Variables**: Mounts public certificates into workload containers and sets `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, and `NODE_EXTRA_CA_CERTS`.
4. **DNS Configuration / Host Aliases**: Routes target hostnames to interceptable IPs via CoreDNS or sidecar DNS ([#157](https://github.com/gke-labs/service-portals/issues/157)).

### Limitations of Today's Approach
While functional, this model has notable architectural and security drawbacks:
- **Privilege in the Pod Spec**: The pod manifest must request `CAP_NET_ADMIN` for the init container. In multi-tenant clusters or environments enforcing restricted Pod Security Standards (PSS), granting network admin capabilities—even to an init container—requires exemptions.
- **The UID-1337 Loop Avoidance Vulnerability**: Loop avoidance relies on exempting packets from UID 1337 (`iptables -m owner --uid-owner 1337 -j RETURN`). If a workload container process can run as or switch to UID 1337, or if a bug allows UID manipulation, the workload can completely bypass interception.
- **Risk of Workload Capability Escalation**: If an untrusted workload container possesses or acquires `CAP_NET_ADMIN` (or runs with `allowPrivilegeEscalation: true`), it can flush or manipulate the pod-local iptables chains (`iptables -F`).
- **Container Startup Latency**: Executing an init container incurs container runtime orchestration overhead (image verification, cgroup initialization, process execution, certificate generation) adding hundreds of milliseconds to sandbox startup.
- **Webhook Fragility**: A cluster-wide mutating webhook introduces an operational dependency; if the webhook service becomes unavailable, pod creation fails or falls back to unintercepted execution.

### Goals of this Investigation
This design investigates alternative interception mechanisms that can hook into outbound traffic **outside the pod spec**, eliminating the in-pod init container, removing pod-level capabilities, ensuring unbypassable enforcement from within the sandbox, and evaluating compatibility across **GKE Standard**, **GKE Autopilot**, and local **kind** development clusters.

---

## 2. Comprehensive Comparison Table

The following matrix evaluates the seven candidate interception mechanisms against the eight criteria established in Issue #159:

| Mechanism | 1. Invisibility (Pod Spec Changes) | 2. Privileges & GKE Autopilot Support | 3. Bypass Resistance (Root, NET_ADMIN, UID 1337) | 4. Pod Identity (Node Proxy) | 5. CA Distribution (Without Webhook) | 6. Failure Mode (Concrete Mechanics) | 7. Kind & GKE Support (Standard vs Autopilot) | 8. Operational Complexity & Blast Radius |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **1. NRI Plugin (containerd / CRI-O)** | **High**: Pod needs only a label/annotation (`portals.gke.io/intercept`). | **Node Daemon**: Requires DaemonSet with `hostPath` to `/var/run/nri/nri.sock`. Pod has **zero** privileges.<br>**Autopilot**: ❌ Blocked (NRI is platform-managed; custom plugins restricted). | **Very High**: Rules installed from host into netns via `createRuntime` OCI hook. Pod cannot touch rules (no `NET_ADMIN`). | NRI maps `(Pod UID, Sandbox ID, IP)` to node proxy via IPC/shared memory. | **High**: NRI directly injects CA host bind mount and `SSL_CERT_FILE` into container OCI spec at creation. | **Fail-Closed**: Via containerd `required_plugins` config or pod annotation `required-plugins.noderesource.dev`. Pod creation aborts if plugin fails. | **Kind**: ✅ Fully supported (containerd 2.0+ default).<br>**GKE Standard**: ✅ Supported (1.33+).<br>**GKE Autopilot**: ❌ Blocked. | **Moderate**: Node daemon required. Blast radius limited to pods matching portal annotations on that node. |
| **2. DRA Driver + CDI Hooks** | **Low**: Requires `spec.resourceClaims` and container `resources.claims` in pod spec, or mutating webhook anyway. | **Node Daemon**: Requires privileged DRA driver DaemonSet.<br>**Autopilot**: ❌ Blocked (DRA only supported for Google GPU/TPU drivers). | **High**: CDI injects `createRuntime` OCI hook that installs rules from host. | Driver tracks `ResourceClaim` allocation to pod UID/IP. | **Moderate**: CDI injects host CA mount and env vars via `containerEdits`. | **Fail-Closed**: If `NodePrepareResources` fails, kubelet blocks container execution. | **Kind**: ⚠️ Requires kind feature gates (`DynamicResourceAllocation`).<br>**GKE Standard**: ✅ GA (1.34+, March 2026).<br>**Autopilot**: ❌ Blocked. | **Very High**: Significant architectural mismatch (treating security policy as hardware device). Heavy CRD/scheduling churn. |
| **3. CNI Chaining Plugin** | **High**: Pod needs only a label/annotation. | **Node Daemon**: Requires privileged DaemonSet writing to `/etc/cni/net.d` and `/opt/cni/bin`.<br>**Autopilot**: ❌ Blocked (Host paths to CNI directories forbidden). | **High**: Rules installed at CNI `ADD` in pod netns before any container process runs. | Difficult: `CNI_ARGS` provides Pod Name/Namespace, but not labels; requires synchronous kube-apiserver query. | **None**: CNI operates at network layer only; cannot inject CA mounts or env vars into container filesystems. | **Fail-Closed**: If CNI `ADD` exits non-zero, pod sandbox creation fails immediately. | **Kind**: ✅ Supported.<br>**GKE Standard**: ⚠️ Fragile (conflicts with GKE Dataplane V2 / Cilium reconciling `/etc/cni/net.d`).<br>**Autopilot**: ❌ Blocked. | **High**: Risk of disrupting node-wide networking if CNI config is corrupted or overwritten by GKE updates. |
| **4. eBPF (cgroup sock_addr / TC)** | **Highest**: Zero changes to pod spec (can match by pod cgroup/namespace). | **Node Daemon**: Requires privileged node daemon with `CAP_BPF`, `CAP_NET_ADMIN`, `hostPID`.<br>**Autopilot**: ❌ Blocked (`CAP_BPF` and host cgroups forbidden). | **Unrivaled**: Intercepts at socket syscall level (`connect4/6`). Unbypassable from within container even with root/NET_ADMIN. No iptables. | **Native**: `bpf_get_current_cgroup_id()` retrieves exact pod cgroup ID directly in the socket hook. | **None**: eBPF cannot inject files into container filesystem. Requires separate CA distribution. | **Fail-Closed**: BPF program returns `0` (drop/reject) if policy check fails or proxy is unreachable. | **Kind**: ⚠️ Requires kind node with mounted cgroup v2 and BPF capabilities.<br>**GKE Standard**: ⚠️ Dataplane V2 already uses eBPF; risk of hook collision.<br>**Autopilot**: ❌ Blocked. | **Very High**: Steep kernel/BPF maintenance cost, kernel version dependencies, verifier constraints. |
| **5. Host-Side for MicroVM Runtimes (gVisor/Kata)** | **Highest**: Zero changes beyond `runtimeClassName` (`gvisor` or `kata`). | **Node Daemon**: Host daemon manipulates host-end `veth` / `tap`. Guest container has **zero** privileges.<br>**Autopilot**: ❌ Custom host daemons blocked (though gVisor runtime itself is supported). | **Maximum**: Isolation boundary is the VM/hypervisor. Guest has zero visibility or access to host-side iptables/tc rules on `vethXXXX`/`tapXXXX`. | Host interface name (`vethXXXX` or `tapXXXX`) maps 1:1 to pod sandbox ID. | **Moderate**: Requires mounting CA via projected volume or NRI mount into sandbox. | **Fail-Closed**: Host-side drop rules drop egress if host proxy daemon is down. | **Kind**: ❌ MicroVMs require KVM/nested virt.<br>**GKE Standard**: ✅ Supported (GKE Sandbox / Kata).<br>**Autopilot**: ⚠️ Runtime allowed, but custom host-side interception hooks blocked. | **Moderate**: Ideal architectural fit for untrusted sandboxes on dedicated node pools. |
| **6. Native Sidecar (Drop Init, In-Pod NET_ADMIN)** | **Moderate**: Requires mutating webhook ([#150](https://github.com/gke-labs/service-portals/issues/150)) to inject native sidecar (`restartPolicy: Always`). | **Pod Capability**: Sidecar container requires `CAP_NET_ADMIN`. Workload has **zero** privileges.<br>**Autopilot**: ✅ Supported with `--workload-policies=allow-net-admin`. | **Moderate**: Workload cannot bypass if `drop: ["ALL"]` and `NoNewPrivs: 1`. Still relies on UID-1337 loop avoidance. | **Implicit**: 1:1 sidecar inside pod netns; no pod identity mapping required. | **Built-in**: Managed via in-pod Secret / emptyDir volume mounts. | **Fail-Closed**: Native sidecar starts before workload; `startupProbe` prevents workload start if rules fail. | **Kind**: ✅ Fully supported (Kubernetes 1.29+).<br>**GKE Standard**: ✅ Supported.<br>**GKE Autopilot**: ✅ Supported (with `allow-net-admin`). | **Lowest**: Minimal moving parts, no node-level daemons, standard Kubernetes primitives. |
| **7. Application-Level Only (HTTP_PROXY + NetworkPolicy)** | **High**: Pod needs proxy env vars and a NetworkPolicy selector label. | **Zero Privileges Anywhere**: Pod runs unprivileged (`runAsNonRoot: true`, `drop: ["ALL"]`). No node daemons.<br>**Autopilot**: ✅ 100% supported out of the box. | **High against exfiltration**: Direct connections dropped by NetworkPolicy. Limitation: Apps ignoring `HTTP_PROXY` fail rather than intercepting transparently. | Node/Gateway proxy maps client source IP (anti-spoofed by CNI). | **Standard**: `ClusterTrustBundle` (projected volume) or webhook/CDI mount. | **Fail-Closed**: If app ignores proxy, NetworkPolicy drops packets; if proxy is down, connection fails. | **Kind**: ✅ Supported.<br>**GKE Standard**: ✅ Supported.<br>**GKE Autopilot**: ✅ 100% Supported (default policies). | **Lowest**: Zero custom kernel or runtime code. Standard Kubernetes manifests. |

---

## 3. Detailed Technical Evaluation of Each Mechanism

### Mechanism 1: Node Resource Interface (NRI) Plugin
The Node Resource Interface is an open standard (managed under containerd and CRI-O) that allows external plugins to intercept container lifecycle events without modifying core runtime code. In containerd 2.0+ (the default in Kubernetes 1.32+ and kind), NRI is compiled in and enabled by default (`disable = false`).

#### Lifecycle Hook Execution
NRI plugins can subscribe to `RunPodSandbox`, `CreateContainer`, `StartContainer`, and `StopContainer`. During `CreateContainer`, an NRI plugin returns an `Adjustment` to containerd before runc is invoked:
1. **OCI Hook Injection**: The plugin injects an OCI `createRuntime` hook. When runc creates the container, it executes the hook binary on the host with the container's PID passed via stdin (`{"pid": 12345, "bundle": "..."}`).
2. **Namespace Entry from Host**: The hook binary on the host runs `nsenter -t <PID> -n iptables ...`, setting up the `PORTAL_OUTPUT` and `PORTAL_EGRESS` chains directly inside the pod's network namespace **before any container process executes**.
3. **Mount & Env Injection**: NRI can inject bind mounts (mounting a host-level node CA certificate directly into `/etc/ssl/certs/service-portal-ca.crt`) and inject environment variables (`SSL_CERT_FILE`, `HTTP_PROXY`).

#### Answers to Issue #159 Questions
- **Can NRI inject a sidecar container?** **No**. NRI operates on containers already defined in the pod spec by kubelet. It cannot dynamically introduce new containers into a Pod. Therefore, NRI must be paired with either a **per-node proxy** ([#151](https://github.com/gke-labs/service-portals/issues/151)) or a mutating admission webhook ([#150](https://github.com/gke-labs/service-portals/issues/150)).
- **How to ship the plugin?** A DaemonSet deploying a daemon container that mounts `/var/run/nri/nri.sock` via a `hostPath` volume. The daemon connects over ttRPC and registers with containerd. Alternatively, it drops a precompiled binary into `/opt/nri/plugins`.
- **GKE Support (Standard vs Autopilot)**:
  - *GKE Standard*: Fully supported on GKE 1.33+. Google uses NRI extensively (e.g., `nri-device-injector` for GPUDirect-TCPX on A3 clusters). DaemonSets mounting `/var/run/nri/nri.sock` run cleanly.
  - *GKE Autopilot*: NRI is enabled in the underlying containerd runtime, but **restricted to platform-managed Google agents** (`anetd`). Autopilot blocks user DaemonSets with `hostPath` to system directories or root capabilities, preventing custom NRI plugin deployment unless granted partner-level custom allowlists (GKE 1.35+).
- **Failure Mode & Enforcing Fail-Closed**:
  By default, containerd NRI has a 2-second request timeout and falls back to **fail-open** if a plugin is missing or times out. To enforce **fail-closed**, containerd 2.2+ supports:
  ```toml
  [plugins."io.containerd.nri.v1.nri".default_validator]
    enable = true
    required_plugins = ["service-portal-nri"]
  ```
  Or via the per-pod annotation:
  ```yaml
  metadata:
    annotations:
      required-plugins.noderesource.dev: '["service-portal-nri"]'
  ```
  If the plugin is down or errors, container creation is aborted (`CreateContainerError`), preventing unintercepted traffic from ever flowing.

---

### Mechanism 2: DRA Driver + Container Device Interface (CDI)
Dynamic Resource Allocation (graduated to GA in Kubernetes 1.34/1.37, and GA on GKE Standard in March 2026) replaces legacy device plugins with a claims-based resource model (`resource.k8s.io`). A pod requests a resource class (e.g., `portal-egress`), and the DRA node driver returns a CDI specification containing `containerEdits`.

#### Evaluation & Answers to Issue #159 Questions
- **Is using DRA for egress interception reasonable or an architectural abuse?**
  **Architectural Mismatch / Abuse**. DRA is designed for physical or assignable hardware devices (GPUs, TPUs, SR-IOV NICs). Using DRA for security and egress policy introduces severe overhead:
  1. Every sandbox pod requires a `ResourceClaim` object, adding API server storage and scheduler churn.
  2. The Kubernetes scheduler must invoke DRA scheduling algorithms for a software network hook.
  3. Deletion and cleanup of ephemeral claims adds latency to short-lived sandbox churn.
- **Can a `ResourceClaimTemplate` be defaulted by namespace?**
  **No**. Kubernetes `LimitRange` natively defaults `cpu`, `memory`, and `storage`, but has no support for `resourceClaims`. Defaulting a `ResourceClaimTemplate` requires a mutating admission webhook—defeating the goal of avoiding a webhook.
- **Kind and GKE Support**:
  - *Kind*: Requires custom kind cluster configuration with feature gates `DynamicResourceAllocation: true` and runtime config `resource.k8s.io/v1beta1: "true"`.
  - *GKE*: GA on GKE Standard (1.34+). Autopilot supports DRA solely for managed GPU/TPU devices, not third-party drivers.

---

### Mechanism 3: CNI Chaining Plugin
CNI chaining (the model popularized by Istio-CNI and Calico) inserts a secondary binary (`service-portal-cni`) into the host `/etc/cni/net.d/*.conflist` chain. During `RunPodSandbox`, containerd executes `CNI ADD`. The plugin receives `CNI_NETNS` (the pod netns path) and executes iptables rules inside the pod netns from the host before any container starts.

#### Evaluation & Answers to Issue #159 Questions
- **GKE Autopilot Compatibility**: **Strictly Incompatible**. Autopilot completely disallows DaemonSets with `hostPath` access to `/etc/cni/net.d` or `/opt/cni/bin` and forbids `privileged: true`.
- **Conflict with Provider CNI (GKE Dataplane V2)**:
  GKE Dataplane V2 is an integrated, Cilium-based networking stack managed by Google. Dataplane V2 dynamically reconciles `/etc/cni/net.d`. Modifying `.conflist` files on GKE nodes frequently causes configuration overrides during node reboots, agent updates, or autoscaling events, resulting in silent interception failures or node-wide network partition.
- **Pod Label Discovery Limitation**:
  `CNI_ARGS` supplies `K8S_POD_NAME` and `K8S_POD_NAMESPACE`, but **omits pod labels and annotations**. To determine whether a pod requires portal interception, the CNI plugin must synchronously call the Kubernetes API server (`GET /api/v1/namespaces/{ns}/pods/{pod}`) during the latency-critical pod networking phase. In high-density sandbox environments, burst scheduling creates severe API server load and networking timeouts.
- **CA Distribution Inability**: CNI operates exclusively at the network layer. It has no mechanism to mount CA bundles or set environment variables in container filesystems.

---

### Mechanism 4: eBPF (cgroup sock_addr & Traffic Control)
eBPF programs attached to pod cgroups via `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` (`sock_addr/connect4` and `sock_addr/connect6`) intercept outbound `connect()` system calls at the socket layer in the kernel.

#### Evaluation & Answers to Issue #159 Questions
- **Unbypassable Enforcement**: eBPF cgroup hooks execute in the host kernel context above the network namespace. Even if a workload runs as root with `CAP_NET_ADMIN` and `CAP_NET_RAW`, it has no access to the host cgroup hierarchy or BPF subsystems and cannot bypass or unload the program.
- **Pod Identity Resolution**: The socket hook provides `bpf_get_current_cgroup_id()`. The BPF program writes a mapping `(src_ip, src_port) -> cgroup_id` into a BPF hash map before redirecting the connection to the node proxy listener. When the node proxy accepts the connection, it queries the map to establish the caller's pod identity with cryptographic certainty, impervious to IP/MAC spoofing.
- **GKE Dataplane V2 Interaction**:
  GKE Dataplane V2 already utilizes Cilium eBPF programs on host cgroups. Running custom cgroup eBPF programs alongside Dataplane V2 creates risk of hook chaining conflicts or verifier compatibility issues across GKE node kernel updates.
- **Autopilot Support**: GKE Autopilot strictly forbids deploying privileged DaemonSets with `CAP_BPF` or `CAP_SYS_ADMIN`.

---

### Mechanism 5: Host-Side Interception for Sandboxed Runtimes (gVisor & MicroVMs)
When sandboxes run under specialized microVM or isolation runtimes (e.g., `runtimeClassName: gvisor` in GKE Sandbox, or `runtimeClassName: kata` in Kata Containers / Firecracker), the pod's networking model changes fundamentally:
- **gVisor (runsc)**: Uses Netstack (user-space TCP/IP in the Sentry process). Outbound traffic is emitted via an `AF_PACKET` socket connected to a `veth` pair. One end (`eth0`) is in the sandbox netns; the peer end (`vethXXXX`) resides in the host root network namespace.
- **Kata / MicroVMs**: The guest kernel connects via a virtual `TAP` interface (`tapXXXX`) on the host bridge.

#### Why Host-Side Interception is the Gold Standard for Sandboxes
1. **Physical Isolation from Guest**: Redirection rules (via `iptables`, `nftables`, or `tc` clsact filters) are applied to the **host end** (`vethXXXX` or `tapXXXX`) in the host network namespace. Even if an attacker achieves arbitrary remote code execution in the sandbox or compromises the guest kernel, they have zero access to the host network namespace or host routing tables.
2. **Loop Avoidance Solved Cleanly**: Outbound traffic redirected on the host side targets a local proxy port on the host (or node proxy). The proxy forwards validated traffic out of the host's physical network adapter (`eth0`). Because the redirect rules exist solely on the `vethXXXX` interface, the proxy's outbound traffic never loops, completely eliminating the fragile UID-1337 loop avoidance trick!
3. **Pairing with RuntimeClass**: An NRI plugin or node agent detects `runtimeClassName: gvisor` / `kata` during `RunPodSandbox` and automatically attaches `tc` filters to the host peer interface upon interface creation.

---

### Mechanism 6: Native Sidecar (Drop Init Container, In-Pod NET_ADMIN)
Kubernetes 1.29+ natively supports sidecar containers (`initContainers` with `restartPolicy: Always`). Kubernetes 1.30+ (GA in 1.36) introduces user namespaces (`hostUsers: false`).

#### Architecture & Evaluation
- **Eliminating the Init Container**: Instead of running a dedicated `init-service-portals` init container, the `all-in-one-portal` proxy runs as a native sidecar container granted `CAP_NET_ADMIN`.
- **Startup Sequencing**: The native sidecar entrypoint installs the iptables rules in the pod netns and immediately starts the proxy server. The sidecar's `startupProbe` (checking `http://127.0.0.1:8080/healthz`) guarantees that no workload container can start until rules are active and the proxy is listening.
- **GKE Autopilot Compatibility**:
  GKE Autopilot permits `CAP_NET_ADMIN` in container specs when the cluster is configured with the workload policy:
  ```bash
  gcloud container clusters create-auto CLUSTER_NAME --workload-policies=allow-net-admin
  ```
  This makes Option 6 fully compatible with GKE Autopilot clusters where this policy is enabled.
- **Residual Tradeoff**: Still relies on UID-1337 loop avoidance inside the shared pod network namespace.

---

### Mechanism 7: Application-Level Only (HTTP_PROXY + Egress NetworkPolicy)
Option 7 establishes a zero-privilege interception and egress enforcement model:
1. **Workload Environment**: The workload pod runs completely unprivileged (`runAsNonRoot: true`, `drop: ["ALL"]`, `allowPrivilegeEscalation: false`). No init container, no `NET_ADMIN`.
2. **Proxy Environment Injection**: Standard proxy variables (`HTTP_PROXY`, `HTTPS_PROXY`, `http_proxy`, `https_proxy`, `NO_PROXY`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`) are injected into the workload container.
3. **Egress NetworkPolicy Enforcement**: A standard Kubernetes `NetworkPolicy` isolates the sandbox pod:
   - All external egress to `0.0.0.0/0` is **denied by default**.
   - Egress is permitted **only** to the proxy endpoint (e.g., node proxy DaemonSet, cluster proxy Service, or in-pod sidecar loopback) and cluster CoreDNS (`10.96.0.10:53`).
4. **Integration with Sidecar DNS ([#157](https://github.com/gke-labs/service-portals/issues/157))**:
   Under standard HTTP forward proxy protocol, the client issues `GET http://target/` or `CONNECT target:443` directly to the proxy. The client **does not resolve external target hostnames locally**; DNS resolution is delegated entirely to the proxy upstream!

#### Bypass Resistance Analysis
- *Can a malicious workload bypass the proxy?*
  If an untrusted script unsets `HTTP_PROXY` and attempts a raw TCP connection to an external IP or metadata server (`169.254.169.254`), the cluster CNI NetworkPolicy engine (enforced at the host `veth` / eBPF layer) **instantly drops the packets**. Exfiltration is prevented.
- *Tradeoff*: Workloads or legacy binaries that do not honor `HTTP_PROXY` or issue raw TCP sockets cannot connect out. For AI agent sandboxes (Python `requests`, `httpx`, `openai`, `google-genai`, Node.js `fetch`, Go `http.Client`, `curl`, `wget`), proxy environment variables are universal and first-class.

---

## 4. Cross-Cutting Architectural Concerns

### 4.1 Pod Identity Resolution & Anti-Spoofing
When a proxy is shared outside the pod (DaemonSet or Gateway Service):
- **Source IP Binding**: Kubernetes CNIs (Dataplane V2, Calico, Kindnet) enforce source IP anti-spoofing at the veth interface using eBPF or rp_filter. A workload container cannot emit packets with a spoofed IP.
- **cgroup ID (eBPF / NRI)**: On the node, `cgroup_id` provides unforgeable kernel identity.
- **In-Pod Sidecar Advantage**: Retaining a 1:1 sidecar (Options 6 & 7) guarantees unambiguous pod identity without any lookup infrastructure.

### 4.2 CA Certificate Distribution Without a Webhook
- **`ClusterTrustBundle`**: Graduated to GA in upstream Kubernetes 1.37 and GKE 1.37 (`certificates.k8s.io/v1`). Pods consume cluster-wide trust anchors via projected volumes:
  ```yaml
  volumes:
  - name: ca-bundle
    projected:
      sources:
      - clusterTrustBundle:
          name: portal-root-ca
          path: tls.crt
  ```
- **NRI / CDI Direct Mounts**: NRI plugins and CDI specifications inject the host-minted CA certificate directly into container mount specifications at creation time, requiring **zero volume declarations in the pod spec**.

### 4.3 Loop Avoidance Mechanics
| Method | Where Applied | Risk Profile |
| :--- | :--- | :--- |
| **UID 1337 Exemption** | Pod-local iptables | Vulnerable if workload container runs as UID 1337 or escalates permissions. |
| **SO_MARK Socket Marking** | Sidecar proxy socket | Proxy marks outbound packets (`setsockopt SO_MARK 0x5350`). iptables matches mark. Avoids UID dependency. |
| **Host-Side Interface Routing** | Host veth / tap (gVisor/Kata) | **Zero risk**. Redirect rule applies only to ingress on `vethXXXX`. Outbound proxy traffic leaves `eth0`. |
| **Explicit HTTP(S)_PROXY** | Application layer | **Zero risk**. Workload sends explicit proxy requests; proxy connects directly to upstream. |

### 4.4 Fail-Closed Enforcement
Egress security requires a strict fail-closed posture:
1. **NRI Failure**: Configure `default_validator.required_plugins = ["service-portal-nri"]` or annotate the pod with `required-plugins.noderesource.dev`. Container creation fails immediately if the plugin is offline.
2. **OCI Hook Failure**: OCI `createRuntime` hooks run with `set -eo pipefail`. If rule insertion fails, runc terminates container initialization.
3. **NetworkPolicy**: Deny-by-default egress policies ensure that if proxy injection fails, raw outbound packets are blackholed.

---

## 5. Strategic Recommendations & Roadmap

### 5.1 Recommendation for GKE Autopilot
GKE Autopilot enforces strict node and privilege isolation:
- **Primary Production Path**: **In-Pod Admission Webhook ([#150](https://github.com/gke-labs/service-portals/issues/150)) + Native Sidecar (Option 6)**. Enable `--workload-policies=allow-net-admin` on the cluster. The mutating webhook injects the native sidecar, rules, and DNS configuration. Workloads require no manifest changes.
- **Zero-Privilege Fallback Path**: **Application-Level Interception (Option 7)**. For standard Autopilot clusters where `allow-net-admin` is not enabled, inject proxy environment variables and apply default-deny egress `NetworkPolicy`. This requires zero special capabilities anywhere.

### 5.2 Recommendation for GKE Standard
- **Phase 1 (Short-Term)**: Deploy Webhook + Native Sidecar (Option 6) to eliminate the separate init container.
- **Phase 2 (Medium-Term High-Density Sandboxes)**:
  - For standard container sandboxes: **NRI Plugin (Option 1)** paired with Per-Node Proxy DaemonSet ([#151](https://github.com/gke-labs/service-portals/issues/151)). Eliminates all in-pod capabilities and automates CA mounting via containerd.
  - For untrusted/unvetted agent execution: **Host-Side Interception (Option 5)** with GKE Sandbox (`runtimeClassName: gvisor`).

### 5.3 Guidance on Issue #151 (DaemonSet Mode)
- **Do NOT proceed with CNI Chaining**: CNI chaining is brittle on GKE Dataplane V2 and cannot inject CA certificates.
- **Proceed with #151 ONLY when coupled with NRI (Option 1) or Host-Side Interception (Option 5)**: NRI provides the exact lifecycle hooks needed to configure netns rules and inject CA mounts without pod privileges.

---

## 6. The Kind Spike: Empirical Verification

To empirically validate that interception and default-deny egress can be enforced without an in-pod init container, a complete throwaway spike was created and tested on kind.

### Spike Overview
- **Repository Branch**: [`spike/issue-159-node-hook`](https://github.com/codebot-robot/service-portals/tree/spike/issue-159-node-hook)
- **Mechanism Tested**: Node-level runtime hook (emulating containerd NRI / OCI `createRuntime` hook injection).
- **Workload Security Context**:
  - `initContainers`: **NONE** (completely absent from pod manifest).
  - `runAsUser`: `1000` (non-root).
  - `allowPrivilegeEscalation`: `false`.
  - Capabilities: Default unprivileged (`CAP_NET_ADMIN` is NOT requested anywhere in the pod).

### Spike Architecture on Kind
1. An OCI `createRuntime` hook (`/kind/bin/portal-hook.sh`) is registered in `/etc/containerd/cri-base.json` on the kind control-plane node.
2. When the pod is created, runc executes the hook on the node with the container's PID before any application process starts.
3. The hook enters the pod network namespace from the host (`nsenter -t $PID -n`) and installs:
   - `PORTAL_OUTPUT`: NAT redirection of ports 80 and 443 to the local proxy ports.
   - `PORTAL_EGRESS`: Filter rules allowing only localhost/proxy ports, proxy UID 1337, and cluster DNS (`10.96.0.10:53`), rejecting all other TCP and UDP outbound traffic with `icmp-port-unreachable`.
4. Workload container process starts in an already-locked network namespace.

### Test Results: #147 Deny Suite Passing Cleanly
Running `TestNodeHookInterceptionDenied` on kind executes all six negative and positive assertion suites:

```text
=== RUN   TestNodeHookInterceptionDenied
    e2e_test.go:1003: Creating cluster node-hook-denied-e2e
    e2e_test.go:1008: Building docker image all-in-one-portal:e2e
    e2e_test.go:1009: Building docker image toolbox:e2e
    e2e_test.go:1011: Loading image all-in-one-portal:e2e into kind
    e2e_test.go:1012: Loading image toolbox:e2e into kind
    e2e_test.go:1015: Installing runtime interception hook on kind control-plane node
    e2e_test.go:1058: Applying manifest content
    e2e_test.go:1059: Waiting for deployment backend
    e2e_test.go:1063: Backend ClusterIP: 10.96.29.15
    e2e_test.go:1095: Applying manifest content
    e2e_test.go:1186: Applying manifest content
    e2e_test.go:1187: Waiting for pod with label app=test-client-sidecar-deny to be ready
=== RUN   TestNodeHookInterceptionDenied/DirectIP_InterceptedPort_HTTP
    e2e_test.go:1197: direct IP HTTP request failed as expected: exit status 8
=== RUN   TestNodeHookInterceptionDenied/DirectIP_InterceptedPort_HTTPS
    e2e_test.go:1212: direct IP HTTPS request failed as expected: exit status 4
=== RUN   TestNodeHookInterceptionDenied/UnlistedHostname_InterceptedPort_HTTP
    e2e_test.go:1228: unlisted host HTTP request failed as expected: exit status 8
=== RUN   TestNodeHookInterceptionDenied/UnlistedHostname_InterceptedPort_HTTPS
    e2e_test.go:1243: unlisted host HTTPS request failed as expected: exit status 4
=== RUN   TestNodeHookInterceptionDenied/NonInterceptedPort_HTTP_8080
    e2e_test.go:1259: non-intercepted port HTTP request failed as expected: exit status 4
=== RUN   TestNodeHookInterceptionDenied/NonInterceptedPort_RawTCP_9999
    e2e_test.go:1274: raw TCP connection to port 9999 failed as expected: exit status 1 (connection refused)
=== RUN   TestNodeHookInterceptionDenied/ArbitraryDNS_Blocked
    e2e_test.go:1285: toolbox probe dns to 8.8.8.8 failed as expected: exit status 1 (operation not permitted)
    e2e_test.go:1293: cluster DNS resolution succeeded as expected
=== RUN   TestNodeHookInterceptionDenied/PositiveControl_GeminiHTTPS
    e2e_test.go:1305: positive control output: {"headers":{"Authorization":["Bearer gemini-sidecar-token"]}}
=== RUN   TestNodeHookInterceptionDenied/BypassAttempt_Disallowed
    e2e_test.go:1342: workload NoNewPrivs status: NoNewPrivs: 1
    e2e_test.go:1353: su to UID 1337 failed as expected: exit status 1
--- PASS: TestNodeHookInterceptionDenied (40.57s)
```

This live test confirms that:
1. An unprivileged pod with **no init container** can be locked down from the node runtime hook.
2. The proxy correctly intercepts allowed hostnames and injects credentials.
3. Direct IPs, unlisted hostnames, non-intercepted ports, and external DNS servers are rejected.
4. Workload privilege escalation to proxy UID 1337 is completely prevented.
