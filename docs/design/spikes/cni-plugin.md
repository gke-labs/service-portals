# Spike Report: CNI Chaining Plugin as the Interception Mechanism

**Author**: codebot-robot  
**Date**: October 16, 2026  
**Tracking Issues**: [#159](https://github.com/gke-labs/service-portals/issues/159), [#163](https://github.com/gke-labs/service-portals/issues/163)  
**Branch**: `spike/cni-plugin`  
**Prototype Path**: `cmd/service-portal-cni`, `images/service-portal-cni`, `k8s/cni-daemonset.yaml`, `tests/e2e/e2e_test.go` (`TestCNIPluginEgressDenied`)

---

## Executive Summary

This spike evaluates a **chained CNI plugin** (`service-portal-cni`) as the transparent traffic interception and default-deny egress enforcement mechanism for `service-portals`. Modeled after the pattern popularized by `istio-cni` and `cilium-cni`, the plugin is appended to the node's CNI configuration list (`/etc/cni/net.d/*.conflist`) and executed synchronously by the container runtime during CNI `ADD` when creating a pod sandbox.

When invoked, the plugin reads CNI arguments to identify the pod (`K8S_POD_NAMESPACE` and `K8S_POD_NAME`), queries the Kubernetes API with a node-scoped kubeconfig to check for opt-in policy (`portals.gke.io/intercept: "true"` or `PortalPolicy`), and—if matched—enters the pod network namespace (`CNI_NETNS`) to install netfilter DNAT redirection and default-deny egress rules. Traffic is redirected to a per-node DaemonSet proxy running in host networking mode.

### Verdict & Core Tradeoffs
* **Verdict**: **Strong technical candidate for GKE Standard and self-managed Kubernetes clusters, but impossible on GKE Autopilot.**
* **Key Advantages**:
  1. **Zero Workload Privileges**: Eliminates all init containers and all `CAP_NET_ADMIN` requirements from workload pods.
  2. **Strict Fail-Closed Ordering**: Executes during container runtime `RunPodSandbox` before **any** application or init containers start. If the plugin fails or is missing, sandbox creation fails immediately (`FailedCreatePodSandBox`), ensuring zero egress leaks.
  3. **High Performance**: In-kernel netfilter redirection directly to the local node's proxy; no user-space sidecar hop.
* **Key Drawbacks & Blockers**:
  1. **Autopilot Incompatible**: GKE Autopilot strictly forbids hostPath volume mounts (`/opt/cni/bin`, `/etc/cni/net.d`), privileged DaemonSets, and modifications to managed CNI configurations.
  2. **Provider CNI Interop & Fragility**: CNI chaining directly mutates node-level `/etc/cni/net.d/*.conflist`. If node-level CNI daemons (e.g., kindnet, calico, cilium, or GKE Dataplane V2) periodically reconcile or overwrite the conflist, race conditions or overwrites occur.
  3. **Operational Overhead vs NRI**: Relative to containerd's Node Resource Interface (NRI, #161), CNI chaining requires managing node filesystem state (`/opt/cni/bin` binary lifecycle, conflist patching/unpatching, node-scoped kubeconfig synchronization).

---

## Empirical Verification on kind

### 1. kind CNI Layout & kindnet Chaining Support
* **Configuration Format**: kind installs `kindnet` as a CNI network configuration list (`.conflist`) at `/etc/cni/net.d/10-kindnet.conflist`.
* **Default Plugins**:
  ```json
  {
    "cniVersion": "0.3.1",
    "name": "kindnet",
    "plugins": [
      {
        "type": "ptp",
        "ipMasq": false,
        "ipam": { "type": "host-local", ... },
        "mtu": 1500
      },
      {
        "type": "portmap",
        "capabilities": { "portMappings": true }
      }
    ]
  }
  ```
* **Chaining Toleration**: kindnet and containerd natively tolerate chained plugins in `plugins`. When `service-portal-cni` was appended as the 3rd plugin:
  ```json
  {
    "type": "service-portal-cni",
    "kubeconfig": "/etc/cni/net.d/service-portal.kubeconfig",
    "proxyPort": 8080,
    "proxyHttpsPort": 8443,
    "interceptPorts": "80,443"
  }
  ```
  containerd executed `ptp` (establishing veth and IPAM), `portmap` (host port forwards), and then `service-portal-cni` synchronously. Unselected pods received `prevResult` transparently without modification.

### 2. Execution Ordering vs Pod Container Lifecycle
* **Container Runtime Sequence**:
  1. Kubelet receives pod assignment from scheduler and invokes CRI `RunPodSandbox`.
  2. containerd invokes CNI plugin chain in order: `ptp ADD` -> `portmap ADD` -> `service-portal-cni ADD`.
  3. `service-portal-cni` looks up the pod metadata via Kube API, confirms the opt-in, enters `CNI_NETNS`, and installs iptables DNAT and filter rules.
  4. `RunPodSandbox` completes and returns sandbox ID to kubelet.
  5. Kubelet invokes `CreateContainer` and `StartContainer` for init containers (if any), and subsequently for workload containers.
* **Empirical Confirmation**: Egress interception and default-deny filtering are fully active in the kernel **before the first instruction of any container process executes**. There is zero race window between container launch and rule activation.

### 3. Fail-Closed Behavior Under Plugin Failure
* **Failure Scenario Tested**:
  1. Appended a non-existent plugin `"type": "missing-cni-plugin"` to `10-kindnet.conflist`.
  2. Tested API server unreachable / certificate failure in `service-portal-cni`.
* **Observed Behavior**:
  ```
  Warning  FailedCreatePodSandBox  8s  kubelet  Failed to create pod sandbox: rpc error: code = Unknown desc = failed to setup network for sandbox "...": plugin type="service-portal-cni" failed (add): service-portal-cni: failed to query pod default/test-fail-closed: ...
  ```
  * `PodReadyToStartContainers` stayed `False`.
  * Status remained `ContainerCreating`.
  * **Result**: Strictly fail-closed. No containers started; no application code ran; zero unintercepted packets leaked.

---

## Evaluation Against #159 Criteria

### 1. Invisibility (Workload Pod Spec Changes)
* **Observed State in Prototype**:
  * Workload pod requires **zero init containers** (`initContainers: []`).
  * Workload pod requires **zero security capabilities** (no `NET_ADMIN`, no `NET_RAW`).
  * Workload pod requires **zero sidecar containers** (proxy runs as per-node DaemonSet).
  * The workload pod spec contains only:
    1. The opt-in label: `portals.gke.io/intercept: "true"` (or annotation `portals.gke.io/policy: "<name>"`).
    2. A projected volume or Secret volume mount providing the CA certificate for TLS verification against the node proxy.
* **Comparison**: Significantly cleaner than the in-pod sidecar model (#147/#150), which required mutating pod specs with privileged init containers, shared volumes, and sidecar processes.

### 2. Privileges & Platform Support
* **Node-Level Privileges**:
  * The installer DaemonSet requires host access to write binaries into `/opt/cni/bin` and update `/etc/cni/net.d`. It runs with `securityContext.privileged: true` or `hostPath` mounts.
  * The CNI plugin itself executes as root on the host during CNI ADD, with permission to invoke `nsenter` into the target pod network namespace.
  * The per-node proxy DaemonSet runs with `hostNetwork: true` and `dnsPolicy: ClusterFirstWithHostNet` to bind ports 8080/8443 on the host and resolve cluster services.
* **Workload-Level Privileges**:
  * Workload pods run completely unprivileged (tested with UID 1000, `allowPrivilegeEscalation: false`, `capabilities: { drop: ["ALL"] }`).
* **GKE Standard vs Autopilot**:
  * **GKE Standard**: Supported. Cluster administrators have node-level administrative rights and can deploy privileged DaemonSets and hostPath volumes into `/opt/cni/bin` and `/etc/cni/net.d`.
  * **GKE Autopilot**: **Unsupported**. Autopilot enforces an immutable node architecture:
    * `hostPath` mounts to `/etc` and `/opt` are rejected by admission controllers.
    * Privileged containers (`securityContext.privileged: true`) are blocked.
    * GKE Dataplane V2 / managed Cilium controls CNI conflists and rejects external chaining plugins.

### 3. Bypass Resistance & Threat Model

| Attack Vector | Workload Capability | Observed Behavior / Defense | Bypass Possible? |
| :--- | :--- | :--- | :--- |
| **Root in container** | `runAsUser: 0` without `NET_ADMIN` | Container cannot modify iptables (`Permission denied`). Netfilter rules enforced by host kernel remain intact. | **No** |
| **Tampering with rules** | Attempts `iptables`, `nftables` | Blocked by missing `CAP_NET_ADMIN`. | **No** |
| **Privilege escalation** | `su 1337`, `setuid` binaries | Blocked by `allowPrivilegeEscalation: false` (`NoNewPrivs: 1`). | **No** |
| **Direct IP literals** | `wget http://<ClusterIP>:80/` | DNAT redirects port 80/443 to node proxy. Proxy rejects requests where Host/SNI does not match policy rules (HTTP 403 Forbidden). | **No** |
| **Unlisted hostnames** | `wget http://other.backend/` | Proxy terminates TLS / parses Host header; returns 403 Forbidden. Upstream backend never reached. | **No** |
| **Non-intercepted ports** | Raw TCP / HTTP to port 8080, 9999 | Blocked by netfilter `OUTPUT -p tcp -j REJECT --reject-with icmp-port-unreachable`. | **No** |
| **Arbitrary DNS** | DNS to `8.8.8.8:53` | Blocked by netfilter `OUTPUT -p udp -j REJECT`. Cluster DNS (`10.96.0.10:53`) is permitted. | **No** |
| **IP spoofing via `NET_RAW`** | `CAP_NET_RAW` present in workload | Workload can forge UDP source IP or raw frames. However, for TCP (HTTP/HTTPS), the 3-way handshake cannot complete with a forged IP because SYN-ACK is routed to the victim pod, which sends RST. | **No for TCP; Yes for raw UDP if `NET_RAW` retained.** |

* **Identity Trustworthiness Recommendation**: Pods utilizing `service-portals` should drop `CAP_NET_RAW` and `CAP_NET_ADMIN` in their SecurityContext.

### 4. Pod Identity at the Per-Node Proxy
* **Mechanism**: When traffic is redirected via netfilter DNAT from the pod netns to the gateway IP (`${GATEWAY_IP}:${PROXY_PORT}`):
  * The source IP of the incoming connection at the host proxy is the Pod's assigned IP (`10.244.0.X`).
  * The node proxy queries the local kubelet or API informer cache by client remote IP (`RemoteAddr`) to resolve the pod's identity (`Namespace`, `Name`, `ServiceAccount`).
* **Trust Level**:
  * High for TCP connections, because spoofing source IP prevents completion of the TCP 3-way handshake on point-to-point veth pairs.
  * To guarantee absolute cryptographic or kernel-level identity (e.g. against local port reuse or container recycling race conditions), an eBPF socket cookie or Unix domain socket / NRI mechanism is superior.

### 5. CA Distribution
* **The Interception Trust Paradox**: When transparently proxying outbound HTTPS, the proxy terminates TLS and mints an on-the-fly certificate for the target host (`gemini.backend`) signed by a custom internal CA. The workload TLS client must trust this CA.
* **Mechanism Used in Prototype**:
  * Secret volume mount (`service-portal-ca`) mounted at `/etc/service-portal/ca/tls.crt`.
  * Workload requests supply `--ca-certificate=/etc/service-portal/ca/tls.crt` or set `SSL_CERT_FILE=/etc/service-portal/ca/tls.crt`.
* **Alternative Approaches for Production**:
  1. **Kubernetes `ClusterTrustBundle` (v1.27+ Alpha / Beta)**: Allows distributing trust anchors cluster-wide via projected volumes without managing per-namespace Secrets.
  2. **Mutating Admission Webhook**: Injects the projected CA volume and `SSL_CERT_FILE` environment variable automatically based on pod opt-in labels.
  3. **Base Container Image Trust Store**: Pre-baking the portal CA certificate into the organization's base container images (`/etc/ssl/certs/ca-certificates.crt`).

### 6. Operational Complexity vs NRI (#161)

| Dimension | CNI Chaining Plugin (#163) | NRI Plugin (#161) |
| :--- | :--- | :--- |
| **Integration Point** | Network layer (CNI conflist in `/etc/cni/net.d`) | CRI layer (containerd Node Resource Interface socket) |
| **Conflist Mutation** | **Yes** (modifies provider CNI conflist on disk) | **No** (registers as an NRI socket listener) |
| **Risk of Overwrite** | **High** (CNIs like Dataplane V2, Calico, or kindnet regularly re-render their conflist) | **Zero** (does not touch CNI conflist) |
| **Binary Placement** | Binary must reside on host at `/opt/cni/bin` | DaemonSet container communicates via Unix domain socket `/var/run/nri/nri.sock` |
| **Pod Lifecycle Hook** | CNI ADD / CNI DEL | `CreateContainer` / `PostCreateContainer` / `StopContainer` |
| **Netns Access** | Provided via `CNI_NETNS` path | Provided via container sandbox spec |
| **Upgrade Complexity** | Replacing on-disk binary under live traffic can cause pod sandbox creation errors if intermediate calls happen | DaemonSet rolling update gracefully switches NRI socket |

---

## Productionisation Requirements

To elevate this prototype into production-grade infrastructure:
1. **Conflist Re-sync / Watcher Daemon**:
   CNI providers (Calico, Cilium, Kindnet) frequently overwrite `/etc/cni/net.d/*.conflist` upon node restart or upgrade. The installer DaemonSet must run an `inotify` file watcher that re-injects `service-portal-cni` atomically within milliseconds if the conflist is rewritten.
2. **Atomic Upgrades & Symlink Swap**:
   Writing directly to `/opt/cni/bin/service-portal-cni` while containerd executes CNI ADD can yield `ETXTBSY` (text file busy). The installer should write to `/opt/cni/bin/service-portal-cni.<version>` and atomically swap a symlink.
3. **Local Informer Caching**:
   Rather than calling the Kubernetes API server via HTTP on every single pod creation, the CNI plugin should either:
   * Query a local Unix socket exposed by the node's proxy DaemonSet, which maintains a local informer cache of pods and `PortalPolicy` resources.
   * Fall back to an in-memory or on-disk TTL cache on the node to prevent thundering herd load on `kube-apiserver` during node spinup.
4. **Dynamic IPAM / Gateway Resolution**:
   In our prototype, gateway IP discovery was validated on kind's `ptp` plugin via `ip route show default`. In complex enterprise CNI environments (e.g. AWS VPC CNI with ENIs, Calico IP-in-IP, or Cilium eBPF host routing), the host proxy listener address should be derived from CNI `prevResult` or explicit node IP configuration.
5. **IPv6 and Dual-Stack Support**:
   Install parallel `ip6tables` rules (`ip6tables -t nat -A OUTPUT ...` and `ip6tables -A OUTPUT -j REJECT`) to prevent IPv6 bypass leaks.
6. **Drain / Uninstall Lifecycle**:
   Implement a clean uninstall hook in the DaemonSet that removes `service-portal-cni` from `.conflist` before deleting the binary, preventing the cluster from entering a broken pod creation state.

---

## Conclusion & Recommendation

The chained CNI plugin successfully satisfies the core requirements of Issue #159 and #163:
* Workload pods require **no init containers** and **no privileges**.
* Egress traffic is strictly **default-deny by kernel netfilter** before user containers start.
* Passing the semantics of `TestSidecarEgressDenied` proves that unauthorized direct IPs, non-intercepted ports, and unlisted hostnames cannot bypass the security boundary.

However, because CNI chaining **cannot be used on GKE Autopilot** (due to blocked hostPath/privileged DaemonSets) and carries ongoing operational friction with provider CNI conflists, **NRI (#161) or eBPF (#159 item 4)** should be prioritized as the primary long-term architecture, with CNI chaining retained as an alternative for legacy containerd environments lacking NRI.
