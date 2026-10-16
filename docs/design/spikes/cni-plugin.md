# Spike Report: CNI Chaining Plugin as the Interception Mechanism

**Author**: codebot-robot  
**Date**: October 16, 2026  
**Tracking Issues**: [#159](https://github.com/gke-labs/service-portals/issues/159), [#163](https://github.com/gke-labs/service-portals/issues/163)  
**Status**: **Not Pursued** (Decision: NRI selected as the mechanism to build on for #159)

---

## Executive Summary

This spike evaluates a **chained CNI plugin** (`service-portal-cni`) as the transparent traffic interception and default-deny egress enforcement mechanism for `service-portals`. Modeled after the pattern popularized by `istio-cni` and `cilium-cni`, the plugin is appended to the node's CNI configuration list (`/etc/cni/net.d/*.conflist`) and executed synchronously by the container runtime during CNI `ADD` when creating a pod sandbox.

When invoked, the plugin reads CNI arguments to identify the pod (`K8S_POD_NAMESPACE` and `K8S_POD_NAME`), queries the Kubernetes API with a node-scoped kubeconfig to check for opt-in policy (`portals.gke.io/intercept: "true"` or `PortalPolicy`), and—if matched—enters the pod network namespace (`CNI_NETNS`) to install netfilter DNAT redirection and default-deny egress rules. Traffic is redirected to a per-node DaemonSet proxy running in host networking mode.

### Verdict & Decision
* **Verdict**: **Not pursued**. Following the comparison in #159, CNI chaining is not being pursued; Node Resource Interface (NRI, #161) is the mechanism we build on.
* **Key Findings & Blockers**:
  1. **Sandboxed Runtimes Unprotected**: Rules are configured in the pod network namespace (`configureNetnsRules`), which gVisor's netstack and a Kata guest do not traverse. Because the plugin never inspects `runtimeClassName`, CNI `ADD` succeeds silently, leaving sandboxed workloads unprotected.
  2. **GKE Incompatible**: Conflist ownership conflicts directly with GKE Dataplane V2 / Cilium `cni-exclusive` mode. The default CNI bin directory is wrong for GKE (`/home/kubernetes/bin` vs `/opt/cni/bin`). Chaining is unsupported on GKE Standard and impossible on GKE Autopilot (which prohibits hostPath mounts to CNI directories and privileged DaemonSets).
  3. **Bypasses in Threat Model**: The UID-1337 exemption was retained in both `nat` and `filter` tables despite having no in-pod proxy, creating an egress bypass under PSA baseline (`runAsUser: 1337`). IPv6 traffic remains completely unfiltered. Furthermore, the bypass verification subtest (`iptables -L`) passed trivially only because the toolbox image lacked the `iptables` binary.
  4. **Unauthenticated Per-Node Proxy & Expiring Token**: The per-node proxy authenticates nobody, allowing any pod on the node to obtain credentials by SNI. The node-scoped kubeconfig token copied to the host by the installer DaemonSet is never refreshed and fails once expired.
* **Property Carried Forward**: CNI's `prevResult` names the host-side interface, which is where enforcement must live for microVMs. That concept moves to the NRI follow-up (#161).

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
  * The installer DaemonSet requires host access to write binaries into `/opt/cni/bin` (or `/home/kubernetes/bin` on GKE) and update `/etc/cni/net.d`. It runs with `securityContext.privileged: true` or `hostPath` mounts.
  * The CNI plugin itself executes as root on the host during CNI ADD, with permission to invoke `nsenter` into the target pod network namespace.
  * The per-node proxy DaemonSet runs with `hostNetwork: true` and `dnsPolicy: ClusterFirstWithHostNet` to bind ports 8080/8443 on the host and resolve cluster services.
* **Workload-Level Privileges**:
  * Workload pods run completely unprivileged (tested with UID 1000, `allowPrivilegeEscalation: false`, `capabilities: { drop: ["ALL"] }`).
* **GKE Standard vs Autopilot**:
  * **GKE Standard**: **Unsupported**. Conflist ownership directly conflicts with GKE Dataplane V2 / Cilium `cni-exclusive` mode, which actively manages and reconciles `/etc/cni/net.d/*.conflist`. Furthermore, GKE uses `/home/kubernetes/bin` as its CNI binary directory rather than the standard `/opt/cni/bin`.
  * **GKE Autopilot**: **Impossible**. Autopilot enforces an immutable node architecture:
    * `hostPath` mounts to `/etc` and `/home/kubernetes/bin` are rejected by admission controllers.
    * Privileged containers (`securityContext.privileged: true`) are blocked.
    * GKE Dataplane V2 / managed Cilium controls CNI conflists and rejects external chaining plugins.

### 3. Bypass Resistance & Threat Model

| Attack Vector | Workload Capability | Observed Behavior / Defense | Bypass Possible? |
| :--- | :--- | :--- | :--- |
| **Root in container** | `runAsUser: 0` without `NET_ADMIN` | Container cannot modify iptables (`Permission denied`). Netfilter rules enforced by host kernel remain intact. | **No** |
| **Tampering with rules** | Attempts `iptables`, `nftables` | Blocked by missing `CAP_NET_ADMIN`. | **No** |
| **Privilege escalation** | `su 1337`, `setuid` binaries | Blocked by `allowPrivilegeEscalation: false` (`NoNewPrivs: 1`). | **No** |
| **UID 1337 exemption bypass** | `runAsUser: 1337` under PSA baseline | Netfilter rules retain the UID-1337 exemption in `nat` and `filter` tables (`main.go ~458, ~492`). Since no proxy runs inside the pod, any process with UID 1337 bypasses all rules. | **Yes** |
| **Direct IP literals** | `wget http://<ClusterIP>:80/` | DNAT redirects port 80/443 to node proxy. Proxy rejects requests where Host/SNI does not match policy rules (HTTP 403 Forbidden). | **No** |
| **Unlisted hostnames** | `wget http://other.backend/` | Proxy terminates TLS / parses Host header; returns 403 Forbidden. Upstream backend never reached. | **No** |
| **Non-intercepted ports** | Raw TCP / HTTP to port 8080, 9999 | Blocked by netfilter `OUTPUT -p tcp -j REJECT --reject-with icmp-port-unreachable`. | **No** |
| **Arbitrary DNS** | DNS to `8.8.8.8:53` | Blocked by netfilter `OUTPUT -p udp -j REJECT`. Cluster DNS is permitted. | **No** |
| **IPv6 traffic** | Outbound IPv6 requests | Netfilter rules were installed solely via `iptables`; `ip6tables` was not configured, leaving all IPv6 egress completely unfiltered. | **Yes** |
| **Sandboxed runtimes (gVisor / Kata)** | Pod with `runtimeClassName: gvisor` or `kata` | Netfilter rules in pod netns (`configureNetnsRules`) are not traversed by gVisor's netstack or Kata guest VM. Plugin does not check `runtimeClassName`, so ADD succeeds unprotected. | **Yes** |
| **Toolbox bypass test artifact** | Testing `iptables -L` in test pod | The bypass subtest passed trivially because the `toolbox` container image lacked the `iptables` binary, not because kernel enforcement blocked it. | **N/A (Test False Positive)** |

### 4. Pod Identity at the Per-Node Proxy
* **Mechanism**: In the prototype, traffic is redirected via netfilter DNAT from the pod netns to the gateway IP (`${GATEWAY_IP}:${PROXY_PORT}`).
* **Missing Identity Verification**: In this prototype, **the proxy does not resolve `RemoteAddr` to a pod; that was not implemented**. The per-node proxy authenticates nobody. Consequently, any pod on the node can send traffic to the node proxy's port and obtain the swapped credential purely by specifying the target SNI / Host header.
* **Kubeconfig Token Expiration**: The node-scoped kubeconfig token copied to `/etc/cni/net.d/service-portal.kubeconfig` by `install-cni.sh` is a static copy of the installer pod's projected service account token. This token is never refreshed, meaning that once the token expires, the CNI plugin fails on all subsequent pod sandbox creations.

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
| **Binary Placement** | Binary must reside on host at `/opt/cni/bin` (or `/home/kubernetes/bin`) | DaemonSet container communicates via Unix domain socket `/var/run/nri/nri.sock` |
| **Pod Lifecycle Hook** | CNI ADD / CNI DEL | `RunPodSandbox` / `StopPodSandbox` |
| **Netns Access** | Provided via `CNI_NETNS` path | Provided via container sandbox spec |
| **Upgrade Complexity** | Replacing on-disk binary under live traffic can cause pod sandbox creation errors if intermediate calls happen | Pods that start while the plugin is disconnected run unprotected unless the plugin is pre-registered with containerd or the node is tainted until it reconnects |

---

## Conclusion: Not Pursued

Following the comparative evaluation in issue #159, **CNI chaining is not being pursued**. Node Resource Interface (NRI, #161) is the mechanism we build on instead.

The prototype surfaced several critical reasons that make CNI chaining unsuitable:

1. **Sandboxed Runtimes Bypass Pod Netns Rules**:
   - Rules are installed in the pod network namespace (`configureNetnsRules`), which gVisor's netstack and a Kata guest do not traverse.
   - The plugin never checks `runtimeClassName`, so CNI `ADD` succeeds and the pod runs completely unprotected with no traffic intercepted and no egress filtered.

2. **GKE Incompatibility and Conflist Conflicts**:
   - Conflist ownership conflicts directly with GKE Dataplane V2 / Cilium `cni-exclusive` mode, where the underlying CNI daemon manages and reconciles `/etc/cni/net.d/*.conflist`.
   - The default CNI binary directory (`/opt/cni/bin`) is wrong for GKE, which uses `/home/kubernetes/bin`.
   - CNI chaining is unsupported on GKE Standard and impossible on GKE Autopilot (which prohibits hostPath mounts to CNI directories and privileged DaemonSets).

3. **Bypasses and Incomplete Enforcement**:
   - The UID-1337 exemption remains in both tables (`main.go ~458, ~492`) despite having no in-pod proxy. Under PSA baseline, any workload can specify `runAsUser: 1337` to bypass interception and egress restrictions entirely.
   - IPv6 is completely unfiltered (`ip6tables` is not configured).
   - In e2e testing, the bypass subtest asserting that a container cannot run `iptables -L` passed trivially only because the `toolbox` test image had no `iptables` binary installed.

4. **Unauthenticated Proxy and Token Expiration**:
   - The per-node proxy authenticates nobody, so any pod on the node can obtain the swapped credential purely by SNI.
   - The node-scoped kubeconfig token copied by `install-cni.sh` is never refreshed, leading to inevitable token expiration and node-wide CNI failures.

### Property Worth Carrying Forward: Host-Side Interface from `prevResult`

One property identified during this spike is worth carrying forward: CNI chaining's `prevResult` explicitly names the **host-side interface** (e.g., `veth*` or tap device). For microVMs and sandboxed runtimes (Kata, gVisor), network enforcement cannot reside within the guest/pod network namespace and must live on the host-side interface. That idea moves to the NRI follow-up (#161).
