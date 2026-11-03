# Spike Report: CNI Chaining Plugin as the Interception Mechanism

**Author**: codebot-robot  
**Date**: November 3, 2026  
**Tracking Issues**: [#159](https://github.com/gke-labs/service-portals/issues/159), [#163](https://github.com/gke-labs/service-portals/issues/163), [#194](https://github.com/gke-labs/service-portals/issues/194)  
**Status**: **Not pursued** (the #159 comparison chose NRI)

---

## Executive Summary

This spike evaluated a **chained CNI plugin** as the transparent traffic interception and default-deny egress mechanism for `service-portals`. Appended to the node's CNI network configuration list (`/etc/cni/net.d/*.conflist`), the plugin executes synchronously during CNI `ADD` within CRI `RunPodSandbox`.

On `ADD`, the plugin identifies the pod via CNI args, queries the Kubernetes API server using a node-scoped kubeconfig to check for opt-in policy, and enters the pod network namespace (`CNI_NETNS`) via `nsenter` to install netfilter DNAT redirection (ports 80 and 443 to a per-node DaemonSet proxy) and egress filter rules.

### Verdict
* **Status**: **Not pursued**. The #159 comparison chose Node Resource Interface (NRI) as the mechanism we build on.
* **Property Carried Forward**: CNI `prevResult` names the host-side interface (e.g. `veth*` or tap device), which is where enforcement must live for microVMs (now #181 under NRI).

---

## What the Spike Built and Observed on kind

1. **Chained Plugin Appended to the kindnet conflist**:
   * kind writes its CNI config to `/etc/cni/net.d/10-kindnet.conflist` with `ptp` and `portmap` plugins.
   * Appending `service-portal-cni` as a chained plugin in `plugins` was natively tolerated by kindnet and containerd.
   * Unselected pods received `prevResult` transparently without modification.

2. **Pod Lookup via the API with a Node Kubeconfig**:
   * CNI args supply `K8S_POD_NAMESPACE` and `K8S_POD_NAME`.
   * The plugin queried the Kubernetes API using a node-scoped kubeconfig (`/etc/cni/net.d/service-portal.kubeconfig`) to check for opt-in labels (`service-portal.gke.io/intercept: "true"`).

3. **Rules Installed via nsenter into the Pod Network Namespace**:
   * For opted-in pods, the plugin entered `CNI_NETNS` via `nsenter` and installed iptables DNAT rules (redirecting 80/443 to the node proxy) and filter rules (permitting loopback, established connections, proxy ports, and cluster DNS, while rejecting other traffic).

4. **Ordering Relative to Init Containers**:
   * Container runtime lifecycle: kubelet `RunPodSandbox` invokes the CNI plugin chain (`ptp` -> `portmap` -> `service-portal-cni`).
   * Only after `RunPodSandbox` completes successfully does kubelet call `CreateContainer`/`StartContainer` for init containers, followed by application containers.
   * Interception rules are active in the kernel before any container or init container process executes, eliminating race windows at startup.

5. **Fail-Closed Behaviour When the Plugin Errors**:
   * If the plugin returns an error (e.g., API lookup failure, missing binary, or rule configuration failure), CNI `ADD` fails.
   * `RunPodSandbox` fails with `FailedCreatePodSandBox`, the pod remains in `ContainerCreating`, and no container starts.
   * Network interception is strictly fail-closed.

---

## Evaluation Against Threat Model and Platform Requirements

### 1. Pod Identity at the Per-Node Proxy
* **Identity Stated Honestly**: In this prototype, **the proxy did not resolve `RemoteAddr` to a pod; that was not implemented**.
* The per-node proxy authenticated nobody. Any pod on the node could send traffic directly to the node proxy's host port and receive swapped credentials based solely on the requested Host header or SNI.
* **Kubeconfig Token Expiration**: The node-scoped kubeconfig token copied to the host by the installer DaemonSet was a static service account token and was never refreshed. Once expired, all subsequent CNI `ADD` calls failed.

### 2. Bypass Resistance & Sandbox Isolation
* **In-Pod Rules vs Sandboxed Runtimes**: Rules configured in the pod network namespace are not traversed by gVisor's netstack or a Kata guest kernel. Because the plugin never checked `runtimeClassName`, CNI `ADD` succeeded silently, leaving sandboxed pods running completely unprotected.
* **UID-1337 Exemption**: The netfilter rules retained a UID-1337 bypass in both `nat` and `filter` tables. Because no proxy ran inside the pod, any workload running with `runAsUser: 1337` (allowed under Pod Security Admission `baseline`) completely bypassed redirection and egress filtering.
* **IPv6 Unfiltered**: Rules were only installed via `iptables`; `ip6tables` was not configured, leaving all IPv6 egress open and unfiltered.
* **Test False Positive**: In the bypass verification test, `iptables -L` executed inside the pod passed only because the `toolbox` container image lacked the `iptables` binary, not because capability restrictions blocked execution.

### 3. Comparison with NRI

| Dimension | CNI Chaining Plugin | NRI Plugin |
| :--- | :--- | :--- |
| **Hook Point** | CNI `ADD` / `DEL` | CRI `RunPodSandbox` / `StopPodSandbox` |
| **Configuration** | Modifies on-disk conflist (`/etc/cni/net.d/*.conflist`) | Registers dynamically via NRI socket (`/var/run/nri/nri.sock`) |
| **Provider Conflict** | Conflicts with managed CNI conflist reconciliation | No interaction with CNI configuration |
| **Binary Location** | Host binary path (`/opt/cni/bin` or `/home/kubernetes/bin`) | Packaged within DaemonSet container image |
| **Disconnection / Rollout** | Binary missing or failing fails pod sandbox creation (fail-closed) | A DaemonSet rolling update leaves pods that start while the plugin is disconnected unprotected unless the plugin is pre-registered with containerd or the node is tainted until it reconnects |

---

## Conclusion: Reasons CNI Chaining Is Not Pursued

Following the #159 comparison, CNI chaining is **not pursued** in favor of NRI due to four observed reasons:

1. **Sandboxed Runtimes Unprotected**: Rules installed in the pod network namespace are not traversed by gVisor's netstack or a Kata guest. Because the plugin never checked `runtimeClassName`, sandboxed pods ran completely unprotected.
2. **GKE Incompatibility and Conflist Conflicts**: Conflist ownership conflicts directly with Dataplane V2 / Cilium `cni-exclusive` mode, which owns `/etc/cni/net.d`. GKE uses `/home/kubernetes/bin` instead of `/opt/cni/bin`. Chaining is unsupported on GKE Standard and impossible on Autopilot (which blocks privileged DaemonSets and hostPath mounts to CNI directories).
3. **Bypasses and Incomplete Enforcement**: The UID-1337 exemption remained in both tables with no in-pod proxy (a bypass under PSA baseline). IPv6 traffic remained completely unfiltered. Furthermore, the bypass subtest's `iptables -L` passed only because the toolbox image had no iptables installed.
4. **Unauthenticated Proxy and Token Expiration**: The per-node proxy authenticated nobody (pod identity from `RemoteAddr` was not implemented), and the kubeconfig token copied to the node by the installer was never refreshed.

### Property Carried Forward
CNI `prevResult` names the host-side interface (veth peer or tap). This host-side interface is where network enforcement must live for microVMs and sandboxed runtimes, an architectural property carried forward into NRI follow-up #181.
