# Design Documents & Architectural Decision Records

This directory contains architectural designs, decision records, and spike reports evaluating traffic interception and egress enforcement mechanisms for `service-portals`.

---

## Document Index & Status

| Document | Type | Status | Description |
| :--- | :--- | :--- | :--- |
| **[`daemonset-mode.md`](daemonset-mode.md)** | **System Design** | **Implementation Architecture** ([#151](https://github.com/gke-labs/service-portals/issues/151) / [#152](https://github.com/gke-labs/service-portals/pull/152)) | Concrete technical architecture for the per-node DaemonSet NRI plugin, detailing host-side peer interface filtering ([#181](https://github.com/gke-labs/service-portals/issues/181)), pod caller attribution ([#182](https://github.com/gke-labs/service-portals/issues/182)), CA distribution, and fail-closed operation. |
| **[`interception-mechanisms.md`](interception-mechanisms.md)** | **Decision Record** | **Decision Record** ([#159](https://github.com/gke-labs/service-portals/issues/159) / [#200](https://github.com/gke-labs/service-portals/issues/200) / [#225](https://github.com/gke-labs/service-portals/issues/225)) | Evaluates candidate interception mechanisms and records the decision to converge on NRI as the single target mode. |
| **[`spikes/cni-plugin.md`](spikes/cni-plugin.md)** | **Spike Report** | **Historical (Not Pursued)** ([#163](https://github.com/gke-labs/service-portals/issues/163) / [#166](https://github.com/gke-labs/service-portals/pull/166) / [#194](https://github.com/gke-labs/service-portals/issues/194) / [#196](https://github.com/gke-labs/service-portals/pull/196)) | Evaluated a chained CNI plugin inserted into `/etc/cni/net.d/*.conflist`. Dropped due to conflist ownership conflicts on managed CNIs (GKE Dataplane V2 / Cilium), missing pod labels in `CNI_ARGS`, inability to inject CA certificates, and silent loss of rules under sandboxed runtimes (gVisor/Kata). |
| **`spikes/application-level.md`** *(pending PR #215)* | **Spike Report** | **Historical (Not Pursued)** ([#162](https://github.com/gke-labs/service-portals/issues/162) / [#164](https://github.com/gke-labs/service-portals/pull/164) / [#214](https://github.com/gke-labs/service-portals/issues/214) / [#215](https://github.com/gke-labs/service-portals/pull/215)) | Evaluated zero-privilege pod interception using standard proxy environment variables (`HTTP_PROXY`, `HTTPS_PROXY`) paired with default-deny Kubernetes `NetworkPolicy` and per-pod `Proxy-Authorization` tokens. Dropped / not pursued; there will be no separate code path for Autopilot. |
| **`spikes/nri.md`** *(pending PR #198)* | **Spike Report** | **Target Prototype (Pending PR #198)** ([#161](https://github.com/gke-labs/service-portals/issues/161) / [#165](https://github.com/gke-labs/service-portals/pull/165) / [#198](https://github.com/gke-labs/service-portals/pull/198)) | Evaluated the containerd Node Resource Interface (NRI) plugin using `github.com/containerd/nri/pkg/stub`. Demonstrated invisible pod specs and elimination of the UID-1337 loop avoidance exemption. Led directly to host-side interface enforcement ([#181](https://github.com/gke-labs/service-portals/issues/181)). |
| **`spikes/dra-cdi.md`** *(pending PR #168)* | **Spike Report** | **Historical (Dropped)** ([#160](https://github.com/gke-labs/service-portals/issues/160) / [#168](https://github.com/gke-labs/service-portals/pull/168)) | Evaluated Dynamic Resource Allocation (DRA) driver with Container Device Interface (CDI) OCI runtime hooks. Dropped due to treating security policy as hardware, mutating webhook requirement for claim defaulting, prototype fail-open behavior on iptables error, and silent loss in sandboxed runtimes. |

---

## Architecture Evolution & Convergence

1. **Current Production Mode**: **Transparent In-Pod Sidecar**  
   Described in [docs/sidecar-container.md](../sidecar-container.md). An `initContainer` (`init-service-portals`) configures `iptables` NAT redirection and ephemeral Root CA generation, while `all-in-one-portal` intercepts outbound traffic and swaps credentials. This is the **current recommended quick-start path**.
2. **The Target Single Mode**: **containerd NRI DaemonSet with Host-Side Enforcement**  
   Detailed in [`daemonset-mode.md`](daemonset-mode.md) (and the decision record in [`interception-mechanisms.md`](interception-mechanisms.md)). Moving redirection and egress filtering to the host end of the `veth`/`tap` interface eliminates `CAP_NET_ADMIN` requirements in workload pods (PSA `baseline` compliance), eliminates the UID-1337 bypass, and uniformly preserves interception across `runc`, `gVisor`, and `Kata Containers`.
3. **Roadmap & Deprecation Plan**:  
   See [docs/roadmap.md](../roadmap.md) for the convergence plan, acceptance criteria, and schedule for removing legacy modes (explicit Service mode, explicit `HTTP_PROXY` mode, and in-pod init container mode).
