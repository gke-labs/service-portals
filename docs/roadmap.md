# Project Roadmap: Convergence on NRI as the Single Mode

**Status**: Active Roadmap  
**Target Architecture**: Per-Node containerd NRI Plugin with Host-Side Enforcement  
**Current Recommendation**: Transparent In-Pod Sidecar  
**Tracking Issue**: [#200](https://github.com/gke-labs/service-portals/issues/200)  

---

## 1. Executive Summary & Direction

**Project Decision ([#200](https://github.com/gke-labs/service-portals/issues/200))**: *Prove that NRI works well, then remove the other modes of operation.*

Historically, `service-portals` accumulated at least five different ways to place the proxy in the traffic path:
1. **Transparent sidecar with an init container** (the current recommended mode)
2. **Explicit Service mode** (`k8s/manifests.yaml`, single-target portal binaries)
3. **Explicit `HTTP_PROXY`/`CONNECT` mode** (`cmd/service-portal`)
4. **Application-level interception** (spiked in [#164](https://github.com/gke-labs/service-portals/pull/164); not pursued, [#214](https://github.com/gke-labs/service-portals/issues/214)/[#215](https://github.com/gke-labs/service-portals/pull/215))
5. **Per-node containerd NRI plugin** ([#198](https://github.com/gke-labs/service-portals/pull/198) and follow-ups)

Having multiple parallel modes created user confusion, made the recommended path difficult to identify, and imposed high maintenance overhead. The project is therefore executing a two-step plan to converge on a single, unified mode of operation based on the containerd Node Resource Interface (NRI). Once NRI meets the acceptance bar defined below, all other modes will be deleted rather than deprecated indefinitely.

---

## 2. The Two-Step Plan

### Step 1: Make the Recommendation Unmistakable (Current)

During the transition, the transparent sidecar remains the **only recommended deployment path and quick start**:
- **Documentation Clarity**: The [README](../README.md) presents the transparent sidecar as the single quick-start path. All other modes are moved to [docs/deployment-modes.md](deployment-modes.md) under a dedicated section titled *"Other modes (legacy / experimental)"* with explicit statuses (legacy, not pursued, future default).
- **Legacy Binaries**: Single-target binaries (`gemini-portal/`, `anthropic-portal/`, `github-portal/`) and `cmd/service-portal` are marked as *legacy* and scheduled for removal alongside explicit Service mode.
- **Design Consolidation**: All architectural spikes and decision records are indexed in [docs/design/README.md](design/README.md), clearly distinguishing between approved decision records and historical evaluations.

### Step 2: Remove Other Modes (Gated on NRI Acceptance)

Once the NRI implementation meets the acceptance bar below on `main`, the remaining modes and legacy components will be removed in separate, focused pull requests:
- Delete explicit Service mode and the per-service portal binaries (`gemini-portal/`, `anthropic-portal/`, `github-portal/`, `cmd/service-portal/`, and associated manifests).
- Delete explicit `HTTP_PROXY`/`CONNECT` mode (or retain solely as a tested internal mechanism if required by NRI).
- Delete the init-container sidecar mode and `init-service-portals` once NRI covers its use cases.
- Remove corresponding docs, manifests, and e2e tests.
- Update [AGENTS.md](../AGENTS.md).
- Behavior removal is a breaking change; release notes and semantic versioning will reflect this.

---

## 3. Acceptance Bar for "NRI Works Well" (Gates Step 2)

All of the following criteria must be merged to `main` and passing green in CI before Step 2 removals begin:

1. **Deny Suite on kind (including direct-to-proxy cases)**:
   The [#147](https://github.com/gke-labs/service-portals/issues/147) default-deny test suite passes in NRI mode on kind, **including the two direct-to-proxy cases** ([#182](https://github.com/gke-labs/service-portals/issues/182)):
   - An opted-in pod connecting directly to the node proxy with a foreign host header is denied.
   - A non-opted-in pod cannot access or use the node proxy at all.
2. **Host-Side Enforcement for Sandboxed Runtimes**:
   Interception rules attach to the host side of the `veth`/`tap` interface ([#181](https://github.com/gke-labs/service-portals/issues/181)) so enforcement holds under gVisor and Kata Containers, with at least one microVM runtime empirically verified (not just reasoned about).
3. **IPv6 and Bounded DNS**:
   Dual-stack IPv6 egress rejection and bounded DNS resolution ([#183](https://github.com/gke-labs/service-portals/issues/183)), with dual-stack e2e tests ([#169](https://github.com/gke-labs/service-portals/issues/169)/[#170](https://github.com/gke-labs/service-portals/pull/170)) passing in NRI mode.
4. **Fail-Closed Semantics**:
   Demonstrated fail-closed behavior when the NRI plugin is absent, failed, or restarting (via taint gating `service-portal.gke.io/uninitialized:NoSchedule` or pre-registration), with zero silent fallbacks to unintercepted egress.
5. **Per-Pod Identity and Attribution**:
   The node proxy resolves the calling pod identity and attributes requests for quota and policy lookup ([#182](https://github.com/gke-labs/service-portals/issues/182)).
6. **Migration & Unsupported Platform Policy**:
   A documented migration guide explaining how a cluster running sidecar mode transitions to NRI mode. The project decision ([#200](https://github.com/gke-labs/service-portals/issues/200)) is that NRI is the single supported mode where available; on platforms where NRI is unavailable (such as GKE Autopilot today), `service-portals` is unsupported, with no separate application-level code path maintained.
