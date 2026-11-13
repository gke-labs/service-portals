# Design proposal: DRA as the front end for NRI interception

**Status**: Proposal for discussion. Nothing here is built.
**Date**: 2026-11-13
**Related**: [`interception-mechanisms.md`](interception-mechanisms.md) (decision record), [`daemonset-mode.md`](daemonset-mode.md), [`spikes/dra-cdi.md`](spikes/dra-cdi.md) (the earlier DRA spike), [`spikes/nri.md`](spikes/nri.md)

## Summary

The earlier spike rejected DRA. It tested DRA plus CDI hooks as the *interception mechanism* and modelled egress as a pool of exclusive devices. Both choices were wrong for us, and the spike's conclusions about them stand.

Colleagues who work on DRA (John and Morten) suggested a different mapping: **one shared device per node**, standing for the node agent DaemonSet, with each opted-in pod consuming a share of it, possibly a nominal one. This document evaluates that mapping.

The conclusion is that DRA is a good fit as the **API and scheduling layer**, and that it **does not replace NRI**. DRA decides *whether and where* a pod may run and records *what policy it gets*. NRI still installs the host-side rules, because DRA has no hook at the point where the pod's network namespace exists. This is the same split the DRA network driver DraNet uses.

## What DRA gives us

Claims in this section are checked against the Kubernetes documentation and source as of the date above; the references are at the end.

1. **A capacity model that fits.** With consumable capacity, a driver marks a device `allowMultipleAllocations: true` and many independent ResourceClaims share it; the scheduler tracks the total consumed. One device per node, published by the node agent, removes the fake pools (`egress-0`, `egress-1`, ...) that broke under autoscaling in the spike. A real capacity, such as "number of intercepted pods this node agent will serve", is available if we want one.

2. **Fail-closed scheduling without a taint.** A pod with a claim is only scheduled to a node whose driver has published a matching device in a ResourceSlice. On the node, the kubelet calls the driver to prepare the claim and does not create the pod sandbox if that call fails. Today we rely on a taint that an external actor applies and removes, and a plugin restart leaves a window in which new pods start unprotected; that is the weakest item on the NRI acceptance bar. With DRA, "the agent is not ready" means "the pod stays Pending or fails to start", enforced by the scheduler and the kubelet.

3. **Opt-in and policy as API objects.** Today a pod opts in with a label and selects policy with an annotation. A ResourceClaim is a typed object under RBAC, and its opaque device configuration can carry the policy reference. The claim's `status.reservedFor` and the prepare call give the node agent an authoritative record of which pod has which claim, supplied by the kubelet and not inferred from pod metadata.

4. **Health as a scheduling signal.** A driver can taint its own device, so a node agent that detects a broken proxy can stop new intercepted pods from landing on the node.

## What DRA does not give us: we still need NRI

1. **No hook where the network namespace exists.** The kubelet prepares claims *before* it creates the pod sandbox. At prepare time there is no network namespace and no host-side veth or tap to attach rules to. The host-side enforcement that makes interception hold under gVisor (verified in CI) has to be installed after the sandbox exists and before any container runs, which is exactly NRI's `RunPodSandbox`.

2. **CDI is per container and only for containers that name the claim.** The kubelet passes a claim's CDI devices only to containers that list the claim in `resources.claims`. A CDI hook therefore does not cover a container that omits the claim, and it runs per container, not once per pod. This is the init-container gap the spike found, and it is inherent, not a prototype bug.

3. **Precedent.** DraNet, the Kubernetes SIG network DRA driver, talks to the kubelet through DRA and to the container runtime through NRI, and does its network configuration from the NRI call once the pod's network namespace exists.

So the proposal is DRA **and** NRI in one node agent, each doing the part it is good at:

| Concern | Today (NRI only) | Proposed (DRA front end + NRI) |
| :--- | :--- | :--- |
| Opt-in | Pod label | Pod references a ResourceClaim (or template) |
| Policy selection | Pod annotation | Claim device configuration |
| Is the node ready? | Taint, applied and removed externally | ResourceSlice published by the agent; kubelet prepare call |
| Agent down or restarting | New pods start unprotected until containerd reconnects | New pods do not start: prepare fails closed |
| Which pods are opted in | Pod map built from NRI events | Prepared claims (kubelet-supplied), cross-checked in the NRI hook |
| Install host-side rules | NRI `RunPodSandbox` | NRI `RunPodSandbox` (unchanged) |
| CA trust injection | NRI `CreateContainer` | NRI `CreateContainer` (unchanged; CDI is an alternative, see open questions) |
| Late binding for warm pools | Bind API | Bind API (unchanged; a claim is fixed at pod creation) |

The NRI hook gains one check: an opted-in sandbox must have a prepared claim, and a sandbox with a prepared claim must get rules or fail. That closes the case where the two mechanisms disagree.

## Trade-offs

**For**
- Removes the taint gate and the restart window with machinery Kubernetes already has.
- Opt-in becomes visible to the scheduler, to RBAC and to admission policy; "this namespace must be intercepted" becomes "pods here must carry this claim".
- The claim is a natural place for per-pod policy and, later, quota.
- It is the mapping suggested by colleagues who work on DRA for a per-node shared service.

**Against**
- **Two mechanisms instead of one.** The node agent becomes a DRA driver as well as an NRI plugin: a kubelet plugin registration, ResourceSlice publishing, and a DeviceClass to install. More surface, more ways for the two halves to disagree.
- **The pod spec is no longer untouched.** A label becomes a `resourceClaims` entry plus `resources.claims` on a container, and each namespace needs a ResourceClaimTemplate. Requesting the device as an extended resource is an alternative that keeps the pod spec close to today's shape; an admission policy can add either form.
- **Version floor.** Core DRA is stable from Kubernetes 1.34. Consumable capacity is on by default only from 1.36 (beta). Without it, sharing one device means one ResourceClaim shared by many pods, which caps at 256 consumers per claim and loses per-pod configuration. Availability on GKE release channels is `[unverified]`.
- **A zero share is `[unverified]`.** The documentation shows a per-capacity `requestPolicy` with a default and a valid range; whether a request may consume exactly zero, or whether we should simply publish a device with no capacities, needs a test.
- **Does not help where NRI is unavailable.** A DRA driver is still a privileged per-node DaemonSet, so the Autopilot position is unchanged.

## Open questions

1. Does a kubelet prepare failure reliably keep the pod from starting when the node agent is down, and what does the pod see while the agent restarts (retry, backoff, events)? This is the property that justifies the whole proposal and should be the first thing a spike demonstrates, with no taint involved.
2. Extended-resource request or explicit claim: which opt-in form do we want users to write?
3. Should the CA bundle move from NRI `CreateContainer` to CDI? CDI only reaches containers that name the claim, so the NRI path is the safer default.
4. Does the bind API become "update the claim's configuration", or stay a separate call? Claims are immutable in the parts that matter, which suggests it stays.
5. If the claim is present but the label is not (or the reverse), which wins? Proposed: the claim is the opt-in and the label goes away.

## Suggested next step

A spike of about 200 lines on kind (the CI node image is Kubernetes 1.37): the node agent publishes one shared device, a test pod opts in through a claim, the prepare call records the pod, and the existing NRI hook installs rules only for prepared pods. Two tests decide it: the pod stays unstarted while the agent is stopped, and the existing deny suite passes unchanged when it is running. If the first test fails, the proposal is not worth its cost.

## References

- Kubernetes documentation, Dynamic Resource Allocation: feature gate `DynamicResourceAllocation` stable from 1.34; `DRAConsumableCapacity` alpha 1.34, beta and on by default from 1.36; `DRAExtendedResource` stable from 1.37; `DRADeviceTaints` stable from 1.37 (`content/en/docs/reference/command-line-tools-reference/feature-gates/` in `kubernetes/website`). Consumable capacity semantics: `dra-features.md`, section "Consumable capacity".
- Kubelet ordering: `pkg/kubelet/kuberuntime/kuberuntime_manager.go` on `master`, `SyncPod` step 4 calls `PrepareDynamicResources` and returns on error before `createPodSandbox`.
- CDI devices per container: `pkg/kubelet/cm/dra/manager.go`, `GetResources`, iterates `container.Resources.Claims`.
- `ResourceClaimReservedForMaxSize = 256`: `staging/src/k8s.io/api/resource/v1/types.go`.
- DraNet: https://github.com/kubernetes-sigs/dranet ("communicates with the Kubelet through the DRA API and with the Container Runtime via NRI").
