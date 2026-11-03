# Spike Report: Dynamic Resource Allocation (DRA) + Container Device Interface (CDI) Hooks as the Interception Mechanism

* **Issue Reference:** Sub-issue of [#159](https://github.com/gke-labs/service-portals/issues/159), Issue [#160](https://github.com/gke-labs/service-portals/issues/160)
* **Prototype Branch:** `spike/dra-cdi`
* **Status:** Concluded — **Not Pursued**. Decision from the #159 comparison: DRA + CDI is not being pursued; Node Resource Interface (NRI) is the mechanism we build on.

---

## 1. Executive Summary & Verdict

This spike investigated replacing the in-pod mutating webhook injector and `initContainers` with Kubernetes **Dynamic Resource Allocation (DRA)** and **Container Device Interface (CDI)** OCI runtime hooks.

In this model:
1. Workload egress interception was modeled as an abstract "device" (`portal-egress.portals.gke.io`).
2. Workload pods opted in by referencing a `ResourceClaimTemplate` in `spec.resourceClaims` and claiming it in `spec.containers[*].resources.claims`.
3. The node-local DRA driver (a DaemonSet) handled `NodePrepareResources` by generating a root CA certificate and writing a dynamic **CDI specification** to `/etc/cdi/portal-egress.json`.
4. When containerd created the container, CDI automatically applied `containerEdits`:
   - Mounts the CA certificate into `/etc/service-portal/ca/tls.crt`.
   - Injects `SSL_CERT_FILE=/etc/service-portal/ca/tls.crt` into the container environment.
   - Registers an OCI **`createRuntime` hook** (`/usr/local/bin/portal-cdi-hook`).
5. The `createRuntime` hook executed on the host before the container process started, joined the container's network namespace (`/proc/<pid>/ns/net`), and configured iptables redirect and default-deny egress rules.

### Verdict: Concluded — Not Pursued

**Decision:** Following architectural comparison across candidate interception mechanisms in #159, **DRA + CDI is not being pursued**. Service Portals will instead build on **NRI (Node Resource Interface)**.

While the spike demonstrated that CDI injection of mounts, environment variables, and OCI lifecycle hooks can function in containerd, the mechanism suffered from fundamental lifecycle and architectural drawbacks:
- The hook executed per-container rather than per-pod, leaving `initContainers` unprotected.
- Modeling network interception as exclusive hardware devices required artificial capacity workarounds (`ResourceSlice` pools) that break under node autoscaling.
- The approach introduced high operational complexity, rapid API churn, host filesystem dependencies (`/usr/local/bin` is read-only on Container-Optimized OS), and poor sandboxed runtime (gVisor/Kata) isolation.
- The prototype revealed a severe security regression: the node-wide CA private key was bind-mounted into every workload container.
- The prototype hook implementation failed open on iptables errors, and the pod spec still required extensive configuration (sidecar container, hostPath, Secret, hostAliases), missing the intended invisibility bar.

---

## 2. Kubernetes and Runtime Prerequisites

### 2.1 Kubernetes Version & Feature Gates

* **Kubernetes 1.30 (Alpha) / 1.31–1.32 (Beta):**
  - DRA was substantially overhauled in Kubernetes 1.30/1.31 with **Structured Parameters** (KEP-4381) under API group `resource.k8s.io/v1beta1`.
  - Feature Gate: `DynamicResourceAllocation=true` (enabled on API server, scheduler, and kubelet).
  - Runtime Config: `resource.k8s.io/v1beta1=true` on the API server.

### 2.2 kind Configuration

To test DRA and CDI on kind, the cluster was provisioned with feature gates, API runtime configuration, and containerd CRI patches:

```yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
featureGates:
  DynamicResourceAllocation: true
runtimeConfig:
  "resource.k8s.io/v1beta1": "true"
nodes:
- role: control-plane
containerdConfigPatches:
- |-
  [plugins."io.containerd.grpc.v1.cri"]
    enable_cdi = true
    cdi_spec_dirs = ["/etc/cdi", "/var/run/cdi"]
```

### 2.3 Containerd CDI & Hook Support Verification

In kind node images (`kindest/node:v1.32.2` with containerd v2.3.6 / runc 1.5.2):
* `crictl info` confirms containerd CDI support:
  ```json
  "config": {
    "cdiSpecDirs": ["/etc/cdi", "/var/run/cdi"],
    "enableCDI": true
  }
  ```
* Containerd natively translates CDI `containerEdits.hooks` into OCI runtime `config.json` hooks (`createRuntime`).
* When runc executes the `createRuntime` hook, it provides container state on `stdin` containing:
  ```json
  {
    "ociVersion": "1.2.0",
    "id": "<container-id>",
    "status": "creating",
    "pid": 2672,
    "bundle": "/run/containerd/io.containerd.runtime.v2.task/k8s.io/<container-id>",
    "annotations": {
      "io.kubernetes.cri.container-name": "workload",
      "io.kubernetes.cri.sandbox-name": "test-client-dra-deny",
      "io.kubernetes.cri.sandbox-namespace": "default",
      "io.kubernetes.cri.sandbox-uid": "8b5145b4-661b-46bc-a304-3a1d847593cd"
    }
  }
  ```

### 2.4 Google Kubernetes Engine (GKE) Support

* **GKE Standard:**
  - Dynamic Resource Allocation (DRA) is available as an Alpha/Beta feature on GKE Standard clusters running GKE 1.31+ with cluster feature flags or Alpha clusters (`--enable-kubernetes-alpha`).
  - Containerd on GKE nodes has CDI enabled by default for GPU and accelerator drivers.
  - A node-local DaemonSet running with hostPath and `privileged: true` can register as a kubelet plugin on GKE Standard.
* **GKE Autopilot:**
  - **Not currently supported on Autopilot.** GKE Autopilot prohibits `privileged: true`, `hostPath` volume mounts to `/var/lib/kubelet` or `/etc/cdi`, and `hostPID`/`hostNetwork` on workload or system daemons without Google-managed exceptions. Unless Google provides DRA drivers as a managed platform feature, third-party DRA DaemonSets cannot run on Autopilot.

---

## 3. Prototype Architecture & Implementation

### 3.1 Components Created in Prototype

1. **`cmd/dra-portal-driver`:**
   - Registered with kubelet via `/var/lib/kubelet/plugins_registry/portal-egress.portals.gke.io-reg.sock`.
   - Implemented gRPC services `v1beta1.DRAPlugin` and `v1alpha3.Node` on `/var/lib/kubelet/plugins/portal-egress.portals.gke.io/dra.sock`.
   - Generated CA keypair in `/var/run/service-portal/ca`.
   - Copied `/usr/local/bin/portal-cdi-hook` to the host's `/usr/local/bin/portal-cdi-hook`.
   - Wrote CDI specification `/etc/cdi/portal-egress.json`.
   - On `NodePrepareResources`, resolved claims and returned CDI device `portals.gke.io/portal-egress=portal-egress`.
2. **`cmd/portal-cdi-hook`:**
   - Standalone OCI `createRuntime` hook binary executed by runc.
   - Read OCI JSON state from `stdin` to obtain the container's host `pid`.
   - Discovered cluster DNS nameserver IP (reading `/var/lib/kubelet/pods/*/resolv.conf` or defaulting to `10.96.0.10`).
   - Executed `nsenter -t <pid> -n` to configure `iptables-restore` inside the container network namespace.
3. **`k8s/dra-portal-driver.yaml`:**
   - Declared `DeviceClass` `portal-egress.portals.gke.io`.
   - Declared `ResourceClaimTemplate` `portal-egress-template`.
   - Declared `dra-portal-driver` DaemonSet.
4. **`tests/e2e/e2e_test.go` (`TestDRAEgressDenied`):**
   - Automated end-to-end test verifying deny semantics on kind.

### 3.2 The Pod Opt-In Contract & Reality Check

The intended opt-in model aimed for zero pod-level changes beyond a resource claim:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-client-dra-deny
spec:
  resourceClaims:
  - name: portal-egress
    resourceClaimTemplateName: portal-egress-template
  containers:
  - name: workload
    image: toolbox:e2e
    securityContext:
      runAsUser: 1000
      allowPrivilegeEscalation: false
    resources:
      claims:
      - name: portal-egress
```

**Correction & Reality Check on Pod Invisibility:**
While the `workload` container entry itself did not require `initContainers`, `NET_ADMIN`, or explicit CA volume mounts in its container block, the prototype did **not** meet the "only the opt-in" bar at the pod level. In reality, the working test pod still had to explicitly declare:
1. The **`service-portal-sidecar` container** in `spec.containers`.
2. A **`hostPath` volume** (`/var/run/service-portal/ca`) to supply the CA keypair to the sidecar.
3. A **`Secret` volume** (`sidecar-portal-deny-rules-secret`) containing the `PortalRule` definitions.
4. **`hostAliases`** mapping target backend hostnames to synthetic IPs.

Thus, full pod spec invisibility was not achieved; pod authors or admission webhooks would still need to inject substantial infrastructure scaffolding into the pod spec.

### 3.3 Exploring the "No-Pod-Change" Path: Namespace Defaulting

Can a `ResourceClaim` be defaulted per namespace without changing pod specs?

* **Native Kubernetes Core:** Kubernetes has **no built-in defaulting controller** for `spec.resourceClaims`. Unlike PVCs, which cannot be defaulted onto pods without a pod spec change, DRA claims must be explicitly listed in `spec.resourceClaims` and referenced by containers.
* **CEL MutatingAdmissionPolicy (Alpha in 1.32):**
  - MutatingAdmissionPolicy (`mutating.admissionregistration.k8s.io/v1alpha1`) allows in-tree CEL mutations.
  - While CEL mutation can add `spec.resourceClaims` and `spec.containers[*].resources.claims` to incoming pods matching a namespace label, MutatingAdmissionPolicy is currently Alpha and restricted in expression power.
* **Mutating Admission Webhook:**
  - A traditional mutating webhook can inject `spec.resourceClaims` and `spec.containers[*].resources.claims` on pod creation.
  - *Irony:* If an admission webhook is required to default the claim onto the pod, we have reintroduced the admission webhook that we sought to avoid by using DRA. However, the webhook would only inject declarative metadata (`resourceClaims`), rather than injecting certificates, init containers, volumes, and network privileges.

---

## 4. Key Questions Answered

### Q1: Is the CDI Hook Race-Free vs Workload Start?
**Lifecycle: Race-free; Implementation: Failed Open.**
In the OCI runtime lifecycle:
1. `createRuntime` hooks run **after** the container namespaces (network, PID, cgroups) are created, but **before** `pivot_root` and before the container's entrypoint process is executed.
2. The hook executes `nsenter -t <pid> -n iptables-restore`, which installs the redirection and default-deny firewall rules inside the container's network namespace before the workload starts.
3. **Correction regarding Failure Behavior:** While the OCI specification terminates the container if a hook returns a non-zero exit code, our prototype hook implementation (`cmd/portal-cdi-hook/main.go:336-345`) actually **failed open**:
   ```go
   if err := applyRulesInNetns(state.Pid, v4Rules, false); err != nil {
       log.Printf("Warning: failed to apply IPv4 rules in netns of PID %d: %v", state.Pid, err)
   }
   ```
   Errors were logged as warnings, and the hook process exited with code 0. If iptables failed, runc proceeded to start the container unprotected without firewall rules.

### Q2: Is DRA Fail-Closed When the Driver is Down?
**Yes, at the Kubelet scheduling/preparation layer.**
We experimentally tested this in `TestDRAEgressDenied/FailClosed_UnregisteredPlugin`:
1. When a pod references a claim for an unregistered or offline driver, the Kubernetes scheduler binds the pod to the node based on `ResourceSlice`.
2. When kubelet reconciles the pod, it attempts to call `NodePrepareResources` on the driver's gRPC socket.
3. Because the driver is offline or unregistered, kubelet logs:
   ```
   Warning FailedPrepareDynamicResources: failed to get gRPC client for driver <name>: plugin name not found in the list of registered DRA plugins
   ```
4. The pod remains in `Pending` / `ContainerCreating` status indefinitely.
5. Kubelet **refuses to invoke CRI `CreateContainer` or start the workload**. The container is never executed unprotected.

---

## 5. Evaluation Against Issue #159 Criteria

| Criterion | Evaluation / Observed Result |
| :--- | :--- |
| **Invisibility** | **Low-to-Moderate:** The workload container block required only `resources.claims: [{ name: portal-egress }]`. However, the pod spec still carried the sidecar container, a `hostPath` volume, a `Secret` volume, and `hostAliases`. The "only the opt-in" bar was not met. |
| **Privileges** | **Workload: Zero privileges.** Workload runs as unprivileged user (UID 1000) with `allowPrivilegeEscalation: false` (`NoNewPrivs: 1`) and zero capabilities.<br>**Node: High privileges.** The DRA driver DaemonSet runs as a privileged container with hostPath mounts (`/var/lib/kubelet`, `/etc/cdi`, `/usr/local/bin`). Autopilot does not currently permit third-party DRA plugins. |
| **Bypass Resistance** | **Partial / Flawed in Prototype:** Within the network namespace, unprivileged processes cannot alter iptables. However, the hook implementation failed open on errors, and init containers ran prior to hook execution (see Section 9). |
| **Pod Identity** | In sidecar mode (used in this spike), pod identity was implicitly 1:1 local. In per-node DaemonSet mode, mapping pod IP or container ID to pod identity requires complex CRI metadata reconciliation in the hook. |
| **CA Distribution** | **Dynamic CDI mount (with severe security defect):** The DRA driver wrote the CA keypair to `/var/run/service-portal/ca`. The CDI spec bind-mounted this into `/etc/service-portal/ca`, inadvertently exposing the CA private key to workloads (see Section 6.3). |
| **Failure Mode** | **Mixed:** Kubelet fails closed if the driver is offline or `NodePrepareResources` fails (pod stays in `Pending`). However, the prototype OCI hook failed open on iptables errors (logged and exited 0). |
| **Testability on kind** | **Full:** Functional on kind v0.27.0 with containerd v2.3.6 and Kubernetes 1.32.2 with custom feature gates and CRI config patches. |
| **Operational Complexity** | **Very High:** Requires cluster-level feature gates, containerd CDI enablement in `config.toml`, host binary installation, node DaemonSets, and custom DRA API objects (`DeviceClass`, `ResourceSlice`). |

---

## 6. Credentials & Security Analysis

### 6.1 `opaque` Device Config Parameters
In Kubernetes DRA, a `ResourceClaim` can include `spec.devices.config`:
```yaml
config:
- opaque:
    driver: portal-egress.portals.gke.io
    parameters:
      policy: "gemini-portal-policy"
```
When `NodePrepareResources` is called, kubelet passes opaque parameters to the node driver. The driver can read the named `PortalPolicy` or rules for that pod.

### 6.2 What Could a Pod Learn About Other Pods' Claims?
1. **`ResourceClaim` Scope:** `ResourceClaim` is namespaced. A pod with default service account permissions cannot list or read claims outside its namespace.
2. **`ResourceSlice` Scope:** `ResourceSlice` is cluster-scoped. If RBAC allows reading `ResourceSlice`, allocated device names (`egress-0`) and node assignments are visible, but claim secrets or policy configurations are not stored there.
3. **CDI Specs on Disk:** CDI files in `/etc/cdi` are owned by root on the host. Workload containers cannot read `/etc/cdi` as they are isolated in their own mount namespace.
4. **Secret Isolation Mandate:** Plaintext credentials should never be passed inside opaque claim parameters. Claims must only pass references (e.g. Secret name in the pod's namespace).

### 6.3 Security Regression Lesson: CA Private Key Bind-Mounted into Workloads
A critical security flaw was identified in the prototype driver (`cmd/dra-portal-driver/main.go:176-178, 326`):
1. The driver generated both `tls.crt` and `tls.key` into `/var/run/service-portal/ca` on the host.
2. The CDI specification injected a host bind-mount of `/var/run/service-portal/ca` into `/etc/service-portal/ca` in every claiming container.
3. Consequently, the **node-wide CA private key (`tls.key`) was mounted directly into every workload container**.
4. Any workload pod claiming egress could read the private key and mint arbitrary TLS certificates for any domain, completely dismantling TLS trust boundaries across the node.

---

## 7. What Was Faked or Prototyped

To ensure complete transparency regarding this spike:
1. **Proxy Placement:** The spike evaluated interception using a sidecar proxy container (`all-in-one-portal:e2e`) injected alongside the workload, running as UID 1337. The workload container had no init container and no `NET_ADMIN`, but the sidecar was still required in the pod spec.
2. **ResourceSlice Provisioning:** The prototype driver did not dynamically publish a `ResourceSlice`. The e2e test hand-created a static `ResourceSlice` with three devices (`egress-0`, `egress-1`, `egress-2`).

---

## 8. What Would Be Needed to Productionise

If DRA + CDI were to be productionised, the following substantial engineering efforts would be required:
1. **Dynamic ResourceSlice Controller:** Implement dynamic generation of `ResourceSlice` instances in `cmd/dra-portal-driver` using `client-go`, adjusting device count and capacity automatically.
2. **Claim Cleanup on Deletion:** Enhance `NodeUnprepareResources` to clean up ephemeral pod certificates and per-claim CDI spec files on container destruction.
3. **Containerd Configuration Automation:** Node provisioning scripts (cloud-init or GKE node initializers) must configure `/etc/containerd/config.toml` to enable `enable_cdi = true` and specify `cdi_spec_dirs`.
4. **Fail-Closed Hook Hardening:** Modify the hook to exit non-zero on any iptables failure, and isolate public CA certificates from private keys.
5. **GKE Autopilot Platform Feature Request:** Advocate with GKE engineering for managed DRA egress driver support, or pursue sibling mechanisms (NRI or eBPF) that can be packaged into managed platform runtimes.

---

## 9. Conclusion: Not Pursued & Lessons Learned

### 9.1 Decision & Observed Reasons

Decision from the [#159](https://github.com/gke-labs/service-portals/issues/159) comparison: **DRA + CDI is not being pursued**. Node Resource Interface (NRI) is the mechanism we build on.

The reasons observed during this spike:

1. **Per-Container Hook Lifecycle vs Pod-Level Egress:**
   - The CDI hook fires per-container, and *only* for containers that explicitly list the claim in their `resources.claims`.
   - Consequently, any `initContainers` (or auxiliary sidecars that do not list the claim) execute *before* any iptables rules exist. This creates an unmitigated window during pod initialization where traffic escapes uninspected.
   - In contrast, NRI's `RunPodSandbox` hook fires once per pod *before* any container (init or application) is created or started, providing airtight pod-wide network encapsulation.

2. **Capacity Semantics Are an Unnatural Workaround:**
   - DRA models devices as exclusive resources allocated to specific containers. Egress interception is an abstract pod-level capability, not a scarce, exclusive physical device.
   - The driver does not dynamically publish `ResourceSlice` objects; in the e2e test, a `ResourceSlice` had to be hand-created with an arbitrary static number of devices (`egress-0`, `egress-1`, `egress-2`).
   - Autoscaled or dynamically added nodes would have no devices provisioned, leading to pod scheduling deadlocks unless complex controller logic continuously synthesizes fake device capacity.

3. **High Operational Complexity & API Churn:**
   - **API Churn:** The DRA API is undergoing rapid breaking changes across Kubernetes versions (`v1alpha3` / `v1beta1` pinned at `main.go:263`, transitioning to `v1` in 1.34), creating high maintenance drag.
   - **Host Binary & Path Dependencies:** The driver requires registering as a kubelet plugin, maintaining CDI directories (`/etc/cdi`), and copying a standalone hook binary to `/usr/local/bin/portal-cdi-hook` on the host (`main.go:338`). On Container-Optimized OS (COS), `/usr/local/bin` is mounted read-only, making host binary installation fail without invasive workarounds.

4. **Sandboxed Runtimes (gVisor & Kata Containers) Limitations:**
   - The OCI hook installs iptables rules into the host-side pod network namespace (`/proc/<pid>/ns/net`).
   - In sandboxed runtimes like gVisor (`runsc`) or Kata Containers, network traffic processing occurs inside the guest sandbox and does not traverse the host-side network namespace in the same manner. Host-side iptables rules are bypassed.
   - Furthermore, OCI hook execution under gVisor and Kata is runtime-dependent, often unsupported or ignored entirely.

### 9.2 Summary of Corrected Claims

1. **Hook Failure Semantics (Failed Open):**
   Contrary to claims in early drafts that OCI hooks provide strictly fail-closed guarantees, the prototype hook (`cmd/portal-cdi-hook/main.go:336-345`) logged iptables failures as warnings and exited 0. If iptables rules failed to apply, the container was launched completely unprotected.
2. **Pod Spec Invisibility Bar Not Met:**
   Contrary to claims of zero pod changes beyond the opt-in claim, the pod spec still carried the `service-portal-sidecar` container, a `hostPath` volume for CA data, a `Secret` volume for rules, and `hostAliases`.

### 9.3 Security Regression Lesson

* **CA Private Key Exposure:** As documented in Section 6.3, the prototype bind-mounted `/var/run/service-portal/ca` into `/etc/service-portal/ca`, exposing the node-wide CA private key (`tls.key`) to every workload container. In subsequent designs (e.g. NRI), CA distribution must strictly separate public certificates from signing keys so that workloads only ever receive public trust bundles.

### 9.4 Properties Worth Remembering for NRI

Two valuable properties emerged from the DRA investigation that should be carried forward into the NRI implementation:

1. **The Scheduling Gate:**
   Under DRA, a pod requesting the claim cannot be scheduled or started if the driver is offline or unregistered—kubelet fails resource preparation and refuses to start the container. With NRI, we can achieve an equivalent guarantee by using **NRI pre-registration combined with a node readiness taint** (e.g., tainting nodes until the NRI interception daemon is healthy and registered), ensuring no pods can run unprotected before the interception mechanism is active.
2. **Explicit, Admission-Checkable Opt-in:**
   Having an explicit, declarative claim in the pod spec (`spec.resourceClaims`) allows admission webhooks, CEL policies, and security auditors to readily inspect and enforce egress interception policies at the API layer without relying on fragile side-effects or annotations.
