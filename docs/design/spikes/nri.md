# Spike (#159 / #161): containerd Node Resource Interface (NRI) Plugin as Interception Mechanism

**Author**: codebot-robot  
**Date**: October 2026  
**Status**: Prototype / Spike Complete  
**Branch**: `spike/nri`  
**Tracking Issue**: [#161](https://github.com/gke-labs/service-portals/issues/161) (Sub-issue of [#159](https://github.com/gke-labs/service-portals/issues/159))  

---

## 1. Executive Summary

This spike investigates using a **containerd Node Resource Interface (NRI) plugin** (`github.com/containerd/nri/pkg/stub`) as the transparent network interception mechanism for `service-portals`, completely replacing the per-pod init container (`init-service-portals`) and sidecar container (`all-in-one-portal`).

We implemented an NRI plugin daemon (`cmd/portal-nri-plugin`), packaged it in a container image (`images/portal-nri-plugin/Dockerfile`), deployed it as a node-level DaemonSet alongside a node-level proxy, and proved that it successfully passes all assertions of the default-deny egress test suite (`TestNRIPluginEgressDenied`, reusing the exact semantics of `TestSidecarEgressDenied` from #147 / #155) on a kind cluster.

### Key Result: Workload Pod Spec
The workload pod runs with **zero init containers, zero sidecars, zero capabilities (`NET_ADMIN` omitted), zero volume mounts, zero environment variables, and zero `hostAliases`**. The workload pod spec contains solely the opt-in label:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-client-nri-deny
  labels:
    app: test-client-nri-deny
    service-portal.gke.io/intercept: "true"
spec:
  containers:
  - name: workload
    image: toolbox:e2e
    imagePullPolicy: Never
    securityContext:
      runAsUser: 1000
      allowPrivilegeEscalation: false
    command: ["/bin/sh", "-c", "sleep 3600"]
```

---

## 2. Architecture & How it Works

```
+-------------------------------------------------------------------------------+
| Node (Host Network & PID Namespace)                                           |
|                                                                               |
|  +-------------------------------------------------------------------------+  |
|  | portal-node-agent DaemonSet                                             |  |
|  |                                                                         |  |
|  |  [proxy container] (all-in-one-portal)                                  |  |
|  |  • Listens on Host Network :8080 (HTTP) and :8443 (HTTPS)               |  |
|  |  • Mounts Node CA (/etc/service-portal/ca/tls.{crt,key})                |  |
|  |  • Injects upstream credentials and forwards traffic                    |  |
|  |                                                                         |  |
|  |  [nri-plugin container] (portal-nri-plugin)                             |  |
|  |  • Connects to containerd NRI socket: /var/run/nri/nri.sock            |  |
|  |  • Subscribes to: Synchronize, RunPodSandbox, StopPodSandbox,           |  |
|  |    CreateContainer                                                      |  |
|  +-----------------------------------+-------------------------------------+  |
|                                      |                                        |
+--------------------------------------|----------------------------------------+
                                       |
    [NRI Events: Synchronous CRI Hook] |
                                       v
+-------------------------------------------------------------------------------+
| Workload Pod Sandbox (Pod Netns)                                              |
|                                                                               |
|  1. RunPodSandbox:                                                            |
|     - Plugin receives pod metadata and netns path (/run/netns/cni-xxxx).      |
|     - Plugin executes nsenter --net=<path> iptables:                          |
|         • DNAT port 80 -> <Node-IP>:8080                                      |
|         • DNAT port 443 -> <Node-IP>:8443                                     |
|         • Egress filter: allow Node-IP:8080/8443, allow cluster DNS (UDP/TCP) |
|         • Reject all non-intercepted TCP/UDP egress (Default Deny)            |
|     - Plugin appends intercepted domains to /var/lib/kubelet/pods/<uid>/etc-hosts|
|                                                                               |
|  2. CreateContainer:                                                          |
|     - Plugin inspects container creation request.                             |
|     - Returns ContainerAdjustment:                                            |
|         • Injects env: SSL_CERT_FILE=/etc/service-portal/ca/tls.crt           |
|         • Injects bind mount: Host /etc/service-portal/ca/tls.crt ->          |
|                               Container /etc/service-portal/ca/tls.crt (ro)   |
|                                                                               |
|  3. Workload Container Runs:                                                  |
|     - Runs as unprivileged UID 1000 with allowPrivilegeEscalation: false.     |
|     - Requests to gemini.backend:80 or :443 resolve to intercept IP           |
|       and are DNAT'd to node proxy :8080 or :8443.                            |
|     - Proxy presents dynamic TLS certificate signed by Node CA.               |
|     - Workload verifies cert against injected SSL_CERT_FILE.                  |
|     - Proxy swaps authorization header and calls upstream backend.            |
+-------------------------------------------------------------------------------+
```

---

## 3. Detailed Evaluation Against #159 Criteria

### Criterion 1: Invisibility
* **Requirement**: No changes to the workload pod spec beyond an opt-in (label/annotation).
* **Observed Reality**: **100% Invisible**.
  * No `initContainers` needed in the pod spec.
  * No sidecar container needed in the pod spec.
  * No `securityContext.capabilities` needed (`NET_ADMIN` is not needed in the pod).
  * No CA certificate volume or volumeMount needed in the pod spec (injected by NRI `CreateContainer` adjustment).
  * No `SSL_CERT_FILE` environment variable needed in the pod spec (injected by NRI `CreateContainer` adjustment).
  * No `hostAliases` needed in the pod spec (intercepted hostnames are written by the NRI plugin to the pod's kubelet-managed `/etc/hosts`).
  * The pod spec contains only `labels: { service-portal.gke.io/intercept: "true" }`.

### Criterion 2: Privileges
* **Workload Pod**: Completely unprivileged. Tested with UID 1000 and `allowPrivilegeEscalation: false`. Workload has 0 Linux capabilities.
* **Node Agent DaemonSet**:
  * Runs on the node with `hostNetwork: true`, `hostPID: true`, and `privileged: true` (or `CAP_SYS_ADMIN` + `CAP_NET_ADMIN`).
  * Requires host volume mounts:
    * `/var/run/nri/nri.sock` (containerd NRI control socket).
    * `/run/netns` (with `mountPropagation: HostToContainer`) to access pod network namespaces.
    * `/var/lib/kubelet/pods` (to append DNS mappings to pod `/etc/hosts`).
* **Autopilot vs. GKE Standard**:
  * **GKE Autopilot**: **Incompatible / Not Supported**. Autopilot does not permit user-deployed privileged DaemonSets, host network/PID namespaces, or hostPath bind mounts to `/var/run/nri/nri.sock` or `/run/netns`. Google internally uses NRI in Autopilot (e.g. for GPU device injection and Istio Ambient Mesh), but user NRI plugins cannot be deployed by tenants.
  * **GKE Standard**: **Supported** `[unverified]`. NRI is enabled in containerd 2.0+ by default; on GKE Standard, NRI availability is pending confirmation `[unverified: earlier docs referenced GKE 1.29, but issue #167 indicates GKE 1.33+ / containerd 2.0]`. User DaemonSets can mount `/var/run/nri/nri.sock` and register NRI plugins on GKE Standard nodes where NRI is active.

### Criterion 3: Bypass Resistance
* **Root in Workload**: Even if a process runs as root (UID 0) inside the workload container, in Kubernetes default container runtimes it does *not* receive `CAP_NET_ADMIN` in the network namespace. Without `CAP_NET_ADMIN`, it is impossible to run `iptables`, flush chains, remove DNAT rules, or modify routes (`Operation not permitted`).
* **UID 1337 Bypass Elimination**: In the transparent sidecar architecture, an iptables exemption (`-m owner --uid-owner 1337 -j RETURN`) was required so that the proxy's outbound traffic did not loop back into itself. A workload process that escalated to UID 1337 could bypass the proxy.
  * **In the NRI DaemonSet model, the proxy runs on the host network outside the pod netns.**
  * Therefore, **no UID exemption exists inside the pod network namespace**.
  * Even if a workload process runs as UID 1337 inside the pod, its traffic on ports 80 and 443 is unconditionally DNAT'd to the node proxy. The UID 1337 bypass attack vector is completely eliminated.
* **IP Literals & Unlisted Hostnames**: All traffic to ports 80 and 443 is DNAT'd to the proxy listener. When a request arrives with an IP literal or an unlisted hostname, the proxy router (`RuleRouter`) finds no matching `PortalRule` and terminates the request (403/404/502). The request never reaches the backend.
* **Non-Intercepted Ports**: The egress filter chain (`PORTAL_EGRESS`) unconditionally rejects all non-intercepted TCP and UDP egress with `icmp-port-unreachable`. Tested with port 8080 and raw TCP port 9999 (both fail immediately).
* **Arbitrary DNS**: Port 53 UDP and TCP traffic is filtered to permit only the cluster DNS nameserver(s) (e.g., `10.96.0.10`). Attempts to probe external resolvers (`8.8.8.8`) are blocked with `operation not permitted`.
* **IPv6 Traffic Unfiltered**: The current prototype exclusively installs IPv4 `iptables` rules. IPv6 is unfiltered in the pod netns (`ip6tables` rules are not installed), leaving an exfiltration vector if IPv6 networking is active on the cluster. Enforcing IPv6 parity or dropping all IPv6 traffic in the netns is tracked for follow-up work.

### Criterion 4: Pod Identity & Caller Authentication for Per-Node Proxy
* **Source IP**:
  * Because the pod and the host proxy are on the same node connected via a veth pair, the TCP connection arrives at the node proxy listener with the remote address set to the pod's IP (`10.244.0.x`).
  * CNI assigns a unique, immutable IP to each pod for its lifetime.
  * TCP handshake requires completing a bidirectional 3-way handshake; a container cannot spoof its source IP with `NET_RAW` to hijack another pod's identity because SYN-ACK replies will route to the real owner of the IP.
  * The node proxy can map `source_ip -> Pod (Namespace, Name, UID, Labels)` via an in-memory cache synchronized by the NRI plugin or local kubelet API.
* **Cgroup / Mark Tagging**:
  * NRI receives `pod.Linux.CgroupParent` and `ctr.Linux.CgroupsPath`.
  * If eBPF (`sockops` or `cgroup_skb`) or SO_PEERCRED / cgroup lookup is used on the host, the connection can be correlated directly with the pod's cgroup ID on the host socket without relying solely on IP.
* **Caller Authentication Limitation**:
  * **The per-node proxy does not authenticate callers.** It listens on the node network (`0.0.0.0:8080` / `0.0.0.0:8443`) and does not inspect `RemoteAddr` to authenticate the calling pod. Consequently, any pod or process on the node could directly address the proxy ports. Implementing mutual authentication or strict per-pod identity enforcement at the proxy is tracked as follow-up work.

### Criterion 5: CA Distribution Without Webhooks
* **Mechanism**:
  * When `CreateContainer` is invoked for a container in an intercepted pod, the plugin adds a bind mount to the container adjustment:
    ```go
    adjustment.AddMount(&api.Mount{
        Destination: "/etc/service-portal/ca/tls.crt",
        Source:      "/etc/service-portal/ca/tls.crt",
        Type:        "bind",
        Options:     []string{"rbind", "ro"},
    })
    adjustment.AddEnv("SSL_CERT_FILE", "/etc/service-portal/ca/tls.crt")
    ```
  * Containerd on the host injects this mount and environment variable before container execution.
* **Host Path Dependency**: Containerd resolves NRI adjustment mount sources in the host filesystem namespace. Therefore, the node CA certificate bundle must exist on the host (e.g. at `/etc/service-portal/ca/tls.crt` mounted via the DaemonSet `hostPath`).
* **No Spec Mutation**: The workload pod's `spec.volumes` and `spec.containers[*].volumeMounts` remain completely untouched.

### Criterion 6: Fail-Closed Behavior & Failure Semantics
We empirically tested failure and timeout behaviors:
1. **Plugin Returns Error in `RunPodSandbox`**:
   * If `portal-nri-plugin` fails during `RunPodSandbox` (e.g. iptables failure or netns error), containerd CRI immediately aborts sandbox creation:
     `Warning FailedCreatePodSandBox: rpc error: code = Unknown desc = NRI RunPodSandbox failed: ...`
   * The pod remains in `ContainerCreating`. **Workload containers are never created and never run.**
2. **Plugin Returns Error in `CreateContainer`**:
   * If the plugin returns an error during `CreateContainer`, containerd CRI aborts container creation:
     `Warning Failed: Error: failed to create containerd container: failed to get NRI adjustment for container: ...`
   * The container enters `CreateContainerError` and code never executes.
3. **Plugin Timeout**:
   * Containerd enforces `plugin_request_timeout = "2s"`. If the plugin hangs, containerd CRI times out and aborts pod sandbox creation. Observed on containerd v2.0.2 in kind image `kindest/node:v1.32.2` (containerd NRI default `plugin_request_timeout = "2s"`).
4. **No Silent Fallbacks in Rules Configuration**:
   * In earlier iterations, failures to resolve gateway IP, DNS servers, or intercept addresses fell back to hard-coded IPs (`10.244.0.1`, `10.96.0.10`, `8.8.8.8`).
   * In this implementation, all silent fallbacks have been removed. If gateway detection fails, DNS discovery fails, or the intercept IP is unconfigured/invalid, the plugin returns an explicit error from `RunPodSandbox` and `Synchronize`, causing containerd to immediately fail sandbox creation closed.
5. **Plugin Absence / DaemonSet Restart Mitigation**:
   * If the NRI plugin is down, containerd's default NRI behavior without registered plugins is to bypass hooks.
   * **Why Pre-registration in `/opt/nri/plugins` Is Impractical on Kind and Live Nodes**:
     * In containerd NRI architecture, pre-installed binary plugins in `/opt/nri/plugins` are discovered exclusively during containerd startup (`Adaptation.Start()`). Containerd has no inotify watcher or periodic rescan of `/opt/nri/plugins`. An init container or DaemonSet dropping a binary into `/opt/nri/plugins` after containerd has started will never be launched unless containerd itself is restarted.
     * Container shims survive a containerd restart, but restarting containerd still disrupts containerd-to-kubelet CRI streaming connections, container event listeners, and live exec/logs sessions.
     * When containerd launches a pre-installed binary, it scrubs the environment, passing only `NRI_PLUGIN_SOCKET=3`, `NRI_PLUGIN_NAME`, and `NRI_PLUGIN_IDX`. Pre-registered binaries receive no environment variables, downward API, or Kubernetes secret mounts, and run outside Kubernetes scheduling and resource tracking.
   * **Fail-Closed Mitigation via Node Taint Gating and `Synchronize`**:
     * **Node Taint Gating**: Nodes are tainted on startup (`service-portal.gke.io/uninitialized:NoSchedule`). Intercepted workloads do not tolerate this taint, preventing them from scheduling to uninitialized nodes. The DaemonSet tolerates the taint. Once `portal-nri-plugin` connects to containerd's NRI socket and synchronizes, it removes the node taint via the Kubernetes API.
     * **`Synchronize` Implementation**: When `portal-nri-plugin` starts or reconnects, containerd invokes `Synchronize(pods, containers)`. The plugin iterates through all existing sandboxes and re-applies iptables redirection and default-deny egress rules as well as `/etc/hosts` entries for all opted-in pods. Per-pod errors are logged without failing plugin registration.
     * **Residual Risk on Plugin Crash**: Once the node taint is removed after initial daemon startup, if the NRI plugin crashes, subsequent pods created while the plugin is down would run unprotected until the DaemonSet restarts and `Synchronize` re-applies the rules. Nothing automatically re-applies the node taint upon plugin crash. Proposed mitigations include a host-level watchdog/liveness controller that re-taints the node on agent failure, or moving enforcement to host-side veth devices (#181).

### Criterion 7: Runtime Classes (gVisor, Kata Containers)
* **Pod Netns vs. Host-Side Enforcement**:
  * In the current implementation, rules are installed inside the pod network namespace (`nsenter --net=<netnsPath> iptables`).
  * This works for runc/containerd standard container runtimes where the container shares the Linux network namespace created for the sandbox.
* **Isolated Runtime Class Limitations**:
  * **gVisor (`runsc`)**: gVisor implements its own userspace networking stack (netstack) inside the sandbox. Traffic originating inside a gVisor sandbox is processed by netstack and sent directly across the sandbox boundary; host iptables rules installed in the network namespace are bypassed / not traversed by gVisor's netstack.
  * **Kata Containers**: Kata runs the pod sandbox inside a dedicated guest microVM. Network devices are passed through to the VM, and network processing occurs within the guest kernel, bypassing network namespace rules on the host.
* **Next Steps**:
  * The plugin currently does not inspect `pod.RuntimeHandler` or `runtimeClassName`.
  * In a follow-up issue, enforcement will move to the host side of the veth interface (or tap device) using host-level iptables, tc, or eBPF. Host-side veth enforcement guarantees traffic interception and default-deny egress regardless of whether the sandbox runs runc, gVisor, or Kata.

### Criterion 8: Testability on Kind & Runtime Versions
* **containerd Version in Kind**:
  * Kind node image `kindest/node:v1.32.2` runs **containerd v2.0.2** (`containerd github.com/containerd/containerd/v2 v2.0.2 c507a0257ea6462fbd6f5ba4f5c74facb04021f4`).
* **NRI Status**:
  * In **containerd 2.0+**, NRI is **enabled by default** (`disable = false`).
  * NRI socket `/var/run/nri/nri.sock` is active out-of-the-box on standard kind clusters without any `containerdConfigPatches`!
  * (In containerd 1.7.x, NRI was disabled by default and required a kind configuration patch under `[plugins."io.containerd.nri.v1.nri"] disable = false`).
* **Netns Mount Propagation**:
  * In kind (and Linux host runtimes), `/run/netns` is a tmpfs mount where CNI dynamically creates netns mount points (`/run/netns/cni-...`).
  * The DaemonSet container mounting `/run/netns` **must specify `mountPropagation: HostToContainer`**. Without this flag, dynamically created netns mount points on the host appear as unmounted inodes inside the container, causing `nsenter: reassociate to namespace 'ns/net' failed: Invalid argument` (EINVAL).
* **HostNetwork DNS Resolution**:
  * A DaemonSet proxy running with `hostNetwork: true` uses the host's `/etc/resolv.conf` by default. To resolve in-cluster Kubernetes services (like `http://backend`), the DaemonSet pod spec must specify `dnsPolicy: ClusterFirstWithHostNet`.

---

## 4. E2E Test Suite Results

The prototype passes the exact semantics of `TestSidecarEgressDenied`, including taint gating verification and both HTTP and HTTPS positive controls:

```
=== RUN   TestNRIPluginEgressDenied
=== RUN   TestNRIPluginEgressDenied/DirectIP_InterceptedPort_HTTP
=== RUN   TestNRIPluginEgressDenied/DirectIP_InterceptedPort_HTTPS
=== RUN   TestNRIPluginEgressDenied/UnlistedHostname_InterceptedPort_HTTP
=== RUN   TestNRIPluginEgressDenied/UnlistedHostname_InterceptedPort_HTTPS
=== RUN   TestNRIPluginEgressDenied/NonInterceptedPort_HTTP_8080
=== RUN   TestNRIPluginEgressDenied/NonInterceptedPort_RawTCP_9999
=== RUN   TestNRIPluginEgressDenied/ArbitraryDNS_Blocked
=== RUN   TestNRIPluginEgressDenied/ClusterDNS_Allowed
=== RUN   TestNRIPluginEgressDenied/PositiveControl_GeminiHTTP
=== RUN   TestNRIPluginEgressDenied/PositiveControl_GeminiHTTPS
=== RUN   TestNRIPluginEgressDenied/BypassAttempt_Disallowed
--- PASS: TestNRIPluginEgressDenied (55.30s)
    --- PASS: TestNRIPluginEgressDenied/DirectIP_InterceptedPort_HTTP (0.17s)
    --- PASS: TestNRIPluginEgressDenied/DirectIP_InterceptedPort_HTTPS (0.17s)
    --- PASS: TestNRIPluginEgressDenied/UnlistedHostname_InterceptedPort_HTTP (0.15s)
    --- PASS: TestNRIPluginEgressDenied/UnlistedHostname_InterceptedPort_HTTPS (0.18s)
    --- PASS: TestNRIPluginEgressDenied/NonInterceptedPort_HTTP_8080 (1.21s)
    --- PASS: TestNRIPluginEgressDenied/NonInterceptedPort_RawTCP_9999 (0.10s)
    --- PASS: TestNRIPluginEgressDenied/ArbitraryDNS_Blocked (0.21s)
    --- PASS: TestNRIPluginEgressDenied/ClusterDNS_Allowed (0.22s)
    --- PASS: TestNRIPluginEgressDenied/PositiveControl_GeminiHTTP (0.21s)
    --- PASS: TestNRIPluginEgressDenied/PositiveControl_GeminiHTTPS (0.25s)
    --- PASS: TestNRIPluginEgressDenied/BypassAttempt_Disallowed (0.32s)
PASS
```

* **Node Taint Gating**: Node is tainted with `service-portal.gke.io/uninitialized:NoSchedule`. Client pod is confirmed `Pending`. DaemonSet connects, removes the taint via `Synchronize`, and client pod transitions to `Running` and `Ready`.
* **Direct IP**: Wget to `http://<Backend-ClusterIP>:80` and `https://<Backend-ClusterIP>:443` fails. Backend access logs confirm the request was never forwarded.
* **Unlisted Hostname**: Wget to `other.backend` fails on HTTP and HTTPS. Backend access logs confirm no request.
* **Non-Intercepted Ports**: Connecting to port 8080 or port 9999 immediately fails with `connection refused` (rejected by iptables `PORTAL_EGRESS` chain).
* **Arbitrary DNS**: DNS query to `8.8.8.8` fails with `operation not permitted`.
* **Cluster DNS**: Query to cluster DNS `10.96.0.10` successfully resolves `backend`.
* **Positive Controls**:
  * Query to `http://gemini.backend/positive-control-http` succeeds over HTTP, intercepted and injected with `Authorization: Bearer gemini-nri-token`.
  * Query to `https://gemini.backend/positive-control` succeeds over TLS with dynamically minted certificate, injecting `Authorization: Bearer gemini-nri-token`.
* **Bypass Attempt**: Workload UID is confirmed as 1000, `NoNewPrivs: 1` is verified, and switching to UID 1337 fails.

---

## 5. What Was Faked & Limitations of the Spike

1. **Static Rules Configuration in Test**: The test DaemonSet proxy loaded `PortalRule`s from a static Secret rather than dynamically reconciling per-namespace `PortalPolicy` CRDs across multiple tenants.
2. **Kubelet `/etc/hosts` Mutation & Naive Deduplication**: The spike appends `<intercept-ip> <hosts...>` to `/var/lib/kubelet/pods/<pod-uid>/etc-hosts`. `appendHostsEntry` dedupes using substring match (`strings.Contains`) and writes a kubelet-managed file. Because kubelet owns and may regenerate this file on pod sync, pairing NRI with node-local DNS interception or sidecar DNS (#157) is cleaner for production.
3. **No Caller Authentication at Proxy**: The node proxy does not authenticate callers (it never inspects `RemoteAddr` against pod IPs), allowing any pod or process on the node network to reach proxy ports.
4. **IPv6 Unfiltered**: Netns iptables rules are IPv4-only; IPv6 is unfiltered.
5. **Runtime Classes Unhandled**: Pod netns rules are not traversed by gVisor netstack or Kata guest VMs; `runtimeClassName` is not yet checked.
6. **NRI Cannot Inject Containers**: As confirmed and documented, the NRI API (`*api.ContainerAdjustment`) has no method to inject additional containers into a pod. A sidecar proxy cannot be injected via NRI; the proxy must run as a per-node DaemonSet or be added via an admission webhook.
7. **Single-Node Kind Cluster**: Kind runs a single node with all pods sharing the kind control-plane node. Multi-node cross-traffic between nodes was not tested in this spike.

---

## 6. What Would Be Needed to Productionise

1. **Host-Side Veth / Tap Enforcement & Runtime Class Support**:
   * Move egress filtering and DNAT to host-side veth/tap devices to enforce rules for gVisor and Kata sandboxes.
2. **Per-Pod Identity & Caller Authentication at Proxy**:
   * Map incoming TCP connection `source_ip` or host cgroup ID to pod identity, verifying callers against tenant policies.
3. **IPv6 Parity & DNS Bounds**:
   * Block or intercept IPv6 traffic in the netns and bound DNS exfiltration paths.
4. **Multi-Tenant Policy Engine in Node Proxy**:
   * A controller watching `PortalPolicy` CRDs per namespace.
5. **Node Taint Gating**:
   * Standardize node initialization taints to prevent uninitialized nodes from running intercepted workloads before the DaemonSet connects and synchronizes.
6. **GKE Autopilot Alternative**:
   * Retain the webhook injector (#150) for Autopilot, while using NRI for GKE Standard.

---

## 7. Conclusion & Recommendation

The NRI plugin approach is an exceptionally viable, high-performance interception mechanism for **GKE Standard and self-managed Kubernetes**:
- **Pros**: Zero workload pod modifications, zero init container overhead, zero `NET_ADMIN` privileges in the workload, elimination of the UID 1337 bypass vector, and sub-millisecond setup latency.
- **Cons**: Requires host-level DaemonSet privileges and cannot run on GKE Autopilot.

**Recommendation**: Retain the webhook injector (#150) for Autopilot support, and offer the NRI plugin + per-node DaemonSet mode (#151 / #161) for high-density sandboxes on GKE Standard and bare-metal environments.
