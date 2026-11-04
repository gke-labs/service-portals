# Spike (#159 / #193): containerd Node Resource Interface (NRI) Plugin as Interception Mechanism

**Author**: codebot-robot  
**Date**: November 2026  
**Status**: Mergeable Spike Complete  
**Tracking Issues**: [#193](https://github.com/gke-labs/service-portals/issues/193), [#159](https://github.com/gke-labs/service-portals/issues/159)  
**Follow-up Issues**: [#181](https://github.com/gke-labs/service-portals/issues/181) (Host-side veth/tap enforcement), [#182](https://github.com/gke-labs/service-portals/issues/182) (Proxy caller identity and per-pod policy), [#183](https://github.com/gke-labs/service-portals/issues/183) (IPv6 and bounded DNS)  

---

## 1. Executive Summary

This spike implements and validates a **containerd Node Resource Interface (NRI) plugin** (`cmd/portal-nri-plugin`, container image `images/portal-nri-plugin`) as the interception mechanism for `service-portals`.

The plugin is deployed via a DaemonSet alongside `all-in-one-portal` serving as a per-node proxy listening on host ports 8080 (HTTP) and 8443 (HTTPS). Opted-in workload pods require **no init container, no `NET_ADMIN` capability, no sidecar container, no CA certificate mounts, and no `hostAliases`**. The workload pod spec specifies only the opt-in label:

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

## 2. Architecture & Lifecycle Hooks

```
+-------------------------------------------------------------------------------+
| Node (Host Network Namespace)                                                 |
|                                                                               |
|  +-------------------------------------------------------------------------+  |
|  | portal-node-agent DaemonSet                                             |  |
|  |                                                                         |  |
|  |  [proxy container] (all-in-one-portal)                                  |  |
|  |  • Listens on Host Network :8080 (HTTP) and :8443 (HTTPS)               |  |
|  |  • Mounts Node CA (/etc/service-portal/ca/tls.{crt,key})                |  |
|  |  • Swaps authorization tokens and forwards to upstreams                 |  |
|  |                                                                         |  |
|  |  [nri-plugin container] (portal-nri-plugin)                             |  |
|  |  • Runs with NET_ADMIN + SYS_ADMIN capabilities (no privileged flag)    |  |
|  |  • Mounts NRI socket: /var/run/nri/nri.sock and host /run/netns         |  |
|  |  • Subscribes to CRI hooks: RunPodSandbox, CreateContainer, Synchronize |  |
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
|     - Matches opted-in label service-portal.gke.io/intercept: "true".         |
|     - Resolves netns path strictly from sandbox Linux.Namespaces network      |
|       entry (fails closed on hostNetwork or matching host netns).              |
|     - Installs iptables rules before any container exists:                    |
|         • NAT DNAT ports 80/443 -> <proxyHost>:<proxyPort>                    |
|         • Filter PORTAL_EGRESS: loopback, established, proxy ports, port 53   |
|           only to configured cluster DNS servers; REJECT all else.            |
|                                                                               |
|  2. CreateContainer:                                                          |
|     - Fails closed if node CA certificate bundle is missing on host.          |
|     - Injects container adjustment:                                           |
|         • Env: SSL_CERT_FILE=/etc/service-portal/ca/tls.crt                   |
|         • Bind mount: host /etc/service-portal/ca/tls.crt (ro)                |
|                                                                               |
|  3. Synchronize:                                                              |
|     - Re-applies rules to already-running opted-in sandboxes only.            |
|     - Collects and joins per-pod errors via errors.Join.                      |
+-------------------------------------------------------------------------------+
```

---

## 3. Detailed Evaluation & Observations

### Opt-In Contract
* **Key & Value**: Exactly one documented label key: `service-portal.gke.io/intercept: "true"`.
* **No Shorthand & No Annotation Confusion**: Opt-in is exclusively checked via the label; annotations are not checked for opt-in, and undocumented shorthand values (e.g. `"1"`, `"yes"`) are rejected.
* **Early Return**: Every hook (`Synchronize`, `RunPodSandbox`, `CreateContainer`) returns early without taking action for pods without this label.

### Network Namespace Resolution & Safety
* **Source**: The pod network namespace is retrieved exclusively from `pod.Linux.Namespaces` where `Type == "network"`.
* **No Fallback**: Fallbacks to `/proc/<pid>/ns/net` are eliminated.
* **Safety Guards**:
  * Labelled `hostNetwork` pods have no network namespace entry in `Linux.Namespaces`; attempting to intercept them returns an explicit error (`hostNetwork pods cannot be intercepted`).
  * If the resolved namespace matches the plugin's own host network namespace (verified via `os.SameFile`), the hook immediately returns an error. The node's own iptables chains are never touched.

### Netns Isolation & Immutability Preconditions
* **Workload Isolation**: Even though redirection and filter rules reside in the pod's network namespace, standard unprivileged Kubernetes containers run without `CAP_NET_ADMIN` in their namespace (which holds under Pod Security Standards `baseline` and `restricted` profiles). Without `CAP_NET_ADMIN`, any attempt by a workload process (even running as root UID 0) to inspect, modify, flush, or delete iptables rules or alter routing tables is rejected by the Linux kernel with `EPERM` ("Operation not permitted").
* **Precondition & Core Assumption**: This guarantee strictly depends on opted-in pods not being granted `CAP_NET_ADMIN` or privileged execution in their pod spec; a container with `CAP_NET_ADMIN` in the pod netns can rewrite or delete these rules. Host-side enforcement (tracked in [#181](https://github.com/gke-labs/service-portals/issues/181)) is required to remove this trust assumption.

### Transparent Interception Without Hosts Mutation
* **All-Traffic Interception**: Because iptables DNAT unconditionally redirects all TCP port 80 and 443 traffic to the node proxy listener regardless of destination IP, fake hostname resolution tricks (such as mutating `/etc/hosts` or `/var/lib/kubelet/pods/<uid>/etc-hosts`) are unnecessary. Real Kubernetes Service hostnames (e.g. `backend`) resolve normally via cluster DNS, and the transparent proxy matches and routes on the HTTP `Host` header or TLS SNI.
* **Elimination of HostPath Dependencies**: This removes the need to mount `/var/lib/kubelet/pods` or `/var/lib/containerd` into the DaemonSet.

### DaemonSet Privileges
* **Reduced Privilege Profile**: The `portal-nri-plugin` container does not require `privileged: true`. It runs with:
  ```yaml
  securityContext:
    capabilities:
      add: ["NET_ADMIN", "SYS_ADMIN"]
  ```
  `CAP_SYS_ADMIN` is required for `setns(2)` to enter the pod network namespace, and `CAP_NET_ADMIN` is required for `iptables`.
* **No Host PID**: The container mounts `/run/netns` and executes `nsenter --net=/run/netns/...`, eliminating the need for `hostPID: true`.

### Fail-Closed Behavior & Taint Gating
* **Fail-Closed on Configuration**: The plugin strictly validates required configuration (`PROXY_HOST`, `DNS_SERVERS`, `CA_CERT_PATH`) at startup and terminates immediately if any required parameter is missing or invalid, avoiding silent fallbacks.
* **Fail-Closed in CreateContainer**: If the node CA bundle is missing on the host, `CreateContainer` immediately returns an error rather than silently degrading, preventing containers from running without trust bundles.
* **Taint Gating as a Test Step vs Production Reality**:
  * In the kind e2e test, taint gating demonstrates the *pattern*: the node is tainted (`service-portal.gke.io/uninitialized:NoSchedule`), the client pod remains `Pending`, the DaemonSet starts and becomes `Ready`, the taint is removed via `kubectl taint`, and the workload transitions to `Running` and intercepted.
  * In a real production cluster, nothing in this repository applies or removes that taint today. An operator or external controller (e.g. node-pool taint plus a step that removes it after the DaemonSet is `Ready`) must do it.
  * Crucially, once the taint is removed, a plugin crash or restart leaves newly scheduled pods unprotected (fail-open) until containerd reconnects to the plugin. True fail-closed enforcement requires host-side gating (tracked in [#181](https://github.com/gke-labs/service-portals/issues/181) and [#182](https://github.com/gke-labs/service-portals/issues/182)).

### Synchronize Semantics
* `Synchronize(pods, containers)` is invoked by containerd when the plugin registers or reconnects.
* It iterates across all existing sandboxes, evaluates `matchesPod(pod)`, and re-applies iptables redirection and filter rules for opted-in sandboxes only.
* Errors across sandboxes are collected and joined using `errors.Join`.
* **Registration Failure Consequence**: Containerd treats a non-nil error returned from `Synchronize` as a failed plugin registration and terminates the connection. Consequently, one misconfigured existing pod will take the entire plugin offline, leaving newly created pods to start unprotected (fail-open) until the DaemonSet pod restarts and reconnects. This consequence is accepted for this spike because a proper cluster-level admission and fail-closed gate is deferred to [#181](https://github.com/gke-labs/service-portals/issues/181) / [#182](https://github.com/gke-labs/service-portals/issues/182).

---

## 4. Runtime Classes: Host-Side Enforcement under runc, gVisor, and Kata (#181)

### The Host-Side Enforcement Architecture
In the initial prototype, iptables rules were installed inside the pod's network namespace (`nsenter --net=<netnsPath> iptables`). While effective for standard `runc` containers lacking `CAP_NET_ADMIN`, this failed for sandboxed runtimes:
* **gVisor (`runsc`)**: Implements its own userspace networking stack (`netstack`). Outgoing frames are written directly to the veth interface via `AF_PACKET` raw sockets, bypassing netfilter chains inside the pod network namespace entirely.
* **Kata Containers (`kata`)**: Executes pods inside a dedicated microVM guest kernel. Network processing occurs inside the guest kernel, and frames emerge on a host-side tap or veth device; rules inside a pod network namespace on the host are not traversed.

To enforce transparent redirection and default-deny egress consistently across all container and microVM runtimes, `#181` moves all iptables enforcement to the **node/host side** of the interface:
1. **Interface Discovery**:
   - In `RunPodSandbox`, the plugin determines the pod's network namespace path (`netnsPath`) from `pod.Linux.Namespaces`.
   - The plugin queries link status in the netns via `nsenter --net=<netnsPath> ip -o link show` and identifies the peer interface index (`@if<peerIndex>`).
   - Using `net.InterfaceByIndex(peerIndex)` in the host network namespace (or matching `link-netns <basename>` on the host), the plugin discovers the host-side device name (e.g. `vethXXXX` or `tapXXXX`).
   - The pod IPv4 address is also resolved from `pod.Ips` or `ip -o -4 addr show`.
2. **Dedicated Per-Interface Host Chains**:
   - NAT Table: Creates a per-interface chain `PORTAL_PR_<hostIface>` and inserts a jump at the head of `PREROUTING`:
     ```text
     -I PREROUTING 1 -i <hostIface> -j PORTAL_PR_<hostIface>
     -A PORTAL_PR_<hostIface> -p tcp --dport 80 -j DNAT --to-destination <proxyHost>:<proxyPort>
     -A PORTAL_PR_<hostIface> -p tcp --dport 443 -j DNAT --to-destination <proxyHost>:<proxyHTTPSPort>
     ```
     Inserting at position 1 ensures redirection happens before `kube-proxy` service DNAT rewrites destination IPs.
   - Filter Table: Creates a per-interface chain `PORTAL_EG_<hostIface>` and inserts jumps at the head of both `INPUT` (for local proxy traffic) and `FORWARD` (for external/cluster traffic):
     ```text
     -I INPUT 1 -i <hostIface> -j PORTAL_EG_<hostIface>
     -I FORWARD 1 -i <hostIface> -j PORTAL_EG_<hostIface>
     -A PORTAL_EG_<hostIface> -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
     -A PORTAL_EG_<hostIface> -d <proxyHost> -p tcp --dport <proxyPort> -j ACCEPT
     -A PORTAL_EG_<hostIface> -d <proxyHost> -p tcp --dport <proxyHTTPSPort> -j ACCEPT
     -A PORTAL_EG_<hostIface> -d <dnsServer> -p udp --dport 53 -j ACCEPT
     -A PORTAL_EG_<hostIface> -d <dnsServer> -p tcp --dport 53 -j ACCEPT
     -A PORTAL_EG_<hostIface> -m conntrack --ctorigdst <dnsServer> -p udp --dport 53 -j ACCEPT
     -A PORTAL_EG_<hostIface> -m conntrack --ctorigdst <dnsServer> -p tcp --dport 53 -j ACCEPT
     -A PORTAL_EG_<hostIface> -p tcp -j REJECT --reject-with icmp-port-unreachable
     -A PORTAL_EG_<hostIface> -p udp -j REJECT --reject-with icmp-port-unreachable
     -A PORTAL_EG_<hostIface> -j REJECT --reject-with icmp-port-unreachable
     ```
     *Cluster DNS Conntrack Note*: Because `kube-proxy` translates cluster DNS Service IPs (e.g. `10.96.0.10`) to endpoint pod IPs (e.g. `10.244.0.2`) in `PREROUTING`, matching `-m conntrack --ctorigdst <dnsServer>` ensures DNS queries continue to be accepted in `FORWARD` even after DNAT translation.
3. **Lifecycle Management & Idempotency**:
   - `portalPlugin` tracks active pod network state (`hostInterface`, `podIP`, `runtimeClass`) keyed by sandbox ID in an in-memory map protected by a mutex.
   - On pod termination (`StopPodSandbox` and `RemovePodSandbox`), host rules are unlinked and chains deleted (`-D PREROUTING`, `-D INPUT`, `-D FORWARD`, `-F`, `-X`). Cleanups are fully idempotent.
   - On plugin startup or reconnect (`Synchronize`), all existing opted-in pods are re-discovered and their host-side rules re-applied.

### RuntimeClass Detection & Fail-Closed Validation
The plugin inspects `pod.RuntimeHandler` (and CRI annotation `io.kubernetes.cri.runtime-handler`):
* **Supported Runtimes**: `""` (containerd default runc), `"runc"`, `"gvisor"`, `"runsc"`, `"kata"`, `"kata-qemu"`, `"kata-clh"`, `"kata-fc"`, and `"kata-containers"`.
* **Fail-Closed on Unknown RuntimeClass**: If an opted-in pod specifies an unknown or unvalidated runtime class (e.g. `runtimeClassName: unsupported-microvm`), `RunPodSandbox` and `CreateContainer` immediately return an error:
  ```text
  unsupported runtime class "unsupported-microvm" for opted-in pod <namespace>/<name>: refusing to start unprotected pod
  ```
  The pod sandbox fails to initialize, preventing workloads from starting without verified interception.
* **Non-Opted-In Pods**: Unrelated pods without `service-portal.gke.io/intercept: "true"` are ignored and run unrestricted on whatever runtime class they specify.

### Observations and Architectural Reasoning per Runtime
* **Standard Containers (`runc`)**:
  - Outgoing packets emerge from the pod veth peer into the host network namespace.
  - Verified on kind: passes the entire egress deny suite (`TestNRIPluginEgressDenied`) against host-side rules.
* **gVisor (`runsc`) `[unverified]`**:
  - Userspace netstack injects packets via raw packet socket onto the container interface.
  - Architectural reasoning: because netfilter hooks are situated on the host-side veth peer, netstack frames arrive in the host namespace before routing, where host-side PREROUTING/INPUT/FORWARD rules intercept them.
  - Verification status: `[unverified]`. Not yet verified in CI or against a live cluster.
* **Kata Containers (`kata`) `[unverified]`**:
  - Pod runs inside a microVM guest kernel; traffic egresses over virtio-net to the host-side tap device.
  - Architectural reasoning: host-side iptables inspects incoming packets on the host tap interface. Guest kernel or container processes have no access to the host's iptables rules.
  - Verification status: `[unverified]`. Not yet verified in CI or against a live cluster.

### Verification Status & Open Follow-Up
* **runc (kind)**: Fully verified in this PR. `TestNRIPluginEgressDenied` passes unchanged with host-side rules on kind (containerd v2.0.2).
* **gVisor and Kata microVMs**: Open. Host-side enforcement for microVM runtimes is designed and implemented based on netfilter hook positioning on host veth/tap interfaces, but live verification on a gVisor or Kata cluster is open and tracked in a dedicated follow-up issue (running the NRI deny suite under a gVisor RuntimeClass on kind in CI).

---

## 5. Security & Authentication Boundaries

* **Proxy Caller Identity (#182)**: The per-node proxy (`all-in-one-portal`) listens on host ports `0.0.0.0:8080` and `0.0.0.0:8443`. It does not inspect `RemoteAddr` or host cgroups to verify the calling pod's identity or enforce per-pod policies. Any process or pod on the node network capable of reaching host ports can currently connect to the proxy. Caller authentication and per-pod policy enforcement are tracked in [#182](https://github.com/gke-labs/service-portals/issues/182).
* **Per-Pod Certificates (#182 follow-up)**: As noted during review, generating per-pod leaf certificates (encoding pod identity or UID in leaf SANs) would surface if the proxy ever confused one pod for another ("crossed the streams"). A workload would fail TLS validation if served another pod's certificate, exposing cross-pod routing bugs immediately. This will be evaluated as part of the caller identity and TLS termination work in [#182](https://github.com/gke-labs/service-portals/issues/182).
* **IPv6 and Bounded DNS (#183)**: The current rules install only IPv4 iptables rules. IPv6 traffic is unfiltered in the network namespace, and CoreDNS forwarding for unlisted external domains is unrestricted. Enforcing IPv6 parity and bounding DNS queries to policy-listed hostnames are tracked in [#183](https://github.com/gke-labs/service-portals/issues/183).

---

## 6. Environment & Platform Verification

* **Kind Node containerd Version**: Verified on Kind node image `kindest/node:v1.32.2`, which runs **containerd v2.0.2** (`containerd github.com/containerd/containerd/v2 v2.0.2 c507a0257ea6462fbd6f5ba4f5c74facb04021f4`).
* **NRI Enabled by Default**: In containerd 2.0+, NRI is enabled by default (`disable = false` per containerd 2.0 release documentation), and `/var/run/nri/nri.sock` is active without requiring custom containerd configuration patches.
* **GKE Standard Support**: `[unverified]`. GKE Standard nodes running containerd with NRI enabled support user DaemonSets mounting `/var/run/nri/nri.sock` with `NET_ADMIN` and `SYS_ADMIN` capabilities.
* **GKE Autopilot Support**: Incompatible (cited per official GKE Autopilot security posture). Autopilot does not permit DaemonSets with `CAP_SYS_ADMIN`, host network namespaces, or hostPath mounts to `/var/run/nri/nri.sock`. Autopilot workloads require alternative interception models (e.g. webhook injection).

---

## 7. E2E Test Execution Output

The following test results were captured directly from a complete run of `TestNRIPluginEgressDenied` against a live kind cluster running containerd v2.0.2:

```
=== RUN   TestNRIPluginEgressDenied
    e2e_test.go:1027: Creating cluster nri-egress-denied-e2e
    e2e_test.go:1027: Waiting for CoreDNS deployment rollout
    e2e_test.go:1027: Waiting for kube-dns service endpoints
    e2e_test.go:1027: kube-dns endpoint slice ready: 10.244.0.2 10.244.0.3
    e2e_test.go:1032: Building docker image all-in-one-portal:e2e
    e2e_test.go:1033: Building docker image init-service-portals:e2e
    e2e_test.go:1034: Building docker image portal-nri-plugin:e2e
    e2e_test.go:1035: Building docker image toolbox:e2e
    e2e_test.go:1037: Loading image all-in-one-portal:e2e into kind
    e2e_test.go:1038: Loading image init-service-portals:e2e into kind
    e2e_test.go:1039: Loading image portal-nri-plugin:e2e into kind
    e2e_test.go:1040: Loading image toolbox:e2e into kind
    e2e_test.go:1095: Applying manifest content
    e2e_test.go:1096: Waiting for deployment backend
    e2e_test.go:1100: Backend ClusterIP: 10.96.10.242
    e2e_test.go:1250: Applying manifest content
    e2e_test.go:1262: Client pod is correctly Pending due to node taint: Pending
    e2e_test.go:1265: Applying manifest content
    e2e_test.go:1266: Waiting for pod with label app=portal-node-agent to be ready
    e2e_test.go:1275: Waiting for pod with label app=test-client-nri-deny to be ready
=== RUN   TestNRIPluginEgressDenied/DirectIP_InterceptedPort_HTTP
    e2e_test.go:811: direct IP HTTP request failed as expected: exit status 8 (output: command terminated with exit code 8
        )
=== RUN   TestNRIPluginEgressDenied/DirectIP_InterceptedPort_HTTPS
    e2e_test.go:826: direct IP HTTPS request failed as expected: exit status 4 (output: command terminated with exit code 4
        )
=== RUN   TestNRIPluginEgressDenied/UnlistedHostname_InterceptedPort_HTTP
    e2e_test.go:842: unlisted host HTTP request failed as expected: exit status 8 (output: command terminated with exit code 8
        )
=== RUN   TestNRIPluginEgressDenied/UnlistedHostname_InterceptedPort_HTTPS
    e2e_test.go:857: unlisted host HTTPS request failed as expected: exit status 4 (output: command terminated with exit code 4
        )
=== RUN   TestNRIPluginEgressDenied/NonInterceptedPort_HTTP_8080
    e2e_test.go:873: non-intercepted port HTTP request failed as expected: exit status 4 (output: command terminated with exit code 4
        )
=== RUN   TestNRIPluginEgressDenied/NonInterceptedPort_RawTCP_9999
    e2e_test.go:888: raw TCP connection to port 9999 failed as expected: exit status 1 (output: 2026/11/03 22:27:13 tcp dial to 10.96.10.242:9999 failed: dial tcp 10.96.10.242:9999: connect: connection refused
        command terminated with exit code 1
        )
=== RUN   TestNRIPluginEgressDenied/ArbitraryDNS_Blocked
    e2e_test.go:900: toolbox probe dns to 8.8.8.8 failed as expected: exit status 1 (output: 2026/11/03 22:27:13 dns lookup of example.com via 8.8.8.8:53 failed: lookup example.com on 10.96.0.10:53: write udp 10.244.0.6:58495->8.8.8.8:53: write: operation not permitted
        command terminated with exit code 1
        )
    e2e_test.go:909: nslookup to 8.8.8.8 failed as expected: exit status 1 (output: ;; communications error to 8.8.8.8#53: connection refused
        ;; communications error to 8.8.8.8#53: connection refused
        ;; communications error to 8.8.8.8#53: connection refused
        ;; no servers could be reached
        
        command terminated with exit code 1
        )
=== RUN   TestNRIPluginEgressDenied/ClusterDNS_Allowed
    e2e_test.go:921: cluster DNS probe succeeded: RESOLVED backend: [10.96.10.242]
    e2e_test.go:931: cluster nslookup succeeded: ;; Got recursion not available from 10.96.0.10
        Server:		10.96.0.10
        Address:	10.96.0.10#53
        
        Name:	backend.default.svc.cluster.local
        Address: 10.96.10.242
        ;; Got recursion not available from 10.96.0.10
        
=== RUN   TestNRIPluginEgressDenied/PositiveControl_HTTP
    e2e_test.go:943: positive control HTTP output: {"body":"","headers":{"Accept":["*/*"],"Accept-Encoding":["identity"],"Authorization":["Bearer gemini-nri-token"],"User-Agent":["Wget/1.21.3"]},"method":"GET","path":"/positive-control-http"}
=== RUN   TestNRIPluginEgressDenied/PositiveControl_HTTPS
    e2e_test.go:966: positive control output: {"body":"","headers":{"Accept":["*/*"],"Accept-Encoding":["identity"],"Authorization":["Bearer gemini-nri-token"],"User-Agent":["Wget/1.21.3"]},"method":"GET","path":"/positive-control"}
=== RUN   TestNRIPluginEgressDenied/BypassAttempt_Disallowed
    e2e_test.go:1005: workload NoNewPrivs status: NoNewPrivs:	1
    e2e_test.go:1017: su to UID 1337 failed as expected: exit status 1 (output: su: user 1337 does not exist or the user entry does not contain all the required fields
        command terminated with exit code 1
        )
=== NAME  TestNRIPluginEgressDenied
    harness.go:55: Deleting cluster nri-egress-denied-e2e
--- PASS: TestNRIPluginEgressDenied (121.98s)
    --- PASS: TestNRIPluginEgressDenied/DirectIP_InterceptedPort_HTTP (0.14s)
    --- PASS: TestNRIPluginEgressDenied/DirectIP_InterceptedPort_HTTPS (0.14s)
    --- PASS: TestNRIPluginEgressDenied/UnlistedHostname_InterceptedPort_HTTP (0.13s)
    --- PASS: TestNRIPluginEgressDenied/UnlistedHostname_InterceptedPort_HTTPS (0.15s)
    --- PASS: TestNRIPluginEgressDenied/NonInterceptedPort_HTTP_8080 (1.15s)
    --- PASS: TestNRIPluginEgressDenied/NonInterceptedPort_RawTCP_9999 (0.08s)
    --- PASS: TestNRIPluginEgressDenied/ArbitraryDNS_Blocked (0.18s)
    --- PASS: TestNRIPluginEgressDenied/ClusterDNS_Allowed (0.18s)
    --- PASS: TestNRIPluginEgressDenied/PositiveControl_HTTP (0.14s)
    --- PASS: TestNRIPluginEgressDenied/PositiveControl_HTTPS (0.25s)
    --- PASS: TestNRIPluginEgressDenied/BypassAttempt_Disallowed (0.23s)
PASS
ok  	github.com/gke-labs/service-portals/tests/e2e	121.984s
```
