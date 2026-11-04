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
* **gVisor (`runsc`)**:
  - Userspace netstack injects packets via raw packet socket onto the container interface.
  - Architectural reasoning: because netfilter hooks are situated on the host-side veth peer, netstack frames arrive in the host namespace before routing, where host-side PREROUTING/INPUT/FORWARD rules intercept them.
  - Verification status: Verified in PR [#229](https://github.com/gke-labs/service-portals/pull/229) via the `ap-e2e-gvisor` presubmit job on kind with `runsc` and `containerd-shim-runsc-v1` ([green CI run 41853971474](https://github.com/gke-labs/service-portals/actions/runs/41853971474)).
  - Observations:
    - Host-side iptables rules successfully intercept and enforce default-deny across all 11 assertions in `TestNRIPluginEgressDenied` (direct-IP HTTP/HTTPS blocked, unlisted hostname HTTP/HTTPS blocked, non-intercepted port 8080 and raw TCP 9999 blocked, arbitrary DNS 8.8.8.8 blocked, cluster DNS allowed, and positive control HTTP and HTTPS proxy interception with token injection verified).
    - Vacuity verification: disabling host-side rule installation in the plugin causes the deny suite under gVisor to fail ([red CI run 41858581883](https://github.com/gke-labs/service-portals/actions/runs/41858581883), executed on the pre-#228 tree with rule installation disabled), where egress to non-intercepted ports, direct IPs, unlisted hostnames, and arbitrary DNS all leaked through and positive controls failed due to missing token injection, confirming that enforcement is non-vacuous and strictly provided by the host-side rules.
* **Kata Containers (`kata`) `[unverified]`**:
  - Pod runs inside a microVM guest kernel; traffic egresses over virtio-net to the host-side tap device.
  - Architectural reasoning: host-side iptables inspects incoming packets on the host tap interface. Guest kernel or container processes have no access to the host's iptables rules.
  - Verification status: `[unverified]`. Not yet verified in CI or against a live cluster.

### Verification Status & Open Follow-Up
* **runc (kind)**: Fully verified in PR [#223](https://github.com/gke-labs/service-portals/pull/223). `TestNRIPluginEgressDenied` passes with host-side rules on kind (containerd v2.0.2).
* **gVisor (kind)**: Fully verified in PR [#229](https://github.com/gke-labs/service-portals/pull/229), CI run [41853971474](https://github.com/gke-labs/service-portals/actions/runs/41853971474) via dedicated CI job (`ap-e2e-gvisor`). The deny suite passes under `runtimeClassName: gvisor`, and fails as expected if host-side rules are removed ([red CI run 41858581883](https://github.com/gke-labs/service-portals/actions/runs/41858581883), pre-#228 tree).
* **Kata microVMs**: Open (`[unverified]`). Host-side enforcement for microVM runtimes is designed and implemented based on netfilter hook positioning on host veth/tap interfaces, but live verification requires a Kata-capable virtualization environment.

---

## 5. Security & Authentication Boundaries

* **Proxy Caller Identity & Per-Pod Policy (#182)**:
  * **Pod Map Lifecycle**: `portal-nri-plugin` maintains an in-memory pod map indexed by Pod UID and IP addresses through `RunPodSandbox`, `StopPodSandbox`, and `Synchronize`. It exposes this state to the proxy on the same node via an internal Admin API (`127.0.0.1:8081`).
  * **Loopback Admin Restriction**: The Admin and Bind API binds strictly to `127.0.0.1:8081` (or a private Unix domain socket) and refuses non-loopback addresses (`validateAdminAddr`). Because the node agent operates with `hostNetwork: true`, binding to `0.0.0.0` or an external node IP would expose pod registration and policy binding to any unintercepted pod or external host, creating an unauthenticated privilege escalation vulnerability. Bind operations are called locally on the node or driven via authenticated cluster mechanisms (e.g. `kubectl exec`).
  * **Caller Resolution & Fail-Closed Enforcement**: On each incoming HTTP request (`:8080`) and TLS ClientHello (`:8443`), the proxy extracts the client IP from `RemoteAddr` (or `net.Conn.RemoteAddr()`). If the caller is unknown or not an opted-in pod, the proxy denies the request immediately with HTTP 403 Forbidden (or aborts the TLS handshake).
  * **Per-Pod Policy Enforcement**: The proxy evaluates the pod's assigned policy against the target rule and host. An opted-in pod connecting directly or via transparent interception with a host/SNI it is not entitled to is denied with HTTP 403 Forbidden and receives no credential.
  * **Pod Attribution & Logging**: Proxy logs carry caller pod attribution (`Caller: <namespace>/<name> (identity: <id>)`). To prevent leaking internal cluster pod identity to external public upstreams, upstream requests carry attribution headers (`X-Consumer-Identity` and `X-Forwarded-Client-Pod`) only when a `PortalRule` explicitly opts in via `attributionHeaders: true`.
  * **Proxy Address Binding**: The proxy binds to `${PROXY_HOST}:${PORT}` (the node's pod-facing address) rather than `0.0.0.0` where the CNI makes that possible. On CNIs where the node IP faces both cluster traffic and the pod network (such as kindnet), caller IP authentication at the proxy provides the security boundary against non-opted-in callers.

* **Dynamic Bind API for Warm Pools**:
  * In warm-pool architectures (such as agent-sandbox prelaunched pools), sandboxes are created before the tenant or user identity is known.
  * The node agent exposes an explicit **Bind API** (`POST /bind` and `POST /unbind`). A coordinator (e.g. sandbox claim controller) calls `Bind(pod UID, identity, policy)` immediately before issuing commands in the sandbox, and `Unbind(pod UID)` upon sandbox release.
  * Unbound opted-in pods fail closed by default: they get only deny rules and receive no credentials.
  * Rebinding a warm pod requires no pod mutation, eliminating the need to propagate tenant identities through mutable pod specs. NRI pod synchronization (`Synchronize`) and background reconciliation serve as the fallback to recover state after agent restarts and prune disappeared pods.

* **Spoofing Analysis: `CAP_NET_RAW` and Host-Side Pod Map Trustworthiness**:
  * **What `CAP_NET_RAW` Permits**: Under Kubernetes Pod Security Standards (PSS) Baseline profile, containers retain `CAP_NET_RAW`. A compromised workload or untrusted tenant code can open `SOCK_RAW` / `AF_PACKET` sockets, craft arbitrary Ethernet/IP packets with forged Source IP addresses, and send raw ICMP frames.
  * **Why the Host-Side Pod Map is Trustworthy**:
    1. *TCP 3-Way Handshake Protection*: The service-portal operates as an L7 HTTP/HTTPS reverse proxy over TCP. Initiating an HTTP request or TLS handshake strictly requires completing the TCP three-way handshake (SYN -> SYN-ACK -> ACK). If Pod A emits a TCP SYN forging the Source IP of Pod B (`10.244.0.10`):
       * The proxy responds with a TCP SYN-ACK packet addressed to `10.244.0.10`.
       * The host Linux kernel and CNI bridge route the SYN-ACK to Pod B's veth interface.
       * Pod A never receives the SYN-ACK and cannot determine the TCP sequence numbers.
       * Pod B receives an unexpected SYN-ACK for a connection it never initiated; its kernel immediately responds with a TCP RST (reset) packet back to the proxy, tearing down the embryonic connection.
       * Pod A cannot complete the TCP handshake, cannot establish a stream, and cannot transmit HTTP headers or obtain swapped credentials.
    2. *Host-Side Veth / Tap Isolation*: Each pod is attached to a dedicated host-side peer interface (`veth*` or `tap*`). Host-side reverse path filtering (`rp_filter`) and CNI ingress filters prevent packets with forged source IPs from being delivered to the host stack.
    3. *Host Cgroup Tracking*: Because the proxy runs on the host, future eBPF `sock_ops` integration can correlate accepted sockets directly to the kernel cgroup ID on the host.

* **Per-Pod Certificates (#182 follow-up)**: As noted during review, generating per-pod leaf certificates (encoding pod identity or UID in leaf SANs) would surface if the proxy ever confused one pod for another ("crossed the streams"). A workload would fail TLS validation if served another pod's certificate, exposing cross-pod routing bugs immediately. This will be evaluated as part of the caller identity and TLS termination work in [#182](https://github.com/gke-labs/service-portals/issues/182).
* **IPv6 Rules and Bounded DNS (#183)**:
  - *Dual-Stack IPv6 Egress Parity*: Dual-stack is detected from sandbox pod IP addresses. `portal-nri-plugin` installs the same host-side per-interface chains (`PORTAL_PR_<iface>` in nat PREROUTING, `PORTAL_EG_<iface>` in filter INPUT/FORWARD) via `ip6tables`. TCP ports 80 and 443 are DNAT'd to `[PROXY_HOST_V6]:PORT`, port 53 (UDP & TCP) is DNAT'd to `[PROXY_HOST_V6]:53`, ICMPv6 Neighbor Discovery (NDP types 133-137) and error messages (types 1-4) are accepted for link-local reachability and PMTU, and all other IPv6 egress is rejected with `icmp6-port-unreachable`.
  - *Bounded DNS Architecture (Option b)*: Port 53 (UDP & TCP) on the host peer interface is redirected via DNAT to the node proxy's DNS server (`pkg/dns`). The server responds with synthetic A records pointing to `PROXY_HOST` and AAAA records pointing to `PROXY_HOST_V6` for configured `PortalRule` hosts. All unlisted names return `NXDOMAIN` by default. Hard-coded resolver fallbacks (`10.96.0.10`) are removed. CoreDNS is completely inaccessible to opted-in pods, closing the DNS exfiltration side channel.
  - *Design Limits*:
    1. *No Arbitrary External or In-Cluster Resolution*: Workloads cannot resolve unlisted domains or unlisted in-cluster Service names. Any endpoint the workload must reach must be declared in a `PortalRule`.
    2. *CNAME Chaining*: The bounded DNS server synthesizes A/AAAA records directly for matched names without resolving upstream CNAME chains. Upstream resolution is performed exclusively by the L7 proxy.
    3. *Workload DNS Search Domains*: Pod `/etc/resolv.conf` search path expansions (e.g. `backend.default.svc.cluster.local`) are matched against declared rule hosts by prefix to avoid resolution failures under `ndots:5`.

---

## 6. Environment & Platform Verification

* **Kind Node containerd Version**: Verified on Kind node image `kindest/node:v1.32.2`, which runs **containerd v2.0.2** (`containerd github.com/containerd/containerd/v2 v2.0.2 c507a0257ea6462fbd6f5ba4f5c74facb04021f4`).
* **NRI Enabled by Default**: In containerd 2.0+, NRI is enabled by default (`disable = false` per containerd 2.0 release documentation), and `/var/run/nri/nri.sock` is active without requiring custom containerd configuration patches.
* **GKE Standard Support**: `[unverified]`. GKE Standard nodes running containerd with NRI enabled support user DaemonSets mounting `/var/run/nri/nri.sock` with `NET_ADMIN` and `SYS_ADMIN` capabilities.
* **GKE Autopilot Support**: Incompatible (cited per official GKE Autopilot security posture). Autopilot does not permit DaemonSets with `CAP_SYS_ADMIN`, host network namespaces, or hostPath mounts to `/var/run/nri/nri.sock`. Autopilot workloads require alternative interception models (e.g. webhook injection).

---

## 7. E2E Test Coverage

The end-to-end test suite (`TestNRIPluginEgressDenied` in `tests/e2e/e2e_test.go`) verifies the complete set of interception and security behaviors against a live kind cluster running containerd v2.0.2:
- **Node Initialization Taint**: Opted-in pods remain `Pending` until the `portal-node-agent` DaemonSet is ready and removes the node initialization taint.
- **Fail-Closed Unbound State**: Opted-in pods start unbound and fail closed by default, rejecting outbound requests until explicitly bound.
- **Dynamic Bind API**: The node agent Bind API binds the pod UID to user identity and policy over the local Unix domain socket (`portal-nri-plugin bind`), enabling subsequent requests to receive swapped credentials.
- **Attribution & Logging**: Proxy logs carry caller pod identity (`Caller: <namespace>/<name>`), and upstream requests preserve confidentiality by omitting attribution headers unless explicitly opted in via `attributionHeaders: true`.
- **Direct-to-Proxy Denials**: Opted-in pods connecting directly to the proxy port with unentitled hostnames receive a 403, and non-opted-in pods on the node connecting directly to the proxy port receive a 403.
- **Unbind Reversion**: Unbinding the pod UID (`portal-nri-plugin unbind`) immediately reverts subsequent requests to denied (403).
- **Network Egress Isolation**: Direct IP requests, unlisted hostnames, non-intercepted ports, raw TCP, and arbitrary external DNS queries to public resolvers are strictly blocked, while cluster DNS queries to CoreDNS continue to resolve normally.
