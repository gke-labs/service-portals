# Deployment Modes

`service-portals` places an intercepting proxy in the outbound traffic path between your workload and external services to swap placeholder tokens with production credentials and enforce default-deny egress policies.

The **Transparent Sidecar Mode** is the **current recommended deployment mode** and the only quick-start path. All other modes are either legacy architectures scheduled for removal or experimental/in-development paths leading toward the project's single-mode NRI convergence plan (see [Roadmap](roadmap.md)).

---

## Mode Summary & Status

| Mode | Status | Primary Binary / Mechanism | Privilege Requirements | Key Characteristics |
| :--- | :--- | :--- | :--- | :--- |
| **Transparent Sidecar Mode** | **Recommended (Current Default)** | `cmd/all-in-one-portal` + `cmd/init-service-portals` | `CAP_NET_ADMIN` for init container; workload is unprivileged | Zero application code changes; ephemeral pod-local CA; dynamic SNI TLS minting; packet-level default-deny egress filtering. |
| **Explicit Service Mode** | *Legacy* (scheduled for removal) | `cmd/service-portal` or service-specific portals (`gemini-portal`, etc.) | Unprivileged pod | Centralized cluster `Service`; plain HTTP in cluster; shared secret blast radius; no packet-level egress enforcement. |
| **Explicit HTTP Proxy Mode** | *Legacy* (scheduled for removal) | `cmd/service-portal` | Unprivileged pod | Workloads set `HTTP_PROXY`/`HTTPS_PROXY`; single-upstream `CONNECT` tunnel; no `PortalRule` multi-host routing; low bypass resistance. |
| **Application-Level Interception** | *Historical (Not Pursued)* | Injected proxy env + Kubernetes `NetworkPolicy` | Zero privileges (PSA baseline & restricted) | Spiked in #164; not pursued. Zero-privilege proxy env and NetworkPolicy; no separate code path for Autopilot. |
| **Per-Node NRI Mode** | *In Development, Future Default* | containerd NRI plugin DaemonSet (`#198`) | Node-level daemon; zero in-pod privileges | Target: host-side (#181); current prototype uses pod-netns rules. Target single mode; eliminates UID-1337 bypass. |

---

## 1. Transparent Sidecar Mode (Recommended)

In transparent sidecar mode, each application pod runs two helper containers alongside the workload: an `init-service-portals` init container and an `all-in-one-portal` sidecar container.

```
+---------------------------------------------------------------------------------+
|                                     POD                                         |
|                                                                                 |
|  +--------------------+                               +----------------------+  |
|  | Workload Container |                               | Sidecar Proxy        |  |
|  | (UID 1000)         |                               | (UID 1337)           |  |
|  |                    |  Port 80 (HTTP) -> 8080       |                      |  |
|  | Talks to           |------------------------------>| Injects real secrets |  |
|  | gemini.backend     |  Port 443 (HTTPS) -> 8443     | from Secret mount    |  |
|  | (via hostAliases)  |------------------------------>| and proxies upstream |  |
|  +--------------------+                               +----------+-----------+  |
|                                                                  |              |
+------------------------------------------------------------------|--------------+
                                                                   v External API
```

### How it Works
1. **Init Container (`init-service-portals`)**:
   - Runs with `CAP_NET_ADMIN` privileges before application containers start.
   - Generates an ephemeral RSA-2048 Root CA certificate (`tls.crt`) in a shared `ca-cert` volume, and the CA private key (`tls.key`) in a `ca-private` volume chowned to UID `1337`.
   - Installs `iptables` and `ip6tables` rules:
     - Redirects port `80` to local port `8080` (HTTP).
     - Redirects port `443` to local port `8443` (HTTPS).
     - Excludes UID `1337` to avoid redirecting the proxy's own outbound requests.
     - Drops/rejects all other outbound TCP and UDP traffic from the pod (except DNS on port 53).
2. **Workload Container**:
   - Runs as non-root (e.g. UID `1000`) with `allowPrivilegeEscalation: false`.
   - Mounts `ca-cert` read-only to trust the pod-local CA.
   - Resolves fake hostnames (e.g. `gemini.backend`) to arbitrary IPs using pod `hostAliases`.
   - Makes requests without API keys or with dummy tokens.
3. **Sidecar Proxy (`all-in-one-portal`)**:
   - Runs as UID `1337`.
   - Mounts `ca-private` read-only to access the CA private key.
   - Loads `PortalRule` definitions from a mounted Secret volume.
   - Mints per-host TLS certificates dynamically when TLS connections arrive on port `8443`.
   - Injects the real credentials and proxies to the upstream service over public TLS.

### Best Used For
- **Sandboxed untrusted code (agents, CI jobs)** where you must guarantee that credentials cannot be stolen or bypassed, even if the code inside the workload is malicious or compromised.
- See the [Sidecar Deployment Guide](sidecar-container.md) for complete manifests and configuration details.

---

## 2. Other modes (legacy / experimental)

### Explicit Service Mode (Status: Legacy)
*Status: legacy.* In explicit service mode, the proxy is deployed as a cluster-internal Kubernetes Service (via `k8s/manifests.yaml` or single-target binaries like `gemini-portal`, `anthropic-portal`, `github-portal`, or `cmd/service-portal`) that workloads explicitly address (e.g., `http://gemini-portal/v1/...`). While this avoids requiring `CAP_NET_ADMIN` in the workload pod, it lacks packet-level egress enforcement, passes plain HTTP across the cluster network, shares secrets across all consumers of the service, and provides no protection against direct egress bypasses. Explicit Service mode and its dedicated binaries are legacy and scheduled for complete removal once per-node NRI mode meets its acceptance bar (see [Roadmap](roadmap.md)).

### Explicit HTTP Proxy Mode (Status: Legacy)
*Status: legacy.* In explicit HTTP proxy mode, workloads configure standard proxy environment variables (`HTTP_PROXY`, `HTTPS_PROXY`, and `SSL_CERT_FILE`) to route outbound requests through `cmd/service-portal` via `HTTP CONNECT` TLS interception. This mode only supports a single upstream target configured by `TARGET_URL` and `UPSTREAM_AUTH_TOKEN` (requests to other hosts are passed through without modification, and `PortalRule` declarative multi-host routing is not evaluated; see [#127](https://github.com/gke-labs/service-portals/issues/127)), while remaining vulnerable to environment variable tampering or direct bypass if the workload has outbound network access. Explicit `HTTP_PROXY` mode is legacy and scheduled for removal (or retention strictly as an internal implementation mechanism if required by NRI) once NRI meets its acceptance bar (see [Roadmap](roadmap.md)).

### Application-Level Interception Mode (Status: Not Pursued)
*Status: historical (not pursued).* Spiked in [#164](https://github.com/gke-labs/service-portals/pull/164) (with findings recorded in [#214](https://github.com/gke-labs/service-portals/issues/214) / [#215](https://github.com/gke-labs/service-portals/pull/215)), application-level interception evaluated establishing a zero-privilege proxy model by injecting standard proxy environment variables into workload containers, restricting egress with a default-deny Kubernetes `NetworkPolicy`, and passing per-pod `Proxy-Authorization` tokens. The project decided not to pursue a separate application-level code path for platforms lacking NRI (such as GKE Autopilot today); on platforms where NRI is unavailable, `service-portals` is unsupported (see [Roadmap](roadmap.md) and the spike writeup in pending PR #215).

### Per-Node NRI Mode (Status: In Development, Future Default)
*Status: in development, future default.* The target architecture ([#151](https://github.com/gke-labs/service-portals/issues/151), [#181](https://github.com/gke-labs/service-portals/issues/181), [#182](https://github.com/gke-labs/service-portals/issues/182), [#183](https://github.com/gke-labs/service-portals/issues/183), [#198](https://github.com/gke-labs/service-portals/pull/198)) deploys a node-level DaemonSet that registers with containerd via the Node Resource Interface (NRI). While the current prototype in #198 installs rules in the pod network namespace, the #181 target moves redirection and egress filtering to the host side of the `veth`/`tap` network interface to provide 100% invisible pod manifests with zero workload Linux capabilities (PSA `baseline` and `restricted` compliant), eliminate the UID-1337 bypass vulnerability, resolve pod caller identity directly at the node proxy, and guarantee uniform enforcement across standard `runc`, `gVisor`, and `Kata Containers`. Per-node NRI will become the single supported mode of operation once it passes the acceptance bar, after which all other modes will be removed (see [Roadmap](roadmap.md) and [`docs/design/daemonset-mode.md`](design/daemonset-mode.md)).
