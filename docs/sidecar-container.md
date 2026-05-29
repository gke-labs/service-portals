# Service Portal - Sidecar Container Configuration

This document describes how to deploy the **All-In-One Service Portal** as a sidecar container inside a Kubernetes pod. This deployment pattern centralizes authentication and credentials management without exposing API keys or tokens to the application (workload) container, and without requiring code changes to the application.

---

## Architecture Overview

In a sidecar deployment model, the workload container and the Service Portal proxy run within the same Kubernetes Pod, sharing the same network namespace and loopback interface.

An `initContainer` is used to configure `iptables` NAT rules before the main containers start. These rules transparently intercept outbound TCP traffic on designated ports (e.g., `80` and `443`) and redirect them to the local proxy port (`8080`).

```
+------------------------------------------------------------------------+
|                               POD                                      |
|                                                                        |
|  +--------------------+                      +----------------------+  |
|  | Workload Container |                      |   Sidecar Container  |  |
|  |                    |                      | (all-in-one-portal)  |  |
|  | Makes HTTP request |                      |                      |  |
|  | to external host   |                      | Listens on :8080     |  |
|  +---------+----------+                      +----------+-----------+  |
|            |                                            ^              |
|            v                                            |              |
|   [ Outbound TCP Port 80/443 ]                          |              |
|            |                                            |              |
|            +--------- (Redirected via iptables) --------+              |
|                                                                        |
+------------------------------------------------------------------------+
```

---

## Setup and Configuration

### 1. Transparent Redirection via `iptables` (`initContainer`)

The `init-iptables` container is a minimal container running as `root` with `NET_ADMIN` privileges. It executes a shell script that sets up the following `iptables` rules:

1. Creates a custom chain `PORTAL_OUTPUT`.
2. Jumps to `PORTAL_OUTPUT` from the `OUTPUT` chain.
3. Excludes loopback (`lo`) interface traffic.
4. Excludes traffic originating from the proxy's UID (e.g., `1337`) to prevent infinite redirection loops.
5. Redirects all specified target TCP ports (e.g., `80,443`) to the local proxy port (`8080`).

### 2. Sidecar Proxy Container

The sidecar container runs the `all-in-one-portal`. Crucially, it must run with the security context matching the bypassed `PROXY_UID` (e.g., `1337`).

---

## Comparison: REDIRECT vs TPROXY

During the design phase, we evaluated two primary methods for transparent traffic interception in iptables: `REDIRECT` and `TPROXY`.

| Criteria | `REDIRECT` (Chosen) | `TPROXY` |
| :--- | :--- | :--- |
| **Ease of Setup** | **Very High**: Single `iptables` rule redirects traffic directly to the local port. | **Moderate**: Requires creating custom IP routing tables, rule policies, and firewall marks. |
| **Privileges** | Requires `NET_ADMIN` in `initContainer` only. | Requires `NET_ADMIN` in `initContainer`, and the proxy socket listener may require additional capabilities/privileges depending on binding. |
| **Proxy Code Complexity** | **None**: The proxy application uses standard TCP/HTTP listeners (e.g., `http.ListenAndServe`). | **High**: The proxy listener must use socket-level options like `IP_TRANSPARENT` to accept traffic destined for arbitrary remote IPs. |
| **IP/Port Preservation** | Overwrites the destination IP to `127.0.0.1`. (The proxy relies on the HTTP `Host` header to determine routing). | Preserves the original destination IP at the network layer. |

### Why We Chose `REDIRECT`

Since the Service Portals rely on standard HTTP routing based on the HTTP `Host` header (e.g., `Host: gemini.backend`), we do not need to preserve the remote destination IP at the TCP layer. `REDIRECT` is simpler, more stable, and allows our Go proxy to run without any custom socket-level logic or extra network privileges.

---

## CA Certificate Store Population

When intercepting HTTPS traffic (port `443`), the sidecar proxy acts as a man-in-the-middle to inject credentials, meaning it terminates TLS and re-encrypts requests using a custom CA certificate. 

For the workload container to trust these intercepted TLS connections, it must trust the proxy's CA certificate. The easiest way to distribute this trust without modifying the workload container image is to use a shared `emptyDir` volume to populate the trusted CA certificate store.

### How it Works

1. Define a shared `emptyDir` volume (e.g., `ca-certs-volume`).
2. Mount the volume at the trusted CA certs directory of the workload container (e.g., `/etc/ssl/certs`).
3. In the `initContainer`, copy the system's default bundle of trusted CA certificates into the shared volume, and append the proxy's custom CA certificate to that bundle. This ensures the workload container continues to trust public CA certificates while also trusting the proxy's certificate.

#### Example Configuration Snippet

```yaml
spec:
  volumes:
  - name: shared-ca-certs
    emptyDir: {}
  - name: portal-ca-secret
    secret:
      secretName: service-portal-ca

  initContainers:
  - name: init-certs
    image: debian:bookworm-slim
    command: ["/bin/sh", "-c"]
    args:
    - |
      # Copy system certs to shared volume
      cp -r /etc/ssl/certs/* /shared-certs/
      # Append custom CA certificate
      cat /secret-certs/tls.crt >> /shared-certs/ca-certificates.crt
    volumeMounts:
    - name: shared-ca-certs
      mountPath: /shared-certs
    - name: portal-ca-secret
      mountPath: /secret-certs
      readOnly: true

  containers:
  - name: workload
    image: alpine:latest
    volumeMounts:
    - name: shared-ca-certs
      mountPath: /etc/ssl/certs
```
