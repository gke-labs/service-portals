# Service Portal - Sidecar Container Configuration

This document describes how to deploy the **All-In-One Service Portal** as a transparent sidecar container inside a Kubernetes pod. This deployment pattern centralizes authentication and credential management without exposing API keys or tokens to the application (workload) container, and without requiring code changes to the application.

---

## Architecture Overview

In a sidecar deployment model, the workload container, the `init-service-portals` init container, and the `all-in-one-portal` proxy container run within the same Kubernetes Pod, sharing the same network namespace, loopback interface, and pod-local storage volumes.

The `init-service-portals` container runs prior to the application start. It generates a pod-local Root CA and configures `iptables` rules to transparently intercept outbound TCP traffic:
- Port `80` (HTTP) is redirected to local proxy port `8080`.
- Port `443` (HTTPS) is redirected to local proxy port `8443`.
- Strict egress filtering is applied to reject direct connections to unintercepted ports.

```
+---------------------------------------------------------------------------------+
|                                       POD                                       |
|                                                                                 |
|  +--------------------+                               +----------------------+  |
|  | Workload Container |                               | Sidecar Container    |  |
|  | (runAsUser: 1000)  |                               | (all-in-one-portal)  |  |
|  |                    |                               | (runAsUser: 1337)    |  |
|  | Makes HTTP/HTTPS   |  Port 80 (HTTP) -> :8080      |                      |  |
|  | request to host    |------------------------------>| HTTP Listener (:8080)|  |
|  | (gemini.backend)   |                               |                      |  |
|  |                    |  Port 443 (HTTPS) -> :8443    | HTTPS Listener(:8443)|  |
|  |                    |------------------------------>| Dynamic SNI Cert     |  |
|  +--------------------+                               +----------+-----------+  |
|                                                                  |              |
+------------------------------------------------------------------|--------------+
                                                                   v Outbound TLS
                                                         +--------------------+
                                                         | External API       |
                                                         +--------------------+
```

---

## Complete Kubernetes Manifest (`k8s/sidecar.yaml`)

Below is the complete, production-ready manifest implementing the transparent sidecar pattern:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: all-in-one-portal-sidecar-secret
stringData:
  gemini-rule.yaml: |
    apiVersion: portals.gke.io/v1alpha1
    kind: PortalRule
    metadata:
      name: gemini
    spec:
      host: gemini.backend
      rewriteUrl: https://generativelanguage.googleapis.com
      authToken: gemini-api-key-here
  github-rule.yaml: |
    apiVersion: portals.gke.io/v1alpha1
    kind: PortalRule
    metadata:
      name: github
    spec:
      host: github.backend
      rewriteUrl: https://api.github.com
      authToken: github-token-here
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: workload-with-sidecar
  labels:
    app: workload-with-sidecar
spec:
  replicas: 1
  selector:
    matchLabels:
      app: workload-with-sidecar
  template:
    metadata:
      labels:
        app: workload-with-sidecar
    spec:
      # Use hostAliases to map backend hostnames to dummy IPs so that they resolve
      # in the pod and trigger TCP connection attempts on port 80/443, which are then
      # transparently intercepted by iptables.
      hostAliases:
      - ip: "8.8.8.8" # or any arbitrary IP; iptables will intercept all TCP traffic on target ports
        hostnames:
        - "gemini.backend"
        - "github.backend"

      initContainers:
      # The init container configures the iptables rules and generates the Root CA
      # within the shared pod network/storage namespace. It requires NET_ADMIN capability and root user.
      - name: init-service-portals
        image: init-service-portals:latest
        imagePullPolicy: IfNotPresent
        env:
        - name: PROXY_PORT
          value: "8080"
        - name: PROXY_HTTPS_PORT
          value: "8443"
        - name: PROXY_UID
          value: "1337"
        - name: INTERCEPT_PORTS
          value: "80,443"
        - name: CHOWN_UID
          value: "1337"
        - name: CHOWN_GID
          value: "1337"
        securityContext:
          capabilities:
            add: ["NET_ADMIN"]
          runAsUser: 0
          runAsGroup: 0
          privileged: false
        volumeMounts:
        - name: ca-cert
          mountPath: /etc/service-portal/ca
        - name: ca-key
          mountPath: /etc/service-portal/ca-private

      containers:
      # 1. The Workload Container: representing the actual application that is consuming
      # external services. It has no access to the API tokens, and simply makes
      # standard HTTP requests to `http://gemini.backend` or HTTPS with the local CA cert.
      # NOTE: It is best practice to configure the workload container with a securityContext
      # that prevents it from running as the proxy UID (1337) and prevents privilege escalation
      # (disabling setuid/setgid binaries). This ensures that any process inside the workload
      # container cannot run as UID 1337 and bypass our iptables redirection rules.
      - name: workload
        image: alpine:latest
        securityContext:
          runAsNonRoot: true
          runAsUser: 1000
          allowPrivilegeEscalation: false
        command: ["/bin/sh", "-c"]
        args: ["while true; do sleep 3600; done"]
        volumeMounts:
        - name: ca-cert
          mountPath: /etc/service-portal/ca
          readOnly: true

      # 2. The Sidecar Container: runs the all-in-one-portal proxy.
      # It must run as the specified non-root user (UID 1337) matching PROXY_UID so that
      # its outbound requests are not intercepted and redirected to itself.
      - name: service-portal-sidecar
        image: all-in-one-portal:latest
        imagePullPolicy: IfNotPresent
        securityContext:
          runAsUser: 1337
          runAsGroup: 1337
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
        ports:
        - containerPort: 8080
          name: proxy
        - containerPort: 8443
          name: proxy-https
        env:
        - name: CA_CERT_PATH
          value: "/etc/service-portal/ca-private/tls.crt"
        - name: CA_KEY_PATH
          value: "/etc/service-portal/ca-private/tls.key"
        args: ["--rules-dir=/etc/portals"]
        volumeMounts:
        - name: rules-volume
          mountPath: /etc/portals
          readOnly: true
        - name: ca-key
          mountPath: /etc/service-portal/ca-private
          readOnly: true

      volumes:
      - name: rules-volume
        secret:
          secretName: all-in-one-portal-sidecar-secret
      - name: ca-cert
        emptyDir: {}
      - name: ca-key
        emptyDir: {}
```

---

## Detailed Component Walkthrough

### 1. Ephemeral Pod-Local CA Generation
When the pod starts:
1. `init-service-portals` executes `/usr/local/bin/init-service-portals`.
2. It generates a self-signed 2048-bit RSA Root Certificate Authority valid for 10 years.
3. The public certificate (`tls.crt`) is saved in `/etc/service-portal/ca` (`ca-cert` volume).
4. The private key (`tls.key`) and certificate are saved in `/etc/service-portal/ca-private` (`ca-key` volume) with file permissions `0600` and ownership changed to UID/GID `1337` (`CHOWN_UID` and `CHOWN_GID`).
5. The `ca-key` volume is mounted **only into the sidecar proxy container**, completely inaccessible to the workload.

### 2. DNS Resolution via `hostAliases`
When workloads make requests to fake hostnames such as `http://gemini.backend` or `https://github.backend`, standard DNS resolution inside Kubernetes would fail because these domains are not registered with CoreDNS.

Using Kubernetes `spec.hostAliases`:
```yaml
hostAliases:
- ip: "8.8.8.8"
  hostnames:
  - "gemini.backend"
  - "github.backend"
```
Kubernetes injects these entries into `/etc/hosts` in the pod. When the workload initiates a TCP connection to `gemini.backend:80` or `gemini.backend:443`, the kernel attempts to connect to `8.8.8.8`, which is instantly intercepted and redirected by `iptables`.

### 3. Transparent Redirection & Egress Filtering (`iptables`)
The `init-service-portals` container sets up the following rules (mirrored in `ip6tables` for dual-stack IPv6). Rules are applied via atomic full-table replaces (`iptables-restore` and `ip6tables-restore`) using dedicated custom chains `PORTAL_OUTPUT` and `PORTAL_EGRESS`. This guarantees idempotency across container restarts, but also means any pre-existing `nat` or `filter` rules configured in the pod's network namespace by another component are replaced.

#### Traffic Redirection (`nat` Table)
1. Creates dedicated chain `PORTAL_OUTPUT` attached to `OUTPUT` for TCP.
2. Excludes loopback (`-o lo -j RETURN`).
3. Excludes proxy UID `1337` (`-m owner --uid-owner 1337 -j RETURN`) to prevent infinite redirection loops.
4. Redirects TCP destination port `443` to `8443` (`PROXY_HTTPS_PORT`).
5. Redirects other specified TCP destination ports (e.g. `80`) to `8080` (`PROXY_PORT`).

#### Bypass Prevention (`filter` Table)
1. Creates dedicated chain `PORTAL_EGRESS` attached to `OUTPUT`.
2. Allows loopback traffic (`-o lo -j ACCEPT`).
3. Allows traffic to localhost (`127.0.0.1` and `::1`).
4. Allows established and related connections (`-m conntrack --ctstate ESTABLISHED,RELATED`).
5. Allows all outbound traffic from proxy UID `1337`.
6. Allows essential kernel-generated control messages:
   - IPv4: destination-unreachable (3), time-exceeded (11), echo-reply (0).
   - IPv6: error messages (1-4) and Neighbor Discovery (133-137: RS, RA, NS, NA, redirect).
7. Blocks cloud metadata server IP ranges (IPv4 `169.254.0.0/16`, AWS IMDS `fd00:ec2::254/128`, GCE metadata `fd20:ce::254/128`) and IPv6 link-local destinations (`fe80::/10`, covering Azure WireServer at `fe80::1234:5678:9abc`) by default *after* Neighbor Discovery and *before* any allowlist rules (opt-in via `ALLOW_METADATA=true`).
8. Restricts DNS lookups on port 53 (UDP and TCP) to designated DNS server IPs (`DNS_SERVER_IPS`, defaults to nameservers in `/etc/resolv.conf`).
9. Allows direct egress to configured CIDRs (`ALLOW_CIDRS`) and extra TCP ports (`ALLOW_PORTS`).
10. Rejects outbound ping requests (`echo-request`) from the workload while allowing loopback and proxy UID traffic.
11. **Rejects all other outbound TCP and UDP traffic** (configurable via `EGRESS_ACTION=REJECT|DROP`, default `REJECT` with ICMP port unreachable).
12. Fail-closed IPv6: If IPv6 is disabled in the netns (`/proc/sys/net/ipv6/conf/all/disable_ipv6=1`), IPv6 rules are skipped with an info log. Otherwise, failure to restore `ip6tables` rules is fatal (`exit 1`) unless opted out with `ALLOW_UNFILTERED_IPV6=true`.
13. Dumps the effective ruleset (`iptables-save`, `ip6tables-save`) to pod logs on startup.

### 4. Sidecar Proxy Container (`all-in-one-portal`)
The proxy container runs as UID `1337` and listens on:
- **Port 8080 (HTTP)**: Handles cleartext HTTP traffic redirected from port 80.
- **Port 8443 (HTTPS)**: Uses the CA private key in `/etc/service-portal/ca-private/tls.key` and certificate in `/etc/service-portal/ca-private/tls.crt` to dynamically sign TLS certificates for the requested SNI hostname.

The proxy monitors the `--rules-dir` directory for `PortalRule` YAML files and reloads configuration dynamically on `SIGHUP`.

### 5. Workload Security Hardening
To prevent a workload process from bypassing the iptables redirection:
- **Do not run as UID 1337**: Configure `runAsUser: 1000` (or another unprivileged UID) and `runAsNonRoot: true`.
- **Disable Privilege Escalation**: Set `allowPrivilegeEscalation: false`. This blocks `setuid` binaries (such as `sudo` or setuid helpers) from changing the process UID to `1337`.

---

## Workload CA Trust Configuration

For HTTPS requests, the workload container must trust the pod-local CA certificate mounted at `/etc/service-portal/ca/tls.crt`.

Depending on your application stack:

### Command-line Tools (`curl`, `wget`)
```bash
# curl
curl --cacert /etc/service-portal/ca/tls.crt https://gemini.backend/v1/models

# wget
wget --ca-certificate=/etc/service-portal/ca/tls.crt -qO- https://gemini.backend/v1/models
```

### Environment Variables
Most modern HTTP client libraries respect standard environment variables:
```bash
export SSL_CERT_FILE=/etc/service-portal/ca/tls.crt
export REQUESTS_CA_BUNDLE=/etc/service-portal/ca/tls.crt
export NODE_EXTRA_CA_CERTS=/etc/service-portal/ca/tls.crt
```

### System CA Store (Linux Distributions)
If the workload container runs as root during a custom entrypoint (or if using an entrypoint script before dropping privileges), the CA can be added to the system bundle:
```bash
# Debian / Ubuntu
cp /etc/service-portal/ca/tls.crt /usr/local/share/ca-certificates/portal-ca.crt
update-ca-certificates

# Alpine
cp /etc/service-portal/ca/tls.crt /usr/local/share/ca-certificates/portal-ca.crt
update-ca-certificates
```

Alternatively, mount the `ca-cert` volume directly to the system certificate location or bundle if your workload image supports it.
