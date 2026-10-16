# Architecture & Security Model

`service-portals` is a credential-swapping, layer-7 intercepting proxy designed to secure untrusted and semi-trusted workloads (such as AI agents, CI/CD runners, and code-execution sandboxes).

Instead of distributing real API keys, tokens, or credentials into sandbox containers, `service-portals` keeps real credentials strictly outside the sandbox. Outbound traffic is intercepted, decrypted, and modified to inject upstream authentication headers before forwarding requests to target APIs.

The foundational design philosophy is simple: **Tokens that aren't there can't leak.**

---

## Threat Model & Sandbox Isolation

### The Problem
Modern workloads increasingly run semi-trusted or untrusted code:
- **Autonomous AI Agents**: Executing LLM-generated code or multi-step tool calls.
- **CI/CD Build Pipelines**: Executing arbitrary build scripts and tests from untrusted contributors.
- **Code Execution Sandboxes**: Running user-submitted code in evaluation or playground environments.

These workloads frequently require access to external services—such as LLM APIs (Gemini, Anthropic), source control (GitHub), or cloud infrastructure (GCP/AWS).

If real credentials (e.g., `GITHUB_TOKEN`, `GEMINI_API_KEY`, or cloud IAM bearer tokens) reside inside the sandbox container—in environment variables, on disk, or in memory—they are vulnerable to exfiltration via:
1. **Prompt Injection**: An agent is coerced into revealing environment variables or file contents.
2. **Malicious Dependencies**: A rogue package in `npm`, `pip`, or `cargo` harvests environment secrets and phones home.
3. **Application Bugs & Logging**: Accidental dumping of configuration state, request dumps, or stack traces containing authorization headers into logs.
4. **SSRF & Direct Exfiltration**: Code making unauthorized outbound network calls to send stolen tokens to attacker-controlled endpoints.

### The Solution: Credential Swapping
With `service-portals`, the sandbox container never holds or receives the real credentials. The workload either sends a dummy placeholder token (e.g., `Authorization: Bearer placeholder`) or no credentials at all.

All outbound traffic is redirected through the portal proxy. The proxy terminates TLS, inspects the request, matches it against routing rules, strips any placeholder credentials, injects the real credentials, and sends the request to the real upstream service.

```
+-----------------------------------------------------------------------------------+
|                                  SANDBOX POD                                      |
|                                                                                   |
|  +--------------------+                               +------------------------+  |
|  | Workload Container |                               | Sidecar Proxy          |  |
|  | (Untrusted sandbox)|                               | (all-in-one-portal)    |  |
|  |                    |                               |                        |  |
|  | Holds NO secrets.  |  HTTP/HTTPS                   | Holds REAL secrets in  |  |
|  | Sends placeholder  |  (Intercepted via iptables)   | private volume mount.  |  |
|  | token or no token. |------------------------------>| Injects real token,    |  |
|  +--------------------+                               | rewrites host & path.  |  |
|                                                       +-----------+------------+  |
+-------------------------------------------------------------------|---------------+
                                                                    | Real TLS with
                                                                    | real credential
                                                                    v
                                                        +------------------------+
                                                        | Upstream Service       |
                                                        | (GitHub, Gemini, etc.) |
                                                        +------------------------+
```

---

## Trust Model & Interception ("MITM for Good")

To inspect and modify HTTPS traffic, `service-portals` operates as an intercepting proxy (man-in-the-middle). This interception is deliberate and strictly confined to the pod's private network namespace for the workload's protection.

### 1. Ephemeral, Pod-Local Root CA
Each pod generates its own dedicated Root Certificate Authority (CA) during pod initialization:
- The `init-service-portals` init container runs `init-service-portals` to generate a fresh 2048-bit RSA key pair and self-signed X.509 CA certificate valid for that pod.
- **No cluster-wide private key**: Every pod has its own unique CA. Compromising one pod does not compromise the TLS trust of any other pod.

### 2. Strict Privilege Separation
The pod uses two distinct volume mounts to isolate CA keys:
- **`ca-cert` (`emptyDir`)**: Contains only the public certificate (`tls.crt`). This volume is mounted **read-only into the workload container**. The workload container adds this certificate to its trust store (or passes it to client libraries).
- **`ca-private` (`emptyDir`)**: Contains both the private key (`tls.key`) and the certificate (`tls.crt`). The init container runs `chown 1337:1337` on this directory and sets `0600` permissions on `tls.key`. This volume is mounted **only into the proxy container**, which runs as UID `1337`.

The workload container cannot access `ca-private` and has no access to the CA's private key.

### 3. Workload User Isolation
To ensure traffic cannot bypass the proxy, the workload container must never be allowed to run as the proxy's UID:
- The proxy container runs as UID `1337` (`PROXY_UID`).
- The workload container is configured with:
  ```yaml
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000 # Any UID other than 1337
    allowPrivilegeEscalation: false
  ```
- Setting `allowPrivilegeEscalation: false` prevents any process in the workload container from executing `setuid` binaries or escalating privileges to UID `1337`.

---

## Interception Mechanics

### 1. NAT Redirection (`iptables`)
The `init-service-portals` container runs with `CAP_NET_ADMIN` privileges to configure `iptables` and `ip6tables` rules inside the shared pod network namespace before the application starts. Rules are applied via an atomic full-table replace (`iptables-restore` and `ip6tables-restore`), guaranteeing idempotency across container restarts while replacing any pre-existing `nat` or `filter` rules in the pod network namespace:
- Creates a dedicated NAT chain `PORTAL_OUTPUT`.
- Traffic on the loopback interface (`-o lo`) is untouched.
- Traffic originating from `PROXY_UID` (`1337`) is excluded (`-m owner --uid-owner 1337 -j RETURN`) to prevent infinite redirection loops when the proxy establishes outbound connections.
- Outbound TCP traffic destined for port `80` is redirected to local port `8080` (`PROXY_PORT`).
- Outbound TCP traffic destined for port `443` is redirected to local port `8443` (`PROXY_HTTPS_PORT`).

### 2. Strict Egress Filtering
To prevent malicious or compromised code in the workload from bypassing the proxy (for example, by directly connecting to an external server on port `8080` or `22`), `init-service-portals` configures strict egress filtering in a dedicated `PORTAL_EGRESS` chain in the `filter` table:
1. Allows loopback traffic (`-o lo -j ACCEPT`).
2. Allows traffic to localhost (`127.0.0.1` and `::1`).
3. Allows established and related connections (`-m conntrack --ctstate ESTABLISHED,RELATED`).
4. Allows all outbound traffic from `PROXY_UID` (`1337`).
5. Allows essential kernel-generated ICMP/ICMPv6 control messages:
   - IPv4: destination-unreachable (3), time-exceeded (11), echo-reply (0).
   - IPv6: error messages (1-4) and Neighbor Discovery (133-137: RS, RA, NS, NA, redirect).
6. Blocks cloud metadata server IP ranges (IPv4 `169.254.0.0/16`, AWS IMDS `fd00:ec2::254/128`, GCE metadata `fd20:ce::254/128`) and IPv6 link-local destinations (`fe80::/10`, covering Azure WireServer at `fe80::1234:5678:9abc`) by default *after* Neighbor Discovery and *before* any allowlist rules (opt-in via `ALLOW_METADATA=true`).
7. Restricts DNS resolution queries on port 53 (UDP and TCP) to designated DNS servers (`DNS_SERVER_IPS`, defaulting to nameservers discovered in `/etc/resolv.conf`).
8. Allows direct egress to configured CIDRs (`ALLOW_CIDRS`) and extra TCP ports (`ALLOW_PORTS`).
9. Rejects outbound ping requests (`echo-request`) from the workload to prevent ICMP tunneling.
10. **Rejects all other outbound TCP and UDP traffic** (configurable via `EGRESS_ACTION=REJECT|DROP`, default `REJECT` with ICMP port unreachable).
11. Mirrors all rules in `ip6tables` with fail-closed behavior (unless IPv6 is disabled in the netns or opted out with `ALLOW_UNFILTERED_IPV6=true`), and logs the final ruleset via `iptables-save` and `ip6tables-save`.

Any attempt by the workload to connect directly to external IP addresses or unauthorized ports is rejected at the packet level.

### 3. Dynamic SNI TLS Minting
When the workload issues an HTTPS request to an intercepted host (e.g., `https://gemini.backend` or `https://api.github.com`):
1. The TCP connection is redirected by iptables to `all-in-one-portal` on port `8443`.
2. The proxy inspects the Server Name Indication (SNI) in the TLS `ClientHello`.
3. The proxy dynamically mints an X.509 server certificate matching that hostname, signed by the pod-local CA private key (`ca-private/tls.key`), and caches the certificate in memory.
4. The workload completes the TLS handshake successfully because it trusts the pod-local CA certificate (`ca-cert/tls.crt`).

### 4. Layer-7 Host Routing and Credential Injection
Once the TLS session is established, the proxy reads the decrypted HTTP request:
1. It extracts the `Host` header (or request URL host), strips any port, and matches it against loaded `PortalRule` definitions.
2. If matched:
   - The destination URL is rewritten to `spec.rewriteUrl`.
   - The upstream authorization header (default `Authorization: Bearer <token>`) is injected using the secret token configured in the rule.
   - Hop-by-hop headers and spoofed headers are sanitized.
3. The proxy establishes a secure, standard HTTPS connection to the real upstream service using its own TLS client, executes the request, and streams the response back to the workload.

---

## "Duck Identity" & Workload Identity

A central concept introduced by `service-portals` is **"Duck Identity"**:

> *If it walks like a duck and quacks like a duck, it's a duck.*

In traditional security architectures, identity is tied to cryptographic credentials or tokens directly held by the running process (e.g., a mounted Kubernetes ServiceAccount token, a private key, or an OAuth secret). If that token is stolen, the attacker assumes that identity.

With `service-portals`, the workload's identity is defined entirely by the **portal's configuration**, not by anything inside the workload:
- The workload container possesses no credentials.
- When the workload talks to `github.backend`, the portal injects GitHub credentials granting access to a specific organization or repository.
- When the workload talks to `gemini.backend`, the portal injects an API key bound to a specific quota or project.
- The workload's effective identity when communicating with the outside world is whatever identity the portal bestows upon it.

### Relationship to Workload Identity & SPIFFE
`service-portals` acts as the bridge between pod-level identity and external third-party services:
- Traditional Workload Identity (GCP Workload Identity, AWS IAM Roles for Service Accounts) allows pods to authenticate to a single cloud provider via service accounts.
- `service-portals` extends this boundary to *arbitrary third-party APIs* (Anthropic, OpenAI, GitHub, arbitrary REST endpoints) without requiring native Workload Identity federation on each upstream provider.
- In future iterations (see Issue #97), the sidecar configuration itself can be dynamically updated via private gRPC APIs utilizing SPIFFE/mTLS or Kubernetes `PodCertificateRequest`, removing static Secrets from pod manifests entirely.
