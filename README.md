# Service Portals

> **A credential-swapping, layer-7 intercepting proxy for sandboxes.**<br>
> Keep real credentials out of untrusted workloads—because *tokens that aren't there can't leak.*

We welcome contributions! Please see [docs/contributing.md](docs/contributing.md) for more information.

We follow [Google's Open Source Community Guidelines](https://opensource.google.com/conduct/).

---

## What is Service Portals?

Modern workloads—such as autonomous AI agents, CI/CD runners, and code execution sandboxes—need to call external services like GitHub, Google Gemini, Anthropic, or cloud infrastructure APIs.

If the real API keys or bearer tokens reside inside the sandbox container (in environment variables, files, or process memory), they can easily be leaked:
- By an **AI prompt injection** coercing the agent to dump its environment.
- By a **malicious dependency** in `npm` or `pip` exfiltrating credentials to an external server.
- By an **application bug or crash reporter** logging request headers and tokens.
- By **unintended network egress**.

**The solution:** Don't give the sandbox any real credentials.

Instead, route all outbound traffic through an intercepting proxy running alongside the workload. The proxy acts as a deliberate **man-in-the-middle (MITM)**—terminating TLS using an ephemeral Certificate Authority trusted exclusively within the pod, matching requests against declarative routing rules, and replacing whatever placeholder token (or no token) the workload sent with the real upstream credential.

The sandbox never sees or holds the real token.

---

## How it Works

```
+-----------------------------------------------------------------------------------+
|                                  SANDBOX POD                                      |
|                                                                                   |
|  +--------------------+                               +------------------------+  |
|  | Workload Container |                               | Sidecar Proxy          |  |
|  | (Agent / Sandbox)  |                               | (all-in-one-portal)    |  |
|  |                    |                               |                        |  |
|  | Holds NO secrets!  |  1. Transparent Redirection   | Holds REAL secrets in  |  |
|  | Sends placeholder  |     via iptables              | private volume mount.  |  |
|  | or no token:       |     (:80 -> 8080, :443 -> 8443)                        |  |
|  |                    |------------------------------>| 2. Decrypts TLS via    |  |
|  | Host:              |                               |    pod-local Root CA.  |  |
|  | gemini.backend     |                               | 3. Swaps placeholder   |  |
|  |                    |                               |    for real API token. |  |
|  | Authorization:     |                               | 4. Rewrites host to    |  |
|  | Bearer placeholder |                               |    real target.        |  |
|  +--------------------+                               +-----------+------------+  |
|                                                                   |               |
+-------------------------------------------------------------------|---------------+
                                                                    | 5. Standard TLS
                                                                    |    with real token
                                                                    v
                                                        +------------------------+
                                                        | Upstream Service       |
                                                        | (Gemini, GitHub, etc.) |
                                                        +------------------------+
```

1. **Pod-Local CA Generation**: An `initContainer` (`init-service-portals`) generates a fresh, ephemeral Root Certificate Authority valid only for the pod. The public certificate is mounted into the workload container; the private key is mounted into the proxy container only.
2. **Transparent Interception & Egress Filtering**: `iptables` rules redirect outbound TCP traffic on port 80 to port 8080 and port 443 to port 8443. All other outbound TCP and UDP connections (except DNS on port 53 and traffic from the proxy UID `1337`) are rejected at the packet layer.
3. **Dynamic SNI TLS Termination**: The proxy terminates TLS connections on port 8443 by dynamically minting per-host certificates signed by the pod-local CA.
4. **Credential Swapping & Rewriting**: The proxy matches the request against declarative `PortalRule` definitions, replaces placeholder authorization headers with real upstream credentials, rewrites the destination URL, and forwards the request over public TLS.

---

## What You Get For Free

Placing an intercepting proxy in the outbound traffic path provides powerful capabilities almost for free:

- **Granular Policy**: Restrict sandboxes to specific hosts, URL paths, HTTP methods, repositories, or models—far more granular control than a bearer token or API key alone can enforce.
- **Egress Control**: Prevent network exfiltration. The `init-service-portals` container installs `iptables` egress rules that reject all outbound TCP/UDP traffic to unauthorized ports and destinations.
- **Caching**: Reduce latency and API costs. Enable response caching with `cacheTTL` on any `PortalRule`, or use the specialized Git caching proxy (`cmd/gitproxy-server`) to cache packfiles and resolve commit DAGs for fast fetches.
- **Observability**: Built-in OpenTelemetry tracing ([docs/opentelemetry.md](docs/opentelemetry.md)) and structured logging. The specialized LLM portals (`gemini-portal/` and `anthropic-portal/`) automatically decode and log parsed prompts, system instructions, and model responses while strictly redacting authentication tokens.
- **"Duck Identity"**: Workload identity without keys in the workload. The identity of the sandbox *becomes* whichever identity the proxy injects (*if it walks like a duck and quacks like a duck...*). The sandbox's privileges are defined by the portal's rules, not by anything the sandbox possesses.

---

## Deployment Modes

`service-portals` supports three primary deployment architectures:

| Mode | Summary | Documentation |
| :--- | :--- | :--- |
| **Transparent Sidecar Mode** *(Primary)* | `init-service-portals` configures iptables redirection and a pod-local CA; `all-in-one-portal` intercepts HTTP (:8080) and HTTPS (:8443) traffic. Requires zero application code changes and provides strict packet-level egress filtering. | [Sidecar Guide](docs/sidecar-container.md) |
| **Explicit Service Mode** | Centralized, cluster-wide reverse proxy exposed via a standard Kubernetes `Service`. Workloads address the proxy explicitly (e.g. `http://gemini-portal/`). Does not require `NET_ADMIN`. | [Deployment Modes](docs/deployment-modes.md#2-explicit-service-mode-shared-in-cluster-gateway) |
| **Explicit HTTP Proxy Mode** | Standard `HTTP_PROXY` and `HTTPS_PROXY` tunneling (`CONNECT` method). Supports a single upstream configured by `TARGET_URL` / `UPSTREAM_AUTH_TOKEN`; requests to other hosts are forwarded without modification; `PortalRule` routing is not applied in this mode today (see [#127](https://github.com/gke-labs/service-portals/issues/127)). | [Deployment Modes](docs/deployment-modes.md#3-explicit-http-proxy-mode-httpproxy--httpsproxy) |

For a detailed architectural comparison and trade-offs, see [docs/deployment-modes.md](docs/deployment-modes.md).

---

## Quick Start: Transparent Sidecar with `PortalPolicy`

Using the mutating admission webhook ([docs/injector.md](docs/injector.md)), Service Portals is completely drop-in: you define a [`PortalPolicy`](docs/portal-policy.md) and deploy your workload container as normal—with **no sidecar or init container manifests written by hand**.

### 1. Enable Injection on the Namespace

Label the target namespace to enable automatic sidecar injection:

```bash
kubectl label namespace sandboxes portals.gke.io/injection=enabled
```

### 2. Store Credentials in Secrets

Store your real API keys or bearer tokens in standard Kubernetes Secrets:

```bash
kubectl create secret generic gemini-creds --from-literal=apiKey="YOUR_GEMINI_API_KEY" -n sandboxes
kubectl create secret generic github-creds --from-literal=token="YOUR_GITHUB_TOKEN" -n sandboxes
```

### 3. Create a `PortalPolicy`

Declare which pods are selected and how outbound hosts are routed and authenticated:

```yaml
apiVersion: portals.gke.io/v1alpha1
kind: PortalPolicy
metadata:
  name: agent-sandbox
  namespace: sandboxes
spec:
  podSelector:
    matchLabels:
      app: agent
  rules:
  - host: gemini.backend
    rewriteUrl: https://generativelanguage.googleapis.com
    authHeader: x-goog-api-key
    secretRef:
      name: gemini-creds
      key: apiKey
  - host: github.backend
    rewriteUrl: https://api.github.com
    authHeader: Authorization
    secretRef:
      name: github-creds
      key: token
```

### 4. Deploy Your Plain Workload

Deploy your application manifest with **zero portal-specific configuration**:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-agent
  namespace: sandboxes
  labels:
    app: agent
spec:
  containers:
  - name: workload
    image: python:3.11-slim
    securityContext:
      runAsNonRoot: true
      runAsUser: 1000
      allowPrivilegeEscalation: false
    command: ["sleep", "3600"]
```

The webhook automatically injects the `init-service-portals` init container, the native sidecar proxy (`service-portal-sidecar`), the pod CA volume and trust environment variables (`SSL_CERT_FILE`), `hostAliases`, and a generated rules secret.

For manual deployment or understanding what this expands to under the hood, see [`k8s/sidecar.yaml`](k8s/sidecar.yaml) and [docs/sidecar-container.md](docs/sidecar-container.md).

### 5. Test from Within the Sandbox

Exec into the workload container. Outbound requests are transparently intercepted and authenticated without the sandbox ever seeing the credentials:

```bash
# HTTP request (intercepted on port 80 -> proxy 8080)
wget -qO- http://gemini.backend/v1beta/models

# HTTPS request (intercepted on port 443 -> proxy 8443, pod CA trusted automatically via SSL_CERT_FILE)
wget -qO- https://gemini.backend/v1beta/models
```

---

## Available Service Portals & Components

- **`all-in-one-portal`** (`cmd/all-in-one-portal/`): Multi-service sidecar proxy with dynamic `PortalRule` routing, SNI TLS termination, and `SIGHUP` reload. ([README](cmd/all-in-one-portal/README.md))
- **`init-service-portals`** (`cmd/init-service-portals/`): Init container utility for Root CA generation, permission setup, and iptables redirection. ([README](cmd/init-service-portals/README.md))
- **`gitproxy-server`** (`cmd/gitproxy-server/`): High-performance Git HTTP caching proxy supporting protocols v0/v1/v2, commit DAG reachability pruning, and packfile generation. ([README](cmd/gitproxy-server/README.md))
- **`service-portal`** (`cmd/service-portal/`): Generic single-target reverse proxy and explicit HTTP CONNECT proxy. ([README](cmd/service-portal/README.md))
- **`gemini-portal`** (`gemini-portal/`): Specialized Google Gemini proxy with JSON and gRPC protobuf inspection and token redaction. ([README](gemini-portal/README.md))
- **`anthropic-portal`** (`anthropic-portal/`): Specialized Anthropic Messages API proxy with JSON message parsing and gzip decompression. ([README](anthropic-portal/README.md))
- **`github-portal`** (`github-portal/`): Specialized GitHub API proxy with Bearer token injection. ([README](github-portal/README.md))

---

## Documentation Index

- **[PortalPolicy CRD Specification](docs/portal-policy.md)**: Full field reference and examples for declarative `PortalPolicy` resources.
- **[Portal Injector Admission Webhook](docs/injector.md)**: Mutating/validating admission webhook guide, annotations, and security requirements.
- **[Architecture & Security Model](docs/architecture.md)**: Threat model, trust model, MITM mechanics, iptables egress filtering, and "Duck Identity".
- **[Configuration Reference](docs/configuration.md)**: `PortalRule` specification, environment variables, flags, caching, and fallback behavior.
- **[Deployment Modes](docs/deployment-modes.md)**: Comparison of Transparent Sidecar vs. Explicit Service vs. HTTP Proxy modes.
- **[Sidecar Deployment Guide](docs/sidecar-container.md)**: Detailed step-by-step walkthrough and Kubernetes manifest for transparent sidecar pods.
- **[OpenTelemetry Instrumentation](docs/opentelemetry.md)**: Guide to configuring distributed tracing with OpenTelemetry.
- **[Contributing](docs/contributing.md)**: Information about submitting contributions and signing the CLA.
- **[Agent Guide](AGENTS.md)**: Codebase map and guidance for automated coding agents.

---

## Installation & Deployment from Source

To build and deploy service-portals from source, you can use the `ap` tool (https://raw.githubusercontent.com/gke-labs/gke-labs-infra/main/ap/llms.txt):

```bash
IMAGE_PREFIX=example.com/foo ap deploy //...
```

To run tests locally:

```bash
go test ./...
```

---

## Disclaimer

This is not an officially supported Google product.

This project is not eligible for the Google Open Source Software Vulnerability Rewards Program.
