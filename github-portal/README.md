# GitHub Portal (`github-portal/`)

> **Status: Legacy Single-Target Binary (Scheduled for Removal)**<br>
> `github-portal` is a legacy single-target proxy binary designed for explicit Service mode. In accordance with the [project roadmap](../docs/roadmap.md), explicit Service mode and per-service portal binaries are scheduled for removal once the per-node containerd NRI mode meets its acceptance bar. New deployments should use the multi-service [`all-in-one-portal`](../cmd/all-in-one-portal/README.md) in the recommended transparent sidecar mode ([docs/sidecar-container.md](../docs/sidecar-container.md)).

`github-portal` is a specialized service portal tailored for the GitHub API (`https://api.github.com/`). It proxies HTTP requests, injects a GitHub personal access token (PAT) or OAuth token into the `Authorization` header, and logs proxied requests while redacting sensitive tokens.

---

## Key Features

1. **Default Target**: Pre-configured for `https://api.github.com/`.
2. **Authentication Header**: Injects the configured `UPSTREAM_AUTH_TOKEN` into the `Authorization` header (formatted as `Bearer <token>`).
3. **Sensitive Data Redaction**: Automatically redacts the `Authorization` header from proxy request logs.
4. **Transparent Proxying**: Passes requests and streaming response bodies transparently while removing hop-by-hop HTTP headers.

---

## Configuration

| Environment Variable | Default | Description |
| :--- | :--- | :--- |
| `TARGET_URL` | `https://api.github.com/` | Upstream GitHub API URL. |
| `UPSTREAM_AUTH_TOKEN` | `""` | GitHub token injected into upstream requests. |
| `UPSTREAM_AUTH_HEADER` | `Authorization` | Header name for injecting the token. |
| `PORT` | `8080` | Port to listen on. |
| `HTTPS_PORT` | `8443` | HTTPS port for TLS connections (requires `CA_CERT_PATH` and `CA_KEY_PATH` to sign certificates). |
| `CA_CERT_PATH` | `""` | Path to Root CA certificate PEM file. |
| `CA_KEY_PATH` | `""` | Path to Root CA private key PEM file. |
| `OTEL_INSTRUMENTATION_ENABLED` | `""` | Set to `"true"` to enable OpenTelemetry tracing. |

---

## Kubernetes Deployment

Deploy using the provided manifests:
```bash
kubectl apply -f github-portal/k8s/manifests.yaml
```
Internal workloads can then access GitHub endpoints directly via `http://github-portal`.
