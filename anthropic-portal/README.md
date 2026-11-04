# Anthropic Portal (`anthropic-portal/`)

> **Status: Legacy Single-Target Binary (Scheduled for Removal)**<br>
> `anthropic-portal` is a legacy single-target proxy binary designed for explicit Service mode. In accordance with the [project roadmap](../docs/roadmap.md), explicit Service mode and per-service portal binaries are scheduled for removal once the per-node containerd NRI mode meets its acceptance bar. New deployments should use the multi-service [`all-in-one-portal`](../cmd/all-in-one-portal/README.md) in the recommended transparent sidecar mode ([docs/sidecar-container.md](../docs/sidecar-container.md)).

`anthropic-portal` is a specialized service portal tailored for Anthropic's Messages API (`https://api.anthropic.com`). It terminates requests, injects the Anthropic API key, and provides structured logging of prompts, system instructions, and assistant responses.

---

## Key Differences from Generic Portal

1. **Default Target**: Configured out-of-the-box for `https://api.anthropic.com`.
2. **Authentication Header**: Injects the API key into the `x-api-key` header (default for Anthropic).
3. **Sensitive Data Redaction**: Automatically redacts `x-api-key` and `Authorization` headers from proxy logs.
4. **Message Inspection & Decompression**:
   - Parses the JSON request body to extract and log `system` prompts and `messages` (role and content).
   - Inspects response bodies, automatically decompressing `gzip` content if encoded, and logs assistant text content.

---

## Configuration

| Environment Variable | Default | Description |
| :--- | :--- | :--- |
| `TARGET_URL` | `https://api.anthropic.com` | Upstream Anthropic API URL. |
| `UPSTREAM_AUTH_TOKEN` | `""` | Anthropic API key injected into upstream requests. |
| `UPSTREAM_AUTH_HEADER` | `x-api-key` | Header name for injecting the API key. |
| `PORT` | `8080` | Port to listen on. |
| `HTTPS_PORT` | `8443` | HTTPS port for TLS connections (requires `CA_CERT_PATH` and `CA_KEY_PATH` to sign certificates). |
| `CA_CERT_PATH` | `""` | Path to Root CA certificate PEM file. |
| `CA_KEY_PATH` | `""` | Path to Root CA private key PEM file. |
| `OTEL_INSTRUMENTATION_ENABLED` | `""` | Set to `"true"` to enable OpenTelemetry tracing. |

---

## Kubernetes Deployment

Deploy using the provided manifests:
```bash
kubectl apply -f anthropic-portal/k8s/manifests.yaml
```
Internal workloads can then access the Anthropic API directly via `http://anthropic-portal`.
