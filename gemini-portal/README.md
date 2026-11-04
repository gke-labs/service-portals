# Gemini Portal (`gemini-portal/`)

> **Status: Legacy Single-Target Binary (Scheduled for Removal)**<br>
> `gemini-portal` is a legacy single-target proxy binary designed for explicit Service mode. In accordance with the [project roadmap](../docs/roadmap.md), explicit Service mode and per-service portal binaries are scheduled for removal once the per-node containerd NRI mode meets its acceptance bar. New deployments should use the multi-service [`all-in-one-portal`](../cmd/all-in-one-portal/README.md) in the recommended transparent sidecar mode ([docs/sidecar-container.md](../docs/sidecar-container.md)).

`gemini-portal` is a specialized service portal tailored for Google's Generative Language API (`https://generativelanguage.googleapis.com`). It terminates requests, injects the Gemini API key, and provides structured logging of prompts and model responses across both JSON and gRPC protocols.

---

## Key Differences from Generic Portal

1. **Default Target**: Configured out-of-the-box for `https://generativelanguage.googleapis.com`.
2. **Authentication Header**: Injects the API key into the `x-goog-api-key` header (default for Gemini).
3. **Sensitive Data Redaction**: Automatically redacts `x-goog-api-key` and `Authorization` headers from proxy logs.
4. **Protobuf & JSON Inspection**:
   - **JSON**: Parses `system_instruction` and request `contents` by role (`user`, `model`), logging individual prompt parts. Parses response candidates and logs generated response text.
   - **gRPC**: Unmarshals raw binary gRPC frames for `generativelanguagepb.GenerateContentRequest` and `generativelanguagepb.GenerateContentResponse`, logging system instructions, input turns, and candidate responses.
   - **Streaming Support**: Detects `application/grpc` streaming responses and bypasses full-body buffering to preserve low-latency streaming behavior.

---

## Configuration

| Environment Variable | Default | Description |
| :--- | :--- | :--- |
| `TARGET_URL` | `https://generativelanguage.googleapis.com` | Upstream Gemini API URL. |
| `UPSTREAM_AUTH_TOKEN` | `""` | Gemini API key injected into upstream requests. |
| `UPSTREAM_AUTH_HEADER` | `x-goog-api-key` | Header name for injecting the API key. |
| `PORT` | `8080` | Port to listen on. |
| `HTTPS_PORT` | `8443` | HTTPS port for TLS connections (requires `CA_CERT_PATH` and `CA_KEY_PATH` to sign certificates). |
| `CA_CERT_PATH` | `""` | Path to Root CA certificate PEM file. |
| `CA_KEY_PATH` | `""` | Path to Root CA private key PEM file. |
| `OTEL_INSTRUMENTATION_ENABLED` | `""` | Set to `"true"` to enable OpenTelemetry tracing. |

---

## Kubernetes Deployment

Deploy using the provided manifests:
```bash
kubectl apply -f gemini-portal/k8s/manifests.yaml
```
Internal workloads can then access the Gemini API directly via `http://gemini-portal`.
