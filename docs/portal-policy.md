# PortalPolicy Custom Resource Definition

`PortalPolicy` (`portals.gke.io/v1alpha1`) defines declarative egress routing rules, authentication secret references, and packet-level egress boundaries for matching Kubernetes pods.

Instead of writing `PortalRule` documents or complex sidecar and init container manifests by hand, operators declare a `PortalPolicy` per namespace or workload group. The `portal-injector` mutating webhook automatically resolves the policy and injects all required network interception, CA certificates, and sidecar components into selected pods.

---

## Example `PortalPolicy`

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
  - host: github.backend
    rewriteUrl: https://api.github.com
    authHeader: Authorization
    secretRef:
      name: github-creds
      key: token
  - host: gemini.backend
    rewriteUrl: https://generativelanguage.googleapis.com
    authHeader: x-goog-api-key
    secretRef:
      name: gemini-creds
      key: apiKey
    cacheTTL: 10m
  egress:
    defaultAction: Deny
    allowCIDRs:
    - 10.0.0.0/8
    allowPorts:
    - 53
    dns:
      servers:
      - 10.96.0.10
      allowMetadata: false
  intercept:
    ports:
    - 80
    - 443
  proxy:
    image: all-in-one-portal:latest
```

---

## Specification Reference

### `spec.podSelector` (Required)
A standard Kubernetes `metav1.LabelSelector` defining which pods in the same namespace this policy applies to.
- If multiple policies select the same pod, admission is rejected with an error.

### `spec.rules[]` (Optional)
A list of routing and credential swapping rules:
- `host` *(string, required)*: The virtual target hostname used by the workload (e.g. `gemini.backend`).
- `rewriteUrl` *(string, optional)*: The real upstream URL destination (e.g. `https://generativelanguage.googleapis.com`).
- `authHeader` *(string, optional)*: Name of the HTTP header to swap (e.g. `Authorization` or `x-goog-api-key`).
- `secretRef` *(object, optional)*: Reference to a Kubernetes Secret in the same namespace containing the real authentication token.
  - `name` *(string, required)*: Name of the Secret.
  - `key` *(string, required)*: Key within the Secret holding the token.
- `cacheTTL` *(string, optional)*: Cache expiration duration (e.g. `10m`, `1h`) for response caching.

> **Security Note:** `PortalPolicy` does not accept inline auth tokens. All credentials must come via `secretRef` so that secret values never appear in the policy custom resource.

### `spec.egress` (Optional)
Outbound packet-level egress configuration:
- `defaultAction` *(string, optional)*: Action for unmatched outbound traffic: `Deny` (default) or `Allow`.
- `allowCIDRs` *(list of strings, optional)*: List of CIDR blocks that the workload may contact directly without proxying (e.g. cluster service or pod CIDRs).
- `allowPorts` *(list of integers, optional)*: Additional outbound TCP ports allowed directly.
- `dns` *(object, optional)*:
  - `servers` *(list of strings, optional)*: IP addresses of allowed DNS servers (defaults to cluster DNS).
  - `allowMetadata` *(boolean, optional)*: Whether to allow outbound traffic to cloud instance metadata servers (`169.254.169.254`). Defaults to `false`.

### `spec.intercept` (Optional)
- `ports` *(list of integers, optional)*: List of TCP ports intercepted and redirected to the proxy. Defaults to `[80, 443]`.

### `spec.proxy` (Optional)
- `image` *(string, optional)*: Overrides the default sidecar proxy container image.
- `resources` *(ResourceRequirements, optional)*: Kubernetes CPU/memory requests and limits for the proxy sidecar container.

---

## Status

`PortalPolicy` status exposes:
- `conditions`: List of standard Kubernetes condition objects (e.g., `Ready`, `Invalid`).
- `selectedPods`: Count of pods currently selected and injected by this policy.
