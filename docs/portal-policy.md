# PortalPolicy Specification (`portals.gke.io/v1alpha1`)

`PortalPolicy` is a Kubernetes Custom Resource Definition (CRD) that defines per-pod routing rules, secret references, and default-deny egress boundaries for `service-portals` sidecars.

---

## Overview

In traditional sidecar setups, configuring a sandboxed pod requires assembling multiple distinct resources and specifications by hand:
- A Kubernetes `Secret` containing multiple embedded `PortalRule` YAML documents.
- `hostAliases` entries in `pod.spec` to resolve backend hostnames to dummy IPs.
- Init-container environment variables (`INTERCEPT_PORTS`, `ALLOW_CIDRS`, `DNS_SERVER_IPS`, etc.).
- Sidecar volume mounts and UID configurations.

`PortalPolicy` provides a single declarative, Kubernetes-native object that selects onto pods by label and defines:
1. **Routing and Credential Swapping**: Which hosts map to which upstreams and which Kubernetes Secrets supply credentials.
2. **Egress Security Boundary**: Default-deny versus opt-in fallback, allowed direct CIDRs/ports, DNS server lockdown, and metadata endpoint blocking.
3. **Interception**: Which TCP ports are transparently captured by `init-service-portals`.
4. **Proxy Overrides**: Optional image and resource requirement overrides for the proxy container.

---

## Example

```yaml
apiVersion: portals.gke.io/v1alpha1
kind: PortalPolicy
metadata:
  name: agent-sandbox
  namespace: sandboxes
spec:
  podSelector:
    matchLabels: { app: agent }
  rules:                                   # same shape as PortalRule.spec today
  - host: github.backend
    rewriteUrl: https://api.github.com
    authHeader: Authorization
    secretRef: { name: github-creds, key: token }   # K8s Secret in the same namespace
  - host: gemini.backend
    rewriteUrl: https://generativelanguage.googleapis.com
    authHeader: x-goog-api-key
    secretRef: { name: gemini-creds, key: apiKey }
    cacheTTL: 10m
  egress:
    defaultAction: Deny                    # Deny | Allow (Allow = today's TARGET_URL fallback, explicit opt-in)
    allowCIDRs: []                         # passed to init container ALLOW_CIDRS
    allowPorts: []                         # ALLOW_PORTS
    dns:
      servers: []                          # default: cluster DNS only
      allowMetadata: false
  intercept:
    ports: [80, 443]                       # INTERCEPT_PORTS
  proxy:
    image: ""                              # optional overrides; defaults from the injector config
    resources: {}
```

---

## Specification Reference

### Metadata

| Field | Type | Required | Description |
|---|---|---|---|
| `metadata.name` | `string` | **Yes** | Name of the `PortalPolicy`. |
| `metadata.namespace` | `string` | **Yes** | Namespace of the policy. Referenced secrets must reside in this same namespace. |

### `spec.podSelector`

Selects the pods to which this policy applies. Uses standard Kubernetes label selector syntax.

| Field | Type | Required | Description |
|---|---|---|---|
| `podSelector.matchLabels` | `map[string]string` | No | Map of key-value label pairs that must match. |
| `podSelector.matchExpressions` | `[]LabelSelectorRequirement` | No | List of label selector requirements (`In`, `NotIn`, `Exists`, `DoesNotExist`). |

### `spec.rules[]`

Defines proxy routing and credential injection rules.

> **Security Note**: Credentials must always be referenced via `secretRef`. Inline `authToken` fields are deliberately not supported in `PortalPolicy` so that credentials never appear in policy definitions or audit logs.

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `name` | `string` | No | Derived from `host` | Optional descriptive rule identifier. |
| `host` | `string` | **Yes** | None | Intercepted hostname (e.g. `github.backend`). Must be a valid RFC 1123 hostname. |
| `rewriteUrl` | `string` | No | `https://<host>` | Target upstream URL (e.g. `https://api.github.com`). |
| `authHeader` | `string` | No | `Authorization` | HTTP header name for credential injection. |
| `secretRef` | `SecretKeyRef` | **Yes** | None | Reference to a Kubernetes Secret in the same namespace. |
| `secretRef.name` | `string` | **Yes** | None | Name of the Secret. |
| `secretRef.key` | `string` | **Yes** | None | Key within the Secret data containing the token. |
| `cacheTTL` | `string` | No | None | Optional response cache duration (e.g. `10m`, `1h`). |

### `spec.egress`

Controls outbound traffic filtering configured by `init-service-portals` and the proxy.

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `defaultAction` | `string` (`Deny` \| `Allow`) | No | `Deny` | Action for unmatched outbound requests. `Deny` rejects unmatched requests; `Allow` forwards them to the fallback target (`TARGET_URL`). |
| `allowCIDRs` | `[]string` | No | `[]` | List of CIDR blocks permitted for direct outbound traffic (passed to init container `ALLOW_CIDRS`). |
| `allowPorts` | `[]int` | No | `[]` | Additional TCP ports permitted for direct outbound traffic (passed to init container `ALLOW_PORTS`). |
| `dns.servers` | `[]string` | No | `[]` (cluster DNS) | Authorized DNS resolver IP addresses (passed to init container `DNS_SERVER_IPS`). |
| `dns.allowMetadata` | `bool` | No | `false` | Whether to allow outbound traffic to cloud instance metadata (`169.254.169.254`). |

### `spec.intercept`

Controls transparent port redirection to the sidecar proxy.

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `ports` | `[]int` | No | `[80, 443]` | TCP ports redirected by iptables to the proxy (passed to init container `INTERCEPT_PORTS`). |

### `spec.proxy`

Container specification overrides for the sidecar proxy.

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | `string` | No | Default injector image | Overrides the sidecar proxy container image. |
| `resources` | `ResourceRequirements` | No | Default injector resources | Overrides resource limits and requests for the sidecar proxy container. |

### `status`

Observed status of the policy.

| Field | Type | Description |
|---|---|---|
| `status.conditions[]` | `[]Condition` | Conditions representing the status of the policy (e.g. `Ready`, `Invalid`). |
| `status.selectedPods` | `int` | Total count of pods currently matched by this policy. |

---

## Multiple Policies Selecting One Pod (Conflict Rule)

In `portals.gke.io/v1alpha1`, **each pod may be selected by at most one `PortalPolicy`**:
- **0 matching policies**: The pod is unaffected and no sidecar injection occurs.
- **1 matching policy**: The policy is resolved and injected into the pod.
- **2 or more matching policies**: **Rejected at admission**. The mutating webhook / injector denies pod creation with an error message indicating the conflicting policies (e.g., `multiple PortalPolicies match pod (sandboxes/policy-a, sandboxes/policy-b): policy merging is not supported in v1alpha1, rejected at admission`).

Policy merging across overlapping selectors is intentionally deferred to future API versions. Workload labels and policy selectors must be partitioned to prevent ambiguity.

---

## Resolution Library (`pkg/policy`)

The Go package `pkg/policy` provides the resolution logic consumed by injectors and controllers:

```go
func Resolve(policy v1alpha1.PortalPolicy, secrets SecretGetter) (SidecarConfig, error)
```

Given a `PortalPolicy` and an implementation of `SecretGetter`, `Resolve` produces a `SidecarConfig` containing:
1. **`Rules` & `RuleDocuments`**: Complete `PortalRule` objects and serialized YAML documents ready to mount into the proxy's `--rules-dir` Secret volume.
2. **`HostAliases`**: A `hostAliases` entry mapping all policy hosts to a non-loopback dummy IP (`8.8.8.8`) to trigger transparent interception.
3. **`InitEnv`**: Environment variables for `init-service-portals` (`INTERCEPT_PORTS`, `ALLOW_CIDRS`, `ALLOW_PORTS`, `DNS_SERVER_IPS`, `ALLOW_METADATA`, `EGRESS_ACTION`).
4. **`ProxyEnv`**: Proxy settings including `DEFAULT_ACTION`.
5. **`ProxyImage` & `ProxyResources`**: Any container overrides specified in the policy.
