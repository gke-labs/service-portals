# Portal Injector Admission Webhook

The `portal-injector` makes Service Portals a drop-in solution for Kubernetes clusters. It implements a mutating and validating admission webhook that turns a declarative `PortalPolicy` into the init container, native sidecar proxy, pod-local CA, and credential rules volume—requiring **zero changes** to your workload pod manifests.

---

## How It Works

1. **Pod Selection**:
   - The webhook selects pods created in namespaces labelled `portals.gke.io/injection: enabled` whose labels match a `PortalPolicy.spec.podSelector`.
   - Pods can opt out by setting the pod annotation `portals.gke.io/inject: "false"`.
   - Pods can force injection (even without a labelled namespace) by setting `portals.gke.io/inject: "true"`.
   - If no `PortalPolicy` matches an ordinary pod, admission proceeds without mutation. If `portals.gke.io/inject: "true"` is set but no policy matches, admission is rejected with an explicit error.
   - If multiple policies select the same pod, admission is rejected.

2. **Mutation (Rendered from Policy)**:
   - **`init-service-portals` init container**: Injected with `NET_ADMIN` capability and configured with environment variables (`INTERCEPT_PORTS`, `ALLOW_CIDRS`, `ALLOW_PORTS`, `DNS_SERVER_IPS`, `PROXY_UID: 1337`).
   - **`service-portal-sidecar` proxy**: Injected as a **native sidecar container** (`initContainers[]` entry with `restartPolicy: Always` for Kubernetes >= 1.29), ensuring the proxy is running before the workload starts and remains active until after workload containers terminate. A CLI flag (`--native-sidecars=false`) falls back to regular containers on older clusters.
   - **CA Volumes**: Shared `ca-cert` and `ca-key` `emptyDir` volumes. The public CA certificate (`ca-cert`) is mounted read-only into **every workload container** at `/etc/service-portal/ca`.
   - **CA Environment Variables**: Workload containers automatically receive `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, and `NODE_EXTRA_CA_CERTS` pointing to `/etc/service-portal/ca/tls.crt`. Clients (Python `requests`, Node.js, Go, cURL, etc.) trust the pod CA out of the box with no image changes. This can be disabled via annotation `portals.gke.io/inject-ca-env: "false"`.
   - **Generated Rules Secret**: The injector resolves referenced `secretRef` credentials, compiles `PortalRule` documents, and creates a generated Kubernetes Secret (`<pod-owner>-portal-rules-<hash>`) owner-referenced to the pod's controller or the `PortalPolicy`. The secret is mounted **only** into the proxy sidecar. The workload container never sees it.
   - **Host Aliases**: Automatically adds `hostAliases` mapping every configured rule host to a dummy IP (`8.8.8.8`) to trigger transparent network interception.

3. **Validation & Security Enforcement**:
   To prevent untrusted workloads from bypassing the proxy, the webhook validates:
   - `spec.hostNetwork`: Must NOT be `true`.
   - Workload containers:
     - `runAsNonRoot`: Must be `true` (set at container or pod level).
     - `runAsUser`: Must NOT be `1337` (the proxy's reserved UID).
     - `allowPrivilegeEscalation`: Must be explicitly `false`.
     - `securityContext.capabilities`: Cannot add `NET_ADMIN` or `NET_RAW`.
   Rejections clearly report the violating container and field.

4. **Idempotency**:
   Re-admission of already-injected pods (such as during updates) is a no-op. Injected pods are marked with annotations:
   - `portals.gke.io/status: "injected"`
   - `portals.gke.io/policy: "<policy-name>"`
   - `portals.gke.io/policy-generation: "<policy-generation>"`

---

## Enabling Injection

### 1. Label the Namespace

Enable automatic sidecar injection for all selected workloads in a namespace:

```bash
kubectl label namespace sandboxes portals.gke.io/injection=enabled
```

### 2. Define a `PortalPolicy`

Create a `PortalPolicy` in that namespace:

```yaml
apiVersion: portals.gke.io/v1alpha1
kind: PortalPolicy
metadata:
  name: sandbox-policy
  namespace: sandboxes
spec:
  podSelector:
    matchLabels:
      app: my-agent
  rules:
  - host: gemini.backend
    rewriteUrl: https://generativelanguage.googleapis.com
    authHeader: x-goog-api-key
    secretRef:
      name: gemini-credentials
      key: apiKey
```

### 3. Deploy Plain Workload

Deploy your application without any sidecar definitions or credentials:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-agent
  namespace: sandboxes
spec:
  selector:
    matchLabels:
      app: my-agent
  template:
    metadata:
      labels:
        app: my-agent
    spec:
      containers:
      - name: agent
        image: my-agent:latest
        securityContext:
          runAsNonRoot: true
          runAsUser: 1000
          allowPrivilegeEscalation: false
```

The webhook automatically injects the init container, native sidecar proxy, CA mounts, host aliases, and rules secret!

---

## Annotations Reference

| Annotation | Value | Description |
| :--- | :--- | :--- |
| `portals.gke.io/inject` | `"true"` \| `"false"` | `"true"` forces injection even in unlabelled namespaces. `"false"` disables injection. |
| `portals.gke.io/inject-ca-env` | `"true"` \| `"false"` | Controls whether `SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE` / `NODE_EXTRA_CA_CERTS` are injected (default: `true`). |
| `portals.gke.io/status` | `"injected"` | Added by the injector to mark completed mutation. |
| `portals.gke.io/policy` | `<name>` | Name of the matched `PortalPolicy`. |
| `portals.gke.io/policy-generation` | `<generation>` | Generation of the matched `PortalPolicy`. |
