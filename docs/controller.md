# Service Portal Controller

The Service Portal Controller provides a single authenticated gRPC endpoint (`PodBindService`) that sandbox controllers dial to configure egress policies and credentials for sandbox pods. A sandbox controller pushes an `EgressPolicy` and named secrets keyed by pod UID. The controller verifies each pod's scheduled node in the Kubernetes API and forwards the push over a long-lived gRPC stream to the node agent running on that node. The node agent stores the policy and secrets locally and enforces them in the node proxy; nothing is allowed until bound, and traffic from unbound pods or traffic that does not match an allowed rule is denied by default.

For architectural background and rationale, see the design records:
- [Service Portal Controller design](design/service-portal-controller.md)
- [Egress Policy language design](design/egress-policy.md)

---

## Deploying the Controller

The controller reference manifest is designed to be applied unchanged (for example with `ap deploy` or `kubectl apply -f k8s/controller.yaml`):

```bash
ap deploy k8s/controller.yaml
```

The controller Deployment (`k8s/controller.yaml`) reads its audience, node agent service account, and client allowlist from a ConfigMap named `service-portal-config` in the `service-portal-system` namespace through non-optional `configMapKeyRef` environment variables.

Until the ConfigMap exists, the controller pod does not start and remains in `CreateContainerConfigError` (with the error message naming the missing ConfigMap), signaling that the controller is not configured yet.

After deployment, configure the controller by running `dev/tasks/configure` (or creating the ConfigMap directly):

```bash
dev/tasks/configure \
  --audience="https://service-portal-controller" \
  --node-agent-account="system:serviceaccount:service-portal-system:portal-node-agent" \
  --client-allowlist="system:serviceaccount:default:sandbox-controller"
```

Once the ConfigMap is created, Kubernetes starts the controller pod.

### ConfigMap Keys (`service-portal-config`)

| Key | Description |
|---|---|
| `audience` | Expected TokenReview audience for validating caller tokens. |
| `node-agent-account` | Permitted node agent service account in `system:serviceaccount:<namespace>:<name>` format. |
| `client-allowlist` | Comma-separated list of permitted client service accounts (`system:serviceaccount:<namespace>:<name>`). If empty, all client calls are refused. |

### TLS Secret

The deployer supplies a Kubernetes TLS Secret containing a server certificate and private key (`tls.crt` and `tls.key`), mounted into the controller pod.

The CA certificate that signed the controller's certificate must be distributed to:
- Sandbox controllers, to verify the controller's TLS certificate when dialing `PodBindService`.
- Node agents, to verify the controller's TLS certificate when establishing the outbound node stream.

### Controller Configuration

The `service-portal-controller` binary accepts flags or environment variables:

| Flag | Environment Variable | Default | Description |
|---|---|---|---|
| `-listen-address` | | `:8443` | Address and TCP port on which the controller serves gRPC over TLS. |
| `-tls-cert-file` | | `""` | File path to the TLS server certificate PEM file (**required**). |
| `-tls-key-file` | | `""` | File path to the TLS server private key PEM file (**required**). |
| `-audience` | `AUDIENCE` | `""` | Expected TokenReview audience for validating caller tokens (**required**; falls back to `AUDIENCE` env var). Both client and node agent tokens must match this audience. |
| `-node-agent-account` | `NODE_AGENT_ACCOUNT` | `""` | Kubernetes service account permitted for node agents (**required**; falls back to `NODE_AGENT_ACCOUNT` env var), formatted as `system:serviceaccount:<namespace>:<name>`. |
| `-client-allowlist` | `CLIENT_ALLOWLIST` | `""` | Comma-separated list of permitted client service accounts (`system:serviceaccount:<namespace>:<name>`; falls back to `CLIENT_ALLOWLIST` env var). If empty, all client calls are refused. |
| `-kubeconfig` | | `""` | Path to kubeconfig file. If omitted, uses in-cluster config. Requires RBAC permissions to read pods (`get`, `list`, `watch`) and `create` on `tokenreviews`. |
| `-push-timeout` | | `1m` | Timeout waiting for a node agent to accept a push before returning `DeadlineExceeded`. |

### What the Node Agent Needs

The node agent DaemonSet pod runs two containers: the node proxy (`service-portal-agent`) and the NRI plugin (`service-portal-nri-plugin`). The controller connection and binding persistence belong to the **node proxy container (`service-portal-agent`)**, not `service-portal-nri-plugin`.

The `service-portal-agent` container requires the following environment variables and volume mounts:

#### Environment Variables (in `service-portal-agent`)
- `CONTROLLER_ADDR`: The gRPC address of the controller (`host:port`, matching the Service in `k8s/controller.yaml`: `service-portal-controller.service-portal-system.svc:8443`). When set, the proxy dials out to the controller over TLS.
- `CONTROLLER_CA_CERT_PATH`: File path to the CA certificate used to verify the controller's TLS server certificate. Required when `CONTROLLER_ADDR` is set.
- `CONTROLLER_TOKEN_PATH`: File path to the node agent's projected service account token file. Required when `CONTROLLER_ADDR` is set.
- `STORE_DIR`: Directory path where the proxy persists pod bindings on the node (e.g. `/run/service-portal/store`).

#### Volume Mounts (mounted into `service-portal-agent`)
- **CA Certificate Volume**: Mounts the CA certificate used to verify the controller's server certificate at the path matching `CONTROLLER_CA_CERT_PATH`.
- **Token Volume**: A Kubernetes projected volume mount providing a service account token at the path matching `CONTROLLER_TOKEN_PATH`, configured with:
  - `audience` matching the controller's `-audience` flag.
  - Bound to the node agent pod on that node so the Kubernetes API returns the `authentication.kubernetes.io/node-name` claim during TokenReview.
- **Store Volume**: A `hostPath` volume on the node's memory-backed `/run` (tmpfs, e.g. `/run/service-portal/store`), restricted to the proxy UID and root (mode `0700` / `0600`), mounted at the path matching `STORE_DIR`. Bindings written here survive node proxy container crashes and DaemonSet rolling updates without requiring the sandbox controller to re-push.

#### Kubernetes Version Requirement

Node agents are identified from the node name that `TokenReview` returns for a pod-bound token (`authentication.kubernetes.io/node-name` in `status.user.extra`). This requires **Kubernetes 1.32 or newer** (where pod-bound token metadata is stable and enabled by default), and on earlier versions (1.29 to 1.31) only where the feature is enabled. See the [Kubernetes Service Accounts administration documentation](https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/). On older clusters, `TokenReview` does not return the node name, causing the controller to refuse the connection (`codes.PermissionDenied`), and no node agent can connect.

---

## Calling the Controller from a Sandbox Controller

Sandbox controllers use the generated `PodBindServiceClient` (`github.com/gke-labs/service-portals/pkg/portals/v1`) to push policy and secrets.

### Connection & Calling Sequence

1. **Establish TLS Connection**: Establish a gRPC connection over TLS using the CA certificate that signed the controller's server certificate.
2. **Attach Token Metadata**: Read a projected service account token minted for the controller's audience, and attach it to the gRPC outgoing metadata (`authorization: Bearer <token>`) on each call.
3. **Push Policy (`Bind`)**: Call `Bind` with `wait = true` passing the pod UID and `EgressPolicy`.
4. **Push Secrets (`InjectSecrets`)**: Call `InjectSecrets` with `wait = true` passing the pod UID and named secrets map (if any are referenced by `secret://<name>` in the policy).
5. **Verify Acceptance**: Check the returned status. Release and unpause the sandbox container **only** when the status is `ACCEPTANCE_STATUS_ACCEPTED`. If the status is `ACCEPTANCE_STATUS_REFUSED` or an error is returned, do not release the sandbox.

### Tested Go Implementation

A complete, runnable implementation of this sequence is maintained in [`pkg/controller/example_test.go`](../pkg/controller/example_test.go) (`BindAndReleaseSandbox` and `ExamplePodBindServiceClient`), which is compiled and tested in presubmit CI.

---

## What the Answers Mean

A call to `Bind` or `InjectSecrets` either succeeds and returns a response containing an `AcceptanceStatus` enum (`status`), or fails with a gRPC status error.

### Response Statuses (`AcceptanceStatus`)

| Status | Meaning | What to do |
|---|---|---|
| `ACCEPTANCE_STATUS_ACCEPTED` | The node holds the egress policy and every secret that the policy names in its rules. Enforcement is active. | Safe to release or unpause the sandbox container. |
| `ACCEPTANCE_STATUS_PENDING` | The push was received or stored on the node, but cannot yet be enforced. This happens when:<br>1. The call was made with `wait = false`.<br>2. A policy was bound that references secrets (`secret://<name>`) that have not yet arrived on the node.<br>3. The pod is not yet scheduled or the node has not yet connected (when called with `wait = false`).<br><br>When called with `wait = true`, the response (`BindResponse` or `InjectSecretsResponse`) includes `missing_secrets` listing the names of secrets referenced by the policy that the node is still missing. | **Do not release the sandbox.** If companion secrets are needed by the policy, call `InjectSecrets` with `wait = true`. If the call was made without `wait = true`, call again with `wait = true` and verify the status is `ACCEPTED` before releasing the pod. |
| `ACCEPTANCE_STATUS_REFUSED` | The push was refused **by the node agent** (e.g. `pod "<uid>" not found on node` if the pod is not running on that node, or if the node could not store the binding). The response includes `refusal_reason` from the node.<br><br>*Note:* `REFUSED` comes only from the node. Controller-side validation errors fail immediately as gRPC errors (see below). | **Do not release the sandbox.** Inspect `refusal_reason`. Verify that the pod UID is correct and that the pod has been scheduled to and started on the node. |

### gRPC Status Errors

When a request cannot be processed or verified, the controller fails the RPC with a standard gRPC error:

| gRPC Status Code | Cause | What to do |
|---|---|---|
| `InvalidArgument`<br>(`codes.InvalidArgument`) | The controller rejected the request before contacting the node. Occurs when `pod_uid` is empty, `policy` is nil, or the policy violates validation rules (e.g. empty hostnames, duplicate ports, unsupported `tls_passthrough`, or invalid credential URI syntax). | Fix the request arguments or policy structure. The error message contains details from `policy.Validate()`. |
| `Unauthenticated`<br>(`codes.Unauthenticated`) | The caller failed authentication. Occurs when the `authorization` metadata header is missing, the Bearer token is malformed or expired, the token audience does not match the controller's `-audience`, or Kubernetes TokenReview fails. | Attach a valid projected service account token with the matching audience in `authorization: Bearer <token>`. |
| `PermissionDenied`<br>(`codes.PermissionDenied`) | The caller's authenticated service account is not permitted by the controller's `-client-allowlist` flag (or `-client-allowlist` is empty). | Add the sandbox controller's service account (`system:serviceaccount:<namespace>:<name>`) to the controller's `-client-allowlist`. |
| `DeadlineExceeded`<br>(`codes.DeadlineExceeded`) | When calling with `wait = true`, the push timed out waiting for node acceptance. Occurs when the pod is not scheduled to a node, the node agent is disconnected or crashed, or the node failed to acknowledge within `-push-timeout` (default 1 minute). | Check pod scheduling (`kubectl get pod <pod>`), verify node agent health and connectivity to `CONTROLLER_ADDR`, and retry or fail sandbox creation. |
| `Unimplemented`<br>(`codes.Unimplemented`) | The requested method is not implemented on the controller (specifically `Get`, since binding state lives on the node agent, not on the controller). | Do not call `Get` on the controller. State is maintained locally on each node agent. |

---

## Example Egress Policy

The sandbox controller supplies an `EgressPolicy` containing `rules`. Outbound traffic matching no rule is denied.

Here is an example policy that provides:
1. HTTPS rules for hosts requiring no credentials (`api.anthropic.com`, `crates.io`).
2. An HTTPS rule for `api.github.com` that swaps the `Authorization` header with a named secret (`secret://github-token`).

> **Important: All HTTPS rules intercept TLS.** An HTTPS rule without `effects` (like `api.anthropic.com` below) is still terminated at the node proxy with a dynamically generated certificate signed by the pod-local CA, and re-encrypted upstream. The sandbox container must trust that pod-local CA for these connections as well. This is intercepted TLS, not raw TCP/TLS forwarding (`tls_passthrough` is an unsupported feature and is rejected by policy validation).

### Policy Definition (JSON / protojson)

```json
{
  "rules": [
    {
      "https": {
        "hostnames": ["api.anthropic.com", "crates.io"]
      }
    },
    {
      "https": {
        "hostnames": ["api.github.com"],
        "effects": {
          "replaceHeaders": [
            {
              "header": "Authorization",
              "prefix": "Bearer ",
              "credentialUri": "secret://github-token"
            }
          ]
        }
      }
    }
  ]
}
```

The `EgressPolicy` and `PodBindService` APIs are defined in protobuf; see [`pkg/portals/v1/egress.proto`](../pkg/portals/v1/egress.proto) and [`pkg/portals/v1/bind.proto`](../pkg/portals/v1/bind.proto). For the corresponding Go structs and complete calling code, see [`pkg/controller/example_test.go`](../pkg/controller/example_test.go).

### What Happens to Unallowed Traffic

Any traffic not permitted by an explicit rule in the bound policy is blocked. The sandbox observes the following:

| Destination | Name Resolution (DNS) | Port 80 (HTTP) | Port 443 (HTTPS) | Other Ports |
|---|---|---|---|---|
| **Plain `http` to host with only `https` rule**<br>(e.g. `crates.io`) | Resolves to proxy IP | HTTP `403 Forbidden`<br>(no rule allows `http` to that host) | Allowed<br>(TLS intercepted at proxy) | Connection refused<br>(egress blocked) |
| **Host with no rule**<br>(e.g. `google.com`) | `NXDOMAIN`<br>(resolution fails) | HTTP `403 Forbidden`<br>(if accessing by IP or hosts entry) | TLS handshake fails with no certificate<br>(if accessing by IP or hosts entry) | Connection refused<br>(egress blocked) |

---

## Security Notes for Operators

1. **Client Allowlist (`-client-allowlist`)**:
   The controller restricts access to `PodBindService` using an explicit allowlist of service accounts. If `-client-allowlist` is not configured, the controller refuses all client calls (`codes.PermissionDenied`). Operators must only grant access to authorized sandbox controller service accounts.
2. **Restrict `create` on `serviceaccounts/token` for the Node Agent**:
   Node agents authenticate using projected service account tokens validated through Kubernetes TokenReview. The controller trusts the `authentication.kubernetes.io/node-name` claim in the token to determine which node is connected, routing secrets for a pod only to that node. This requires Kubernetes 1.32 or newer (or earlier versions where the feature is enabled; see [Kubernetes Service Accounts administration](https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/)); on older clusters the claim is absent and no node agent can connect.
   In Kubernetes, the API server mints node-bound tokens for kubelet on that node, or for callers with RBAC `create` permission on `serviceaccounts/token` for that service account. Anyone granted `create` on `serviceaccounts/token` for the node agent service account could mint a token claiming to be any node in the cluster and steal secrets routed to that node. Operators must tightly hold and restrict `create` on `serviceaccounts/token` for the node agent's service account.
3. **Credentials Must Be Short-Lived and Per-Sandbox**:
   Secrets supplied via `InjectSecrets` should be ephemeral and scoped to the lifetime of an individual sandbox pod. Calling `InjectSecrets` replaces the pod's entire secret set on the node (it does not merge), allowing straightforward rotation and revocation.

---

## Limits Today

- **Single Controller Replica**: The controller maintains long-lived streaming connections from node agents in memory without inter-replica routing. There is no leader election in the controller. Deploy one replica.
- **Kubernetes Version Requirement**: Node agents require Kubernetes 1.32 or newer (and on earlier versions only where the feature is enabled) so that `TokenReview` returns the `authentication.kubernetes.io/node-name` claim for pod-bound tokens ([Kubernetes documentation](https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/)). On older clusters, no node agent can connect.
- **`Get` is Not Implemented on the Controller**: The controller is a router, not a persistent database; state lives on the node agent. Calling `Get` on the controller returns `codes.Unimplemented` (`"get is not implemented: state lives on the node"`).
- **Bindings Do Not Survive a Node Reboot**: When `STORE_DIR` is stored in `/run` (tmpfs), bindings survive node agent container crashes and DaemonSet upgrades, but are lost if the host node reboots. When a node reboots, the sandbox controller must re-push bindings for pods on that node.
- **Replace-Only-If-Present**: The proxy replaces a credential header only when the request from the sandbox container already contains that header (e.g. `Authorization: placeholder`). A request sent without the header is forwarded unmodified without credentials.
- **Unsupported Features at Load**: `tls_passthrough` and `actor_jwt` credential sources are not currently supported by the proxy and are rejected by policy validation (`policy.Validate()`). Cleartext `http` and intercepted `https` rules with `replace_headers` using `secret://<name>` are supported.
